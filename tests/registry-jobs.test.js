'use strict';

// MemoryRegistry sysscript jobs (cp_sysscript_jobs, .omc/plans/async-sysscript-jobs.md
// §6-§7): the tenant predicate on reads and cancel, guarded transitions
// (host, from-status, conn_id; terminal rows never change), the one-time
// dispatch claim, bumpJobAlert at 20, the sweepers, sync reconciliation by
// conn_id, output expiry and pruning, the atomic caps, and the in-process
// event bus. The Postgres variants are in tests/registry-pg.test.js.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { MemoryRegistry, jobRetentionDays, jobOutputRetentionHours } = require('../controlplane/registry');

const HOST_A = 'host-a';
const HOST_A2 = 'host-a2';
const HOST_B = 'host-b';

function sshKey(fill) {
  const name = Buffer.from('ssh-ed25519');
  const buf = Buffer.alloc(4 + name.length + 4 + 32);
  buf.writeUInt32BE(name.length, 0);
  name.copy(buf, 4);
  buf.writeUInt32BE(32, 4 + name.length);
  Buffer.alloc(32, fill).copy(buf, 4 + name.length + 4);
  return `ssh-ed25519 ${buf.toString('base64')} t@x`;
}

async function rig() {
  const reg = new MemoryRegistry({ NODE_ENV: 'test' });
  await reg.enroll({ tenantId: 'acme', userId: 'u-a', keyId: 'k-a', hostId: HOST_A, hostname: 'a', sshPubkey: sshKey(1) });
  await reg.enroll({ tenantId: 'acme', userId: 'u-a', keyId: 'k-a', hostId: HOST_A2, hostname: 'a2', sshPubkey: sshKey(2) });
  await reg.enroll({ tenantId: 'beta', userId: 'u-b', keyId: 'k-b', hostId: HOST_B, hostname: 'b', sshPubkey: sshKey(3) });
  return reg;
}

function jobId() {
  return `sjb_${crypto.randomBytes(16).toString('base64url')}`;
}

function jobRow(over = {}) {
  return {
    job_id: jobId(),
    tenant_id: 'acme',
    host_id: HOST_A,
    actor: 'u-a',
    source: 'api',
    script_sha256: 'a'.repeat(64),
    entitlements_sha256: 'b'.repeat(64),
    entitlements: { allow_exec: true },
    timeout_s: 300,
    deadline_at: new Date(Date.now() + 300000),
    lease_nonce: crypto.randomBytes(16).toString('hex'),
    dispatch: { script: 'print(1)', entitlements: {}, lease: { nonce_hex: 'x' } },
    ...over
  };
}

function events(reg) {
  const seen = [];
  reg.onJobEvent((e) => seen.push(e));
  return seen;
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

test('createJob validates the row, binds the host to the tenant, writes the submit audit row and publishes dispatch after it', async () => {
  const reg = await rig();
  const seen = events(reg);
  await assert.rejects(reg.createJob(jobRow({ job_id: 'sjb_short' })), (e) => e.status === 400 && e.code === 'bad_job');
  await assert.rejects(reg.createJob(jobRow({ source: 'cron' })), (e) => e.code === 'bad_job');
  await assert.rejects(reg.createJob(jobRow({ timeout_s: 3601 })), (e) => e.code === 'bad_job');
  await assert.rejects(reg.createJob(jobRow({ dispatch: null })), (e) => e.code === 'bad_job');
  await assert.rejects(reg.createJob(jobRow({ host_id: HOST_B })), (e) => e.status === 404, 'a host of another tenant');

  const row = jobRow();
  const job = await reg.createJob(row);
  assert.equal(job.status, 'submitted');
  assert.equal('dispatch' in job, false, 'the script never leaves through a read');
  assert.ok(job.deadline_at instanceof Date && job.created_at instanceof Date);
  await assert.rejects(reg.createJob({ ...row }), (e) => e.status === 409);
  assert.deepEqual(seen, [], 'delivered after the current turn, like a NOTIFY after COMMIT');
  await tick();
  assert.deepEqual(seen, [{ k: 'dispatch', job_id: row.job_id, host_id: HOST_A, status: 'submitted' }]);

  const audit = reg.audit.filter((a) => a.action === 'sysscript_job_submit');
  assert.equal(audit.length, 1);
  assert.deepEqual(audit[0].payload, {
    job_id: row.job_id, script_sha256: row.script_sha256, entitlements_sha256: row.entitlements_sha256,
    timeout_s: 300, lease_nonce: row.lease_nonce, source: 'api'
  });
  assert.equal((await reg.verifyAudit()).ok, true);

  // A failed audit write leaves no row and no event.
  const real = reg.appendAudit;
  reg.appendAudit = async () => { throw new Error('audit refused'); };
  const failed = jobRow();
  await assert.rejects(reg.createJob(failed), /audit refused/);
  reg.appendAudit = real;
  await tick();
  assert.equal(await reg.getJob(['acme'], failed.job_id), null);
  assert.equal(seen.length, 1);
});

test('reads and cancel carry the tenant predicate', async () => {
  const reg = await rig();
  const a = jobRow();
  const b = jobRow({ tenant_id: 'beta', host_id: HOST_B, actor: 'u-b' });
  await reg.createJob(a);
  await reg.createJob(b);
  assert.equal(await reg.getJob(['beta'], a.job_id), null);
  assert.equal(await reg.getJob([], a.job_id), null);
  assert.equal((await reg.getJob(['acme'], a.job_id)).job_id, a.job_id);
  assert.deepEqual((await reg.listJobs(['beta'])).map((j) => j.job_id), [b.job_id]);
  assert.deepEqual(await reg.listJobs([]), []);
  assert.equal(await reg.requestJobCancel(['beta'], a.job_id, 'u-b'), null);
  assert.equal((await reg.getJob(['acme'], a.job_id)).cancel_requested_at, null);
  assert.equal(reg.audit.some((r) => r.action === 'sysscript_job_cancel'), false);
});

test('listJobs never returns output and filters by host, status and limit', async () => {
  const reg = await rig();
  const a = jobRow();
  await reg.createJob(a);
  await reg.createJob(jobRow({ host_id: HOST_A2 }));
  await reg.markDispatched(a.job_id, HOST_A, 'c1');
  await reg.transitionJob(a.job_id, HOST_A, ['submitted', 'accepted', 'running'], { status: 'succeeded', output: 'secret out' });
  const all = await reg.listJobs(['acme']);
  assert.equal(all.length, 2);
  assert.ok(all.every((j) => !('output' in j) && !('dispatch' in j)));
  assert.deepEqual((await reg.listJobs(['acme'], { hostId: HOST_A2 })).map((j) => j.host_id), [HOST_A2]);
  assert.deepEqual((await reg.listJobs(['acme'], { status: 'succeeded' })).map((j) => j.job_id), [a.job_id]);
  assert.equal((await reg.listJobs(['acme'], { limit: 1 })).length, 1);
  await assert.rejects(reg.listJobs(['acme'], { status: 'bogus' }), (e) => e.code === 'bad_status');
  assert.equal((await reg.getJob(['acme'], a.job_id)).output, 'secret out');
});

test('markDispatched claims the dispatch payload once, for the right host only', async () => {
  const reg = await rig();
  const a = jobRow();
  await reg.createJob(a);
  assert.equal(await reg.markDispatched(a.job_id, HOST_A2, 'c1'), null, 'another host');
  const claimed = await reg.markDispatched(a.job_id, HOST_A, 'c1');
  assert.deepEqual(claimed.dispatch, a.dispatch);
  assert.equal(claimed.conn_id, 'c1');
  assert.ok(claimed.sent_at instanceof Date);
  assert.equal(await reg.markDispatched(a.job_id, HOST_A, 'c2'), null, 'already claimed');
  assert.equal(reg.jobs.get(a.job_id).dispatch, null, 'the script is not kept after dispatch');
});

test('transitionJob is guarded by host, from-status and conn_id; terminal rows never change', async () => {
  const reg = await rig();
  const seen = events(reg);
  const a = jobRow();
  await reg.createJob(a);
  await reg.markDispatched(a.job_id, HOST_A, 'c1');

  assert.equal(await reg.transitionJob(a.job_id, HOST_A2, ['submitted'], { status: 'accepted' }), null, 'wrong host');
  assert.equal(await reg.transitionJob(a.job_id, HOST_A, ['accepted'], { status: 'running' }), null, 'wrong from');
  assert.equal(await reg.transitionJob(a.job_id, HOST_A, ['submitted'], { status: 'accepted' }, { connId: 'c2' }), null, 'wrong conn');
  assert.equal(await reg.transitionJob('sjb_unknownunknownunknow', HOST_A, ['submitted'], { status: 'accepted' }), null);
  assert.equal((await reg.getJob(['acme'], a.job_id)).status, 'submitted');

  const acc = await reg.transitionJob(a.job_id, HOST_A, ['submitted'], { status: 'accepted' }, { connId: 'c1', notify: true });
  assert.equal(acc.status, 'accepted');
  assert.ok(acc.accepted_at instanceof Date);
  const run = await reg.transitionJob(a.job_id, HOST_A, ['submitted', 'accepted'], { status: 'running' });
  assert.ok(run.started_at instanceof Date);

  const done = await reg.transitionJob(a.job_id, HOST_A, ['submitted', 'accepted', 'running'],
    { status: 'succeeded', output: 'ok', output_truncated: true, duration_ms: 812, error: null },
    { audit: { actor: 'agent' }, notify: true });
  assert.equal(done.status, 'succeeded');
  assert.equal(done.output, 'ok');
  assert.equal(done.output_truncated, true);
  assert.ok(done.finished_at instanceof Date);
  const end = reg.audit.filter((r) => r.action === 'sysscript_job_end');
  assert.equal(end.length, 1);
  assert.deepEqual(end[0].payload, { job_id: a.job_id, status: 'succeeded', error_code: null, duration_ms: 812, alerts: 0 });
  assert.equal(end[0].actor, 'agent');
  assert.equal(end[0].tenant_id, 'acme');

  // A re-sent result for the terminal row changes nothing.
  assert.equal(await reg.transitionJob(a.job_id, HOST_A, ['submitted', 'accepted', 'running'], { status: 'failed', output: 'evil' }), null);
  assert.equal((await reg.getJob(['acme'], a.job_id)).output, 'ok');
  await assert.rejects(reg.transitionJob(a.job_id, HOST_A, ['succeeded'], { status: 'failed' }), (e) => e.code === 'bad_job_transition');
  await assert.rejects(reg.transitionJob(a.job_id, HOST_A, ['running'], { status: 'running' }), (e) => e.code === 'bad_job_transition');
  await assert.rejects(reg.transitionJob(a.job_id, HOST_A, ['running'], { status: 'submitted' }), (e) => e.code === 'bad_job_transition');

  await tick();
  assert.deepEqual(seen.filter((e) => e.k === 'state').map((e) => e.status), ['accepted', 'succeeded']);
});

test('a transition whose audit row fails is rolled back and publishes nothing', async () => {
  const reg = await rig();
  const a = jobRow();
  await reg.createJob(a);
  await reg.markDispatched(a.job_id, HOST_A, 'c1');
  await tick();
  const seen = events(reg);
  const real = reg.appendAudit;
  reg.appendAudit = async () => { throw new Error('audit refused'); };
  await assert.rejects(reg.transitionJob(a.job_id, HOST_A, ['submitted'], { status: 'failed', error: 'x' }, { audit: { actor: 'agent' }, notify: true }), /audit refused/);
  reg.appendAudit = real;
  await tick();
  const row = await reg.getJob(['acme'], a.job_id);
  assert.equal(row.status, 'submitted');
  assert.equal(row.finished_at, null);
  assert.deepEqual(seen, []);
});

test('bumpJobAlert stores 20 per job, refuses the rest, and is bound to the host and to accepted/running', async () => {
  const reg = await rig();
  const a = jobRow();
  await reg.createJob(a);
  assert.deepEqual(await reg.bumpJobAlert(a.job_id, HOST_A, 20), { ok: false, reason: 'unknown_execution' }, 'still submitted');
  await reg.markDispatched(a.job_id, HOST_A, 'c1');
  await reg.transitionJob(a.job_id, HOST_A, ['submitted'], { status: 'running' });
  assert.deepEqual(await reg.bumpJobAlert(a.job_id, HOST_B, 20), { ok: false, reason: 'unknown_execution' }, 'another host');
  const out = await Promise.all(Array.from({ length: 25 }, () => reg.bumpJobAlert(a.job_id, HOST_A, 20)));
  assert.equal(out.filter((r) => r.ok).length, 20);
  assert.ok(out.filter((r) => r.ok).every((r) => r.tenant_id === 'acme'));
  assert.equal(out.filter((r) => r.reason === 'rate_limited').length, 5);
  assert.equal((await reg.getJob(['acme'], a.job_id)).alert_count, 20);
});

test('requestJobCancel: a sent job gets cancel_requested once; an unsent one ends cancelled; a finished one is 409', async () => {
  const reg = await rig();
  const seen = events(reg);
  const sent = jobRow();
  const unsent = jobRow();
  await reg.createJob(sent);
  await reg.createJob(unsent);
  await reg.markDispatched(sent.job_id, HOST_A, 'c1');
  await tick();
  seen.length = 0;

  const c = await reg.requestJobCancel(['acme'], sent.job_id, 'u-a');
  assert.equal(c.status, 'submitted');
  assert.ok(c.cancel_requested_at instanceof Date);
  assert.equal(c.cancel_actor, 'u-a');
  const again = await reg.requestJobCancel(['acme'], sent.job_id, 'someone-else');
  assert.equal(again.cancel_actor, 'u-a');
  assert.equal(reg.audit.filter((r) => r.action === 'sysscript_job_cancel').length, 1);
  assert.deepEqual((await reg.pendingForHosts([HOST_A])).find((p) => p.job_id === sent.job_id),
    { job_id: sent.job_id, host_id: HOST_A, status: 'submitted', dispatch_pending: false, cancel_pending: true });
  assert.equal(await reg.markCancelSent(sent.job_id, HOST_A2), null);
  assert.ok((await reg.markCancelSent(sent.job_id, HOST_A)).cancel_sent_at instanceof Date);
  assert.equal((await reg.pendingForHosts([HOST_A])).some((p) => p.job_id === sent.job_id), false);

  const u = await reg.requestJobCancel(['acme'], unsent.job_id, 'u-a');
  assert.equal(u.status, 'cancelled');
  assert.equal(u.error, 'cancelled_before_dispatch');
  assert.equal(await reg.markDispatched(unsent.job_id, HOST_A, 'c1'), null, 'nothing left to dispatch');
  await assert.rejects(reg.requestJobCancel(['acme'], unsent.job_id, 'u-a'), (e) => e.status === 409 && e.code === 'job_finished');
  assert.equal(reg.audit.filter((r) => r.action === 'sysscript_job_end').length, 1);
  await tick();
  assert.deepEqual(seen.map((e) => [e.k, e.job_id]), [['cancel', sent.job_id], ['state', unsent.job_id]]);
  assert.equal((await reg.verifyAudit()).ok, true);
});

test('sweepJobs ends dispatch_timeout, agent_no_ack (connected conn only) and result_lost rows with end audit rows', async () => {
  const reg = await rig();
  const never = jobRow();
  const noAck = jobRow();
  const offline = jobRow();
  const lost = jobRow({ host_id: HOST_A2, deadline_at: new Date(Date.now() + 1000) });
  const fresh = jobRow({ host_id: HOST_A2 });
  for (const r of [never, noAck, offline, lost, fresh]) await reg.createJob(r);
  await reg.markDispatched(noAck.job_id, HOST_A, 'live');
  await reg.markDispatched(offline.job_id, HOST_A, 'gone');
  await reg.markDispatched(lost.job_id, HOST_A2, 'live');
  await reg.transitionJob(lost.job_id, HOST_A2, ['submitted'], { status: 'running' });
  await reg.markDispatched(fresh.job_id, HOST_A2, 'live');

  assert.deepEqual(await reg.sweepJobs(Date.now(), { connectedConnIds: ['live'] }), [], 'nothing overdue yet');
  // fresh: as if sent 10 s before the sweep, inside the 15 s ack window.
  reg.jobs.get(fresh.job_id).sent_at = new Date(Date.now() + 60000);
  const ended = await reg.sweepJobs(Date.now() + 70000, { connectedConnIds: ['live'] });
  const byId = Object.fromEntries(ended.map((j) => [j.job_id, j.error]));
  assert.deepEqual(byId, {
    [never.job_id]: 'dispatch_timeout',
    [noAck.job_id]: 'agent_no_ack',
    [lost.job_id]: 'result_lost'
  });
  assert.ok(ended.every((j) => j.status === 'failed' && j.finished_at instanceof Date));
  assert.equal((await reg.getJob(['acme'], offline.job_id)).status, 'submitted', 'a disconnected conn waits for sync or the deadline');
  assert.equal((await reg.getJob(['acme'], fresh.job_id)).status, 'submitted');
  const end = reg.audit.filter((r) => r.action === 'sysscript_job_end');
  assert.equal(end.length, 3);
  assert.ok(end.every((r) => r.actor === 'system'));
  assert.equal(reg.jobs.get(never.job_id).dispatch, null);
});

test('reconcileHostJobs ends only rows sent on another connection and absent from the sync lists', async () => {
  const reg = await rig();
  const listedActive = jobRow();
  const listedUnacked = jobRow();
  const missing = jobRow();
  const thisConn = jobRow();
  const neverSent = jobRow();
  const otherHost = jobRow({ host_id: HOST_A2 });
  for (const r of [listedActive, listedUnacked, missing, thisConn, neverSent, otherHost]) await reg.createJob(r);
  for (const r of [listedActive, listedUnacked, missing]) await reg.markDispatched(r.job_id, HOST_A, 'old');
  await reg.markDispatched(thisConn.job_id, HOST_A, 'new');
  await reg.markDispatched(otherHost.job_id, HOST_A2, 'old');

  await assert.rejects(reg.reconcileHostJobs(HOST_A, 'new', 'nope'), (e) => e.code === 'bad_job_sync');
  const ended = await reg.reconcileHostJobs(HOST_A, 'new', [listedActive.job_id, listedUnacked.job_id, 'junk']);
  assert.deepEqual(ended.map((j) => [j.job_id, j.status, j.error]), [[missing.job_id, 'failed', 'agent_lost_job']]);
  for (const r of [listedActive, listedUnacked]) {
    assert.equal((await reg.getJob(['acme'], r.job_id)).status, 'accepted', 'being listed in sync is an ack');
  }
  for (const r of [thisConn, neverSent, otherHost]) {
    assert.equal((await reg.getJob(['acme'], r.job_id)).status, 'submitted');
  }
  assert.equal(reg.audit.filter((r) => r.action === 'sysscript_job_end').length, 1);
});

test('expireOutput nulls old output and keeps the row; pruneJobs deletes old terminal rows only', async () => {
  const reg = await rig();
  const old = jobRow();
  const recent = jobRow();
  const active = jobRow();
  for (const r of [old, recent, active]) await reg.createJob(r);
  for (const r of [old, recent]) {
    await reg.markDispatched(r.job_id, HOST_A, 'c1');
    await reg.transitionJob(r.job_id, HOST_A, ['submitted'], { status: 'succeeded', output: 'out' });
  }
  reg.jobs.get(old.job_id).finished_at = new Date(Date.now() - 73 * 3600000);
  reg.jobs.get(active.job_id).finished_at = new Date(Date.now() - 100 * 86400000);
  assert.equal(await reg.expireOutput(72), 1);
  const o = await reg.getJob(['acme'], old.job_id);
  assert.equal(o.output, null);
  assert.equal(o.output_expired, true);
  assert.equal((await reg.getJob(['acme'], recent.job_id)).output, 'out');

  reg.jobs.get(old.job_id).finished_at = new Date(Date.now() - 31 * 86400000);
  assert.equal(await reg.pruneJobs(30), 1);
  assert.equal(await reg.getJob(['acme'], old.job_id), null);
  assert.ok(await reg.getJob(['acme'], recent.job_id));
  assert.ok(await reg.getJob(['acme'], active.job_id), 'a non-terminal row is never pruned');
});

test('the caps are atomic: of 20 concurrent creates exactly the host cap succeed; the tenant cap holds across hosts', async () => {
  const reg = await rig();
  const out = await Promise.allSettled(Array.from({ length: 20 }, () => reg.createJob(jobRow(), { hostCap: 8, tenantCap: 64 })));
  assert.equal(out.filter((r) => r.status === 'fulfilled').length, 8);
  assert.ok(out.filter((r) => r.status === 'rejected').every((r) => r.reason.status === 429 && r.reason.code === 'too_many_jobs'));
  await assert.rejects(reg.createJob(jobRow({ host_id: HOST_A2 }), { hostCap: 8, tenantCap: 8 }), (e) => e.code === 'too_many_jobs');
  assert.ok(await reg.createJob(jobRow({ host_id: HOST_A2 }), { hostCap: 8, tenantCap: 64 }));
  // Terminal rows do not count.
  const [first] = await reg.listJobs(['acme'], { hostId: HOST_A, limit: 1 });
  await reg.markDispatched(first.job_id, HOST_A, 'c1');
  await reg.transitionJob(first.job_id, HOST_A, ['submitted'], { status: 'failed' });
  assert.ok(await reg.createJob(jobRow(), { hostCap: 8 }));
});

test('job events: malformed ones are not published; a throwing handler does not stop the others; unsubscribe works', async () => {
  const reg = await rig();
  assert.equal(reg.publishJobEvent({ k: 'evil', job_id: jobId(), host_id: HOST_A }), false);
  assert.equal(reg.publishJobEvent({ k: 'state', job_id: 'x', host_id: HOST_A }), false);
  const seen = [];
  const offThrow = reg.onJobEvent(() => { throw new Error('boom'); });
  const off = reg.onJobEvent((e) => seen.push(e));
  await off.ready;
  const realError = console.error;
  console.error = () => {};
  try {
    assert.equal(reg.publishJobEvent({ k: 'state', job_id: jobId(), host_id: HOST_A, status: 'running' }), true);
    await tick();
  } finally {
    console.error = realError;
  }
  assert.equal(seen.length, 1);
  off();
  offThrow();
  reg.publishJobEvent({ k: 'state', job_id: jobId(), host_id: HOST_A });
  await tick();
  assert.equal(seen.length, 1);
});

test('retention settings default and clamp', () => {
  assert.equal(jobRetentionDays({}), 30);
  assert.equal(jobRetentionDays({ SYSTEMAPI_JOB_RETENTION_DAYS: '7' }), 7);
  assert.equal(jobRetentionDays({ SYSTEMAPI_JOB_RETENTION_DAYS: '0' }), 30);
  assert.equal(jobOutputRetentionHours({}), 72);
  assert.equal(jobOutputRetentionHours({ SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS: '8760' }), 8760);
  assert.equal(jobOutputRetentionHours({ SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS: '8761' }), 72);
});

test('stored output is capped at 1 MiB of UTF-8 on a character boundary, with output_truncated', async () => {
  const reg = await rig();
  const a = jobRow();
  await reg.createJob(a);
  await reg.markDispatched(a.job_id, HOST_A, 'c1');
  const big = 'x'.repeat(1024 * 1024 - 1) + 'é' + 'tail';
  const done = await reg.transitionJob(a.job_id, HOST_A, ['submitted'], { status: 'succeeded', output: big, output_truncated: false });
  assert.equal(done.output_truncated, true);
  assert.equal(Buffer.byteLength(done.output, 'utf8'), 1024 * 1024 - 1, 'the 2-byte character is not split');
  assert.equal(done.output.includes('�'), false);
});

test('the end audit row carries only a code-shaped error; free text stays on the row', async () => {
  const reg = await rig();
  const a = jobRow();
  const b = jobRow();
  await reg.createJob(a);
  await reg.createJob(b);
  await reg.markDispatched(a.job_id, HOST_A, 'c1');
  await reg.markDispatched(b.job_id, HOST_A, 'c1');
  await reg.transitionJob(a.job_id, HOST_A, ['submitted'], { status: 'failed', error: 'Traceback: secret /etc/shadow' }, { audit: { actor: 'agent' } });
  await reg.transitionJob(b.job_id, HOST_A, ['submitted'], { status: 'failed', error: 'agent_busy' }, { audit: { actor: 'agent' } });
  const codes = Object.fromEntries(reg.audit.filter((r) => r.action === 'sysscript_job_end').map((r) => [r.payload.job_id, r.payload.error_code]));
  assert.deepEqual(codes, { [a.job_id]: 'agent_error', [b.job_id]: 'agent_busy' });
  assert.equal((await reg.getJob(['acme'], a.job_id)).error, 'Traceback: secret /etc/shadow');
});

test('createJob refuses a deadline that is not in the future; a duplicate id is 409 even at the cap', async () => {
  const reg = await rig();
  await assert.rejects(reg.createJob(jobRow({ deadline_at: new Date(Date.now() - 1) })), (e) => e.code === 'bad_job');
  const a = jobRow();
  await reg.createJob(a, { hostCap: 1 });
  await assert.rejects(reg.createJob({ ...a }, { hostCap: 1 }), (e) => e.status === 409);
});

test('a failed audit write puts back only the fields the change wrote', async () => {
  const reg = await rig();
  const a = jobRow();
  await reg.createJob(a);
  await reg.markDispatched(a.job_id, HOST_A, 'c1');
  await reg.transitionJob(a.job_id, HOST_A, ['submitted'], { status: 'running' });
  const real = reg.appendAudit;
  let release;
  reg.appendAudit = () => new Promise((resolve, reject) => { release = () => reject(new Error('audit refused')); });
  const pending = reg.transitionJob(a.job_id, HOST_A, ['running'], { status: 'failed', error: 'x' }, { audit: { actor: 'agent' } });
  // An alert lands while the audit write is in flight.
  reg.jobs.get(a.job_id).alert_count = 3;
  release();
  await assert.rejects(pending, /audit refused/);
  reg.appendAudit = real;
  const row = await reg.getJob(['acme'], a.job_id);
  assert.equal(row.status, 'running');
  assert.equal(row.error, null);
  assert.equal(row.finished_at, null);
  assert.equal(row.alert_count, 3, 'the concurrent write survives');
});

test('reconcileHostJobs moves listed rows to the new connection', async () => {
  const reg = await rig();
  const a = jobRow();
  const done = jobRow();
  await reg.createJob(a);
  await reg.createJob(done);
  await reg.markDispatched(a.job_id, HOST_A, 'old');
  await reg.markDispatched(done.job_id, HOST_A, 'old');
  await reg.transitionJob(done.job_id, HOST_A, ['submitted'], { status: 'succeeded' });
  await reg.reconcileHostJobs(HOST_A, 'new', [a.job_id, done.job_id]);
  const listed = await reg.getJob(['acme'], a.job_id);
  assert.equal(listed.conn_id, 'new');
  assert.equal(listed.status, 'accepted', 'being listed in sync is an ack');
  assert.ok(listed.accepted_at instanceof Date);
  assert.equal((await reg.getJob(['acme'], done.job_id)).conn_id, 'old', 'terminal rows never change');
  // Long after the ack window, the listed job is not ended agent_no_ack.
  assert.deepEqual(await reg.sweepJobs(Date.now() + 30000, { connectedConnIds: ['new'] }), []);
  assert.ok(await reg.transitionJob(a.job_id, HOST_A, ['accepted'], { status: 'running' }, { connId: 'new' }));
});

test('one sweep ends at most 500 rows; the next tick ends the rest', async () => {
  const reg = await rig();
  for (let i = 0; i < 501; i += 1) await reg.createJob(jobRow(), { hostCap: 1000, tenantCap: 1000 });
  const later = Date.now() + 120000;
  assert.equal((await reg.sweepJobs(later)).length, 500);
  assert.equal((await reg.sweepJobs(later)).length, 1);
  assert.equal((await reg.listJobs(['acme'], { status: 'submitted' })).length, 0);
});

test('a rejecting async event handler is logged and does not stop the others', async () => {
  const reg = await rig();
  const seen = [];
  const logged = [];
  const offBad = reg.onJobEvent(async () => { throw new Error('async boom'); });
  const off = reg.onJobEvent((e) => seen.push(e));
  const realError = console.error;
  console.error = (msg) => logged.push(msg);
  try {
    reg.publishJobEvent({ k: 'state', job_id: jobId(), host_id: HOST_A, status: 'running' });
    await tick();
    await tick();
  } finally {
    console.error = realError;
    offBad();
    off();
  }
  assert.equal(seen.length, 1);
  assert.ok(logged.some((m) => /async boom/.test(m)));
});
