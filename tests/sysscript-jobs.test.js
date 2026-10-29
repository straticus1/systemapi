'use strict';

// Async sysscript jobs, server side (.omc/plans/async-sysscript-jobs.md §6,
// §8, commit 6a): the /jobs routes, playground/jobs.js and its agent frames,
// driven by a fake agent over a real WebSocket (tests/job-agent-rig.js) that
// verifies every sysscript_job lease and canonical entitlements hash.

const test = require('node:test');
const assert = require('node:assert/strict');

const { MemoryRegistry } = require('../controlplane/registry');
const { rig, connectAgent, waitUntil } = require('./job-agent-rig');
const { tickSchedules } = require('../controlplane/index');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const HOST_C = '33333333-3333-4333-8333-333333333333';
const KEYS = {
  'agent-key': { key_id: 'k-agent', user_id: 'user-1' },
  'beta-agent': { key_id: 'k-beta-agent', user_id: 'user-2' },
  'admin-key': { key_id: 'k-admin', user_id: 'user-1' },
  'op-key': { key_id: 'k-op', user_id: 'user-3' },
  'op2-key': { key_id: 'k-op2', user_id: 'user-6' },
  'view-key': { key_id: 'k-view', user_id: 'user-4' },
  'beta-key': { key_id: 'k-beta', user_id: 'user-2' },
  'mixed-key': { key_id: 'k-mixed', user_id: 'user-5' }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// acme: user-1 admin (enrolls HOST_A/HOST_B), user-3 and user-6 operators,
// user-4 viewer, user-5 operator. beta: user-2 admin (enrolls HOST_C),
// user-5 viewer. Every key's own scopes are admin, so the role decides.
// caps: what HOST_A's agent advertises (default sysscript_jobs).
async function world({ env = {}, registry = new MemoryRegistry({ NODE_ENV: 'test' }), agent = true, caps } = {}) {
  const r = await rig({ registry, keys: KEYS, env });
  for (const { key_id: id } of Object.values(KEYS)) await registry.setScopes(id, ['admin']);
  const a = agent ? await connectAgent(r, HOST_A, caps === undefined ? {} : { caps }) : null;
  await registry.addMember('acme', 'user-3', 'operator');
  await registry.addMember('acme', 'user-6', 'operator');
  await registry.addMember('acme', 'user-4', 'viewer');
  await registry.addMember('acme', 'user-5', 'operator');
  return { r, reg: registry, a };
}

async function submit(r, key, hostId, body = {}) {
  return r.api('POST', `/api/v1/fleet/${hostId}/jobs`, key, { script: 'print("hi")', ...body });
}

async function row(reg, jobId) {
  return reg.jobs.get(jobId);
}

// Submits as key and returns the job id once the agent received the frame.
async function dispatched(r, agent, key = 'op-key', body = {}) {
  const res = await submit(r, key, agent.hostId, body);
  assert.equal(res.status, 202, JSON.stringify(res.body));
  const job = await agent.waitJob(res.body.job_id);
  assert.equal(job.lease.ok, true, job.lease.error);
  return res.body.job_id;
}

async function ended(reg, jobId, status) {
  return waitUntil(`${jobId} ${status}`, async () => {
    const j = await row(reg, jobId);
    return j && j.status === status && j;
  });
}

test('submit returns 202 at once; the frame carries a valid lease; accepted, running, result; acked; audited', async () => {
  const { r, reg, a } = await world();
  try {
    const t0 = Date.now();
    const res = await submit(r, 'op-key', HOST_A, { timeout_s: 120 });
    assert.ok(Date.now() - t0 < 1000);
    assert.equal(res.status, 202);
    assert.match(res.body.job_id, /^sjb_[A-Za-z0-9_-]{22}$/);
    assert.equal(res.body.status, 'submitted');
    const id = res.body.job_id;
    const { frame, lease } = await a.waitJob(id);
    assert.equal(lease.ok, true);
    assert.equal(frame.script, 'print("hi")');
    assert.equal(frame.timeout_s, 120);
    assert.equal(frame.deadline_unix, res.body.deadline_unix);
    const stored = await row(reg, id);
    assert.equal(stored.dispatch, null, 'the script is not kept after dispatch');
    assert.ok(stored.conn_id.startsWith(`${r.fm.jobs.instanceId}:`));
    assert.equal(stored.source, 'api');
    assert.equal(stored.actor, 'user-3');

    a.status(id, { status: 'accepted', deadline_unix: frame.deadline_unix, queued: true });
    a.status(id, { status: 'running', started_unix: Math.floor(Date.now() / 1000) });
    await ended(reg, id, 'running');
    a.result(id, { status: 'succeeded', output: 'hi\n', duration_ms: 90000 });
    await a.waitFor('sysscript_job_ack', id);
    const got = await r.api('GET', `/api/v1/jobs/${id}`, 'op-key');
    assert.equal(got.status, 200);
    assert.equal(got.body.job.status, 'succeeded');
    assert.equal(got.body.job.output, 'hi\n');
    assert.equal(got.body.job.output_visible, true);
    assert.equal(got.body.job.duration_ms, 90000);
    assert.equal(got.body.job.error, null);
    assert.equal(got.body.job.conn_id, undefined);
    assert.equal(got.body.job.lease_nonce, undefined);

    const submitRow = reg.audit.find((x) => x.action === 'sysscript_job_submit');
    assert.equal(submitRow.payload.job_id, id);
    assert.equal(submitRow.payload.lease_nonce, frame.lease.nonce_hex);
    assert.equal(submitRow.payload.source, 'api');
    const endRow = reg.audit.find((x) => x.action === 'sysscript_job_end');
    assert.deepEqual(endRow.payload, { job_id: id, status: 'succeeded', error_code: null, duration_ms: 90000, alerts: 0 });
    assert.equal(endRow.actor, 'agent');
    const verify = await r.api('GET', '/api/v1/audit/verify', 'admin-key');
    assert.equal(verify.status, 200);
    assert.equal(verify.body.ok, true);
  } finally {
    await r.close();
  }
});

test('wait_s answers 200 {job} when the job ends in time, 202 when it does not', async () => {
  const { r, a } = await world();
  try {
    const p = submit(r, 'op-key', HOST_A, { wait_s: 5 });
    const { frame } = await a.waitJob();
    a.status(frame.job_id, { status: 'accepted' });
    a.result(frame.job_id, { status: 'timed_out', error: 'script timed out' });
    const res = await p;
    assert.equal(res.status, 200);
    assert.equal(res.body.job.status, 'timed_out');
    assert.equal(res.body.job.error, 'script timed out');

    const t0 = Date.now();
    const slow = await submit(r, 'op-key', HOST_A, { wait_s: 1 });
    assert.equal(slow.status, 202);
    assert.ok(Date.now() - t0 >= 900);
  } finally {
    await r.close();
  }
});

test('the frame carries exactly the clamped entitlements the lease hashed; a non-admin gets none of the admin ones', async () => {
  const { r, a } = await world();
  try {
    const ents = {
      allow_exec: true, allow_k8s: true, allow_packages: ['nginx', 'curl', 'nginx', 'bad*'], allow_sysctl: ['kernel.modprobe', 'vm.swappiness']
    };
    const id = await dispatched(r, a, 'admin-key', { entitlements: ents });
    const { frame } = a.jobs.get(id);
    assert.equal(frame.entitlements.allow_exec, true);
    assert.equal(frame.entitlements.allow_k8s, true);
    assert.deepEqual(frame.entitlements.allow_packages, ['nginx', 'curl', 'nginx']);
    assert.deepEqual(frame.entitlements.allow_sysctl, ['vm.swappiness']);

    const op = await dispatched(r, a, 'op-key', { entitlements: ents });
    const opFrame = a.jobs.get(op).frame;
    assert.equal(opFrame.entitlements.allow_exec, true);
    assert.equal(opFrame.entitlements.allow_k8s, false);
    assert.deepEqual(opFrame.entitlements.allow_packages, []);

    // A lone surrogate cannot be put in canonical form: 400 before signing.
    const bad = await r.api('POST', `/api/v1/fleet/${HOST_A}/jobs`, 'admin-key', '{"script":"x","entitlements":{"allow_packages":["\\ud800"]}}');
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error, 'bad_entitlements');
    const arr = await submit(r, 'op-key', HOST_A, { entitlements: ['allow_exec'] });
    assert.equal(arr.body.error, 'bad_entitlements');
  } finally {
    await r.close();
  }
});

test('submit refusals: script, timeout, wait, scope, host, agent offline or unsupported, kill switch, caps', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_SYSSCRIPT_JOB_MAX_S: '600' } });
  try {
    const cases = [
      [{ script: '' }, 'bad_script'],
      [{ script: 'x'.repeat(64 * 1024 + 1) }, 'bad_script'],
      [{ script: 'é'.repeat(40 * 1024) }, 'bad_script'],
      [{ timeout_s: 0 }, 'bad_timeout'],
      [{ timeout_s: 601 }, 'bad_timeout'],
      [{ timeout_s: '30' }, 'bad_timeout'],
      [{ wait_s: 26 }, 'bad_wait'],
      [{ wait_s: -1 }, 'bad_wait']
    ];
    for (const [body, code] of cases) {
      const res = await submit(r, 'op-key', HOST_A, body);
      assert.equal(res.status, 400, code);
      assert.equal(res.body.error, code);
    }
    assert.equal((await submit(r, 'view-key', HOST_A)).status, 403);
    const foreign = await submit(r, 'op-key', HOST_C);
    assert.equal(foreign.status, 404);
    assert.ok(reg.securityEvents.some((e) => e.kind === 'idor'));

    // HOST_B enrolled once, then gone: offline. An agent without the
    // capability: 501.
    const b = await connectAgent(r, HOST_B, { caps: '' });
    assert.equal((await submit(r, 'op-key', HOST_B)).body.error, 'agent_unsupported');
    b.ws.terminate();
    await waitUntil('B offline', () => !r.fm.connectedAgents.has(HOST_B));
    const off = await submit(r, 'op-key', HOST_B);
    assert.equal(off.status, 409);
    assert.equal(off.body.error, 'agent_offline');

    // The agent's workers and queue are full: failed[agent_busy] at once.
    const busy = await dispatched(r, a);
    a.result(busy, { status: 'rejected', error: 'agent_busy' });
    const failed = await ended(reg, busy, 'failed');
    assert.equal(failed.error, 'agent_busy');

    // Eight live jobs per host; the ninth is 429.
    const live = [];
    for (let i = 0; i < 8; i += 1) live.push(await submit(r, 'op-key', HOST_A));
    assert.ok(live.every((x) => x.status === 202));
    const ninth = await submit(r, 'op-key', HOST_A);
    assert.equal(ninth.status, 429);
    assert.equal(ninth.body.error, 'too_many_jobs');

    r.fm.env.SYSTEMAPI_SYSSCRIPT_JOBS = '0';
    for (const [method, path] of [['POST', `/api/v1/fleet/${HOST_A}/jobs`], ['GET', '/api/v1/jobs'],
      ['GET', `/api/v1/jobs/${busy}`], ['POST', `/api/v1/jobs/${busy}/cancel`]]) {
      const res = await r.api(method, path, 'op-key', method === 'POST' ? { script: 'x' } : undefined);
      assert.equal(res.status, 503, path);
      assert.equal(res.body.error, 'jobs_disabled');
    }
  } finally {
    await r.close();
  }
});

test('tenant isolation: foreign 404 with an idor event, viewer 403, output only for the submitter or an admin, list per exec:run tenant', async () => {
  const { r, reg, a } = await world();
  try {
    const c = await connectAgent(r, HOST_C, { tenant: 'beta', key: 'beta-agent' });
    await reg.addMember('beta', 'user-5', 'viewer');
    const id = await dispatched(r, a, 'op-key');
    a.status(id, { status: 'accepted' });
    a.result(id, { status: 'succeeded', output: 'secret' });
    await a.waitFor('sysscript_job_ack', id);
    const betaJob = await dispatched(r, c, 'beta-key');

    const before = reg.securityEvents.filter((e) => e.kind === 'idor').length;
    assert.equal((await r.api('GET', `/api/v1/jobs/${id}`, 'beta-key')).status, 404);
    assert.equal((await r.api('POST', `/api/v1/jobs/${id}/cancel`, 'beta-key')).status, 404);
    assert.equal(reg.securityEvents.filter((e) => e.kind === 'idor').length, before + 2);
    assert.equal((await r.api('GET', `/api/v1/jobs/${id}`, 'view-key')).status, 403);
    assert.equal((await r.api('GET', '/api/v1/jobs', 'view-key')).status, 403);

    const other = await r.api('GET', `/api/v1/jobs/${id}`, 'op2-key');
    assert.equal(other.status, 200);
    assert.equal(other.body.job.status, 'succeeded');
    assert.equal(other.body.job.output, null);
    assert.equal(other.body.job.output_visible, false);
    const admin = await r.api('GET', `/api/v1/jobs/${id}`, 'admin-key');
    assert.equal(admin.body.job.output, 'secret');

    const mixed = await r.api('GET', '/api/v1/jobs', 'mixed-key');
    assert.equal(mixed.status, 200);
    assert.deepEqual(mixed.body.jobs.map((j) => j.job_id), [id]);
    assert.equal('output' in mixed.body.jobs[0], false);
    const beta = await r.api('GET', '/api/v1/jobs', 'beta-key');
    assert.deepEqual(beta.body.jobs.map((j) => j.job_id), [betaJob]);
    assert.equal((await r.api('GET', `/api/v1/jobs?host_id=${HOST_B}`, 'op-key')).body.jobs.length, 0);
    assert.equal((await r.api('GET', '/api/v1/jobs?status=nope', 'op-key')).status, 400);
    assert.equal((await r.api('GET', '/api/v1/jobs?limit=x', 'op-key')).status, 400);
  } finally {
    await r.close();
  }
});

test('cancel: submitter or admin only; delivered to the agent; cancelled result and audit; finished is 409', async () => {
  const { r, reg, a } = await world();
  try {
    const id = await dispatched(r, a, 'op-key');
    a.status(id, { status: 'accepted' });
    a.status(id, { status: 'running' });
    await ended(reg, id, 'running');
    const denied = await r.api('POST', `/api/v1/jobs/${id}/cancel`, 'op2-key');
    assert.equal(denied.status, 403);
    const res = await r.api('POST', `/api/v1/jobs/${id}/cancel`, 'op-key');
    assert.equal(res.status, 202);
    assert.ok(res.body.job.cancel_requested_at);
    const cancel = await a.waitFor('sysscript_job_cancel', id);
    assert.equal(cancel.reason, 'user');
    await waitUntil('cancel_sent_at', async () => (await row(reg, id)).cancel_sent_at);
    a.result(id, { status: 'cancelled', error: 'script cancelled' });
    await ended(reg, id, 'cancelled');
    await a.waitFor('sysscript_job_ack', id);
    const actions = reg.audit.filter((x) => x.payload && x.payload.job_id === id).map((x) => x.action);
    assert.deepEqual(actions, ['sysscript_job_submit', 'sysscript_job_cancel', 'sysscript_job_end']);
    const again = await r.api('POST', `/api/v1/jobs/${id}/cancel`, 'admin-key');
    assert.equal(again.status, 409);
    assert.equal(again.body.error, 'job_finished');

    // An admin may cancel another user's job.
    const id2 = await dispatched(r, a, 'op-key');
    assert.equal((await r.api('POST', `/api/v1/jobs/${id2}/cancel`, 'admin-key')).status, 202);
    await a.waitFor('sysscript_job_cancel', id2);
  } finally {
    await r.close();
  }
});

test('a rejected result ends only a submitted job, never an accepted or running one', async () => {
  const { r, reg, a } = await world();
  try {
    const id = await dispatched(r, a);
    a.status(id, { status: 'accepted' });
    a.result(id, { status: 'rejected', error: 'duplicate_job' });
    a.status(id, { status: 'running' });
    await ended(reg, id, 'running');
    a.result(id, { status: 'rejected', error: 'replay' });
    await sleep(100);
    assert.equal((await row(reg, id)).status, 'running');
    assert.equal(reg.audit.some((x) => x.action === 'sysscript_job_end'), false);

    const id2 = await dispatched(r, a);
    a.result(id2, { status: 'rejected', error: 'Not A Code' });
    const failed = await ended(reg, id2, 'failed');
    assert.equal(failed.error, 'agent_rejected');
    assert.equal(a.of('sysscript_job_ack', id2).length, 0);
  } finally {
    await r.close();
  }
});

test('a result for host A\'s job on host B\'s socket changes nothing, is not acked, and is a security event; a re-sent result is acked', async () => {
  const { r, reg, a } = await world();
  try {
    const b = await connectAgent(r, HOST_B);
    const id = await dispatched(r, a);
    a.status(id, { status: 'accepted' });
    b.result(id, { status: 'succeeded', output: 'forged' });
    b.status(id, { status: 'running' });
    await waitUntil('mismatch event', () => reg.securityEvents.filter((e) => e.kind === 'job_frame_host_mismatch').length >= 2);
    const cur = await row(reg, id);
    assert.equal(cur.status, 'accepted');
    assert.equal(cur.output, null);
    assert.equal(b.of('sysscript_job_ack').length, 0);
    b.result('sjb_AAAAAAAAAAAAAAAAAAAAAA', { status: 'succeeded' });
    await waitUntil('unknown event', () => reg.securityEvents.some((e) => e.kind === 'job_frame_unknown'));

    a.result(id, { status: 'succeeded', output: 'real' });
    await a.waitFor('sysscript_job_ack', id);
    const first = { ...(await row(reg, id)) };
    a.result(id, { status: 'failed', output: 'again' });
    await waitUntil('second ack', () => a.of('sysscript_job_ack', id).length === 2);
    const now = await row(reg, id);
    assert.equal(now.status, 'succeeded');
    assert.equal(now.output, 'real');
    assert.equal(now.finished_at.getTime(), first.finished_at.getTime());
    assert.equal(reg.audit.filter((x) => x.action === 'sysscript_job_end').length, 1);
  } finally {
    await r.close();
  }
});

test('alerts: 20 per job, then rate limited; an alert right before the result is stored; unknown jobs store nothing', async () => {
  const { r, reg, a } = await world();
  try {
    const id = await dispatched(r, a);
    a.status(id, { status: 'running' });
    for (let i = 0; i < 25; i += 1) a.alert(id, { severity: 'warning', message: `m${i}` });
    a.alert(id, { severity: 'loud', message: 'x' });
    await waitUntil('20 alerts', async () => (await reg.listAlerts(['acme'])).length === 20);
    await sleep(100);
    assert.equal((await reg.listAlerts(['acme'])).length, 20);
    assert.equal((await row(reg, id)).alert_count, 20);
    const audit = reg.audit.find((x) => x.action === 'sysscript_alert');
    assert.equal(audit.payload.job_id, id);
    assert.equal(audit.actor, 'agent');

    const id2 = await dispatched(r, a);
    a.status(id2, { status: 'accepted' });
    a.alert(id2, { severity: 'critical', message: 'last words' });
    a.result(id2, { status: 'succeeded' });
    await ended(reg, id2, 'succeeded');
    const alerts = await reg.listAlerts(['acme']);
    assert.ok(alerts.some((x) => x.message === 'last words' && x.host_id === HOST_A));
    assert.equal((await row(reg, id2)).alert_count, 1);
    const end = reg.audit.find((x) => x.action === 'sysscript_job_end' && x.payload.job_id === id2);
    assert.equal(end.payload.alerts, 1);

    // A message within 4096 bytes that grows past them once U+0000 becomes
    // U+FFFD is cut on a character boundary.
    const id3 = await dispatched(r, a);
    a.status(id3, { status: 'running' });
    a.alert(id3, { severity: 'info', message: 'x' + '\u0000'.repeat(4000) });
    const long = await waitUntil('long alert', async () => (await reg.listAlerts(['acme'])).find((x) => x.message.startsWith('x\uFFFD')));
    assert.ok(Buffer.byteLength(long.message, 'utf8') <= 4096);
    assert.equal(long.message, 'x' + '\uFFFD'.repeat(1365));
    a.result(id3, { status: 'succeeded' });
    await ended(reg, id3, 'succeeded');
    // The legacy path too.
    r.fm.pendingExecutions.set('req-long', { resolve() {}, reject() {}, script: 'x', hostId: HOST_A });
    const legacy = await r.fm.onAgentAlert(HOST_A, { request_id: 'req-long', payload: { severity: 'info', message: '\u0000'.repeat(4096) } });
    assert.equal(legacy.alert.message, '\uFFFD'.repeat(1365));
    r.fm.pendingExecutions.delete('req-long');
    const before = (await reg.listAlerts(['acme'])).length;

    a.alert(id2, { severity: 'critical', message: 'after the end' });
    a.alert('sjb_AAAAAAAAAAAAAAAAAAAAAA', { severity: 'critical', message: 'nobody' });
    await sleep(100);
    assert.equal((await reg.listAlerts(['acme'])).length, before);
  } finally {
    await r.close();
  }
});

test('durability: a result finished while disconnected is listed unacked, re-sent after the sync, stored once and acked', async () => {
  const { r, reg, a } = await world();
  try {
    const id = await dispatched(r, a);
    a.status(id, { status: 'accepted' });
    a.status(id, { status: 'running' });
    await ended(reg, id, 'running');
    a.ws.terminate();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    const resend = { type: 'sysscript_job_result', job_id: id, payload: { status: 'succeeded', error: '', output: 'done', output_truncated: false, duration_ms: 7 } };
    const a2 = await connectAgent(r, HOST_A, { sync: { active: [], unacked: [{ job_id: id, status: 'succeeded' }] }, resend: [resend] });
    await a2.waitFor('sysscript_job_ack', id);
    const done = await row(reg, id);
    assert.equal(done.status, 'succeeded');
    assert.equal(done.output, 'done');
    assert.equal(reg.audit.filter((x) => x.action === 'sysscript_job_end').length, 1);
    // Unacked again on the next connection (the ack was lost): acked from
    // the sync, the row unchanged.
    a2.ws.terminate();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    const a3 = await connectAgent(r, HOST_A, { sync: { active: [], unacked: [{ job_id: id, status: 'succeeded' }] } });
    await a3.waitFor('sysscript_job_ack', id);
    assert.equal(reg.audit.filter((x) => x.action === 'sysscript_job_end').length, 1);
  } finally {
    await r.close();
  }
});

test('durability: an agent restart mid-job ends it agent_lost_job; a job it still runs is rebound and survives', async () => {
  const { r, reg, a } = await world();
  try {
    const lost = await dispatched(r, a);
    const kept = await dispatched(r, a);
    a.status(lost, { status: 'running' });
    a.status(kept, { status: 'accepted' });
    await ended(reg, kept, 'accepted');
    a.ws.terminate();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    const a2 = await connectAgent(r, HOST_A, { sync: { active: [kept], unacked: [] } });
    const gone = await ended(reg, lost, 'failed');
    assert.equal(gone.error, 'agent_lost_job');
    const end = reg.audit.find((x) => x.action === 'sysscript_job_end' && x.payload.job_id === lost);
    assert.equal(end.actor, 'system');
    const still = await row(reg, kept);
    assert.equal(still.status, 'accepted');
    assert.equal(still.conn_id, r.fm.jobs.connIds.get(r.fm.connectedAgents.get(HOST_A)));
    a2.result(kept, { status: 'succeeded' });
    await a2.waitFor('sysscript_job_ack', kept);
  } finally {
    await r.close();
  }
});

test('sync: a terminal job listed active gets a cancel; an unknown id gets a cancel and a security event; a pending cancel is re-sent', async () => {
  const { r, reg, a } = await world();
  try {
    const fin = await dispatched(r, a);
    a.result(fin, { status: 'failed', error: 'boom' });
    await ended(reg, fin, 'failed');
    const cancelMe = await dispatched(r, a);
    a.status(cancelMe, { status: 'running' });
    await ended(reg, cancelMe, 'running');
    a.ws.terminate();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    // Cancelled while the agent was away: sent when it comes back.
    assert.equal((await r.api('POST', `/api/v1/jobs/${cancelMe}/cancel`, 'op-key')).status, 202);
    const unknown = 'sjb_BBBBBBBBBBBBBBBBBBBBBB';
    const a2 = await connectAgent(r, HOST_A, { sync: { active: [fin, unknown, cancelMe], unacked: [] } });
    assert.equal((await a2.waitFor('sysscript_job_cancel', fin)).reason, 'terminal');
    assert.equal((await a2.waitFor('sysscript_job_cancel', unknown)).reason, 'unknown');
    assert.equal((await a2.waitFor('sysscript_job_cancel', cancelMe)).reason, 'user');
    await waitUntil('unknown on sync', () => reg.securityEvents.some((e) => e.kind === 'job_unknown_on_sync'));
    const events = reg.securityEvents.filter((e) => e.kind === 'job_unknown_on_sync');
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].detail.job_ids, [unknown]);
    assert.equal(events[0].detail.count, 1);
    assert.equal((await row(reg, cancelMe)).status, 'running');
  } finally {
    await r.close();
  }
});

test('sweeps: no ack in 15 s is agent_no_ack; past the deadline + 60 s is result_lost', async () => {
  const { r, reg, a } = await world();
  try {
    const silent = await dispatched(r, a);
    await r.fm.jobs.tick(Date.now() + 16000);
    assert.equal((await ended(reg, silent, 'failed')).error, 'agent_no_ack');

    const id = await dispatched(r, a, 'op-key', { timeout_s: 1 });
    a.status(id, { status: 'accepted' });
    await ended(reg, id, 'accepted');
    a.ws.terminate();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    await r.fm.jobs.tick(Date.now() + 30000);
    assert.equal((await row(reg, id)).status, 'accepted', 'a disconnected host waits for its deadline');
    await r.fm.jobs.tick(Date.now() + 62000);
    assert.equal((await ended(reg, id, 'failed')).error, 'result_lost');
  } finally {
    await r.close();
  }
});

test('job frames before enroll are dropped; frames are handled in order per host', async () => {
  const { r, reg, a } = await world();
  try {
    const id = await dispatched(r, a);
    a.status(id, { status: 'accepted' });
    await ended(reg, id, 'accepted');
    a.ws.terminate();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    const enroll = reg.enroll.bind(reg);
    reg.enroll = async (args) => { await sleep(150); return enroll(args); };
    const early = { type: 'sysscript_job_result', job_id: id, payload: { status: 'succeeded', output: 'early', error: '', output_truncated: false, duration_ms: 1 } };
    const a2 = await connectAgent(r, HOST_A, {
      sync: { active: [id], unacked: [] },
      onOpen: (agent) => agent.send(early)
    });
    reg.enroll = enroll;
    await sleep(150);
    assert.equal((await row(reg, id)).status, 'accepted');
    assert.equal(a2.of('sysscript_job_ack', id).length, 0);
    // In order, back to back: running then the result.
    a2.status(id, { status: 'running' });
    a2.result(id, { status: 'succeeded', output: 'late' });
    await a2.waitFor('sysscript_job_ack', id);
    const done = await row(reg, id);
    assert.equal(done.output, 'late');
    assert.ok(done.started_at);
  } finally {
    await r.close();
  }
});

test('an agent that floods its job queue is disconnected; a 1 MiB output frame keeps the socket open', async () => {
  const { r, reg, a } = await world();
  try {
    const id = await dispatched(r, a);
    a.status(id, { status: 'accepted' });
    await ended(reg, id, 'accepted');
    const big = '<'.repeat(1024 * 1024);
    a.result(id, { status: 'succeeded', output: big, output_truncated: true });
    await a.waitFor('sysscript_job_ack', id);
    assert.equal(a.ws.readyState, 1);
    const stored = await row(reg, id);
    assert.equal(stored.output.length, big.length);
    assert.equal(stored.output_truncated, true);

    r.fm.agentQueueMaxItems = 3;
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const transition = reg.transitionJob.bind(reg);
    reg.transitionJob = async (...args) => { await gate; return transition(...args); };
    const closed = new Promise((resolve) => a.ws.once('close', resolve));
    for (let i = 0; i < 10; i += 1) a.status(id, { status: 'running' });
    await closed;
    release();
  } finally {
    await r.close();
  }
});

test('agent presence is recorded on enroll and cleared on close; an older enroll never overwrites a newer one', async () => {
  const { r, reg, a } = await world();
  try {
    const connId = r.fm.jobs.connIds.get(r.fm.connectedAgents.get(HOST_A));
    assert.deepEqual(await reg.hostAgent(HOST_A), { instance: r.fm.jobs.instanceId, conn_id: connId, caps: ['sysscript_jobs'] });
    a.ws.terminate();
    await waitUntil('presence cleared', async () => (await reg.hostAgent(HOST_A)) === null);

    // A enrolled first but its write is delayed; B enrolled later and wrote;
    // then A's write lands and A closes. B stays.
    const t = Date.now();
    const A = { caps: ['sysscript_jobs'], instance: 'inst-a', connId: 'inst-a:1', enrolledAt: new Date(t + 1000) };
    const B = { caps: ['sysscript_jobs'], instance: 'inst-b', connId: 'inst-b:1', enrolledAt: new Date(t + 2000) };
    assert.equal(await reg.setAgentPresence(HOST_A, B), true);
    assert.equal(await reg.setAgentPresence(HOST_A, A), false);
    assert.equal(await reg.clearAgentPresence(HOST_A, A.connId), false);
    assert.equal((await reg.hostAgent(HOST_A)).conn_id, B.connId);
    // The same enroll may write again (the tick re-asserts it).
    assert.equal(await reg.setAgentPresence(HOST_A, B), true);
    assert.equal(await reg.clearAgentPresence(HOST_A, B.connId), true);
    assert.equal(await reg.hostAgent(HOST_A), null);

    // Skew: a stale owner C whose clock ran ahead holds the row, so the live
    // socket D's write is refused; C closes, and D's next re-assert wins.
    const C = { caps: ['sysscript_jobs'], instance: 'inst-c', connId: 'inst-c:1', enrolledAt: new Date(t + 600000) };
    const D = { caps: ['sysscript_jobs'], instance: 'inst-d', connId: 'inst-d:1', enrolledAt: new Date(t + 3000) };
    assert.equal(await reg.setAgentPresence(HOST_A, C), true);
    assert.equal(await reg.setAgentPresence(HOST_A, D), false);
    assert.equal(await reg.clearAgentPresence(HOST_A, C.connId), true);
    assert.equal(await reg.setAgentPresence(HOST_A, D), true);
    assert.equal((await reg.hostAgent(HOST_A)).conn_id, D.connId);
  } finally {
    await r.close();
  }
});

test('the tick re-asserts presence; a job goes only to the socket cp_hosts names', async () => {
  const { r, reg, a } = await world();
  try {
    const connId = r.fm.jobs.connIds.get(r.fm.connectedAgents.get(HOST_A));
    reg.hosts.get(HOST_A).agent_conn_id = null; // a lost write
    await r.fm.jobs.tick();
    await waitUntil('presence healed', async () => (await reg.hostAgent(HOST_A)) && (await reg.hostAgent(HOST_A)).conn_id === connId);

    // A newer enroll of the same host elsewhere: this socket gets nothing.
    await reg.setAgentPresence(HOST_A, { caps: ['sysscript_jobs'], instance: 'other', connId: 'other:1', enrolledAt: new Date(Date.now() + 60000) });
    const res = await submit(r, 'op-key', HOST_A);
    assert.equal(res.status, 202);
    await sleep(150);
    assert.equal(a.jobs.has(res.body.job_id), false);
    assert.equal((await row(reg, res.body.job_id)).status, 'submitted');
  } finally {
    await r.close();
  }
});

test('review: NUL in a script is 400; a 500 says internal; error text only beside visible output; never-dispatched cancel is ended', async () => {
  const { r, reg, a } = await world();
  try {
    const nul = await submit(r, 'op-key', HOST_A, { script: 'print(1)\u0000' });
    assert.equal(nul.status, 400);
    assert.equal(nul.body.error, 'bad_script');

    const create = reg.createJob.bind(reg);
    reg.createJob = async () => { const e = new Error('22P05 unsupported Unicode escape'); e.code = '22P05'; throw e; };
    const boom = await submit(r, 'op-key', HOST_A);
    assert.equal(boom.status, 500);
    assert.equal(boom.body.error, 'internal');
    reg.createJob = create;

    const id = await dispatched(r, a, 'op-key');
    a.result(id, { status: 'failed', error: 'secret path /etc/shadow\u0000x', output: 'out\u0000put' });
    await a.waitFor('sysscript_job_ack', id);
    const stored = await row(reg, id);
    assert.equal(stored.output, 'out\uFFFDput');
    assert.equal(stored.error, 'secret path /etc/shadow\uFFFDx');
    assert.equal((await r.api('GET', `/api/v1/jobs/${id}`, 'op-key')).body.job.error, 'secret path /etc/shadow\uFFFDx');
    assert.equal((await r.api('GET', `/api/v1/jobs/${id}`, 'op2-key')).body.job.error, 'agent_error');
    const listed = (await r.api('GET', '/api/v1/jobs', 'op-key')).body.jobs.find((j) => j.job_id === id);
    assert.equal(listed.error, 'agent_error');
    const coded = await dispatched(r, a, 'op-key');
    a.result(coded, { status: 'rejected', error: 'agent_busy' });
    await ended(reg, coded, 'failed');
    assert.equal((await r.api('GET', `/api/v1/jobs/${coded}`, 'op2-key')).body.job.error, 'agent_busy');

    // Offline agent row still named in cp_hosts: the job is never sent and
    // its cancel ends it on the spot.
    const ends = [];
    const orig = r.fm.jobs.ended.bind(r.fm.jobs);
    r.fm.jobs.ended = (j) => { ends.push(j.job_id); orig(j); };
    a.ws.terminate();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    await reg.setAgentPresence(HOST_A, { caps: ['sysscript_jobs'], instance: 'other', connId: 'other:2', enrolledAt: new Date(Date.now() + 120000) });
    const never = await submit(r, 'op-key', HOST_A);
    assert.equal(never.status, 202);
    const c = await r.api('POST', `/api/v1/jobs/${never.body.job_id}/cancel`, 'op-key');
    assert.equal(c.status, 202);
    assert.equal(c.body.job.status, 'cancelled');
    assert.deepEqual(ends, [never.body.job_id]);
  } finally {
    await r.close();
  }
});

test('job frame security events are rate limited per host and carry the suppressed count', async () => {
  const { r, reg, a } = await world();
  try {
    for (let i = 0; i < 15; i += 1) a.result(`sjb_${String(i).padStart(22, 'Z')}`, { status: 'succeeded' });
    await waitUntil('frames handled', () => (r.fm.jobs.chains.get(HOST_A) || { queued: 0 }).queued === 0 && reg.securityEvents.length >= 10);
    await sleep(50);
    assert.equal(reg.securityEvents.filter((e) => e.kind === 'job_frame_unknown').length, 10);
    // Next window: the event that gets through says how many were dropped.
    r.fm.jobs.securityRate.get(HOST_A).get('job_frame_unknown').start -= 61000;
    a.result('sjb_YYYYYYYYYYYYYYYYYYYYYY', { status: 'succeeded' });
    const ev = await waitUntil('next event', () => reg.securityEvents.filter((e) => e.kind === 'job_frame_unknown')[10]);
    assert.equal(ev.detail.suppressed, 5);

    // Per kind, and a frame for another host's job is never suppressed.
    const b = await connectAgent(r, HOST_B);
    const id = await dispatched(r, a);
    for (let i = 0; i < 15; i += 1) b.result(id, { status: 'succeeded' });
    await waitUntil('15 mismatch events', () => reg.securityEvents.filter((e) => e.kind === 'job_frame_host_mismatch').length === 15);
    b.result('sjb_XXXXXXXXXXXXXXXXXXXXXX', { status: 'succeeded' });
    await waitUntil('B unknown', () => reg.securityEvents.some((e) => e.kind === 'job_frame_unknown' && e.detail.host_id === HOST_B));
    // A host whose socket closed loses its rate state.
    assert.ok(r.fm.jobs.securityRate.has(HOST_B));
    b.ws.terminate();
    await waitUntil('rate state gone', () => !r.fm.jobs.securityRate.has(HOST_B));
  } finally {
    await r.close();
  }
});

test('the ack-timeout sweep skips a host whose job frames are still queued', async () => {
  const { r, reg, a } = await world();
  try {
    const id = await dispatched(r, a);
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const transition = reg.transitionJob.bind(reg);
    reg.transitionJob = async (...args) => { await gate; return transition(...args); };
    a.status(id, { status: 'accepted' });
    await waitUntil('queued', () => (r.fm.jobs.chains.get(HOST_A) || { queued: 0 }).queued > 0);
    await r.fm.jobs.tick(Date.now() + 16000);
    assert.equal((await row(reg, id)).status, 'submitted');
    // Busy for more than 15 s: no longer held off.
    r.fm.jobs.chains.get(HOST_A).busySince -= 16000;
    await r.fm.jobs.tick(Date.now() + 16000);
    assert.equal((await row(reg, id)).error, 'agent_no_ack');
    release();
  } finally {
    await r.close();
  }
});

test('two instances on one registry: dispatch, result, wait and cancel cross instances; the fallback scan covers lost events', async () => {
  const registry = new MemoryRegistry({ NODE_ENV: 'test' });
  const two = await rig({ registry, keys: KEYS });
  const a = await connectAgent(two, HOST_A);
  const one = await world({ registry, agent: false });
  try {
    assert.equal(one.r.fm.connectedAgents.has(HOST_A), false);

    // Submitted on one with wait_s; two holds the socket.
    const p = submit(one.r, 'op-key', HOST_A, { wait_s: 5 });
    const { frame, lease } = await a.waitJob();
    assert.equal(lease.ok, true);
    a.status(frame.job_id, { status: 'accepted' });
    a.result(frame.job_id, { status: 'succeeded', output: 'x' });
    const res = await p;
    assert.equal(res.status, 200);
    assert.equal(res.body.job.status, 'succeeded');
    await a.waitFor('sysscript_job_ack', frame.job_id);

    // Cancel on one, delivered by two.
    const c = await submit(one.r, 'op-key', HOST_A);
    await a.waitJob(c.body.job_id);
    assert.equal((await one.r.api('POST', `/api/v1/jobs/${c.body.job_id}/cancel`, 'op-key')).status, 202);
    await a.waitFor('sysscript_job_cancel', c.body.job_id);

    // Events lost on two: nothing is delivered until its tick.
    two.fm.jobs.stop();
    two.fm.jobs.events = false;
    const d = await submit(one.r, 'op-key', HOST_A);
    await sleep(100);
    assert.equal(a.jobs.has(d.body.job_id), false);
    await two.fm.jobs.tick();
    await a.waitJob(d.body.job_id);
    assert.equal((await one.r.api('POST', `/api/v1/jobs/${d.body.job_id}/cancel`, 'op-key')).status, 202);
    await sleep(100);
    assert.equal(a.of('sysscript_job_cancel', d.body.job_id).length, 0);
    await two.fm.jobs.tick();
    await a.waitFor('sysscript_job_cancel', d.body.job_id);

    // Never dispatched (the holder neither hears nor scans): dispatch_timeout.
    const e = await submit(one.r, 'op-key', HOST_A);
    await one.r.fm.jobs.tick(Date.now() + 61000);
    assert.equal((await ended(registry, e.body.job_id, 'failed')).error, 'dispatch_timeout');
  } finally {
    await two.close();
    await one.r.close();
  }
});

// Commit 6b: the legacy callers. A fake agent that also answers the legacy
// sysscript frame with a command_result, as an agent without the
// capability does.
function answerLegacy(agent, output = 'legacy') {
  agent.ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const f = JSON.parse(data.toString());
    if (f.type === 'sysscript') agent.send({ type: 'command_result', request_id: f.request_id, payload: { error: '', output } });
  });
}

function jobsOf(reg, source) {
  return [...reg.jobs.values()].filter((j) => j.source === source);
}

const execute = (r, body, key = 'op-key') => r.api('POST', `/api/v1/fleet/${HOST_A}/execute`, key, { script: 'print("hi")', ...body });

test('legacy /execute on a sysscript_jobs agent goes as a job with the same answer; 504 names the job; timed_out is a result error', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_SYSSCRIPT_JOB_MAX_S: '600' } });
  try {
    const p = execute(r, {});
    const { frame, lease } = await a.waitJob();
    assert.equal(lease.ok, true, lease.error);
    assert.equal(frame.timeout_s, 300, 'no timeout_s: the 300 s default');
    a.status(frame.job_id, { status: 'running' });
    a.result(frame.job_id, { status: 'succeeded', output: 'hi\n' });
    const res = await p;
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body, {
      success: true,
      request_id: frame.job_id,
      job_id: frame.job_id,
      result: { error: '', output: 'hi\n' },
      executed_by: 'user-3'
    });
    const stored = await row(reg, frame.job_id);
    assert.equal(stored.source, 'execute');
    assert.equal(stored.actor, 'user-3');
    assert.equal(a.of('sysscript').length, 0, 'no legacy frame');
    const actions = reg.audit.map((x) => x.action);
    assert.ok(actions.includes('sysscript_job_submit') && actions.includes('sysscript_job_end'));
    assert.equal(actions.includes('sysscript'), false);
    assert.equal(actions.includes('command_result'), false);

    // Not done within the wait: 504 agent_timeout with the job id; the job
    // runs on and ends later.
    r.fm.executeJobWaitMs = 150;
    const slow = await execute(r, { timeout_s: 45 });
    assert.equal(slow.status, 504);
    assert.equal(slow.body.error, 'agent_timeout');
    assert.match(slow.body.job_id, /^sjb_/);
    const sf = (await a.waitJob(slow.body.job_id)).frame;
    assert.equal(sf.timeout_s, 45);
    a.result(slow.body.job_id, { status: 'succeeded', output: 'late' });
    assert.equal((await ended(reg, slow.body.job_id, 'succeeded')).output, 'late');

    // timed_out and cancelled answer 200 with result.error set.
    r.fm.executeJobWaitMs = 5000;
    for (const status of ['timed_out', 'cancelled']) {
      const q = execute(r, {});
      const n = a.jobs.size;
      await waitUntil('next job', () => a.jobs.size > n);
      const id = [...a.jobs.keys()].pop();
      a.result(id, { status, output: 'part' });
      const out = await q;
      assert.equal(out.status, 200);
      assert.deepEqual(out.body.result, { error: status, output: 'part' });
    }
    // A script error keeps the agent's text, as the legacy path does.
    const q = execute(r, {});
    const n = a.jobs.size;
    await waitUntil('next job', () => a.jobs.size > n);
    a.result([...a.jobs.keys()].pop(), { status: 'failed', error: 'boom: line 1', output: '' });
    assert.deepEqual((await q).body.result, { error: 'boom: line 1', output: '' });

    // A bad timeout_s or a script the job store cannot hold is 400 and
    // creates nothing.
    const before = reg.jobs.size;
    for (const [body, code] of [[{ timeout_s: 0 }, 'bad_timeout'], [{ timeout_s: 601 }, 'bad_timeout'],
      [{ timeout_s: '30' }, 'bad_timeout'], [{ script: 'a\u0000b' }, 'bad_script']]) {
      const bad = await execute(r, body);
      assert.equal(bad.status, 400, code);
      assert.equal(bad.body.error, code);
    }
    assert.equal(reg.jobs.size, before);
  } finally {
    await r.close();
  }
});

test('/fleet/execute and /playbooks/:id/run on a sysscript_jobs agent go as jobs (fleet_execute, playbook)', async () => {
  const { r, reg, a } = await world();
  try {
    const p = r.api('POST', '/api/v1/fleet/execute', 'op-key', { host_ids: [HOST_A], script: 'print(1)', timeout_s: 60 });
    const { frame } = await a.waitJob();
    assert.equal(frame.timeout_s, 60);
    a.result(frame.job_id, { status: 'succeeded', output: '1\n' });
    const res = await p;
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.results, [{ host_id: HOST_A, request_id: frame.job_id, job_id: frame.job_id, result: { error: '', output: '1\n' } }]);
    assert.equal((await row(reg, frame.job_id)).source, 'fleet_execute');

    const q = r.api('POST', '/api/v1/playbooks/disk_report/run', 'op-key', { host_id: HOST_A });
    await waitUntil('playbook job', () => a.jobs.size === 2);
    const pb = [...a.jobs.values()][1];
    assert.equal(pb.lease.ok, true, pb.lease.error);
    assert.equal(pb.frame.entitlements.allow_exec, true);
    assert.equal(pb.frame.timeout_s, 300);
    a.result(pb.frame.job_id, { status: 'succeeded', output: 'disk' });
    const out = await q;
    assert.equal(out.status, 200);
    assert.equal(out.body.playbook, 'disk_report');
    assert.equal(out.body.job_id, pb.frame.job_id);
    assert.deepEqual(out.body.result, { error: '', output: 'disk' });
    assert.equal((await row(reg, pb.frame.job_id)).source, 'playbook');
    assert.equal(a.of('sysscript').length, 0);
  } finally {
    await r.close();
  }
});

test('the scheduler and rule playbooks submit jobs without waiting; the schedule audit row carries the job id', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_SCHEDULE_JOB_TIMEOUT_S: '77' } });
  try {
    await reg.createSchedule({ id: 'sch-1', tenant_id: 'acme', host_id: HOST_A, cron: '* * * * *', script: 'print("tick")' });
    const t0 = Date.now();
    await tickSchedules(r.fm, { error: (...m) => assert.fail(m.join(' ')) });
    assert.ok(Date.now() - t0 < 2000, 'the tick does not wait on the agent');
    const [sch] = jobsOf(reg, 'schedule');
    assert.equal(sch.actor, 'scheduler');
    assert.equal(sch.timeout_s, 77);
    const { frame, lease } = await a.waitJob(sch.job_id);
    assert.equal(lease.ok, true, lease.error);
    assert.equal(frame.timeout_s, 77);
    assert.deepEqual(frame.entitlements, { allow_exec: true });
    const audit = reg.audit.find((x) => x.action === 'schedule');
    assert.equal(audit.actor, 'scheduler');
    assert.deepEqual(audit.payload, { schedule_id: 'sch-1', minute: audit.payload.minute, job_id: sch.job_id });

    await r.fm.dispatchPlaybook('disk_report', HOST_A);
    const [rule] = jobsOf(reg, 'rule');
    assert.equal(rule.actor, 'system:rule');
    assert.equal(rule.timeout_s, 300);
    const rj = await a.waitJob(rule.job_id);
    assert.equal(rj.lease.ok, true, rj.lease.error);
    assert.equal(rj.frame.entitlements.allow_exec, true);
    assert.equal(rj.frame.entitlements.allow_fs_write, false);
    assert.equal(a.of('sysscript').length, 0);
  } finally {
    await r.close();
  }
});

// Every legacy caller once, against an agent answering the legacy frame:
// the unchanged pushSysscript path, no job rows, the legacy audit actions.
async function assertAllLegacy(r, reg, a) {
  answerLegacy(a);
  const ex = await execute(r, {});
  assert.equal(ex.status, 200, JSON.stringify(ex.body));
  assert.deepEqual(Object.keys(ex.body).sort(), ['executed_by', 'request_id', 'result', 'success']);
  assert.deepEqual(ex.body.result, { error: '', output: 'legacy' });
  assert.doesNotMatch(ex.body.request_id, /^sjb_/);
  const fx = await r.api('POST', '/api/v1/fleet/execute', 'op-key', { host_ids: [HOST_A], script: 'print(1)' });
  assert.equal(fx.status, 200);
  assert.equal(fx.body.results[0].job_id, undefined);
  const pb = await r.api('POST', '/api/v1/playbooks/disk_report/run', 'op-key', { host_id: HOST_A });
  assert.equal(pb.status, 200);
  assert.equal(pb.body.job_id, undefined);
  await reg.createSchedule({ id: 'sch-l', tenant_id: 'acme', host_id: HOST_A, cron: '* * * * *', script: 'print(2)' });
  await tickSchedules(r.fm, { error: (...m) => assert.fail(m.join(' ')) });
  const sch = reg.audit.find((x) => x.action === 'schedule');
  assert.equal(sch.payload.job_id, undefined);
  await r.fm.dispatchPlaybook('disk_report', HOST_A);
  assert.equal(a.of('sysscript').length, 5);
  assert.equal(a.jobs.size, 0);
  assert.equal(reg.jobs.size, 0);
  assert.equal(reg.audit.filter((x) => x.action === 'sysscript').length, 3);
  assert.equal(reg.audit.some((x) => x.action === 'sysscript_job_submit'), false);
}

test('an agent without sysscript_jobs stays on the legacy path for every caller (production until commit 6c)', async () => {
  const { r, reg, a } = await world({ caps: '' });
  try {
    assert.equal(r.fm.agentSupports(HOST_A, 'sysscript_jobs'), false);
    await assertAllLegacy(r, reg, a);
  } finally {
    await r.close();
  }
});

test('SYSTEMAPI_SYSSCRIPT_JOBS=0 keeps every caller on the legacy path on a sysscript_jobs agent', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_SYSSCRIPT_JOBS: '0' } });
  try {
    assert.equal(r.fm.agentSupports(HOST_A, 'sysscript_jobs'), true);
    await assertAllLegacy(r, reg, a);
  } finally {
    await r.close();
  }
});

test('legacy /execute on another instance: a capable agent there gets a job, an old one stays legacy (409 here, as today)', async () => {
  const registry = new MemoryRegistry({ NODE_ENV: 'test' });
  const two = await rig({ registry, keys: KEYS });
  const a = await connectAgent(two, HOST_A);
  const one = await world({ registry, agent: false });
  try {
    const p = execute(one.r, {});
    const { frame } = await a.waitJob();
    a.result(frame.job_id, { status: 'succeeded', output: 'x' });
    const res = await p;
    assert.equal(res.status, 200);
    assert.equal(res.body.job_id, frame.job_id);
    assert.equal((await row(registry, frame.job_id)).source, 'execute');

    const b = await connectAgent(two, HOST_B, { caps: '' });
    const off = await one.r.api('POST', `/api/v1/fleet/${HOST_B}/execute`, 'op-key', { script: 'print(1)' });
    assert.equal(off.status, 409);
    assert.equal(off.body.error, 'agent_offline');
    assert.equal(b.of('sysscript').length, 0);
  } finally {
    await two.close();
    await one.r.close();
  }
});

// Collects unhandled rejections while fn runs (an unhandled rejection ends
// the server process under Node 22).
async function noUnhandled(fn) {
  const seen = [];
  const on = (err) => seen.push(err);
  process.on('unhandledRejection', on);
  try {
    await fn();
    await sleep(50);
  } finally {
    process.off('unhandledRejection', on);
  }
  assert.deepEqual(seen.map((e) => (e && e.message) || String(e)), []);
}

const RULE = { metric: 'cpu.usage_percent', operator: '>', threshold_value: '50', action_type: 'playbook', action_target: 'disk_report' };
const HOT = { cpu: { usage_percent: 99 }, host: { hostname: 'a.example' } };

test('a rule playbook at the host job cap, or an incident action that throws, is logged and never an unhandled rejection', async () => {
  const { r, reg, a } = await world();
  try {
    for (let i = 0; i < 8; i += 1) assert.equal((await submit(r, 'op-key', HOST_A)).status, 202);
    await noUnhandled(async () => {
      await r.fm.dispatchPlaybook('disk_report', HOST_A);
      r.fm.checkRule('user-1', HOST_A, HOT, { ...RULE, name: 'cap-rule' });
      await sleep(50);
      assert.equal(jobsOf(reg, 'rule').length, 0, 'the cap held');
      r.fm.triggerIncident = async () => { throw Object.assign(new Error('boom'), { code: 'boom' }); };
      r.fm.checkRule('user-1', HOST_A, HOT, { ...RULE, name: 'throw-rule' });
    });
    assert.equal(a.of('sysscript').length, 0);
  } finally {
    await r.close();
  }
});

test('a legacy rule playbook whose agent never answers times out at 30 s without an unhandled rejection', async (t) => {
  const { r, a } = await world({ caps: '' });
  try {
    await noUnhandled(async () => {
      t.mock.timers.enable({ apis: ['setTimeout'] });
      try {
        r.fm.checkRule('user-1', HOST_A, HOT, { ...RULE, name: 'legacy-rule' });
        for (let i = 0; i < 20 && r.fm.pendingExecutions.size === 0; i += 1) await new Promise(setImmediate);
        assert.equal(r.fm.pendingExecutions.size, 1);
        t.mock.timers.tick(30000);
        for (let i = 0; i < 20; i += 1) await new Promise(setImmediate);
      } finally {
        t.mock.timers.reset();
      }
      assert.equal(r.fm.pendingExecutions.size, 0);
    });
    await a.waitFor('sysscript');
  } finally {
    await r.close();
  }
});

test('/fleet/execute: a host at its job cap is a per-host too_many_jobs entry; the other hosts still run', async () => {
  const { r, reg, a } = await world();
  try {
    const b = await connectAgent(r, HOST_B);
    for (let i = 0; i < 8; i += 1) assert.equal((await submit(r, 'op-key', HOST_A)).status, 202);
    const p = r.api('POST', '/api/v1/fleet/execute', 'op-key', { host_ids: [HOST_A, HOST_B], script: 'print(1)' });
    const { frame } = await b.waitJob();
    b.result(frame.job_id, { status: 'succeeded', output: 'b' });
    const res = await p;
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body.results, [
      { host_id: HOST_A, error: 'too_many_jobs' },
      { host_id: HOST_B, request_id: frame.job_id, job_id: frame.job_id, result: { error: '', output: 'b' } }
    ]);
    assert.equal(jobsOf(reg, 'fleet_execute').length, 1);
    assert.equal(a.jobs.size, 8);
  } finally {
    await r.close();
  }
});

test('a capable agent on another instance whose presence is older than 90 s goes legacy (409 here); a re-assert makes it fresh', async () => {
  const registry = new MemoryRegistry({ NODE_ENV: 'test' });
  const two = await rig({ registry, keys: KEYS });
  const a = await connectAgent(two, HOST_A);
  const one = await world({ registry, agent: false });
  try {
    await waitUntil('presence', async () => registry.hosts.get(HOST_A).agent_seen_at);
    registry.hosts.get(HOST_A).agent_seen_at = new Date(Date.now() - 91000);
    assert.equal(await registry.hostAgent(HOST_A, { maxAgeS: 90 }), null);
    assert.ok(await registry.hostAgent(HOST_A));
    const stale = await execute(one.r, {});
    assert.equal(stale.status, 409);
    assert.equal(stale.body.error, 'agent_offline');
    assert.equal(registry.jobs.size, 0);

    await two.fm.jobs.tick();
    await waitUntil('fresh', () => registry.hostAgent(HOST_A, { maxAgeS: 90 }));
    const p = execute(one.r, {});
    const { frame } = await a.waitJob();
    a.result(frame.job_id, { status: 'succeeded', output: 'x' });
    assert.equal((await p).status, 200);
  } finally {
    await two.close();
    await one.r.close();
  }
});

test('POST /jobs for an agent on another instance whose presence is older than 90 s is 409 agent_offline, and no job is created', async () => {
  const registry = new MemoryRegistry({ NODE_ENV: 'test' });
  const two = await rig({ registry, keys: KEYS });
  const a = await connectAgent(two, HOST_A);
  const one = await world({ registry, agent: false });
  try {
    await waitUntil('presence', async () => registry.hosts.get(HOST_A).agent_seen_at);
    registry.hosts.get(HOST_A).agent_seen_at = new Date(Date.now() - 91000);
    assert.ok(await registry.hostAgent(HOST_A));
    const stale = await submit(one.r, 'op-key', HOST_A);
    assert.equal(stale.status, 409, JSON.stringify(stale.body));
    assert.equal(stale.body.error, 'agent_offline');
    assert.equal(registry.jobs.size, 0);

    await two.fm.jobs.tick();
    await waitUntil('fresh', () => registry.hostAgent(HOST_A, { maxAgeS: 90 }));
    const res = await submit(one.r, 'op-key', HOST_A);
    assert.equal(res.status, 202, JSON.stringify(res.body));
    const { frame } = await a.waitJob(res.body.job_id);
    a.result(frame.job_id, { status: 'succeeded', output: 'x' });
    await ended(registry, res.body.job_id, 'succeeded');
  } finally {
    await two.close();
    await one.r.close();
  }
});

// Converge jobs on the job pipeline (.omc/plans/convergence-drift.md §7,
// commit 4): the submit, the dispatch frame, the capability and
// SYSTEMAPI_CONVERGE gates, and the report through the transition and a
// re-send. No routes yet: jobs.submit is driven directly.
const CONV_BUNDLE = JSON.stringify({ v: 1, files: { 'main.star': 'state.file("/etc/x", "x")' }, vars: {}, host: {} });
const CONV_SHA = require('node:crypto').createHash('sha256').update(CONV_BUNDLE, 'utf8').digest('hex');

function convReport({ drift = 1 } = {}) {
  return {
    v: 1,
    mode: 'check',
    bundle_sha256: CONV_SHA,
    plan_sha256: 'c'.repeat(64),
    truncated: false,
    summary: { total: 1, ok: drift ? 0 : 1, drift, changed: 0, failed: 0, denied: 0, skipped: 0 },
    plan: drift ? [{ key: 'file:/etc/x', status: 'drift' }] : [],
    resources: [{ key: 'file:/etc/x', kind: 'file', status: drift ? 'drift' : 'ok', sensitive: false, before: { exists: true }, desired: { mode: '0644' }, diff: '', error: '', backup_id: null }]
  };
}

// A host assignment of a published state on HOST_A; returns the submit
// arguments of a check job for it.
async function convergeSetup(reg) {
  const st = await reg.createState({ tenantId: 'acme', name: 'web', actor: 'user-1' });
  const v = await reg.publishVersion({ tenantId: 'acme', stateId: st.state_id, files: { 'main.star': 'x = 1' }, entitlements: { allow_fs_write: ['/etc/'] }, actor: 'user-1' });
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: st.state_id, versionId: v.version_id, targetKind: 'host', targetValue: HOST_A, actor: 'user-1' });
  return {
    host: { host_id: HOST_A, tenant_id: 'acme' },
    actor: 'user-1',
    source: 'converge_check',
    kind: 'converge',
    mode: 'check',
    expectPlanSha: '-',
    bundleJson: CONV_BUNDLE,
    entitlements: v.entitlements,
    timeoutS: 300,
    converge: { kind: 'check', stateId: st.state_id, assignmentId: a.assignment_id, versionId: v.version_id }
  };
}

test('converge: the frame carries kind, mode, bundle and plan under a converge_job lease; the report is ingested before the ack', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_CONVERGE: '1' }, caps: 'sysscript_jobs,converge' });
  try {
    const args = await convergeSetup(reg);
    const { job } = await r.fm.jobs.submit(args);
    assert.equal(job.script_sha256, CONV_SHA);
    const { frame, lease } = await a.waitJob(job.job_id);
    assert.equal(lease.ok, true, lease.error);
    assert.equal(frame.lease.action, 'converge_job');
    assert.equal(frame.kind, 'converge');
    assert.equal(frame.mode, 'check');
    assert.equal(frame.bundle_json, CONV_BUNDLE);
    assert.equal(frame.expect_plan_sha256, '-');
    assert.equal('script' in frame, false);
    assert.deepEqual(frame.entitlements, args.entitlements);
    assert.equal((await row(reg, job.job_id)).dispatch, null);

    a.status(job.job_id, { status: 'running' });
    a.result(job.job_id, { status: 'succeeded', report: convReport() });
    await a.waitFor('sysscript_job_ack', job.job_id);
    const run = reg.convergeRuns.get(job.job_id);
    assert.match(run.report_sha256, /^[0-9a-f]{64}$/);
    assert.equal(run.summary.drift, 1);
    assert.equal(reg.hostStates.get(`${HOST_A}\u0000${args.converge.stateId}`).status, 'drifted');
    assert.equal((await row(reg, job.job_id)).status, 'succeeded');

    // A malformed report ends the job failed[bad_report], still acked.
    const bad = await r.fm.jobs.submit(args);
    await a.waitJob(bad.job.job_id);
    a.result(bad.job.job_id, { status: 'succeeded', report: { ...convReport(), bundle_sha256: 'f'.repeat(64) } });
    await a.waitFor('sysscript_job_ack', bad.job.job_id);
    const badRow = await row(reg, bad.job.job_id);
    assert.equal(badRow.status, 'failed');
    assert.equal(badRow.error, 'bad_report');
  } finally {
    await r.close();
  }
});

test('converge: a report re-sent for a row already ended without one is ingested once, then acked', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_CONVERGE: '1' }, caps: 'sysscript_jobs,converge' });
  try {
    const args = await convergeSetup(reg);
    const { job } = await r.fm.jobs.submit(args);
    await a.waitJob(job.job_id);
    // Ended elsewhere (a sweep) with no report.
    const swept = await reg.transitionJob(job.job_id, HOST_A, ['submitted', 'accepted', 'running'], { status: 'failed', error: 'result_lost' });
    assert.equal(swept.status, 'failed');
    assert.equal(reg.convergeRuns.get(job.job_id).report_sha256, null);
    a.result(job.job_id, { status: 'succeeded', report: convReport({ drift: 0 }) });
    await a.waitFor('sysscript_job_ack', job.job_id);
    const sha = reg.convergeRuns.get(job.job_id).report_sha256;
    assert.match(sha, /^[0-9a-f]{64}$/);
    // A second re-send changes nothing and is acked again.
    a.result(job.job_id, { status: 'succeeded', report: convReport({ drift: 1 }) });
    await waitUntil('second ack', () => a.of('sysscript_job_ack', job.job_id).length === 2);
    assert.equal(reg.convergeRuns.get(job.job_id).report_sha256, sha);
  } finally {
    await r.close();
  }
});

test('converge: never dispatched to an agent without converge, nor while SYSTEMAPI_CONVERGE is off; submit refuses off and bad modes', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_CONVERGE: '1' } });
  try {
    const args = await convergeSetup(reg);
    const { job } = await r.fm.jobs.submit(args);
    // A plain job after it is still sent; the converge row is not claimed.
    const plain = await dispatched(r, a);
    assert.ok(plain);
    assert.equal(await r.fm.jobs.pump(HOST_A), 0);
    assert.equal(await r.fm.jobs.deliverDispatch(HOST_A, job.job_id), false);
    const stored = await row(reg, job.job_id);
    assert.equal(stored.status, 'submitted');
    assert.equal(stored.dispatch.kind, 'converge', 'the payload is left for a capable agent');
    assert.equal(a.jobs.has(job.job_id), false);

    // Submit refusals.
    const refuse = (over, code) => assert.rejects(r.fm.jobs.submit({ ...args, ...over }), (e) => e.code === code, code);
    await refuse({ expectPlanSha: 'a'.repeat(64) }, 'bad_mode');
    await refuse({ mode: 'apply', expectPlanSha: 'a'.repeat(64) }, 'bad_mode');
    await refuse({ mode: 'apply', expectPlanSha: '-', source: 'converge_apply' }, 'bad_mode');
    await refuse({ mode: 'verify' }, 'bad_mode');
    await refuse({ bundleJson: 'x'.repeat(64 * 1024 + 1) }, 'bad_bundle');
    await refuse({ bundleJson: '' }, 'bad_bundle');
    await refuse({ kind: 'shell' }, 'bad_kind');
    r.fm.env.SYSTEMAPI_CONVERGE = '0';
    await assert.rejects(r.fm.jobs.submit(args), (e) => e.status === 503 && e.code === 'converge_disabled');
  } finally {
    await r.close();
  }
});

test('converge: SYSTEMAPI_CONVERGE off leaves a converge row unsent even to a converge agent; results still land', async () => {
  const { r, reg, a } = await world({ env: { SYSTEMAPI_CONVERGE: '1' }, caps: 'sysscript_jobs,converge' });
  try {
    const args = await convergeSetup(reg);
    // Sent while on; the switch goes off while it runs: its result is
    // still stored and acked.
    const { job } = await r.fm.jobs.submit(args);
    await a.waitJob(job.job_id);
    r.fm.env.SYSTEMAPI_CONVERGE = '0';
    a.result(job.job_id, { status: 'succeeded', report: convReport() });
    await a.waitFor('sysscript_job_ack', job.job_id);
    assert.match(reg.convergeRuns.get(job.job_id).report_sha256, /^[0-9a-f]{64}$/);
    // A converge row still queued is not sent while off.
    r.fm.env.SYSTEMAPI_CONVERGE = '1';
    r.fm.jobs.events = false;
    r.fm.jobs.stop();
    const capable = r.fm.jobs.capable;
    r.fm.jobs.capable = () => false; // keep submit from sending it at once
    const queued = await r.fm.jobs.submit(args);
    r.fm.jobs.capable = capable;
    r.fm.env.SYSTEMAPI_CONVERGE = '0';
    assert.equal(await r.fm.jobs.pump(HOST_A), 0);
    assert.equal(await r.fm.jobs.deliverDispatch(HOST_A, queued.job.job_id), false);
    assert.notEqual((await row(reg, queued.job.job_id)).dispatch, null);
    // On again, the same row goes out.
    r.fm.env.SYSTEMAPI_CONVERGE = '1';
    assert.equal(await r.fm.jobs.pump(HOST_A), 1);
    const { lease } = await a.waitJob(queued.job.job_id);
    assert.equal(lease.ok, true, lease.error);
  } finally {
    await r.close();
  }
});
