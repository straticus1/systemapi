'use strict';

// MemoryRegistry desired state and converge runs (.omc/plans/convergence-drift.md
// §5-§8): states, immutable versions, assignments and their §6.2 rules,
// syncHostStates on enroll, retire, tag change and assignment mutations, the
// converge part of createJob (claim, plan consumption after the caps), report
// ingestion in the terminal transition (conditional host-state writes, drift
// alerts, bad reports), finalize on sweep/lost/cancel, re-send ingestion,
// approvePlan, claimDueChecks, stale marking and retention. The Postgres
// variants are in tests/registry-pg.test.js.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { MemoryRegistry } = require('../controlplane/registry');
const { convergeReport, effectiveAssignments, hostStateDiff } = require('../controlplane/statestore');

const H1 = 'host-1';
const H2 = 'host-2';
const HB = 'host-b';

function sshKey(fill) {
  const name = Buffer.from('ssh-ed25519');
  const buf = Buffer.alloc(4 + name.length + 4 + 32);
  buf.writeUInt32BE(name.length, 0);
  name.copy(buf, 4);
  buf.writeUInt32BE(32, 4 + name.length);
  Buffer.alloc(32, fill).copy(buf, 4 + name.length + 4);
  return `ssh-ed25519 ${buf.toString('base64')} t@x`;
}

const sha = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');
const BUNDLE = JSON.stringify({ v: 1, files: { 'main.star': 'state.file("/etc/x", "x")' }, vars: {}, host: {} });
const BUNDLE_SHA = sha(BUNDLE);

async function rig(env = {}) {
  const reg = new MemoryRegistry({ NODE_ENV: 'test', ...env });
  await reg.enroll({ tenantId: 'acme', userId: 'u-a', keyId: 'k-a', hostId: H1, hostname: 'one', sshPubkey: sshKey(1) });
  await reg.enroll({ tenantId: 'acme', userId: 'u-a', keyId: 'k-a', hostId: H2, hostname: 'two', sshPubkey: sshKey(2) });
  await reg.enroll({ tenantId: 'beta', userId: 'u-b', keyId: 'k-b', hostId: HB, hostname: 'b', sshPubkey: sshKey(3) });
  return reg;
}

async function published(reg, tenantId = 'acme', name = 'web', actor = 'u-a') {
  const st = await reg.createState({ tenantId, name, actor });
  const v = await reg.publishVersion({ tenantId, stateId: st.state_id, files: { 'main.star': 'x = 1' }, entitlements: { allow_fs_write: ['/etc/'] }, actor });
  return { st, v };
}

function jobRow(t, over = {}) {
  return {
    job_id: `sjb_${crypto.randomBytes(16).toString('base64url')}`,
    tenant_id: t.tenantId || 'acme',
    host_id: t.hostId || H1,
    actor: t.actor || 'u-a',
    source: `converge_${t.kind || 'check'}`,
    script_sha256: BUNDLE_SHA,
    entitlements_sha256: t.v.entitlements_sha256,
    entitlements: t.v.entitlements,
    timeout_s: 300,
    deadline_at: new Date(Date.now() + 300000),
    lease_nonce: crypto.randomBytes(16).toString('hex'),
    dispatch: { kind: 'converge', bundle_json: BUNDLE },
    ...over
  };
}

function convOpts(t, a, over = {}) {
  const kind = t.kind || 'check';
  return {
    kind,
    stateId: t.st.state_id,
    assignmentId: a ? a.assignment_id : undefined,
    versionId: t.v.version_id,
    bundleJson: kind === 'plan' ? BUNDLE : undefined,
    ...over
  };
}

function report(kind, { drift = 0, ok = 1, failed = 0, changed = 0, truncated = false, key = 'file:/etc/x', planSha = 'c'.repeat(64) } = {}) {
  const resources = [];
  const status = failed ? 'failed' : drift ? 'drift' : changed ? 'changed' : 'ok';
  resources.push({ key, kind: 'file', status, sensitive: false, before: { exists: true, sha256: 'd'.repeat(64), mode: '0644' }, desired: { sha256: 'e'.repeat(64) }, diff: drift ? '--- a\n+++ b' : '', error: '', backup_id: null });
  return {
    v: 1,
    mode: kind === 'apply' ? 'apply' : 'check',
    bundle_sha256: BUNDLE_SHA,
    plan_sha256: planSha,
    truncated,
    summary: { total: 1, ok: ok && !drift && !failed && !changed ? 1 : 0, drift: drift ? 1 : 0, changed: changed ? 1 : 0, failed: failed ? 1 : 0, denied: 0, skipped: 0 },
    plan: drift ? [{ key, status: 'drift' }] : [],
    resources
  };
}

// Submits a converge job, dispatches it and returns its id.
async function submit(reg, t, a, over = {}, opts = {}) {
  const row = jobRow(t, over);
  await reg.createJob(row, { converge: convOpts(t, a, opts.conv), ...(opts.caps || {}) });
  await reg.markDispatched(row.job_id, row.host_id, 'c1');
  return row;
}

async function finish(reg, row, rep, status = 'succeeded') {
  return reg.transitionJob(row.job_id, row.host_id, ['submitted', 'accepted', 'running'],
    { status, output: '' }, { audit: { actor: 'agent' }, converge: { report: rep } });
}

const hs = (reg, host, stateId) => reg.hostStates.get(`${host}\u0000${stateId}`);

test('states and versions: tenant-scoped, versions numbered and immutable, files only on request', async () => {
  const reg = await rig();
  const { st, v } = await published(reg);
  await assert.rejects(reg.createState({ tenantId: 'acme', name: 'web', actor: 'u-a' }), (e) => e.code === 'state_exists');
  await assert.rejects(reg.createState({ tenantId: 'acme', name: 'Bad Name', actor: 'u-a' }), (e) => e.code === 'bad_state_name');
  await assert.rejects(reg.publishVersion({ tenantId: 'beta', stateId: st.state_id, files: { 'main.star': '' }, actor: 'u-b' }), (e) => e.status === 404);
  await assert.rejects(reg.publishVersion({ tenantId: 'acme', stateId: st.state_id, files: { 'x.star': '' }, actor: 'u-a' }), (e) => e.code === 'bad_bundle');
  const v2 = await reg.publishVersion({ tenantId: 'acme', stateId: st.state_id, files: { 'main.star': 'y = 2' }, actor: 'u-a' });
  assert.equal(v.version, 1);
  assert.equal(v2.version, 2);
  assert.equal('files' in v, false);
  assert.match(v.entitlements_sha256, /^[0-9a-f]{64}$/);
  assert.equal(await reg.getState(['beta'], st.state_id), null);
  assert.equal(await reg.getVersion(['beta'], v.version_id), null);
  assert.deepEqual((await reg.getVersion(['acme'], v.version_id, { withFiles: true })).files, { 'main.star': 'x = 1' });
  assert.deepEqual((await reg.listVersions(['acme'], st.state_id)).map((x) => x.version), [2, 1]);
  assert.deepEqual(await reg.listVersions(['beta'], st.state_id), []);
  assert.deepEqual(reg.audit.map((r) => r.action), ['state_create', 'state_publish', 'state_publish']);
});

test('assignments: approval forced on tag and tenant targets, auto_remediate host-only, cross-tenant refused', async () => {
  const reg = await rig();
  const { st, v } = await published(reg);
  const base = { tenantId: 'acme', stateId: st.state_id, versionId: v.version_id, actor: 'u-a' };
  const tag = await reg.createAssignment({ ...base, targetKind: 'tag', targetValue: 'web', requireApproval: false });
  assert.equal(tag.require_approval, true);
  await assert.rejects(reg.createAssignment({ ...base, targetKind: 'tenant', autoRemediate: true }), (e) => e.code === 'auto_remediate_host_only');
  await assert.rejects(reg.createAssignment({ ...base, targetKind: 'tag', targetValue: 'db', autoRemediate: true }), (e) => e.code === 'auto_remediate_host_only');
  await assert.rejects(reg.createAssignment({ ...base, targetKind: 'host', targetValue: H1, autoRemediate: true, requireApproval: true }), (e) => e.code === 'auto_remediate_host_only');
  await assert.rejects(reg.createAssignment({ ...base, targetKind: 'host', targetValue: HB }), (e) => e.code === 'host_not_found');
  await assert.rejects(reg.createAssignment({ ...base, tenantId: 'beta', actor: 'u-b', targetKind: 'tenant' }), (e) => e.status === 404);
  const host = await reg.createAssignment({ ...base, targetKind: 'host', targetValue: H1, autoRemediate: true });
  assert.equal(host.auto_remediate, true);
  assert.equal(host.require_approval, false);
  await assert.rejects(reg.createAssignment({ ...base, targetKind: 'host', targetValue: H1 }), (e) => e.code === 'assignment_exists');
  await assert.rejects(reg.updateAssignment({ tenantId: 'acme', assignmentId: host.assignment_id, patch: { requireApproval: true }, actor: 'u-a' }),
    (e) => e.code === 'auto_remediate_host_only');
  await assert.rejects(reg.updateAssignment({ tenantId: 'acme', assignmentId: tag.assignment_id, patch: { autoRemediate: true }, actor: 'u-a' }),
    (e) => e.code === 'auto_remediate_host_only');
  await assert.rejects(reg.updateAssignment({ tenantId: 'beta', assignmentId: host.assignment_id, patch: { driftThreshold: 2 }, actor: 'u-b' }),
    (e) => e.status === 404);
  await assert.rejects(reg.deleteAssignment({ tenantId: 'beta', assignmentId: host.assignment_id, actor: 'u-b' }), (e) => e.status === 404);
  assert.equal(await reg.getAssignment(['beta'], host.assignment_id), null);
  assert.deepEqual(await reg.listAssignments(['beta']), []);
  assert.equal((await reg.listAssignments(['acme'])).length, 2);
});

test('syncHostStates: precedence host > tag > tenant, tag conflicts, enroll, tag change, retire and delete', async () => {
  const reg = await rig();
  const { st, v } = await published(reg);
  const base = { tenantId: 'acme', stateId: st.state_id, versionId: v.version_id, actor: 'u-a' };
  const ten = await reg.createAssignment({ ...base, targetKind: 'tenant' });
  assert.equal(hs(reg, H1, st.state_id).assignment_id, ten.assignment_id);
  assert.equal(hs(reg, H2, st.state_id).assignment_id, ten.assignment_id);
  assert.equal(hs(reg, HB, st.state_id), undefined, 'never another tenant');
  assert.ok(hs(reg, H1, st.state_id).next_check_at instanceof Date);

  const web = await reg.createAssignment({ ...base, targetKind: 'tag', targetValue: 'web' });
  await reg.setHostTags({ tenantId: 'acme', hostId: H1, tags: ['web'], actor: 'u-a' });
  assert.equal(hs(reg, H1, st.state_id).assignment_id, web.assignment_id);
  await reg.createAssignment({ ...base, targetKind: 'tag', targetValue: 'edge' });
  await reg.setHostTags({ tenantId: 'acme', hostId: H1, tags: ['web', 'edge'], actor: 'u-a' });
  assert.equal(hs(reg, H1, st.state_id).status, 'conflict');
  assert.equal(hs(reg, H1, st.state_id).assignment_id, null);
  const own = await reg.createAssignment({ ...base, targetKind: 'host', targetValue: H1 });
  assert.equal(hs(reg, H1, st.state_id).assignment_id, own.assignment_id);
  assert.equal(hs(reg, H1, st.state_id).status, 'unknown');
  await assert.rejects(reg.setHostTags({ tenantId: 'beta', hostId: H1, tags: [], actor: 'u-b' }), (e) => e.status === 404);
  await assert.rejects(reg.setHostTags({ tenantId: 'acme', hostId: H1, tags: ['Bad'], actor: 'u-a' }), (e) => e.code === 'bad_tags');

  // A new host enrolls into the tenant assignment.
  await reg.enroll({ tenantId: 'acme', userId: 'u-a', keyId: 'k-a', hostId: 'host-3', hostname: 'three', sshPubkey: sshKey(9) });
  assert.equal(hs(reg, 'host-3', st.state_id).assignment_id, ten.assignment_id);

  // Leaving: the row is deleted and its drift alert (open or ack) resolved.
  await reg.deleteAssignment({ tenantId: 'acme', assignmentId: ten.assignment_id, actor: 'u-a' });
  assert.equal(hs(reg, H2, st.state_id), undefined);
  const alert = await reg.openAlert({ tenant_id: 'acme', host_id: H1, rule_name: `drift:${st.state_id}` });
  alert.status = 'ack';
  await reg.retireHost({ tenantId: 'acme', hostId: H1, actor: 'u-a', reason: 'gone' });
  assert.equal(hs(reg, H1, st.state_id), undefined);
  assert.equal(alert.status, 'resolved');
  assert.ok(reg.audit.some((r) => r.action === 'host_tags'));
  assert.ok(reg.audit.some((r) => r.action === 'state_unassign'));
  assert.equal((await reg.verifyAudit()).ok, true);
});

test('statestore: effectiveAssignments and hostStateDiff are pure and delete rows of a moved host', () => {
  const a = { assignment_id: 'a1', state_id: 's1', version_id: 'v1', target_kind: 'tenant', target_value: 't', check_interval_s: 3600 };
  const eff = effectiveAssignments([{ host_id: 'h', tags: [] }], [a]);
  const d = hostStateDiff([{ host_id: 'h', state_id: 's1', tenant_id: 'old', assignment_id: 'a0', version_id: 'v0', status: 'drifted' }], eff, 't');
  assert.equal(d.deletes.length, 1, 'the row under the old tenant goes');
  assert.equal(d.inserts.length, 1);
  assert.equal(d.inserts[0].tenant_id, 't');
  assert.ok(d.inserts[0].next_offset_s >= 0 && d.inserts[0].next_offset_s < 3600);
});

test('ingest: drift opens one alert, an ack\'d alert is not duplicated, a clean check resolves it; reports are sanitized', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  const j1 = await submit(reg, t, a);
  assert.equal(hs(reg, H1, t.st.state_id).check_job_id, j1.job_id);
  const r1 = report('check', { drift: 1 });
  r1.resources[0].extra = 'dropped';
  const done = await finish(reg, j1, r1);
  assert.equal(done.status, 'succeeded');
  assert.equal(done.converge.status, 'drifted');
  assert.equal(done.converge.alerts.length, 1);
  const row = hs(reg, H1, t.st.state_id);
  assert.equal(row.check_job_id, null);
  assert.equal(row.check_claimed_at, null);
  assert.equal(row.consecutive_drift, 1);
  assert.deepEqual(Object.keys(row.facts), ['file:/etc/x']);
  assert.equal('extra' in reg.convergeRuns.get(j1.job_id).report.resources[0], false);
  const alerts = () => reg.alerts.filter((x) => x.rule_name === `drift:${t.st.state_id}`);
  alerts()[0].status = 'ack';

  const j2 = await submit(reg, t, a);
  const d2 = await finish(reg, j2, report('check', { drift: 1 }));
  assert.equal(d2.converge.alerts.length, 0, 'already active');
  assert.equal(alerts().length, 1);
  assert.equal(hs(reg, H1, t.st.state_id).consecutive_drift, 2);
  assert.equal(reg.convergeRuns.get(j2.job_id).report, null, 'same report hash, body already stored');

  const j3 = await submit(reg, t, a);
  const d3 = await finish(reg, j3, report('check'));
  assert.equal(d3.converge.status, 'compliant');
  assert.deepEqual(d3.converge.alerts.map((x) => x.type), ['drift_resolved']);
  assert.equal(alerts()[0].status, 'resolved');
  // state_report audit rows: on a status change only, for scheduled checks.
  assert.equal(reg.audit.filter((r) => r.action === 'state_report').length, 2);
  assert.equal((await reg.verifyAudit()).ok, true);
});

test('ingest: a malformed report ends the job failed[bad_report] with a security event and keeps the host status', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  const j = await submit(reg, t, a);
  const bad = report('check');
  bad.bundle_sha256 = 'f'.repeat(64);
  const out = await finish(reg, j, bad);
  assert.equal(out.status, 'failed');
  assert.equal(out.error, 'bad_report');
  assert.equal(reg.securityEvents.at(-1).kind, 'converge_bad_report');
  const row = hs(reg, H1, t.st.state_id);
  assert.equal(row.status, 'unknown');
  assert.equal(row.check_job_id, null, 'the claim is released');
  assert.equal(row.last_error, 'bad_report');
  assert.equal(convergeReport({ ...report('check'), summary: { total: -1 } }, 'check', BUNDLE_SHA).ok, false);
  const sens = report('check');
  sens.resources[0].sensitive = true;
  sens.resources[0].before = { exists: true, sha256: 'd'.repeat(64), matches: false };
  const ok = convergeReport(sens, 'check', BUNDLE_SHA);
  assert.deepEqual(ok.report.resources[0].before, { matches: false });
  assert.equal(ok.report.resources[0].desired, null);
  assert.equal(ok.facts['file:/etc/x'].digest, null);
});

test('AC 18: a late result for job A after job B took the row records A\'s run but leaves the host state alone', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  const jA = await submit(reg, t, a);
  const jB = await submit(reg, t, a);
  const late = await finish(reg, jA, report('check', { drift: 1 }));
  assert.equal(late.converge.host_state_updated, false);
  assert.ok(reg.convergeRuns.get(jA.job_id).report_sha256);
  const row = hs(reg, H1, t.st.state_id);
  assert.equal(row.status, 'unknown');
  assert.equal(row.check_job_id, jB.job_id);
  assert.equal(reg.alerts.length, 0);
  const own = await finish(reg, jB, report('check'));
  assert.equal(own.converge.status, 'compliant');
});

test('sweep, lost and cancel finalize: the claim is released, a lost apply becomes partial; a re-sent result is ingested once', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  const j = await submit(reg, t, a, { deadline_at: new Date(Date.now() + 1000) });
  await reg.transitionJob(j.job_id, H1, ['submitted'], { status: 'running' });
  const ended = await reg.sweepJobs(Date.now() + 70000);
  assert.deepEqual(ended.map((x) => x.error), ['result_lost']);
  let row = hs(reg, H1, t.st.state_id);
  assert.equal(row.check_claimed_at, null);
  assert.equal(row.check_job_id, null);
  assert.equal(row.status, 'unknown');
  assert.equal(row.last_error, 'result_lost');
  // The re-sent result: the run takes its report once; the host state stays.
  const re = await reg.ingestConvergeResend(j.job_id, H1, report('check', { drift: 1 }));
  assert.equal(re.ingested, true);
  assert.equal(re.converge.host_state_updated, false);
  assert.deepEqual(await reg.ingestConvergeResend(j.job_id, H1, report('check')), { ingested: false, reason: 'already_ingested' });
  assert.equal((await reg.ingestConvergeResend(j.job_id, H2, report('check'))).ingested, false, 'another host');

  // Cancel before dispatch releases the claim.
  const c = jobRow(t);
  await reg.createJob(c, { converge: convOpts(t, a) });
  await reg.requestJobCancel(['acme'], c.job_id, 'u-a');
  row = hs(reg, H1, t.st.state_id);
  assert.equal(row.check_job_id, null);
  assert.equal(row.last_error, 'cancelled_before_dispatch');

  // An apply lost on sync: partial.
  const p = await submit(reg, { ...t, kind: 'plan' }, a);
  await finish(reg, p, report('plan', { drift: 1 }));
  const ap = await submit(reg, { ...t, kind: 'apply' }, a, {}, { conv: { planRunId: p.job_id } });
  await reg.transitionJob(ap.job_id, H1, ['submitted'], { status: 'running' });
  const lost = await reg.reconcileHostJobs(H1, 'c2', []);
  assert.deepEqual(lost.map((x) => x.job_id), [ap.job_id]);
  assert.equal(hs(reg, H1, t.st.state_id).status, 'partial');
  assert.equal((await reg.verifyAudit()).ok, true);
});

test('plan, approve, apply: self-approval, truncation, 429 does not burn the plan, consumed once, manual apply recorded', async () => {
  const reg = await rig({ SYSTEMAPI_PLAN_MAX_AGE_S: '900' });
  const t = await published(reg);
  await reg.addMember('acme', 'u-c', 'admin');
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'tag', targetValue: 'web' });
  await reg.setHostTags({ tenantId: 'acme', hostId: H1, tags: ['web'], actor: 'u-a' });
  const plan = { ...t, kind: 'plan' };
  const apply = { ...t, kind: 'apply' };

  const trunc = await submit(reg, plan, a);
  await finish(reg, trunc, report('plan', { drift: 1, truncated: true }));
  await assert.rejects(reg.approvePlan({ tenantIds: ['acme'], runId: trunc.job_id, actor: 'u-c' }), (e) => e.code === 'plan_truncated');

  const p = await submit(reg, plan, a);
  await finish(reg, p, report('plan', { drift: 1 }));
  assert.equal(reg.convergeRuns.get(p.job_id).plan_sha256, 'c'.repeat(64));
  const applyOpts = { conv: { planRunId: p.job_id } };
  await assert.rejects(submit(reg, apply, a, {}, applyOpts), (e) => e.code === 'approval_required');
  await assert.rejects(reg.approvePlan({ tenantIds: ['acme'], runId: p.job_id, actor: 'u-a' }), (e) => e.code === 'self_approval');
  assert.equal(await reg.approvePlan({ tenantIds: ['beta'], runId: p.job_id, actor: 'u-b' }), null);
  assert.equal((await reg.approvePlan({ tenantIds: ['acme'], runId: p.job_id, actor: 'u-c' })).approved_by, 'u-c');

  // Fill the host to its cap: the apply is 429 and the plan stays usable.
  const filler = await submit(reg, t, a);
  await assert.rejects(submit(reg, apply, a, {}, { ...applyOpts, caps: { hostCap: 1 } }), (e) => e.status === 429);
  assert.equal(reg.convergeRuns.get(p.job_id).consumed_by_run_id, null);
  assert.ok(reg.convergeRuns.get(p.job_id).bundle_json);
  await finish(reg, filler, report('check', { drift: 1 }));
  await assert.rejects(submit(reg, apply, a, { script_sha256: 'a'.repeat(64) }, applyOpts), (e) => e.code === 'plan_bundle_mismatch');

  const ap = await submit(reg, apply, a, {}, applyOpts);
  assert.equal(reg.convergeRuns.get(p.job_id).consumed_by_run_id, ap.job_id);
  assert.equal(reg.convergeRuns.get(p.job_id).bundle_json, null);
  await assert.rejects(submit(reg, apply, a, {}, applyOpts), (e) => e.code === 'apply_in_progress');
  await assert.rejects(submit(reg, t, a), (e) => e.code === 'apply_in_progress', 'no check beside an apply');
  const done = await finish(reg, ap, report('apply', { changed: 1 }));
  await assert.rejects(submit(reg, apply, a, {}, applyOpts), (e) => e.code === 'plan_consumed');
  assert.equal(done.converge.status, 'compliant');
  const row = hs(reg, H1, t.st.state_id);
  assert.equal(row.last_applied_version_id, t.v.version_id);
  assert.equal(row.manual_apply_assignment_id, a.assignment_id);
  assert.equal(row.manual_apply_version_id, t.v.version_id);
  assert.equal(reg.alerts.find((x) => x.rule_name === `drift:${t.st.state_id}`).status, 'resolved');

  // Expired and superseded plans.
  const old = await submit(reg, plan, a);
  await finish(reg, old, report('plan', { drift: 1 }));
  reg.convergeRuns.get(old.job_id).created_at = new Date(Date.now() - 901000);
  await assert.rejects(reg.approvePlan({ tenantIds: ['acme'], runId: old.job_id, actor: 'u-c' }), (e) => e.code === 'plan_expired');
  const p2 = await submit(reg, plan, a);
  await finish(reg, p2, report('plan', { drift: 1 }));
  await reg.approvePlan({ tenantIds: ['acme'], runId: p2.job_id, actor: 'u-c' });
  const v2 = await reg.publishVersion({ tenantId: 'acme', stateId: t.st.state_id, files: { 'main.star': 'z = 3' }, entitlements: { allow_fs_write: ['/etc/'] }, actor: 'u-a' });
  await reg.updateAssignment({ tenantId: 'acme', assignmentId: a.assignment_id, patch: { versionId: v2.version_id }, actor: 'u-a' });
  await assert.rejects(submit(reg, apply, a, {}, { conv: { planRunId: p2.job_id } }), (e) => e.code === 'plan_superseded');
  assert.ok(reg.audit.some((r) => r.action === 'state_approve'));
  assert.equal((await reg.verifyAudit()).ok, true);
});

test('createJob converge: source and options must agree; the effective version and entitlements must match', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  await assert.rejects(reg.createJob(jobRow(t)), (e) => e.code === 'bad_job', 'converge source without opts.converge');
  await assert.rejects(reg.createJob(jobRow(t, { source: 'api' }), { converge: convOpts(t, a) }), (e) => e.code === 'bad_job');
  await assert.rejects(reg.createJob(jobRow({ ...t, kind: 'plan' }), { converge: convOpts({ ...t, kind: 'plan' }, a, { bundleJson: '{}' }) }), (e) => e.code === 'bad_job');
  await assert.rejects(reg.createJob(jobRow(t, { entitlements_sha256: 'b'.repeat(64) }), { converge: convOpts(t, a) }), (e) => e.code === 'entitlements_mismatch');
  await assert.rejects(reg.createJob(jobRow(t, { host_id: H2 }), { converge: convOpts(t, a) }), (e) => e.code === 'state_not_assigned');
  await assert.rejects(reg.createJob(jobRow(t), { converge: convOpts(t, a, { versionId: 'stv_other' }) }), (e) => e.code === 'assignment_changed');
  assert.equal(reg.convergeRuns.size, 0);
});

test('claimDueChecks: per-tenant cap counts in-flight claims, budget, presence and capability filters, claim expiry, release, stale', async () => {
  const reg = await rig();
  const t = await published(reg);
  await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'tenant', checkIntervalS: 300 });
  const tb = await published(reg, 'beta', 'web', 'u-b');
  await reg.createAssignment({ tenantId: 'beta', stateId: tb.st.state_id, versionId: tb.v.version_id, actor: 'u-b', targetKind: 'tenant', checkIntervalS: 300 });
  // First checks are spread over the interval; make every row due now.
  const past = new Date(Date.now() - 1000);
  for (const r of reg.hostStates.values()) r.next_check_at = past;
  const opts = { replicaBudget: 50, perTenantCap: 1, claimExpiryS: 420 };
  assert.deepEqual(await reg.claimDueChecks(opts), [], 'no live converge agents');
  for (const h of [H1, HB]) await reg.setAgentPresence(h, { caps: ['sysscript_jobs', 'converge'], instance: 'i', connId: `c-${h}`, enrolledAt: new Date() });
  await reg.setAgentPresence(H2, { caps: ['sysscript_jobs'], instance: 'i', connId: 'c-x', enrolledAt: new Date() });
  const first = await reg.claimDueChecks(opts);
  assert.deepEqual(first.map((r) => r.host_id).sort(), [H1, HB]);
  assert.ok(first.every((r) => r.next_check_at.getTime() >= Date.now() + 419000), 'next_check_at moves to the claim expiry');
  assert.equal((await reg.claimDueChecks({ ...opts, perTenantCap: 2 })).length, 0, 'H2 is not converge-capable; claimed rows are not due');
  await reg.setAgentPresence(H2, { caps: ['sysscript_jobs', 'converge'], instance: 'i', connId: 'c-y', enrolledAt: new Date() });
  assert.deepEqual(await reg.claimDueChecks(opts), [], 'cap 1 per tenant is held by the unexpired H1 claim');
  assert.deepEqual((await reg.claimDueChecks({ ...opts, perTenantCap: 2 })).map((r) => r.host_id), [H2]);
  // Expiry, untouched rows: a claim whose run never reports is due again
  // when it expires (here after 1 s), and it is reclaimed.
  const reg2 = await rig();
  const t2 = await published(reg2);
  await reg2.createAssignment({ tenantId: 'acme', stateId: t2.st.state_id, versionId: t2.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1, checkIntervalS: 300 });
  hs(reg2, H1, t2.st.state_id).next_check_at = past;
  await reg2.setAgentPresence(H1, { caps: ['converge'], instance: 'i', connId: 'c1', enrolledAt: new Date() });
  const short = { replicaBudget: 5, perTenantCap: 5, claimExpiryS: 1 };
  assert.equal((await reg2.claimDueChecks(short)).length, 1);
  assert.equal((await reg2.claimDueChecks(short)).length, 0);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal((await reg2.claimDueChecks(short)).length, 1, 'reclaimed after expiry');
  // A conflict row with an assignment (a resource-key clash) stays claimable.
  hs(reg2, H1, t2.st.state_id).status = 'conflict';
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal((await reg2.claimDueChecks(short)).length, 1);
  assert.equal(await reg.releaseCheckClaim(H1, t.st.state_id), true);
  assert.equal(hs(reg, H1, t.st.state_id).check_claimed_at, null);
  assert.ok(hs(reg, H1, t.st.state_id).next_check_at > new Date());
  assert.equal((await reg.claimDueChecks({ ...opts, replicaBudget: 1, perTenantCap: 10 })).length, 0, 'not due');
  // Stale after 3 missed intervals.
  hs(reg, H1, t.st.state_id).last_check_at = new Date(Date.now() - 901000);
  hs(reg, H1, t.st.state_id).status = 'compliant';
  assert.equal(await reg.markStaleHostStates(), 1);
  assert.equal(hs(reg, H1, t.st.state_id).status, 'stale');
});

test('retention: check runs go with their job, reports expire with the output, plan and apply runs are kept longer', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  const c = await submit(reg, t, a);
  await finish(reg, c, report('check', { drift: 1 }));
  const p = await submit(reg, { ...t, kind: 'plan' }, a);
  await finish(reg, p, report('plan', { drift: 1 }));
  for (const id of [c.job_id, p.job_id]) {
    reg.jobs.get(id).finished_at = new Date(Date.now() - 40 * 86400000);
    reg.convergeRuns.get(id).finished_at = new Date(Date.now() - 40 * 86400000);
    reg.convergeRuns.get(id).created_at = new Date(Date.now() - 40 * 86400000);
  }
  await reg.expireOutput(72);
  assert.equal(reg.convergeRuns.get(p.job_id).report, null);
  assert.equal(reg.convergeRuns.get(p.job_id).report_expired, true);
  assert.equal(reg.convergeRuns.get(p.job_id).bundle_json, null, 'the plan bundle is past the plan max age');
  assert.ok(reg.convergeRuns.get(p.job_id).summary);
  // The expired check body is stored again by the next identical check.
  const c2 = await submit(reg, t, a);
  await finish(reg, c2, report('check', { drift: 1 }));
  assert.ok(reg.convergeRuns.get(c2.job_id).report);
  assert.equal(await reg.pruneJobs(30), 2);
  assert.equal(reg.convergeRuns.has(c.job_id), false);
  assert.equal(reg.convergeRuns.has(p.job_id), true);
});

test('memory: a failed audit append undoes the ingest (job, run, host state, alert), the finalize and the re-send', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  const real = reg.appendAudit.bind(reg);
  const refuse = () => { reg.appendAudit = async () => { throw new Error('audit refused'); }; };
  const allow = () => { reg.appendAudit = real; };
  const j = await submit(reg, t, a);
  const before = JSON.stringify(hs(reg, H1, t.st.state_id));
  refuse();
  await assert.rejects(finish(reg, j, report('check', { drift: 1 })), /audit refused/);
  allow();
  assert.equal(reg.jobs.get(j.job_id).status, 'submitted');
  assert.equal(reg.convergeRuns.get(j.job_id).report_sha256, null);
  assert.equal(reg.convergeRuns.get(j.job_id).finished_at, null);
  assert.equal(JSON.stringify(hs(reg, H1, t.st.state_id)), before);
  assert.equal(reg.alerts.length, 0);
  const ok = await finish(reg, j, report('check', { drift: 1 }));
  assert.equal(ok.converge.alerts.length, 1, 'the retry ingests');

  // A clean check that would resolve the alert: undone, the alert stays open.
  const j2 = await submit(reg, t, a);
  refuse();
  await assert.rejects(finish(reg, j2, report('check')), /audit refused/);
  allow();
  assert.equal(reg.alerts[0].status, 'open');
  assert.equal(hs(reg, H1, t.st.state_id).status, 'drifted');
  assert.equal(hs(reg, H1, t.st.state_id).check_job_id, j2.job_id);

  // Sweep finalize.
  const j3 = jobRow(t, { deadline_at: new Date(Date.now() + 1000) });
  reg.jobs.get(j2.job_id).status = 'cancelled';
  await reg.createJob(j3, { converge: convOpts(t, a) });
  refuse();
  await assert.rejects(reg.sweepJobs(Date.now() + 70000), /audit refused/);
  allow();
  assert.equal(hs(reg, H1, t.st.state_id).check_job_id, j3.job_id);
  assert.equal(reg.convergeRuns.get(j3.job_id).finished_at, null);

  // Re-send of a swept plan (a plan report is always audited).
  await reg.sweepJobs(Date.now() + 70000);
  const p = jobRow({ ...t, kind: 'plan' }, { deadline_at: new Date(Date.now() + 1000) });
  await reg.createJob(p, { converge: convOpts({ ...t, kind: 'plan' }, a) });
  await reg.sweepJobs(Date.now() + 70000);
  refuse();
  await assert.rejects(reg.ingestConvergeResend(p.job_id, H1, report('plan')), /audit refused/);
  allow();
  assert.equal(reg.convergeRuns.get(p.job_id).report_sha256, null);
  assert.equal((await reg.ingestConvergeResend(p.job_id, H1, report('plan'))).ingested, true);
});

test('memory: one apply at a time, no apply beside a check, no check beside an apply; check bundleJson must match', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  await assert.rejects(reg.createJob(jobRow(t), { converge: convOpts(t, a, { bundleJson: '{"v":1}' }) }), (e) => e.code === 'bad_job');
  const plans = [];
  for (let i = 0; i < 2; i += 1) {
    const p = await submit(reg, { ...t, kind: 'plan' }, a);
    await finish(reg, p, report('plan', { drift: 1 }));
    plans.push(p);
  }
  const chk = await submit(reg, t, a, {}, { conv: { bundleJson: BUNDLE } });
  await assert.rejects(submit(reg, { ...t, kind: 'apply' }, a, {}, { conv: { planRunId: plans[0].job_id } }), (e) => e.code === 'check_in_progress');
  await finish(reg, chk, report('check', { drift: 1 }));
  const ap = await submit(reg, { ...t, kind: 'apply' }, a, {}, { conv: { planRunId: plans[0].job_id } });
  await assert.rejects(submit(reg, { ...t, kind: 'apply' }, a, {}, { conv: { planRunId: plans[1].job_id } }), (e) => e.code === 'apply_in_progress');
  await assert.rejects(submit(reg, { ...t, kind: 'plan' }, a), (e) => e.code === 'apply_in_progress');
  // A due row whose apply is in flight is not claimed.
  hs(reg, H1, t.st.state_id).next_check_at = new Date(Date.now() - 1000);
  await reg.setAgentPresence(H1, { caps: ['converge'], instance: 'i', connId: 'c9', enrolledAt: new Date() });
  assert.deepEqual(await reg.claimDueChecks({ replicaBudget: 5, perTenantCap: 5, claimExpiryS: 420 }), []);
  await finish(reg, ap, report('apply', { changed: 1 }));
  assert.equal((await reg.claimDueChecks({ replicaBudget: 5, perTenantCap: 5, claimExpiryS: 420 })).length, 1);
});

test('memory: claim ties break on (next_check_at, host_id, state_id); a concurrent assignment update is refused, not lost', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'tenant' });
  const at = new Date(Date.now() - 1000);
  for (const r of reg.hostStates.values()) r.next_check_at = at;
  for (const h of [H2, H1]) await reg.setAgentPresence(h, { caps: ['converge'], instance: 'i', connId: `c-${h}`, enrolledAt: new Date() });
  assert.deepEqual((await reg.claimDueChecks({ replicaBudget: 1, perTenantCap: 5, claimExpiryS: 420 })).map((r) => r.host_id), [H1]);
  const out = await Promise.allSettled([
    reg.updateAssignment({ tenantId: 'acme', assignmentId: a.assignment_id, patch: { driftThreshold: 2 }, actor: 'u-a' }),
    reg.updateAssignment({ tenantId: 'acme', assignmentId: a.assignment_id, patch: { checkIntervalS: 600 }, actor: 'u-a' })
  ]);
  const won = out.filter((x) => x.status === 'fulfilled');
  assert.equal(won.length, 1);
  assert.equal(out.find((x) => x.status === 'rejected').reason.code, 'conflict');
  const cur = await reg.getAssignment(['acme'], a.assignment_id);
  assert.deepEqual([cur.drift_threshold, cur.check_interval_s], [won[0].value.drift_threshold, won[0].value.check_interval_s]);
});

test('memory: a check that ends without a report is next due one interval later, not at the claim expiry', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1, checkIntervalS: 3600 });
  hs(reg, H1, t.st.state_id).next_check_at = new Date(Date.now() - 1000);
  await reg.setAgentPresence(H1, { caps: ['converge'], instance: 'i', connId: 'c1', enrolledAt: new Date() });
  assert.equal((await reg.claimDueChecks({ replicaBudget: 5, perTenantCap: 5, claimExpiryS: 420 })).length, 1);
  const j = await submit(reg, t, a);
  await reg.transitionJob(j.job_id, H1, ['submitted'], { status: 'failed', error: 'bad_payload' }, { converge: {} });
  const row = hs(reg, H1, t.st.state_id);
  assert.equal(row.check_claimed_at, null);
  assert.ok(row.next_check_at.getTime() >= Date.now() + 0.9 * 3600000 - 1000, 'one interval (± 10%) ahead');
});

test('memory: the undo of a failed ingest removes only the alert it added', async () => {
  const reg = await rig();
  const t = await published(reg);
  const a = await reg.createAssignment({ tenantId: 'acme', stateId: t.st.state_id, versionId: t.v.version_id, actor: 'u-a', targetKind: 'host', targetValue: H1 });
  const real = reg.appendAudit.bind(reg);
  const j = await submit(reg, t, a);
  // While the audit append is pending, another writer opens an alert.
  reg.appendAudit = async () => {
    await reg.openAlert({ tenant_id: 'acme', host_id: H2, rule_name: 'cpu' });
    throw new Error('audit refused');
  };
  await assert.rejects(finish(reg, j, report('check', { drift: 1 })), /audit refused/);
  reg.appendAudit = real;
  assert.deepEqual(reg.alerts.map((x) => x.rule_name), ['cpu']);
});
