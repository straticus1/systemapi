// Threats: cross-tenant host reads, host theft by a second API key, a
// host moved to new hands by a re-enroll with the same key but another SSH
// public key (refused host_key_mismatch; the stored ssh_pubkey never changes
// on re-enroll, so an intentional rotation is an admin resetting the cp_hosts
// row on the server: UPDATE its ssh_pubkey, or DELETE it so the agent
// enrolls afresh; there is no HTTP route for it), a retired host coming back
// (retireHost stamps retired_at with a host_retired audit row in one step; a
// retired host_id is refused re-enroll as host_retired and is left out of
// resolveHosts, listHosts unless asked, countHosts and channelPolicies; the
// row is never deleted), a rewritten audit row, and a security event with no tenant shown to every
// audit reader. Queries are parameterized. A host id that belongs to another
// tenant is returned as not found. Webhook HMAC secrets are sealed before
// insert; this store does not log them. listSecurity returns only rows whose
// tenant_id is in the caller's set. Does NOT authenticate the caller.
'use strict';

const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { GENESIS, canonicalJSON, rowHash, verifyRows } = require('./chain');
const { scopesForKeyRows } = require('./authz');
const { escapeLike, efficiency: efficiencyOf } = require('./stats');
const { fingerprint } = require('./token');
const { assertPolicyShape } = require('./channels');
const { demoKeyAllowed } = require('./httpauth');
const { sshKeyMaterial } = require('./sshkey');
const {
  AUTO_ACTOR, CONVERGE_SOURCES, HOST_STATE_STATUSES, RUN_KINDS, applyRunRetentionDays, assignmentInput, assignmentPatch, convergeOutcome,
  convergeReport, driftRule, effectiveAssignments, firstCheckOffsetS, hostStateDiff, isConvergeSource, newId,
  planMaxAgeS, sha256Hex, stateInput, tagsInput, versionInput
} = require('./statestore');

const METRICS = new Set(['cpu.usage_percent', 'memory.used_percent', 'disk.used_percent']);
const ROLES = new Set(['admin', 'operator', 'viewer']);
const SCHEMA_SQL = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
// The playground tables (API keys, legacy hosts) the app reads but did not
// create: applied at boot after the control-plane schema, keys file first
// (the fleet file references playground_api_keys). Both are idempotent.
const PLAYGROUND_SQL = ['playground_schema.sql', 'playground_fleet_schema.sql']
  .map((name) => fs.readFileSync(path.join(__dirname, '..', 'playground', name), 'utf8'));
const TELEMETRY_CAP = 5000;
const DEMO_KEY_ID = 'ak_live_1234';

function http(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function publicHost(row) {
  if (!row) return null;
  return {
    host_id: row.host_id,
    tenant_id: row.tenant_id,
    hostname: row.hostname,
    os: row.os || '',
    platform: row.platform || '',
    ssh_pubkey: row.ssh_pubkey,
    status: row.status,
    last_seen_at: row.last_seen_at,
    tags: row.tags || [],
    created_at: row.created_at,
    retired_at: row.retired_at || null,
    cpu_percent: row.cpu_percent ?? null,
    sparkline: row.sparkline || []
  };
}

function publicWebhook(row) {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    url: row.url,
    secret_fingerprint: row.secret_fingerprint,
    created_at: row.created_at
  };
}

// The chain-wide audit lock: the two-int advisory form (its own key space,
// apart from the hashtext single-key locks), namespace 'SAPI', key 1.
const AUDIT_LOCK_NS = 0x53415049;
const AUDIT_LOCK_KEY = 1;

// Appends one chained audit row inside the caller's transaction. The tail is
// read only under the chain-wide transaction lock: a row lock alone (FOR
// UPDATE on the tail) lets a READ COMMITTED waiter wake up on the old tail
// after the holder commits a newer row, and the chain forks. Lock order:
// callers take every other lock (rows, sjob:*, cp_members.sso_sub) before
// their first audit row, so the chain lock is always the last one taken.
async function auditInsert(client, entry) {
  await client.query('SELECT pg_advisory_xact_lock($1::int, $2::int)', [AUDIT_LOCK_NS, AUDIT_LOCK_KEY]);
  const prevRes = await client.query('SELECT row_hash FROM cp_audit ORDER BY seq DESC LIMIT 1');
  const prev = prevRes.rows[0] ? prevRes.rows[0].row_hash : GENESIS;
  const payload = JSON.parse(canonicalJSON(entry.payload || {}));
  const cols = {
    tenant_id: entry.tenant_id || null,
    host_id: entry.host_id || null,
    actor: entry.actor || null,
    action: entry.action,
    payload
  };
  const hash = rowHash(prev, cols);
  const ins = await client.query(
    `INSERT INTO cp_audit (prev_hash, row_hash, tenant_id, host_id, actor, action, payload)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
     RETURNING seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload, created_at`,
    [prev, hash, cols.tenant_id, cols.host_id, cols.actor, cols.action, JSON.stringify(payload)]
  );
  return ins.rows[0];
}

// The audit row for an SSO bind or unbind. The sub is recorded as a
// fingerprint, never in clear.
function ssoAuditEntry(tenantId, userId, sub, previous, actor) {
  return {
    tenant_id: tenantId,
    actor,
    action: sub === null ? 'sso_unbind' : 'sso_bind',
    payload: {
      user_id: userId,
      sso_sub_fp: sub === null ? null : fingerprint(sub),
      previous_fp: previous ? fingerprint(previous) : null
    }
  };
}

// The SSO bind (or unbind, sub null) of one membership row inside the
// caller's transaction: PgRegistry.setSsoSub and bootstrapAdmin share it.
// The advisory lock serializes binds, so the "one sub, one member id" check
// cannot race.
async function ssoBindInTx(client, { tenantId, userId, sub, actor }) {
  await client.query("SELECT pg_advisory_xact_lock(hashtext('cp_members.sso_sub'))");
  const cur = await client.query(
    'SELECT sso_sub FROM cp_members WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE',
    [tenantId, userId]
  );
  if (!cur.rows[0]) throw http(404, 'not_found');
  if (sub !== null) {
    const taken = await client.query(
      'SELECT 1 FROM cp_members WHERE sso_sub = $1 AND user_id <> $2 LIMIT 1',
      [sub, userId]
    );
    if (taken.rowCount > 0) throw http(409, 'sso_sub_taken');
    const conflict = await client.query(
      `SELECT 1 FROM cp_members
       WHERE user_id = $1 AND tenant_id <> $2 AND sso_sub IS NOT NULL AND sso_sub <> $3 LIMIT 1`,
      [userId, tenantId, sub]
    );
    if (conflict.rowCount > 0) throw http(409, 'sso_sub_conflict');
  }
  await client.query(
    'UPDATE cp_members SET sso_sub = $3 WHERE tenant_id = $1 AND user_id = $2',
    [tenantId, userId, sub]
  );
  await auditInsert(client, ssoAuditEntry(tenantId, userId, sub, cur.rows[0].sso_sub || null, actor));
  return { tenant_id: tenantId, user_id: userId, bound: sub !== null };
}

// The audit row for a host channel policy write: why, and the new and the
// previous policies of both columns.
function channelPolicyAuditEntry(tenantId, hostId, actor, action, reason, tcpPolicy, filePolicy, prevTcp, prevFile) {
  return {
    tenant_id: tenantId,
    host_id: hostId,
    actor,
    action,
    payload: {
      reason: reason ?? null,
      tcp_policy: tcpPolicy,
      file_policy: filePolicy,
      previous_tcp_policy: prevTcp ?? null,
      previous_file_policy: prevFile ?? null
    }
  };
}

// The audit row for a host retirement: why, who, and what the row was.
function hostRetiredAuditEntry(row, actor, reason, forced) {
  return {
    tenant_id: row.tenant_id,
    host_id: row.host_id,
    actor,
    action: 'host_retired',
    payload: {
      reason,
      hostname: row.hostname,
      forced: forced === true,
      last_seen_at: row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null
    }
  };
}

function retireReason(reason) {
  if (typeof reason !== 'string' || reason.trim() === '') throw http(400, 'reason_required');
  if (reason.length > 256) throw http(400, 'bad_reason');
  return reason.trim();
}

// Async sysscript jobs (cp_sysscript_jobs; .omc/plans/async-sysscript-jobs.md
// §6-§7). Threats: a job read or cancelled from another tenant (every read
// and user write carries a tenant predicate), an agent frame for another
// host's job (every agent-driven write carries host_id, and conn_id where it
// applies, in the WHERE), a terminal row rewritten (transitions only leave
// non-terminal statuses), the job caps raced past (advisory locks, then count
// and insert in one transaction), and the script kept at rest (dispatch is
// nulled when it is claimed or the job ends; reads never return it). Does NOT
// decide who may see output or cancel: the routes do.
const JOB_STATUSES = new Set(['submitted', 'accepted', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out']);
const JOB_ACTIVE = ['submitted', 'accepted', 'running'];
const JOB_SOURCES = new Set(['api', 'execute', 'fleet_execute', 'playbook', 'schedule', 'rule',
  'converge_check', 'converge_plan', 'converge_apply']);
const JOB_ID_RE = /^sjb_[A-Za-z0-9_-]{22}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const JOB_CHANNEL = 'cp_sysscript_jobs';
const JOB_EVENT_KINDS = new Set(['dispatch', 'cancel', 'state']);
const JOB_LIST_MAX = 200;
const JOB_SYNC_MAX = 1024;
// Rows one sweep ends: it holds the audit chain lock for one end row each,
// so the batch is bounded; the next tick takes the rest.
const JOB_SWEEP_BATCH = 500;
const JOB_ERROR_MAX = 1024;
// Stored output cap, in UTF-8 bytes (the agent's own cap, plan §4.2).
const JOB_OUTPUT_MAX = 1024 * 1024;
const ERROR_CODE_RE = /^[a-z_]{1,64}$/;
const JOB_COLS = ['job_id', 'tenant_id', 'host_id', 'actor', 'source', 'script_sha256', 'entitlements_sha256',
  'entitlements', 'status', 'error', 'output', 'output_truncated', 'output_expired', 'timeout_s', 'deadline_at',
  'lease_nonce', 'conn_id', 'sent_at', 'alert_count', 'cancel_requested_at', 'cancel_sent_at', 'cancel_actor',
  'created_at', 'accepted_at', 'started_at', 'finished_at', 'duration_ms'];

// The column list interpolated into job SQL. SECURITY-RULES rule 7: it is
// built only from the JOB_COLS constant and a constant prefix ('' or 'j.'),
// never from input; every value is a bound parameter.
function jobCols(prefix = '', { output = true } = {}) {
  return JOB_COLS.filter((c) => output || c !== 'output').map((c) => prefix + c).join(', ');
}

function isTerminal(status) {
  return JOB_STATUSES.has(status) && !JOB_ACTIVE.includes(status);
}

function nonEmpty(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256;
}

function toDate(value) {
  const d = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

// The checked insert row of createJob. Anything malformed is 400 bad_job.
function jobInsertRow(row) {
  const r = row || {};
  const deadline = r.deadline_at == null ? null : toDate(r.deadline_at);
  const ent = r.entitlements === undefined ? {} : r.entitlements;
  const ok = JOB_ID_RE.test(String(r.job_id))
    && nonEmpty(r.tenant_id) && nonEmpty(r.host_id) && nonEmpty(r.actor)
    && JOB_SOURCES.has(r.source)
    && SHA256_RE.test(String(r.script_sha256)) && SHA256_RE.test(String(r.entitlements_sha256))
    && ent !== null && typeof ent === 'object' && !Array.isArray(ent)
    && Number.isInteger(r.timeout_s) && r.timeout_s >= 1 && r.timeout_s <= 3600
    && deadline !== null && deadline.getTime() > Date.now()
    && NONCE_RE.test(String(r.lease_nonce))
    && r.dispatch !== null && typeof r.dispatch === 'object' && !Array.isArray(r.dispatch);
  if (!ok) throw http(400, 'bad_job');
  return {
    job_id: r.job_id,
    tenant_id: r.tenant_id,
    host_id: r.host_id,
    actor: r.actor,
    source: r.source,
    script_sha256: r.script_sha256,
    entitlements_sha256: r.entitlements_sha256,
    entitlements: JSON.parse(JSON.stringify(ent)),
    timeout_s: r.timeout_s,
    deadline_at: deadline,
    lease_nonce: r.lease_nonce,
    dispatch: JSON.parse(JSON.stringify(r.dispatch))
  };
}

function jobCaps(opts = {}) {
  const hostCap = opts.hostCap === undefined ? 8 : opts.hostCap;
  const tenantCap = opts.tenantCap === undefined ? 64 : opts.tenantCap;
  if (!Number.isInteger(hostCap) || hostCap < 1 || !Number.isInteger(tenantCap) || tenantCap < 1) {
    throw http(500, 'bad_job_caps');
  }
  return { hostCap, tenantCap };
}

// fromStatuses must be non-terminal and the target a different, later
// status: terminal rows never change.
function jobTransition(fromStatuses, fields) {
  const from = Array.isArray(fromStatuses) ? [...new Set(fromStatuses)] : [];
  const to = fields && fields.status;
  if (from.length === 0 || !from.every((s) => JOB_ACTIVE.includes(s))
    || !JOB_STATUSES.has(to) || to === 'submitted' || from.includes(to)) {
    throw http(500, 'bad_job_transition');
  }
  const set = { status: to };
  if ('error' in fields) set.error = fields.error == null ? null : noNul(String(fields.error)).slice(0, JOB_ERROR_MAX);
  if ('output' in fields) {
    if (fields.output !== null && typeof fields.output !== 'string') throw http(400, 'bad_job_output');
    set.output = fields.output === null ? null : noNul(fields.output);
  }
  if ('output_truncated' in fields) set.output_truncated = fields.output_truncated === true;
  if (typeof set.output === 'string' && Buffer.byteLength(set.output, 'utf8') > JOB_OUTPUT_MAX) {
    set.output = truncateUtf8(set.output, JOB_OUTPUT_MAX);
    set.output_truncated = true;
  }
  if ('duration_ms' in fields) {
    const n = fields.duration_ms;
    set.duration_ms = Number.isInteger(n) && n >= 0 && n <= 2147483647 ? n : null;
  }
  return { from, set };
}

// At most max UTF-8 bytes, cut on a character boundary.
function truncateUtf8(text, max) {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= max) return text;
  let end = max;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end -= 1;
  return buf.subarray(0, end).toString('utf8');
}

// The memory mirror of the SET clause PgRegistry.transitionJob builds.
function applyJobSet(row, set, now) {
  Object.assign(row, set);
  if (set.status === 'accepted' || set.status === 'running') row.accepted_at = row.accepted_at || now;
  if (set.status === 'running') row.started_at = row.started_at || now;
  if (isTerminal(set.status)) {
    row.finished_at = now;
    row.dispatch = null;
  }
}

function jobAlertCap(max) {
  if (!Number.isInteger(max) || max < 1 || max > 1000) throw http(500, 'bad_alert_cap');
  return max;
}

// sweepJobs inputs: ack timeout (default 15 s), dispatch timeout (60 s, the
// lease TTL) and the grace after the deadline (60 s). The cutoff dates are
// for MemoryRegistry; PgRegistry computes them from now() in SQL.
function jobSweep(now, opts = {}) {
  const at = toDate(now);
  const ms = (v, d) => (v === undefined ? d : v);
  const ackMs = ms(opts.ackMs, 15000);
  const dispatchMs = ms(opts.dispatchMs, 60000);
  const graceMs = ms(opts.graceMs, 60000);
  if (!at || ![ackMs, dispatchMs, graceMs].every((v) => Number.isInteger(v) && v >= 0)) throw http(500, 'bad_job_sweep');
  return {
    ackMs,
    dispatchMs,
    graceMs,
    ackCutoff: new Date(at.getTime() - ackMs),
    dispatchCutoff: new Date(at.getTime() - dispatchMs),
    deadlineCutoff: new Date(at.getTime() - graceMs),
    connIds: connIdList(opts.connectedConnIds)
  };
}

function jobListQuery(opts = {}) {
  const hostId = opts.hostId == null ? null : String(opts.hostId);
  const status = opts.status == null ? null : opts.status;
  if (status !== null && !JOB_STATUSES.has(status)) throw http(400, 'bad_status');
  const n = opts.limit === undefined ? 50 : Number(opts.limit);
  const limit = Number.isInteger(n) && n >= 1 ? Math.min(n, JOB_LIST_MAX) : 50;
  return { hostId, status, limit };
}

function syncIds(listedIds) {
  if (!Array.isArray(listedIds) || listedIds.length > JOB_SYNC_MAX) throw http(400, 'bad_job_sync');
  return [...new Set(listedIds.filter((id) => typeof id === 'string' && JOB_ID_RE.test(id)))];
}

function connIdList(ids) {
  return Array.isArray(ids) ? ids.filter((id) => typeof id === 'string' && id.length > 0) : [];
}

// The NOTIFY payload, also what onJobEvent handlers receive. Anything else
// is dropped.
function jobEvent(evt) {
  if (!evt || !JOB_EVENT_KINDS.has(evt.k) || !JOB_ID_RE.test(String(evt.job_id)) || !nonEmpty(evt.host_id)) return null;
  return { k: evt.k, job_id: evt.job_id, host_id: evt.host_id, status: JOB_STATUSES.has(evt.status) ? evt.status : null };
}

function stateEvent(row, k = 'state') {
  return { k, job_id: row.job_id, host_id: row.host_id, status: row.status };
}

function jobSubmitAuditEntry(row) {
  return {
    tenant_id: row.tenant_id,
    host_id: row.host_id,
    actor: row.actor,
    action: 'sysscript_job_submit',
    payload: {
      job_id: row.job_id,
      script_sha256: row.script_sha256,
      entitlements_sha256: row.entitlements_sha256,
      timeout_s: row.timeout_s,
      lease_nonce: row.lease_nonce,
      source: row.source
    }
  };
}

function jobCancelAuditEntry(row, actor, reason) {
  return {
    tenant_id: row.tenant_id,
    host_id: row.host_id,
    actor,
    action: 'sysscript_job_cancel',
    payload: { job_id: row.job_id, reason }
  };
}

function jobEndAuditEntry(row, actor) {
  return {
    tenant_id: row.tenant_id,
    host_id: row.host_id,
    actor,
    action: 'sysscript_job_end',
    payload: {
      job_id: row.job_id,
      status: row.status,
      // Only a code-shaped error goes into the audit chain; free text from
      // the agent stays on the row.
      error_code: row.error == null ? null : (ERROR_CODE_RE.test(String(row.error)) ? String(row.error) : 'agent_error'),
      duration_ms: row.duration_ms == null ? null : row.duration_ms,
      alerts: row.alert_count || 0
    }
  };
}

// transitionJob's opts.audit: {actor} writes the end row for a terminal
// status; {actor, action, payload} writes that row instead.
function transitionAuditEntry(row, audit) {
  if (!audit) return null;
  if (audit.action) return { tenant_id: row.tenant_id, host_id: row.host_id, actor: audit.actor || null, action: audit.action, payload: audit.payload || {} };
  if (!isTerminal(row.status)) throw http(500, 'bad_job_audit');
  return jobEndAuditEntry(row, audit.actor || 'system');
}

function transitionNotify(row, notify) {
  if (!notify) return null;
  return stateEvent(row, notify === true ? 'state' : notify);
}

// A copy of a row without dispatch (the script and lease never leave the
// registry through a read), and without output when withOutput is false.
function publicJob(row, { withOutput = true } = {}) {
  if (!row) return null;
  const out = {};
  for (const c of JOB_COLS) {
    if (c === 'output' && !withOutput) continue;
    const v = row[c];
    if (v instanceof Date) out[c] = new Date(v.getTime());
    else if (c === 'entitlements') out[c] = v == null ? {} : JSON.parse(JSON.stringify(v));
    else out[c] = v === undefined ? null : v;
  }
  return out;
}

// Capability tokens as parseCapabilities (channels.js) accepts them, at
// most 16.
function agentCapList(caps) {
  return [...(caps || [])].filter((c) => typeof c === 'string' && /^[a-z][a-z0-9_]{0,15}$/.test(c)).slice(0, 16);
}

function agentPresence(caps, instance, connId, enrolledAt) {
  const at = enrolledAt == null ? null : toDate(enrolledAt);
  if (!nonEmpty(instance) || !nonEmpty(connId) || !at) throw http(500, 'bad_agent_presence');
  return { caps: agentCapList(caps), instance, connId, enrolledAt: at };
}

// Postgres TEXT cannot hold U+0000 (22021): a result or alert that carries
// one would fail to store and be lost. It becomes U+FFFD.
function noNul(text) {
  return text.includes('\u0000') ? text.replace(/\u0000/g, '\uFFFD') : text;
}

function jobRetentionDays(env) {
  const n = Number(env && env.SYSTEMAPI_JOB_RETENTION_DAYS);
  if (!Number.isInteger(n) || n < 1 || n > 3650) return 30;
  return n;
}

function jobOutputRetentionHours(env) {
  const n = Number(env && env.SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS);
  if (!Number.isInteger(n) || n < 1 || n > 8760) return 72;
  return n;
}

// Delivers one event to every handler; a handler that throws, or whose
// promise rejects, is logged and does not stop the others.
function deliverJobEvent(emitter, evt) {
  const failed = (err) => console.error(`[control] job event handler failed: ${err && err.message}`);
  for (const fn of emitter.listeners('event')) {
    try {
      const out = fn(evt);
      if (out && typeof out.then === 'function') out.then(undefined, failed);
    } catch (err) {
      failed(err);
    }
  }
}

// Desired state and converge runs (cp_states, cp_state_versions,
// cp_state_assignments, cp_host_state, cp_converge_runs;
// .omc/plans/convergence-drift.md §5-§8; pure rules in statestore.js).
// Threats: a state, version, assignment, host state or run read or written
// from another tenant (every read and user write carries a tenant
// predicate; agent-driven writes go through the job row, matched on
// host_id), a late or duplicate result overwriting a newer run (host-state
// writes are conditional on check_job_id for check and plan runs and on
// last_apply_run_id for apply runs; a run's report is written once, guarded
// by report_sha256 IS NULL), a plan burned by a refused submit (consumed in
// the createJob transaction, after the caps), a plan applied stale,
// truncated, unapproved, superseded or twice, and duplicate drift alerts
// across replicas (ON CONFLICT on the active-drift unique index). Lock
// order: job rows, then converge run rows, then cp_host_state rows (in
// (host_id, state_id) order), then alert rows, then the audit chain lock
// last. Does NOT decide scopes, roles or who may see diffs, source or vars:
// the routes do.
const RUN_LIST_MAX = 200;
const RUN_COLS = ['run_id', 'tenant_id', 'host_id', 'state_id', 'assignment_id', 'version_id', 'kind', 'actor',
  'plan_run_id', 'parent_job_id', 'plan_sha256', 'plan_truncated', 'report_sha256', 'summary', 'report_expired',
  'approved_by', 'approved_at', 'consumed_by_run_id', 'created_at', 'finished_at'];
const HOST_STATE_COLS = ['host_id', 'state_id', 'tenant_id', 'assignment_id', 'version_id', 'status', 'facts',
  'consecutive_drift', 'last_error', 'last_check_run_id', 'last_check_at', 'last_apply_run_id',
  'last_applied_version_id', 'last_applied_at', 'manual_apply_assignment_id', 'manual_apply_version_id',
  'auto_apply_failures', 'last_report_sha256', 'next_check_at', 'check_claimed_at', 'check_job_id'];
const ASSIGNMENT_COLS = ['assignment_id', 'tenant_id', 'state_id', 'version_id', 'target_kind', 'target_value', 'vars',
  'check_interval_s', 'drift_threshold', 'auto_remediate', 'require_approval', 'created_by', 'created_at', 'updated_at'];

// SECURITY-RULES rule 7: column lists interpolated into SQL come only from
// the constant arrays above and a constant prefix, never from input.
function cols(list, prefix = '') {
  return list.map((c) => prefix + c).join(', ');
}

function copyValue(v) {
  if (v instanceof Date) return new Date(v.getTime());
  if (v !== null && typeof v === 'object') return JSON.parse(JSON.stringify(v));
  return v === undefined ? null : v;
}

function pick(row, list) {
  if (!row) return null;
  const out = {};
  for (const c of list) out[c] = copyValue(row[c]);
  return out;
}

function publicState(row) {
  return pick(row, ['state_id', 'tenant_id', 'name', 'description', 'created_by', 'created_at', 'archived_at']);
}

// Without files unless withFiles (the source is for state:write holders).
function publicVersion(row, { withFiles = false } = {}) {
  const out = pick(row, ['version_id', 'state_id', 'tenant_id', 'version', 'files_sha256', 'entitlements',
    'entitlements_sha256', 'published_by', 'notes', 'published_at']);
  if (out && withFiles) out.files = copyValue(row.files);
  return out;
}

function publicAssignment(row) {
  return pick(row, ASSIGNMENT_COLS);
}

function publicHostState(row) {
  return pick(row, HOST_STATE_COLS);
}

// Never bundle_json unless withBundle (the apply route needs the plan's
// exact bytes), never report unless withReport.
function publicRun(row, { withReport = false, withBundle = false } = {}) {
  const out = pick(row, RUN_COLS);
  if (!out) return null;
  if (withReport) out.report = copyValue(row.report);
  if (withBundle) out.bundle_json = row.bundle_json == null ? null : row.bundle_json;
  return out;
}

function stateAuditEntry(tenantId, hostId, actor, action, payload) {
  return { tenant_id: tenantId, host_id: hostId || null, actor, action, payload };
}

function assignmentAuditPayload(row, op) {
  return {
    op,
    assignment_id: row.assignment_id,
    state_id: row.state_id,
    version_id: row.version_id,
    target_kind: row.target_kind,
    target_value: row.target_value,
    check_interval_s: row.check_interval_s,
    drift_threshold: row.drift_threshold,
    auto_remediate: row.auto_remediate,
    require_approval: row.require_approval
  };
}

// createJob's opts.converge: {kind, stateId, assignmentId, versionId,
// planRunId (apply), bundleJson (plan), parentJobId}. The job source must
// be the kind's; a converge source needs opts.converge.
function convergeJobInput(r, c) {
  if (c === undefined || c === null) {
    if (isConvergeSource(r.source)) throw http(400, 'bad_job');
    return null;
  }
  const ok = c !== null && typeof c === 'object' && r.source === CONVERGE_SOURCES[c.kind]
    && nonEmpty(c.stateId)
    && (c.kind === 'apply' ? nonEmpty(c.planRunId) : nonEmpty(c.assignmentId) && nonEmpty(c.versionId))
    && (c.parentJobId === undefined || c.parentJobId === null || nonEmpty(c.parentJobId))
    && (c.kind !== 'plan' || (typeof c.bundleJson === 'string' && sha256Hex(c.bundleJson) === r.script_sha256));
  if (!ok) throw http(400, 'bad_job');
  return {
    kind: c.kind,
    state_id: c.stateId,
    assignment_id: c.kind === 'apply' ? null : c.assignmentId,
    version_id: c.kind === 'apply' ? null : c.versionId,
    plan_run_id: c.kind === 'apply' ? c.planRunId : null,
    bundle_json: c.kind === 'plan' ? c.bundleJson : null,
    parent_job_id: c.parentJobId || null
  };
}

// The checks createJob makes on a converge job against the rows it read
// (and locked) in its transaction: hs the host's cp_host_state row,
// version the effective version, assignment the effective assignment,
// plan (apply) the plan run with its job's status and age in seconds.
// Returns the run's assignment and version.
function convergeCreateCheck(r, c, { hs, version, assignment, plan, planJobStatus, planAgeS, maxAgeS }) {
  if (!hs || hs.tenant_id !== r.tenant_id || hs.assignment_id == null || !assignment) throw http(409, 'state_not_assigned');
  if (c.kind !== 'apply') {
    if (hs.assignment_id !== c.assignment_id || hs.version_id !== c.version_id) throw http(409, 'assignment_changed');
  } else {
    if (!plan || plan.kind !== 'plan' || plan.tenant_id !== r.tenant_id || plan.host_id !== r.host_id
      || plan.state_id !== c.state_id || planJobStatus !== 'succeeded' || plan.report_sha256 == null || plan.plan_sha256 == null) {
      throw http(409, 'plan_required');
    }
    if (plan.consumed_by_run_id) throw http(409, 'plan_consumed');
    if (plan.plan_truncated) throw http(409, 'plan_truncated');
    if (planAgeS > maxAgeS || plan.bundle_json == null) throw http(409, 'plan_expired');
    if (hs.assignment_id !== plan.assignment_id || hs.version_id !== plan.version_id) throw http(409, 'plan_superseded');
    if (assignment.require_approval && !plan.approved_by) throw http(409, 'approval_required');
    if (sha256Hex(plan.bundle_json) !== r.script_sha256) throw http(409, 'plan_bundle_mismatch');
  }
  if (!version || version.version_id !== hs.version_id || version.entitlements_sha256 !== r.entitlements_sha256) {
    throw http(409, 'entitlements_mismatch');
  }
  return { assignment_id: hs.assignment_id, version_id: hs.version_id };
}

// transitionJob on a converge row: the report is validated before the
// UPDATE. Returns {set, rep, bad}: a terminal status with a malformed (or,
// for succeeded, missing) report becomes failed[bad_report].
function convergeVerdict(from, fields, set, opts, job) {
  if (!isTerminal(set.status) || !job || !isConvergeSource(job.source)) return { set, rep: null, bad: null };
  const report = opts.converge ? opts.converge.report : undefined;
  let bad = null;
  let rep = null;
  if (report === undefined || report === null) {
    if (set.status === 'succeeded') bad = 'missing';
  } else {
    const kind = job.source.slice('converge_'.length);
    const v = convergeReport(report, kind, job.script_sha256);
    if (!v.ok) bad = v.reason;
    else if (set.status === 'succeeded' && v.report.summary.failed + v.report.summary.denied > 0) bad = 'status_mismatch';
    else rep = v;
  }
  if (!bad) return { set, rep, bad: null };
  const { set: failed } = jobTransition(from, { ...fields, status: 'failed', error: 'bad_report' });
  return { set: failed, rep: null, bad };
}

function badReportEvent(job, reason) {
  return {
    tenant_id: job.tenant_id,
    kind: 'converge_bad_report',
    actor_fingerprint: null,
    detail: { job_id: job.job_id, host_id: job.host_id, reason }
  };
}

// The audit row of an ingested report: always for plan and apply, for a
// check only when the host status changed.
function reportAuditEntry(run, job, sha, rep, prevStatus, status) {
  if (run.kind === 'check' && (status === null || status === prevStatus)) return null;
  return stateAuditEntry(run.tenant_id, run.host_id, 'system', 'state_report', {
    run_id: run.run_id,
    state_id: run.state_id,
    version_id: run.version_id,
    kind: run.kind,
    job_status: job.status,
    report_sha256: sha,
    summary: rep.summary,
    prev_status: prevStatus,
    status
  });
}

function driftAlertEntry(run, rep) {
  return {
    tenant_id: run.tenant_id,
    host_id: run.host_id,
    rule_name: driftRule(run.state_id),
    value: rep.summary.drift,
    severity: 'warning',
    message: `drift: ${rep.summary.drift} resource(s)`
  };
}

// The cp_host_state change of an ingest (v a convergeReport result) or a
// finalize (v null) on the row hs this run still owns; clash is a resource
// key also declared by another state on the host. Returns {set, now,
// nextCheck}: set the column values, now the columns set to the clock,
// nextCheck whether next_check_at moves one interval (± 10%) ahead.
function hostStateUpdate(run, job, v, hs, clash) {
  const rep = v ? v.report : null;
  const out = convergeOutcome(run.kind, job.status, rep, hs);
  let status = out.status;
  let lastError = job.error == null ? null : noNul(String(job.error)).slice(0, JOB_ERROR_MAX);
  if (clash) {
    status = 'conflict';
    lastError = 'resource_key_conflict';
  }
  const auto = run.actor === AUTO_ACTOR;
  const set = {};
  const now = [];
  let nextCheck = false;
  if (run.kind === 'apply') {
    Object.assign(set, { status, consecutive_drift: out.consecutive_drift, last_error: lastError });
    if (rep) set.facts = v.facts;
    if (status === 'compliant') {
      set.last_applied_version_id = run.version_id;
      now.push('last_applied_at');
      if (!auto) Object.assign(set, { manual_apply_assignment_id: run.assignment_id, manual_apply_version_id: run.version_id, auto_apply_failures: 0 });
    } else if (auto) {
      set.auto_apply_failures = (hs.auto_apply_failures || 0) + 1;
    }
  } else if (rep) {
    Object.assign(set, {
      status, facts: v.facts, consecutive_drift: out.consecutive_drift, last_error: lastError,
      last_check_run_id: run.run_id, check_claimed_at: null, check_job_id: null
    });
    if (run.kind === 'check') set.last_report_sha256 = v.sha256;
    now.push('last_check_at');
    nextCheck = true;
  } else {
    Object.assign(set, { check_claimed_at: null, check_job_id: null, last_error: lastError });
  }
  return { set, now, nextCheck };
}

function claimInput({ replicaBudget, perTenantCap, claimExpiryS, presenceFreshS = 90 } = {}) {
  const ok = [replicaBudget, perTenantCap, claimExpiryS, presenceFreshS].every((n) => Number.isInteger(n) && n >= 1)
    && replicaBudget <= 1000 && perTenantCap <= 1000 && claimExpiryS <= 86400 && presenceFreshS <= 3600;
  if (!ok) throw http(500, 'bad_claim');
  return { replicaBudget, perTenantCap, claimExpiryS, presenceFreshS };
}

function runListQuery(opts = {}) {
  const hostId = opts.hostId == null ? null : String(opts.hostId);
  const stateId = opts.stateId == null ? null : String(opts.stateId);
  const kind = opts.kind == null ? null : opts.kind;
  if (kind !== null && !RUN_KINDS.has(kind)) throw http(400, 'bad_kind');
  const n = opts.limit === undefined ? 50 : Number(opts.limit);
  const limit = Number.isInteger(n) && n >= 1 ? Math.min(n, RUN_LIST_MAX) : 50;
  return { hostId, stateId, kind, limit };
}

function hostStateQuery({ hostId = null, stateId = null, status = null } = {}) {
  if (status !== null && !HOST_STATE_STATUSES.has(status)) throw http(400, 'bad_status');
  return { hostId: hostId == null ? null : String(hostId), stateId: stateId == null ? null : String(stateId), status };
}

function hsKey(hostId, stateId) {
  return `${hostId}\u0000${stateId}`;
}

class MemoryRegistry {
  constructor(env = {}) {
    this.env = env;
    this.tenants = new Map();
    this.members = [];
    this.hosts = new Map();
    this.telemetry = [];
    this.metricInserts = 0;
    this.alerts = [];
    this.alertSeq = 1;
    this.audit = [];
    this.auditSeq = 1;
    this.auditChain = Promise.resolve();
    this.webhooks = [];
    this.schedules = [];
    this.comments = [];
    this.commentSeq = 1;
    this.securityEvents = [];
    this.securitySeq = 1;
    this.scopes = new Map();
    this.revokedKeys = new Set();
        this.software = [];
    this.cves = [];
    // Channel policies live apart from host rows so publicHost never sees them.
    this.hostPolicies = new Map();
    this.tenantPolicies = new Map();
    this.jobs = new Map();
    this.jobBus = new EventEmitter();
    this.states = new Map();
    this.stateVersions = new Map();
    this.assignments = new Map();
    this.hostStates = new Map();
    this.convergeRuns = new Map();
  }

  async enroll({ tenantId, userId, keyId, hostId, hostname, os, platform, sshPubkey }) {
    const existing = this.tenants.get(tenantId);
    const mine = this.members.filter((m) => m.user_id === userId);
    if (!existing) {
      if (mine.length > 0) throw http(403, 'tenant_create_denied');
      this.tenants.set(tenantId, {
        tenant_id: tenantId,
        display_name: tenantId,
        owner_user_id: userId,
        created_at: new Date().toISOString()
      });
      this.members.push({ tenant_id: tenantId, user_id: userId, email: null, role: 'admin' });
    } else if (!mine.some((m) => m.tenant_id === tenantId)) {
      throw http(403, 'not_a_member');
    }
    const prev = this.hosts.get(hostId);
    if (prev && (prev.tenant_id !== tenantId || prev.key_id !== keyId)) {
      throw http(403, 'host_steal');
    }
    if (prev && prev.retired_at) throw http(403, 'host_retired');
    if (prev && sshKeyMaterial(prev.ssh_pubkey) !== sshKeyMaterial(sshPubkey)) {
      throw http(403, 'host_key_mismatch');
    }
    const now = new Date().toISOString();
    this.hosts.set(hostId, {
      host_id: hostId,
      tenant_id: tenantId,
      key_id: keyId,
      hostname,
      os: os || '',
      platform: platform || '',
      ssh_pubkey: prev ? prev.ssh_pubkey : sshPubkey,
      status: 'online',
      last_seen_at: now,
      tags: prev ? prev.tags : [],
      created_at: prev ? prev.created_at : now,
      retired_at: null
    });
    this.memSync(tenantId, hostId);
    return this.getHost([tenantId], hostId);
  }

  tenantIdsOf(userId) {
    return this.members.filter((m) => m.user_id === userId).map((m) => m.tenant_id);
  }

  // Identity is the member id only; email is display data, never a match key.
  async membershipsForUser(userId) {
    return this.members
      .filter((m) => m.user_id === userId)
      .map((m) => ({ ...m }));
  }

  // Rows whose sso_sub is exactly this Authentik sub (byte-exact).
  async membershipsForSub(sub) {
    if (typeof sub !== 'string' || sub.length === 0) return [];
    return this.members.filter((m) => m.sso_sub === sub).map((m) => ({ ...m }));
  }

  // A member's identity is the same in every tenant: binding a row to a sub
  // that differs from another bound row of that member is refused
  // (sso_sub_conflict); changing it means unbinding every row first.
  // Sets (or clears, with sub null) one membership row's sso_sub and appends
  // the audit row; the row is put back if the audit write fails.
  async setSsoSub({ tenantId, userId, sub, actor }) {
    const row = this.members.find((m) => m.tenant_id === tenantId && m.user_id === userId);
    if (!row) throw http(404, 'not_found');
    if (sub !== null && this.members.some((m) => m.sso_sub === sub && m.user_id !== userId)) {
      throw http(409, 'sso_sub_taken');
    }
    if (sub !== null && this.members.some((m) => m.user_id === userId && m.tenant_id !== tenantId
      && m.sso_sub != null && m.sso_sub !== sub)) {
      throw http(409, 'sso_sub_conflict');
    }
    const previous = row.sso_sub || null;
    row.sso_sub = sub;
    try {
      await this.appendAudit(ssoAuditEntry(tenantId, userId, sub, previous, actor));
    } catch (err) {
      row.sso_sub = previous;
      throw err;
    }
    return { tenant_id: tenantId, user_id: userId, bound: sub !== null };
  }

  async addMember(tenantId, userId, role, email) {
    if (!ROLES.has(role)) throw http(400, 'bad_role');
    if (!this.tenants.has(tenantId)) throw http(404, 'not_found');
    const idx = this.members.findIndex((m) => m.tenant_id === tenantId && m.user_id === userId);
    const prev = idx >= 0 ? this.members[idx] : null;
    const row = { tenant_id: tenantId, user_id: userId, email: email || (prev ? prev.email : null), role, sso_sub: prev ? prev.sso_sub : null };
    if (idx >= 0) this.members[idx] = row;
    else this.members.push(row);
    return { tenant_id: row.tenant_id, user_id: row.user_id, email: row.email, role: row.role };
  }

  decorate(row) {
    const series = this.telemetry
      .filter((t) => t.host_id === row.host_id && t.metric === 'cpu.usage_percent')
      .slice(-20)
      .map((t) => t.value);
    return publicHost({ ...row, sparkline: series, cpu_percent: series.length ? series[series.length - 1] : null });
  }

  // Retired rows only when includeRetired is true.
  async listHosts(tenantIds, query, { includeRetired = false } = {}) {
    const allow = new Set(tenantIds || []);
    let rows = [...this.hosts.values()].filter((h) => allow.has(h.tenant_id) && (includeRetired || !h.retired_at));
    if (query) {
      const needle = String(query).toLowerCase();
      rows = rows.filter((h) => h.hostname.toLowerCase().includes(needle));
    }
    rows.sort((a, b) => String(b.last_seen_at || '').localeCompare(String(a.last_seen_at || '')));
    return rows.map((row) => this.decorate(row));
  }

  async getHost(tenantIds, hostId) {
    const row = this.hosts.get(hostId);
    if (!row || !(tenantIds || []).includes(row.tenant_id)) return null;
    return this.decorate(row);
  }

  // Exact host_id, else exact case-insensitive hostname, inside tenantIds.
  // Retired rows never resolve.
  async resolveHosts(tenantIds, name) {
    const allow = new Set(tenantIds || []);
    const byId = this.hosts.get(name);
    if (byId && allow.has(byId.tenant_id) && !byId.retired_at) return [this.decorate(byId)];
    const needle = String(name).toLowerCase();
    return [...this.hosts.values()]
      .filter((h) => allow.has(h.tenant_id) && !h.retired_at && String(h.hostname).toLowerCase() === needle)
      .map((row) => this.decorate(row));
  }

  async touchHost(hostId, fields = {}) {
    const row = this.hosts.get(hostId);
    if (!row) return;
    row.last_seen_at = new Date().toISOString();
    row.status = 'online';
    if (fields.os) row.os = fields.os;
    if (fields.platform) row.platform = fields.platform;
  }

  // SAH channel policies, raw (unparsed) values. See controlplane/channels.js
  // effectivePolicies for the host -> tenant -> deny-all fallback.
  async channelPolicies(hostId) {
    const row = this.hosts.get(hostId);
    if (!row || row.retired_at) return null;
    const h = this.hostPolicies.get(hostId) || {};
    const t = this.tenantPolicies.get(row.tenant_id) || {};
    return {
      host_tcp_policy: h.tcp_policy ?? null,
      host_file_policy: h.file_policy ?? null,
      tenant_tcp_policy: t.tcp_policy ?? null,
      tenant_file_policy: t.file_policy ?? null
    };
  }

  // Only keys present in `fields` change; null clears a column.
  async setHostChannelPolicy(hostId, fields) {
    if (!this.hosts.has(hostId)) throw http(404, 'not_found');
    const cur = { ...(this.hostPolicies.get(hostId) || {}) };
    for (const key of ['tcp_policy', 'file_policy']) {
      if (!(key in fields)) continue;
      assertPolicyShape(key === 'tcp_policy' ? 'tcp' : 'file', fields[key]);
      cur[key] = fields[key] === null ? null : JSON.parse(JSON.stringify(fields[key]));
    }
    this.hostPolicies.set(hostId, cur);
  }

  // Both host columns and their audit row together: the row is written
  // first and the policy changes only once it is in (see PgRegistry).
  async setHostChannelPolicyAudited({ tenantId, hostId, tcpPolicy, filePolicy, actor, action, reason }) {
    const row = this.hosts.get(hostId);
    if (!row || row.tenant_id !== tenantId) throw http(404, 'not_found');
    assertPolicyShape('tcp', tcpPolicy);
    assertPolicyShape('file', filePolicy);
    const cur = this.hostPolicies.get(hostId) || {};
    await this.appendAudit(channelPolicyAuditEntry(tenantId, hostId, actor, action, reason, tcpPolicy, filePolicy, cur.tcp_policy, cur.file_policy));
    this.hostPolicies.set(hostId, {
      tcp_policy: tcpPolicy === null ? null : JSON.parse(JSON.stringify(tcpPolicy)),
      file_policy: filePolicy === null ? null : JSON.parse(JSON.stringify(filePolicy))
    });
  }

  async setTenantChannelPolicy(tenantId, fields) {
    if (!this.tenants.has(tenantId)) throw http(404, 'not_found');
    const cur = { ...(this.tenantPolicies.get(tenantId) || {}) };
    for (const key of ['tcp_policy', 'file_policy']) {
      if (!(key in fields)) continue;
      assertPolicyShape(key === 'tcp_policy' ? 'tcp' : 'file', fields[key]);
      cur[key] = fields[key] === null ? null : JSON.parse(JSON.stringify(fields[key]));
    }
    this.tenantPolicies.set(tenantId, cur);
  }

  async setHostStatus(hostId, status) {
    const row = this.hosts.get(hostId);
    if (row) row.status = status;
  }

  // The live agent of a host (cp_hosts.agent_caps, agent_instance,
  // agent_conn_id, agent_enrolled_at), written by the instance holding its
  // socket. A write from an enroll older than the stored one is refused
  // (false), so a delayed write never undoes a newer enroll elsewhere; the
  // same enroll may write again (the tick re-asserts it). A close clears
  // only its own conn_id, and its enroll time too, so an owner whose clock
  // ran ahead cannot lock out the live socket's next re-assert. The enroll
  // time is the enrolling instance's clock.
  async setAgentPresence(hostId, { caps, instance, connId, enrolledAt }) {
    const p = agentPresence(caps, instance, connId, enrolledAt);
    const row = this.hosts.get(hostId);
    if (!row || (row.agent_enrolled_at && row.agent_enrolled_at > p.enrolledAt)) return false;
    row.agent_caps = p.caps;
    row.agent_instance = p.instance;
    row.agent_conn_id = p.connId;
    row.agent_enrolled_at = p.enrolledAt;
    row.agent_seen_at = new Date();
    return true;
  }

  async clearAgentPresence(hostId, connId) {
    const row = this.hosts.get(hostId);
    if (!row || !row.agent_conn_id || row.agent_conn_id !== connId) return false;
    row.agent_caps = null;
    row.agent_instance = null;
    row.agent_conn_id = null;
    row.agent_enrolled_at = null;
    row.agent_seen_at = null;
    return true;
  }

  // {instance, conn_id, caps} of the host's live agent, or null when none
  // is recorded (or the host is retired). With maxAgeS, also null when the
  // presence was last written more than maxAgeS seconds ago.
  async hostAgent(hostId, { maxAgeS = null } = {}) {
    const row = this.hosts.get(hostId);
    if (!row || row.retired_at || !row.agent_conn_id) return null;
    if (maxAgeS !== null && (!row.agent_seen_at || Date.now() - row.agent_seen_at.getTime() > maxAgeS * 1000)) return null;
    return { instance: row.agent_instance, conn_id: row.agent_conn_id, caps: [...(row.agent_caps || [])] };
  }

  // Stamps retired_at and appends the host_retired audit row (written
  // first; the row changes only once it is in, see PgRegistry). The row
  // must belong to tenantId; a second retire is 409 already_retired.
  async retireHost({ tenantId, hostId, actor, reason, forced }) {
    const text = retireReason(reason);
    const row = this.hosts.get(hostId);
    if (!row || row.tenant_id !== tenantId) throw http(404, 'not_found');
    if (row.retired_at) throw http(409, 'already_retired');
    await this.appendAudit(hostRetiredAuditEntry(row, actor, text, forced));
    row.retired_at = new Date().toISOString();
    row.status = 'offline';
    this.memSync(tenantId, hostId);
    return this.decorate(row);
  }

  async countHosts() {
    const live = [...this.hosts.values()].filter((h) => !h.retired_at);
    const online = live.filter((h) => h.status === 'online').length;
    return { total: live.length, online, offline: live.length - online };
  }

  async countOpenAlerts() {
    return this.alerts.filter((row) => row.status === 'open').length;
  }

  async recordMetric(hostId, metric, value, labels = {}) {
    if (!METRICS.has(metric) || typeof value !== 'number' || Number.isNaN(value)) return;
    this.telemetry.push({
      host_id: hostId,
      ts: new Date().toISOString(),
      metric,
      value,
      labels
    });
    if (this.telemetry.length > TELEMETRY_CAP) {
      this.telemetry.splice(0, this.telemetry.length - TELEMETRY_CAP);
    }
    this.metricInserts += 1;
    if (this.metricInserts % 100 === 0) {
      const days = retentionDays(this.env);
      const cutoff = Date.now() - days * 86400000;
      this.telemetry = this.telemetry.filter((t) => Date.parse(t.ts) >= cutoff);
    }
  }

  async metricSeries(hostId, metric, limit = 60) {
    if (!METRICS.has(metric)) return [];
    return this.telemetry
      .filter((t) => t.host_id === hostId && t.metric === metric)
      .slice(-limit)
      .map((t) => ({ ts: t.ts, value: t.value }));
  }

  async metricAggregate(hostId, metric, bucket, from, to) {
    if (!METRICS.has(metric)) return [];
    const rows = this.telemetry.filter((t) => {
      if (t.host_id !== hostId || t.metric !== metric) return false;
      const ms = Date.parse(t.ts);
      if (from && ms < from) return false;
      if (to && ms >= to) return false;
      return true;
    });
    const groups = new Map();
    for (const row of rows) {
      const key = bucketKey(row.ts, bucket);
      const cur = groups.get(key) || { bucket: key, sum: 0, n: 0 };
      cur.sum += row.value;
      cur.n += 1;
      groups.set(key, cur);
    }
    return [...groups.values()].map((g) => ({ bucket: g.bucket, value: g.sum / g.n }));
  }

  async appendAudit(entry) {
    const run = this.auditChain.then(() => {
      const prev = this.audit.length ? this.audit[this.audit.length - 1].row_hash : GENESIS;
      const payload = JSON.parse(canonicalJSON(entry.payload || {}));
      const row = {
        seq: this.auditSeq++,
        prev_hash: prev,
        tenant_id: entry.tenant_id || null,
        host_id: entry.host_id || null,
        actor: entry.actor || null,
        action: entry.action,
        payload,
        created_at: new Date().toISOString()
      };
      row.row_hash = rowHash(prev, row);
      this.audit.push(row);
      return row;
    });
    this.auditChain = run.then(() => {}, () => {});
    return run;
  }

  async verifyAudit() {
    return verifyRows(this.audit);
  }

  async listAudit(tenantIds, limit = 100) {
    const allow = new Set(tenantIds || []);
    return this.audit.filter((row) => row.tenant_id && allow.has(row.tenant_id)).slice(-limit).reverse();
  }

  async recordSecurity(event) {
    const row = {
      id: this.securitySeq++,
      tenant_id: event.tenant_id || null,
      kind: event.kind,
      actor_fingerprint: event.actor_fingerprint || null,
      detail: event.detail || {},
      created_at: new Date().toISOString()
    };
    this.securityEvents.push(row);
    return row;
  }

  async listSecurity(tenantIds, limit = 100) {
    const allow = new Set(tenantIds || []);
    return this.securityEvents
      .filter((row) => row.tenant_id && allow.has(row.tenant_id))
      .slice(-limit)
      .reverse();
  }

  async scopesForKey(keyId) {
    const rows = this.scopes.get(keyId) || [];
    return scopesForKeyRows(rows, this.env);
  }

  async setScopes(keyId, scopes) {
    this.scopes.set(keyId, [...scopes]);
  }

  // The memory registry holds no key rows (verifyApiKey needs the database),
  // so a key is active until revokeKey marks it.
  async keyActive(keyId) {
    return typeof keyId === 'string' && keyId.length > 0 && !this.revokedKeys.has(keyId);
  }

  async revokeKey(keyId) {
    this.revokedKeys.add(keyId);
  }

  async recentAlert(hostId, ruleName, withinMs, now = Date.now()) {
    return this.alerts.some((a) => a.host_id === hostId && a.rule_name === ruleName && now - Date.parse(a.created_at) < withinMs);
  }

  async openAlert(entry) {
    const row = {
      id: this.alertSeq++,
      tenant_id: entry.tenant_id,
      host_id: entry.host_id,
      rule_name: entry.rule_name,
      metric: entry.metric || null,
      value: entry.value,
      severity: entry.severity || null,
      message: entry.message || null,
      status: 'open',
      created_at: new Date().toISOString()
    };
    this.alerts.push(row);
    return row;
  }

  async listAlerts(tenantIds, status) {
    const allow = new Set(tenantIds || []);
    return this.alerts.filter((a) => allow.has(a.tenant_id) && (!status || a.status === status));
  }

  async setAlertStatus(tenantIds, id, status) {
    const allow = new Set(tenantIds || []);
    const row = this.alerts.find((a) => a.id === id && allow.has(a.tenant_id));
    if (!row) return null;
    row.status = status;
    return row;
  }

  async createWebhook(row) {
    this.webhooks.push(row);
    return publicWebhook(row);
  }

  async listWebhooks(tenantId) {
    return this.webhooks.filter((w) => w.tenant_id === tenantId).map(publicWebhook);
  }

  async deleteWebhook(tenantId, id) {
    const before = this.webhooks.length;
    this.webhooks = this.webhooks.filter((w) => !(w.tenant_id === tenantId && w.id === id));
    return this.webhooks.length < before;
  }

  async webhooksForTenant(tenantId) {
    return this.webhooks.filter((w) => w.tenant_id === tenantId).map((w) => ({ ...w }));
  }

  async createSchedule(row) {
    this.schedules.push(row);
    return publicSchedule(row);
  }

  async listSchedules(tenantId) {
    return this.schedules.filter((s) => s.tenant_id === tenantId).map(publicSchedule);
  }

  async deleteSchedule(tenantId, id) {
    const before = this.schedules.length;
    this.schedules = this.schedules.filter((s) => !(s.tenant_id === tenantId && s.id === id));
    return this.schedules.length < before;
  }

  async dueSchedules(date) {
    const { cronMatches } = require('./stats');
    return this.schedules.filter((s) => cronMatches(s.cron, date)).map((s) => ({ ...s }));
  }

  async markSchedule(id, minuteKey) {
    const row = this.schedules.find((s) => s.id === id);
    if (!row) return false;
    if (row.last_run_minute === minuteKey) return false;
    row.last_run_minute = minuteKey;
    return true;
  }

  async addComment(entry) {
    if (typeof entry.body !== 'string' || entry.body.length === 0 || entry.body.length > 2000) {
      throw http(400, 'bad_comment');
    }
    const row = {
      id: this.commentSeq++,
      tenant_id: entry.tenant_id,
      host_id: entry.host_id,
      author: entry.author,
      body: entry.body,
      created_at: new Date().toISOString()
    };
    this.comments.push(row);
    return row;
  }

  async listComments(tenantId, hostId) {
    return this.comments.filter((c) => c.tenant_id === tenantId && c.host_id === hostId);
  }

  async upsertSoftware(hostId, sw) {
    const name = sw.name || 'unknown';
    const version = sw.version || 'unknown';
    const found = this.software.find((s) => s.host_id === hostId && s.name === name && s.version === version);
    if (found) {
      found.last_detected_at = new Date().toISOString();
      return { inserted: false };
    }
    this.software.push({
      host_id: hostId,
      name,
      version,
      architecture: sw.architecture || '',
      last_detected_at: new Date().toISOString()
    });
    return { inserted: true };
  }

  async listSoftware(hostId) {
    return this.software.filter((s) => s.host_id === hostId);
  }

  async saveCVE(row) {
    const found = this.cves.find((c) => c.host_id === row.host_id && c.cve_id === row.cve_id && c.software_name === row.software_name);
    if (found) return found;
    const stored = { ...row, discovered_at: new Date().toISOString() };
    this.cves.push(stored);
    return stored;
  }

  async listCVEs(hostId) {
    return this.cves.filter((c) => c.host_id === hostId);
  }

  // The caps are counted and the row inserted before the first await, so
  // concurrent calls cannot both pass the count. The row is removed again
  // if the submit audit row fails (the Pg transaction rolls back).
  async createJob(row, opts = {}) {
    const r = jobInsertRow(row);
    const conv = convergeJobInput(r, opts.converge);
    const { hostCap, tenantCap } = jobCaps(opts);
    const host = this.hosts.get(r.host_id);
    if (!host || host.tenant_id !== r.tenant_id || host.retired_at) throw http(404, 'not_found');
    if (this.jobs.has(r.job_id)) throw http(409, 'conflict');
    let onHost = 0;
    let onTenant = 0;
    for (const j of this.jobs.values()) {
      if (!JOB_ACTIVE.includes(j.status)) continue;
      if (j.host_id === r.host_id) onHost += 1;
      if (j.tenant_id === r.tenant_id) onTenant += 1;
    }
    if (onHost >= hostCap || onTenant >= tenantCap) throw http(429, 'too_many_jobs');
    const convChange = conv ? this.memConvergePrepare(r, conv) : null;
    const stored = {
      ...r,
      status: 'submitted',
      error: null,
      output: null,
      output_truncated: false,
      output_expired: false,
      conn_id: null,
      sent_at: null,
      alert_count: 0,
      cancel_requested_at: null,
      cancel_sent_at: null,
      cancel_actor: null,
      created_at: new Date(),
      accepted_at: null,
      started_at: null,
      finished_at: null,
      duration_ms: null
    };
    this.jobs.set(r.job_id, stored);
    const convUndo = convChange ? convChange() : null;
    try {
      await this.appendAudit(jobSubmitAuditEntry(stored));
    } catch (err) {
      this.jobs.delete(r.job_id);
      if (convUndo) convUndo();
      throw err;
    }
    this.publishJobEvent(stateEvent(stored, 'dispatch'));
    return publicJob(stored);
  }

  // Applies change, then writes the audit rows auditOf returns; if either
  // fails, only the fields change wrote are put back (a concurrent write to
  // another field, such as alert_count, survives). The event is published
  // only once both are in. change runs before the first await, so a guard
  // checked by the caller in the same turn still holds when it runs.
  async jobWrite(row, change, auditOf, eventOf) {
    const before = { ...row };
    let written = [];
    try {
      change(row);
      written = Object.keys(row).filter((k) => row[k] !== before[k]);
      for (const entry of auditOf ? auditOf(row) : []) await this.appendAudit(entry);
    } catch (err) {
      if (written.length === 0) written = Object.keys(row).filter((k) => row[k] !== before[k]);
      for (const k of written) row[k] = before[k];
      throw err;
    }
    if (eventOf) this.publishJobEvent(eventOf(row));
  }

  async getJob(tenantIds, jobId) {
    const row = this.jobs.get(jobId);
    if (!row || !(tenantIds || []).includes(row.tenant_id)) return null;
    return publicJob(row);
  }

  // Never returns output.
  async listJobs(tenantIds, opts = {}) {
    const { hostId, status, limit } = jobListQuery(opts);
    const allow = new Set(tenantIds || []);
    return [...this.jobs.values()]
      .filter((j) => allow.has(j.tenant_id) && (hostId === null || j.host_id === hostId) && (status === null || j.status === status))
      .sort((a, b) => b.created_at - a.created_at || (a.job_id < b.job_id ? 1 : -1))
      .slice(0, limit)
      .map((j) => publicJob(j, { withOutput: false }));
  }

  // Guarded: the row must be this host's, in one of fromStatuses, and (with
  // opts.connId) sent on that connection. Null when the guard does not hold.
  // A converge row's terminal transition also ingests opts.converge.report
  // (validated first: a malformed one ends the job failed[bad_report] with a
  // security event), or finalizes the run without one; the result carries
  // .converge (see memConvergeIngest).
  async transitionJob(jobId, hostId, fromStatuses, fields, opts = {}) {
    const { from, set: asked } = jobTransition(fromStatuses, fields);
    const guardConn = 'connId' in opts;
    if (guardConn && !nonEmpty(opts.connId)) throw http(500, 'bad_conn_id');
    const row = this.jobs.get(jobId);
    if (!row || row.host_id !== hostId || !from.includes(row.status)) return null;
    if (guardConn && row.conn_id !== opts.connId) return null;
    const { set, rep, bad } = convergeVerdict(from, fields, asked, opts, row);
    let conv = null;
    await this.jobWrite(
      row,
      (r) => {
        applyJobSet(r, set, new Date());
        if (isTerminal(r.status) && isConvergeSource(r.source)) conv = this.memConvergeIngest(r, rep);
      },
      (r) => [...(conv ? conv.audits : []), transitionAuditEntry(r, opts.audit)].filter(Boolean),
      opts.notify ? (r) => transitionNotify(r, opts.notify) : null
    );
    if (bad) await this.recordSecurity(badReportEvent(row, bad));
    const out = publicJob(row);
    if (conv) out.converge = conv.result;
    return out;
  }

  // Claims the dispatch payload once: it is returned to this caller and
  // nulled on the row, with conn_id and sent_at set.
  async markDispatched(jobId, hostId, connId) {
    if (!nonEmpty(connId)) throw http(500, 'bad_conn_id');
    const row = this.jobs.get(jobId);
    if (!row || row.host_id !== hostId || row.status !== 'submitted' || row.dispatch == null) return null;
    const dispatch = row.dispatch;
    row.dispatch = null;
    row.conn_id = connId;
    row.sent_at = new Date();
    return { ...publicJob(row), dispatch };
  }

  // Null when the job is not in tenantIds; 409 job_finished when terminal.
  // A second request returns the row unchanged. A job never sent to the
  // agent ends cancelled right here.
  async requestJobCancel(tenantIds, jobId, actor, reason = 'user') {
    if (!nonEmpty(actor) || !nonEmpty(reason)) throw http(400, 'bad_cancel');
    const row = this.jobs.get(jobId);
    if (!row || !(tenantIds || []).includes(row.tenant_id)) return null;
    if (isTerminal(row.status)) throw http(409, 'job_finished');
    if (row.cancel_requested_at) return publicJob(row);
    const never = row.status === 'submitted' && row.dispatch != null;
    await this.jobWrite(
      row,
      (r) => {
        const now = new Date();
        r.cancel_requested_at = now;
        r.cancel_actor = actor;
        if (never) {
          applyJobSet(r, { status: 'cancelled', error: 'cancelled_before_dispatch' }, now);
          if (isConvergeSource(r.source)) this.memConvergeIngest(r, null);
        }
      },
      (r) => [jobCancelAuditEntry(r, actor, reason), ...(never ? [jobEndAuditEntry(r, 'system')] : [])],
      (r) => stateEvent(r, never ? 'state' : 'cancel')
    );
    return publicJob(row);
  }

  async markCancelSent(jobId, hostId) {
    const row = this.jobs.get(jobId);
    if (!row || row.host_id !== hostId || !row.cancel_requested_at || isTerminal(row.status)) return null;
    row.cancel_sent_at = new Date();
    return publicJob(row);
  }

  // {ok:true, tenant_id, alert_count} or {ok:false, reason}.
  async bumpJobAlert(jobId, hostId, max = 20) {
    const cap = jobAlertCap(max);
    const row = this.jobs.get(jobId);
    if (!row || row.host_id !== hostId || !['accepted', 'running'].includes(row.status)) {
      return { ok: false, reason: 'unknown_execution' };
    }
    if (row.alert_count >= cap) return { ok: false, reason: 'rate_limited' };
    row.alert_count += 1;
    return { ok: true, tenant_id: row.tenant_id, alert_count: row.alert_count };
  }

  // Sync step 3: this host's non-terminal rows sent on another connection
  // and absent from listedIds end failed[agent_lost_job]. Returns them.
  // Listed non-terminal rows of this host move to connId (the agent holds
  // them on this socket now), and a listed 'submitted' row counts as acked:
  // it becomes 'accepted', so the ack timeout cannot end a job the agent has.
  async reconcileHostJobs(hostId, connId, listedIds) {
    if (!nonEmpty(connId)) throw http(500, 'bad_conn_id');
    const listed = new Set(syncIds(listedIds));
    const ended = [];
    const lost = (j) => j.host_id === hostId && JOB_ACTIVE.includes(j.status) && j.conn_id != null
      && j.conn_id !== connId && !listed.has(j.job_id);
    for (const j of this.jobs.values()) {
      if (j.host_id === hostId && JOB_ACTIVE.includes(j.status) && j.conn_id != null && listed.has(j.job_id)) {
        j.conn_id = connId;
        if (j.status === 'submitted') j.status = 'accepted';
        j.accepted_at = j.accepted_at || new Date();
      }
    }
    const rows = [...this.jobs.values()].filter(lost).sort((a, b) => (a.job_id < b.job_id ? -1 : 1));
    for (const row of rows) {
      if (!lost(row)) continue;
      await this.jobWrite(
        row,
        (r) => {
          applyJobSet(r, { status: 'failed', error: 'agent_lost_job' }, new Date());
          if (isConvergeSource(r.source)) this.memConvergeIngest(r, null);
        },
        (r) => [jobEndAuditEntry(r, 'system')],
        (r) => stateEvent(r)
      );
      ended.push(publicJob(row));
    }
    return ended;
  }

  // The fallback scan: rows of these hosts with a dispatch to claim or a
  // cancel not yet sent.
  async pendingForHosts(hostIds) {
    const allow = new Set(connIdList(hostIds));
    return [...this.jobs.values()]
      .filter((j) => allow.has(j.host_id) && JOB_ACTIVE.includes(j.status)
        && (j.dispatch != null || (j.cancel_requested_at && !j.cancel_sent_at)))
      .sort((a, b) => a.created_at - b.created_at || (a.job_id < b.job_id ? -1 : 1))
      .slice(0, 1000)
      .map((j) => ({
        job_id: j.job_id,
        host_id: j.host_id,
        status: j.status,
        dispatch_pending: j.dispatch != null,
        cancel_pending: Boolean(j.cancel_requested_at && !j.cancel_sent_at)
      }));
  }

  // Ends failed[dispatch_timeout | agent_no_ack | result_lost] rows (§6.1),
  // at most JOB_SWEEP_BATCH in job_id order, each with its end audit row.
  // Returns them.
  async sweepJobs(now = Date.now(), opts = {}) {
    const s = jobSweep(now, opts);
    const conns = new Set(s.connIds);
    const ended = [];
    const rows = [...this.jobs.values()].filter((j) => JOB_ACTIVE.includes(j.status))
      .sort((a, b) => (a.job_id < b.job_id ? -1 : 1));
    for (const row of rows) {
      if (!JOB_ACTIVE.includes(row.status)) continue; // ended while an earlier audit row was written
      let error = null;
      if (row.status === 'submitted' && row.dispatch != null && row.created_at < s.dispatchCutoff) error = 'dispatch_timeout';
      else if (row.status === 'submitted' && row.conn_id != null && conns.has(row.conn_id)
        && row.sent_at && row.sent_at < s.ackCutoff) error = 'agent_no_ack';
      else if (row.deadline_at < s.deadlineCutoff) error = 'result_lost';
      if (!error) continue;
      if (ended.length >= JOB_SWEEP_BATCH) break;
      await this.jobWrite(
        row,
        (r) => {
          applyJobSet(r, { status: 'failed', error }, new Date());
          if (isConvergeSource(r.source)) this.memConvergeIngest(r, null);
        },
        (r) => [jobEndAuditEntry(r, 'system')],
        (r) => stateEvent(r)
      );
      ended.push(publicJob(row));
    }
    return ended;
  }

  async expireOutput(hours) {
    const n = jobOutputRetentionHours({ SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS: String(hours) });
    const cutoff = Date.now() - n * 3600000;
    let count = 0;
    for (const row of this.jobs.values()) {
      if (row.output != null && row.finished_at && row.finished_at.getTime() < cutoff) {
        row.output = null;
        row.output_expired = true;
        count += 1;
      }
    }
    const planCutoff = Date.now() - planMaxAgeS(this.env) * 1000;
    for (const run of this.convergeRuns.values()) {
      if (run.report != null && run.finished_at && run.finished_at.getTime() < cutoff) {
        run.report = null;
        run.report_expired = true;
      }
      if (run.kind === 'plan' && run.bundle_json != null && run.created_at.getTime() < planCutoff) run.bundle_json = null;
    }
    return count;
  }

  async pruneJobs(days) {
    const n = jobRetentionDays({ SYSTEMAPI_JOB_RETENTION_DAYS: String(days) });
    const cutoff = Date.now() - n * 86400000;
    let count = 0;
    for (const [id, row] of this.jobs) {
      if (isTerminal(row.status) && row.finished_at && row.finished_at.getTime() < cutoff) {
        this.jobs.delete(id);
        const run = this.convergeRuns.get(id);
        if (run && run.kind === 'check') this.convergeRuns.delete(id);
        count += 1;
      }
    }
    const runCutoff = Date.now() - applyRunRetentionDays(this.env) * 86400000;
    for (const [id, run] of this.convergeRuns) {
      if (run.kind !== 'check' && run.created_at.getTime() < runCutoff) this.convergeRuns.delete(id);
    }
    return count;
  }

  // In-process stand-in for NOTIFY: delivered after the current turn, as a
  // notification arrives only after COMMIT.
  publishJobEvent(evt) {
    const e = jobEvent(evt);
    if (!e) return false;
    setImmediate(() => deliverJobEvent(this.jobBus, e));
    return true;
  }

  // Returns the unsubscribe function; its .ready resolves once listening.
  onJobEvent(fn) {
    this.jobBus.on('event', fn);
    const off = () => { this.jobBus.off('event', fn); };
    off.ready = Promise.resolve();
    return off;
  }

  async closeJobEvents() {
    this.jobBus.removeAllListeners('event');
  }

  // --- desired state (see the Threats note above convergeJobInput) --------
  // MemoryRegistry writes the audit row first and changes the store only
  // once it is in (re-checking what it checked before the await).

  async createState(input) {
    const s = stateInput(input);
    const check = () => {
      if (!this.tenants.has(s.tenant_id)) throw http(404, 'not_found');
      if ([...this.states.values()].some((x) => x.tenant_id === s.tenant_id && x.name === s.name)) throw http(409, 'state_exists');
    };
    check();
    const row = { state_id: newId('st'), ...s, created_at: new Date(), archived_at: null };
    await this.appendAudit(stateAuditEntry(row.tenant_id, null, row.created_by, 'state_create', { state_id: row.state_id, name: row.name }));
    check();
    this.states.set(row.state_id, row);
    return publicState(row);
  }

  async getState(tenantIds, stateId) {
    const row = this.states.get(stateId);
    return row && (tenantIds || []).includes(row.tenant_id) ? publicState(row) : null;
  }

  async listStates(tenantIds) {
    const allow = new Set(tenantIds || []);
    return [...this.states.values()].filter((s) => allow.has(s.tenant_id))
      .sort((a, b) => (a.name < b.name ? -1 : 1)).map(publicState);
  }

  async publishVersion(input) {
    const v = versionInput(input);
    const state = () => {
      const st = this.states.get(v.state_id);
      if (!st || st.tenant_id !== v.tenant_id || st.archived_at) throw http(404, 'not_found');
    };
    state();
    const next = () => 1 + Math.max(0, ...[...this.stateVersions.values()].filter((x) => x.state_id === v.state_id).map((x) => x.version));
    const row = { version_id: newId('stv'), ...v, version: next(), published_at: new Date() };
    await this.appendAudit(stateAuditEntry(v.tenant_id, null, v.published_by, 'state_publish', {
      state_id: v.state_id, version_id: row.version_id, version: row.version,
      files_sha256: v.files_sha256, entitlements_sha256: v.entitlements_sha256
    }));
    state();
    row.version = next();
    this.stateVersions.set(row.version_id, row);
    return publicVersion(row);
  }

  async getVersion(tenantIds, versionId, { withFiles = false } = {}) {
    const row = this.stateVersions.get(versionId);
    return row && (tenantIds || []).includes(row.tenant_id) ? publicVersion(row, { withFiles }) : null;
  }

  async listVersions(tenantIds, stateId) {
    const allow = new Set(tenantIds || []);
    return [...this.stateVersions.values()].filter((v) => v.state_id === stateId && allow.has(v.tenant_id))
      .sort((a, b) => b.version - a.version).map((v) => publicVersion(v));
  }

  assignmentRefs(a) {
    const st = this.states.get(a.state_id);
    if (!st || st.tenant_id !== a.tenant_id || st.archived_at) throw http(404, 'not_found');
    const v = this.stateVersions.get(a.version_id);
    if (!v || v.state_id !== a.state_id || v.tenant_id !== a.tenant_id) throw http(404, 'version_not_found');
    if (a.target_kind === 'host') {
      const h = this.hosts.get(a.target_value);
      if (!h || h.tenant_id !== a.tenant_id || h.retired_at) throw http(404, 'host_not_found');
    }
  }

  async createAssignment(input) {
    const a = assignmentInput(input);
    const check = () => {
      this.assignmentRefs(a);
      if ([...this.assignments.values()].some((x) => x.tenant_id === a.tenant_id && x.state_id === a.state_id
        && x.target_kind === a.target_kind && x.target_value === a.target_value)) throw http(409, 'assignment_exists');
    };
    check();
    const now = new Date();
    const row = { assignment_id: newId('sta'), ...a, created_at: now, updated_at: now };
    await this.appendAudit(stateAuditEntry(a.tenant_id, a.target_kind === 'host' ? a.target_value : null, a.created_by,
      'state_assign', assignmentAuditPayload(row, 'create')));
    check();
    this.assignments.set(row.assignment_id, row);
    this.memSync(a.tenant_id);
    return publicAssignment(row);
  }

  async updateAssignment({ tenantId, assignmentId, patch, actor }) {
    if (!nonEmpty(actor)) throw http(400, 'bad_assignment');
    const cur = this.assignments.get(assignmentId);
    if (!cur || cur.tenant_id !== tenantId) throw http(404, 'not_found');
    const next = assignmentPatch(publicAssignment(cur), patch);
    this.assignmentRefs(next);
    await this.appendAudit(stateAuditEntry(tenantId, next.target_kind === 'host' ? next.target_value : null, actor,
      'state_assign', assignmentAuditPayload(next, 'update')));
    if (this.assignments.get(assignmentId) !== cur) throw http(409, 'conflict');
    this.assignmentRefs(next);
    const intervalChanged = next.check_interval_s !== cur.check_interval_s;
    Object.assign(cur, next, { updated_at: new Date() });
    this.memSync(tenantId);
    if (intervalChanged) {
      for (const hs of this.hostStates.values()) {
        if (hs.assignment_id !== assignmentId) continue;
        const off = firstCheckOffsetS(hs.host_id, hs.state_id, cur.check_interval_s);
        hs.next_check_at = off === null ? null : new Date(Date.now() + off * 1000);
      }
    }
    return publicAssignment(cur);
  }

  async deleteAssignment({ tenantId, assignmentId, actor }) {
    if (!nonEmpty(actor)) throw http(400, 'bad_assignment');
    const cur = this.assignments.get(assignmentId);
    if (!cur || cur.tenant_id !== tenantId) throw http(404, 'not_found');
    await this.appendAudit(stateAuditEntry(tenantId, cur.target_kind === 'host' ? cur.target_value : null, actor,
      'state_unassign', assignmentAuditPayload(cur, 'delete')));
    if (!this.assignments.delete(assignmentId)) throw http(404, 'not_found');
    this.memSync(tenantId);
    return true;
  }

  async getAssignment(tenantIds, assignmentId) {
    const row = this.assignments.get(assignmentId);
    return row && (tenantIds || []).includes(row.tenant_id) ? publicAssignment(row) : null;
  }

  async listAssignments(tenantIds, { stateId = null } = {}) {
    const allow = new Set(tenantIds || []);
    return [...this.assignments.values()].filter((a) => allow.has(a.tenant_id) && (stateId === null || a.state_id === stateId))
      .sort((a, b) => a.created_at - b.created_at).map(publicAssignment);
  }

  // Replaces the host's tags (audited) and re-syncs its host states.
  async setHostTags({ tenantId, hostId, tags, actor }) {
    const next = tagsInput(tags);
    if (!nonEmpty(actor)) throw http(400, 'bad_tags');
    const row = this.hosts.get(hostId);
    if (!row || row.tenant_id !== tenantId || row.retired_at) throw http(404, 'not_found');
    await this.appendAudit(stateAuditEntry(tenantId, hostId, actor, 'host_tags', { tags: next, previous: [...(row.tags || [])] }));
    row.tags = next;
    this.memSync(tenantId, hostId);
    return this.decorate(row);
  }

  // The effective assignment per (host, state), applied: new rows, changed
  // assignments, conflicts, and rows the host no longer matches deleted
  // with their drift alerts resolved. With hostId, that host only (in its
  // current tenant: rows under another tenant are deleted).
  async syncHostStates(tenantId, { hostId = null } = {}) {
    return this.memSync(tenantId, hostId);
  }

  memSync(tenantId, hostId = null) {
    let tenant = tenantId;
    let hosts;
    if (hostId) {
      const h = this.hosts.get(hostId);
      if (h) tenant = h.tenant_id;
      hosts = h && !h.retired_at ? [h] : [];
    } else {
      hosts = [...this.hosts.values()].filter((h) => h.tenant_id === tenant && !h.retired_at);
    }
    const assigns = [...this.assignments.values()].filter((a) => {
      const st = this.states.get(a.state_id);
      return a.tenant_id === tenant && st && !st.archived_at;
    });
    const existing = [...this.hostStates.values()].filter((r) => (hostId ? r.host_id === hostId : r.tenant_id === tenant));
    const d = hostStateDiff(existing, effectiveAssignments(hosts, assigns), tenant);
    const now = Date.now();
    const at = (off) => (off === null ? null : new Date(now + off * 1000));
    const resolved = [];
    for (const row of d.deletes) {
      this.hostStates.delete(hsKey(row.host_id, row.state_id));
      resolved.push(...this.memResolveDrift(row.tenant_id, row.host_id, row.state_id));
    }
    for (const u of d.updates) {
      Object.assign(this.hostStates.get(hsKey(u.host_id, u.state_id)), {
        assignment_id: u.assignment_id,
        version_id: u.version_id,
        status: u.status,
        consecutive_drift: 0,
        check_claimed_at: null,
        check_job_id: null,
        last_apply_run_id: null,
        next_check_at: at(u.next_offset_s)
      });
    }
    for (const i of d.inserts) {
      this.hostStates.set(hsKey(i.host_id, i.state_id), {
        host_id: i.host_id, state_id: i.state_id, tenant_id: i.tenant_id,
        assignment_id: i.assignment_id, version_id: i.version_id, status: i.status, facts: {},
        consecutive_drift: 0, last_error: null, last_check_run_id: null, last_check_at: null,
        last_apply_run_id: null, last_applied_version_id: null, last_applied_at: null,
        manual_apply_assignment_id: null, manual_apply_version_id: null, auto_apply_failures: 0,
        last_report_sha256: null, next_check_at: at(i.next_offset_s), check_claimed_at: null, check_job_id: null
      });
    }
    return { inserted: d.inserts.length, updated: d.updates.length, deleted: d.deletes.length, resolved };
  }

  memResolveDrift(tenantId, hostId, stateId) {
    const out = [];
    for (const a of this.alerts) {
      if (a.tenant_id === tenantId && a.host_id === hostId && a.rule_name === driftRule(stateId)
        && (a.status === 'open' || a.status === 'ack')) {
        a.status = 'resolved';
        out.push(a.id);
      }
    }
    return out;
  }

  async getHostState(tenantIds, hostId, stateId) {
    const row = this.hostStates.get(hsKey(hostId, stateId));
    return row && (tenantIds || []).includes(row.tenant_id) ? publicHostState(row) : null;
  }

  async listHostStates(tenantIds, opts = {}) {
    const { hostId, stateId, status } = hostStateQuery(opts);
    const allow = new Set(tenantIds || []);
    return [...this.hostStates.values()]
      .filter((r) => allow.has(r.tenant_id) && (hostId === null || r.host_id === hostId)
        && (stateId === null || r.state_id === stateId) && (status === null || r.status === status))
      .sort((a, b) => (hsKey(a.host_id, a.state_id) < hsKey(b.host_id, b.state_id) ? -1 : 1))
      .map(publicHostState);
  }

  // The memory mirror of PgRegistry.claimDueChecks (§8.2).
  async claimDueChecks(opts) {
    const { replicaBudget, perTenantCap, claimExpiryS, presenceFreshS } = claimInput(opts);
    const now = Date.now();
    const expired = (r) => r.check_claimed_at == null || r.check_claimed_at.getTime() <= now - claimExpiryS * 1000;
    const inflight = new Map();
    for (const r of this.hostStates.values()) {
      if (!expired(r)) inflight.set(r.tenant_id, (inflight.get(r.tenant_id) || 0) + 1);
    }
    const due = [...this.hostStates.values()].filter((r) => {
      const h = this.hosts.get(r.host_id);
      return h && h.tenant_id === r.tenant_id && !h.retired_at && h.agent_seen_at
        && h.agent_seen_at.getTime() > now - presenceFreshS * 1000 && (h.agent_caps || []).includes('converge')
        && r.next_check_at && r.next_check_at.getTime() <= now && r.status !== 'conflict' && r.assignment_id && expired(r);
    }).sort((a, b) => a.next_check_at - b.next_check_at);
    const rank = new Map();
    const pickRows = [];
    for (const r of due) {
      const rk = (rank.get(r.tenant_id) || 0) + 1;
      rank.set(r.tenant_id, rk);
      if (rk + (inflight.get(r.tenant_id) || 0) <= perTenantCap) pickRows.push(r);
    }
    const out = [];
    for (const r of pickRows.slice(0, replicaBudget)) {
      const a = this.assignments.get(r.assignment_id);
      if (!a) continue;
      r.check_claimed_at = new Date(now);
      r.next_check_at = new Date(now + a.check_interval_s * (0.9 + Math.random() * 0.2) * 1000);
      out.push(publicHostState(r));
    }
    return out;
  }

  // A claim that got no job (429 too_many_jobs): released, retried after
  // retryInS.
  async releaseCheckClaim(hostId, stateId, { retryInS = 60 } = {}) {
    if (!Number.isInteger(retryInS) || retryInS < 0 || retryInS > 86400) throw http(500, 'bad_claim');
    const r = this.hostStates.get(hsKey(hostId, stateId));
    if (!r || r.check_claimed_at == null || r.check_job_id != null) return false;
    r.check_claimed_at = null;
    r.next_check_at = new Date(Date.now() + retryInS * 1000);
    return true;
  }

  // Rows not checked for 3 intervals become stale.
  async markStaleHostStates() {
    const now = Date.now();
    let n = 0;
    for (const r of this.hostStates.values()) {
      const a = r.assignment_id ? this.assignments.get(r.assignment_id) : null;
      if (!a || a.check_interval_s === 0 || r.status === 'stale' || r.status === 'conflict' || !r.last_check_at) continue;
      if (r.last_check_at.getTime() < now - 3 * a.check_interval_s * 1000) {
        r.status = 'stale';
        n += 1;
      }
    }
    return n;
  }

  async getConvergeRun(tenantIds, runId, { withReport = false, withBundle = false } = {}) {
    const row = this.convergeRuns.get(runId);
    return row && (tenantIds || []).includes(row.tenant_id) ? publicRun(row, { withReport, withBundle }) : null;
  }

  async listConvergeRuns(tenantIds, opts = {}) {
    const { hostId, stateId, kind, limit } = runListQuery(opts);
    const allow = new Set(tenantIds || []);
    return [...this.convergeRuns.values()]
      .filter((r) => allow.has(r.tenant_id) && (hostId === null || r.host_id === hostId)
        && (stateId === null || r.state_id === stateId) && (kind === null || r.kind === kind))
      .sort((a, b) => b.created_at - a.created_at || (a.run_id < b.run_id ? 1 : -1))
      .slice(0, limit).map((r) => publicRun(r));
  }

  // Approval by a principal other than the plan's actor (the route checks
  // state:apply). The approval does not extend the plan's age.
  async approvePlan({ tenantIds, runId, actor }) {
    if (!nonEmpty(actor)) throw http(400, 'bad_approval');
    const check = () => {
      const run = this.convergeRuns.get(runId);
      if (!run || run.kind !== 'plan' || !(tenantIds || []).includes(run.tenant_id)) return null;
      const job = this.jobs.get(run.run_id);
      if (!job || job.status !== 'succeeded' || run.report_sha256 == null || run.plan_sha256 == null) throw http(409, 'plan_required');
      if (run.plan_truncated) throw http(409, 'plan_truncated');
      if (run.consumed_by_run_id) throw http(409, 'plan_consumed');
      if ((Date.now() - run.created_at.getTime()) / 1000 > planMaxAgeS(this.env)) throw http(409, 'plan_expired');
      if (run.actor === actor) throw http(409, 'self_approval');
      if (run.approved_by) throw http(409, 'plan_approved');
      return run;
    };
    const run = check();
    if (!run) return null;
    await this.appendAudit(stateAuditEntry(run.tenant_id, run.host_id, actor, 'state_approve', {
      run_id: run.run_id, state_id: run.state_id, version_id: run.version_id, plan_sha256: run.plan_sha256
    }));
    check();
    run.approved_by = actor;
    run.approved_at = new Date();
    return publicRun(run);
  }

  // createJob's converge part, before the job row goes in: checks, and
  // returns the change to make (which returns its undo). Nothing is
  // written here.
  memConvergePrepare(r, c) {
    const hs = this.hostStates.get(hsKey(r.host_id, c.state_id));
    let plan = null;
    let planJobStatus = null;
    let planAgeS = 0;
    if (c.kind === 'apply') {
      plan = this.convergeRuns.get(c.plan_run_id) || null;
      const pj = plan ? this.jobs.get(plan.run_id) : null;
      planJobStatus = pj ? pj.status : null;
      planAgeS = plan ? (Date.now() - plan.created_at.getTime()) / 1000 : 0;
    }
    const assignment = hs && hs.assignment_id ? this.assignments.get(hs.assignment_id) : null;
    const version = hs && hs.version_id ? this.stateVersions.get(hs.version_id) : null;
    const eff = convergeCreateCheck(r, c, { hs, version, assignment, plan, planJobStatus, planAgeS, maxAgeS: planMaxAgeS(this.env) });
    return () => {
      const run = {
        run_id: r.job_id, tenant_id: r.tenant_id, host_id: r.host_id, state_id: c.state_id,
        assignment_id: eff.assignment_id, version_id: eff.version_id, kind: c.kind, actor: r.actor,
        plan_run_id: c.plan_run_id, parent_job_id: c.parent_job_id, bundle_json: c.bundle_json,
        plan_sha256: null, plan_truncated: false, report_sha256: null, summary: null, report: null,
        report_expired: false, approved_by: null, approved_at: null, consumed_by_run_id: null,
        created_at: new Date(), finished_at: null
      };
      const hsBefore = { ...hs };
      const planBefore = plan ? { ...plan } : null;
      this.convergeRuns.set(run.run_id, run);
      if (c.kind === 'apply') {
        hs.last_apply_run_id = run.run_id;
        plan.consumed_by_run_id = run.run_id;
        plan.bundle_json = null;
      } else {
        hs.check_job_id = run.run_id;
        hs.check_claimed_at = new Date();
      }
      return () => {
        this.convergeRuns.delete(run.run_id);
        Object.assign(hs, hsBefore);
        if (plan) Object.assign(plan, planBefore);
      };
    };
  }

  // The report ingestion (§7.5) of a converge job that just ended (or a
  // re-send), synchronous so it lands with the job's transition: v is a
  // convergeReport result, or null to finalize a run that ended without
  // one. Returns {result, audits}, or null when there is no run or the run
  // already has its report.
  memConvergeIngest(job, v) {
    const run = this.convergeRuns.get(job.job_id);
    if (!run || run.tenant_id !== job.tenant_id || run.host_id !== job.host_id) return null;
    if (v && run.report_sha256 != null) return null;
    const a = this.assignments.get(run.assignment_id) || null;
    const cur = this.hostStates.get(hsKey(run.host_id, run.state_id));
    const hs = cur && cur.tenant_id === run.tenant_id
      && (run.kind === 'apply' ? cur.last_apply_run_id === run.run_id : cur.check_job_id === run.run_id) ? cur : null;
    const now = new Date();
    const rep = v ? v.report : null;
    if (v) {
      const body = run.kind !== 'check' || !hs || hs.last_report_sha256 !== v.sha256
        || ![...this.convergeRuns.values()].some((x) => x.kind === 'check' && x.host_id === run.host_id
          && x.state_id === run.state_id && x.report_sha256 === v.sha256 && x.report != null);
      Object.assign(run, {
        report_sha256: v.sha256, summary: rep.summary, report: body ? rep : null,
        plan_sha256: rep.plan_sha256, plan_truncated: rep.truncated
      });
    }
    run.finished_at = run.finished_at || now;
    const result = { run_id: run.run_id, kind: run.kind, host_id: run.host_id, state_id: run.state_id,
      version_id: run.version_id, host_state_updated: false, prev_status: null, status: null, alerts: [] };
    const audits = [];
    if (!hs) {
      if (rep) {
        const entry = reportAuditEntry(run, job, v.sha256, rep, null, null);
        if (entry) audits.push(entry);
      }
      return { result, audits };
    }
    const prev = hs.status;
    const keys = rep ? Object.keys(v.facts) : [];
    const clash = keys.length > 0 && [...this.hostStates.values()].some((x) => x.host_id === hs.host_id
      && x.state_id !== hs.state_id && keys.some((k) => Object.hasOwn(x.facts || {}, k)));
    const upd = hostStateUpdate(run, job, v, hs, clash);
    Object.assign(hs, JSON.parse(JSON.stringify(upd.set)));
    for (const c of upd.now) hs[c] = now;
    if (upd.nextCheck) {
      const interval = a ? a.check_interval_s : 0;
      hs.next_check_at = interval ? new Date(now.getTime() + interval * (0.9 + Math.random() * 0.2) * 1000) : null;
    }
    Object.assign(result, { host_state_updated: true, prev_status: prev, status: hs.status });
    if (rep && hs.status === 'drifted' && a && hs.consecutive_drift >= a.drift_threshold) {
      const rule = driftRule(run.state_id);
      const active = this.alerts.some((x) => x.host_id === run.host_id && x.rule_name === rule && (x.status === 'open' || x.status === 'ack'));
      if (!active) {
        const e = driftAlertEntry(run, rep);
        const id = this.alertSeq++;
        this.alerts.push({ id, ...e, metric: null, status: 'open', created_at: now.toISOString() });
        result.alerts.push({ type: 'drift', alert_id: id, summary: rep.summary });
      }
    } else if (rep && hs.status === 'compliant') {
      for (const id of this.memResolveDrift(run.tenant_id, run.host_id, run.state_id)) {
        result.alerts.push({ type: 'drift_resolved', alert_id: id, summary: rep.summary });
      }
    }
    if (rep) {
      const entry = reportAuditEntry(run, job, v.sha256, rep, prev, hs.status);
      if (entry) audits.push(entry);
    }
    return { result, audits };
  }

  // A result re-sent for a converge job that is already terminal and whose
  // run has no report yet (§7.5): ingested once, with the same conditional
  // host-state write. {ingested, reason?, converge?}.
  async ingestConvergeResend(jobId, hostId, report) {
    const job = this.jobs.get(jobId);
    if (!job || job.host_id !== hostId || !isTerminal(job.status) || !isConvergeSource(job.source)) return { ingested: false, reason: 'unknown_job' };
    const run = this.convergeRuns.get(jobId);
    if (!run || run.report_sha256 != null) return { ingested: false, reason: 'already_ingested' };
    const v = convergeReport(report, run.kind, job.script_sha256);
    if (!v.ok) {
      await this.recordSecurity(badReportEvent(job, v.reason));
      return { ingested: false, reason: 'bad_report' };
    }
    const out = this.memConvergeIngest(job, v);
    if (!out) return { ingested: false, reason: 'already_ingested' };
    for (const entry of out.audits) await this.appendAudit(entry);
    return { ingested: true, converge: out.result };
  }

  async efficiency(tenantIds) {
    const hosts = [];
    for (const host of await this.listHosts(tenantIds)) {
      const cpu = await this.metricSeries(host.host_id, 'cpu.usage_percent', 100);
      const mem = await this.metricSeries(host.host_id, 'memory.used_percent', 100);
      hosts.push({
        host_id: host.host_id,
        hostname: host.hostname,
        cpu_avg: avg(cpu.map((p) => p.value)),
        mem_avg: avg(mem.map((p) => p.value))
      });
    }
    return efficiencyOf(hosts);
  }
}

class PgRegistry {
  constructor(pool, env = {}) {
    this.pool = pool;
    this.env = env;
    this.metricInserts = 0;
  }

  async enroll({ tenantId, userId, keyId, hostId, hostname, os, platform, sshPubkey }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const mem = await client.query('SELECT tenant_id FROM cp_members WHERE user_id = $1', [userId]);
      const ins = await client.query(
        `INSERT INTO cp_tenants (tenant_id, display_name, owner_user_id)
         VALUES ($1, $1, $2)
         ON CONFLICT (tenant_id) DO NOTHING
         RETURNING tenant_id`,
        [tenantId, userId]
      );
      if (ins.rowCount > 0) {
        if (mem.rowCount > 0) throw http(403, 'tenant_create_denied');
        await client.query(
          `INSERT INTO cp_members (tenant_id, user_id, role) VALUES ($1, $2, 'admin')
           ON CONFLICT DO NOTHING`,
          [tenantId, userId]
        );
      } else {
        const member = await client.query(
          'SELECT role FROM cp_members WHERE tenant_id = $1 AND user_id = $2',
          [tenantId, userId]
        );
        if (member.rowCount === 0) throw http(403, 'not_a_member');
      }
      // A re-enroll keeps the stored ssh_pubkey: the row is locked, a
      // different key is refused, and the stored line (comment included) is
      // what the upsert compares, so the ON CONFLICT branch never rewrites it.
      // A row that appears between the lock and the insert must carry the
      // presented line exactly, else the upsert matches nothing.
      const cur = await client.query(
        'SELECT tenant_id, key_id, ssh_pubkey, retired_at FROM cp_hosts WHERE host_id = $1 FOR UPDATE',
        [hostId]
      );
      let pubkey = sshPubkey;
      if (cur.rowCount > 0) {
        const row = cur.rows[0];
        if (row.tenant_id !== tenantId || row.key_id !== keyId) throw http(403, 'host_steal');
        if (row.retired_at) throw http(403, 'host_retired');
        if (sshKeyMaterial(row.ssh_pubkey) !== sshKeyMaterial(sshPubkey)) throw http(403, 'host_key_mismatch');
        pubkey = row.ssh_pubkey;
      }
      const host = await client.query(
        `INSERT INTO cp_hosts (host_id, tenant_id, key_id, hostname, os, platform, ssh_pubkey, status, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'online', now())
         ON CONFLICT (host_id) DO UPDATE SET
           hostname = EXCLUDED.hostname,
           os = EXCLUDED.os,
           platform = EXCLUDED.platform,
           status = 'online',
           last_seen_at = now()
         WHERE cp_hosts.tenant_id = EXCLUDED.tenant_id AND cp_hosts.key_id = EXCLUDED.key_id
           AND cp_hosts.ssh_pubkey = EXCLUDED.ssh_pubkey AND cp_hosts.retired_at IS NULL
         RETURNING host_id`,
        [hostId, tenantId, keyId, hostname, os || '', platform || '', pubkey]
      );
      if (host.rowCount === 0) throw http(403, 'host_rejected');
      await this.syncHostStatesInTx(client, tenantId, hostId);
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
      throw err;
    } finally {
      client.release();
    }
    return this.getHost([tenantId], hostId);
  }

  // Identity is the member id only; email is display data, never a match key.
  async membershipsForUser(userId) {
    const res = await this.pool.query(
      'SELECT tenant_id, user_id, email, role, sso_sub FROM cp_members WHERE user_id = $1',
      [userId]
    );
    return res.rows;
  }

  async membershipsForSub(sub) {
    if (typeof sub !== 'string' || sub.length === 0) return [];
    const res = await this.pool.query(
      'SELECT tenant_id, user_id, email, role, sso_sub FROM cp_members WHERE sso_sub = $1',
      [sub]
    );
    return res.rows;
  }

  // One transaction: the binding and its audit-chain row land together or
  // not at all.
  async setSsoSub({ tenantId, userId, sub, actor }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const out = await ssoBindInTx(client, { tenantId, userId, sub, actor });
      await client.query('COMMIT');
      return out;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
      if (err.code === '23505') throw http(409, 'sso_sub_taken');
      throw err;
    } finally {
      client.release();
    }
  }

  // First-admin bootstrap (scripts/bootstrap-admin.js). One transaction:
  // the tenant (created when missing), the admin membership, the API key
  // that mintKey(client) inserts, its admin scope row, the audit row and,
  // with sub, the SSO binding and its audit row all land together or not at
  // all. Refused (409 admin_exists) while any admin member or admin-scoped
  // key exists, unless force; a forced run says so in its audit row. The
  // advisory lock serializes two bootstraps racing on an empty database.
  async bootstrapAdmin({ tenantId, userId, email, sub, force, actor, mintKey }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('cp_bootstrap_admin'))");
      // ssoBindInTx below takes this lock after the first audit row; taking
      // it now keeps the audit chain lock last (see auditInsert).
      if (typeof sub === 'string') await client.query("SELECT pg_advisory_xact_lock(hashtext('cp_members.sso_sub'))");
      const existing = await client.query(
        `SELECT (SELECT count(*) FROM cp_members WHERE role = 'admin')::int AS members,
                (SELECT count(*) FROM cp_api_scopes WHERE scope = 'admin')::int AS keys`
      );
      const { members, keys } = existing.rows[0];
      if ((members > 0 || keys > 0) && !force) throw http(409, 'admin_exists');
      const tenant = await client.query(
        `INSERT INTO cp_tenants (tenant_id, display_name, owner_user_id)
         VALUES ($1, $1, $2)
         ON CONFLICT (tenant_id) DO NOTHING
         RETURNING tenant_id`,
        [tenantId, userId]
      );
      const prev = await client.query(
        'SELECT role FROM cp_members WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE',
        [tenantId, userId]
      );
      await client.query(
        `INSERT INTO cp_members (tenant_id, user_id, role, email)
         VALUES ($1, $2, 'admin', $3)
         ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = 'admin', email = COALESCE(EXCLUDED.email, cp_members.email)`,
        [tenantId, userId, email || null]
      );
      const { keyId, keySecret } = await mintKey(client);
      await client.query("INSERT INTO cp_api_scopes (key_id, scope) VALUES ($1, 'admin')", [keyId]);
      await auditInsert(client, {
        tenant_id: tenantId,
        actor,
        action: 'bootstrap_admin',
        payload: {
          user_id: userId,
          key_fp: fingerprint(keyId),
          scopes: ['admin'],
          tenant_created: tenant.rowCount > 0,
          previous_role: prev.rows[0] ? prev.rows[0].role : null,
          forced: force === true,
          existing_admin_members: members,
          existing_admin_keys: keys,
          sso_bound: typeof sub === 'string'
        }
      });
      if (typeof sub === 'string') await ssoBindInTx(client, { tenantId, userId, sub, actor });
      await client.query('COMMIT');
      return { tenant_id: tenantId, user_id: userId, key_id: keyId, key_secret: keySecret, sso_bound: typeof sub === 'string', forced: force === true };
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
      if (err.code === '23505') throw http(409, 'conflict');
      throw err;
    } finally {
      client.release();
    }
  }

  async addMember(tenantId, userId, role, email) {
    if (!ROLES.has(role)) throw http(400, 'bad_role');
    const res = await this.pool.query(
      `INSERT INTO cp_members (tenant_id, user_id, role, email)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role, email = COALESCE(EXCLUDED.email, cp_members.email)
       RETURNING tenant_id, user_id, email, role`,
      [tenantId, userId, role, email || null]
    );
    return res.rows[0];
  }

  async listHosts(tenantIds, query, { includeRetired = false } = {}) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const like = query ? `%${escapeLike(query)}%` : null;
    const res = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, os, platform, ssh_pubkey, status, last_seen_at, tags, created_at, retired_at
       FROM cp_hosts
       WHERE tenant_id = ANY($1::text[])
         AND ($2::text IS NULL OR hostname ILIKE $2 ESCAPE '\\')
         AND ($3::boolean OR retired_at IS NULL)
       ORDER BY last_seen_at DESC NULLS LAST`,
      [tenantIds, like, includeRetired === true]
    );
    const ids = res.rows.map((r) => r.host_id);
    const sparks = await this.sparklines(ids);
    return res.rows.map((row) => {
      const series = sparks.get(row.host_id) || [];
      return publicHost({
        ...row,
        sparkline: series,
        cpu_percent: series.length ? series[series.length - 1] : null
      });
    });
  }

  async sparklines(hostIds) {
    const out = new Map();
    if (!hostIds.length) return out;
    const res = await this.pool.query(
      `SELECT host_id, value FROM (
         SELECT host_id, value, row_number() OVER (PARTITION BY host_id ORDER BY ts DESC) AS rn
         FROM cp_telemetry
         WHERE metric = 'cpu.usage_percent' AND host_id = ANY($1::text[])
       ) t WHERE rn <= 20`,
      [hostIds]
    );
    for (const row of res.rows) {
      if (!out.has(row.host_id)) out.set(row.host_id, []);
      out.get(row.host_id).push(Number(row.value));
    }
    for (const [id, values] of out) out.set(id, values.reverse());
    return out;
  }

  async getHost(tenantIds, hostId) {
    if (!tenantIds || tenantIds.length === 0) return null;
    const res = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, os, platform, ssh_pubkey, status, last_seen_at, tags, created_at, retired_at
       FROM cp_hosts WHERE host_id = $1 AND tenant_id = ANY($2::text[])`,
      [hostId, tenantIds]
    );
    if (!res.rows[0]) return null;
    const sparks = await this.sparklines([hostId]);
    const series = sparks.get(hostId) || [];
    return publicHost({
      ...res.rows[0],
      sparkline: series,
      cpu_percent: series.length ? series[series.length - 1] : null
    });
  }

  // Exact host_id, else exact case-insensitive hostname, inside tenantIds.
  async resolveHosts(tenantIds, name) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const byId = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, status, last_seen_at FROM cp_hosts
       WHERE host_id = $1 AND tenant_id = ANY($2::text[]) AND retired_at IS NULL`,
      [name, tenantIds]
    );
    if (byId.rows.length > 0) return byId.rows;
    const res = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, status, last_seen_at FROM cp_hosts
       WHERE lower(hostname) = lower($1) AND tenant_id = ANY($2::text[]) AND retired_at IS NULL
       ORDER BY host_id LIMIT 100`,
      [name, tenantIds]
    );
    return res.rows;
  }

  async touchHost(hostId, fields = {}) {
    await this.pool.query(
      `UPDATE cp_hosts SET last_seen_at = now(), status = 'online',
         os = COALESCE($2, os),
         platform = COALESCE($3, platform)
       WHERE host_id = $1`,
      [hostId, fields.os || null, fields.platform || null]
    );
  }

  async channelPolicies(hostId) {
    const res = await this.pool.query(
      `SELECT h.tcp_policy AS host_tcp_policy, h.file_policy AS host_file_policy,
              t.tcp_policy AS tenant_tcp_policy, t.file_policy AS tenant_file_policy
       FROM cp_hosts h JOIN cp_tenants t ON t.tenant_id = h.tenant_id
       WHERE h.host_id = $1 AND h.retired_at IS NULL`,
      [hostId]
    );
    return res.rows[0] || null;
  }

  async setHostChannelPolicy(hostId, fields) {
    await this.setChannelPolicy('cp_hosts', 'host_id', hostId, fields);
  }

  async setTenantChannelPolicy(tenantId, fields) {
    await this.setChannelPolicy('cp_tenants', 'tenant_id', tenantId, fields);
  }

  // One transaction on one client: lock the host row (it must belong to
  // tenantId), replace both policy columns, append the audit row with the old
  // and new policies. Any failure rolls all of it back.
  async setHostChannelPolicyAudited({ tenantId, hostId, tcpPolicy, filePolicy, actor, action, reason }) {
    assertPolicyShape('tcp', tcpPolicy);
    assertPolicyShape('file', filePolicy);
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const cur = await client.query(
        'SELECT tcp_policy, file_policy FROM cp_hosts WHERE host_id = $1 AND tenant_id = $2 FOR UPDATE',
        [hostId, tenantId]
      );
      if (cur.rowCount === 0) throw http(404, 'not_found');
      const prev = cur.rows[0];
      await client.query(
        'UPDATE cp_hosts SET tcp_policy = $2::jsonb, file_policy = $3::jsonb WHERE host_id = $1',
        [hostId, tcpPolicy === null ? null : JSON.stringify(tcpPolicy), filePolicy === null ? null : JSON.stringify(filePolicy)]
      );
      await auditInsert(client, channelPolicyAuditEntry(tenantId, hostId, actor, action, reason, tcpPolicy, filePolicy, prev.tcp_policy, prev.file_policy));
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
      throw err;
    } finally {
      client.release();
    }
  }

  // table and key are fixed identifiers from the two callers above, never
  // caller input. Values are parameters.
  async setChannelPolicy(table, keyColumn, id, fields) {
    const sets = [];
    const values = [id];
    for (const key of ['tcp_policy', 'file_policy']) {
      if (!(key in fields)) continue;
      assertPolicyShape(key === 'tcp_policy' ? 'tcp' : 'file', fields[key]);
      values.push(fields[key] === null ? null : JSON.stringify(fields[key]));
      sets.push(`${key} = $${values.length}::jsonb`);
    }
    if (sets.length === 0) return;
    const res = await this.pool.query(`UPDATE ${table} SET ${sets.join(', ')} WHERE ${keyColumn} = $1`, values);
    if (res.rowCount === 0) throw http(404, 'not_found');
  }

  async setHostStatus(hostId, status) {
    await this.pool.query('UPDATE cp_hosts SET status = $2 WHERE host_id = $1', [hostId, status]);
  }

  async setAgentPresence(hostId, { caps, instance, connId, enrolledAt }) {
    const p = agentPresence(caps, instance, connId, enrolledAt);
    const res = await this.pool.query(
      `UPDATE cp_hosts SET agent_caps = $2::text[], agent_instance = $3, agent_conn_id = $4, agent_enrolled_at = $5,
       agent_seen_at = now()
       WHERE host_id = $1 AND (agent_enrolled_at IS NULL OR agent_enrolled_at <= $5)`,
      [hostId, p.caps, p.instance, p.connId, p.enrolledAt]
    );
    return res.rowCount > 0;
  }

  async clearAgentPresence(hostId, connId) {
    const res = await this.pool.query(
      `UPDATE cp_hosts SET agent_caps = NULL, agent_instance = NULL, agent_conn_id = NULL, agent_enrolled_at = NULL,
       agent_seen_at = NULL
       WHERE host_id = $1 AND agent_conn_id = $2`,
      [hostId, String(connId)]
    );
    return res.rowCount > 0;
  }

  // The database clock decides the age, the same for every replica.
  async hostAgent(hostId, { maxAgeS = null } = {}) {
    const res = await this.pool.query(
      `SELECT agent_caps, agent_instance, agent_conn_id FROM cp_hosts
       WHERE host_id = $1 AND retired_at IS NULL AND agent_conn_id IS NOT NULL
       AND ($2::int IS NULL OR agent_seen_at > now() - make_interval(secs => $2::int))`,
      [hostId, maxAgeS]
    );
    const row = res.rows[0];
    if (!row) return null;
    return { instance: row.agent_instance, conn_id: row.agent_conn_id, caps: [...(row.agent_caps || [])] };
  }

  // One transaction: lock the host row (it must belong to tenantId), stamp
  // retired_at, append the host_retired audit row. Any failure rolls both
  // back.
  async retireHost({ tenantId, hostId, actor, reason, forced }) {
    const text = retireReason(reason);
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const cur = await client.query(
        `SELECT host_id, tenant_id, hostname, last_seen_at, retired_at FROM cp_hosts
         WHERE host_id = $1 AND tenant_id = $2 FOR UPDATE`,
        [hostId, tenantId]
      );
      if (cur.rowCount === 0) throw http(404, 'not_found');
      if (cur.rows[0].retired_at) throw http(409, 'already_retired');
      await client.query(
        `UPDATE cp_hosts SET retired_at = now(), status = 'offline' WHERE host_id = $1`,
        [hostId]
      );
      await this.syncHostStatesInTx(client, tenantId, hostId);
      await auditInsert(client, hostRetiredAuditEntry(cur.rows[0], actor, text, forced));
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
      throw err;
    } finally {
      client.release();
    }
    return this.getHost([tenantId], hostId);
  }

  async countHosts() {
    const res = await this.pool.query(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE status = 'online')::int AS online
       FROM cp_hosts WHERE retired_at IS NULL`
    );
    const total = res.rows[0].total || 0;
    const online = res.rows[0].online || 0;
    return { total, online, offline: total - online };
  }

  async countOpenAlerts() {
    const res = await this.pool.query(
      `SELECT count(*)::int AS n FROM cp_alert_events WHERE status = 'open'`
    );
    return res.rows[0].n || 0;
  }

  async recordMetric(hostId, metric, value, labels = {}) {
    if (!METRICS.has(metric) || typeof value !== 'number' || Number.isNaN(value)) return;
    await this.pool.query(
      `INSERT INTO cp_telemetry (host_id, metric, value, labels) VALUES ($1, $2, $3, $4::jsonb)`,
      [hostId, metric, value, JSON.stringify(labels)]
    );
    this.metricInserts += 1;
    if (this.metricInserts % 100 === 0) await this.pruneTelemetry(retentionDays(this.env));
  }

  async pruneTelemetry(days) {
    const n = retentionDays({ SYSTEMAPI_METRICS_RETENTION_DAYS: String(days) });
    await this.pool.query('DELETE FROM cp_telemetry WHERE ts < now() - make_interval(days => $1::int)', [n]);
  }

  async metricSeries(hostId, metric, limit = 60) {
    if (!METRICS.has(metric)) return [];
    const res = await this.pool.query(
      `SELECT ts, value FROM cp_telemetry
       WHERE host_id = $1 AND metric = $2
       ORDER BY ts DESC LIMIT $3`,
      [hostId, metric, limit]
    );
    return res.rows.reverse().map((r) => ({ ts: r.ts, value: Number(r.value) }));
  }

  async metricAggregate(hostId, metric, bucket, from, to) {
    if (!METRICS.has(metric)) return [];
    const res = await this.pool.query(
      `SELECT date_trunc($1::text, ts) AS bucket, avg(value) AS value
       FROM cp_telemetry
       WHERE host_id = $2 AND metric = $3
         AND ($4::timestamptz IS NULL OR ts >= $4)
         AND ($5::timestamptz IS NULL OR ts < $5)
       GROUP BY 1 ORDER BY 1`,
      [bucket, hostId, metric, from ? new Date(from) : null, to ? new Date(to) : null]
    );
    return res.rows.map((r) => ({ bucket: r.bucket, value: Number(r.value) }));
  }

  async appendAudit(entry) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const row = await auditInsert(client, entry);
      await client.query('COMMIT');
      return row;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* already closed */ }
      throw err;
    } finally {
      client.release();
    }
  }

  async verifyAudit() {
    const res = await this.pool.query(
      'SELECT seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload FROM cp_audit ORDER BY seq ASC'
    );
    return verifyRows(res.rows.map((row) => ({ ...row, seq: Number(row.seq) })));
  }

  async listAudit(tenantIds, limit = 100) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload, created_at
       FROM cp_audit WHERE tenant_id = ANY($1::text[])
       ORDER BY seq DESC LIMIT $2`,
      [tenantIds, limit]
    );
    return res.rows;
  }

  async recordSecurity(event) {
    const res = await this.pool.query(
      `INSERT INTO cp_security_events (tenant_id, kind, actor_fingerprint, detail)
       VALUES ($1, $2, $3, $4::jsonb)
       RETURNING id, tenant_id, kind, actor_fingerprint, detail, created_at`,
      [event.tenant_id || null, event.kind, event.actor_fingerprint || null, JSON.stringify(event.detail || {})]
    );
    return res.rows[0];
  }

  async listSecurity(tenantIds, limit = 100) {
    const ids = Array.isArray(tenantIds) ? tenantIds : [];
    if (ids.length === 0) return [];
    const res = await this.pool.query(
      `SELECT id, tenant_id, kind, actor_fingerprint, detail, created_at
       FROM cp_security_events
       WHERE tenant_id = ANY($1::text[])
       ORDER BY id DESC LIMIT $2`,
      [ids, limit]
    );
    return res.rows;
  }

  async scopesForKey(keyId) {
    const res = await this.pool.query('SELECT scope FROM cp_api_scopes WHERE key_id = $1', [keyId]);
    return scopesForKeyRows(res.rows.map((r) => r.scope), this.env);
  }

  // True only while the key row exists, is active, is not locked and has
  // not expired: the same rules verifyApiKey applies. The demo key has no
  // row and is active only where demoKeyAllowed says so.
  async keyActive(keyId) {
    if (typeof keyId !== 'string' || keyId.length === 0) return false;
    if (keyId === DEMO_KEY_ID) return demoKeyAllowed(this.env);
    const res = await this.pool.query(
      `SELECT 1 FROM playground_api_keys
       WHERE key_id = $1 AND is_active = true AND is_locked = false
         AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
      [keyId]
    );
    return res.rows.length > 0;
  }

  async setScopes(keyId, scopes) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM cp_api_scopes WHERE key_id = $1', [keyId]);
      for (const scope of scopes) {
        await client.query('INSERT INTO cp_api_scopes (key_id, scope) VALUES ($1, $2)', [keyId, scope]);
      }
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    } finally {
      client.release();
    }
  }

  async recentAlert(hostId, ruleName, withinMs) {
    const res = await this.pool.query(
      `SELECT 1 FROM cp_alert_events
       WHERE host_id = $1 AND rule_name = $2 AND created_at > now() - make_interval(secs => $3::int)
       LIMIT 1`,
      [hostId, ruleName, Math.ceil(withinMs / 1000)]
    );
    return res.rowCount > 0;
  }

  async openAlert(entry) {
    const res = await this.pool.query(
      `INSERT INTO cp_alert_events (tenant_id, host_id, rule_name, metric, value, severity, message, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'open')
       RETURNING id, tenant_id, host_id, rule_name, metric, value, severity, message, status, created_at`,
      [entry.tenant_id, entry.host_id, entry.rule_name, entry.metric || null, entry.value, entry.severity || null, entry.message || null]
    );
    return res.rows[0];
  }

  async listAlerts(tenantIds, status) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT id, tenant_id, host_id, rule_name, metric, value, severity, message, status, created_at
       FROM cp_alert_events
       WHERE tenant_id = ANY($1::text[]) AND ($2::text IS NULL OR status = $2)
       ORDER BY created_at DESC`,
      [tenantIds, status || null]
    );
    return res.rows;
  }

  async setAlertStatus(tenantIds, id, status) {
    if (!tenantIds || tenantIds.length === 0) return null;
    const res = await this.pool.query(
      `UPDATE cp_alert_events SET status = $3
       WHERE id = $1 AND tenant_id = ANY($2::text[])
       RETURNING id, tenant_id, host_id, rule_name, metric, value, severity, message, status, created_at`,
      [id, tenantIds, status]
    );
    return res.rows[0] || null;
  }

  async createWebhook(row) {
    await this.pool.query(
      `INSERT INTO cp_webhooks (id, tenant_id, url, secret, secret_fingerprint)
       VALUES ($1, $2, $3, $4, $5)`,
      [row.id, row.tenant_id, row.url, row.secret, row.secret_fingerprint]
    );
    return publicWebhook(row);
  }

  async listWebhooks(tenantId) {
    const res = await this.pool.query(
      `SELECT id, tenant_id, url, secret_fingerprint, created_at FROM cp_webhooks WHERE tenant_id = $1`,
      [tenantId]
    );
    return res.rows.map(publicWebhook);
  }

  async deleteWebhook(tenantId, id) {
    const res = await this.pool.query('DELETE FROM cp_webhooks WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
    return res.rowCount > 0;
  }

  async webhooksForTenant(tenantId) {
    const res = await this.pool.query(
      'SELECT id, tenant_id, url, secret, secret_fingerprint FROM cp_webhooks WHERE tenant_id = $1',
      [tenantId]
    );
    return res.rows;
  }

  async createSchedule(row) {
    await this.pool.query(
      `INSERT INTO cp_schedules (id, tenant_id, host_id, cron, script) VALUES ($1, $2, $3, $4, $5)`,
      [row.id, row.tenant_id, row.host_id, row.cron, row.script]
    );
    return publicSchedule(row);
  }

  async listSchedules(tenantId) {
    const res = await this.pool.query(
      `SELECT id, tenant_id, host_id, cron, last_run_minute, created_at FROM cp_schedules WHERE tenant_id = $1`,
      [tenantId]
    );
    return res.rows.map(publicSchedule);
  }

  async deleteSchedule(tenantId, id) {
    const res = await this.pool.query('DELETE FROM cp_schedules WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
    return res.rowCount > 0;
  }

  async dueSchedules(date) {
    const { cronMatches } = require('./stats');
    const res = await this.pool.query('SELECT id, tenant_id, host_id, cron, script, last_run_minute FROM cp_schedules');
    return res.rows.filter((row) => cronMatches(row.cron, date));
  }

  async markSchedule(id, minuteKey) {
    const res = await this.pool.query(
      `UPDATE cp_schedules SET last_run_minute = $2
       WHERE id = $1 AND (last_run_minute IS DISTINCT FROM $2)`,
      [id, minuteKey]
    );
    return res.rowCount > 0;
  }

  async addComment(entry) {
    if (typeof entry.body !== 'string' || entry.body.length === 0 || entry.body.length > 2000) {
      throw http(400, 'bad_comment');
    }
    const res = await this.pool.query(
      `INSERT INTO cp_comments (tenant_id, host_id, author, body)
       VALUES ($1, $2, $3, $4)
       RETURNING id, tenant_id, host_id, author, body, created_at`,
      [entry.tenant_id, entry.host_id, entry.author, entry.body]
    );
    return res.rows[0];
  }

  async listComments(tenantId, hostId) {
    const res = await this.pool.query(
      `SELECT id, tenant_id, host_id, author, body, created_at
       FROM cp_comments WHERE tenant_id = $1 AND host_id = $2 ORDER BY id ASC`,
      [tenantId, hostId]
    );
    return res.rows;
  }

  async upsertSoftware(hostId, sw) {
    const res = await this.pool.query(
      `INSERT INTO cp_software (host_id, name, version, architecture)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (host_id, name, version) DO UPDATE SET last_detected_at = now()
       RETURNING (xmax = 0) AS inserted`,
      [hostId, sw.name || 'unknown', sw.version || 'unknown', sw.architecture || '']
    );
    return { inserted: Boolean(res.rows[0] && res.rows[0].inserted) };
  }

  async listSoftware(hostId) {
    const res = await this.pool.query(
      'SELECT host_id, name, version, architecture, last_detected_at FROM cp_software WHERE host_id = $1 ORDER BY name',
      [hostId]
    );
    return res.rows;
  }

  async saveCVE(row) {
    await this.pool.query(
      `INSERT INTO cp_cves (host_id, software_name, software_version, cve_id, severity, description)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT DO NOTHING`,
      [row.host_id, row.software_name, row.software_version, row.cve_id, row.severity || 'Unknown', row.description || '']
    );
  }

  async listCVEs(hostId) {
    const res = await this.pool.query(
      `SELECT host_id, software_name, software_version, cve_id, severity, description, discovered_at
       FROM cp_cves WHERE host_id = $1 ORDER BY discovered_at DESC`,
      [hostId]
    );
    return res.rows;
  }

  // A client whose ROLLBACK fails is destroyed, never returned to the pool
  // with a transaction possibly still open.
  async inTx(fn) {
    const client = await this.pool.connect();
    let broken;
    try {
      await client.query('BEGIN');
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch (rollbackErr) { broken = rollbackErr; }
      throw err;
    } finally {
      client.release(broken);
    }
  }

  // pg_notify inside the caller's transaction: delivered only on COMMIT.
  async notifyInTx(client, evt) {
    const e = jobEvent(evt);
    if (!e) throw http(500, 'bad_job_event');
    await client.query('SELECT pg_notify($1, $2)', [JOB_CHANNEL, JSON.stringify(e)]);
  }

  // Ends rows already updated in this transaction: converge finalize, then
  // end audit and state notify for each.
  async endedInTx(client, rows) {
    const sorted = [...rows].sort((a, b) => (a.job_id < b.job_id ? -1 : 1));
    // A converge run ended here has no report: its claim is released and its
    // host state finalized (an apply becomes partial) before any audit row.
    for (const row of sorted) {
      if (isConvergeSource(row.source)) await this.convergeIngestInTx(client, row, null);
    }
    for (const row of sorted) {
      await auditInsert(client, jobEndAuditEntry(row, 'system'));
      await this.notifyInTx(client, stateEvent(row));
    }
    return sorted.map((row) => publicJob(row));
  }

  // One transaction: the tenant then the host advisory lock (fixed order),
  // the host must be this tenant's and live, count the non-terminal rows,
  // insert, the submit audit row, NOTIFY dispatch.
  // A converge job (opts.converge) also locks and checks its plan run
  // (apply) and host-state row after the caps, inserts its cp_converge_runs
  // row, and claims the host state (check_job_id) or consumes the plan
  // (last_apply_run_id): a 429 or any refusal rolls all of it back, so it
  // never burns a plan.
  async createJob(row, opts = {}) {
    const r = jobInsertRow(row);
    const conv = convergeJobInput(r, opts.converge);
    const { hostCap, tenantCap } = jobCaps(opts);
    try {
      return await this.inTx(async (client) => {
        await client.query("SELECT pg_advisory_xact_lock(hashtext('sjob:t:' || $1))", [r.tenant_id]);
        await client.query("SELECT pg_advisory_xact_lock(hashtext('sjob:h:' || $1))", [r.host_id]);
        const host = await client.query(
          'SELECT 1 FROM cp_hosts WHERE host_id = $1 AND tenant_id = $2 AND retired_at IS NULL',
          [r.host_id, r.tenant_id]
        );
        if (host.rowCount === 0) throw http(404, 'not_found');
        // Same order as MemoryRegistry: a duplicate id is 409 even at the cap.
        const dup = await client.query('SELECT 1 FROM cp_sysscript_jobs WHERE job_id = $1', [r.job_id]);
        if (dup.rowCount > 0) throw http(409, 'conflict');
        const counts = await client.query(
          `SELECT count(*) FILTER (WHERE host_id = $1)::int AS on_host,
                  count(*) FILTER (WHERE tenant_id = $2)::int AS on_tenant
           FROM cp_sysscript_jobs
           WHERE status = ANY($3::text[]) AND (host_id = $1 OR tenant_id = $2)`,
          [r.host_id, r.tenant_id, JOB_ACTIVE]
        );
        const { on_host: onHost, on_tenant: onTenant } = counts.rows[0];
        if (onHost >= hostCap || onTenant >= tenantCap) throw http(429, 'too_many_jobs');
        const eff = conv ? await this.convergeCheckInTx(client, r, conv) : null;
        const ins = await client.query(
          `INSERT INTO cp_sysscript_jobs (job_id, tenant_id, host_id, actor, source, script_sha256, entitlements_sha256,
             entitlements, status, timeout_s, deadline_at, lease_nonce, dispatch)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, 'submitted', $9, $10, $11, $12::jsonb)
           RETURNING ${jobCols()}`,
          [r.job_id, r.tenant_id, r.host_id, r.actor, r.source, r.script_sha256, r.entitlements_sha256,
            JSON.stringify(r.entitlements), r.timeout_s, r.deadline_at, r.lease_nonce, JSON.stringify(r.dispatch)]
        );
        const stored = ins.rows[0];
        if (conv) await this.convergeCreateInTx(client, r, conv, eff);
        await auditInsert(client, jobSubmitAuditEntry(stored));
        await this.notifyInTx(client, stateEvent(stored, 'dispatch'));
        return publicJob(stored);
      });
    } catch (err) {
      if (err.code === '23505') throw http(409, 'conflict');
      throw err;
    }
  }

  async getJob(tenantIds, jobId) {
    if (!tenantIds || tenantIds.length === 0 || typeof jobId !== 'string') return null;
    const res = await this.pool.query(
      `SELECT ${jobCols()} FROM cp_sysscript_jobs WHERE job_id = $1 AND tenant_id = ANY($2::text[])`,
      [jobId, tenantIds]
    );
    return publicJob(res.rows[0] || null);
  }

  // Never returns output.
  async listJobs(tenantIds, opts = {}) {
    const { hostId, status, limit } = jobListQuery(opts);
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT ${jobCols('', { output: false })} FROM cp_sysscript_jobs
       WHERE tenant_id = ANY($1::text[])
         AND ($2::text IS NULL OR host_id = $2)
         AND ($3::text IS NULL OR status = $3)
       ORDER BY created_at DESC, job_id DESC LIMIT $4`,
      [tenantIds, hostId, status, limit]
    );
    return res.rows.map((row) => publicJob(row, { withOutput: false }));
  }

  // One guarded UPDATE (job_id, host_id, status in fromStatuses, and
  // conn_id with opts.connId), with the optional audit row and NOTIFY in the
  // same transaction. Null when the guard does not hold. SECURITY-RULES rule
  // 7: the interpolated SET column names and $n placeholders come from the
  // fixed key list below and a counter, never from input; values are bound.
  // A terminal transition locks the row first: on a converge row,
  // opts.converge.report is validated before the UPDATE (a malformed one ends
  // the job failed[bad_report] with a security event) and ingested after it
  // (convergeIngestInTx: run, host state, drift alert, state_report audit),
  // all before the job's own audit row and the commit; the result carries
  // .converge. A converge row ended without a report is finalized.
  async transitionJob(jobId, hostId, fromStatuses, fields, opts = {}) {
    const { from, set: asked } = jobTransition(fromStatuses, fields);
    const guardConn = 'connId' in opts;
    if (guardConn && !nonEmpty(opts.connId)) throw http(500, 'bad_conn_id');
    if (typeof jobId !== 'string' || typeof hostId !== 'string') return null;
    return this.inTx(async (client) => {
      let verdict = { set: asked, rep: null, bad: null };
      if (isTerminal(asked.status)) {
        const cur = await client.query(
          'SELECT job_id, tenant_id, host_id, source, script_sha256 FROM cp_sysscript_jobs WHERE job_id = $1 AND host_id = $2 FOR UPDATE',
          [jobId, hostId]
        );
        verdict = convergeVerdict(from, fields, asked, opts, cur.rows[0]);
      }
      const { set } = verdict;
      const values = [jobId, hostId, from, set.status];
      const sets = ['status = $4'];
      for (const key of ['error', 'output', 'output_truncated', 'duration_ms']) {
        if (!(key in set)) continue;
        values.push(set[key]);
        sets.push(`${key} = $${values.length}`);
      }
      if (set.status === 'accepted' || set.status === 'running') sets.push('accepted_at = COALESCE(accepted_at, now())');
      if (set.status === 'running') sets.push('started_at = COALESCE(started_at, now())');
      if (isTerminal(set.status)) sets.push('finished_at = now()', 'dispatch = NULL');
      let guard = '';
      if (guardConn) {
        values.push(opts.connId);
        guard = ` AND conn_id = $${values.length}`;
      }
      const res = await client.query(
        `UPDATE cp_sysscript_jobs SET ${sets.join(', ')}
         WHERE job_id = $1 AND host_id = $2 AND status = ANY($3::text[])${guard}
         RETURNING ${jobCols()}`,
        values
      );
      const row = res.rows[0];
      if (!row) return null;
      if (verdict.bad) await this.securityInTx(client, badReportEvent(row, verdict.bad));
      const conv = isTerminal(row.status) && isConvergeSource(row.source)
        ? await this.convergeIngestInTx(client, row, verdict.rep) : null;
      const entry = transitionAuditEntry(row, opts.audit);
      if (entry) await auditInsert(client, entry);
      const evt = transitionNotify(row, opts.notify);
      if (evt) await this.notifyInTx(client, evt);
      const out = publicJob(row);
      if (conv) out.converge = conv;
      return out;
    });
  }

  // Claims the dispatch payload once across instances: the row lock makes a
  // second caller see dispatch already NULL.
  async markDispatched(jobId, hostId, connId) {
    if (!nonEmpty(connId)) throw http(500, 'bad_conn_id');
    if (typeof jobId !== 'string' || typeof hostId !== 'string') return null;
    const res = await this.pool.query(
      `WITH cur AS (
         SELECT job_id, dispatch FROM cp_sysscript_jobs
         WHERE job_id = $1 AND host_id = $2 AND status = 'submitted' AND dispatch IS NOT NULL
         FOR UPDATE
       )
       UPDATE cp_sysscript_jobs j SET conn_id = $3, sent_at = now(), dispatch = NULL
       FROM cur WHERE j.job_id = cur.job_id
       RETURNING cur.dispatch AS claimed_dispatch, ${jobCols('j.')}`,
      [jobId, hostId, connId]
    );
    const row = res.rows[0];
    if (!row) return null;
    return { ...publicJob(row), dispatch: row.claimed_dispatch };
  }

  // Null when the job is not in tenantIds; 409 job_finished when terminal.
  // A second request returns the row unchanged. A job never sent to the
  // agent ends cancelled right here. Cancel audit (and end audit) and
  // NOTIFY in the same transaction.
  async requestJobCancel(tenantIds, jobId, actor, reason = 'user') {
    if (!nonEmpty(actor) || !nonEmpty(reason)) throw http(400, 'bad_cancel');
    if (!tenantIds || tenantIds.length === 0 || typeof jobId !== 'string') return null;
    return this.inTx(async (client) => {
      const cur = await client.query(
        `SELECT ${jobCols()}, (dispatch IS NOT NULL) AS undispatched FROM cp_sysscript_jobs
         WHERE job_id = $1 AND tenant_id = ANY($2::text[]) FOR UPDATE`,
        [jobId, tenantIds]
      );
      const row = cur.rows[0];
      if (!row) return null;
      if (isTerminal(row.status)) throw http(409, 'job_finished');
      if (row.cancel_requested_at) return publicJob(row);
      const never = row.status === 'submitted' && row.undispatched;
      const upd = await client.query(
        never
          ? `UPDATE cp_sysscript_jobs SET cancel_requested_at = now(), cancel_actor = $2, status = 'cancelled',
               error = 'cancelled_before_dispatch', finished_at = now(), dispatch = NULL
             WHERE job_id = $1 RETURNING ${jobCols()}`
          : `UPDATE cp_sysscript_jobs SET cancel_requested_at = now(), cancel_actor = $2
             WHERE job_id = $1 RETURNING ${jobCols()}`,
        [jobId, actor]
      );
      const out = upd.rows[0];
      if (never && isConvergeSource(out.source)) await this.convergeIngestInTx(client, out, null);
      await auditInsert(client, jobCancelAuditEntry(out, actor, reason));
      if (never) await auditInsert(client, jobEndAuditEntry(out, 'system'));
      await this.notifyInTx(client, stateEvent(out, never ? 'state' : 'cancel'));
      return publicJob(out);
    });
  }

  async markCancelSent(jobId, hostId) {
    if (typeof jobId !== 'string' || typeof hostId !== 'string') return null;
    const res = await this.pool.query(
      `UPDATE cp_sysscript_jobs SET cancel_sent_at = now()
       WHERE job_id = $1 AND host_id = $2 AND cancel_requested_at IS NOT NULL AND status = ANY($3::text[])
       RETURNING ${jobCols()}`,
      [jobId, hostId, JOB_ACTIVE]
    );
    return publicJob(res.rows[0] || null);
  }

  // {ok:true, tenant_id, alert_count} or {ok:false, reason}.
  async bumpJobAlert(jobId, hostId, max = 20) {
    const cap = jobAlertCap(max);
    if (typeof jobId !== 'string' || typeof hostId !== 'string') return { ok: false, reason: 'unknown_execution' };
    const res = await this.pool.query(
      `UPDATE cp_sysscript_jobs SET alert_count = alert_count + 1
       WHERE job_id = $1 AND host_id = $2 AND status IN ('accepted', 'running') AND alert_count < $3
       RETURNING tenant_id, alert_count`,
      [jobId, hostId, cap]
    );
    if (res.rows[0]) return { ok: true, tenant_id: res.rows[0].tenant_id, alert_count: res.rows[0].alert_count };
    const live = await this.pool.query(
      `SELECT 1 FROM cp_sysscript_jobs WHERE job_id = $1 AND host_id = $2 AND status IN ('accepted', 'running')`,
      [jobId, hostId]
    );
    return { ok: false, reason: live.rowCount > 0 ? 'rate_limited' : 'unknown_execution' };
  }

  // Sync step 3 (§6.1), in one transaction with the end audit rows. The
  // host's sent, non-terminal rows are locked first in job_id order (so two
  // writers over the same rows cannot deadlock); the UPDATEs that follow are
  // new statements and see every committed change. Listed rows move to
  // connId: the agent holds them on this socket now.
  async reconcileHostJobs(hostId, connId, listedIds) {
    if (!nonEmpty(connId)) throw http(500, 'bad_conn_id');
    const listed = syncIds(listedIds);
    if (typeof hostId !== 'string') return [];
    return this.inTx(async (client) => {
      await client.query(
        `SELECT job_id FROM cp_sysscript_jobs
         WHERE host_id = $1 AND status = ANY($2::text[]) AND conn_id IS NOT NULL
         ORDER BY job_id FOR UPDATE`,
        [hostId, JOB_ACTIVE]
      );
      await client.query(
        `UPDATE cp_sysscript_jobs SET conn_id = $3,
           status = CASE WHEN status = 'submitted' THEN 'accepted' ELSE status END,
           accepted_at = COALESCE(accepted_at, now())
         WHERE host_id = $1 AND status = ANY($2::text[]) AND conn_id IS NOT NULL
           AND job_id = ANY($4::text[])`,
        [hostId, JOB_ACTIVE, connId, listed]
      );
      const res = await client.query(
        `UPDATE cp_sysscript_jobs SET status = 'failed', error = 'agent_lost_job', finished_at = now(), dispatch = NULL
         WHERE host_id = $1 AND status = ANY($2::text[]) AND conn_id IS NOT NULL AND conn_id <> $3
           AND NOT (job_id = ANY($4::text[]))
         RETURNING ${jobCols()}`,
        [hostId, JOB_ACTIVE, connId, listed]
      );
      return this.endedInTx(client, res.rows);
    });
  }

  async pendingForHosts(hostIds) {
    const ids = connIdList(hostIds);
    if (ids.length === 0) return [];
    const res = await this.pool.query(
      `SELECT job_id, host_id, status, (dispatch IS NOT NULL) AS dispatch_pending,
              (cancel_requested_at IS NOT NULL AND cancel_sent_at IS NULL) AS cancel_pending
       FROM cp_sysscript_jobs
       WHERE host_id = ANY($1::text[]) AND status = ANY($2::text[])
         AND (dispatch IS NOT NULL OR (cancel_requested_at IS NOT NULL AND cancel_sent_at IS NULL))
       ORDER BY created_at, job_id LIMIT 1000`,
      [ids, JOB_ACTIVE]
    );
    return res.rows;
  }

  // Ends overdue rows (§6.1), at most JOB_SWEEP_BATCH (a constant, the only
  // interpolation besides the fixed condition text; SECURITY-RULES rule 7),
  // with their error code, end audit rows and NOTIFYs, in one transaction. The cutoffs come from the
  // database clock (now()), so replicas with skewed clocks agree; the now
  // argument is used only by MemoryRegistry. Overdue rows are locked in
  // job_id order with SKIP LOCKED (a row another writer holds is left for
  // the next tick), then updated by id in a new statement.
  async sweepJobs(now = Date.now(), opts = {}) {
    const s = jobSweep(now, opts);
    const overdue = `status = ANY($1::text[]) AND (
           (status = 'submitted' AND dispatch IS NOT NULL
             AND created_at < now() - make_interval(secs => $3::double precision / 1000))
           OR (status = 'submitted' AND conn_id = ANY($2::text[])
             AND sent_at < now() - make_interval(secs => $4::double precision / 1000))
           OR deadline_at < now() - make_interval(secs => $5::double precision / 1000))`;
    const params = [JOB_ACTIVE, s.connIds, s.dispatchMs, s.ackMs, s.graceMs];
    return this.inTx(async (client) => {
      const locked = await client.query(
        `SELECT job_id FROM cp_sysscript_jobs WHERE ${overdue}
         ORDER BY job_id LIMIT ${JOB_SWEEP_BATCH} FOR UPDATE SKIP LOCKED`,
        params
      );
      if (locked.rowCount === 0) return [];
      const res = await client.query(
        `UPDATE cp_sysscript_jobs SET status = 'failed', finished_at = now(), dispatch = NULL,
           error = CASE
             WHEN status = 'submitted' AND dispatch IS NOT NULL
               AND created_at < now() - make_interval(secs => $3::double precision / 1000) THEN 'dispatch_timeout'
             WHEN status = 'submitted' AND conn_id = ANY($2::text[])
               AND sent_at < now() - make_interval(secs => $4::double precision / 1000) THEN 'agent_no_ack'
             ELSE 'result_lost' END
         WHERE job_id = ANY($6::text[]) AND ${overdue}
         RETURNING ${jobCols()}`,
        [...params, locked.rows.map((r) => r.job_id)]
      );
      return this.endedInTx(client, res.rows);
    });
  }

  // Also nulls converge run reports on the same retention (summary and
  // report_sha256 stay) and plan bundles older than the plan max age.
  // Returns the count of job rows.
  async expireOutput(hours) {
    const n = jobOutputRetentionHours({ SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS: String(hours) });
    const res = await this.pool.query(
      `UPDATE cp_sysscript_jobs SET output = NULL, output_expired = true
       WHERE output IS NOT NULL AND finished_at < now() - make_interval(hours => $1::int)`,
      [n]
    );
    await this.pool.query(
      `UPDATE cp_converge_runs SET report = NULL, report_expired = true
       WHERE report IS NOT NULL AND finished_at < now() - make_interval(hours => $1::int)`,
      [n]
    );
    await this.pool.query(
      `UPDATE cp_converge_runs SET bundle_json = NULL
       WHERE kind = 'plan' AND bundle_json IS NOT NULL AND created_at < now() - make_interval(secs => $1::int)`,
      [planMaxAgeS(this.env)]
    );
    return res.rowCount;
  }

  // Check runs go with their job row; plan and apply runs are kept
  // SYSTEMAPI_APPLY_RUN_RETENTION_DAYS (365). Returns the count of job rows.
  async pruneJobs(days) {
    const n = jobRetentionDays({ SYSTEMAPI_JOB_RETENTION_DAYS: String(days) });
    const res = await this.pool.query(
      `WITH gone AS (
         DELETE FROM cp_sysscript_jobs
         WHERE NOT (status = ANY($2::text[])) AND finished_at < now() - make_interval(days => $1::int)
         RETURNING job_id),
       runs AS (
         DELETE FROM cp_converge_runs c USING gone WHERE c.run_id = gone.job_id AND c.kind = 'check')
       SELECT count(*)::int AS n FROM gone`,
      [n, JOB_ACTIVE]
    );
    await this.pool.query(
      `DELETE FROM cp_converge_runs WHERE kind IN ('plan', 'apply') AND created_at < now() - make_interval(days => $1::int)`,
      [applyRunRetentionDays(this.env)]
    );
    return res.rows[0].n;
  }

  // A NOTIFY outside any write (the writes above notify in their own
  // transaction).
  async publishJobEvent(evt) {
    const e = jobEvent(evt);
    if (!e) return false;
    await this.pool.query('SELECT pg_notify($1, $2)', [JOB_CHANNEL, JSON.stringify(e)]);
    return true;
  }

  // Returns the unsubscribe function. Its .ready never rejects: it resolves
  // true once LISTEN is in, or false when the first attempt failed (degraded:
  // reconnects go on in the background, and the pendingForHosts scan covers
  // the gap) or the listener was closed first.
  onJobEvent(fn) {
    if (!this.jobBus) this.jobBus = new EventEmitter();
    this.jobBus.on('event', fn);
    const off = () => { this.jobBus.off('event', fn); };
    off.ready = this.listenJobEvents();
    return off;
  }

  // One dedicated client per registry runs LISTEN. On an error or end it is
  // dropped and reconnected with backoff (250 ms doubling to 10 s); events
  // lost in the gap are found by the pendingForHosts scan. A payload that is
  // not a well-formed job event is dropped. The channel is a constant.
  listenJobEvents() {
    if (this.jobListen) return this.jobListen.ready;
    const state = { stopped: false, client: null, detach: null, timer: null, backoff: 250 };
    let resolveReady;
    state.ready = new Promise((resolve) => { resolveReady = resolve; });
    state.settle = (ok) => { resolveReady(ok); };
    this.jobListen = state;
    const retry = (err) => {
      state.settle(false);
      if (state.stopped) return;
      console.warn(`[control] job LISTEN lost (${err && err.message}); retrying`);
      state.timer = setTimeout(connect, state.backoff);
      state.timer.unref();
      state.backoff = Math.min(state.backoff * 2, 10000);
    };
    const connect = async () => {
      state.timer = null;
      if (state.stopped) return;
      let client;
      try {
        client = await this.pool.connect();
      } catch (err) {
        retry(err);
        return;
      }
      let failed = false;
      const onNote = (msg) => {
        if (msg.channel !== JOB_CHANNEL) return;
        let parsed = null;
        try { parsed = JSON.parse(msg.payload); } catch { parsed = null; /* malformed: dropped below */ }
        const e = jobEvent(parsed);
        if (e && this.jobBus) deliverJobEvent(this.jobBus, e);
      };
      const detach = () => {
        client.removeListener('notification', onNote);
        client.removeListener('error', fail);
        client.removeListener('end', onEnd);
      };
      function fail(err) {
        if (failed) return;
        failed = true;
        detach();
        if (state.client === client) {
          state.client = null;
          state.detach = null;
        }
        client.release(err instanceof Error ? err : new Error('listen client failed'));
        retry(err);
      }
      function onEnd() { fail(new Error('listen client ended')); }
      client.on('notification', onNote);
      client.on('error', fail);
      client.on('end', onEnd);
      try {
        // SECURITY-RULES rule 7: an identifier cannot be bound; JOB_CHANNEL is
        // a constant.
        await client.query(`LISTEN ${JOB_CHANNEL}`);
      } catch (err) {
        fail(err);
        return;
      }
      if (state.stopped) {
        failed = true;
        detach();
        client.release(true);
        return;
      }
      state.client = client;
      state.detach = detach;
      state.backoff = 250;
      state.settle(true);
    };
    connect();
    return state.ready;
  }

  async closeJobEvents() {
    const state = this.jobListen;
    this.jobListen = null;
    if (this.jobBus) this.jobBus.removeAllListeners('event');
    if (!state) return;
    state.stopped = true;
    state.settle(false);
    if (state.timer) clearTimeout(state.timer);
    const { client, detach } = state;
    state.client = null;
    if (!client) return;
    detach();
    // Destroyed, not returned to the pool: it is still LISTENing.
    client.release(true);
  }

  // --- desired state (see the Threats note above convergeJobInput) --------
  // Every write runs in one transaction with its audit row, which is
  // written last (the chain lock is the last lock taken).

  async createState(input) {
    const s = stateInput(input);
    try {
      return await this.inTx(async (client) => {
        const t = await client.query('SELECT 1 FROM cp_tenants WHERE tenant_id = $1', [s.tenant_id]);
        if (t.rowCount === 0) throw http(404, 'not_found');
        const ins = await client.query(
          `INSERT INTO cp_states (state_id, tenant_id, name, description, created_by)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING state_id, tenant_id, name, description, created_by, created_at, archived_at`,
          [newId('st'), s.tenant_id, s.name, s.description, s.created_by]
        );
        const row = ins.rows[0];
        await auditInsert(client, stateAuditEntry(row.tenant_id, null, row.created_by, 'state_create', { state_id: row.state_id, name: row.name }));
        return publicState(row);
      });
    } catch (err) {
      if (err.code === '23505') throw http(409, 'state_exists');
      throw err;
    }
  }

  async getState(tenantIds, stateId) {
    if (!tenantIds || tenantIds.length === 0 || typeof stateId !== 'string') return null;
    const res = await this.pool.query(
      `SELECT state_id, tenant_id, name, description, created_by, created_at, archived_at
       FROM cp_states WHERE state_id = $1 AND tenant_id = ANY($2::text[])`,
      [stateId, tenantIds]
    );
    return publicState(res.rows[0] || null);
  }

  async listStates(tenantIds) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT state_id, tenant_id, name, description, created_by, created_at, archived_at
       FROM cp_states WHERE tenant_id = ANY($1::text[]) ORDER BY name, state_id`,
      [tenantIds]
    );
    return res.rows.map(publicState);
  }

  // The state row is locked, so two publishes get consecutive numbers.
  async publishVersion(input) {
    const v = versionInput(input);
    return this.inTx(async (client) => {
      const st = await client.query(
        'SELECT 1 FROM cp_states WHERE state_id = $1 AND tenant_id = $2 AND archived_at IS NULL FOR UPDATE',
        [v.state_id, v.tenant_id]
      );
      if (st.rowCount === 0) throw http(404, 'not_found');
      const ins = await client.query(
        `INSERT INTO cp_state_versions (version_id, state_id, tenant_id, version, files, files_sha256, entitlements,
           entitlements_sha256, published_by, notes)
         SELECT $1, $2, $3, COALESCE(max(version), 0) + 1, $4::jsonb, $5, $6::jsonb, $7, $8, $9
         FROM cp_state_versions WHERE state_id = $2
         RETURNING version_id, state_id, tenant_id, version, files_sha256, entitlements, entitlements_sha256,
           published_by, notes, published_at`,
        [newId('stv'), v.state_id, v.tenant_id, JSON.stringify(v.files), v.files_sha256, JSON.stringify(v.entitlements),
          v.entitlements_sha256, v.published_by, v.notes]
      );
      const row = ins.rows[0];
      await auditInsert(client, stateAuditEntry(v.tenant_id, null, v.published_by, 'state_publish', {
        state_id: v.state_id, version_id: row.version_id, version: row.version,
        files_sha256: v.files_sha256, entitlements_sha256: v.entitlements_sha256
      }));
      return publicVersion(row);
    });
  }

  async getVersion(tenantIds, versionId, { withFiles = false } = {}) {
    if (!tenantIds || tenantIds.length === 0 || typeof versionId !== 'string') return null;
    const res = await this.pool.query(
      `SELECT version_id, state_id, tenant_id, version, files, files_sha256, entitlements, entitlements_sha256,
         published_by, notes, published_at
       FROM cp_state_versions WHERE version_id = $1 AND tenant_id = ANY($2::text[])`,
      [versionId, tenantIds]
    );
    return res.rows[0] ? publicVersion(res.rows[0], { withFiles }) : null;
  }

  async listVersions(tenantIds, stateId) {
    if (!tenantIds || tenantIds.length === 0 || typeof stateId !== 'string') return [];
    const res = await this.pool.query(
      `SELECT version_id, state_id, tenant_id, version, files_sha256, entitlements, entitlements_sha256,
         published_by, notes, published_at
       FROM cp_state_versions WHERE state_id = $1 AND tenant_id = ANY($2::text[]) ORDER BY version DESC`,
      [stateId, tenantIds]
    );
    return res.rows.map((r) => publicVersion(r));
  }

  async assignmentRefsInTx(client, a) {
    const st = await client.query(
      'SELECT 1 FROM cp_states WHERE state_id = $1 AND tenant_id = $2 AND archived_at IS NULL',
      [a.state_id, a.tenant_id]
    );
    if (st.rowCount === 0) throw http(404, 'not_found');
    const v = await client.query(
      'SELECT 1 FROM cp_state_versions WHERE version_id = $1 AND state_id = $2 AND tenant_id = $3',
      [a.version_id, a.state_id, a.tenant_id]
    );
    if (v.rowCount === 0) throw http(404, 'version_not_found');
    if (a.target_kind === 'host') {
      const h = await client.query(
        'SELECT 1 FROM cp_hosts WHERE host_id = $1 AND tenant_id = $2 AND retired_at IS NULL',
        [a.target_value, a.tenant_id]
      );
      if (h.rowCount === 0) throw http(404, 'host_not_found');
    }
  }

  async createAssignment(input) {
    const a = assignmentInput(input);
    try {
      return await this.inTx(async (client) => {
        await client.query("SELECT pg_advisory_xact_lock(hashtext('state:t:' || $1))", [a.tenant_id]);
        await this.assignmentRefsInTx(client, a);
        const ins = await client.query(
          `INSERT INTO cp_state_assignments (assignment_id, tenant_id, state_id, version_id, target_kind, target_value, vars,
             check_interval_s, drift_threshold, auto_remediate, require_approval, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12)
           RETURNING ${cols(ASSIGNMENT_COLS)}`,
          [newId('sta'), a.tenant_id, a.state_id, a.version_id, a.target_kind, a.target_value, JSON.stringify(a.vars),
            a.check_interval_s, a.drift_threshold, a.auto_remediate, a.require_approval, a.created_by]
        );
        const row = ins.rows[0];
        await this.syncHostStatesInTx(client, a.tenant_id, null);
        await auditInsert(client, stateAuditEntry(a.tenant_id, a.target_kind === 'host' ? a.target_value : null, a.created_by,
          'state_assign', assignmentAuditPayload(row, 'create')));
        return publicAssignment(row);
      });
    } catch (err) {
      if (err.code === '23505') throw http(409, 'assignment_exists');
      if (err.code === '23514') throw http(400, 'auto_remediate_host_only');
      throw err;
    }
  }

  async updateAssignment({ tenantId, assignmentId, patch, actor }) {
    if (!nonEmpty(actor) || typeof assignmentId !== 'string' || typeof tenantId !== 'string') throw http(400, 'bad_assignment');
    try {
      return await this.inTx(async (client) => {
        await client.query("SELECT pg_advisory_xact_lock(hashtext('state:t:' || $1))", [tenantId]);
        const cur = await client.query(
          `SELECT ${cols(ASSIGNMENT_COLS)} FROM cp_state_assignments WHERE assignment_id = $1 AND tenant_id = $2 FOR UPDATE`,
          [assignmentId, tenantId]
        );
        if (cur.rowCount === 0) throw http(404, 'not_found');
        const before = cur.rows[0];
        const next = assignmentPatch(publicAssignment(before), patch);
        await this.assignmentRefsInTx(client, next);
        const upd = await client.query(
          `UPDATE cp_state_assignments SET version_id = $3, vars = $4::jsonb, check_interval_s = $5, drift_threshold = $6,
             auto_remediate = $7, require_approval = $8, updated_at = now()
           WHERE assignment_id = $1 AND tenant_id = $2
           RETURNING ${cols(ASSIGNMENT_COLS)}`,
          [assignmentId, tenantId, next.version_id, JSON.stringify(next.vars), next.check_interval_s, next.drift_threshold,
            next.auto_remediate, next.require_approval]
        );
        const row = upd.rows[0];
        await this.syncHostStatesInTx(client, tenantId, null);
        if (row.check_interval_s !== before.check_interval_s) {
          const rows = await client.query(
            'SELECT host_id, state_id FROM cp_host_state WHERE assignment_id = $1 AND tenant_id = $2 ORDER BY host_id, state_id FOR UPDATE',
            [assignmentId, tenantId]
          );
          const offs = rows.rows.map((r) => firstCheckOffsetS(r.host_id, r.state_id, row.check_interval_s));
          await client.query(
            `UPDATE cp_host_state hs SET next_check_at = CASE WHEN u.o IS NULL THEN NULL
               ELSE now() + make_interval(secs => u.o::double precision) END
             FROM unnest($1::text[], $2::text[], $3::int[]) AS u(h, s, o)
             WHERE hs.host_id = u.h AND hs.state_id = u.s`,
            [rows.rows.map((r) => r.host_id), rows.rows.map((r) => r.state_id), offs]
          );
        }
        await auditInsert(client, stateAuditEntry(tenantId, row.target_kind === 'host' ? row.target_value : null, actor,
          'state_assign', assignmentAuditPayload(row, 'update')));
        return publicAssignment(row);
      });
    } catch (err) {
      if (err.code === '23514') throw http(400, 'auto_remediate_host_only');
      throw err;
    }
  }

  async deleteAssignment({ tenantId, assignmentId, actor }) {
    if (!nonEmpty(actor) || typeof assignmentId !== 'string' || typeof tenantId !== 'string') throw http(400, 'bad_assignment');
    return this.inTx(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtext('state:t:' || $1))", [tenantId]);
      const del = await client.query(
        `DELETE FROM cp_state_assignments WHERE assignment_id = $1 AND tenant_id = $2 RETURNING ${cols(ASSIGNMENT_COLS)}`,
        [assignmentId, tenantId]
      );
      if (del.rowCount === 0) throw http(404, 'not_found');
      const row = del.rows[0];
      await this.syncHostStatesInTx(client, tenantId, null);
      await auditInsert(client, stateAuditEntry(tenantId, row.target_kind === 'host' ? row.target_value : null, actor,
        'state_unassign', assignmentAuditPayload(row, 'delete')));
      return true;
    });
  }

  async getAssignment(tenantIds, assignmentId) {
    if (!tenantIds || tenantIds.length === 0 || typeof assignmentId !== 'string') return null;
    const res = await this.pool.query(
      `SELECT ${cols(ASSIGNMENT_COLS)} FROM cp_state_assignments WHERE assignment_id = $1 AND tenant_id = ANY($2::text[])`,
      [assignmentId, tenantIds]
    );
    return publicAssignment(res.rows[0] || null);
  }

  async listAssignments(tenantIds, { stateId = null } = {}) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT ${cols(ASSIGNMENT_COLS)} FROM cp_state_assignments
       WHERE tenant_id = ANY($1::text[]) AND ($2::text IS NULL OR state_id = $2)
       ORDER BY created_at, assignment_id`,
      [tenantIds, stateId]
    );
    return res.rows.map(publicAssignment);
  }

  // Replaces the host's tags and re-syncs its host states, with the
  // host_tags audit row, in one transaction.
  async setHostTags({ tenantId, hostId, tags, actor }) {
    const next = tagsInput(tags);
    if (!nonEmpty(actor)) throw http(400, 'bad_tags');
    await this.inTx(async (client) => {
      const cur = await client.query(
        'SELECT tags FROM cp_hosts WHERE host_id = $1 AND tenant_id = $2 AND retired_at IS NULL FOR UPDATE',
        [hostId, tenantId]
      );
      if (cur.rowCount === 0) throw http(404, 'not_found');
      await client.query('UPDATE cp_hosts SET tags = $2::text[] WHERE host_id = $1', [hostId, next]);
      await this.syncHostStatesInTx(client, tenantId, hostId);
      await auditInsert(client, stateAuditEntry(tenantId, hostId, actor, 'host_tags', { tags: next, previous: cur.rows[0].tags || [] }));
    });
    return this.getHost([tenantId], hostId);
  }

  async syncHostStates(tenantId, { hostId = null } = {}) {
    return this.inTx((client) => this.syncHostStatesInTx(client, tenantId, hostId));
  }

  // The effective assignment per (host, state), applied inside the
  // caller's transaction (statestore.effectiveAssignments/hostStateDiff).
  // With hostId, that host only, in its current tenant: rows under another
  // tenant (a moved host) and every row of a retired or missing host are
  // deleted. Deleted rows have their drift alerts resolved. A per-tenant
  // advisory lock serializes syncs of one tenant; the host-state rows are
  // locked in key order before they change.
  async syncHostStatesInTx(client, tenantId, hostId) {
    let tenant = tenantId;
    if (hostId) {
      const h = await client.query('SELECT tenant_id FROM cp_hosts WHERE host_id = $1', [hostId]);
      if (h.rows[0]) tenant = h.rows[0].tenant_id;
    }
    await client.query("SELECT pg_advisory_xact_lock(hashtext('state:t:' || $1))", [tenant]);
    const hosts = hostId
      ? (await client.query('SELECT host_id, tags FROM cp_hosts WHERE host_id = $1 AND tenant_id = $2 AND retired_at IS NULL', [hostId, tenant])).rows
      : (await client.query('SELECT host_id, tags FROM cp_hosts WHERE tenant_id = $1 AND retired_at IS NULL', [tenant])).rows;
    const assigns = (await client.query(
      `SELECT a.assignment_id, a.state_id, a.version_id, a.target_kind, a.target_value, a.check_interval_s
       FROM cp_state_assignments a JOIN cp_states s ON s.state_id = a.state_id AND s.tenant_id = a.tenant_id
       WHERE a.tenant_id = $1 AND s.archived_at IS NULL`,
      [tenant]
    )).rows;
    const existing = (await client.query(
      hostId
        ? 'SELECT host_id, state_id, tenant_id, assignment_id, version_id, status FROM cp_host_state WHERE host_id = $1 ORDER BY host_id, state_id FOR UPDATE'
        : 'SELECT host_id, state_id, tenant_id, assignment_id, version_id, status FROM cp_host_state WHERE tenant_id = $1 ORDER BY host_id, state_id FOR UPDATE',
      [hostId || tenant]
    )).rows;
    const d = hostStateDiff(existing, effectiveAssignments(hosts, assigns), tenant);
    let resolved = [];
    if (d.deletes.length > 0) {
      await client.query(
        `DELETE FROM cp_host_state WHERE (host_id, state_id) IN (SELECT * FROM unnest($1::text[], $2::text[]))`,
        [d.deletes.map((r) => r.host_id), d.deletes.map((r) => r.state_id)]
      );
      const res = await client.query(
        `UPDATE cp_alert_events SET status = 'resolved'
         WHERE status IN ('open', 'ack')
           AND (tenant_id, host_id, rule_name) IN (SELECT * FROM unnest($1::text[], $2::text[], $3::text[]))
         RETURNING id`,
        [d.deletes.map((r) => r.tenant_id), d.deletes.map((r) => r.host_id), d.deletes.map((r) => driftRule(r.state_id))]
      );
      resolved = res.rows.map((r) => r.id);
    }
    if (d.updates.length > 0) {
      const u = d.updates;
      await client.query(
        `UPDATE cp_host_state hs SET assignment_id = u.a, version_id = u.v, status = u.st, consecutive_drift = 0,
           check_claimed_at = NULL, check_job_id = NULL, last_apply_run_id = NULL,
           next_check_at = CASE WHEN u.o IS NULL THEN NULL ELSE now() + make_interval(secs => u.o::double precision) END
         FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::int[]) AS u(h, s, a, v, st, o)
         WHERE hs.host_id = u.h AND hs.state_id = u.s`,
        [u.map((x) => x.host_id), u.map((x) => x.state_id), u.map((x) => x.assignment_id), u.map((x) => x.version_id),
          u.map((x) => x.status), u.map((x) => x.next_offset_s)]
      );
    }
    if (d.inserts.length > 0) {
      const i = d.inserts;
      await client.query(
        `INSERT INTO cp_host_state (host_id, state_id, tenant_id, assignment_id, version_id, status, next_check_at)
         SELECT u.h, u.s, u.t, u.a, u.v, u.st,
           CASE WHEN u.o IS NULL THEN NULL ELSE now() + make_interval(secs => u.o::double precision) END
         FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::int[]) AS u(h, s, t, a, v, st, o)
         ON CONFLICT (host_id, state_id) DO NOTHING`,
        [i.map((x) => x.host_id), i.map((x) => x.state_id), i.map((x) => x.tenant_id), i.map((x) => x.assignment_id),
          i.map((x) => x.version_id), i.map((x) => x.status), i.map((x) => x.next_offset_s)]
      );
    }
    return { inserted: d.inserts.length, updated: d.updates.length, deleted: d.deletes.length, resolved };
  }

  async getHostState(tenantIds, hostId, stateId) {
    if (!tenantIds || tenantIds.length === 0 || typeof hostId !== 'string' || typeof stateId !== 'string') return null;
    const res = await this.pool.query(
      `SELECT ${cols(HOST_STATE_COLS)} FROM cp_host_state WHERE host_id = $1 AND state_id = $2 AND tenant_id = ANY($3::text[])`,
      [hostId, stateId, tenantIds]
    );
    return publicHostState(res.rows[0] || null);
  }

  async listHostStates(tenantIds, opts = {}) {
    const { hostId, stateId, status } = hostStateQuery(opts);
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT ${cols(HOST_STATE_COLS)} FROM cp_host_state
       WHERE tenant_id = ANY($1::text[]) AND ($2::text IS NULL OR host_id = $2)
         AND ($3::text IS NULL OR state_id = $3) AND ($4::text IS NULL OR status = $4)
       ORDER BY host_id, state_id LIMIT 5000`,
      [tenantIds, hostId, stateId, status]
    );
    return res.rows.map(publicHostState);
  }

  // §8.2: due rows of live, fresh, converge-capable hosts, ranked per tenant
  // without locks, the per-tenant cap (counting every replica's unexpired
  // claims) applied before the replica budget, then the chosen rows locked
  // by key with SKIP LOCKED and the claim predicate re-checked under the
  // lock. The drift:claim lock serializes claim transactions, so the cap is
  // exact across replicas.
  async claimDueChecks(opts) {
    const { replicaBudget, perTenantCap, claimExpiryS, presenceFreshS } = claimInput(opts);
    return this.inTx(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtext('drift:claim'))");
      const res = await client.query(
        `WITH inflight AS (
           SELECT tenant_id, count(*) AS n FROM cp_host_state
           WHERE check_claimed_at > now() - make_interval(secs => $3)
           GROUP BY tenant_id),
         ranked AS (
           SELECT hs.host_id, hs.state_id, hs.tenant_id, hs.next_check_at,
                  row_number() OVER (PARTITION BY hs.tenant_id ORDER BY hs.next_check_at, hs.host_id, hs.state_id) AS rk
           FROM cp_host_state hs
           JOIN cp_hosts h ON h.host_id = hs.host_id AND h.tenant_id = hs.tenant_id AND h.retired_at IS NULL
            AND h.agent_seen_at > now() - make_interval(secs => $4)
            AND 'converge' = ANY(h.agent_caps)
           WHERE hs.next_check_at <= now() AND hs.status <> 'conflict' AND hs.assignment_id IS NOT NULL
             AND (hs.check_claimed_at IS NULL OR hs.check_claimed_at <= now() - make_interval(secs => $3))),
         pick AS (
           SELECT r.host_id, r.state_id FROM ranked r LEFT JOIN inflight i USING (tenant_id)
           WHERE r.rk + coalesce(i.n, 0) <= $2
           ORDER BY r.next_check_at, r.host_id, r.state_id LIMIT $1),
         locked AS (
           SELECT hs.host_id, hs.state_id FROM cp_host_state hs JOIN pick p USING (host_id, state_id)
           WHERE (hs.check_claimed_at IS NULL OR hs.check_claimed_at <= now() - make_interval(secs => $3))
             AND hs.next_check_at <= now()
           FOR UPDATE OF hs SKIP LOCKED)
         UPDATE cp_host_state hs SET check_claimed_at = now(),
           next_check_at = now() + make_interval(secs => a.check_interval_s * (0.9 + random() * 0.2))
         FROM locked l, cp_state_assignments a
         WHERE hs.host_id = l.host_id AND hs.state_id = l.state_id AND a.assignment_id = hs.assignment_id
         RETURNING ${cols(HOST_STATE_COLS, 'hs.')}`,
        [replicaBudget, perTenantCap, claimExpiryS, presenceFreshS]
      );
      return res.rows.map(publicHostState);
    });
  }

  // A claim that got no job (429 too_many_jobs): released, retried after
  // retryInS. Only while no job owns the row.
  async releaseCheckClaim(hostId, stateId, { retryInS = 60 } = {}) {
    if (!Number.isInteger(retryInS) || retryInS < 0 || retryInS > 86400) throw http(500, 'bad_claim');
    if (typeof hostId !== 'string' || typeof stateId !== 'string') return false;
    const res = await this.pool.query(
      `UPDATE cp_host_state SET check_claimed_at = NULL, next_check_at = now() + make_interval(secs => $3)
       WHERE host_id = $1 AND state_id = $2 AND check_claimed_at IS NOT NULL AND check_job_id IS NULL`,
      [hostId, stateId, retryInS]
    );
    return res.rowCount > 0;
  }

  // Rows not checked for 3 intervals become stale (the next report
  // replaces it with the real status).
  async markStaleHostStates() {
    const res = await this.pool.query(
      `UPDATE cp_host_state hs SET status = 'stale'
       FROM cp_state_assignments a
       WHERE a.assignment_id = hs.assignment_id AND a.check_interval_s > 0
         AND hs.status NOT IN ('stale', 'conflict')
         AND hs.last_check_at < now() - make_interval(secs => a.check_interval_s * 3)`
    );
    return res.rowCount;
  }

  async getConvergeRun(tenantIds, runId, { withReport = false, withBundle = false } = {}) {
    if (!tenantIds || tenantIds.length === 0 || typeof runId !== 'string') return null;
    const res = await this.pool.query(
      `SELECT ${cols(RUN_COLS)}, report, bundle_json FROM cp_converge_runs WHERE run_id = $1 AND tenant_id = ANY($2::text[])`,
      [runId, tenantIds]
    );
    return res.rows[0] ? publicRun(res.rows[0], { withReport, withBundle }) : null;
  }

  async listConvergeRuns(tenantIds, opts = {}) {
    const { hostId, stateId, kind, limit } = runListQuery(opts);
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT ${cols(RUN_COLS)} FROM cp_converge_runs
       WHERE tenant_id = ANY($1::text[]) AND ($2::text IS NULL OR host_id = $2)
         AND ($3::text IS NULL OR state_id = $3) AND ($4::text IS NULL OR kind = $4)
       ORDER BY created_at DESC, run_id DESC LIMIT $5`,
      [tenantIds, hostId, stateId, kind, limit]
    );
    return res.rows.map((r) => publicRun(r));
  }

  // Approval by a principal other than the plan's actor (the route checks
  // state:apply), with its audit row. The approval does not extend the
  // plan's age. Null when the run is not a plan in tenantIds.
  async approvePlan({ tenantIds, runId, actor }) {
    if (!nonEmpty(actor)) throw http(400, 'bad_approval');
    if (!tenantIds || tenantIds.length === 0 || typeof runId !== 'string') return null;
    return this.inTx(async (client) => {
      const cur = await client.query(
        `SELECT ${cols(RUN_COLS, 'r.')}, j.status AS job_status,
           extract(epoch FROM now() - r.created_at)::float8 AS age_s
         FROM cp_converge_runs r LEFT JOIN cp_sysscript_jobs j ON j.job_id = r.run_id
         WHERE r.run_id = $1 AND r.tenant_id = ANY($2::text[]) FOR UPDATE OF r`,
        [runId, tenantIds]
      );
      const run = cur.rows[0];
      if (!run || run.kind !== 'plan') return null;
      if (run.job_status !== 'succeeded' || run.report_sha256 == null || run.plan_sha256 == null) throw http(409, 'plan_required');
      if (run.plan_truncated) throw http(409, 'plan_truncated');
      if (run.consumed_by_run_id) throw http(409, 'plan_consumed');
      if (run.age_s > planMaxAgeS(this.env)) throw http(409, 'plan_expired');
      if (run.actor === actor) throw http(409, 'self_approval');
      if (run.approved_by) throw http(409, 'plan_approved');
      const upd = await client.query(
        `UPDATE cp_converge_runs SET approved_by = $2, approved_at = now() WHERE run_id = $1 RETURNING ${cols(RUN_COLS)}`,
        [runId, actor]
      );
      await auditInsert(client, stateAuditEntry(run.tenant_id, run.host_id, actor, 'state_approve', {
        run_id: run.run_id, state_id: run.state_id, version_id: run.version_id, plan_sha256: run.plan_sha256
      }));
      return publicRun(upd.rows[0]);
    });
  }

  // createJob's converge part, inside its transaction after the caps: the
  // plan run (apply) and then the host-state row are locked and checked
  // (statestore rules in convergeCreateCheck). Returns the run's effective
  // assignment and version.
  async convergeCheckInTx(client, r, c) {
    let plan = null;
    if (c.kind === 'apply') {
      const p = await client.query(
        `SELECT ${cols(RUN_COLS, 'r.')}, r.bundle_json, j.status AS job_status,
           extract(epoch FROM now() - r.created_at)::float8 AS age_s
         FROM cp_converge_runs r LEFT JOIN cp_sysscript_jobs j ON j.job_id = r.run_id
         WHERE r.run_id = $1 AND r.tenant_id = $2 FOR UPDATE OF r`,
        [c.plan_run_id, r.tenant_id]
      );
      plan = p.rows[0] || null;
    }
    const hsRes = await client.query(
      `SELECT ${cols(HOST_STATE_COLS)} FROM cp_host_state WHERE host_id = $1 AND state_id = $2 AND tenant_id = $3 FOR UPDATE`,
      [r.host_id, c.state_id, r.tenant_id]
    );
    const hs = hsRes.rows[0] || null;
    let assignment = null;
    let version = null;
    if (hs && hs.assignment_id) {
      assignment = (await client.query(
        'SELECT assignment_id, require_approval FROM cp_state_assignments WHERE assignment_id = $1 AND tenant_id = $2',
        [hs.assignment_id, r.tenant_id]
      )).rows[0] || null;
      version = (await client.query(
        'SELECT version_id, entitlements_sha256 FROM cp_state_versions WHERE version_id = $1 AND tenant_id = $2',
        [hs.version_id, r.tenant_id]
      )).rows[0] || null;
    }
    return convergeCreateCheck(r, c, {
      hs, version, assignment, plan,
      planJobStatus: plan ? plan.job_status : null,
      planAgeS: plan ? plan.age_s : 0,
      maxAgeS: planMaxAgeS(this.env)
    });
  }

  async convergeCreateInTx(client, r, c, eff) {
    await client.query(
      `INSERT INTO cp_converge_runs (run_id, tenant_id, host_id, state_id, assignment_id, version_id, kind, actor,
         plan_run_id, parent_job_id, bundle_json)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [r.job_id, r.tenant_id, r.host_id, c.state_id, eff.assignment_id, eff.version_id, c.kind, r.actor,
        c.plan_run_id, c.parent_job_id, c.bundle_json]
    );
    if (c.kind === 'apply') {
      await client.query(
        'UPDATE cp_host_state SET last_apply_run_id = $3 WHERE host_id = $1 AND state_id = $2',
        [r.host_id, c.state_id, r.job_id]
      );
      const used = await client.query(
        `UPDATE cp_converge_runs SET consumed_by_run_id = $2, bundle_json = NULL
         WHERE run_id = $1 AND consumed_by_run_id IS NULL`,
        [c.plan_run_id, r.job_id]
      );
      if (used.rowCount !== 1) throw http(409, 'plan_consumed');
    } else {
      await client.query(
        'UPDATE cp_host_state SET check_job_id = $3, check_claimed_at = now() WHERE host_id = $1 AND state_id = $2',
        [r.host_id, c.state_id, r.job_id]
      );
    }
  }

  // The report ingestion (§7.5) of a converge job inside the transaction
  // that ended it (or a re-send): v is a convergeReport result, or null to
  // finalize a run that ended without one. The run is updated once
  // (report_sha256 IS NULL); the host state only while this run still owns
  // it (check_job_id, or last_apply_run_id for apply); the drift alert is
  // opened (ON CONFLICT DO NOTHING) or resolved here; the state_report
  // audit row is written last. Returns the result for webhooks, or null
  // when there is no run or it already has its report.
  async convergeIngestInTx(client, job, v) {
    const runRes = await client.query(
      `SELECT ${cols(RUN_COLS, 'r.')}, a.drift_threshold, a.check_interval_s
       FROM cp_converge_runs r
       LEFT JOIN cp_state_assignments a ON a.assignment_id = r.assignment_id AND a.tenant_id = r.tenant_id
       WHERE r.run_id = $1 AND r.tenant_id = $2 AND r.host_id = $3 FOR UPDATE OF r`,
      [job.job_id, job.tenant_id, job.host_id]
    );
    const run = runRes.rows[0];
    if (!run || (v && run.report_sha256 != null)) return null;
    // SECURITY-RULES rule 7: the guard column is one of two constants chosen
    // by the run kind; every value is bound.
    const guardCol = run.kind === 'apply' ? 'last_apply_run_id' : 'check_job_id';
    const hsRes = await client.query(
      `SELECT ${cols(HOST_STATE_COLS)} FROM cp_host_state
       WHERE host_id = $1 AND state_id = $2 AND tenant_id = $3 AND ${guardCol} = $4 FOR UPDATE`,
      [run.host_id, run.state_id, run.tenant_id, run.run_id]
    );
    const hs = hsRes.rows[0] || null;
    const rep = v ? v.report : null;
    if (v) {
      let body = run.kind !== 'check' || !hs || hs.last_report_sha256 !== v.sha256;
      if (!body) {
        const kept = await client.query(
          `SELECT 1 FROM cp_converge_runs WHERE tenant_id = $1 AND host_id = $2 AND state_id = $3 AND kind = 'check'
             AND report_sha256 = $4 AND report IS NOT NULL LIMIT 1`,
          [run.tenant_id, run.host_id, run.state_id, v.sha256]
        );
        body = kept.rowCount === 0;
      }
      const upd = await client.query(
        `UPDATE cp_converge_runs SET report_sha256 = $2, summary = $3::jsonb, report = $4::jsonb, plan_sha256 = $5,
           plan_truncated = $6, finished_at = COALESCE(finished_at, now())
         WHERE run_id = $1 AND report_sha256 IS NULL`,
        [run.run_id, v.sha256, JSON.stringify(rep.summary), body ? JSON.stringify(rep) : null, rep.plan_sha256, rep.truncated]
      );
      if (upd.rowCount === 0) return null;
    } else {
      await client.query('UPDATE cp_converge_runs SET finished_at = COALESCE(finished_at, now()) WHERE run_id = $1', [run.run_id]);
    }
    const result = { run_id: run.run_id, kind: run.kind, host_id: run.host_id, state_id: run.state_id,
      version_id: run.version_id, host_state_updated: false, prev_status: null, status: null, alerts: [] };
    if (hs) {
      const keys = rep ? Object.keys(v.facts) : [];
      let clash = false;
      if (keys.length > 0) {
        const other = await client.query(
          'SELECT 1 FROM cp_host_state WHERE host_id = $1 AND state_id <> $2 AND facts ?| $3::text[] LIMIT 1',
          [run.host_id, run.state_id, keys]
        );
        clash = other.rowCount > 0;
      }
      const upd = hostStateUpdate(run, job, v, hs, clash);
      // SECURITY-RULES rule 7: the SET column names come from hostStateUpdate,
      // which only ever uses fixed HOST_STATE_COLS names (checked here); the
      // values are bound.
      const values = [run.host_id, run.state_id];
      const sets = [];
      for (const [col, val] of Object.entries(upd.set)) {
        if (!HOST_STATE_COLS.includes(col)) throw http(500, 'bad_host_state_column');
        values.push(col === 'facts' ? JSON.stringify(val) : val);
        sets.push(`${col} = $${values.length}${col === 'facts' ? '::jsonb' : ''}`);
      }
      for (const col of upd.now) {
        if (!HOST_STATE_COLS.includes(col)) throw http(500, 'bad_host_state_column');
        sets.push(`${col} = now()`);
      }
      if (upd.nextCheck) {
        values.push(run.check_interval_s || 0);
        const n = values.length;
        sets.push(`next_check_at = CASE WHEN $${n}::int > 0 THEN now() + make_interval(secs => $${n}::int * (0.9 + random() * 0.2)) ELSE NULL END`);
      }
      const after = await client.query(
        `UPDATE cp_host_state SET ${sets.join(', ')} WHERE host_id = $1 AND state_id = $2 RETURNING status, consecutive_drift`,
        values
      );
      const now = after.rows[0];
      Object.assign(result, { host_state_updated: true, prev_status: hs.status, status: now.status });
      if (rep && now.status === 'drifted' && run.drift_threshold != null && now.consecutive_drift >= run.drift_threshold) {
        const e = driftAlertEntry(run, rep);
        const ins = await client.query(
          `INSERT INTO cp_alert_events (tenant_id, host_id, rule_name, value, severity, message, status)
           VALUES ($1, $2, $3, $4, $5, $6, 'open')
           ON CONFLICT (host_id, rule_name) WHERE status IN ('open', 'ack') AND rule_name LIKE 'drift:%' DO NOTHING
           RETURNING id`,
          [e.tenant_id, e.host_id, e.rule_name, e.value, e.severity, e.message]
        );
        if (ins.rows[0]) result.alerts.push({ type: 'drift', alert_id: ins.rows[0].id, summary: rep.summary });
      } else if (rep && now.status === 'compliant') {
        const res = await client.query(
          `UPDATE cp_alert_events SET status = 'resolved'
           WHERE tenant_id = $1 AND host_id = $2 AND rule_name = $3 AND status IN ('open', 'ack') RETURNING id`,
          [run.tenant_id, run.host_id, driftRule(run.state_id)]
        );
        for (const row of res.rows) result.alerts.push({ type: 'drift_resolved', alert_id: row.id, summary: rep.summary });
      }
    }
    if (rep) {
      const entry = reportAuditEntry(run, job, v.sha256, rep, result.prev_status, result.status);
      if (entry) await auditInsert(client, entry);
    }
    return result;
  }

  async securityInTx(client, event) {
    await client.query(
      `INSERT INTO cp_security_events (tenant_id, kind, actor_fingerprint, detail) VALUES ($1, $2, $3, $4::jsonb)`,
      [event.tenant_id || null, event.kind, event.actor_fingerprint || null, JSON.stringify(event.detail || {})]
    );
  }

  // A result re-sent for a converge job that is already terminal and whose
  // run has no report yet (§7.5): ingested once in one transaction, with
  // the same conditional host-state write. {ingested, reason?, converge?}.
  async ingestConvergeResend(jobId, hostId, report) {
    if (typeof jobId !== 'string' || typeof hostId !== 'string') return { ingested: false, reason: 'unknown_job' };
    return this.inTx(async (client) => {
      const cur = await client.query(
        `SELECT ${jobCols()} FROM cp_sysscript_jobs WHERE job_id = $1 AND host_id = $2 FOR UPDATE`,
        [jobId, hostId]
      );
      const job = cur.rows[0];
      if (!job || !isTerminal(job.status) || !isConvergeSource(job.source)) return { ingested: false, reason: 'unknown_job' };
      const run = (await client.query('SELECT kind, report_sha256 FROM cp_converge_runs WHERE run_id = $1', [jobId])).rows[0];
      if (!run || run.report_sha256 != null) return { ingested: false, reason: 'already_ingested' };
      const v = convergeReport(report, run.kind, job.script_sha256);
      if (!v.ok) {
        await this.securityInTx(client, badReportEvent(job, v.reason));
        return { ingested: false, reason: 'bad_report' };
      }
      const out = await this.convergeIngestInTx(client, job, v);
      if (!out) return { ingested: false, reason: 'already_ingested' };
      return { ingested: true, converge: out };
    });
  }

  async efficiency(tenantIds) {
    if (!tenantIds || tenantIds.length === 0) return efficiencyOf([]);
    const res = await this.pool.query(
      `SELECT h.host_id, h.hostname,
              avg(t.value) FILTER (WHERE t.metric = 'cpu.usage_percent') AS cpu_avg,
              avg(t.value) FILTER (WHERE t.metric = 'memory.used_percent') AS mem_avg
       FROM cp_hosts h
       LEFT JOIN cp_telemetry t ON t.host_id = h.host_id
       WHERE h.tenant_id = ANY($1::text[]) AND h.retired_at IS NULL
       GROUP BY h.host_id, h.hostname`,
      [tenantIds]
    );
    return efficiencyOf(res.rows.map((r) => ({
      host_id: r.host_id,
      hostname: r.hostname,
      cpu_avg: r.cpu_avg == null ? null : Number(r.cpu_avg),
      mem_avg: r.mem_avg == null ? null : Number(r.mem_avg)
    })));
  }
}

function publicSchedule(row) {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    host_id: row.host_id,
    cron: row.cron,
    last_run_minute: row.last_run_minute || null,
    created_at: row.created_at || null
  };
}

function retentionDays(env) {
  const n = Number(env && env.SYSTEMAPI_METRICS_RETENTION_DAYS);
  if (!Number.isInteger(n) || n < 1 || n > 3650) return 30;
  return n;
}

function avg(values) {
  if (!values.length) return null;
  return values.reduce((sum, n) => sum + n, 0) / values.length;
}

function bucketKey(ts, bucket) {
  const d = new Date(ts);
  if (bucket === 'day') return d.toISOString().slice(0, 10);
  if (bucket === 'hour') return d.toISOString().slice(0, 13);
  return d.toISOString().slice(0, 16);
}

async function createRegistry({ pool, env, logger = console }) {
  if (env.NODE_ENV === 'production' && !pool) {
    throw http(503, 'registry_unavailable');
  }
  if (pool) {
    try {
      await pool.query(SCHEMA_SQL);
      for (const sql of PLAYGROUND_SQL) await pool.query(sql);
      logger.log('[control] cp schema ready');
      return new PgRegistry(pool, env);
    } catch (err) {
      if (env.NODE_ENV === 'production') throw err;
      logger.warn(`[control] schema unavailable (${err.message}); using memory registry`);
      return new MemoryRegistry(env);
    }
  }
  logger.warn('[control] no database pool; using memory registry');
  return new MemoryRegistry(env);
}

module.exports = {
  noNul,
  truncateUtf8,
  MemoryRegistry,
  PgRegistry,
  createRegistry,
  fingerprint,
  jobRetentionDays,
  jobOutputRetentionHours
};
