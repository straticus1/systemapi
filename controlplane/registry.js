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
const JOB_SOURCES = new Set(['api', 'execute', 'fleet_execute', 'playbook', 'schedule', 'rule']);
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
  // only its own conn_id. The enroll time is the enrolling instance's clock.
  async setAgentPresence(hostId, { caps, instance, connId, enrolledAt }) {
    const p = agentPresence(caps, instance, connId, enrolledAt);
    const row = this.hosts.get(hostId);
    if (!row || (row.agent_enrolled_at && row.agent_enrolled_at > p.enrolledAt)) return false;
    row.agent_caps = p.caps;
    row.agent_instance = p.instance;
    row.agent_conn_id = p.connId;
    row.agent_enrolled_at = p.enrolledAt;
    return true;
  }

  async clearAgentPresence(hostId, connId) {
    const row = this.hosts.get(hostId);
    if (!row || !row.agent_conn_id || row.agent_conn_id !== connId) return false;
    row.agent_caps = null;
    row.agent_instance = null;
    row.agent_conn_id = null;
    return true;
  }

  // {instance, conn_id, caps} of the host's live agent, or null when none
  // is recorded (or the host is retired).
  async hostAgent(hostId) {
    const row = this.hosts.get(hostId);
    if (!row || row.retired_at || !row.agent_conn_id) return null;
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
    try {
      await this.appendAudit(jobSubmitAuditEntry(stored));
    } catch (err) {
      this.jobs.delete(r.job_id);
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
  async transitionJob(jobId, hostId, fromStatuses, fields, opts = {}) {
    const { from, set } = jobTransition(fromStatuses, fields);
    const guardConn = 'connId' in opts;
    if (guardConn && !nonEmpty(opts.connId)) throw http(500, 'bad_conn_id');
    const row = this.jobs.get(jobId);
    if (!row || row.host_id !== hostId || !from.includes(row.status)) return null;
    if (guardConn && row.conn_id !== opts.connId) return null;
    await this.jobWrite(
      row,
      (r) => applyJobSet(r, set, new Date()),
      (r) => [transitionAuditEntry(r, opts.audit)].filter(Boolean),
      opts.notify ? (r) => transitionNotify(r, opts.notify) : null
    );
    return publicJob(row);
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
        if (never) applyJobSet(r, { status: 'cancelled', error: 'cancelled_before_dispatch' }, now);
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
        (r) => applyJobSet(r, { status: 'failed', error: 'agent_lost_job' }, new Date()),
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
        (r) => applyJobSet(r, { status: 'failed', error }, new Date()),
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
    return count;
  }

  async pruneJobs(days) {
    const n = jobRetentionDays({ SYSTEMAPI_JOB_RETENTION_DAYS: String(days) });
    const cutoff = Date.now() - n * 86400000;
    let count = 0;
    for (const [id, row] of this.jobs) {
      if (isTerminal(row.status) && row.finished_at && row.finished_at.getTime() < cutoff) {
        this.jobs.delete(id);
        count += 1;
      }
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
      `UPDATE cp_hosts SET agent_caps = $2::text[], agent_instance = $3, agent_conn_id = $4, agent_enrolled_at = $5
       WHERE host_id = $1 AND (agent_enrolled_at IS NULL OR agent_enrolled_at <= $5)`,
      [hostId, p.caps, p.instance, p.connId, p.enrolledAt]
    );
    return res.rowCount > 0;
  }

  async clearAgentPresence(hostId, connId) {
    const res = await this.pool.query(
      `UPDATE cp_hosts SET agent_caps = NULL, agent_instance = NULL, agent_conn_id = NULL
       WHERE host_id = $1 AND agent_conn_id = $2`,
      [hostId, String(connId)]
    );
    return res.rowCount > 0;
  }

  async hostAgent(hostId) {
    const res = await this.pool.query(
      `SELECT agent_caps, agent_instance, agent_conn_id FROM cp_hosts
       WHERE host_id = $1 AND retired_at IS NULL AND agent_conn_id IS NOT NULL`,
      [hostId]
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

  // Ends rows already updated in this transaction: end audit and state
  // notify for each.
  async endedInTx(client, rows) {
    const sorted = [...rows].sort((a, b) => (a.job_id < b.job_id ? -1 : 1));
    for (const row of sorted) {
      await auditInsert(client, jobEndAuditEntry(row, 'system'));
      await this.notifyInTx(client, stateEvent(row));
    }
    return sorted.map((row) => publicJob(row));
  }

  // One transaction: the tenant then the host advisory lock (fixed order),
  // the host must be this tenant's and live, count the non-terminal rows,
  // insert, the submit audit row, NOTIFY dispatch.
  async createJob(row, opts = {}) {
    const r = jobInsertRow(row);
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
        const ins = await client.query(
          `INSERT INTO cp_sysscript_jobs (job_id, tenant_id, host_id, actor, source, script_sha256, entitlements_sha256,
             entitlements, status, timeout_s, deadline_at, lease_nonce, dispatch)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, 'submitted', $9, $10, $11, $12::jsonb)
           RETURNING ${jobCols()}`,
          [r.job_id, r.tenant_id, r.host_id, r.actor, r.source, r.script_sha256, r.entitlements_sha256,
            JSON.stringify(r.entitlements), r.timeout_s, r.deadline_at, r.lease_nonce, JSON.stringify(r.dispatch)]
        );
        const stored = ins.rows[0];
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
  async transitionJob(jobId, hostId, fromStatuses, fields, opts = {}) {
    const { from, set } = jobTransition(fromStatuses, fields);
    const guardConn = 'connId' in opts;
    if (guardConn && !nonEmpty(opts.connId)) throw http(500, 'bad_conn_id');
    if (typeof jobId !== 'string' || typeof hostId !== 'string') return null;
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
    return this.inTx(async (client) => {
      const res = await client.query(
        `UPDATE cp_sysscript_jobs SET ${sets.join(', ')}
         WHERE job_id = $1 AND host_id = $2 AND status = ANY($3::text[])${guard}
         RETURNING ${jobCols()}`,
        values
      );
      const row = res.rows[0];
      if (!row) return null;
      const entry = transitionAuditEntry(row, opts.audit);
      if (entry) await auditInsert(client, entry);
      const evt = transitionNotify(row, opts.notify);
      if (evt) await this.notifyInTx(client, evt);
      return publicJob(row);
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

  async expireOutput(hours) {
    const n = jobOutputRetentionHours({ SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS: String(hours) });
    const res = await this.pool.query(
      `UPDATE cp_sysscript_jobs SET output = NULL, output_expired = true
       WHERE output IS NOT NULL AND finished_at < now() - make_interval(hours => $1::int)`,
      [n]
    );
    return res.rowCount;
  }

  async pruneJobs(days) {
    const n = jobRetentionDays({ SYSTEMAPI_JOB_RETENTION_DAYS: String(days) });
    const res = await this.pool.query(
      `DELETE FROM cp_sysscript_jobs
       WHERE NOT (status = ANY($2::text[])) AND finished_at < now() - make_interval(days => $1::int)`,
      [n, JOB_ACTIVE]
    );
    return res.rowCount;
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
  MemoryRegistry,
  PgRegistry,
  createRegistry,
  fingerprint,
  jobRetentionDays,
  jobOutputRetentionHours
};
