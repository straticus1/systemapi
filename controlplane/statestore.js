// Pure helpers of the desired-state store (cp_states, cp_state_versions,
// cp_state_assignments, cp_host_state, cp_converge_runs;
// .omc/plans/convergence-drift.md §5, §6, §7.3, §7.5, §8). No I/O: the
// registry (controlplane/registry.js) calls them inside its transactions.
//
// Threats: an agent report that smuggles content or oversized data into the
// store (convergeReport keeps only typed fields, scalar facts, capped
// strings, drops before/desired/diff of sensitive resources, and refuses a
// report over 512 KiB encoded or one whose bundle hash is not the job's), a
// tag or tenant assignment that applies unattended (assignment rules: tag and
// tenant targets always require approval, auto_remediate only on a host
// target without require_approval), and a late result overwriting a newer run
// (the registry's conditional writes; convergeOutcome is only the status
// arithmetic). Does NOT authorize: scopes and roles are the routes'.
'use strict';

const crypto = require('node:crypto');
const { canonicalJSON } = require('./chain');
const { entitlementsSha256, parseEntitlements } = require('./entitlements');

const SHA256_RE = /^[0-9a-f]{64}$/;
const STATE_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const TAG_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
const FILE_NAME_RE = /^[a-z0-9_][a-z0-9_.-]{0,62}\.(star|tmpl|txt)$/;
const TAGS_MAX = 32;
const VARS_MAX = 8 * 1024;
const BUNDLE_MAX = 64 * 1024;
const FILES_MAX = 64;
const REPORT_MAX = 512 * 1024;
const RESOURCES_MAX = 500;
const PLAN_LINES_MAX = 1000;
const KEY_MAX = 4096;
const DIFF_MAX = 64 * 1024;
const FACT_STRING_MAX = 1024;
const RES_ERROR_MAX = 1024;
const NOTES_MAX = 1024;
const DESCRIPTION_MAX = 1024;
const SUMMARY_KEYS = ['total', 'ok', 'drift', 'changed', 'failed', 'denied', 'skipped'];
const HOST_STATE_STATUSES = new Set(['unknown', 'compliant', 'drifted', 'failed', 'partial', 'conflict', 'stale']);
const TARGET_KINDS = new Set(['host', 'tag', 'tenant']);
const RUN_KINDS = new Set(['check', 'plan', 'apply']);
const CONVERGE_SOURCES = { check: 'converge_check', plan: 'converge_plan', apply: 'converge_apply' };
const RES_STATUS_CHECK = new Set(['ok', 'drift', 'failed', 'denied', 'skipped']);
const RES_STATUS_APPLY = new Set(['ok', 'drift', 'changed', 'failed', 'denied', 'skipped']);
const RES_KEY_RE = /^(file|dir|package|service|sysctl|restart):[^\u0000-\u001f\u007f]{1,4096}$/;
const RES_KIND_RE = /^[a-z]{1,16}$/;
const BACKUP_ID_RE = /^[0-9A-Za-z_.-]{1,64}$/;
// The unattended scheduler (plan §3.1): an apply run by it is an auto-apply.
const AUTO_ACTOR = 'system:drift';

function http(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(16).toString('base64url')}`;
}

function plainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function text(v, max) {
  return typeof v === 'string' && v.length > 0 && v.length <= max && !v.includes('\u0000');
}

function optText(v, max) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string' || v.length > max || v.includes('\u0000')) throw http(400, 'bad_state');
  return v;
}

function envInt(env, name, def, min, max) {
  const n = Number(env && env[name]);
  return Number.isInteger(n) && n >= min && n <= max ? n : def;
}

function planMaxAgeS(env) {
  return envInt(env, 'SYSTEMAPI_PLAN_MAX_AGE_S', 900, 60, 86400);
}

function applyRunRetentionDays(env) {
  return envInt(env, 'SYSTEMAPI_APPLY_RUN_RETENTION_DAYS', 365, 1, 3650);
}

// 32-bit FNV-1a of host_id‖state_id: the first-check offset inside the
// interval, the same on every replica.
function fnv32(textIn) {
  let h = 0x811c9dc5;
  for (const b of Buffer.from(textIn, 'utf8')) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function firstCheckOffsetS(hostId, stateId, intervalS) {
  if (!intervalS) return null;
  return fnv32(`${hostId}\u0000${stateId}`) % intervalS;
}

function stateInput({ tenantId, name, description, actor }) {
  if (!text(tenantId, 256) || !text(actor, 256)) throw http(400, 'bad_state');
  if (typeof name !== 'string' || !STATE_NAME_RE.test(name)) throw http(400, 'bad_state_name');
  return { tenant_id: tenantId, name, description: optText(description, DESCRIPTION_MAX), created_by: actor };
}

// The version's files (name -> source) and entitlements, parsed as the agent
// will, with both hashes. Bundle semantics (main.star, the declaration) are
// checked by the agent and the publish route; this is the storage shape.
function versionInput({ tenantId, stateId, files, entitlements, actor, notes }) {
  if (!text(tenantId, 256) || !text(stateId, 256) || !text(actor, 256)) throw http(400, 'bad_state_version');
  if (!plainObject(files)) throw http(400, 'bad_bundle');
  const names = Object.keys(files);
  if (names.length === 0 || names.length > FILES_MAX || !names.includes('main.star')) throw http(400, 'bad_bundle');
  let size = 0;
  for (const n of names) {
    if (!FILE_NAME_RE.test(n) || typeof files[n] !== 'string' || files[n].includes('\u0000')) throw http(400, 'bad_bundle');
    size += Buffer.byteLength(n, 'utf8') + Buffer.byteLength(files[n], 'utf8');
  }
  if (size > BUNDLE_MAX) throw http(400, 'bundle_too_large');
  const ents = parseEntitlements(entitlements === undefined ? {} : entitlements);
  const filesCopy = JSON.parse(JSON.stringify(files));
  return {
    tenant_id: tenantId,
    state_id: stateId,
    files: filesCopy,
    files_sha256: sha256Hex(canonicalJSON(filesCopy)),
    entitlements: ents,
    entitlements_sha256: entitlementsSha256(ents),
    published_by: actor,
    notes: optText(notes, NOTES_MAX)
  };
}

function varsInput(vars) {
  const v = vars === undefined || vars === null ? {} : vars;
  if (!plainObject(v)) throw http(400, 'bad_vars');
  const copy = JSON.parse(JSON.stringify(v));
  if (Buffer.byteLength(JSON.stringify(copy), 'utf8') > VARS_MAX) throw http(400, 'bad_vars');
  return copy;
}

function intervalInput(v) {
  if (v === undefined) return 3600;
  if (!Number.isInteger(v) || !(v === 0 || (v >= 300 && v <= 86400))) throw http(400, 'bad_check_interval');
  return v;
}

function thresholdInput(v) {
  if (v === undefined) return 1;
  if (!Number.isInteger(v) || v < 1 || v > 10) throw http(400, 'bad_drift_threshold');
  return v;
}

// The §6.2 rules on one (possibly patched) assignment: tag and tenant
// targets always require approval; auto_remediate only on a host target
// without require_approval (400 auto_remediate_host_only). The table CHECKs
// hold the same rules.
function assignmentRules(a) {
  if (a.target_kind !== 'host') a.require_approval = true;
  if (a.auto_remediate && (a.target_kind !== 'host' || a.require_approval)) throw http(400, 'auto_remediate_host_only');
  return a;
}

function assignmentInput({ tenantId, stateId, versionId, targetKind, targetValue, vars, checkIntervalS, driftThreshold, autoRemediate, requireApproval, actor }) {
  if (!text(tenantId, 256) || !text(stateId, 256) || !text(versionId, 256) || !text(actor, 256)) throw http(400, 'bad_assignment');
  if (!TARGET_KINDS.has(targetKind)) throw http(400, 'bad_target');
  if (targetKind === 'tag' && !(typeof targetValue === 'string' && TAG_RE.test(targetValue))) throw http(400, 'bad_target');
  if (targetKind === 'host' && !text(targetValue, 256)) throw http(400, 'bad_target');
  if (targetKind === 'tenant' && targetValue !== undefined && targetValue !== tenantId) throw http(400, 'bad_target');
  if (autoRemediate !== undefined && typeof autoRemediate !== 'boolean') throw http(400, 'bad_assignment');
  if (requireApproval !== undefined && typeof requireApproval !== 'boolean') throw http(400, 'bad_assignment');
  return assignmentRules({
    tenant_id: tenantId,
    state_id: stateId,
    version_id: versionId,
    target_kind: targetKind,
    target_value: targetKind === 'tenant' ? tenantId : targetValue,
    vars: varsInput(vars),
    check_interval_s: intervalInput(checkIntervalS),
    drift_threshold: thresholdInput(driftThreshold),
    auto_remediate: autoRemediate === true,
    require_approval: requireApproval === true,
    created_by: actor
  });
}

// A PATCH: version, vars, interval, threshold and the two flags. The target
// never changes (delete and create instead).
function assignmentPatch(cur, patch) {
  if (!plainObject(patch)) throw http(400, 'bad_assignment');
  const allowed = new Set(['versionId', 'vars', 'checkIntervalS', 'driftThreshold', 'autoRemediate', 'requireApproval']);
  for (const k of Object.keys(patch)) if (!allowed.has(k)) throw http(400, 'bad_assignment');
  const next = { ...cur };
  if (patch.versionId !== undefined) {
    if (!text(patch.versionId, 256)) throw http(400, 'bad_assignment');
    next.version_id = patch.versionId;
  }
  if (patch.vars !== undefined) next.vars = varsInput(patch.vars);
  if (patch.checkIntervalS !== undefined) next.check_interval_s = intervalInput(patch.checkIntervalS);
  if (patch.driftThreshold !== undefined) next.drift_threshold = thresholdInput(patch.driftThreshold);
  for (const [k, col] of [['autoRemediate', 'auto_remediate'], ['requireApproval', 'require_approval']]) {
    if (patch[k] === undefined) continue;
    if (typeof patch[k] !== 'boolean') throw http(400, 'bad_assignment');
    next[col] = patch[k];
  }
  return assignmentRules(next);
}

function tagsInput(tags) {
  if (!Array.isArray(tags) || tags.length > TAGS_MAX) throw http(400, 'bad_tags');
  for (const t of tags) if (typeof t !== 'string' || !TAG_RE.test(t)) throw http(400, 'bad_tags');
  return [...new Set(tags)].sort();
}

// The effective assignment per (host, state), precedence host > tag >
// tenant; two tag assignments of one state matching one host are a
// conflict. hosts: [{host_id, tags}] (live hosts of one tenant);
// assignments: rows of that tenant. Returns Map "<host>\0<state>" ->
// {host_id, state_id, assignment (null on conflict), conflict}.
function effectiveAssignments(hosts, assignments) {
  const out = new Map();
  const rank = { host: 0, tag: 1, tenant: 2 };
  for (const h of hosts) {
    const tags = new Set(h.tags || []);
    const byState = new Map();
    for (const a of assignments) {
      const hit = (a.target_kind === 'host' && a.target_value === h.host_id)
        || (a.target_kind === 'tag' && tags.has(a.target_value))
        || a.target_kind === 'tenant';
      if (!hit) continue;
      const list = byState.get(a.state_id) || [];
      list.push(a);
      byState.set(a.state_id, list);
    }
    for (const [stateId, list] of byState) {
      const best = Math.min(...list.map((a) => rank[a.target_kind]));
      const top = list.filter((a) => rank[a.target_kind] === best);
      const conflict = top.length > 1;
      out.set(`${h.host_id}\u0000${stateId}`, { host_id: h.host_id, state_id: stateId, assignment: conflict ? null : top[0], conflict });
    }
  }
  return out;
}

// The diff syncHostStates applies: rows to insert, update and delete.
// existing: the cp_host_state rows in scope; desired: effectiveAssignments
// over the live hosts of tenantId. A row under another tenant is deleted
// (the host moved). A changed assignment or version resets the row to
// unknown and drops its claim and pending apply, so an in-flight result for
// the old assignment never lands on it.
function hostStateDiff(existing, desired, tenantId) {
  const inserts = [];
  const updates = [];
  const deletes = [];
  const seen = new Set();
  for (const row of existing) {
    const key = `${row.host_id}\u0000${row.state_id}`;
    const want = row.tenant_id === tenantId ? desired.get(key) : undefined;
    if (!want) {
      deletes.push(row);
      continue;
    }
    seen.add(key);
    const a = want.assignment;
    const aId = a ? a.assignment_id : null;
    const vId = a ? a.version_id : null;
    const wasConflict = row.status === 'conflict' && row.assignment_id == null;
    if (row.assignment_id === aId && row.version_id === vId && wasConflict === want.conflict) continue;
    updates.push({
      host_id: row.host_id,
      state_id: row.state_id,
      assignment_id: aId,
      version_id: vId,
      status: want.conflict ? 'conflict' : 'unknown',
      next_offset_s: a ? firstCheckOffsetS(row.host_id, row.state_id, a.check_interval_s) : null
    });
  }
  for (const [key, want] of desired) {
    if (seen.has(key)) continue;
    const a = want.assignment;
    inserts.push({
      host_id: want.host_id,
      state_id: want.state_id,
      tenant_id: tenantId,
      assignment_id: a ? a.assignment_id : null,
      version_id: a ? a.version_id : null,
      status: want.conflict ? 'conflict' : 'unknown',
      next_offset_s: a ? firstCheckOffsetS(want.host_id, want.state_id, a.check_interval_s) : null
    });
  }
  const order = (x, y) => (x.host_id < y.host_id ? -1 : x.host_id > y.host_id ? 1 : (x.state_id < y.state_id ? -1 : x.state_id > y.state_id ? 1 : 0));
  return { inserts: inserts.sort(order), updates: updates.sort(order), deletes: deletes.sort(order) };
}

function driftRule(stateId) {
  return `drift:${stateId}`;
}

function scalarFacts(v) {
  if (v === null || v === undefined) return null;
  if (!plainObject(v)) return undefined;
  const out = {};
  const keys = Object.keys(v);
  if (keys.length > 32) return undefined;
  for (const k of keys) {
    if (!/^[a-z_][a-z0-9_]{0,31}$/.test(k)) return undefined;
    const x = v[k];
    if (x === null || typeof x === 'boolean') out[k] = x;
    else if (typeof x === 'number' && Number.isFinite(x)) out[k] = x;
    else if (typeof x === 'string' && x.length <= FACT_STRING_MAX && !x.includes('\u0000')) out[k] = x;
    else return undefined;
  }
  return out;
}

function count(v) {
  return Number.isInteger(v) && v >= 0 && v <= 1000000 ? v : null;
}

function nulText(v, max) {
  if (v === undefined || v === null) return '';
  if (typeof v !== 'string') return null;
  return v.replace(/\u0000/g, '�').slice(0, max);
}

// Validates and sanitizes an agent report (§7.3) for a run of kind on a
// job whose script_sha256 is the bundle hash. Returns {ok:true, report,
// sha256, facts} or {ok:false, reason}. Sensitive resources keep only
// {matches} of before and nothing of desired or diff.
function convergeReport(input, kind, bundleSha256) {
  const bad = (reason) => ({ ok: false, reason });
  if (!plainObject(input)) return bad('not_object');
  let encoded;
  try { encoded = JSON.stringify(input); } catch { return bad('not_json'); }
  if (Buffer.byteLength(encoded, 'utf8') > REPORT_MAX) return bad('too_large');
  if (input.v !== 1) return bad('version');
  const mode = kind === 'apply' ? 'apply' : 'check';
  if (input.mode !== mode) return bad('mode');
  if (typeof input.bundle_sha256 !== 'string' || input.bundle_sha256 !== bundleSha256) return bad('bundle_sha256');
  const planSha = input.plan_sha256 === undefined || input.plan_sha256 === '' ? null : input.plan_sha256;
  if (planSha !== null && !(typeof planSha === 'string' && SHA256_RE.test(planSha))) return bad('plan_sha256');
  if (input.truncated !== undefined && typeof input.truncated !== 'boolean') return bad('truncated');
  if (!plainObject(input.summary)) return bad('summary');
  const summary = {};
  for (const k of SUMMARY_KEYS) {
    const n = input.summary[k] === undefined ? 0 : count(input.summary[k]);
    if (n === null) return bad('summary');
    summary[k] = n;
  }
  const statuses = kind === 'apply' ? RES_STATUS_APPLY : RES_STATUS_CHECK;
  const planIn = input.plan === undefined || input.plan === null ? [] : input.plan;
  if (!Array.isArray(planIn) || planIn.length > PLAN_LINES_MAX) return bad('plan');
  const plan = [];
  for (const p of planIn) {
    if (!plainObject(p) || typeof p.key !== 'string' || !RES_KEY_RE.test(p.key) || !statuses.has(p.status)) return bad('plan');
    plan.push({ key: p.key, status: p.status });
  }
  const resIn = input.resources === undefined || input.resources === null ? [] : input.resources;
  if (!Array.isArray(resIn) || resIn.length > RESOURCES_MAX) return bad('resources');
  const resources = [];
  const facts = {};
  for (const r of resIn) {
    if (!plainObject(r) || typeof r.key !== 'string' || r.key.length > KEY_MAX || !RES_KEY_RE.test(r.key)) return bad('resources');
    if (r.key.startsWith('restart:') || Object.hasOwn(facts, r.key)) return bad('resources');
    if (typeof r.kind !== 'string' || !RES_KIND_RE.test(r.kind) || !statuses.has(r.status)) return bad('resources');
    if (r.sensitive !== undefined && typeof r.sensitive !== 'boolean') return bad('resources');
    const sensitive = r.sensitive === true;
    const before = scalarFacts(r.before);
    const desired = scalarFacts(r.desired);
    const diff = nulText(r.diff, DIFF_MAX);
    const error = nulText(r.error, RES_ERROR_MAX);
    if (before === undefined || desired === undefined || diff === null || error === null) return bad('resources');
    const backup = r.backup_id === undefined || r.backup_id === null ? null : r.backup_id;
    if (backup !== null && !(typeof backup === 'string' && BACKUP_ID_RE.test(backup))) return bad('resources');
    const out = { key: r.key, kind: r.kind, status: r.status, sensitive, error, backup_id: backup };
    if (sensitive) {
      out.before = before && typeof before.matches === 'boolean' ? { matches: before.matches } : null;
      out.desired = null;
      out.diff = '';
    } else {
      out.before = before;
      out.desired = desired;
      out.diff = diff;
    }
    resources.push(out);
    facts[r.key] = { status: r.status, digest: sensitive || !before ? null : sha256Hex(canonicalJSON(before)) };
  }
  const report = {
    v: 1,
    mode,
    bundle_sha256: input.bundle_sha256,
    plan_sha256: planSha,
    truncated: input.truncated === true,
    summary,
    plan,
    resources
  };
  return { ok: true, report, sha256: sha256Hex(canonicalJSON(report)), facts };
}

// The host-state status after a report (rep, or null when the run ended
// without one) of a run of kind whose job ended jobStatus; prev is the row
// before. Returns {status, consecutive_drift}.
function convergeOutcome(kind, jobStatus, rep, prev) {
  const prevStatus = prev.status;
  const prevDrift = prev.consecutive_drift || 0;
  if (kind === 'apply') {
    if (!rep) return { status: 'partial', consecutive_drift: prevDrift };
    const s = rep.summary;
    if (jobStatus === 'succeeded' && s.failed + s.denied === 0 && !rep.truncated) return { status: 'compliant', consecutive_drift: 0 };
    if (jobStatus === 'cancelled' || jobStatus === 'timed_out' || s.changed > 0) return { status: 'partial', consecutive_drift: prevDrift };
    if (jobStatus === 'succeeded') return { status: 'partial', consecutive_drift: prevDrift };
    return { status: 'failed', consecutive_drift: prevDrift };
  }
  if (!rep) return { status: prevStatus, consecutive_drift: prevDrift };
  const s = rep.summary;
  if (s.failed + s.denied > 0) return { status: 'failed', consecutive_drift: prevDrift };
  if (jobStatus !== 'succeeded') return { status: prevStatus, consecutive_drift: prevDrift };
  if (s.drift > 0) return { status: 'drifted', consecutive_drift: prevDrift + 1 };
  return { status: 'compliant', consecutive_drift: 0 };
}

function isConvergeSource(source) {
  return typeof source === 'string' && source.startsWith('converge_');
}

module.exports = {
  AUTO_ACTOR,
  CONVERGE_SOURCES,
  HOST_STATE_STATUSES,
  RUN_KINDS,
  SHA256_RE,
  TAG_RE,
  applyRunRetentionDays,
  assignmentInput,
  assignmentPatch,
  convergeOutcome,
  convergeReport,
  driftRule,
  effectiveAssignments,
  firstCheckOffsetS,
  fnv32,
  hostStateDiff,
  http,
  isConvergeSource,
  newId,
  planMaxAgeS,
  sha256Hex,
  stateInput,
  tagsInput,
  versionInput
};
