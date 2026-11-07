// Threats: an intent-bound lease (systemapi-lease-v2) minted for an action,
// host, payload or time window other than the one the intent names; an
// intent text whose fields were shifted by an embedded newline, space or
// control byte; and a renew lease that carries a different intent than the
// session it renews. buildIntent refuses (never escapes) any field outside
// .omc/plans/sah-signed-intent-contract.md 1.1; parseIntent accepts only the
// exact canonical text buildIntent produces; the mint helpers refuse a
// payload whose hash differs from the intent and a start after use_by.
// Does NOT decide who approved anything: approvals, consume and the request
// table are phase 2. Nothing calls mintIntentStartLease or
// mintIntentRenewLease yet (phase 1, "nothing sends v2 yet"), so every
// production lease is still v1. Shared vectors with systemapi-agent/intent.go:
// controlplane/testdata/intent-lease-vectors.json.
'use strict';

const crypto = require('node:crypto');
const lease = require('./lease');

const INTENT_PREFIX = 'systemapi-intent-v1';
const INTENT_LINES = 13;
const INTENT_ACTIONS = new Set([
  'breakglass', 'pty_root', 'file_root', 'xfer_root', 'sys_config', 'sys_tweak', 'sys_service',
  'sys_package', 'sysscript_job', 'recovery_sshd', 'policy_grant', 'approver_admin', 'tenant_flag'
]);
// Intent actions that carry a systemapi-lease-v2 (the others carry no lease
// or one R1 defines later).
const LEASE_ACTIONS = new Set([
  'breakglass', 'pty_root', 'file_root', 'xfer_root', 'sys_config', 'sys_tweak', 'sys_service',
  'sys_package', 'sysscript_job'
]);
// Terminal and channel sessions: max_session_deadline is a real deadline
// and the start frame's deadline must equal it.
const SESSION_ACTIONS = new Set(['breakglass', 'pty_root', 'file_root', 'xfer_root']);
const WINDOW_MAX_S = 3600;
const BREAKGLASS_MAX_S = 14400;
// The structural cap for root sessions: PTY_MAX_SECONDS_CAP (fleet.js). The
// tenant's SYSTEMAPI_PTY_MAX_SECONDS is applied by the caller.
const ROOT_SESSION_MAX_S = 7 * 24 * 3600;
const RENEW_PHASE_ACTIONS = new Set(['breakglass', 'pty_root', 'file_root', 'xfer_root']);

const REQUEST_ID_RE = /^apr_[A-Za-z0-9_-]{22}$/;
const TENANT_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const HOST_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const USER_RE = /^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,128}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const DECIMAL_RE = /^(0|[1-9][0-9]{0,15})$/;
const PRINTABLE_RE = /^[\x21-\x7e]+$/;

function refuse(code) {
  const err = new Error(code);
  err.status = 400;
  err.code = code;
  return err;
}

function decimal(n) {
  return Number.isSafeInteger(n) && n >= 0;
}

// checkIntentFields enforces every 1.1 rule on a field object and returns
// the 13 lines, or throws intent_malformed.
function intentLines(f) {
  const bad = () => refuse('intent_malformed');
  if (!f || typeof f !== 'object') throw bad();
  const s = (v) => typeof v === 'string' && PRINTABLE_RE.test(v);
  if (!s(f.request_id) || !REQUEST_ID_RE.test(f.request_id)) throw bad();
  if (!s(f.tenant_id) || !TENANT_RE.test(f.tenant_id)) throw bad();
  if (!s(f.host_id) || !HOST_ID_RE.test(f.host_id)) throw bad();
  if (!s(f.requester) || !f.requester.startsWith('member:') || !USER_RE.test(f.requester.slice(7))) throw bad();
  if (!s(f.action) || !INTENT_ACTIONS.has(f.action)) throw bad();
  if (!s(f.payload_sha256) || !SHA256_HEX_RE.test(f.payload_sha256)) throw bad();
  if (!s(f.reason_sha256) || !SHA256_HEX_RE.test(f.reason_sha256)) throw bad();
  const nb = f.not_before_unix;
  const ub = f.use_by_unix;
  const msd = f.max_session_deadline_unix;
  if (!decimal(nb) || !decimal(ub) || !decimal(msd)) throw bad();
  if (nb > ub || ub - nb > WINDOW_MAX_S) throw bad();
  if (SESSION_ACTIONS.has(f.action)) {
    const cap = f.action === 'breakglass' ? BREAKGLASS_MAX_S : ROOT_SESSION_MAX_S;
    if (msd < ub || msd - nb > cap) throw bad();
  } else if (msd !== 0) {
    throw bad();
  }
  if (!decimal(f.approver_set_version) || f.approver_set_version < 1) throw bad();
  if (!Number.isInteger(f.threshold_k) || f.threshold_k < 1 || f.threshold_k > 9) throw bad();
  return [
    INTENT_PREFIX, f.request_id, f.tenant_id, f.host_id, f.requester, f.action, f.payload_sha256,
    String(nb), String(ub), String(msd), f.reason_sha256, String(f.approver_set_version), String(f.threshold_k)
  ];
}

// buildIntent returns the canonical systemapi-intent-v1 text: 13 LF-ended
// lines. It refuses, never escapes.
function buildIntent(fields) {
  return `${intentLines(fields).join('\n')}\n`;
}

// parseIntent accepts only canonical text (it rebuilds and compares), so two
// different texts can never parse to the same fields.
function parseIntent(text) {
  if (typeof text !== 'string' || text.length > 2048 || !text.endsWith('\n')) throw refuse('intent_malformed');
  const lines = text.slice(0, -1).split('\n');
  if (lines.length !== INTENT_LINES || lines[0] !== INTENT_PREFIX) throw refuse('intent_malformed');
  const num = (v) => {
    if (!DECIMAL_RE.test(v)) throw refuse('intent_malformed');
    const n = Number(v);
    if (!Number.isSafeInteger(n)) throw refuse('intent_malformed');
    return n;
  };
  const fields = {
    request_id: lines[1],
    tenant_id: lines[2],
    host_id: lines[3],
    requester: lines[4],
    action: lines[5],
    payload_sha256: lines[6],
    not_before_unix: num(lines[7]),
    use_by_unix: num(lines[8]),
    max_session_deadline_unix: num(lines[9]),
    reason_sha256: lines[10],
    approver_set_version: num(lines[11]),
    threshold_k: num(lines[12])
  };
  if (buildIntent(fields) !== text) throw refuse('intent_malformed');
  return fields;
}

function intentSha256(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

function signV2(signer, { hostId, action, payloadSha256, intentSha256: intentHash, ttl, now }) {
  if (!signer) {
    const err = new Error('signer_unavailable');
    err.status = 503;
    throw err;
  }
  const seconds = Math.min(Math.max(1, ttl | 0), 300);
  const expiresUnix = Math.floor(now / 1000) + seconds;
  const nonceHex = crypto.randomBytes(16).toString('hex');
  const message = lease.canonicalLeaseV2({ hostId, action, expiresUnix, nonceHex, payloadSha256, intentSha256: intentHash });
  return {
    v: 2,
    host_id: hostId,
    action,
    expires_unix: expiresUnix,
    nonce_hex: nonceHex,
    payload_sha256: payloadSha256,
    intent_sha256: intentHash,
    signature: signer.sign(message)
  };
}

// mintIntentStartLease signs the v2 START lease for an intent (contract
// 4.4). The host comes from the intent; action and payload must be the ones
// the intent hashed, and the CP's clock must be inside [not_before - skew,
// use_by). Consume and approval checks are the caller's (phase 2).
function mintIntentStartLease(signer, { intentText, action, payload, ttl = 60, now = Date.now() } = {}) {
  const intent = parseIntent(intentText);
  if (!LEASE_ACTIONS.has(intent.action) || action !== intent.action) throw refuse('intent_mismatch');
  const payloadSha256 = lease.payloadHash(action, payload);
  if (!lease.hashEqual(payloadSha256, intent.payload_sha256)) throw refuse('intent_mismatch');
  const nowS = Math.floor(now / 1000);
  if (nowS < intent.not_before_unix - 30 || nowS >= intent.use_by_unix) throw refuse('intent_window');
  return signV2(signer, { hostId: intent.host_id, action, payloadSha256, intentSha256: intentSha256(intentText), ttl, now });
}

// mintIntentRenewLease signs a v2 RENEW lease for a live session that was
// started with an intent: the session's stored intent text, its own renew
// payload, no approval lookup and no use_by (contract 4.4). The intent must
// name this host and action, the payload's phase line (line 3) must be
// "renew", so this can never mint a start, and the payload's deadline (line
// 2) must not pass the intent's max_session_deadline_unix (an xfer renew
// moves its deadline forward; it never moves past the approved one).
function mintIntentRenewLease(signer, { hostId, action, payload, intentText, ttl = 60, now = Date.now() } = {}) {
  if (!RENEW_PHASE_ACTIONS.has(action)) throw refuse('bad_action');
  if (typeof hostId !== 'string' || !HOST_ID_RE.test(hostId)) throw refuse('bad_host');
  if (typeof intentText !== 'string' || intentText === '') throw refuse('intent_required');
  const intent = parseIntent(intentText);
  if (intent.host_id !== hostId || intent.action !== action) throw refuse('intent_mismatch');
  const lines = typeof payload === 'string' ? payload.split('\n') : [];
  if (lines[2] !== 'renew') throw refuse('bad_phase');
  if (!DECIMAL_RE.test(lines[1] || '') || Number(lines[1]) > intent.max_session_deadline_unix) throw refuse('intent_deadline');
  return signV2(signer, { hostId, action, payloadSha256: lease.payloadHash(action, payload), intentSha256: intentSha256(intentText), ttl, now });
}

module.exports = {
  INTENT_ACTIONS,
  LEASE_ACTIONS,
  SESSION_ACTIONS,
  BREAKGLASS_MAX_S,
  buildIntent,
  parseIntent,
  intentSha256,
  mintIntentStartLease,
  mintIntentRenewLease
};
