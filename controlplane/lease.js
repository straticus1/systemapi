// Threats: unsigned or swapped command payloads, expired leases, and a lease
// reused against a different host. Verification rejects tampered, expired,
// wrong-host, and wrong-action input. Replay cache is the agent's job (the
// server mints a fresh nonce per issue). Clock skew allowance is 30s. TTL
// cap is 300s. Does NOT stop an agent that ignores the lease.
// Terminal actions (pty, pty_root, breakglass) sign "<action>\n<payload>",
// where the payload is "<session_id>\n<deadline_unix>\n<start|renew>". A
// renewal lease is bound to one session, cannot move its deadline, and cannot
// be replayed as a start.
'use strict';

const crypto = require('node:crypto');
const { randomBytes, timingSafeEqual } = crypto;

const ACTIONS = new Set(['sysscript', 'pty', 'pty_root', 'breakglass']);
const TERMINAL_ACTIONS = new Set(['pty', 'pty_root', 'breakglass']);
const MAX_TTL_S = 300;
const SKEW_S = 30;

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function payloadHash(action, payload) {
  if (TERMINAL_ACTIONS.has(action)) return sha256Hex(Buffer.from(`${action}\n${String(payload)}`, 'utf8'));
  return sha256Hex(Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8'));
}

function canonicalLease({ hostId, action, expiresUnix, nonceHex, payloadSha256 }) {
  return `systemapi-lease-v1\n${hostId}\n${action}\n${expiresUnix}\n${nonceHex}\n${payloadSha256}\n`;
}

function hashEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (!/^[0-9a-f]{64}$/.test(a) || !/^[0-9a-f]{64}$/.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function issueLease(signer, { hostId, action, payload, ttl = 60, now = Date.now() }) {
  if (!signer) {
    const err = new Error('signer_unavailable');
    err.status = 503;
    throw err;
  }
  if (!ACTIONS.has(action)) {
    const err = new Error('bad_action');
    err.status = 400;
    throw err;
  }
  const seconds = Math.min(Math.max(1, ttl | 0), MAX_TTL_S);
  const expiresUnix = Math.floor(now / 1000) + seconds;
  const nonceHex = randomBytes(16).toString('hex');
  const payloadSha256 = payloadHash(action, payload);
  const message = canonicalLease({ hostId, action, expiresUnix, nonceHex, payloadSha256 });
  return {
    v: 1,
    host_id: hostId,
    action,
    expires_unix: expiresUnix,
    nonce_hex: nonceHex,
    payload_sha256: payloadSha256,
    signature: signer.sign(message)
  };
}

function verifyLease(publicKey, lease, payload, nowMs = Date.now()) {
  if (!lease || typeof lease !== 'object') return fail('malformed');
  const { host_id: hostId, action, expires_unix: expiresUnix, nonce_hex: nonceHex, payload_sha256: payloadSha256, signature } = lease;
  if (typeof hostId !== 'string' || !hostId) return fail('bad_host');
  if (!ACTIONS.has(action)) return fail('bad_action');
  if (!Number.isInteger(expiresUnix)) return fail('bad_expiry');
  if (typeof nonceHex !== 'string' || !/^[0-9a-f]{32}$/.test(nonceHex)) return fail('bad_nonce');
  const now = Math.floor(nowMs / 1000);
  if (expiresUnix < now - SKEW_S) return fail('expired');
  if (expiresUnix > now + MAX_TTL_S) return fail('expiry_too_far');
  const expect = payloadHash(action, payload);
  if (!hashEqual(expect, payloadSha256)) return fail('payload_mismatch');
  const message = canonicalLease({ hostId, action, expiresUnix, nonceHex, payloadSha256 });
  let sig;
  try {
    sig = Buffer.from(signature, 'base64');
  } catch {
    return fail('bad_signature');
  }
  const ok = crypto.verify(null, Buffer.from(message, 'utf8'), publicKey, sig);
  if (!ok) return fail('bad_signature');
  return { ok: true, hostId, action, expiresUnix, nonceHex };
}

function fail(error) {
  return { ok: false, error };
}

// phase is 'start' or 'renew', so a renewal lease cannot start a session.
function terminalPayload(sessionId, deadlineUnix, phase) {
  if (phase !== 'start' && phase !== 'renew') throw new Error('bad_phase');
  return `${sessionId}\n${deadlineUnix}\n${phase}`;
}

module.exports = {
  TERMINAL_ACTIONS,
  terminalPayload,
  payloadHash,
  canonicalLease,
  issueLease,
  verifyLease
};
