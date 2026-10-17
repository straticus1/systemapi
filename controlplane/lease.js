// Threats: unsigned or swapped command payloads, expired leases, and a lease
// reused against a different host. Verification rejects tampered, expired,
// wrong-host, and wrong-action input. Replay cache is the agent's job (the
// server mints a fresh nonce per issue). Clock skew allowance is 30s. TTL
// cap is 300s. Does NOT stop an agent that ignores the lease.
// Terminal actions (pty, pty_root, breakglass) sign "<action>\n<payload>",
// where the payload is "<session_id>\n<deadline_unix>\n<start|renew>". A
// renewal lease is bound to one session, cannot move its deadline, and cannot
// be replayed as a start.
// Channel actions (tcp, file, file_root) follow the same rule, "<action>\n
// <payload>", with the payloads of docs/sah-tcp-protocol.md §5
// ("<session_id>\n<deadline_unix>\n<start|renew>\n<target.host>\n<port>")
// and docs/sah-file-protocol.md §7 ("<session_id>\n<deadline_unix>\n
// <start|renew>\n<read|write>\n<root>"), so the agent dials only the signed
// target and opens only the signed root in the signed mode. The builders
// refuse a newline or control byte in any field, so fields cannot be shifted.
// sahxfer grant actions (xfer, xfer_root) follow the same rule with the
// 8-line payload of sahxfer docs/design.md §3.4 ("<grant_id>\n<deadline_unix>
// \n<start|renew>\n<put|get>\n<root>\n<path>\n<size>\n<sha256>"), so a put
// lease cannot authorize a get and the agent writes only the signed path,
// size and hash. The payload deadline is the lease deadline (§3.4: TTL 60 s,
// renewed every 30 s).
'use strict';

const crypto = require('node:crypto');
const { validateFileRoot } = require('./channels');
const { randomBytes, timingSafeEqual } = crypto;

const ACTIONS = new Set(['sysscript', 'pty', 'pty_root', 'breakglass', 'tcp', 'file', 'file_root', 'xfer', 'xfer_root']);
const TERMINAL_ACTIONS = new Set(['pty', 'pty_root', 'breakglass']);
const CHANNEL_ACTIONS = new Set(['tcp', 'file', 'file_root']);
const XFER_ACTIONS = new Set(['xfer', 'xfer_root']);
// Actions whose hash covers "<action>\n<payload>".
const SESSION_ACTIONS = new Set([...TERMINAL_ACTIONS, ...CHANNEL_ACTIONS, ...XFER_ACTIONS]);
const TCP_SESSION_RE = /^tcs_[A-Za-z0-9_-]{16,64}$/;
const FILE_SESSION_RE = /^fls_[A-Za-z0-9_-]{16,64}$/;
const XFER_GRANT_RE = /^xfr_[A-Za-z0-9_-]{8,64}$/;
const MAX_TTL_S = 300;
const SKEW_S = 30;

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function payloadHash(action, payload) {
  if (SESSION_ACTIONS.has(action)) return sha256Hex(Buffer.from(`${action}\n${String(payload)}`, 'utf8'));
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

function badPayload() {
  const err = new Error('bad_payload');
  err.status = 400;
  return err;
}

function checkCommon(sessionId, re, deadlineUnix, phase) {
  if (typeof sessionId !== 'string' || !re.test(sessionId)) throw badPayload();
  if (!Number.isInteger(deadlineUnix) || deadlineUnix <= 0) throw badPayload();
  if (phase !== 'start' && phase !== 'renew') throw badPayload();
}

// TCP §5. host is "local", an IPv4 dotted quad or a canonical IPv6 literal
// (controlplane/channels.js validateTcpTarget output).
function tcpPayload(sessionId, deadlineUnix, phase, host, port) {
  checkCommon(sessionId, TCP_SESSION_RE, deadlineUnix, phase);
  if (typeof host !== 'string' || !/^(local|[0-9A-Fa-f.:]{2,45})$/.test(host)) throw badPayload();
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw badPayload();
  return `${sessionId}\n${deadlineUnix}\n${phase}\n${host}\n${port}`;
}

// FILE §7. mode is "read" or "write"; root is "~" or an absolute path
// (controlplane/channels.js validateFileRoot output).
function filePayload(sessionId, deadlineUnix, phase, mode, root) {
  checkCommon(sessionId, FILE_SESSION_RE, deadlineUnix, phase);
  if (mode !== 'read' && mode !== 'write') throw badPayload();
  if (typeof root !== 'string' || root.length === 0 || root.length > 4096 || /[\u0000-\u001f\u007f]/.test(root)) throw badPayload();
  if (root !== '~' && !root.startsWith('/')) throw badPayload();
  return `${sessionId}\n${deadlineUnix}\n${phase}\n${mode}\n${root}`;
}

// sahxfer design §3.4. dir is "put" or "get"; root is absolute; path is
// relative; size is a safe integer; sha256 is 64 lowercase hex. The route
// already checked root and path; they are checked again here (FILE §2 root
// shape, FILE §5.1 path shape, byte limits) so no caller can sign a payload
// whose lines shift or whose path climbs out of the root.
function xferPayload(grantId, deadlineUnix, phase, dir, root, path, size, sha256) {
  checkCommon(grantId, XFER_GRANT_RE, deadlineUnix, phase);
  if (dir !== 'put' && dir !== 'get') throw badPayload();
  if (!validateFileRoot(root, 'file:root').ok) throw badPayload();
  if (typeof path !== 'string' || !path.isWellFormed() || /[\u0000-\u001f\u007f\\]/.test(path)) throw badPayload();
  const pathBytes = Buffer.byteLength(path, 'utf8');
  if (pathBytes < 1 || pathBytes > 4096 || path.startsWith('/')) throw badPayload();
  for (const c of path.split('/')) {
    if (c === '' || c === '.' || c === '..' || Buffer.byteLength(c, 'utf8') > 255) throw badPayload();
  }
  if (!Number.isSafeInteger(size) || size < 0) throw badPayload();
  if (typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sha256)) throw badPayload();
  return `${grantId}\n${deadlineUnix}\n${phase}\n${dir}\n${root}\n${path}\n${size}\n${sha256}`;
}

module.exports = {
  TERMINAL_ACTIONS,
  CHANNEL_ACTIONS,
  TCP_SESSION_RE,
  FILE_SESSION_RE,
  XFER_ACTIONS,
  XFER_GRANT_RE,
  terminalPayload,
  tcpPayload,
  filePayload,
  xferPayload,
  payloadHash,
  canonicalLease,
  issueLease,
  verifyLease
};
