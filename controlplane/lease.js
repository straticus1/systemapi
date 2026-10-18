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
// 18-line payload of sahxfer docs/design.md §3.4 (grant id, deadline, phase,
// dir, root, path, size, sha256, overwrite, transfer id, first-packet
// deadline, idle_s, max_s, byte cap, profile, transport, peer, material), so
// a put lease cannot authorize a get and the agent acts only on signed
// fields. material is the hex SHA-256 of "sahxfer-material-v1\n" || key ||
// route_token (raw bytes): the lease binds the key without carrying it, and
// the server keeps only that hash for renewals. The payload deadline is the
// lease deadline (§3.4: TTL 60 s, renewed every 30 s). The shared golden
// vector is sahxfer docs/golden-xfer-lease-v2.txt.
// A watch request (docs/sahconnect-terminal-protocol.md §7.2) is signed for
// the watched session's own terminal action over "<session_id>\n
// <deadline_unix>\nwatch\n<watch_id>\n<ro|rw>\n<true|false>\n<reason>", so
// only the lease signer can claim an override and a start or renew lease
// cannot be replayed as a watch (or the reverse).
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
const PTY_SESSION_RE = /^pts_[A-Za-z0-9_-]{16,64}$/;
const WATCH_ID_RE = /^wch_[A-Za-z0-9_-]{16,64}$/;
const WATCH_REASON_MAX = 256;
// The agent's terminalText keeps Go unicode.IsPrint characters: letters,
// marks, numbers, punctuation, symbols and the ASCII space.
const WATCH_REASON_RE = /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]+$/u;
const XFER_TRANSFER_RE = /^[0-9a-f]{16}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const XFER_MAX_S = 3600;
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

// A watch reason: 1..256 UTF-8 bytes of printable characters with some
// non-space content; no tab, newline or other control character, and no
// U+FFFD (the agent refuses all of these as bad_request).
function watchReasonOk(reason) {
  if (typeof reason !== 'string' || !reason.isWellFormed() || reason.trim() === '') return false;
  if (Buffer.byteLength(reason, 'utf8') > WATCH_REASON_MAX) return false;
  return WATCH_REASON_RE.test(reason) && !reason.includes('\uFFFD');
}

// §7.2 watch lease payload. The deadline is the watched session's own
// deadline (the one its start lease carried); override is signed as the
// words true or false.
function watchPayload(sessionId, deadlineUnix, watchId, mode, override, reason) {
  if (typeof sessionId !== 'string' || !PTY_SESSION_RE.test(sessionId)) throw badPayload();
  if (!Number.isInteger(deadlineUnix) || deadlineUnix <= 0) throw badPayload();
  if (typeof watchId !== 'string' || !WATCH_ID_RE.test(watchId)) throw badPayload();
  if (mode !== 'ro' && mode !== 'rw') throw badPayload();
  if (typeof override !== 'boolean') throw badPayload();
  if (!watchReasonOk(reason)) throw badPayload();
  return `${sessionId}\n${deadlineUnix}\nwatch\n${watchId}\n${mode}\n${override}\n${reason}`;
}

// host:port with a numeric port 1..65535; the host is an IP literal or a DNS
// name (IPv6 in brackets). Returns the string or null.
function peerAddress(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 256 || /[\s\u0000-\u001f\u007f]/.test(raw)) return null;
  const m = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,4})$/.exec(raw);
  if (!m || Number(m[2]) > 65535) return null;
  return raw;
}

// Lease line 18: hex SHA-256 of "sahxfer-material-v1\n" || key || route_token
// over the raw 32 and 16 bytes.
function xferMaterial(key, routeToken) {
  if (!Buffer.isBuffer(key) || key.length !== 32 || !Buffer.isBuffer(routeToken) || routeToken.length !== 16) throw badPayload();
  return crypto.createHash('sha256').update('sahxfer-material-v1\n', 'utf8').update(key).update(routeToken).digest('hex');
}

function intIn(n, lo, hi) {
  return Number.isSafeInteger(n) && n >= lo && n <= hi;
}

// sahxfer design §3.4, the 18-line form. dir is "put" or "get"; root is
// absolute; path is relative; size is a safe integer; sha256 is 64 lowercase
// hex; overwrite is a boolean, signed as 0 or 1; transfer_id is 16 lowercase
// hex, not all zero; expires_unix is the first-packet deadline; max_s is
// 1..3600, idle_s 1..max_s; byte_cap is at least size; profile is internet
// or dc; transport is udp (v1); peer is "listen" or "dial:<host:port>";
// material is 64 lowercase hex (xferMaterial). The route already checked
// root and path; they are checked again here (FILE §2 root shape, FILE §5.1
// path shape, byte limits) so no caller can sign a payload whose lines shift
// or whose path climbs out of the root.
function xferPayload({
  grantId, deadlineUnix, phase, dir, root, path, size, sha256, overwrite, transferId,
  expiresUnix, idleS, maxS, byteCap, profile, transport, peer, material
} = {}) {
  checkCommon(grantId, XFER_GRANT_RE, deadlineUnix, phase);
  if (dir !== 'put' && dir !== 'get') throw badPayload();
  if (!validateFileRoot(root, 'file:root').ok) throw badPayload();
  if (typeof path !== 'string' || !path.isWellFormed() || /[\u0000-\u001f\u007f\\]/.test(path)) throw badPayload();
  const pathBytes = Buffer.byteLength(path, 'utf8');
  if (pathBytes < 1 || pathBytes > 4096 || path.startsWith('/')) throw badPayload();
  for (const c of path.split('/')) {
    if (c === '' || c === '.' || c === '..' || Buffer.byteLength(c, 'utf8') > 255) throw badPayload();
  }
  if (!intIn(size, 0, Number.MAX_SAFE_INTEGER)) throw badPayload();
  if (typeof sha256 !== 'string' || !SHA256_HEX_RE.test(sha256)) throw badPayload();
  if (typeof overwrite !== 'boolean') throw badPayload();
  if (typeof transferId !== 'string' || !XFER_TRANSFER_RE.test(transferId) || transferId === '0000000000000000') throw badPayload();
  if (!intIn(expiresUnix, 1, Number.MAX_SAFE_INTEGER)) throw badPayload();
  if (!intIn(maxS, 1, XFER_MAX_S) || !intIn(idleS, 1, maxS)) throw badPayload();
  if (!intIn(byteCap, size, Number.MAX_SAFE_INTEGER)) throw badPayload();
  if (profile !== 'internet' && profile !== 'dc') throw badPayload();
  if (transport !== 'udp') throw badPayload();
  if (peer !== 'listen' && !(typeof peer === 'string' && peer.startsWith('dial:') && peerAddress(peer.slice(5)))) throw badPayload();
  if (typeof material !== 'string' || !SHA256_HEX_RE.test(material)) throw badPayload();
  return [
    grantId, deadlineUnix, phase, dir, root, path, size, sha256, overwrite ? 1 : 0, transferId,
    expiresUnix, idleS, maxS, byteCap, profile, transport, peer, material
  ].join('\n');
}

module.exports = {
  TERMINAL_ACTIONS,
  CHANNEL_ACTIONS,
  TCP_SESSION_RE,
  FILE_SESSION_RE,
  XFER_ACTIONS,
  XFER_GRANT_RE,
  PTY_SESSION_RE,
  WATCH_ID_RE,
  watchReasonOk,
  watchPayload,
  terminalPayload,
  tcpPayload,
  filePayload,
  xferPayload,
  xferMaterial,
  peerAddress,
  payloadHash,
  canonicalLease,
  issueLease,
  verifyLease
};
