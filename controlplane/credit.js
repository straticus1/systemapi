// Threats: one SAH channel stream (TCP forward or file session) growing the
// server's memory without bound, or starving other streams on the shared
// agent socket. Each stream has a credit window per direction
// (docs/sah-tcp-protocol.md §6: 256 KiB; docs/sah-file-protocol.md §6:
// 8 MiB per session). A peer that sends past the window it was given, or
// returns more credit than it could owe, is a fatal protocol violation: the
// ledger reports it and the caller disconnects that agent. Not used by PTY.
// Does NOT pace a peer that stays inside its window (that is the idle timeout
// and byte cap's job), and does NOT itself pause sockets: callers stop
// reading the client while send() reports no credit.
'use strict';

const TCP_WINDOW = 256 * 1024;
const FILE_WINDOW = 8 * 1024 * 1024;
const MAX_TURN = 64 * 1024;

class CreditStream {
  // window: bytes per direction. returnAt: drained bytes batched before a
  // credit frame goes back (default a quarter of the window).
  constructor({ window, returnAt } = {}) {
    if (!Number.isInteger(window) || window <= 0) throw new Error('bad_window');
    this.window = window;
    this.returnAt = Number.isInteger(returnAt) && returnAt > 0 ? Math.min(returnAt, window) : Math.max(1, Math.floor(window / 4));
    this.sendCredit = window; // bytes we may still send to the peer
    this.inWindow = 0; // bytes the peer sent that we have not credited back
    this.drainedUnreturned = 0;
  }

  // Sending side: how much may go out now (capped at one turn).
  sendable(max = MAX_TURN) {
    return Math.min(this.sendCredit, max);
  }

  // Consume n bytes of send credit; false when there is not enough.
  take(n) {
    if (!Number.isInteger(n) || n < 0 || n > this.sendCredit) return false;
    this.sendCredit -= n;
    return true;
  }

  // The peer returned credit. False is a violation: a non-positive or
  // non-integer amount, or more than it could owe (credit past the window).
  grant(n) {
    if (!Number.isInteger(n) || n <= 0) return false;
    if (this.sendCredit + n > this.window) return false;
    this.sendCredit += n;
    return true;
  }

  // Receiving side: the peer sent n bytes. False is an overrun (violation).
  receive(n) {
    if (!Number.isInteger(n) || n < 0) return false;
    if (this.inWindow + n > this.window) return false;
    this.inWindow += n;
    return true;
  }

  // n received bytes were drained (written onward). Returns the credit to
  // send back now, or 0 while it is still batching. Batching cannot stall the
  // peer: a peer with no credit has a full window in flight, which is at
  // least returnAt.
  drain(n) {
    if (!Number.isInteger(n) || n <= 0) return 0;
    this.drainedUnreturned = Math.min(this.inWindow, this.drainedUnreturned + n);
    if (this.drainedUnreturned < this.returnAt) return 0;
    return this.flush();
  }

  // Returns every drained-but-unreturned byte now.
  flush() {
    const out = this.drainedUnreturned;
    this.inWindow -= out;
    this.drainedUnreturned = 0;
    return out;
  }
}

// Per agent connection: the credit state of every channel stream on it.
// onViolation(sessionId, reason) is called once; the caller terminates the
// agent socket.
class CreditLedger {
  constructor({ onViolation } = {}) {
    this.streams = new Map();
    this.onViolation = typeof onViolation === 'function' ? onViolation : () => {};
    this.violated = false;
  }

  open(sessionId, opts) {
    if (this.streams.has(sessionId)) throw new Error('stream_exists');
    const s = new CreditStream(opts);
    this.streams.set(sessionId, s);
    return s;
  }

  get(sessionId) {
    return this.streams.get(sessionId) || null;
  }

  close(sessionId) {
    this.streams.delete(sessionId);
  }

  violation(sessionId, reason) {
    if (this.violated) return false;
    this.violated = true;
    this.onViolation(sessionId, reason);
    return false;
  }

  // Data from the agent for sessionId. Data for an unknown stream is
  // ignored (it may have just closed); past the window is a violation.
  receive(sessionId, n) {
    const s = this.streams.get(sessionId);
    if (!s) return true;
    if (!s.receive(n)) return this.violation(sessionId, 'credit_overrun');
    return true;
  }

  // A credit frame from the agent.
  grant(sessionId, n) {
    const s = this.streams.get(sessionId);
    if (!s) return true;
    if (!s.grant(n)) return this.violation(sessionId, 'credit_overflow');
    return true;
  }
}

// Credit frames: {"type":"<kind>_credit","session_id":"...","bytes":N},
// kind "tcp" or "file".
function creditFrame(kind, sessionId, bytes) {
  return { type: `${kind}_credit`, session_id: sessionId, bytes };
}

// The bytes of a credit frame, or null when malformed.
function creditBytes(msg) {
  if (!msg || typeof msg !== 'object') return null;
  const n = msg.bytes;
  if (!Number.isSafeInteger(n) || n <= 0) return null;
  return n;
}

// Binary data on the agent socket: [1-byte id length][session id][bytes],
// the PTY output format.
function encodeData(sessionId, data) {
  const id = Buffer.from(sessionId, 'latin1');
  if (id.length === 0 || id.length > 255) throw new Error('bad_session_id');
  return Buffer.concat([Buffer.from([id.length]), id, data]);
}

function decodeData(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 1) return null;
  const n = buf[0];
  if (n === 0 || buf.length < 1 + n) return null;
  return { sessionId: buf.toString('latin1', 1, 1 + n), data: buf.subarray(1 + n) };
}

module.exports = {
  TCP_WINDOW,
  FILE_WINDOW,
  MAX_TURN,
  CreditStream,
  CreditLedger,
  creditFrame,
  creditBytes,
  encodeData,
  decodeData
};
