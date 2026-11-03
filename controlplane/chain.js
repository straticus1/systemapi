// Threats: silent edits to an audit row. Each row hashes the previous row hash
// plus a canonical payload. This is a hash chain, not a blockchain: a writer
// who rewrites every later row can recompute it. Verification detects a break.
// Genesis prev_hash is 64 zero hex chars. Rows written since 2026-10-14 hash
// every column (tenant_id, host_id, actor, action, payload), so rewriting the
// actor or host breaks verification. Older rows hashed only the payload; they
// verify only up to legacyMaxSeq (SYSTEMAPI_AUDIT_LEGACY_MAX_SEQ, unset = no
// row), so a v2-era row cannot be downgraded to the weaker hash, and the
// legacy rows' other columns stay unprotected.
// KNOWN_FORKS: a fork already in a production chain (two rows that chained
// from the same parent before the chain-wide append lock, d8c8342). Each pin
// fixes the parent (prev_hash), the sibling row that became a dead branch
// (sibling_seq, sibling_row_hash) and the forked row (seq, row_hash). A fork
// is accepted once, only when the row directly before it is the pinned
// sibling and both share the pinned parent; pinned rows must carry the v2
// (every-column) hash. Editing or deleting either pinned row, inserting rows
// between them, or replaying a pin fails. Does NOT protect: a full rewrite of
// later rows (compare the recorded head), truncation of the tail, or the
// columns legacy (pre-2026-10-14) rows did not hash.
'use strict';

const crypto = require('node:crypto');

const GENESIS = '0'.repeat(64);

// miniapps1 (api.systemapi.io), 2026-10-22T13:08:18Z: tcp_end (seq 24) and
// ticket_issued (seq 25) both chained from seq 23. Checked 2026-11-03: the
// only break in the 48-row chain; every row hash-valid.
const KNOWN_FORKS = Object.freeze([
  Object.freeze({
    seq: 25,
    prev_hash: 'b4b783cf3a1e647a7807739751e9697864908ef98d61267b4ad0b470f57f4810',
    row_hash: 'c5768d715c4f2f24c3692e88cce6086757aa27f618808658c0402e233af2c8ed',
    sibling_seq: 24,
    sibling_row_hash: '66707aeb841345707d7924b70f602f45c35a25f19078652ecbfa7b343c800c2a'
  })
]);

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = stable(value[key]);
    return out;
  }
  return value;
}

function canonicalJSON(value) {
  return JSON.stringify(stable(value));
}

function chainHash(prevHash, payload) {
  return crypto.createHash('sha256').update(`${prevHash}\n${canonicalJSON(payload)}`).digest('hex');
}

function rowFields(row) {
  return {
    v: 2,
    tenant_id: row.tenant_id ?? null,
    host_id: row.host_id ?? null,
    actor: row.actor ?? null,
    action: row.action ?? null,
    payload: row.payload ?? {}
  };
}

// rowHash covers every column of an audit row.
function rowHash(prevHash, row) {
  return chainHash(prevHash, rowFields(row));
}

// verifyRows walks rows in seq order. forks defaults to KNOWN_FORKS (tests
// pass their own); legacyMaxSeq is the last seq allowed the payload-only hash
// (0: none).
function verifyRows(rows, forks = KNOWN_FORKS, { legacyMaxSeq = 0 } = {}) {
  let prev = GENESIS;
  let last = null;
  const used = new Set();
  const accepted = [];
  for (const row of rows) {
    const pin = forks.find((f) => f.row_hash === row.row_hash);
    const pinnedSibling = forks.some((f) => f.sibling_row_hash === row.row_hash);
    if (row.prev_hash !== prev) {
      const ok = pin && !used.has(pin) && pin.seq === row.seq && pin.prev_hash === row.prev_hash &&
        last && last.seq === pin.sibling_seq && last.row_hash === pin.sibling_row_hash &&
        last.prev_hash === row.prev_hash;
      if (!ok) return { ok: false, broken_at: row.seq };
      used.add(pin);
      accepted.push(row.seq);
    } else if (pin) {
      // The pinned row links in line: its sibling is gone.
      return { ok: false, broken_at: row.seq };
    }
    const v2 = rowHash(row.prev_hash, row) === row.row_hash;
    const legacyOk = row.seq <= legacyMaxSeq && chainHash(row.prev_hash, row.payload) === row.row_hash;
    if (!v2 && (pin || pinnedSibling || !legacyOk)) {
      return { ok: false, broken_at: row.seq };
    }
    prev = row.row_hash;
    last = row;
  }
  return accepted.length > 0 ? { ok: true, head: prev, known_forks: accepted } : { ok: true, head: prev };
}

// SYSTEMAPI_AUDIT_LEGACY_MAX_SEQ: a non-negative integer, else 0.
function legacyMaxSeq(env) {
  const n = Number(env && env.SYSTEMAPI_AUDIT_LEGACY_MAX_SEQ);
  return Number.isSafeInteger(n) && n >= 0 ? n : 0;
}

module.exports = { GENESIS, KNOWN_FORKS, canonicalJSON, chainHash, rowHash, verifyRows, legacyMaxSeq };
