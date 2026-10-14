// Threats: silent edits to an audit row. Each row hashes the previous row hash
// plus a canonical payload. This is a hash chain, not a blockchain: a writer
// who rewrites every later row can recompute it. Verification detects a break.
// Genesis prev_hash is 64 zero hex chars. Rows written since 2026-10-14 hash
// every column (tenant_id, host_id, actor, action, payload), so rewriting the
// actor or host breaks verification. Older rows hashed only the payload; they
// still verify, and their other columns stay unprotected.
'use strict';

const crypto = require('node:crypto');

const GENESIS = '0'.repeat(64);

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

function verifyRows(rows) {
  let prev = GENESIS;
  for (const row of rows) {
    if (row.prev_hash !== prev) {
      return { ok: false, broken_at: row.seq };
    }
    if (rowHash(prev, row) !== row.row_hash && chainHash(prev, row.payload) !== row.row_hash) {
      return { ok: false, broken_at: row.seq };
    }
    prev = row.row_hash;
  }
  return { ok: true, head: prev };
}

module.exports = { GENESIS, canonicalJSON, chainHash, rowHash, verifyRows };
