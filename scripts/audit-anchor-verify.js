#!/usr/bin/env node
// Threats: an audit chain rewritten or truncated by someone with database
// write access, and anchoring silently stopped to hide it. Run OFF the
// control-plane host. It lists the signed checkpoints in the anchor sinks
// (read-only credentials, SYSTEMAPI_ANCHOR_SINK1_* / SINK2_*), verifies each
// with the checkpoint PUBLIC key (--vkey or SYSTEMAPI_ANCHOR_VKEY, printed by
// scripts/audit-checkpoint-pubkey.js; never the seed), reads the chain from a
// read-only database URL (SYSTEMAPI_ANCHOR_VERIFY_DATABASE_URL, env only so
// it is not on argv) or a JSON export (--export), recomputes it with
// verifyRows (KNOWN_FORKS applied, SYSTEMAPI_AUDIT_LEGACY_MAX_SEQ honored)
// and checks every anchored seq in one pass. Exit 0: clean. Exit 1: one
// JSON line on stdout with fixed reason codes:
//   chain_broken           the rows do not verify on their own
//   anchor_rewrite         the head at an anchored seq differs, or the row is gone
//   anchor_truncation      an anchored seq is past the current max(seq)
//   anchor_gap             no anchor for more than 2x the cadence (or none at all)
//   anchor_seq_regression  a later anchor names a lower seq than an earlier one
//   anchor_bad_signature   a note not signed by this key
//   anchor_note_invalid    a note that does not parse, is oversized, or whose
//                          object key does not match its contents
//   anchor_time_mismatch   a note's signed time is far from the sink's LastModified
//   anchor_sink_mismatch   two sinks hold different heads for the same seq
// With --export, pass --now <unix time the export was taken>: notes signed
// after it are skipped (they may name rows the export does not hold), and
// the staleness check runs against that time.
// Exit 2: usage or an operational failure (sink_unavailable, db_unavailable,
// export_invalid), code only on stderr. Does NOT prove rows after the last
// anchor (they are checked only as a chain), does NOT check created_at (not
// in the v2 row hash), and is only as good as whoever reads its exit code.
//
// Usage: node scripts/audit-anchor-verify.js [--vkey <vkey>] [--export <file.json>]
//          [--sink sink1|sink2|all] [--cadence-s <300..86400>] [--now <unix>]
// The export is a JSON array of cp_audit rows (seq, prev_hash, row_hash,
// tenant_id, host_id, actor, action, payload), or { "rows": [...] }.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const { verifyRows, legacyMaxSeq, KNOWN_FORKS } = require('../controlplane/chain');
const {
  NOTE_MAX_BYTES, errName, intervalOf, parseNote, parseObjectKey, parseVkey, prefixOf, s3Sink, sinkConfigs
} = require('../controlplane/anchor');

const USAGE = 'usage: node scripts/audit-anchor-verify.js [--vkey <vkey>] [--export <file.json>] '
  + '[--sink sink1|sink2|all] [--cadence-s <300..86400>] [--now <unix>]';
const VALUE_FLAGS = new Set(['--vkey', '--export', '--sink', '--cadence-s', '--now']);
const EXPORT_MAX_BYTES = 1024 * 1024 * 1024;
const TIME_SKEW_S = 600;
const HEX64_RE = /^[0-9a-f]{64}$/;

function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

function parseArgs(argv, env) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!VALUE_FLAGS.has(flag) || i + 1 >= argv.length) throw fail('usage');
    const key = flag.slice(2);
    if (Object.prototype.hasOwnProperty.call(out, key)) throw fail('usage');
    out[key] = argv[(i += 1)];
  }
  const vkeyText = out.vkey !== undefined ? out.vkey : env.SYSTEMAPI_ANCHOR_VKEY;
  if (!vkeyText) throw fail('usage');
  const vkey = parseVkey(vkeyText);
  const sink = out.sink === undefined ? 'all' : out.sink;
  if (!['sink1', 'sink2', 'all'].includes(sink)) throw fail('usage');
  const cadenceS = intervalOf({ SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S: out['cadence-s'] !== undefined ? out['cadence-s'] : env.SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S });
  if (cadenceS === null) throw fail('usage');
  let nowS = Math.floor(Date.now() / 1000);
  if (out.now !== undefined) {
    if (!/^[0-9]{1,12}$/.test(out.now)) throw fail('usage');
    nowS = Number(out.now);
  }
  return { vkey, sink, cadenceS, nowS, nowGiven: out.now !== undefined, exportFile: out.export };
}

function sameHash(a, b) {
  return HEX64_RE.test(a) && HEX64_RE.test(b) && crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

// Rows from an export: shape-checked, then in seq order.
function rowsFromExport(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw fail('export_invalid');
  }
  const rows = Array.isArray(data) ? data : (data && Array.isArray(data.rows) ? data.rows : null);
  if (!rows) throw fail('export_invalid');
  return normalizeRows(rows, 'export_invalid');
}

function normalizeRows(rows, code) {
  const out = rows.map((r) => {
    if (!r || typeof r !== 'object') throw fail(code);
    const seq = Number(r.seq);
    if (!Number.isSafeInteger(seq) || seq < 1 || typeof r.prev_hash !== 'string' || typeof r.row_hash !== 'string' ||
      typeof r.action !== 'string') {
      throw fail(code);
    }
    return {
      seq,
      prev_hash: r.prev_hash,
      row_hash: r.row_hash,
      tenant_id: r.tenant_id ?? null,
      host_id: r.host_id ?? null,
      actor: r.actor ?? null,
      action: r.action,
      payload: r.payload ?? {}
    };
  });
  out.sort((a, b) => a.seq - b.seq);
  return out;
}

async function rowsFromDatabase(url) {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: url, max: 1, statement_timeout: 120000, options: '-c default_transaction_read_only=on' });
  try {
    const res = await pool.query('SELECT seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload FROM cp_audit ORDER BY seq ASC');
    return normalizeRows(res.rows, 'db_invalid');
  } catch (err) {
    if (err.code === 'db_invalid') throw err;
    throw fail('db_unavailable');
  } finally {
    await pool.end().catch(() => {});
  }
}

// Every note in one sink: { notes: [{ key, seq, head, time }], reasons }.
async function readSink(sink, vkey) {
  const reasons = [];
  const notes = [];
  let listed;
  try {
    listed = await sink.list(prefixOf(vkey.deployment));
  } catch (err) {
    const e = fail('sink_unavailable');
    e.detail = `${sink.id} ${errName(err)}`;
    throw e;
  }
  for (const obj of listed) {
    const fromKey = parseObjectKey(vkey.deployment, obj.key);
    if (!fromKey || !(obj.size > 0) || obj.size > NOTE_MAX_BYTES) {
      reasons.push({ code: 'anchor_note_invalid', sink: sink.id, key: String(obj.key).slice(0, 200) });
      continue;
    }
    let body;
    try {
      body = await sink.get(obj.key);
    } catch (err) {
      const e = fail('sink_unavailable');
      e.detail = `${sink.id} ${errName(err)}`;
      throw e;
    }
    let note;
    try {
      note = parseNote(body, vkey);
    } catch (err) {
      reasons.push({ code: err.code === 'anchor_bad_signature' ? 'anchor_bad_signature' : 'anchor_note_invalid', sink: sink.id, key: obj.key });
      continue;
    }
    if (note.seq !== fromKey.seq || note.time !== fromKey.time) {
      reasons.push({ code: 'anchor_note_invalid', sink: sink.id, key: obj.key });
      continue;
    }
    if (obj.lastModified && Math.abs(Math.floor(obj.lastModified.getTime() / 1000) - note.time) > TIME_SKEW_S) {
      reasons.push({ code: 'anchor_time_mismatch', sink: sink.id, seq: note.seq });
    }
    notes.push({ key: obj.key, ...note });
  }
  return { notes, reasons };
}

// The checks over notes already read. bySink: { sinkId: { notes, reasons } }.
function check({ bySink, rows, cadenceS, nowS, forks = KNOWN_FORKS, legacy = 0 }) {
  const reasons = [];
  for (const id of Object.keys(bySink)) reasons.push(...bySink[id].reasons);
  const all = Object.keys(bySink).flatMap((id) => bySink[id].notes.map((n) => ({ ...n, sink: id })));
  // Sinks must agree: one head per seq.
  const headBySeq = new Map();
  for (const n of all) {
    const seen = headBySeq.get(n.seq);
    if (!seen) headBySeq.set(n.seq, n.head);
    else if (!sameHash(seen, n.head)) reasons.push({ code: 'anchor_sink_mismatch', seq: n.seq });
  }
  const seqs = [...new Set(all.map((n) => n.seq))];
  const chain = verifyRows(rows, forks, { legacyMaxSeq: legacy, headsAt: seqs });
  if (!chain.ok) reasons.push({ code: 'chain_broken', seq: chain.broken_at });
  const maxSeq = rows.length ? rows[rows.length - 1].seq : 0;
  for (const n of all) {
    if (n.seq > maxSeq) {
      reasons.push({ code: 'anchor_truncation', sink: n.sink, seq: n.seq });
      continue;
    }
    const head = chain.heads_at[n.seq];
    if (head === undefined && !chain.ok && n.seq >= chain.broken_at) continue;
    if (head === undefined || !sameHash(head, n.head)) reasons.push({ code: 'anchor_rewrite', sink: n.sink, seq: n.seq });
  }
  // Per sink: anchors at most 2x the cadence apart, the last one recent, and
  // seq never going back as time goes on.
  const limit = 2 * cadenceS;
  for (const id of Object.keys(bySink)) {
    const notes = [...bySink[id].notes].sort((a, b) => a.time - b.time || a.seq - b.seq);
    if (notes.length === 0) {
      reasons.push({ code: 'anchor_gap', sink: id, seq: null });
      continue;
    }
    for (let i = 1; i < notes.length; i += 1) {
      if (notes[i].time - notes[i - 1].time > limit) reasons.push({ code: 'anchor_gap', sink: id, seq: notes[i].seq });
      if (notes[i].seq < notes[i - 1].seq) reasons.push({ code: 'anchor_seq_regression', sink: id, seq: notes[i].seq });
    }
    if (nowS - notes[notes.length - 1].time > limit) reasons.push({ code: 'anchor_gap', sink: id, seq: notes[notes.length - 1].seq });
  }
  return { ok: reasons.length === 0, max_seq: maxSeq, anchors: all.length, reasons };
}

// Returns the check result. sinks, readFile, statFile and dbRows are
// injectable for tests.
async function run(argv, { env = process.env, sinks = null, readFile = fs.readFileSync, statFile = fs.statSync, dbRows = rowsFromDatabase } = {}) {
  const args = parseArgs(argv, env);
  if (args.exportFile === undefined && !env.SYSTEMAPI_ANCHOR_VERIFY_DATABASE_URL) throw fail('usage');
  // Notes first, rows second: a checkpoint written in between then names a
  // seq the rows already hold, never one past them (a false truncation).
  let all = sinks;
  if (!all) {
    let cfgs;
    try {
      cfgs = sinkConfigs(env);
    } catch {
      throw fail('sink_config_invalid');
    }
    all = cfgs.map((c) => s3Sink(c));
  }
  const chosen = all.filter((s) => args.sink === 'all' || s.id === args.sink);
  if (chosen.length === 0) throw fail('sink_config_invalid');
  const bySink = {};
  for (const sink of chosen) {
    const read = await readSink(sink, args.vkey);
    // --now (an export's time): notes signed after it are not judged.
    if (args.nowGiven) read.notes = read.notes.filter((n) => n.time <= args.nowS);
    bySink[sink.id] = read;
  }
  let rows;
  if (args.exportFile !== undefined) {
    let text;
    try {
      if (statFile(args.exportFile).size > EXPORT_MAX_BYTES) throw fail('export_invalid');
      text = readFile(args.exportFile, 'utf8');
    } catch (err) {
      throw err.code === 'export_invalid' ? err : fail('export_invalid');
    }
    rows = rowsFromExport(text);
  } else if (env.SYSTEMAPI_ANCHOR_VERIFY_DATABASE_URL) {
    rows = await dbRows(env.SYSTEMAPI_ANCHOR_VERIFY_DATABASE_URL);
  }
  return check({ bySink, rows, cadenceS: args.cadenceS, nowS: args.nowS, legacy: legacyMaxSeq(env) });
}

async function main() {
  try {
    const out = await run(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(out)}\n`);
    process.exit(out.ok ? 0 : 1);
  } catch (err) {
    const code = typeof err.code === 'string' && /^[a-z_]{1,40}$/.test(err.code) ? err.code : 'internal';
    process.stderr.write(code === 'usage' ? `${USAGE}\n` : `${code}${err.detail ? ` ${err.detail}` : ''}\n`);
    process.exit(2);
  }
}

if (require.main === module) main();

module.exports = { run, check, readSink, rowsFromExport, parseArgs };
