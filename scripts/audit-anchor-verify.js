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
// JSON line on stdout { ok, max_seq, anchors, reasons, acked, acked_reasons }
// with fixed reason codes:
//   chain_broken           the rows do not verify on their own
//   anchor_rewrite         the head at an anchored seq differs (compared with
//                          the stored row_hash at or past a break), or the row is gone
//   anchor_truncation      an anchored seq is past the current max(seq)
//   anchor_gap             no anchor for more than 2x the cadence + 300 s (or none)
//   anchor_seq_regression  a later anchor names a lower seq than an earlier one
//   anchor_bad_signature   a note not signed by this key
//   anchor_note_invalid    a note that does not parse, is oversized, has no
//                          LastModified, or whose object key does not match it
//   anchor_time_mismatch   a note's signed time is far from the sink's LastModified
//   anchor_sink_mismatch   two notes hold different heads for one seq, or (both
//                          sinks read) a key older than 600 s is in one sink only
// --ack FILE: a reviewed, off-box JSON list of { code, sink, key, why };
// a reason naming exactly that code, sink and object key is reported under
// acked_reasons and does not fail the run (WORM objects cannot be deleted,
// so an old alarm would otherwise fire forever and bury new ones).
// chain_broken, staleness and an empty sink can never be acked. Gap and
// staleness judge only notes whose signed time is within 600 s of their
// LastModified. --since <unix>: notes signed before it are not fetched or
// judged; the gap rule runs from it.
// With --export, pass --now <unix time the export was taken>: notes signed
// after it are skipped (they may name rows the export does not hold), and
// the staleness check runs against that time. The run is only as honest as
// that --now.
// Exit 2: usage or an operational failure (sink_unavailable,
// sink_list_too_large, sink_config_invalid, db_unavailable, export_invalid,
// ack_invalid, vkey_invalid), code only on stderr. Exit 2 must page like
// exit 1: a verifier that cannot read is a verifier that sees nothing. Does
// NOT prove rows after the last anchor (they are checked only as a chain),
// does NOT check created_at (not in the v2 row hash), and is only as good as
// whoever reads its exit code.
//
// Usage: node scripts/audit-anchor-verify.js [--vkey <vkey>] [--export <file.json>]
//          [--sink sink1|sink2|all] [--cadence-s <300..86400>] [--now <unix>]
//          [--since <unix>] [--ack <file.json>]
// The export is a JSON array of cp_audit rows (seq, prev_hash, row_hash,
// tenant_id, host_id, actor, action, payload), or { "rows": [...] }.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const { verifyRows, legacyMaxSeq, KNOWN_FORKS } = require('../controlplane/chain');
const {
  NOTE_MAX_BYTES, TIME_SKEW_S, errName, intervalOf, parseNote, parseObjectKey, parseVkey, prefixOf, s3Sink, sinkConfigs
} = require('../controlplane/anchor');

const USAGE = 'usage: node scripts/audit-anchor-verify.js [--vkey <vkey>] [--export <file.json>] '
  + '[--sink sink1|sink2|all] [--cadence-s <300..86400>] [--now <unix>] [--since <unix>] [--ack <file.json>]';
const VALUE_FLAGS = new Set(['--vkey', '--export', '--sink', '--cadence-s', '--now', '--since', '--ack']);
const EXPORT_MAX_BYTES = 1024 * 1024 * 1024;
const ACK_MAX_BYTES = 1024 * 1024;
const ACK_MAX = 1000;
// Slack on the 2x-cadence gap rule: the writer ticks every 30 s and writes
// once now - last >= cadence, so one missed checkpoint leaves notes 2x the
// cadence plus up to a tick or two apart. 300 s covers that and clock jitter.
const GAP_SLACK_S = 300;
// Codes an ack may name, always by object key. chain_broken is not one: the
// chain is not verified past a break, so an ack would blind everything after
// it (a known, reviewed fork goes into KNOWN_FORKS in controlplane/chain.js).
// Staleness and empty-sink gaps carry no key and can never be acked.
const ACK_CODES = new Set(['anchor_rewrite', 'anchor_truncation', 'anchor_gap', 'anchor_seq_regression',
  'anchor_bad_signature', 'anchor_note_invalid', 'anchor_time_mismatch', 'anchor_sink_mismatch']);
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
  let sinceS = null;
  if (out.since !== undefined) {
    if (!/^[0-9]{1,12}$/.test(out.since) || Number(out.since) > nowS) throw fail('usage');
    sinceS = Number(out.since);
  }
  return { vkey, sink, cadenceS, nowS, nowGiven: out.now !== undefined, sinceS, exportFile: out.export, ackFile: out.ack };
}

// The reviewed ack file: a JSON array of { code, sink, key, why }, where key
// is the object key the reason names. An acked reason is still reported but
// does not fail the run. Every field is required: a known code (see
// ACK_CODES), sink1 or sink2, the exact key, and a non-empty why.
function parseAcks(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw fail('ack_invalid');
  }
  if (!Array.isArray(data) || data.length > ACK_MAX) throw fail('ack_invalid');
  return data.map((a) => {
    if (!a || typeof a !== 'object' || Array.isArray(a)) throw fail('ack_invalid');
    const extra = Object.keys(a).filter((k) => !['code', 'sink', 'key', 'why'].includes(k));
    if (extra.length > 0 || !ACK_CODES.has(a.code) || (a.sink !== 'sink1' && a.sink !== 'sink2') ||
      typeof a.key !== 'string' || a.key === '' || a.key.length > 512 ||
      typeof a.why !== 'string' || a.why.trim() === '' || a.why.length > 500) {
      throw fail('ack_invalid');
    }
    return { code: a.code, sink: a.sink, key: a.key };
  });
}

// A reason with no key (staleness, an empty sink, chain_broken) never
// matches.
function acked(reason, acks) {
  if (typeof reason.key !== 'string') return false;
  return acks.some((a) => a.code === reason.code && a.sink === reason.sink && a.key === reason.key);
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
  const pool = new Pool({
    connectionString: url,
    max: 1,
    connectionTimeoutMillis: 15000,
    statement_timeout: 120000,
    query_timeout: 130000,
    options: '-c default_transaction_read_only=on'
  });
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

// Every note in one sink: { notes: [{ key, seq, head, time }], keys (every
// well-named key in the window), reasons }. Keys whose time is outside
// [sinceS, untilS] are not fetched.
async function readSink(sink, vkey, { sinceS = null, untilS = null } = {}) {
  const reasons = [];
  const notes = [];
  const keys = new Map();
  let listed;
  try {
    listed = await sink.list(prefixOf(vkey.deployment));
  } catch (err) {
    const e = fail(err && err.code === 'sink_list_too_large' ? 'sink_list_too_large' : 'sink_unavailable');
    e.detail = `${sink.id} ${errName(err)}`;
    throw e;
  }
  for (const obj of listed) {
    const fromKey = parseObjectKey(vkey.deployment, obj.key);
    if (fromKey && ((sinceS !== null && fromKey.time < sinceS) || (untilS !== null && fromKey.time > untilS))) continue;
    if (fromKey) keys.set(obj.key, fromKey.time);
    if (!fromKey || !(obj.size > 0) || obj.size > NOTE_MAX_BYTES || !obj.lastModified) {
      reasons.push({ code: 'anchor_note_invalid', sink: sink.id, key: String(obj.key).slice(0, 512) });
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
    const lastModifiedS = Math.floor(obj.lastModified.getTime() / 1000);
    if (Math.abs(lastModifiedS - note.time) > TIME_SKEW_S) {
      reasons.push({ code: 'anchor_time_mismatch', sink: sink.id, seq: note.seq, key: obj.key });
    }
    notes.push({ key: obj.key, ...note, lastModifiedS });
  }
  return { notes, keys, reasons };
}

// The checks over notes already read. bySink: { sinkId: { notes, keys,
// reasons } }. sinceS: the judging cut-off (the gap rule runs from it).
// acks: parsed ack entries; acked reasons are reported apart and do not fail.
function check({ bySink, rows, cadenceS, nowS, sinceS = null, acks = [], forks = KNOWN_FORKS, legacy = 0 }) {
  const reasons = [];
  for (const id of Object.keys(bySink)) reasons.push(...bySink[id].reasons);
  const all = Object.keys(bySink).flatMap((id) => bySink[id].notes.map((n) => ({ ...n, sink: id })));
  // Sinks must agree: one head per seq.
  const headBySeq = new Map();
  for (const n of all) {
    const seen = headBySeq.get(n.seq);
    if (!seen) headBySeq.set(n.seq, n.head);
    else if (!sameHash(seen, n.head)) reasons.push({ code: 'anchor_sink_mismatch', sink: n.sink, seq: n.seq, key: n.key });
  }
  // Both sinks read: a key one holds and the other lacks, past the retry
  // window, is a mismatch too.
  const ids = Object.keys(bySink);
  if (ids.length === 2) {
    for (const [a, b] of [[ids[0], ids[1]], [ids[1], ids[0]]]) {
      for (const [key, time] of bySink[a].keys || []) {
        if (nowS - time > TIME_SKEW_S && !(bySink[b].keys || new Map()).has(key)) {
          reasons.push({ code: 'anchor_sink_mismatch', sink: b, key });
        }
      }
    }
  }
  const seqs = [...new Set(all.map((n) => n.seq))];
  const chain = verifyRows(rows, forks, { legacyMaxSeq: legacy, headsAt: seqs });
  if (!chain.ok) reasons.push({ code: 'chain_broken', sink: null, seq: chain.broken_at });
  const maxSeq = rows.length ? rows[rows.length - 1].seq : 0;
  const rowBySeq = chain.ok ? new Map() : new Map(rows.map((r) => [r.seq, r]));
  for (const n of all) {
    if (n.seq > maxSeq) {
      reasons.push({ code: 'anchor_truncation', sink: n.sink, seq: n.seq, key: n.key });
      continue;
    }
    // At or past a break there is no verified head: compare with the stored
    // row_hash at that seq instead, so a rewrite there still shows.
    let head = chain.heads_at[n.seq];
    if (head === undefined && !chain.ok && n.seq >= chain.broken_at) {
      const row = rowBySeq.get(n.seq);
      head = row ? row.row_hash : undefined;
    }
    if (head === undefined || !sameHash(head, n.head)) reasons.push({ code: 'anchor_rewrite', sink: n.sink, seq: n.seq, key: n.key });
  }
  // Per sink: anchors at most 2x the cadence (+ slack) apart, the last one
  // recent, and seq never going back as time goes on. Timeliness counts only
  // notes whose signed time is within TIME_SKEW_S of the sink's LastModified
  // (a far-future or backdated note cannot hold off the staleness check,
  // even once its time_mismatch is acked), judged at min(time, LastModified
  // + skew). A gap names the note that ends it; staleness and an empty sink
  // name no key, so they cannot be acked.
  const limit = 2 * cadenceS + GAP_SLACK_S;
  for (const id of Object.keys(bySink)) {
    const notes = bySink[id].notes
      .filter((n) => n.lastModifiedS === undefined || Math.abs(n.time - n.lastModifiedS) <= TIME_SKEW_S)
      .map((n) => ({ ...n, at: n.lastModifiedS === undefined ? n.time : Math.min(n.time, n.lastModifiedS + TIME_SKEW_S) }))
      .sort((a, b) => a.at - b.at || a.seq - b.seq);
    if (notes.length === 0) {
      reasons.push({ code: 'anchor_gap', sink: id, seq: null });
      continue;
    }
    if (sinceS !== null && notes[0].at - sinceS > limit) reasons.push({ code: 'anchor_gap', sink: id, seq: notes[0].seq, key: notes[0].key });
    for (let i = 1; i < notes.length; i += 1) {
      if (notes[i].at - notes[i - 1].at > limit) reasons.push({ code: 'anchor_gap', sink: id, seq: notes[i].seq, key: notes[i].key });
      if (notes[i].seq < notes[i - 1].seq) reasons.push({ code: 'anchor_seq_regression', sink: id, seq: notes[i].seq, key: notes[i].key });
    }
    if (nowS - notes[notes.length - 1].at > limit) reasons.push({ code: 'anchor_gap', sink: id, seq: null, stale: true });
  }
  const open = reasons.filter((r) => !acked(r, acks));
  const done = reasons.filter((r) => acked(r, acks));
  return { ok: open.length === 0, max_seq: maxSeq, anchors: all.length, reasons: open, acked: done.length, acked_reasons: done };
}

// Returns the check result. sinks, readFile, statFile and dbRows are
// injectable for tests.
async function run(argv, { env = process.env, sinks = null, readFile = fs.readFileSync, statFile = fs.statSync, dbRows = rowsFromDatabase } = {}) {
  const args = parseArgs(argv, env);
  let acks = [];
  if (args.ackFile !== undefined) {
    let text;
    try {
      if (statFile(args.ackFile).size > ACK_MAX_BYTES) throw fail('ack_invalid');
      text = readFile(args.ackFile, 'utf8');
    } catch (err) {
      throw err.code === 'ack_invalid' ? err : fail('ack_invalid');
    }
    acks = parseAcks(text);
  }
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
    // --now (an export's time): notes signed after it are not judged;
    // --since: nor are notes before it.
    bySink[sink.id] = await readSink(sink, args.vkey, { sinceS: args.sinceS, untilS: args.nowGiven ? args.nowS : null });
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
  return check({ bySink, rows, cadenceS: args.cadenceS, nowS: args.nowS, sinceS: args.sinceS, acks, legacy: legacyMaxSeq(env) });
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

module.exports = { run, check, readSink, rowsFromExport, parseArgs, parseAcks, GAP_SLACK_S };
