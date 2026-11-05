'use strict';

// controlplane/anchor.js and scripts/audit-anchor-verify.js: signed
// chain-head checkpoints written to mock WORM sinks by the control tick, and
// the off-box verifier that compares them with the rows. No network: the
// sinks are in-memory, and the S3 adapter is checked against a fake client.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { MemoryRegistry } = require('../controlplane/registry');
const { GENESIS, rowHash, verifyRows } = require('../controlplane/chain');
const anchor = require('../controlplane/anchor');
const verify = require('../scripts/audit-anchor-verify');

const ROOT = path.join(__dirname, '..');
const SEED = 'ab'.repeat(32);
const LEASE_SEED = 'cd'.repeat(32);
const DEPLOY = 'prod-1';
const HOUR = 3600;
const T0 = 1_800_000_000;
const quiet = { log() {}, warn() {}, error() {} };

function sinkEnv(n, extra = {}) {
  return {
    [`SYSTEMAPI_ANCHOR_SINK${n}_ENDPOINT`]: n === 1 ? 'https://storage.example.test' : 'https://r2.example.test',
    [`SYSTEMAPI_ANCHOR_SINK${n}_BUCKET`]: 'audit-anchors',
    [`SYSTEMAPI_ANCHOR_SINK${n}_REGION`]: n === 1 ? 'us-east-1' : 'auto',
    [`SYSTEMAPI_ANCHOR_SINK${n}_ACCESS_KEY_ID`]: `AKID${n}`,
    [`SYSTEMAPI_ANCHOR_SINK${n}_SECRET_ACCESS_KEY`]: `secret-${n}-value`,
    ...extra
  };
}

function baseEnv(extra = {}) {
  return {
    SYSTEMAPI_ED25519_SEED: LEASE_SEED,
    SYSTEMAPI_AUDIT_CHECKPOINT_SEED: SEED,
    SYSTEMAPI_AUDIT_DEPLOYMENT: DEPLOY,
    ...sinkEnv(1),
    ...sinkEnv(2),
    ...extra
  };
}

// An in-memory WORM sink: an existing key is never overwritten.
function memorySink(id, { failPut = false } = {}) {
  const objects = new Map();
  let clock = null;
  return {
    id,
    objects,
    failPut,
    puts: 0,
    setClock(fn) { clock = fn; },
    async put(key, body) {
      this.puts += 1;
      if (this.failPut) throw Object.assign(new Error('boom'), { name: 'AccessDenied' });
      if (objects.has(key)) throw Object.assign(new Error('locked'), { name: 'ObjectLocked' });
      objects.set(key, { body: Buffer.from(body, 'utf8'), lastModified: new Date((clock ? clock() : Date.now())) });
    },
    async list(prefix) {
      return [...objects.entries()].filter(([k]) => k.startsWith(prefix)).sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([key, o]) => ({ key, size: o.body.length, lastModified: o.lastModified }));
    },
    async get(key) {
      return Buffer.from(objects.get(key).body);
    }
  };
}

// A registry, an anchor on two memory sinks, and a settable clock (ms).
function rig({ failSink2 = false, env = baseEnv() } = {}) {
  const registry = new MemoryRegistry({});
  const sinks = [memorySink('sink1'), memorySink('sink2', { failPut: failSink2 })];
  let nowMs = T0 * 1000;
  for (const s of sinks) s.setClock(() => nowMs);
  const config = anchor.loadAnchorConfig(env);
  assert.equal(config.enabled, true, config.reason);
  const logs = [];
  const logger = { log: (m) => logs.push(String(m)), warn: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) };
  const a = new anchor.AuditAnchor({ config, registry, sinks, logger, now: () => nowMs });
  return {
    registry, sinks, anchor: a, config, logs,
    advance(s) { nowMs += s * 1000; },
    nowS() { return Math.floor(nowMs / 1000); },
    append(action = 'x', payload = {}) {
      return registry.appendAudit({ tenant_id: 't1', actor: 'k1', action, payload });
    }
  };
}

function vkeyText() {
  return anchor.vkeyOf(anchor.originOf(DEPLOY), anchor.anchorSigner(SEED).publicKeyRaw);
}

function note(fields = {}, seed = SEED) {
  const signer = anchor.anchorSigner(seed);
  return anchor.signNote(signer, { deployment: DEPLOY, seq: 3, head: 'aa'.repeat(32), time: T0, ...fields });
}

async function readAll(r) {
  const vkey = anchor.parseVkey(vkeyText());
  const bySink = {};
  for (const s of r.sinks) bySink[s.id] = await verify.readSink(s, vkey);
  return bySink;
}

// Hourly for n hours, with one row before each checkpoint.
async function runHours(r, n) {
  for (let i = 0; i < n; i += 1) {
    await r.append('x', { i });
    await r.anchor.tick();
    r.advance(HOUR);
  }
}

const codes = (out) => out.reasons.map((x) => x.code);

// --- signed note format --------------------------------------------------

test('a checkpoint note is C2SP signed-note shaped, names the linear chain, and verifies with the public key', () => {
  const text = note();
  const lines = text.split('\n');
  assert.equal(lines[0], 'systemapi.io/audit/prod-1');
  assert.equal(lines[1], '3');
  assert.equal(Buffer.from(lines[2], 'base64').toString('hex'), 'aa'.repeat(32));
  assert.equal(lines[3], 'chain sha256-linear-v2');
  assert.equal(lines[4], `time ${T0}`);
  assert.equal(lines[5], '');
  assert.match(lines[6], /^— systemapi\.io\/audit\/prod-1 [A-Za-z0-9+/]+=*$/);
  const parsed = anchor.parseNote(Buffer.from(text), anchor.parseVkey(vkeyText()));
  assert.deepEqual(parsed, { seq: 3, head: 'aa'.repeat(32), time: T0 });
});

test('a tampered note fails the signature: seq, head, time or origin changed', () => {
  const vkey = anchor.parseVkey(vkeyText());
  const text = note();
  const lines = text.split('\n');
  const tampered = [
    text.replace('\n3\n', '\n4\n'),
    text.replace(lines[2], Buffer.from('bb'.repeat(32), 'hex').toString('base64')),
    text.replace(`time ${T0}`, `time ${T0 + 1}`)
  ];
  for (const t of tampered) {
    assert.throws(() => anchor.parseNote(Buffer.from(t), vkey), { code: 'anchor_bad_signature' });
  }
  // Another origin: the layout check refuses it before any signature.
  assert.throws(() => anchor.parseNote(Buffer.from(text.replace('audit/prod-1\n', 'audit/prod-2\n')), vkey), { code: 'anchor_note_invalid' });
  // A flipped signature byte.
  const sig = Buffer.from(lines[6].split(' ')[2], 'base64');
  sig[10] ^= 1;
  const bad = text.replace(lines[6].split(' ')[2], sig.toString('base64'));
  assert.throws(() => anchor.parseNote(Buffer.from(bad), vkey), { code: 'anchor_bad_signature' });
});

test('a note signed by another key fails as a bad signature', () => {
  const vkey = anchor.parseVkey(vkeyText());
  assert.throws(() => anchor.parseNote(Buffer.from(note({}, 'ef'.repeat(32))), vkey), { code: 'anchor_bad_signature' });
});

test('oversized, garbage, non-UTF-8 and malformed notes are refused as invalid', () => {
  const vkey = anchor.parseVkey(vkeyText());
  const good = note();
  const bad = [
    Buffer.alloc(anchor.NOTE_MAX_BYTES + 1, 0x61),
    crypto.randomBytes(200),
    Buffer.from([0xff, 0xfe, 0x0a, 0x0a]),
    Buffer.alloc(0),
    Buffer.from(good.replace('\n\n', '\n')),
    Buffer.from(good.replace('chain sha256-linear-v2', 'chain sha256-merkle')),
    Buffer.from(good.replace('\n3\n', '\n03\n')),
    Buffer.from(good.replace(`time ${T0}\n`, `time ${T0}\nextra\n`)),
    Buffer.from(good.replace('\n3\n', '\n3\r\n')),
    Buffer.from(good.slice(0, -1)),
    Buffer.from(`${good}${'— x y\n'.repeat(9)}`)
  ];
  for (const b of bad) {
    assert.throws(() => anchor.parseNote(b, vkey), (err) => err.code === 'anchor_note_invalid' || err.code === 'anchor_bad_signature');
  }
  assert.throws(() => anchor.parseNote(Buffer.alloc(anchor.NOTE_MAX_BYTES + 1, 0x61), vkey), { code: 'anchor_note_invalid' });
  assert.throws(() => anchor.parseNote(crypto.randomBytes(200), vkey), { code: 'anchor_note_invalid' });
});

test('a malformed verifier key is refused', () => {
  const good = vkeyText();
  for (const v of ['', 'x', good.replace(/\+[0-9a-f]{8}\+/, '+00000000+'), good.replace('prod-1', 'Prod_1'), `${good}+x`]) {
    assert.throws(() => anchor.parseVkey(v), { code: 'vkey_invalid' });
  }
});

// --- configuration ---------------------------------------------------------

test('anchoring is off with nothing set, and on with seed, deployment and a sink', () => {
  assert.deepEqual(anchor.loadAnchorConfig({ SYSTEMAPI_ED25519_SEED: LEASE_SEED }), { enabled: false, reason: 'anchor_off' });
  const on = anchor.loadAnchorConfig(baseEnv());
  assert.equal(on.enabled, true);
  assert.equal(on.intervalS, 3600);
  assert.deepEqual(on.sinks.map((s) => s.id), ['sink1', 'sink2']);
  assert.equal(on.vkey, vkeyText());
});

test('the checkpoint seed equal to the lease seed (hex, PEM or the running key) is refused', () => {
  assert.equal(anchor.loadAnchorConfig(baseEnv({ SYSTEMAPI_ED25519_SEED: SEED })).reason, 'anchor_seed_reuses_lease_key');
  assert.equal(anchor.loadAnchorConfig(baseEnv({ SYSTEMAPI_ED25519_SEED: SEED.toUpperCase() })).reason, 'anchor_seed_reuses_lease_key');
  const pem = anchor.anchorSigner(SEED).privateKey.export({ format: 'pem', type: 'pkcs8' });
  const env = baseEnv({ SYSTEMAPI_SIGNING_KEY: pem });
  delete env.SYSTEMAPI_ED25519_SEED;
  assert.equal(anchor.loadAnchorConfig(env).reason, 'anchor_seed_reuses_lease_key');
  const running = anchor.anchorSigner(SEED).publicKeyRaw;
  const noLease = baseEnv();
  delete noLease.SYSTEMAPI_ED25519_SEED;
  assert.equal(anchor.loadAnchorConfig(noLease, { leasePublicKey: running }).reason, 'anchor_seed_reuses_lease_key');
});

test('a misconfiguration turns anchoring off with a fixed code and never logs the seed or a secret', () => {
  const cases = [
    [{ SYSTEMAPI_AUDIT_CHECKPOINT_SEED: undefined }, 'anchor_seed_missing'],
    [{ SYSTEMAPI_AUDIT_CHECKPOINT_SEED: `${SEED}0` }, 'anchor_seed_invalid'],
    [{ SYSTEMAPI_AUDIT_DEPLOYMENT: 'Prod 1' }, 'anchor_deployment_invalid'],
    [{ SYSTEMAPI_AUDIT_DEPLOYMENT: '../x' }, 'anchor_deployment_invalid'],
    [{ SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S: '299' }, 'anchor_interval_invalid'],
    [{ SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S: '86401' }, 'anchor_interval_invalid'],
    [{ SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S: '1e4' }, 'anchor_interval_invalid'],
    [{ SYSTEMAPI_ANCHOR_SINK1_BUCKET: undefined }, 'anchor_sink_invalid'],
    [{ SYSTEMAPI_ANCHOR_SINK1_ENDPOINT: 'http://storage.example.test' }, 'anchor_sink_invalid'],
    [{ SYSTEMAPI_ANCHOR_SINK1_ENDPOINT: 'https://u:p@storage.example.test' }, 'anchor_sink_invalid'],
    [{ SYSTEMAPI_ANCHOR_SINK2_ENDPOINT: 'https://storage.example.test' }, 'anchor_sink_invalid']
  ];
  for (const [patch, code] of cases) {
    const env = baseEnv(patch);
    for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
    const logs = [];
    const logger = { log: (m) => logs.push(m), warn: (m) => logs.push(m), error: (m) => logs.push(m) };
    assert.equal(anchor.createAnchor({ env, registry: new MemoryRegistry({}), logger }), null);
    assert.deepEqual(logs, [`[anchor] off: ${code}`]);
  }
  // Sink 2 alone, or no sink at all.
  const only2 = { SYSTEMAPI_AUDIT_CHECKPOINT_SEED: SEED, SYSTEMAPI_AUDIT_DEPLOYMENT: DEPLOY, ...sinkEnv(2) };
  assert.equal(anchor.loadAnchorConfig(only2).reason, 'anchor_sink_invalid');
  assert.equal(anchor.loadAnchorConfig({ SYSTEMAPI_AUDIT_CHECKPOINT_SEED: SEED, SYSTEMAPI_AUDIT_DEPLOYMENT: DEPLOY }).reason, 'anchor_sink_missing');
  // http is allowed only to a loopback store.
  assert.equal(anchor.loadAnchorConfig(baseEnv({ SYSTEMAPI_ANCHOR_SINK1_ENDPOINT: 'http://127.0.0.1:9000' })).enabled, true);
  // The enabled log line names the key fingerprint, not the seed or a secret.
  const logs = [];
  const on = anchor.createAnchor({ env: baseEnv(), registry: new MemoryRegistry({}), logger: { log: (m) => logs.push(m), error: (m) => logs.push(m) }, sinkFactory: (c) => memorySink(c.id) });
  assert.ok(on);
  const joined = logs.join('\n');
  assert.match(joined, /\[anchor\] on: deployment=prod-1 interval_s=3600 sinks=sink1,sink2 key sha256:[0-9a-f]{64}/);
  for (const secret of [SEED, LEASE_SEED, 'secret-1-value', 'secret-2-value']) assert.equal(joined.includes(secret), false);
});

// --- the anchor in the tick -------------------------------------------------

test('the tick writes one checkpoint per interval to every sink and records the per-sink status', async () => {
  const r = rig();
  await r.append();
  await r.append();
  const first = await r.anchor.checkpoint(false);
  assert.equal(first.seq, 2);
  assert.equal(first.head, r.registry.audit[1].row_hash);
  assert.equal(first.key, `checkpoints/prod-1/${'2'.padStart(19, '0')}-${T0}.note`);
  assert.deepEqual(first.sink_status, { sink1: 'ok', sink2: 'ok' });
  assert.deepEqual(r.registry.checkpoints[0].sink_status, { sink1: 'ok', sink2: 'ok' });
  for (const s of r.sinks) assert.equal(s.objects.get(first.key).body.toString(), first.note);
  r.advance(HOUR - 1);
  await r.anchor.tick();
  assert.equal(r.registry.checkpoints.length, 1);
  r.advance(1);
  await r.anchor.tick();
  assert.equal(r.registry.checkpoints.length, 2);
  // Unchanged head: a heartbeat at the same seq under its own key.
  assert.equal(r.registry.checkpoints[1].seq, 2);
  assert.equal(r.sinks[0].objects.size, 2);
});

test('a break-glass terminal start is anchored at once; other rows wait for the interval', async () => {
  const r = rig();
  await r.anchor.tick();
  r.advance(60);
  const plain = await r.append('terminal_start', { purpose: 'terminal:open' });
  r.anchor.noteAudit(plain);
  await r.anchor.tick();
  assert.equal(r.registry.checkpoints.length, 1);
  const bg = await r.append('terminal_start', { purpose: 'breakglass:open' });
  r.anchor.noteAudit(bg);
  await r.anchor.running;
  assert.equal(r.registry.checkpoints.length, 2);
  assert.equal(r.registry.checkpoints[1].seq, bg.seq);
  // Note times rise strictly, so a forced one in the same second gets its own key.
  const again = await r.append('terminal_start', { purpose: 'breakglass:open' });
  r.anchor.noteAudit(again);
  await r.anchor.running;
  const times = r.registry.checkpoints.map((c) => c.note_time);
  assert.ok(times[2] > times[1]);
  assert.equal(r.sinks[0].objects.size, 3);
});

test('a failing sink is recorded and does not block the other sink or the chain', async () => {
  const r = rig({ failSink2: true });
  await r.append();
  const cp = await r.anchor.checkpoint(false);
  assert.deepEqual(cp.sink_status, { sink1: 'ok', sink2: 'put_failed' });
  assert.deepEqual(r.registry.checkpoints[0].sink_status, { sink1: 'ok', sink2: 'put_failed' });
  assert.equal(r.sinks[0].objects.size, 1);
  assert.ok(r.logs.includes('[anchor] sink2 put failed: AccessDenied'));
  await r.append();
  assert.equal((await r.registry.verifyAudit()).ok, true);
});

test('a database failure during a checkpoint is logged as a code and writes nothing', async () => {
  const r = rig();
  r.registry.createAuditCheckpoint = async () => { throw Object.assign(new Error(`password ${SEED}`), { code: '57014' }); };
  assert.equal(await r.anchor.checkpoint(false), null);
  assert.deepEqual(r.logs, ['[anchor] checkpoint failed: db_error 57014']);
  assert.equal(r.sinks[0].objects.size, 0);
});

test('the S3 adapter sends plain PutObject with Content-MD5 and no Object Lock headers', async () => {
  const sent = [];
  const client = { async send(cmd, opts) { sent.push({ name: cmd.constructor.name, input: cmd.input, opts }); return { Contents: [{ Key: 'k', Size: 5, LastModified: new Date(0) }], IsTruncated: false, Body: { transformToByteArray: async () => new Uint8Array([1]) } }; } };
  const cfg = anchor.loadAnchorConfig(baseEnv()).sinks[0];
  const sink = anchor.s3Sink(cfg, { client });
  await sink.put('checkpoints/prod-1/x.note', 'hello\n');
  await sink.list('checkpoints/prod-1/');
  await sink.get('k');
  assert.deepEqual(sent.map((s) => s.name), ['PutObjectCommand', 'ListObjectsV2Command', 'GetObjectCommand']);
  const put = sent[0].input;
  assert.equal(put.Bucket, 'audit-anchors');
  assert.equal(put.ContentMD5, crypto.createHash('md5').update('hello\n').digest('base64'));
  assert.equal(Object.keys(put).some((k) => /ObjectLock|Retention|LegalHold/i.test(k)), false);
  assert.equal(sent[2].input.Range, `bytes=0-${anchor.NOTE_MAX_BYTES}`);
  for (const s of sent) assert.ok(s.opts.abortSignal);
});

// --- verifyRows heads_at -----------------------------------------------------

test('verifyRows reports heads_at for asked seqs in one pass, and is unchanged without it', async () => {
  const r = rig();
  for (let i = 0; i < 4; i += 1) await r.append('x', { i });
  const rows = r.registry.audit;
  assert.deepEqual(verifyRows(rows, []), { ok: true, head: rows[3].row_hash });
  assert.deepEqual(verifyRows(rows, [], { headsAt: [0, 2, 4, 9] }), {
    ok: true, head: rows[3].row_hash, heads_at: { 0: GENESIS, 2: rows[1].row_hash, 4: rows[3].row_hash }
  });
  const broken = rows.map((x) => ({ ...x }));
  broken[2].payload = { i: 99 };
  assert.deepEqual(verifyRows(broken, [], { headsAt: [1, 3, 4] }), { ok: false, broken_at: 3, heads_at: { 1: rows[0].row_hash } });
});

// --- the off-box verifier ------------------------------------------------------

test('the verifier passes a clean chain anchored every hour on both sinks', async () => {
  const r = rig();
  await runHours(r, 5);
  const out = verify.check({ bySink: await readAll(r), rows: r.registry.audit, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.deepEqual(out, { ok: true, max_seq: 5, anchors: 10, reasons: [], acked: 0, acked_reasons: [] });
});

test('a row rewritten after it was anchored (and the chain recomputed) is anchor_rewrite', async () => {
  const r = rig();
  await runHours(r, 4);
  // A DB writer edits seq 2 and re-chains every later row: the chain alone verifies.
  const rows = r.registry.audit.map((x) => ({ ...x }));
  rows[1].payload = { i: 'edited' };
  for (let i = 1; i < rows.length; i += 1) {
    rows[i].prev_hash = rows[i - 1].row_hash;
    rows[i].row_hash = rowHash(rows[i].prev_hash, rows[i]);
  }
  assert.equal(verifyRows(rows, []).ok, true);
  const out = verify.check({ bySink: await readAll(r), rows, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.equal(out.ok, false);
  assert.deepEqual([...new Set(codes(out))], ['anchor_rewrite']);
  assert.deepEqual([...new Set(out.reasons.map((x) => x.seq))].sort(), [2, 3, 4]);
});

test('a truncated chain tail is anchor_truncation', async () => {
  const r = rig();
  await runHours(r, 4);
  const out = verify.check({ bySink: await readAll(r), rows: r.registry.audit.slice(0, 2), cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.deepEqual([...new Set(codes(out))], ['anchor_truncation']);
  assert.deepEqual([...new Set(out.reasons.map((x) => x.seq))].sort(), [3, 4]);
});

test('a missing anchor window, a stale last anchor, or no anchors at all is anchor_gap', async () => {
  const r = rig();
  await runHours(r, 2);
  r.advance(2 * HOUR + 1);
  await runHours(r, 2);
  const mid = verify.check({ bySink: await readAll(r), rows: r.registry.audit, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.deepEqual(codes(mid), ['anchor_gap', 'anchor_gap']);
  // Anchoring stopped: the last anchor is more than 2x the cadence old.
  const stale = verify.check({ bySink: await readAll(r), rows: r.registry.audit, cadenceS: HOUR, nowS: r.nowS() + 3 * HOUR, forks: [] });
  assert.equal(codes(stale).filter((c) => c === 'anchor_gap').length, 4);
  const none = verify.check({ bySink: { sink1: { notes: [], reasons: [] } }, rows: r.registry.audit, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.deepEqual(codes(none), ['anchor_gap']);
});

test('a forged, tampered or misnamed note in a sink is reported, and the sinks must agree', async () => {
  const r = rig();
  await runHours(r, 3);
  const [s1, s2] = r.sinks;
  const keys = [...s1.objects.keys()];
  // Tampered body (head changed, signature kept).
  const t = s1.objects.get(keys[0]);
  const lines = t.body.toString().split('\n');
  lines[2] = Buffer.from('ee'.repeat(32), 'hex').toString('base64');
  t.body = Buffer.from(lines.join('\n'));
  // A note signed by another key, at a fresh key.
  s1.objects.set(anchor.objectKey(DEPLOY, 1, T0 + 5), { body: Buffer.from(note({ seq: 1, time: T0 + 5 }, 'ef'.repeat(32))), lastModified: new Date((T0 + 5) * 1000) });
  // A valid note stored under the wrong key.
  s1.objects.set(anchor.objectKey(DEPLOY, 2, T0 + 6), { body: Buffer.from(s1.objects.get(keys[1]).body), lastModified: new Date((T0 + 6) * 1000) });
  // Garbage and an oversized object.
  s1.objects.set(anchor.objectKey(DEPLOY, 9, T0 + 7), { body: crypto.randomBytes(64), lastModified: new Date((T0 + 7) * 1000) });
  s1.objects.set(anchor.objectKey(DEPLOY, 9, T0 + 8), { body: Buffer.alloc(5000, 0x61), lastModified: new Date((T0 + 8) * 1000) });
  s1.objects.set('checkpoints/prod-1/not-a-note.txt', { body: Buffer.from('x'), lastModified: new Date(T0 * 1000) });
  // Sink 2 holds a validly signed note with another head for seq 3 (a forged
  // backfill by a seed holder), with a signed time far from its LastModified.
  const forged = note({ seq: 3, head: 'dd'.repeat(32), time: T0 + 2 * HOUR + 10 });
  s2.objects.set(anchor.objectKey(DEPLOY, 3, T0 + 2 * HOUR + 10), { body: Buffer.from(forged), lastModified: new Date((T0 + 9 * HOUR) * 1000) });
  const out = verify.check({ bySink: await readAll(r), rows: r.registry.audit, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  const c = codes(out);
  assert.equal(c.filter((x) => x === 'anchor_bad_signature').length, 2);
  assert.equal(c.filter((x) => x === 'anchor_note_invalid').length, 4);
  assert.ok(c.includes('anchor_time_mismatch'));
  assert.ok(c.includes('anchor_sink_mismatch'));
  assert.deepEqual(out.reasons.filter((x) => x.code === 'anchor_rewrite').map((x) => [x.sink, x.seq]), [['sink2', 3]]);
});

test('a later anchor naming a lower seq is anchor_seq_regression', async () => {
  const r = rig();
  await runHours(r, 2);
  const s1 = r.sinks[0];
  const t = T0 + 2 * HOUR;
  s1.objects.set(anchor.objectKey(DEPLOY, 1, t), { body: Buffer.from(note({ seq: 1, head: r.registry.audit[0].row_hash, time: t })), lastModified: new Date(t * 1000) });
  const out = verify.check({ bySink: { sink1: await verify.readSink(s1, anchor.parseVkey(vkeyText())) }, rows: r.registry.audit, cadenceS: HOUR, nowS: t, forks: [] });
  assert.deepEqual(codes(out), ['anchor_seq_regression']);
});

test('the known production fork is still accepted when anchored around it', () => {
  const rows = [];
  let prev = GENESIS;
  for (let seq = 1; seq <= 3; seq += 1) {
    const r = { seq, prev_hash: prev, tenant_id: 't', host_id: null, actor: 'a', action: 'x', payload: { seq } };
    r.row_hash = rowHash(prev, r);
    rows.push(r);
    prev = r.row_hash;
  }
  const r4 = { seq: 4, prev_hash: rows[2].row_hash, tenant_id: 't', host_id: null, actor: 'a', action: 'tcp_end', payload: {} };
  r4.row_hash = rowHash(r4.prev_hash, r4);
  const r5 = { seq: 5, prev_hash: rows[2].row_hash, tenant_id: 't', host_id: null, actor: 'a', action: 'ticket_issued', payload: {} };
  r5.row_hash = rowHash(r5.prev_hash, r5);
  rows.push(r4, r5);
  const forks = [{ seq: 5, prev_hash: r5.prev_hash, row_hash: r5.row_hash, sibling_seq: 4, sibling_row_hash: r4.row_hash }];
  const notes = [{ key: 'a', seq: 3, head: rows[2].row_hash, time: T0 }, { key: 'b', seq: 5, head: r5.row_hash, time: T0 + HOUR }];
  const out = verify.check({ bySink: { sink1: { notes, reasons: [] } }, rows, cadenceS: HOUR, nowS: T0 + HOUR, forks });
  assert.deepEqual(out.reasons, []);
  assert.deepEqual(verify.check({ bySink: { sink1: { notes, reasons: [] } }, rows, cadenceS: HOUR, nowS: T0 + HOUR, forks: [] }).reasons.map((x) => x.code), ['chain_broken']);
});

test('run reads a JSON export, honors --sink and --now, and refuses a bad export or no row source', async () => {
  const r = rig();
  await runHours(r, 3);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-'));
  const file = path.join(dir, 'audit.json');
  fs.writeFileSync(file, JSON.stringify(r.registry.audit.map(({ created_at, ...rest }) => rest)));
  const env = { SYSTEMAPI_ANCHOR_VKEY: vkeyText() };
  const now = String(r.nowS());
  const ok = await verify.run(['--export', file, '--now', now], { env, sinks: r.sinks });
  assert.equal(ok.ok, true);
  assert.equal(ok.anchors, 6);
  const one = await verify.run(['--export', file, '--now', now, '--sink', 'sink2'], { env, sinks: r.sinks });
  assert.equal(one.anchors, 3);
  // An export older than the newest notes: --now set to its time skips them.
  fs.writeFileSync(file, JSON.stringify(r.registry.audit.slice(0, 2)));
  const older = await verify.run(['--export', file, '--now', String(T0 + HOUR)], { env, sinks: r.sinks });
  assert.equal(older.ok, true);
  assert.equal(older.anchors, 4);
  const truncated = await verify.run(['--export', file, '--now', now], { env, sinks: r.sinks });
  assert.ok(codes(truncated).includes('anchor_truncation'));
  fs.writeFileSync(file, '{"rows": [{"seq": "x"}]}');
  await assert.rejects(verify.run(['--export', file], { env, sinks: r.sinks }), { code: 'export_invalid' });
  fs.writeFileSync(file, 'not json');
  await assert.rejects(verify.run(['--export', file], { env, sinks: r.sinks }), { code: 'export_invalid' });
  await assert.rejects(verify.run([], { env, sinks: r.sinks }), { code: 'usage' });
  await assert.rejects(verify.run(['--export', file, '--sink', 'sink3'], { env, sinks: r.sinks }), { code: 'usage' });
  await assert.rejects(verify.run(['--export', file, '--cadence-s', '60'], { env, sinks: r.sinks }), { code: 'usage' });
  await assert.rejects(verify.run(['--export', file], { env: {}, sinks: r.sinks }), { code: 'usage' });
  await assert.rejects(verify.run(['--export', file], { env: { SYSTEMAPI_ANCHOR_VKEY: 'nope' }, sinks: r.sinks }), { code: 'vkey_invalid' });
  const down = { id: 'sink1', async list() { throw new Error('ECONNREFUSED'); } };
  fs.writeFileSync(file, '[]');
  await assert.rejects(verify.run(['--export', file], { env, sinks: [down] }), { code: 'sink_unavailable' });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the verifier CLI exits 2 with a code only, and never echoes a credential', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-'));
  const file = path.join(dir, 'audit.json');
  fs.writeFileSync(file, '[]');
  const env = { PATH: process.env.PATH, SYSTEMAPI_ANCHOR_VKEY: vkeyText(), ...sinkEnv(1, { SYSTEMAPI_ANCHOR_SINK1_ENDPOINT: 'http://example.test' }) };
  const res = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'audit-anchor-verify.js'), '--export', file], { env, encoding: 'utf8' });
  assert.equal(res.status, 2);
  assert.equal(res.stdout, '');
  assert.equal(res.stderr, 'sink_config_invalid\n');
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- the public-key script -------------------------------------------------------

test('audit-checkpoint-pubkey prints only the verifier key, and never the seed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-'));
  const envFile = path.join(dir, 'env');
  fs.writeFileSync(envFile, '');
  const script = path.join(ROOT, 'scripts', 'audit-checkpoint-pubkey.js');
  const base = { PATH: process.env.PATH, ENV_FILE: envFile };
  const ok = spawnSync(process.execPath, [script], { env: { ...base, SYSTEMAPI_AUDIT_CHECKPOINT_SEED: SEED, SYSTEMAPI_AUDIT_DEPLOYMENT: DEPLOY }, encoding: 'utf8' });
  assert.equal(ok.status, 0);
  assert.equal(ok.stdout, `${vkeyText()}\n`);
  assert.equal(ok.stderr, '');
  const seedB64 = Buffer.from(SEED, 'hex').toString('base64');
  for (const out of [ok.stdout, ok.stderr]) {
    assert.equal(out.toLowerCase().includes(SEED), false);
    assert.equal(out.includes(seedB64), false);
  }
  // The printed key verifies a note signed with the seed.
  assert.deepEqual(anchor.parseNote(Buffer.from(note()), anchor.parseVkey(ok.stdout.trim())).seq, 3);
  const badSeed = `${SEED.slice(0, 63)}z`;
  const bad = spawnSync(process.execPath, [script], { env: { ...base, SYSTEMAPI_AUDIT_CHECKPOINT_SEED: badSeed, SYSTEMAPI_AUDIT_DEPLOYMENT: DEPLOY }, encoding: 'utf8' });
  assert.equal(bad.status, 2);
  assert.equal(bad.stdout, '');
  assert.equal(bad.stderr, 'anchor_seed_invalid\n');
  const badDep = spawnSync(process.execPath, [script], { env: { ...base, SYSTEMAPI_AUDIT_CHECKPOINT_SEED: SEED, SYSTEMAPI_AUDIT_DEPLOYMENT: 'Bad Dep' }, encoding: 'utf8' });
  assert.equal(badDep.status, 2);
  assert.equal(badDep.stderr, 'anchor_deployment_invalid\n');
  assert.equal(badDep.stderr.includes(SEED), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- review follow-ups ------------------------------------------------------------

test('two break-glass starts right after a periodic checkpoint give three checkpoints', async () => {
  const r = rig();
  await r.append();
  await r.anchor.tick();
  for (let i = 0; i < 2; i += 1) {
    const bg = await r.append('terminal_start', { purpose: 'breakglass:open' });
    r.anchor.noteAudit(bg);
    await r.anchor.running;
  }
  assert.equal(r.registry.checkpoints.length, 3);
  const times = r.registry.checkpoints.map((c) => c.note_time);
  assert.deepEqual(times, [T0, T0 + 1, T0 + 2]);
  assert.equal(r.sinks[0].objects.size, 3);
});

test('a last checkpoint far in the future does not stall anchoring; keys stay unique', async () => {
  const r = rig();
  await r.append();
  await r.anchor.tick();
  // A clock that ran a day ahead wrote one checkpoint.
  r.registry.checkpoints.push({ ...r.registry.checkpoints[0], id: 2, note_time: T0 + 86400, sink_status: {} });
  r.advance(HOUR);
  await r.append();
  await r.anchor.tick();
  assert.equal(r.registry.checkpoints.length, 3);
  const fresh = r.registry.checkpoints[2];
  assert.equal(fresh.note_time, r.nowS());
  assert.ok(r.logs.includes('[anchor] last_checkpoint_in_future'));
  // The next tick is the normal interval rule again.
  r.advance(60);
  await r.anchor.tick();
  assert.equal(r.registry.checkpoints.length, 3);
  // The clock repeats a sane second: the time is one past the newest sane note.
  r.registry.checkpoints.push({ ...fresh, id: 4, note_time: T0 + 86400, sink_status: {} });
  r.advance(-120);
  await r.anchor.tick();
  assert.equal(r.registry.checkpoints[4].note_time, fresh.note_time + 1);
  assert.equal(new Set(r.registry.checkpoints.map((c) => `${c.seq}-${c.note_time}`)).size, 5);
});

test('a failed put is retried under the same key inside the window, and not after it', async () => {
  const r = rig({ failSink2: true });
  await r.append();
  const cp = await r.anchor.checkpoint(false);
  assert.deepEqual(r.registry.checkpoints[0].sink_status, { sink1: 'ok', sink2: 'put_failed' });
  r.advance(30);
  await r.anchor.tick();
  assert.equal(r.sinks[1].objects.size, 0);
  r.sinks[1].failPut = false;
  r.advance(30);
  await r.anchor.tick();
  assert.deepEqual([...r.sinks[1].objects.keys()], [cp.key]);
  assert.equal(r.sinks[1].objects.get(cp.key).body.toString(), cp.note);
  assert.deepEqual(r.registry.checkpoints[0].sink_status, { sink1: 'ok', sink2: 'ok' });
  const putsOk = r.sinks[0].puts;
  await r.anchor.tick();
  assert.equal(r.sinks[0].puts, putsOk, 'an ok sink is never re-put');
  // Past the window: no late put that the verifier would call backdated.
  const late = rig({ failSink2: true });
  await late.append();
  await late.anchor.checkpoint(false);
  late.sinks[1].failPut = false;
  late.advance(560);
  await late.anchor.tick();
  assert.equal(late.sinks[1].objects.size, 0);
  assert.equal(late.registry.checkpoints[0].sink_status.sink2, 'put_failed');
});

test('one missed checkpoint with 30 s ticks stays inside the gap rule (2x cadence + slack)', async () => {
  const r = rig();
  await r.append();
  for (let t = 0; t < 5 * HOUR; t += 30) {
    // Sink 2 is down from 1h55m to 2h15m, past the retry window of the 2h note.
    r.sinks[1].failPut = t >= HOUR + 55 * 60 && t < 2 * HOUR + 15 * 60;
    if (t % 600 === 0) await r.append('x', { t });
    await r.anchor.tick();
    r.advance(30);
  }
  const bySink = await readAll(r);
  const times = bySink.sink2.notes.map((n) => n.time).sort((a, b) => a - b);
  const maxGap = Math.max(...times.slice(1).map((t, i) => t - times[i]));
  assert.ok(maxGap >= 2 * HOUR, `gap ${maxGap}`);
  const out = verify.check({ bySink, rows: r.registry.audit, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.deepEqual(out.reasons.filter((x) => x.code !== 'anchor_sink_mismatch'), []);
  assert.deepEqual(out.reasons.map((x) => [x.code, x.sink]), [['anchor_sink_mismatch', 'sink2']]);
  // The slack: 7201 s apart is fine, 2x cadence + 301 is not.
  const mk = (times2) => ({ sink1: { notes: times2.map((t, i) => ({ key: `k${i}`, seq: 1, head: r.registry.audit[0].row_hash, time: t })), reasons: [] } });
  const rows1 = r.registry.audit.slice(0, 1);
  assert.deepEqual(verify.check({ bySink: mk([T0, T0 + 7201]), rows: rows1, cadenceS: HOUR, nowS: T0 + 7201, forks: [] }).reasons, []);
  assert.deepEqual(codes(verify.check({ bySink: mk([T0, T0 + 2 * HOUR + verify.GAP_SLACK_S + 1]), rows: rows1, cadenceS: HOUR, nowS: T0 + 3 * HOUR, forks: [] })), ['anchor_gap']);
});

test('a key in one sink and missing from the other is anchor_sink_mismatch once past the skew window', async () => {
  const r = rig();
  await runHours(r, 3);
  const [first] = [...r.sinks[1].objects.keys()];
  r.sinks[1].objects.delete(first);
  const out = verify.check({ bySink: await readAll(r), rows: r.registry.audit, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.deepEqual(out.reasons, [{ code: 'anchor_sink_mismatch', sink: 'sink2', key: first }]);
  // A key only seconds old is not judged yet (its put may still be retried).
  const fresh = rig({ failSink2: true });
  await fresh.append();
  await fresh.anchor.checkpoint(false);
  const recent = verify.check({ bySink: await readAll(fresh), rows: fresh.registry.audit, cadenceS: HOUR, nowS: fresh.nowS() + 60, forks: [] });
  assert.equal(codes(recent).includes('anchor_sink_mismatch'), false);
});

test('after chain_broken an anchored head is still compared with the stored row_hash', async () => {
  const r = rig();
  await runHours(r, 4);
  const rows = r.registry.audit.map((x) => ({ ...x }));
  rows[1].payload = { i: 'edited' };
  rows[3].row_hash = 'ff'.repeat(32);
  const out = verify.check({ bySink: await readAll(r), rows, cadenceS: HOUR, nowS: r.nowS(), forks: [] });
  assert.deepEqual([...new Set(out.reasons.map((x) => `${x.code}:${x.seq}`))], ['chain_broken:2', 'anchor_rewrite:4']);
});

test('a note listed without LastModified is anchor_note_invalid', async () => {
  const r = rig();
  await runHours(r, 1);
  const s1 = r.sinks[0];
  const list = s1.list.bind(s1);
  s1.list = async (prefix) => (await list(prefix)).map((o) => ({ ...o, lastModified: null }));
  const read = await verify.readSink(s1, anchor.parseVkey(vkeyText()));
  assert.deepEqual(read.reasons.map((x) => x.code), ['anchor_note_invalid']);
  assert.equal(read.notes.length, 0);
});

test('a listing over the object cap is its own exit-2 code', async () => {
  const r = rig();
  const big = { id: 'sink1', async list() { throw anchor.anchorError('sink_list_too_large'); } };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-'));
  const file = path.join(dir, 'audit.json');
  fs.writeFileSync(file, '[]');
  await assert.rejects(verify.run(['--export', file], { env: { SYSTEMAPI_ANCHOR_VKEY: vkeyText() }, sinks: [big] }), { code: 'sink_list_too_large' });
  void r;
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--ack keeps reviewed alarms reported but passing, and --since skips notes before a cut-off', async () => {
  const r = rig();
  await runHours(r, 4);
  const s1 = r.sinks[0];
  const junkKey = anchor.objectKey(DEPLOY, 9, T0 + 5);
  s1.objects.set(junkKey, { body: crypto.randomBytes(40), lastModified: new Date((T0 + 5) * 1000) });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-'));
  const file = path.join(dir, 'audit.json');
  const ackFile = path.join(dir, 'ack.json');
  fs.writeFileSync(file, JSON.stringify(r.registry.audit));
  const env = { SYSTEMAPI_ANCHOR_VKEY: vkeyText() };
  const now = String(r.nowS());
  const failing = await verify.run(['--export', file, '--now', now], { env, sinks: r.sinks });
  assert.equal(failing.ok, false);
  assert.deepEqual(failing.reasons.map((x) => x.code).sort(), ['anchor_note_invalid', 'anchor_sink_mismatch']);
  fs.writeFileSync(ackFile, JSON.stringify([
    { code: 'anchor_note_invalid', sink: 'sink1', key: junkKey, why: 'test junk, reviewed 2026-11-05' },
    { code: 'anchor_sink_mismatch', sink: 'sink2', key: junkKey, why: 'same junk, sink1 only' }
  ]));
  const ackedRun = await verify.run(['--export', file, '--now', now, '--ack', ackFile], { env, sinks: r.sinks });
  assert.equal(ackedRun.ok, true);
  assert.equal(ackedRun.acked, 2);
  assert.deepEqual(ackedRun.reasons, []);
  // An ack for another key does not hide a new alarm.
  fs.writeFileSync(ackFile, JSON.stringify([{ code: 'anchor_note_invalid', sink: 'sink1', key: 'other', why: 'x' }]));
  assert.equal((await verify.run(['--export', file, '--now', now, '--ack', ackFile], { env, sinks: r.sinks })).ok, false);
  // Malformed ack files are refused.
  for (const bad of ['nope', '{}', '[{"code":"anchor_gap","why":"x"}]', '[{"code":"made_up","seq":1,"why":"x"}]',
    '[{"code":"anchor_gap","seq":1,"why":""}]', '[{"code":"anchor_gap","seq":1,"key":"k","why":"x"}]', '[{"code":"anchor_gap","sink":"sink9","seq":1,"why":"x"}]']) {
    fs.writeFileSync(ackFile, bad);
    await assert.rejects(verify.run(['--export', file, '--ack', ackFile], { env, sinks: r.sinks }), { code: 'ack_invalid' });
  }
  // --since after the junk: it is not fetched or judged, and the gap rule
  // runs from the cut-off.
  const since = await verify.run(['--export', file, '--now', now, '--since', String(T0 + HOUR)], { env, sinks: r.sinks });
  assert.equal(since.ok, true);
  assert.equal(since.anchors, 6);
  const lateSince = await verify.run(['--export', file, '--now', String(T0 + 6 * HOUR), '--since', String(T0 + 4 * HOUR - 1)], { env, sinks: r.sinks });
  assert.ok(codes(lateSince).includes('anchor_gap'));
  await assert.rejects(verify.run(['--export', file, '--now', now, '--since', String(r.nowS() + 1)], { env, sinks: r.sinks }), { code: 'usage' });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('production refuses to boot with a set but invalid anchoring config; elsewhere it logs and stays off', () => {
  const registry = new MemoryRegistry({});
  const bad = [
    [baseEnv({ SYSTEMAPI_ED25519_SEED: SEED }), 'anchor_seed_reuses_lease_key'],
    [baseEnv({ SYSTEMAPI_AUDIT_DEPLOYMENT: 'Bad' }), 'anchor_deployment_invalid'],
    [baseEnv({ SYSTEMAPI_ANCHOR_SINK1_BUCKET: '' }), 'anchor_sink_invalid']
  ];
  for (const [env, code] of bad) {
    assert.throws(() => anchor.createAnchor({ env: { ...env, NODE_ENV: 'production' }, registry, logger: quiet }), (err) => {
      assert.equal(err.code, code);
      assert.equal(String(err.message).includes(SEED), false);
      return true;
    });
    assert.equal(anchor.createAnchor({ env, registry, logger: quiet }), null);
  }
  assert.throws(() => anchor.createAnchor({ env: { ...baseEnv(), NODE_ENV: 'production' }, registry: null, logger: quiet }), { code: 'registry_unavailable' });
  assert.equal(anchor.createAnchor({ env: { NODE_ENV: 'production', SYSTEMAPI_ED25519_SEED: LEASE_SEED }, registry, logger: quiet }), null);
  assert.ok(anchor.createAnchor({ env: { ...baseEnv(), NODE_ENV: 'production' }, registry, logger: quiet, sinkFactory: (c) => memorySink(c.id) }));
});
