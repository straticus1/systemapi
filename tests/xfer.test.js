'use strict';

// sahxfer grant (sahxfer docs/design.md §3, playground/xfer.js): client HTTP
// -> control plane -> fake agent on the agent stream. The data plane, the
// relay and the agent helper are not here.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { verifyLease, xferPayload, xferMaterial } = require('../controlplane/lease');
const { parseGrantRequest, directAllowList, directPeer } = require('../playground/xfer');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));
const POLICY = { roots: [{ path: '/srv/a', read: true, write: true }, { path: '/srv/b', read: true, write: false }, { path: '/etc', read: true, write: true, root: true }] };
const SHA = 'ab'.repeat(32);
const PEER = '203.0.113.10:4700';
const OPERATOR_SCOPES = ['hosts:read', 'file:read', 'file:write'];

function signer() {
  const key = privateKeyFromSeed(TEST_SEED);
  return buildSigner(key, rawPublicKey(key));
}

function opensshEd25519(raw32) {
  const name = Buffer.from('ssh-ed25519');
  const buf = Buffer.alloc(4 + name.length + 4 + 32);
  buf.writeUInt32BE(name.length, 0);
  name.copy(buf, 4);
  buf.writeUInt32BE(32, 4 + name.length);
  raw32.copy(buf, 4 + name.length + 4);
  return `ssh-ed25519 ${buf.toString('base64')} test@systemapi`;
}

async function waitUntil(what, fn, timeout = 4000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

// API keys: agent-key enrolls; op-key and admin-key are user-1's client keys
// (user-1 is admin of acme, so a key's own scopes decide).
const KEYS = { 'agent-key': 'k-agent', 'op-key': 'k-op', 'admin-key': 'k-admin', 'read-key': 'k-read' };

async function rig(env = { SYSTEMAPI_XFER_PEER_UDP: PEER }) {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test', ...env };
  fm.signer = signer();
  fm.tickets = new Map();
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.auditRetryDelaysMs = [10, 10];
  fm.xfer.readyTimeoutMs = 300;
  fm.xfer.tombstoneMs = 200;
  fm.verifyApiKey = async (key) => (KEYS[key] ? { key_id: KEYS[key], user_id: 'user-1' } : null);
  mount(app, fm);
  await fm.registry.setScopes('k-op', OPERATOR_SCOPES);
  await fm.registry.setScopes('k-admin', ['admin']);
  await fm.registry.setScopes('k-read', ['hosts:read', 'file:read']);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const sockets = [];
  return {
    fm,
    url: `http://127.0.0.1:${port}`,
    ws: `ws://127.0.0.1:${port}`,
    track(ws) { sockets.push(ws); return ws; },
    async close() {
      for (const ws of sockets) if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.terminate();
      for (const g of [...fm.xfer.grants.values()]) await fm.xfer.end(g, 'aborted', { error: 'stopped' });
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

// The fake agent answers xfer_grant with `reply` (a payload, or null for
// silence) after checking that the intent row is already on record.
async function connectAgent(r, { caps = 'pty,tcp,file,xfer', hostId = HOST_A, tenant = 'acme', policy = POLICY, reply = { status: 'ready' } } = {}) {
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': tenant,
      'x-systemapi-host-id': hostId,
      'x-systemapi-hostname': `${hostId.slice(0, 4)}.example`,
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      ...(caps === null ? {} : { 'x-systemapi-capabilities': caps })
    }
  }));
  const agent = { ws, frames: [], intentBeforeGrant: [], reply };
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const f = JSON.parse(data.toString());
    agent.frames.push(f);
    if (f.type === 'xfer_grant') {
      agent.intentBeforeGrant.push(r.fm.registry.audit.some((row) => row.action === 'xfer_intent' && row.payload.grant_id === f.grant_id));
      if (agent.reply) ws.send(JSON.stringify({ type: 'xfer_status', grant_id: f.grant_id, payload: agent.reply }));
    }
  });
  ws.on('error', () => {});
  await waitUntil('enrolled', () => agent.frames.find((f) => f.type === 'enrolled'));
  if (policy) await r.fm.registry.setHostChannelPolicy(hostId, { file_policy: policy });
  return agent;
}

function frames(agent, type) {
  return agent.frames.filter((f) => f.type === type);
}

function body(over = {}) {
  return {
    host_id: HOST_A, purpose: 'xfer:put', dir: 'put', root: '/srv/a', path: 'releases/app.tar.gz',
    size: 123456789, sha256: SHA, overwrite: false, transport: 'udp', ...over
  };
}

async function grant(r, over = {}, headers = { 'x-api-key': 'op-key' }) {
  const res = await fetch(`${r.url}/api/v1/xfer/grant`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(typeof over === 'string' ? over : body(over))
  });
  const text = await res.text();
  let parsed = text;
  try { parsed = JSON.parse(text); } catch { /* text */ }
  return { status: res.status, body: parsed, headers: res.headers };
}

function rows(r, action) {
  return r.fm.registry.audit.filter((row) => row.action === action);
}

// The 18 payload fields the agent rebuilds from an xfer_grant frame, the
// way systemapi-agent does before it verifies the lease.
function fieldsFromFrame(push, phase = 'start', deadlineUnix = push.deadline_unix) {
  return {
    grantId: push.grant_id, deadlineUnix, phase, dir: push.dir, root: push.root, path: push.path, size: push.size,
    sha256: push.sha256, overwrite: push.overwrite, transferId: push.transfer_id, expiresUnix: push.expires_unix,
    idleS: push.idle_s, maxS: push.max_s, byteCap: push.byte_cap, profile: push.profile, transport: push.transport,
    peer: push.peer, material: xferMaterial(Buffer.from(push.key, 'base64'), Buffer.from(push.route_token, 'base64'))
  };
}

// One changed value per field; each must break the lease.
const TAMPER = {
  grantId: 'xfr_tamperedAAAAAAAA', deadlineUnix: (v) => v + 1, phase: (v) => (v === 'start' ? 'renew' : 'start'), dir: 'get',
  root: '/srv/b', path: 'releases/other.tar.gz', size: (v) => v - 1, sha256: 'cd'.repeat(32), overwrite: (v) => !v,
  transferId: 'fedcba9876543210', expiresUnix: (v) => v + 1, idleS: (v) => v + 1, maxS: (v) => v - 1, byteCap: (v) => v + 1,
  profile: 'dc', transport: 'udp', peer: (v) => (v === 'listen' ? 'dial:198.51.100.1:4700' : 'listen'), material: 'ef'.repeat(32)
};

function assertEveryFieldBound(lease, fields) {
  assert.equal(verifyLease(PUBLIC_KEY, lease, xferPayload(fields)).ok, true);
  for (const [k, change] of Object.entries(TAMPER)) {
    if (k === 'transport') continue; // only udp is signable in v1; covered by the builder refusal
    const v = typeof change === 'function' ? change(fields[k]) : change;
    assert.notDeepEqual(v, fields[k], k);
    const res = verifyLease(PUBLIC_KEY, lease, xferPayload({ ...fields, [k]: v }));
    assert.equal(res.ok, false, k);
    assert.equal(res.error, 'payload_mismatch', k);
  }
}

test('request shapes: design §3.2 path, root, size, hash and transport rules', () => {
  const ok = parseGrantRequest(body());
  assert.equal(ok.ok, true);
  assert.equal(ok.request.transport, 'udp');
  assert.equal(parseGrantRequest(body({ transport: undefined })).request.transport, 'udp');
  assert.equal(parseGrantRequest(body({ size: 0 })).ok, true);
  const err = (over, env) => {
    const out = parseGrantRequest(over === null ? null : body(over), env);
    return out.ok ? 'ok' : `${out.status} ${out.error}`;
  };
  assert.equal(err(null), '400 bad_request');
  for (const over of [{ purpose: 'xfer:everything' }, { purpose: 'file:write' }, { dir: 'get' }, { purpose: 'xfer:get', dir: 'put' }, { purpose: 'xfer:root', dir: 'both' }]) {
    assert.equal(err(over), '400 bad_purpose', JSON.stringify(over));
  }
  for (const root of ['~', 'srv/a', '/srv/../etc', '/srv/a/', '', null, '/srv/\u0000a']) assert.equal(err({ root }), '400 bad_root', JSON.stringify(root));
  for (const path of ['../x', '/etc/shadow', '.', '', 'a//b', 'a/./b', 'a\\b', 17]) assert.equal(err({ path }), '400 bad_path', JSON.stringify(path));
  for (const path of ['.sahxfer-xfr_1.part', 'd/.sahxfer-a.part', 'd/.sahsync-a.part']) assert.equal(err({ path }), '400 reserved_name', path);
  assert.equal(err({ size: 2 ** 63 }), '413 too_large');
  assert.equal(err({ size: 11 }, { SYSTEMAPI_XFER_MAX_BYTES: '10' }), '413 too_large');
  assert.equal(err({ size: 10 }, { SYSTEMAPI_XFER_MAX_BYTES: '10' }), 'ok');
  for (const over of [{ size: -1 }, { size: 1.5 }, { size: '12' }, { sha256: SHA.toUpperCase() }, { sha256: undefined }, { sha256: 'ab' },
    { overwrite: 'yes' }, { transport: 'tcp' }, { host_id: '' }, { host_id: 'a b' }]) {
    assert.equal(err(over), '400 bad_request', JSON.stringify(over));
  }
});

// sahxfer docs/golden-xfer-lease-v2.txt, copied byte for byte. The same
// vector is in sahxfer internal/grant/lease_test.go and systemapi-agent
// lease_test.go; do not edit one copy without the others.
const GOLDEN = {
  key: Buffer.from('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', 'hex'),
  routeToken: Buffer.from('a1a2a3a4a5a6a7a8a9aaabacadaeafb0', 'hex'),
  material: 'b23ea5d376d27f2cc2bb3d42be53bb07c06da9693649646bbe64dfd4b087802c',
  fields: {
    grantId: 'xfr_GoldenVectorAAAAAAAAAA', deadlineUnix: 1760745600, phase: 'start', dir: 'put', root: '/srv/app',
    path: 'releases/app.tar.gz', size: 1048576, sha256: 'fce1b8bb923aa974c6756658f3e59e5dedfe1ad2f3082a484cd7a2fe593c29e5',
    overwrite: false, transferId: '0123456789abcdef', expiresUnix: 1760745600, idleS: 30, maxS: 3600, byteCap: 1048576,
    profile: 'internet', transport: 'udp', peer: 'listen'
  },
  payload: 'xfr_GoldenVectorAAAAAAAAAA\n1760745600\nstart\nput\n/srv/app\nreleases/app.tar.gz\n1048576\n' +
    'fce1b8bb923aa974c6756658f3e59e5dedfe1ad2f3082a484cd7a2fe593c29e5\n0\n0123456789abcdef\n1760745600\n30\n3600\n1048576\n' +
    'internet\nudp\nlisten\nb23ea5d376d27f2cc2bb3d42be53bb07c06da9693649646bbe64dfd4b087802c',
  messageSha256: '234e6abdf170097f94d2c8e3f6dafb006e5d1cf761159b6a4a226f3f6ca32380'
};

test('lease payload v2: the shared golden vector, byte for byte', () => {
  assert.equal(GOLDEN.key.toString('base64'), 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=');
  assert.equal(GOLDEN.routeToken.toString('base64'), 'oaKjpKWmp6ipqqusra6vsA==');
  assert.equal(crypto.createHash('sha256').update('sahxfer golden vector contents..').digest('hex'), GOLDEN.fields.sha256);
  const material = xferMaterial(GOLDEN.key, GOLDEN.routeToken);
  assert.equal(material, GOLDEN.material);
  const payload = xferPayload({ ...GOLDEN.fields, material });
  assert.equal(payload, GOLDEN.payload);
  assert.equal(payload.split('\n').length, 18);
  assert.deepEqual(Buffer.from(payload, 'utf8'), Buffer.from(GOLDEN.payload, 'utf8'));
  assert.equal(crypto.createHash('sha256').update(Buffer.from(`xfer\n${payload}`, 'utf8')).digest('hex'), GOLDEN.messageSha256);
  // The lease hash is the same computation.
  assert.equal(require('../controlplane/lease').payloadHash('xfer', payload), GOLDEN.messageSha256);
});

test('lease payload v2: every field is validated, and fields that would shift lines are refused', () => {
  const base = { ...GOLDEN.fields, material: GOLDEN.material };
  assert.equal(xferPayload({ ...base, overwrite: true }).split('\n')[8], '1');
  assert.equal(xferPayload({ ...base, peer: 'dial:203.0.113.10:4700' }).split('\n')[16], 'dial:203.0.113.10:4700');
  assert.equal(xferPayload({ ...base, peer: 'dial:[2001:db8::1]:4700' }).split('\n')[16], 'dial:[2001:db8::1]:4700');
  assert.equal(xferPayload({ ...base, profile: 'dc', size: 0, byteCap: 0, idleS: 1, maxS: 1 }).split('\n').length, 18);
  assert.throws(() => xferMaterial(Buffer.alloc(31), Buffer.alloc(16)), /bad_payload/);
  assert.throws(() => xferMaterial(Buffer.alloc(32), Buffer.alloc(15)), /bad_payload/);
  assert.throws(() => xferMaterial('a'.repeat(32), Buffer.alloc(16)), /bad_payload/);
  for (const over of [
    { grantId: 'bad' }, { grantId: 'xfr_abc\ndefgh' }, { deadlineUnix: 0 }, { deadlineUnix: 1.5 }, { deadlineUnix: '1760745600' },
    { phase: 'begin' }, { dir: 'both' },
    { root: 'srv' }, { root: '/srv/../etc' }, { root: '/' + 'a'.repeat(4096) },
    { path: 'p\n2' }, { path: '/p' }, { path: 'a/../../etc' }, { path: 'a//b' }, { path: 'é'.repeat(128) }, { path: 'a\\b' },
    { size: -1 }, { size: 2 ** 53 }, { size: '5' },
    { sha256: 'AB'.repeat(32) }, { sha256: 'ab' }, { sha256: null },
    { overwrite: 0 }, { overwrite: 'false' }, { overwrite: undefined },
    { transferId: '0000000000000000' }, { transferId: '0123456789ABCDEF' }, { transferId: '0123456789abcde' }, { transferId: 81985529216486895 },
    { expiresUnix: 0 }, { expiresUnix: -5 }, { expiresUnix: '1' },
    { idleS: 0 }, { idleS: 3601, maxS: 3600 }, { idleS: 31, maxS: 30 }, { maxS: 0 }, { maxS: 3601, idleS: 30 }, { idleS: 1.5 },
    { byteCap: 1048575 }, { byteCap: -1 }, { byteCap: '1048576' },
    { profile: 'lan' }, { profile: '' }, { transport: 'quic-stream' }, { transport: 'tcp' },
    { peer: 'dial:' }, { peer: 'dial:host' }, { peer: 'dial:1.2.3.4:0' }, { peer: 'dial:1.2.3.4:65536' }, { peer: 'dial:a b:1' },
    { peer: 'dial:1.2.3.4:4700\nlisten' }, { peer: 'listen:127.0.0.1:1' }, { peer: '' }, { peer: undefined },
    { material: 'AB'.repeat(32) }, { material: 'ab'.repeat(31) }, { material: undefined }
  ]) {
    assert.throws(() => xferPayload({ ...base, ...over }), /bad_payload/, JSON.stringify(over));
  }
  assert.throws(() => xferPayload(), /bad_payload/);
});

test('direct mode allow list: CIDR parsing and the address check', () => {
  const lo = directAllowList(undefined);
  assert.ok(lo);
  assert.equal(directPeer('127.0.0.1:47000', lo), '127.0.0.1:47000');
  assert.equal(directPeer('127.9.9.9:1', lo), '127.9.9.9:1');
  assert.equal(directPeer('[::1]:47000', lo), '[::1]:47000');
  for (const raw of ['10.0.0.1:47000', '[2001:db8::1]:47000', 'localhost:47000', 'example.com:47000', '127.0.0.1', '127.0.0.1:0',
    '127.0.0.1:70000', ' 127.0.0.1:1', undefined, 47000, '[::ffff:10.0.0.1]:1']) {
    assert.equal(directPeer(raw, lo), null, JSON.stringify(raw));
  }
  assert.equal(directPeer('127.0.0.1:1', null), null);
  const lan = directAllowList('10.0.0.0/8, 2001:db8::/32');
  assert.equal(directPeer('10.1.2.3:47000', lan), '10.1.2.3:47000');
  assert.equal(directPeer('[2001:db8::1]:47000', lan), '[2001:db8::1]:47000');
  assert.equal(directPeer('127.0.0.1:47000', lan), null);
  for (const bad of ['10.0.0.0', '10.0.0.0/33', '::1/129', 'example.com/8', '10.0.0.0/8,', ',', '10.0.0.0/-1', '0x7f000001/8']) {
    assert.equal(directAllowList(bad), null, bad);
  }
});

test('a put grant: intent row first, signed push to the agent, exact response, result row', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const res = await grant(r);
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const doc = res.body;
    assert.deepEqual(Object.keys(doc).sort(), ['aead', 'byte_cap', 'expires_at', 'expires_in', 'grant_id', 'host_id', 'idle_seconds', 'key',
      'max_seconds', 'overwrite', 'path', 'peer', 'profile', 'purpose', 'root', 'route_token', 'sha256', 'size', 'transfer_id', 'transport'].sort());
    assert.match(doc.grant_id, /^xfr_[A-Za-z0-9_-]{8,64}$/);
    assert.match(doc.transfer_id, /^[0-9a-f]{16}$/);
    assert.notEqual(doc.transfer_id, '0000000000000000');
    assert.equal(doc.host_id, HOST_A);
    assert.equal(doc.purpose, 'xfer:put');
    assert.equal(doc.root, '/srv/a');
    assert.equal(doc.path, 'releases/app.tar.gz');
    assert.equal(doc.size, 123456789);
    assert.equal(doc.sha256, SHA);
    assert.equal(doc.overwrite, false);
    assert.equal(doc.profile, 'internet');
    assert.equal(doc.transport, 'udp');
    assert.deepEqual(doc.peer, { udp: PEER, quic: null });
    assert.equal(doc.aead, 'ChaCha20-Poly1305');
    assert.equal(doc.expires_in, 60);
    assert.ok(Math.abs(Date.parse(doc.expires_at) - Date.now() - 60_000) < 5000);
    assert.equal(doc.idle_seconds, 30);
    assert.equal(doc.max_seconds, 3600);
    assert.equal(doc.byte_cap, doc.size);
    // Canonical padded base64 of 32 and 16 bytes (sahxfer decodeCanon).
    const key = Buffer.from(doc.key, 'base64');
    const tok = Buffer.from(doc.route_token, 'base64');
    assert.equal(key.length, 32);
    assert.equal(tok.length, 16);
    assert.equal(key.toString('base64'), doc.key);
    assert.equal(tok.toString('base64'), doc.route_token);

    const [push] = frames(agent, 'xfer_grant');
    assert.deepEqual(agent.intentBeforeGrant, [true]);
    for (const k of ['grant_id', 'transfer_id', 'root', 'path', 'size', 'sha256', 'overwrite', 'key', 'route_token']) assert.deepEqual(push[k], doc[k], k);
    assert.deepEqual(Object.keys(push).sort(), ['action', 'actor', 'aead', 'byte_cap', 'deadline_unix', 'dir', 'expires_unix', 'grant_id',
      'idle_s', 'key', 'lease', 'max_s', 'overwrite', 'path', 'peer', 'profile', 'purpose', 'root', 'route_token', 'sha256', 'size',
      'transfer_id', 'transport', 'type'].sort());
    assert.equal(push.peer, `dial:${PEER}`);
    assert.equal(push.action, 'xfer');
    assert.equal(push.dir, 'put');
    assert.equal(push.actor, 'user-1');
    assert.equal(push.idle_s, doc.idle_seconds);
    assert.equal(push.max_s, doc.max_seconds);
    assert.equal(push.byte_cap, doc.byte_cap);
    assert.equal(push.expires_unix, Math.floor(Date.parse(doc.expires_at) / 1000));
    const fields = fieldsFromFrame(push);
    const payload = xferPayload(fields);
    assert.equal(payload.split('\n').length, 18);
    // Every one of the 18 fields is bound.
    assertEveryFieldBound(push.lease, fields);
    // Bound to the host and the action.
    assert.equal(push.lease.host_id, HOST_A);
    assert.equal(verifyLease(PUBLIC_KEY, { ...push.lease, action: 'xfer_root' }, payload).ok, false);
    assert.equal(verifyLease(PUBLIC_KEY, { ...push.lease, host_id: HOST_B }, payload).ok, false);
    // Signed by the pinned key only.
    const other = crypto.generateKeyPairSync('ed25519').publicKey;
    assert.equal(verifyLease(other, push.lease, payload).error, 'bad_signature');
    // Expired past the skew allowance.
    assert.equal(verifyLease(PUBLIC_KEY, push.lease, payload, (push.lease.expires_unix + 31) * 1000).error, 'expired');

    const [intent] = rows(r, 'xfer_intent');
    assert.equal(intent.actor, 'user-1');
    assert.equal(intent.host_id, HOST_A);
    assert.equal(intent.tenant_id, 'acme');
    assert.equal(intent.payload.grant_id, doc.grant_id);
    assert.equal(intent.payload.purpose, 'xfer:put');
    assert.equal(intent.payload.size, 123456789);
    assert.equal(intent.payload.sha256, SHA);
    assert.equal(r.fm.xfer.grants.size, 1);
    // The grant keeps the material hash, never the key or the token.
    const kept = r.fm.xfer.grants.get(doc.grant_id);
    assert.equal(kept.material, fields.material);
    assert.equal(Object.values(kept).some((v) => v === doc.key || v === doc.route_token), false);

    agent.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: doc.grant_id, payload: { status: 'ok', bytes: 123456789, sha256: SHA, committed: true } }));
    const result = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(result.payload.status, 'ok');
    assert.equal(result.payload.bytes, 123456789);
    assert.equal(result.payload.grant_id, doc.grant_id);
    assert.equal(result.payload.committed, true);
    assert.equal('reason' in result.payload, false);
    assert.equal(r.fm.xfer.grants.size, 0);

    // Neither secret reaches the audit log.
    const audit = JSON.stringify(r.fm.registry.audit);
    assert.equal(audit.includes(doc.key), false);
    assert.equal(audit.includes(doc.route_token), false);
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
  } finally {
    await r.close();
  }
});

test('the API key is accepted as Authorization: Bearer; a result that disagrees with the grant is hash_mismatch', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const res = await grant(r, {}, { authorization: 'Bearer op-key' });
    assert.equal(res.status, 200);
    agent.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: res.body.grant_id, payload: { status: 'ok', bytes: 123456789, sha256: 'cd'.repeat(32) } }));
    const result = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(result.payload.status, 'hash_mismatch');
    assert.equal(result.payload.result_sha256, 'cd'.repeat(32));
    assert.equal((await grant(r, {}, {})).status, 401);
    assert.equal((await grant(r, {}, { 'x-api-key': 'nope' })).status, 403);
  } finally {
    await r.close();
  }
});

test('scopes, host tenancy and the file policy root decide before anything is audited or pushed', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    await r.fm.registry.enroll({
      tenantId: 'beta', userId: 'user-2', keyId: 'k2', hostId: HOST_B,
      hostname: 'b.example', os: 'linux', platform: 'amd64', sshPubkey: opensshEd25519(r.fm.signer.publicKeyRaw)
    });
    await r.fm.registry.setHostChannelPolicy(HOST_B, { file_policy: POLICY });
    // A read-only key cannot put.
    let res = await grant(r, {}, { 'x-api-key': 'read-key' });
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'scope_denied');
    // xfer:root is admin only (file:root).
    res = await grant(r, { purpose: 'xfer:root', root: '/etc' });
    assert.equal(res.body.error, 'scope_denied');
    // Outside the policy, and a read-only policy root.
    res = await grant(r, { root: '/srv/c' });
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'root_denied');
    res = await grant(r, { root: '/srv/b' });
    assert.equal(res.body.error, 'root_denied');
    // /srv/a allows write but not root.
    res = await grant(r, { purpose: 'xfer:root', root: '/srv/a' }, { 'x-api-key': 'admin-key' });
    assert.equal(res.body.error, 'root_denied');
    // A host the caller has no tenant in, and one that does not exist.
    res = await grant(r, { host_id: HOST_B });
    assert.equal(res.status, 404);
    res = await grant(r, { host_id: 'nope' });
    assert.equal(res.status, 404);
    // Shape errors are 400 before the host lookup.
    res = await grant(r, { path: '../etc/shadow' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'bad_path');
    assert.equal(rows(r, 'xfer_intent').length, 0);
    assert.equal(frames(agent, 'xfer_grant').length, 0);

    // A beneath-root path under a root-flagged entry, as admin.
    res = await grant(r, { purpose: 'xfer:root', root: '/etc/app' }, { 'x-api-key': 'admin-key' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(frames(agent, 'xfer_grant')[0].action, 'xfer_root');
    assert.equal(rows(r, 'xfer_intent').length, 1);
  } finally {
    await r.close();
  }
});

test('agent_unsupported and agent_offline: no relay, no capability, a QUIC transport, a get, no agent', async () => {
  const noPeer = await rig({});
  try {
    const agent = await connectAgent(noPeer);
    const res = await grant(noPeer);
    assert.equal(res.status, 501);
    assert.equal(res.body.error, 'agent_unsupported');
    assert.equal(frames(agent, 'xfer_grant').length, 0);
  } finally {
    await noPeer.close();
  }
  const r = await rig();
  try {
    // Enrolled earlier, not connected now.
    await r.fm.registry.enroll({
      tenantId: 'acme', userId: 'user-1', keyId: 'k-agent', hostId: HOST_A,
      hostname: '1111.example', os: 'linux', platform: 'amd64', sshPubkey: opensshEd25519(r.fm.signer.publicKeyRaw)
    });
    await r.fm.registry.setHostChannelPolicy(HOST_A, { file_policy: POLICY });
    let res = await grant(r);
    assert.equal(res.status, 503);
    assert.equal(res.body.error, 'agent_offline');
    const agent = await connectAgent(r, { caps: 'pty,tcp,file' });
    res = await grant(r);
    assert.equal(res.body.error, 'agent_unsupported');
    agent.ws.terminate();
    await waitUntil('agent gone', () => !r.fm.connectedAgents.has(HOST_A));
    const xagent = await connectAgent(r);
    res = await grant(r, { transport: 'quic-bridge' });
    assert.equal(res.body.error, 'agent_unsupported');
    res = await grant(r, { purpose: 'xfer:get', dir: 'get', sha256: undefined, size: 0 });
    assert.equal(res.status, 501);
    assert.equal(res.body.error, 'agent_unsupported');
    assert.equal(frames(xagent, 'xfer_grant').length, 0);
    assert.equal(rows(r, 'xfer_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a failed intent write issues nothing: internal, no push', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const append = r.fm.registry.appendAudit.bind(r.fm.registry);
    r.fm.registry.appendAudit = async (entry) => {
      if (entry.action === 'xfer_intent') throw new Error('disk full');
      return append(entry);
    };
    const res = await grant(r);
    assert.equal(res.status, 500);
    assert.equal(res.body.error, 'internal');
    assert.equal(frames(agent, 'xfer_grant').length, 0);
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});

test('an agent refusal or silence is the client error; the grant ends with an aborted result row', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, { reply: { error: 'exists' } });
    let res = await grant(r);
    assert.equal(res.status, 409);
    assert.equal(res.body.error, 'exists');
    let result = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(result.payload.status, 'aborted');
    assert.equal(result.payload.error, 'exists');
    // An unknown agent code does not reach the client.
    agent.reply = { error: 'kaboom' };
    res = await grant(r);
    assert.equal(res.body.error, 'internal');
    // No answer within the start window.
    agent.reply = null;
    res = await grant(r);
    assert.equal(res.status, 503);
    assert.equal(res.body.error, 'agent_offline');
    const cancel = await waitUntil('cancel', () => frames(agent, 'xfer_cancel')[0]);
    assert.equal(cancel.reason, 'start_timeout');
    // The agent may have accepted the frame, so the row does not claim aborted.
    result = await waitUntil('third result', () => rows(r, 'xfer_result')[2]);
    assert.equal(result.payload.status, 'unknown');
    assert.equal(result.payload.error, 'start_timeout');
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});

test('two live grants per actor; a third is cap_reached; a disconnect ends them', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    assert.equal((await grant(r)).status, 200);
    assert.equal((await grant(r, { path: 'b' })).status, 200);
    const third = await grant(r, { path: 'c' });
    assert.equal(third.status, 429);
    assert.equal(third.body.error, 'cap_reached');
    const ids = new Set(frames(agent, 'xfer_grant').map((f) => f.transfer_id));
    assert.equal(ids.size, 2);
    agent.ws.terminate();
    await waitUntil('results', () => rows(r, 'xfer_result').length === 2);
    for (const row of rows(r, 'xfer_result')) {
      assert.equal(row.payload.status, 'unknown');
      assert.equal(row.payload.error, 'agent_disconnected');
    }
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});

test('renewal sends a signed renew lease, and cancels once the actor loses the scope', async () => {
  const r = await rig();
  r.fm.xfer.renewMs = 50;
  try {
    const agent = await connectAgent(r);
    const res = await grant(r);
    assert.equal(res.status, 200);
    const renew = await waitUntil('renew', () => frames(agent, 'xfer_renew')[0]);
    assert.equal(renew.grant_id, res.body.grant_id);
    // A renew is the start payload with only phase and deadline changed.
    const [push] = frames(agent, 'xfer_grant');
    const fields = fieldsFromFrame(push, 'renew', renew.deadline_unix);
    assertEveryFieldBound(renew.lease, fields);
    assert.equal(verifyLease(PUBLIC_KEY, renew.lease, xferPayload({ ...fields, phase: 'start' })).ok, false);
    await r.fm.registry.setScopes('k-op', ['hosts:read', 'file:read']);
    const cancel = await waitUntil('cancel', () => frames(agent, 'xfer_cancel')[0]);
    assert.equal(cancel.reason, 'stopped');
    const result = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(result.payload.status, 'unknown');
    assert.equal(result.payload.error, 'stopped');
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});

test('status frames from another socket and frames naming another host are ignored', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const res = await grant(r);
    assert.equal(res.status, 200);
    r.fm.xfer.onAgentFrame({}, HOST_A, { type: 'xfer_status', grant_id: res.body.grant_id, payload: { error: 'internal' } });
    r.fm.xfer.onAgentFrame(agent.ws, HOST_B, { type: 'xfer_result', grant_id: res.body.grant_id, payload: { status: 'ok' } });
    assert.equal(r.fm.xfer.grants.size, 1);
    assert.equal(rows(r, 'xfer_result').length, 0);
  } finally {
    await r.close();
  }
});

test('S1: a result sent after the agent socket dropped and reconnected is recorded', async () => {
  const r = await rig();
  r.fm.xfer.tombstoneMs = 5000;
  try {
    const agent = await connectAgent(r);
    const res = await grant(r);
    assert.equal(res.status, 200);
    agent.ws.terminate();
    await waitUntil('tombstone', () => r.fm.xfer.grants.get(res.body.grant_id).state === 'tombstone');
    await waitUntil('agent gone', () => !r.fm.connectedAgents.has(HOST_A));
    assert.equal(rows(r, 'xfer_result').length, 0);
    // Still holds the actor's slot while the agent's lease may be valid.
    assert.equal(r.fm.xfer.liveFor('user-1'), 1);
    const again = await connectAgent(r);
    // Status frames from the new socket do not touch the old grant.
    again.ws.send(JSON.stringify({ type: 'xfer_status', grant_id: res.body.grant_id, payload: { error: 'internal' } }));
    again.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: res.body.grant_id, payload: { status: 'ok', bytes: 123456789, sha256: SHA } }));
    const row = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(row.payload.status, 'ok');
    assert.equal(row.payload.error, 'agent_disconnected');
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});

test('S1: a commit that crosses the max_duration cancel is recorded as the agent reports it', async () => {
  const r = await rig({ SYSTEMAPI_XFER_PEER_UDP: PEER, SYSTEMAPI_XFER_MAX_SECONDS: '1' });
  r.fm.xfer.tombstoneMs = 5000;
  try {
    const agent = await connectAgent(r);
    const res = await grant(r);
    assert.equal(res.status, 200);
    assert.equal(res.body.max_seconds, 1);
    agent.ws.send(JSON.stringify({ type: 'xfer_status', grant_id: res.body.grant_id, payload: { status: 'active', bytes: 10 } }));
    const cancel = await waitUntil('cancel', () => frames(agent, 'xfer_cancel')[0], 3000);
    assert.equal(cancel.reason, 'max_duration');
    agent.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: res.body.grant_id, payload: { status: 'ok', bytes: 123456789, sha256: SHA } }));
    const row = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(row.payload.status, 'ok');
    assert.equal(row.payload.error, 'max_duration');
  } finally {
    await r.close();
  }
});

test('S2: no progress within the first-packet window ends the grant; progress keeps it until idle', async () => {
  const r = await rig({ SYSTEMAPI_XFER_PEER_UDP: PEER, SYSTEMAPI_XFER_IDLE_SECONDS: '1' });
  r.fm.xfer.firstPacketMs = 150;
  r.fm.xfer.renewMs = 50;
  try {
    const agent = await connectAgent(r);
    const quiet = await grant(r);
    assert.equal(quiet.status, 200);
    const cancel = await waitUntil('cancel', () => frames(agent, 'xfer_cancel').find((f) => f.grant_id === quiet.body.grant_id));
    assert.equal(cancel.reason, 'first_packet_timeout');
    const renewsAtCancel = frames(agent, 'xfer_renew').filter((f) => f.grant_id === quiet.body.grant_id).length;
    const row = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(row.payload.status, 'unknown');
    assert.equal(row.payload.error, 'first_packet_timeout');
    assert.equal(frames(agent, 'xfer_renew').filter((f) => f.grant_id === quiet.body.grant_id).length, renewsAtCancel);

    const busy = await grant(r, { path: 'busy' });
    assert.equal(busy.status, 200);
    agent.ws.send(JSON.stringify({ type: 'xfer_status', grant_id: busy.body.grant_id, payload: { status: 'active', bytes: 1 } }));
    await new Promise((resolve) => setTimeout(resolve, 400));
    assert.equal(r.fm.xfer.grants.get(busy.body.grant_id).state, 'live');
    const idle = await waitUntil('idle cancel', () => frames(agent, 'xfer_cancel').find((f) => f.grant_id === busy.body.grant_id), 3000);
    assert.equal(idle.reason, 'idle_timeout');
  } finally {
    await r.close();
  }
});

test('S2: a client that hangs up before the response cancels the grant', async () => {
  const r = await rig();
  r.fm.xfer.readyTimeoutMs = 3000;
  try {
    const agent = await connectAgent(r, { reply: null });
    const { port } = new URL(r.url);
    const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/api/v1/xfer/grant',
      headers: { 'content-type': 'application/json', 'x-api-key': 'op-key' } });
    req.on('error', () => {});
    req.end(JSON.stringify(body()));
    const push = await waitUntil('push', () => frames(agent, 'xfer_grant')[0]);
    req.destroy();
    const cancel = await waitUntil('cancel', () => frames(agent, 'xfer_cancel')[0]);
    assert.equal(cancel.grant_id, push.grant_id);
    assert.equal(cancel.reason, 'client_gone');
    const row = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(row.payload.status, 'unknown');
    assert.equal(row.payload.error, 'client_gone');
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});

test('N1: an agent that drops during the intent write gets no push, and the result row follows the intent row', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const append = r.fm.registry.appendAudit.bind(r.fm.registry);
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    let entered = false;
    r.fm.registry.appendAudit = async (entry) => {
      if (entry.action === 'xfer_intent') {
        entered = true;
        await gate;
      }
      return append(entry);
    };
    const pending = grant(r);
    await waitUntil('intent write started', () => entered);
    agent.ws.terminate();
    await waitUntil('agent gone', () => !r.fm.connectedAgents.has(HOST_A));
    assert.equal(rows(r, 'xfer_result').length, 0);
    release();
    const res = await pending;
    assert.equal(res.status, 503);
    assert.equal(res.body.error, 'agent_offline');
    assert.equal(frames(agent, 'xfer_grant').length, 0);
    const actions = r.fm.registry.audit.map((row) => row.action).filter((a) => a.startsWith('xfer_'));
    assert.deepEqual(actions, ['xfer_intent', 'xfer_result']);
    assert.equal(rows(r, 'xfer_result')[0].payload.status, 'aborted');
  } finally {
    await r.close();
  }
});

test('N7: an agent error after ready ends the grant with a result row', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const res = await grant(r);
    assert.equal(res.status, 200);
    agent.ws.send(JSON.stringify({ type: 'xfer_status', grant_id: res.body.grant_id, payload: { error: 'not_found' } }));
    const row = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(row.payload.status, 'aborted');
    assert.equal(row.payload.error, 'not_found');
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});

test('direct mode: the agent-reported address becomes peer.udp, and the lease signs "listen"', async () => {
  const r = await rig({ SYSTEMAPI_XFER_PEER_MODE: 'direct' });
  try {
    const agent = await connectAgent(r, { reply: { status: 'ready', udp: '127.0.0.1:47000' } });
    const res = await grant(r);
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body.peer, { udp: '127.0.0.1:47000', quic: null });
    const [push] = frames(agent, 'xfer_grant');
    assert.equal(push.peer, 'listen');
    const fields = fieldsFromFrame(push);
    assert.equal(xferPayload(fields).split('\n')[16], 'listen');
    assertEveryFieldBound(push.lease, fields);
    // IPv6 loopback is in the default list too.
    agent.reply = { status: 'ready', udp: '[::1]:47001' };
    const v6 = await grant(r, { path: 'v6' });
    assert.equal(v6.status, 200, JSON.stringify(v6.body));
    assert.equal(v6.body.peer.udp, '[::1]:47001');
  } finally {
    await r.close();
  }
});

test('direct mode: a ready without udp, or with an address outside the allow list, is internal and cancels the grant', async () => {
  const r = await rig({ SYSTEMAPI_XFER_PEER_MODE: 'direct' });
  try {
    const agent = await connectAgent(r, { reply: { status: 'ready' } });
    let res = await grant(r);
    assert.equal(res.status, 500);
    assert.equal(res.body.error, 'internal');
    let cancel = await waitUntil('cancel', () => frames(agent, 'xfer_cancel')[0]);
    assert.equal(cancel.reason, 'peer_missing');
    let row = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    // The agent said ready, so its receiver may be running: not "aborted".
    assert.equal(row.payload.status, 'unknown');
    assert.equal(row.payload.error, 'peer_missing');
    for (const [i, udp] of ['203.0.113.10:4700', 'localhost:4700', '10.0.0.1:4700', '127.0.0.1', 'example.com:1'].entries()) {
      agent.reply = { status: 'ready', udp };
      res = await grant(r, { path: `p${i}` });
      assert.equal(res.status, 500, udp);
      assert.equal(res.body.error, 'internal', udp);
      cancel = await waitUntil('cancel', () => frames(agent, 'xfer_cancel')[i + 1]);
      assert.equal(cancel.reason, 'peer_refused', udp);
      await waitUntil('slot freed', () => r.fm.xfer.grants.size === 0);
    }
    assert.equal(JSON.stringify(r.fm.registry.audit).includes('203.0.113.10'), false);
  } finally {
    await r.close();
  }
  // A configured list replaces the loopback default.
  const lan = await rig({ SYSTEMAPI_XFER_PEER_MODE: 'direct', SYSTEMAPI_XFER_DIRECT_ALLOW: '10.0.0.0/8' });
  try {
    const agent = await connectAgent(lan, { reply: { status: 'ready', udp: '10.1.2.3:47000' } });
    const res = await grant(lan);
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.peer.udp, '10.1.2.3:47000');
    agent.reply = { status: 'ready', udp: '127.0.0.1:47000' };
    assert.equal((await grant(lan, { path: 'lo' })).body.error, 'internal');
  } finally {
    await lan.close();
  }
});

test('peer mode configuration: relay ignores a reported address; an unknown mode or a bad allow list is agent_unsupported', async () => {
  const relay = await rig({ SYSTEMAPI_XFER_PEER_MODE: 'relay', SYSTEMAPI_XFER_PEER_UDP: PEER });
  try {
    await connectAgent(relay, { reply: { status: 'ready', udp: '127.0.0.1:47000' } });
    const res = await grant(relay);
    assert.equal(res.status, 200);
    assert.equal(res.body.peer.udp, PEER);
  } finally {
    await relay.close();
  }
  for (const env of [
    { SYSTEMAPI_XFER_PEER_MODE: 'hole-punch', SYSTEMAPI_XFER_PEER_UDP: PEER },
    { SYSTEMAPI_XFER_PEER_MODE: 'DIRECT' },
    { SYSTEMAPI_XFER_PEER_MODE: 'direct', SYSTEMAPI_XFER_DIRECT_ALLOW: '127.0.0.1' },
    { SYSTEMAPI_XFER_PEER_MODE: 'relay', SYSTEMAPI_XFER_PEER_UDP: 'not an address' }
  ]) {
    const r = await rig(env);
    try {
      const agent = await connectAgent(r);
      const res = await grant(r);
      assert.equal(res.status, 501, JSON.stringify(env));
      assert.equal(res.body.error, 'agent_unsupported');
      assert.equal(frames(agent, 'xfer_grant').length, 0);
      assert.equal(rows(r, 'xfer_intent').length, 0);
    } finally {
      await r.close();
    }
  }
});

test('xfer has its own rate budget: a put loop does not spend the file or terminal budget', async () => {
  const r = await rig({ SYSTEMAPI_XFER_PEER_UDP: PEER, SYSTEMAPI_TICKET_RATE_XFER: '1', SYSTEMAPI_TICKET_RATE_PER_HOST: '1' });
  try {
    const agent = await connectAgent(r);
    const first = await grant(r);
    assert.equal(first.status, 200);
    const limited = await grant(r, { path: 'b' });
    assert.equal(limited.status, 429);
    assert.equal(limited.body.error, 'rate_limited');
    assert.equal(frames(agent, 'xfer_grant').length, 1);
    // The terminal budget (file:write tickets) is untouched.
    const ticket = await fetch(`${r.url}/api/v1/ws-ticket`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'op-key' },
      body: JSON.stringify({ host_id: HOST_A, purpose: 'file:write', root: '/srv/a' })
    });
    assert.equal(ticket.status, 200, await ticket.text());
  } finally {
    await r.close();
  }
  // And file tickets do not spend the xfer budget.
  const r2 = await rig({ SYSTEMAPI_XFER_PEER_UDP: PEER, SYSTEMAPI_TICKET_RATE_XFER: '1', SYSTEMAPI_TICKET_RATE_PER_HOST: '1' });
  try {
    await connectAgent(r2);
    const ticket = await fetch(`${r2.url}/api/v1/ws-ticket`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'op-key' },
      body: JSON.stringify({ host_id: HOST_A, purpose: 'file:write', root: '/srv/a' })
    });
    assert.equal(ticket.status, 200);
    assert.equal((await grant(r2)).status, 200);
  } finally {
    await r2.close();
  }
});

test('xfer_result records a known reason and committed; an unknown reason is dropped', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const a = await grant(r);
    const b = await grant(r, { path: 'b' });
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    agent.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: a.body.grant_id,
      payload: { status: 'aborted', reason: 'cancelled', bytes: 10, committed: false } }));
    agent.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: b.body.grant_id,
      payload: { status: 'aborted', reason: 'rm -rf /', committed: 'yes' } }));
    await waitUntil('result rows', () => rows(r, 'xfer_result').length === 2);
    const byId = Object.fromEntries(rows(r, 'xfer_result').map((row) => [row.payload.grant_id, row.payload]));
    assert.equal(byId[a.body.grant_id].reason, 'cancelled');
    assert.equal(byId[a.body.grant_id].committed, false);
    assert.equal(byId[a.body.grant_id].bytes, 10);
    assert.equal('reason' in byId[b.body.grant_id], false);
    assert.equal('committed' in byId[b.body.grant_id], false);
    // Every listed reason passes through.
    for (const reason of ['size_mismatch', 'hash_mismatch', 'expired', 'policy', 'io', 'protocol', 'auth', 'cancelled', 'byte_cap',
      'idle', 'no_space', 'stopped', 'agent_restart']) {
      const g = await grant(r, { path: `r-${reason}` });
      assert.equal(g.status, 200);
      agent.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: g.body.grant_id, payload: { status: 'aborted', reason, committed: false } }));
      const row = await waitUntil('row', () => rows(r, 'xfer_result').find((x) => x.payload.grant_id === g.body.grant_id));
      assert.equal(row.payload.reason, reason);
    }
  } finally {
    await r.close();
  }
});

test('new agent refusals: host codes pass through, lease_required reaches the client as internal', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    for (const [error, status, client] of [['pty_user_unset', 503, 'pty_user_unset'], ['root_unavailable', 503, 'root_unavailable'],
      ['no_space', 507, 'no_space'], ['io', 500, 'io'], ['lease_required', 500, 'internal']]) {
      agent.reply = { error };
      const res = await grant(r, { path: `e-${error}` });
      assert.equal(res.status, status, error);
      assert.equal(res.body.error, client, error);
      const row = await waitUntil('row', () => rows(r, 'xfer_result').find((x) => x.payload.error === error));
      assert.equal(row.payload.status, 'aborted');
    }
    assert.equal(r.fm.xfer.grants.size, 0);
  } finally {
    await r.close();
  }
});
