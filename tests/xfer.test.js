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
const { verifyLease, xferPayload } = require('../controlplane/lease');
const { parseGrantRequest } = require('../playground/xfer');

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

test('lease payload: the 8-line §3.4 form, and fields that would shift lines are refused', () => {
  assert.equal(xferPayload('xfr_abcdefgh', 1700000060, 'start', 'put', '/srv/a', 'r/app', 5, SHA),
    `xfr_abcdefgh\n1700000060\nstart\nput\n/srv/a\nr/app\n5\n${SHA}`);
  for (const args of [
    ['bad', 1, 'start', 'put', '/srv/a', 'p', 1, SHA],
    ['xfr_abcdefgh', 1, 'begin', 'put', '/srv/a', 'p', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'both', '/srv/a', 'p', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/a', 'p\n2', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', 'srv', 'p', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/a', '/p', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/a', 'p', -1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/a', 'p', 1, 'AB'.repeat(32)],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/a', 'a/../../etc', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/a', 'a//b', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/a', 'é'.repeat(128), 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/srv/../etc', 'p', 1, SHA],
    ['xfr_abcdefgh', 1, 'start', 'put', '/' + 'a'.repeat(4096), 'p', 1, SHA]
  ]) {
    assert.throws(() => xferPayload(...args), /bad_payload/, JSON.stringify(args));
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
    assert.equal(push.peer_udp, PEER);
    assert.equal(push.action, 'xfer');
    assert.equal(push.dir, 'put');
    assert.equal(push.actor, 'user-1');
    const payload = xferPayload(push.grant_id, push.deadline_unix, 'start', 'put', '/srv/a', 'releases/app.tar.gz', 123456789, SHA);
    assert.equal(verifyLease(PUBLIC_KEY, push.lease, payload).ok, true);
    // Bound to the host, the direction and the action.
    assert.equal(push.lease.host_id, HOST_A);
    assert.equal(verifyLease(PUBLIC_KEY, push.lease, payload.replace('\nput\n', '\nget\n')).ok, false);
    assert.equal(verifyLease(PUBLIC_KEY, { ...push.lease, action: 'xfer_root' }, payload).ok, false);
    assert.equal(verifyLease(PUBLIC_KEY, { ...push.lease, host_id: HOST_B }, payload).ok, false);

    const [intent] = rows(r, 'xfer_intent');
    assert.equal(intent.actor, 'user-1');
    assert.equal(intent.host_id, HOST_A);
    assert.equal(intent.tenant_id, 'acme');
    assert.equal(intent.payload.grant_id, doc.grant_id);
    assert.equal(intent.payload.purpose, 'xfer:put');
    assert.equal(intent.payload.size, 123456789);
    assert.equal(intent.payload.sha256, SHA);
    assert.equal(r.fm.xfer.grants.size, 1);

    agent.ws.send(JSON.stringify({ type: 'xfer_result', grant_id: doc.grant_id, payload: { status: 'ok', bytes: 123456789, sha256: SHA } }));
    const result = await waitUntil('result row', () => rows(r, 'xfer_result')[0]);
    assert.equal(result.payload.status, 'ok');
    assert.equal(result.payload.bytes, 123456789);
    assert.equal(result.payload.grant_id, doc.grant_id);
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
    const payload = xferPayload(renew.grant_id, renew.deadline_unix, 'renew', 'put', '/srv/a', 'releases/app.tar.gz', 123456789, SHA);
    assert.equal(verifyLease(PUBLIC_KEY, renew.lease, payload).ok, true);
    assert.equal(verifyLease(PUBLIC_KEY, renew.lease, payload.replace('\nrenew\n', '\nstart\n')).ok, false);
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
