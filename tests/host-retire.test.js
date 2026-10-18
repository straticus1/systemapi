'use strict';

// Host retirement (POST /api/v1/hosts/:host_id/retire), resolve's stale-row
// preference (SYSTEMAPI_RESOLVE_STALE_HOURS), and the production refusal of
// an ephemeral lease signing key (SYSTEMAPI_ED25519_SEED).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn, spawnSync } = require('node:child_process');
const express = require('express');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner, loadSigner, assertSignerConfig } = require('../controlplane/keys');

const OLD = '11111111-1111-4111-8111-111111111111';
const NEW = '22222222-2222-4222-8222-222222222222';
const KEYS = { 'agent-key': 'k-agent', 'admin-key': 'k-admin', 'read-key': 'k-read', 'write-key': 'k-write' };
const HOUR = 3600 * 1000;

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

async function rig(env = {}) {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test', ...env };
  fm.signer = signer();
  fm.tickets = new Map();
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.verifyApiKey = async (key) => (KEYS[key] ? { key_id: KEYS[key], user_id: 'user-1' } : null);
  fm.agentPingMs = 100;
  mount(app, fm);
  await fm.registry.setScopes('k-admin', ['admin']);
  await fm.registry.setScopes('k-read', ['hosts:read']);
  await fm.registry.setScopes('k-write', ['hosts:read', 'hosts:write', 'exec:run']);
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
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

// A fake agent; resolves once the server answered enrolled or enroll_error.
async function connectAgent(r, hostId, hostname = 'web1') {
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': hostId,
      'x-systemapi-hostname': hostname,
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      'x-systemapi-capabilities': 'pty,tcp,file,xfer'
    }
  }));
  const agent = { ws, frames: [], closed: null };
  ws.on('message', (data, isBinary) => { if (!isBinary) agent.frames.push(JSON.parse(data.toString())); });
  ws.on('close', (code, reason) => { agent.closed = { code, reason: reason.toString() }; });
  ws.on('error', () => {});
  await waitUntil('enroll answer', () => agent.frames.find((f) => f.type === 'enrolled' || f.type === 'enroll_error'));
  return agent;
}

async function disconnect(r, agent, hostId) {
  agent.ws.close();
  await waitUntil('agent gone', () => !r.fm.connectedAgents.has(hostId) && r.fm.registry.hosts.get(hostId).status === 'offline');
}

async function call(r, method, pathname, { key = 'admin-key', body } = {}) {
  const res = await fetch(`${r.url}${pathname}`, {
    method,
    headers: { 'x-api-key': key, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body))
  });
  const text = await res.text();
  let parsed = text;
  try { parsed = JSON.parse(text); } catch { /* text */ }
  return { status: res.status, body: parsed };
}

const retire = (r, hostId, body, key) => call(r, 'POST', `/api/v1/hosts/${hostId}/retire`, { body, key });
const resolve = (r, name) => call(r, 'GET', `/api/v1/hosts/resolve?name=${encodeURIComponent(name)}`, { key: 'read-key' });

function auditRows(r, action) {
  return r.fm.registry.audit.filter((row) => row.action === action);
}

test('retire an offline host: 200, retired_at set, host_retired audit row with the reason', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, OLD);
    await disconnect(r, agent, OLD);
    const res = await retire(r, OLD, { reason: 'agent re-enrolled with a new state file' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.host_id, OLD);
    assert.equal(res.body.hostname, 'web1');
    assert.equal(res.body.tenant, 'acme');
    assert.equal(res.body.forced, false);
    assert.equal(res.body.agent_closed, false);
    assert.ok(Date.parse(res.body.retired_at) > 0);
    const rows = auditRows(r, 'host_retired');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tenant_id, 'acme');
    assert.equal(rows[0].host_id, OLD);
    assert.equal(rows[0].actor, 'user-1');
    assert.equal(rows[0].payload.reason, 'agent re-enrolled with a new state file');
    assert.equal(rows[0].payload.hostname, 'web1');
    assert.equal(rows[0].payload.forced, false);
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
    // The row is kept, readable by id, and a second retire is refused.
    assert.ok(r.fm.registry.hosts.has(OLD));
    assert.deepEqual(await retire(r, OLD, { reason: 'again' }), { status: 409, body: { error: 'already_retired' } });
    assert.equal(auditRows(r, 'host_retired').length, 1);
  } finally {
    await r.close();
  }
});

test('retire input: reason required and bounded, force must be boolean, unknown host 404', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, OLD);
    await disconnect(r, agent, OLD);
    for (const body of [{}, { reason: '' }, { reason: '   ' }, { reason: 7 }]) {
      assert.deepEqual(await retire(r, OLD, body), { status: 400, body: { error: 'reason_required' } }, JSON.stringify(body));
    }
    assert.deepEqual(await retire(r, OLD, { reason: 'x'.repeat(257) }), { status: 400, body: { error: 'bad_reason' } });
    assert.deepEqual(await retire(r, OLD, { reason: 'ok', force: 'yes' }), { status: 400, body: { error: 'bad_force' } });
    assert.equal((await retire(r, '33333333-3333-4333-8333-333333333333', { reason: 'ok' })).status, 404);
    assert.equal(auditRows(r, 'host_retired').length, 0);
    assert.equal(r.fm.registry.hosts.get(OLD).retired_at, null);
  } finally {
    await r.close();
  }
});

test('an online host is refused 409 host_online without force, and nothing changes', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, OLD);
    for (const body of [{ reason: 'cleanup' }, { reason: 'cleanup', force: false }]) {
      assert.deepEqual(await retire(r, OLD, body), { status: 409, body: { error: 'host_online', host_id: OLD } });
    }
    assert.equal(auditRows(r, 'host_retired').length, 0);
    assert.equal(r.fm.registry.hosts.get(OLD).retired_at, null);
    assert.equal(r.fm.connectedAgents.has(OLD), true);
    assert.equal(agent.closed, null);
  } finally {
    await r.close();
  }
});

test('force retires an online host: the agent socket is closed 4403 host_retired and cannot re-enroll', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, OLD);
    const res = await retire(r, OLD, { reason: 'decommissioned', force: true });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.forced, true);
    assert.equal(res.body.agent_closed, true);
    await waitUntil('agent closed', () => agent.closed);
    assert.deepEqual(agent.closed, { code: 4403, reason: 'host_retired' });
    await waitUntil('agent unregistered', () => !r.fm.connectedAgents.has(OLD));
    const rows = auditRows(r, 'host_retired');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].payload.forced, true);
    assert.equal(rows[0].payload.reason, 'decommissioned');
    // The same host_id (same key, same SSH key) is refused.
    const again = await connectAgent(r, OLD);
    assert.deepEqual(again.frames.find((f) => f.type === 'enroll_error'), { type: 'enroll_error', error: 'host_retired' });
    assert.equal(r.fm.connectedAgents.has(OLD), false);
    assert.equal(r.fm.registry.hosts.get(OLD).status, 'offline');
  } finally {
    await r.close();
  }
});

test('a retired host is left out of resolve, the fleet listing (unless asked), counts and policy lookups', async () => {
  const r = await rig();
  try {
    const old = await connectAgent(r, OLD);
    await disconnect(r, old, OLD);
    await r.fm.registry.setHostChannelPolicy(OLD, { file_policy: { roots: [{ path: '/srv/a', read: true, write: false }] } });
    await connectAgent(r, NEW);
    // Both rows recent: genuinely ambiguous before the retire.
    assert.deepEqual(await resolve(r, 'web1'), { status: 409, body: { error: 'ambiguous', matches: 2 } });
    assert.equal((await retire(r, OLD, { reason: 're-enrolled as ' + NEW })).status, 200);

    assert.deepEqual(await resolve(r, 'web1'), { status: 200, body: { host_id: NEW, hostname: 'web1', tenant: 'acme', status: 'online' } });
    assert.deepEqual(await resolve(r, OLD), { status: 404, body: { error: 'not_found' } });

    const listed = await call(r, 'GET', '/api/v1/fleet', { key: 'read-key' });
    assert.deepEqual(listed.body.hosts.map((h) => h.host_id), [NEW]);
    const all = await call(r, 'GET', '/api/v1/fleet?include_retired=1', { key: 'read-key' });
    assert.deepEqual(all.body.hosts.map((h) => h.host_id).sort(), [OLD, NEW].sort());
    assert.ok(all.body.hosts.find((h) => h.host_id === OLD).retired_at);
    assert.equal(all.body.hosts.find((h) => h.host_id === NEW).retired_at, null);

    assert.equal(await r.fm.registry.channelPolicies(OLD), null);
    assert.deepEqual(await r.fm.registry.countHosts(), { total: 1, online: 1, offline: 0 });
  } finally {
    await r.close();
  }
});

test('resolve prefers the single online row over offline rows older than the stale window', async () => {
  const r = await rig();
  try {
    const old = await connectAgent(r, OLD);
    await disconnect(r, old, OLD);
    await connectAgent(r, NEW);
    const oldRow = r.fm.registry.hosts.get(OLD);

    // Last seen 2 h ago: inside the default 24 h window, so still ambiguous.
    oldRow.last_seen_at = new Date(Date.now() - 2 * HOUR).toISOString();
    assert.deepEqual(await resolve(r, 'web1'), { status: 409, body: { error: 'ambiguous', matches: 2 } });

    // Last seen 25 h ago: the online row wins.
    oldRow.last_seen_at = new Date(Date.now() - 25 * HOUR).toISOString();
    assert.deepEqual(await resolve(r, 'WEB1'), { status: 200, body: { host_id: NEW, hostname: 'web1', tenant: 'acme', status: 'online' } });

    // A wider window makes the same row count again; a malformed value is the default.
    r.fm.env.SYSTEMAPI_RESOLVE_STALE_HOURS = '48';
    assert.equal((await resolve(r, 'web1')).status, 409);
    r.fm.env.SYSTEMAPI_RESOLVE_STALE_HOURS = 'soon';
    assert.equal((await resolve(r, 'web1')).status, 200);
    r.fm.env.SYSTEMAPI_RESOLVE_STALE_HOURS = '1';
    oldRow.last_seen_at = new Date(Date.now() - 2 * HOUR).toISOString();
    assert.equal((await resolve(r, 'web1')).body.host_id, NEW);
    delete r.fm.env.SYSTEMAPI_RESOLVE_STALE_HOURS;

    // Two online rows are ambiguous whatever their age.
    oldRow.last_seen_at = new Date(Date.now() - 25 * HOUR).toISOString();
    r.fm.connectedAgents.set(OLD, r.fm.connectedAgents.get(NEW));
    assert.equal((await resolve(r, 'web1')).status, 409);
    r.fm.connectedAgents.delete(OLD);

    // No online row: ambiguous.
    r.fm.connectedAgents.delete(NEW);
    assert.equal((await resolve(r, 'web1')).status, 409);
  } finally {
    await r.close();
  }
});

test('a non-admin key gets 403 scope_denied and nothing changes', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, OLD);
    await disconnect(r, agent, OLD);
    for (const key of ['read-key', 'write-key']) {
      assert.deepEqual(await retire(r, OLD, { reason: 'cleanup', force: true }, key), { status: 403, body: { error: 'scope_denied' } }, key);
    }
    assert.equal((await retire(r, OLD, { reason: 'cleanup' }, 'nope')).status, 403);
    assert.equal(auditRows(r, 'host_retired').length, 0);
    assert.equal(r.fm.registry.hosts.get(OLD).retired_at, null);
  } finally {
    await r.close();
  }
});

function runCli(r, args, key = 'admin-key') {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, '../cli/systemapi.js'), ...args], {
      env: { PATH: process.env.PATH, SYSTEMAPI_URL: r.url, SYSTEMAPI_API_KEY: key }
    });
    const out = [];
    const err = [];
    child.stdout.on('data', (chunk) => out.push(chunk));
    child.stderr.on('data', (chunk) => err.push(chunk));
    child.on('close', (status) => resolve({ status, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }));
  });
}

test('cli retire: reason required, host_online without --force, JSON on success', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, OLD);
    assert.equal((await runCli(r, ['retire', '--host', OLD])).status, 2);
    const refused = await runCli(r, ['retire', '--host', OLD, '--reason', 'gone']);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /host_online/);
    const denied = await runCli(r, ['retire', '--host', OLD, '--reason', 'gone', '--force'], 'read-key');
    assert.equal(denied.status, 1);
    assert.match(denied.stderr, /scope_denied/);
    const ok = await runCli(r, ['retire', '--host', OLD, '--reason', 'gone', '--force']);
    assert.equal(ok.status, 0, ok.stderr);
    const parsed = JSON.parse(ok.stdout);
    assert.equal(parsed.host_id, OLD);
    assert.equal(parsed.forced, true);
    assert.equal(parsed.agent_closed, true);
    await waitUntil('agent closed', () => agent.closed);
    assert.equal(auditRows(r, 'host_retired')[0].payload.reason, 'gone');
  } finally {
    await r.close();
  }
});

// --- lease signing key -----------------------------------------------------

const SEED_HEX = crypto.randomBytes(32).toString('hex');
const quiet = { log() {}, warn() {}, error() {} };

test('production refuses an unset or malformed SYSTEMAPI_ED25519_SEED', () => {
  assert.throws(() => assertSignerConfig({ NODE_ENV: 'production' }), /SYSTEMAPI_ED25519_SEED is not set/);
  assert.throws(() => loadSigner({ NODE_ENV: 'production' }, quiet), /SYSTEMAPI_ED25519_SEED is not set/);
  assert.throws(() => loadSigner({ NODE_ENV: 'production', SYSTEMAPI_ED25519_SEED: '' }, quiet), /is not set/);
  for (const bad of ['abc', SEED_HEX.slice(1), SEED_HEX + '0', 'z'.repeat(64), ` ${SEED_HEX}`]) {
    assert.throws(() => loadSigner({ NODE_ENV: 'production', SYSTEMAPI_ED25519_SEED: bad }, quiet), /must be 64 hex characters/);
    assert.throws(() => loadSigner({ NODE_ENV: 'development', SYSTEMAPI_ED25519_SEED: bad }, quiet), /must be 64 hex characters/);
  }
  // A good seed is stable across restarts.
  const a = loadSigner({ NODE_ENV: 'production', SYSTEMAPI_ED25519_SEED: SEED_HEX }, quiet);
  const b = loadSigner({ NODE_ENV: 'production', SYSTEMAPI_ED25519_SEED: SEED_HEX.toUpperCase() }, quiet);
  assert.equal(a.publicKeyB64, b.publicKeyB64);
});

test('development keeps the ephemeral key with the warning', () => {
  const lines = [];
  const logger = { log: (m) => lines.push(m) };
  const a = loadSigner({ NODE_ENV: 'development' }, logger);
  const b = loadSigner({}, logger);
  assert.notEqual(a.publicKeyB64, b.publicKeyB64);
  assert.ok(lines.some((m) => /ephemeral signing key; set SYSTEMAPI_ED25519_SEED/.test(m)));
});

test('server.js exits 1 before listening when production has no valid seed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'systemapi-seed-'));
  const envFile = path.join(dir, 'empty.env');
  fs.writeFileSync(envFile, '');
  try {
    for (const seed of [undefined, 'not-hex']) {
      const env = {
        PATH: process.env.PATH,
        ENV_FILE: envFile,
        NODE_ENV: 'production',
        SESSION_SECRET: crypto.randomBytes(16).toString('hex'),
        PORT: '0',
        HOST: '127.0.0.1'
      };
      if (seed !== undefined) env.SYSTEMAPI_ED25519_SEED = seed;
      const out = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js')], { env, encoding: 'utf8', timeout: 20000 });
      assert.equal(out.status, 1, `seed=${seed} stderr=${out.stderr}`);
      assert.match(out.stderr, seed === undefined ? /SYSTEMAPI_ED25519_SEED is not set.*refusing to start/ : /must be 64 hex characters; refusing to start/);
      assert.doesNotMatch(out.stdout, /listening/);
      if (seed) assert.doesNotMatch(out.stderr + out.stdout, /not-hex/);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
