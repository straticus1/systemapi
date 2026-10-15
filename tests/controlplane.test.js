'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { EventEmitter } = require('node:events');
const express = require('express');
const session = require('express-session');

const { MemoryRegistry, PgRegistry } = require('../controlplane/registry');
const { mount, clampEntitlements } = require('../controlplane/router');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { issueLease, verifyLease, canonicalLease, payloadHash } = require('../controlplane/lease');
const { tokenEqual, randomToken } = require('../controlplane/token');
const { demoKeyAllowed, agentAuthFromRequest, ticketFromRequest, corsOrigins, corsMiddleware, trustProxySetting } = require('../controlplane/httpauth');
const { validateSSHPublicKey } = require('../controlplane/sshkey');
const { assertWebhookURL } = require('../controlplane/webhook');
const { cronValid, cronMatches, zscore } = require('../controlplane/stats');
const { OPERATOR, scopesForKeyRows, scopesForRole, ticketScopesHeld } = require('../controlplane/authz');
const { sealSecret, openSecret } = require('../controlplane/seal');
const { refreshGauges } = require('../controlplane/index');
const { startDevice, pollToken, completeExternal, approveUserCode, safeReturnPath, sessionOwnsUser } = require('../controlplane/oauth');
const { consumeTicket, issueTicket } = require('../controlplane/tickets');
const FleetManager = require('../playground/fleet');
const AuthManager = require('../playground/auth');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';

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

function fleet() {
  const sig = signer();
  const registry = new MemoryRegistry({ NODE_ENV: 'test' });
  return {
    env: { NODE_ENV: 'test' },
    signer: sig,
    tickets: new Map(),
    registry,
    metrics: { executionsTotal: { inc() {} } },
    lastPush: null,
    async verifyApiKey(key) {
      if (key === 'good-key') return { key_id: 'ak_test', user_id: 'user-1' };
      return null;
    },
    async pushSysscript(hostId, script, entitlements, requestId, lease) {
      this.lastPush = { hostId, script, entitlements, requestId, lease };
      return { output: 'ok' };
    }
  };
}

function appFor(fm, sessionUser) {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  // Production-like: server.js parses forms with extended: true and does not
  // store sessions nobody wrote to.
  app.use(express.urlencoded({ extended: true, limit: '256kb' }));
  app.use(session({
    secret: 'test-secret-not-production',
    resave: false,
    saveUninitialized: false
  }));
  if (sessionUser) {
    app.use((req, _res, next) => {
      req.session.user = sessionUser;
      next();
    });
  }
  mount(app, fm);
  return app;
}

// Binds an Authentik sub to every membership row of userId (as an admin
// would) and returns the session user Authentik would produce for it.
async function ssoUser(fm, userId, extra = {}, sub = 'sub-' + userId) {
  for (const m of await fm.registry.membershipsForUser(userId)) {
    await fm.registry.setSsoSub({ tenantId: m.tenant_id, userId, sub, actor: 'test' });
  }
  return { id: sub, ...extra };
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      resolve({ server, url: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

async function call(url, opts = {}) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let body = text;
  try { body = text ? JSON.parse(text) : null; } catch { /* text */ }
  return { status: res.status, body };
}

async function seed(fm) {
  const pub = opensshEd25519(fm.signer.publicKeyRaw);
  await fm.registry.enroll({
    tenantId: 'acme', userId: 'user-1', keyId: 'k1', hostId: HOST_A,
    hostname: 'a.example', os: 'linux', platform: 'amd64', sshPubkey: pub
  });
  await fm.registry.enroll({
    tenantId: 'beta', userId: 'user-2', keyId: 'k2', hostId: HOST_B,
    hostname: 'b.example', os: 'linux', platform: 'amd64', sshPubkey: pub
  });
  return pub;
}

test('demo key is off unless the flag is set outside production', () => {
  assert.equal(demoKeyAllowed({ SYSTEMAPI_ALLOW_DEMO: '1', NODE_ENV: 'production' }), false);
  assert.equal(demoKeyAllowed({ SYSTEMAPI_ALLOW_DEMO: '0', NODE_ENV: 'development' }), false);
  assert.equal(demoKeyAllowed({ NODE_ENV: 'development' }), false);
  assert.equal(demoKeyAllowed({ SYSTEMAPI_ALLOW_DEMO: '1', NODE_ENV: 'development' }), true);
});

test('demo key is rejected when the flag is off and when the database throws', async () => {
  const server = new EventEmitter();
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'production', SYSTEMAPI_ALLOW_DEMO: '1' };
  assert.equal(await fm.verifyApiKey('ak_live_1234.demo'), null);
  fm.env = { NODE_ENV: 'development', SYSTEMAPI_ALLOW_DEMO: '1' };
  const demo = await fm.verifyApiKey('ak_live_1234.demo');
  assert.equal(demo.user_id, 'demo_user');
  fm.env = { NODE_ENV: 'development' };
  assert.equal(await fm.verifyApiKey('ak_live_1234.demo'), null);
  fm.db = { query: async () => { throw new Error('db down'); } };
  assert.equal(await fm.verifyApiKey('ak_live_abcd.secret'), null);
});

test('query-string API keys and non-ticket terminal upgrades are rejected', () => {
  const url = new URL('http://127.0.0.1/api/v1/systems/stream?api_key=secret');
  assert.equal(agentAuthFromRequest(url, { authorization: 'Bearer good' }).error, 'query_key_rejected');
  const ticketUrl = new URL('http://127.0.0.1/api/v1/systems/terminal/h?api_key=secret');
  assert.equal(ticketFromRequest(ticketUrl).error, 'query_key_rejected');
  const ok = new URL('http://127.0.0.1/api/v1/systems/stream');
  assert.equal(agentAuthFromRequest(ok, { authorization: 'Bearer good' }).ok, true);
  assert.equal(agentAuthFromRequest(ok, { authorization: 'Bearer  good' }).ok, false);
});

test('private SSH keys and bad wire forms are rejected', () => {
  assert.throws(() => validateSSHPublicKey('-----BEGIN OPENSSH PRIVATE KEY-----\nabc'), /private_key_rejected/);
  assert.throws(() => validateSSHPublicKey('ssh-rsa AAAA'), /bad_ssh_pubkey/);
  const pub = opensshEd25519(Buffer.alloc(32, 7));
  assert.equal(validateSSHPublicKey(pub), pub);
});

test('webhook targets that point at metadata or production loopback are rejected', () => {
  assert.throws(() => assertWebhookURL('http://169.254.169.254/latest', { NODE_ENV: 'production' }), /blocked_url|https_required/);
  assert.throws(() => assertWebhookURL('https://169.254.1.1/hook', { NODE_ENV: 'test' }), /blocked_url/);
  assert.throws(() => assertWebhookURL('https://[::ffff:169.254.169.254]/latest', { NODE_ENV: 'test' }), /blocked_url/);
  assert.throws(() => assertWebhookURL('https://metadata.google.internal/computeMetadata/v1/', { NODE_ENV: 'production' }), /blocked_url/);
  assert.throws(() => assertWebhookURL('https://127.0.0.1/hook', { NODE_ENV: 'production' }), /blocked_url/);
  assert.throws(() => assertWebhookURL('http://hooks.example/in', { NODE_ENV: 'production' }), /https_required/);
  assert.equal(assertWebhookURL('https://hooks.example/in', { NODE_ENV: 'production' }).hostname, 'hooks.example');
});

test('cron and z-score helpers fail closed on bad input', () => {
  assert.equal(cronValid('*/5 * * * *'), true);
  assert.equal(cronValid('* * * *'), false);
  assert.equal(cronValid('60 * * * *'), false);
  assert.equal(cronMatches('*/5 * * * *', new Date('2026-01-01T00:05:00Z')), true);
  assert.equal(cronMatches('not a cron', new Date()), false);
  const base = [10, 11, 9, 10, 12, 8, 10, 11];
  assert.equal(zscore([...base, 10]).anomalous, false);
  assert.equal(zscore([...base, 100]).anomalous, true);
  assert.equal(zscore(Array(9).fill(10)).reason, 'flat');
  assert.equal(zscore([1, 2, 3]).reason, 'insufficient');
});

test('tokens compare by hash and refuse short output', () => {
  const a = randomToken(16);
  assert.equal(tokenEqual(a, a), true);
  assert.equal(tokenEqual(a, randomToken(16)), false);
  assert.equal(tokenEqual(a, 1), false);
  assert.equal(tokenEqual(null, null), false);
  assert.throws(() => randomToken(8), /minimum/);
});

test('leases reject expiry, tamper, payload swap, and a far-future expiry', () => {
  const sig = signer();
  const now = 1700000000000;
  const lease = issueLease(sig, { hostId: HOST_A, action: 'sysscript', payload: 'print(1)\n', ttl: 60, now });
  const pub = sig.privateKey; // verifyLease accepts a KeyObject; public is derived inside crypto.verify from private? 
  // crypto.verify wants the public key. Pass the private KeyObject: Node accepts it for verify.
  assert.equal(verifyLease(pub, lease, 'print(1)\n', now).ok, true);
  const tampered = { ...lease, signature: lease.signature.slice(0, -2) + 'aa' };
  assert.equal(verifyLease(pub, tampered, 'print(1)\n', now).error, 'bad_signature');
  assert.equal(verifyLease(pub, lease, 'print(2)\n', now).error, 'payload_mismatch');
  assert.equal(verifyLease(pub, lease, 'print(1)\n', now + 120000).error, 'expired');
  const far = { ...lease, expires_unix: Math.floor(now / 1000) + 301 };
  assert.equal(verifyLease(pub, far, 'print(1)\n', now).ok, false);
  const stolen = { ...lease, host_id: HOST_B };
  assert.equal(verifyLease(pub, stolen, 'print(1)\n', now).error, 'bad_signature');
});

test('deterministic lease vector matches the Go fixture', () => {
  const sig = signer();
  const now = 1700000000000;
  const payload = 'print(1)\n';
  const expiresUnix = Math.floor(now / 1000) + 60;
  const nonceHex = 'ab'.repeat(16);
  const payloadSha256 = payloadHash('sysscript', payload);
  const message = canonicalLease({ hostId: HOST_A, action: 'sysscript', expiresUnix, nonceHex, payloadSha256 });
  const lease = {
    v: 1,
    host_id: HOST_A,
    action: 'sysscript',
    expires_unix: expiresUnix,
    nonce_hex: nonceHex,
    payload_sha256: payloadSha256,
    signature: sig.sign(message)
  };
  const vector = {
    seed_hex: TEST_SEED.toString('hex'),
    public_raw_b64: sig.publicKeyB64,
    host_id: HOST_A,
    action: 'sysscript',
    payload,
    now_ms: now,
    message,
    lease
  };
  const file = path.join(__dirname, '..', 'controlplane', 'testdata', 'lease-vector.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const encoded = `${JSON.stringify(vector, null, 2)}\n`;
  if (!fs.existsSync(file)) fs.writeFileSync(file, encoded);
  const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(stored.lease, lease);
  assert.equal(stored.message, message);
  assert.equal(verifyLease(sig.privateKey, stored.lease, payload, now).ok, true);
});

test('audit hash chain detects a tampered payload', async () => {
  const reg = new MemoryRegistry({});
  await reg.appendAudit({ tenant_id: 'acme', action: 'sysscript', payload: { n: 1 } });
  await reg.appendAudit({ tenant_id: 'acme', action: 'sysscript', payload: { n: 2 } });
  assert.equal((await reg.verifyAudit()).ok, true);
  reg.audit[0].payload.n = 9;
  const broken = await reg.verifyAudit();
  assert.equal(broken.ok, false);
  assert.equal(broken.broken_at, 1);
});

test('a member cannot create a second tenant or steal a host', async () => {
  const reg = new MemoryRegistry({});
  const pub = opensshEd25519(Buffer.alloc(32, 3));
  await reg.enroll({
    tenantId: 'acme', userId: 'user-1', keyId: 'k1', hostId: HOST_A,
    hostname: 'a.example', os: 'linux', platform: 'amd64', sshPubkey: pub
  });
  await assert.rejects(
    () => reg.enroll({
      tenantId: 'gamma', userId: 'user-1', keyId: 'k1', hostId: HOST_B,
      hostname: 'g.example', os: 'linux', platform: 'amd64', sshPubkey: pub
    }),
    (err) => err.message === 'tenant_create_denied'
  );
  await reg.enroll({
    tenantId: 'beta', userId: 'user-2', keyId: 'k2', hostId: HOST_B,
    hostname: 'b.example', os: 'linux', platform: 'amd64', sshPubkey: pub
  });
  await assert.rejects(
    () => reg.enroll({
      tenantId: 'beta', userId: 'user-2', keyId: 'k2', hostId: HOST_A,
      hostname: 'stolen.example', os: 'linux', platform: 'amd64', sshPubkey: pub
    }),
    (err) => err.message === 'host_steal'
  );
  assert.equal(await reg.getHost(['beta'], HOST_A), null);
});

test('fleet routes reject query keys, hide other tenants, and refuse viewer exec', async () => {
  const fm = fleet();
  await seed(fm);
  await fm.registry.setScopes('ak_test', OPERATOR);
  await fm.registry.addMember('acme', 'viewer-1', 'viewer', 'view@example');
  const { server, url } = await listen(appFor(fm));
  try {
    const query = await call(`${url}/api/v1/fleet?api_key=good-key`);
    assert.equal(query.status, 401);
    assert.equal(query.body.error, 'query_key_rejected');

    const bad = await call(`${url}/api/v1/fleet`, { headers: { 'x-api-key': 'nope' } });
    assert.equal(bad.status, 403);

    const list = await call(`${url}/api/v1/fleet`, { headers: { 'x-api-key': 'good-key' } });
    assert.equal(list.status, 200);
    assert.equal(list.body.hosts.length, 1);
    assert.equal(list.body.hosts[0].host_id, HOST_A);
    assert.equal(list.body.hosts[0].key_id, undefined);

    const other = await call(`${url}/api/v1/fleet/${HOST_B}/software`, { headers: { 'x-api-key': 'good-key' } });
    assert.equal(other.status, 404);
    assert.equal(other.body.error, 'not_found');

    const exec = await call(`${url}/api/v1/fleet/${HOST_A}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'good-key' },
      body: JSON.stringify({ script: 'print(1)\n', entitlements: { allow_exec: true, allow_fs_write: true } })
    });
    assert.equal(exec.status, 200);
    assert.equal(exec.body.success, true);
    assert.equal(fm.lastPush.lease.action, 'sysscript');
    assert.ok(fm.lastPush.lease.signature);
    assert.equal(fm.lastPush.entitlements.allow_exec, true);
    assert.equal(fm.lastPush.entitlements.allow_fs_write, false);
  } finally {
    server.close();
  }
});

test('a viewer session cannot execute and an unbound session is refused', async () => {
  const fm = fleet();
  await seed(fm);
  await fm.registry.addMember('acme', 'viewer-1', 'viewer', 'view@example');
  const viewerApp = appFor(fm, await ssoUser(fm, 'viewer-1', { email: 'view@example', groups: [] }));
  // Its email matches a member and it claims the admin group: still no sub
  // binding, so it is refused.
  const emptyApp = appFor(fm, { id: 'stranger', email: 'view@example', groups: ['systemapi-admins'] });
  const viewer = await listen(viewerApp);
  const empty = await listen(emptyApp);
  try {
    const denied = await call(`${viewer.url}/api/v1/fleet/${HOST_A}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ script: 'print(1)\n' })
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error, 'scope_denied');
    const hosts = await call(`${empty.url}/api/v1/fleet`);
    assert.equal(hosts.status, 403);
    assert.equal(hosts.body.error, 'sso_unbound');
  } finally {
    viewer.server.close();
    empty.server.close();
  }
});

test('a terminal ticket is single use', () => {
  const store = new Map();
  const ticket = issueTicket(store, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme' });
  assert.equal(consumeTicket(store, ticket, HOST_A, 'terminal:open').hostId, HOST_A);
  assert.equal(consumeTicket(store, ticket, HOST_A, 'terminal:open'), null);
});

test('JWT rejects none, a header algorithm, and unsigned fallback', async () => {
  // Discovery unreachable (offline fetch): nothing may verify without it.
  const mgr = new AuthManager('https://idp.example', 'afterdark', 'systemapi', 'systemapi', null, {
    env: {},
    customFetch: async () => { throw new TypeError('fetch failed'); }
  });
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ iss: 'https://idp.example/realms/afterdark', exp: 9999999999 })}.`;
  assert.equal(await mgr.verifyJWTToken(none), null);
  const hs = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'https://idp.example/realms/afterdark' })}.sig`;
  assert.equal(await mgr.verifyJWTToken(hs), null);
  const rs = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ iss: 'https://idp.example/realms/afterdark', aud: 'systemapi', exp: 9999999999 })}.sig`;
  assert.equal(await mgr.verifyJWTToken(rs), null);
});

test('registry is not ready until boot, so the route fails closed', async () => {
  const fm = fleet();
  fm.registry = null;
  const { server, url } = await listen(appFor(fm));
  try {
    const res = await call(`${url}/api/v1/fleet`, { headers: { 'x-api-key': 'good-key' } });
    assert.equal(res.status, 503);
  } finally {
    server.close();
  }
});

test('an API key with no scope rows cannot read or execute', () => {
  assert.equal(scopesForKeyRows([], {}).size, 0);
  assert.equal(scopesForKeyRows([], { SYSTEMAPI_REQUIRE_SCOPES: '1' }).size, 0);
  const legacy = scopesForKeyRows([], { SYSTEMAPI_REQUIRE_SCOPES: '0' });
  assert.equal(legacy.has('exec:run'), true);
  assert.equal(legacy.has('breakglass:open'), false);
  assert.equal(legacy.has('admin'), false);
  const explicit = scopesForKeyRows(['hosts:read'], {});
  assert.deepEqual([...explicit], ['hosts:read']);
});

test('a channel ticket from a revoked, locked or expired API key fails the upgrade re-check', async () => {
  const operator = async () => [{ tenant_id: 'acme', user_id: 'user-1', role: 'operator' }];
  const reg = new MemoryRegistry({ NODE_ENV: 'test' });
  reg.membershipsForUser = operator;
  await reg.setScopes('k1', ['tcp:open']);
  const row = { actor: 'user-1', tenantId: 'acme', auth: { kind: 'key', keyId: 'k1' } };
  assert.equal(await ticketScopesHeld(reg, row, ['tcp:open']), true);
  await reg.revokeKey('k1');
  assert.equal(await ticketScopesHeld(reg, row, ['tcp:open']), false);
  // A registry that cannot say whether the key is active refuses.
  const blind = new MemoryRegistry({ NODE_ENV: 'test' });
  blind.membershipsForUser = operator;
  await blind.setScopes('k1', ['tcp:open']);
  blind.keyActive = undefined;
  assert.equal(await ticketScopesHeld(blind, row, ['tcp:open']), false);
  blind.keyActive = async () => { throw new Error('db down'); };
  assert.equal(await ticketScopesHeld(blind, row, ['tcp:open']), false);
  blind.keyActive = async () => 1;
  assert.equal(await ticketScopesHeld(blind, row, ['tcp:open']), false);

  // PgRegistry asks the key table with the verifyApiKey rules, parameterized.
  const queries = [];
  let rows = [];
  const pg = new PgRegistry({ query: async (sql, params) => { queries.push({ sql, params }); return { rows }; } }, { NODE_ENV: 'production' });
  assert.equal(await pg.keyActive('ak_gone'), false);
  rows = [{ '?column?': 1 }];
  assert.equal(await pg.keyActive('ak_live'), true);
  assert.deepEqual(queries.map((q) => q.params), [['ak_gone'], ['ak_live']]);
  assert.match(queries[0].sql, /is_active = true AND is_locked = false/);
  assert.match(queries[0].sql, /expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP/);
  assert.equal(await pg.keyActive(''), false);
  assert.equal(await pg.keyActive(null), false);
  // The demo key has no row: active only where the demo key is allowed.
  assert.equal(await pg.keyActive('ak_live_1234'), false);
  const dev = new PgRegistry({ query: async () => ({ rows: [] }) }, { NODE_ENV: 'development', SYSTEMAPI_ALLOW_DEMO: '1' });
  assert.equal(await dev.keyActive('ak_live_1234'), true);
});

test('an unscored key is denied on the fleet routes', async () => {
  const fm = fleet();
  await seed(fm);
  const { server, url } = await listen(appFor(fm));
  try {
    const list = await call(`${url}/api/v1/fleet`, { headers: { 'x-api-key': 'good-key' } });
    assert.equal(list.status, 403);
    assert.equal(list.body.error, 'scope_denied');
    const exec = await call(`${url}/api/v1/fleet/${HOST_A}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'good-key' },
      body: JSON.stringify({ script: 'print(1)\n' })
    });
    assert.equal(exec.status, 403);
    assert.equal(exec.body.error, 'scope_denied');
    assert.equal(fm.lastPush, null);
  } finally {
    server.close();
  }
});

test('security events from another tenant or no tenant are not listed', async () => {
  const reg = new MemoryRegistry({});
  await reg.recordSecurity({ kind: 'enroll_fail', detail: { error: 'bad_key' } });
  await reg.recordSecurity({ tenant_id: 'beta', kind: 'auth_fail', detail: { error: 'nope' } });
  await reg.recordSecurity({ tenant_id: 'acme', kind: 'auth_fail', detail: { error: 'mine' } });
  const rows = await reg.listSecurity(['acme']);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].tenant_id, 'acme');
  assert.equal(rows[0].detail.error, 'mine');
  assert.deepEqual(await reg.listSecurity([]), []);
});

test('refreshGauges sets the open alert count', async () => {
  const reg = new MemoryRegistry({});
  await reg.openAlert({ tenant_id: 'acme', host_id: HOST_A, rule_name: 'cpu', value: 99 });
  await reg.openAlert({ tenant_id: 'beta', host_id: HOST_B, rule_name: 'mem', value: 99 });
  const resolved = await reg.openAlert({ tenant_id: 'acme', host_id: HOST_A, rule_name: 'disk', value: 1 });
  await reg.setAlertStatus(['acme'], resolved.id, 'resolved');
  let open = null;
  await refreshGauges({
    registry: reg,
    connectedAgents: new Set(),
    metrics: {
      hostTotalGauge: { set() {} },
      hostOnlineGauge: { set() {} },
      hostOfflineGauge: { set() {} },
      alertsActiveGauge: { set(value) { open = value; } }
    }
  });
  assert.equal(open, 2);
});

test('webhook secrets are sealed and a missing key stores nothing', async () => {
  const key = 'ab'.repeat(32);
  const other = 'cd'.repeat(32);
  const sealed = sealSecret('hook-secret-value', { SYSTEMAPI_WEBHOOK_KEY: key });
  const again = sealSecret('hook-secret-value', { SYSTEMAPI_WEBHOOK_KEY: key });
  assert.equal(sealed.startsWith('v1.'), true);
  assert.notEqual(sealed, again);
  assert.notEqual(sealed, 'hook-secret-value');
  assert.equal(openSecret(sealed, { SYSTEMAPI_WEBHOOK_KEY: key }), 'hook-secret-value');
  assert.throws(
    () => openSecret(sealed, { SYSTEMAPI_WEBHOOK_KEY: other }),
    (err) => err.code === 'webhook_secret_rejected'
  );
  assert.throws(
    () => openSecret('plaintext-secret', { SYSTEMAPI_WEBHOOK_KEY: key }),
    (err) => err.code === 'webhook_secret_rejected'
  );
  const flipped = sealed.slice(0, -1) + (sealed.endsWith('a') ? 'b' : 'a');
  assert.throws(
    () => openSecret(flipped, { SYSTEMAPI_WEBHOOK_KEY: key }),
    (err) => err.code === 'webhook_secret_rejected'
  );
  assert.throws(
    () => sealSecret('x', {}),
    (err) => err.status === 503 && err.code === 'webhook_key_unavailable'
  );
  assert.throws(
    () => openSecret(sealed, {}),
    (err) => err.status === 503 && err.code === 'webhook_key_unavailable'
  );

  const fm = fleet();
  await seed(fm);
  const { server, url } = await listen(appFor(fm, await ssoUser(fm, 'user-1', { email: 'a@example', groups: [] })));
  try {
    const missing = await call(`${url}/api/v1/webhooks`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tenant_id: 'acme', url: 'https://hooks.example/systemapi' })
    });
    assert.equal(missing.status, 503);
    assert.equal(missing.body.error, 'webhook_key_unavailable');
    assert.equal(fm.registry.webhooks.length, 0);

    fm.env.SYSTEMAPI_WEBHOOK_KEY = key;
    const created = await call(`${url}/api/v1/webhooks`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tenant_id: 'acme', url: 'https://hooks.example/systemapi' })
    });
    assert.equal(created.status, 201);
    const stored = fm.registry.webhooks[0].secret;
    assert.equal(stored.startsWith('v1.'), true);
    assert.notEqual(stored, created.body.secret);
    assert.equal(openSecret(stored, fm.env), created.body.secret);
    assert.equal(created.body.secret_fingerprint.length, 64);
    assert.equal(JSON.stringify(created.body).includes(stored), false);

    const listed = await call(`${url}/api/v1/webhooks?tenant_id=acme`);
    assert.equal(listed.status, 200);
    assert.equal(listed.body.webhooks[0].secret, undefined);
    assert.equal(JSON.stringify(listed.body).includes(created.body.secret), false);
  } finally {
    server.close();
  }
});

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const USER_CODE_SHAPE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;

function armPublic(fm, origin) {
  fm.env.NODE_ENV = 'test';
  fm.env.SYSTEMAPI_PUBLIC_URL = origin;
}

function deviceRows(fm) {
  return fm.registry.oauthDevices ? [...fm.registry.oauthDevices.values()] : [];
}

function postJson(url, pathname, body, headers) {
  return call(url + pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body)
  });
}

// One browser: keeps the session cookie between requests.
function browser() {
  let cookie = '';
  const go = async function go(target, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (cookie) headers.cookie = cookie;
    const res = await fetch(target, { ...opts, headers });
    for (const line of res.headers.getSetCookie()) cookie = line.split(';')[0];
    return res;
  };
  go.cookie = () => cookie;
  return go;
}

function csrfIn(html) {
  const m = /name="csrf" value="([^"]+)"/.exec(html);
  return m ? m[1] : null;
}

async function textOf(res) {
  const text = await res.text();
  try { return { status: res.status, body: JSON.parse(text), headers: res.headers }; } catch {
    return { status: res.status, body: text, headers: res.headers };
  }
}

function postForm(go, target, fields) {
  return go(target, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString()
  });
}

// Loads the verify page in this browser and returns its CSRF token.
async function pageCsrf(go, url) {
  return csrfIn(await (await go(url + '/oauth/device/verify')).text());
}

// The whole browser flow: open the page, type the code, see the confirm page,
// then press Yes (or a provider button when extra.provider is set).
async function verifyAs(go, url, code, extra = { confirm: 'yes' }) {
  const csrf = (await pageCsrf(go, url)) || '';
  const confirm = await postForm(go, url + '/oauth/device/verify', { user_code: code, csrf });
  if (confirm.status !== 200) return confirm;
  await confirm.text();
  return postForm(go, url + '/oauth/device/verify', { user_code: code, csrf, ...extra });
}

function runCli(args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, '../cli/systemapi.js'), ...args], { env });
    const out = [];
    const err = [];
    child.stdout.on('data', (chunk) => out.push(chunk));
    child.stderr.on('data', (chunk) => err.push(chunk));
    child.on('close', (status) => {
      resolve({
        status,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8')
      });
    });
  });
}

test('oauth device start returns the RFC 8628 shape and fails closed', async () => {
  const fm = fleet();
  await seed(fm);
  const { server, url } = await listen(appFor(fm));
  try {
    const down = await postJson(url, '/oauth/device', { username: 'user-1' });
    assert.equal(down.status, 503);
    assert.equal(down.body.error, 'oauth_unavailable');
    assert.equal(fm.registry.oauthDevices, undefined);

    armPublic(fm, url);
    for (const username of ['no-such-user', 'not a user', '', '../user-1', 'user-9']) {
      const denied = await postJson(url, '/oauth/device', { username });
      assert.equal(denied.status, 403, username);
      assert.deepEqual(denied.body, { error: 'login_denied' });
    }
    assert.equal(deviceRows(fm).length, 0);

    const badPublic = [
      { NODE_ENV: 'production', SYSTEMAPI_PUBLIC_URL: 'http://127.0.0.1:9' },
      { NODE_ENV: 'production', SYSTEMAPI_PUBLIC_URL: 'https://169.254.169.254' },
      { NODE_ENV: 'test', SYSTEMAPI_PUBLIC_URL: 'http://169.254.1.1' },
      { NODE_ENV: 'production', SYSTEMAPI_PUBLIC_URL: 'https://2852039166' },
      { NODE_ENV: 'production', SYSTEMAPI_PUBLIC_URL: 'https://[::ffff:169.254.169.254]' },
      { NODE_ENV: 'test', SYSTEMAPI_PUBLIC_URL: 'http://metadata.google.internal' },
      { NODE_ENV: 'production', SYSTEMAPI_PUBLIC_URL: 'https://cp.example/oauth' }
    ];
    for (const env of badPublic) {
      await assert.rejects(
        () => startDevice(fm.registry, 'user-1', env),
        (err) => err.status === 503 && err.code === 'oauth_unavailable'
      );
    }
    assert.equal(deviceRows(fm).length, 0);

    // Exactly the RFC 8628 fields the sahconnect client expects; no
    // verification_uri_complete and no code in any URL.
    const started = await call(url + '/oauth/device', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'cli-test/1.0' },
      body: 'username=user-1&interval=99'
    });
    assert.equal(started.status, 200);
    assert.deepEqual(Object.keys(started.body).sort(), ['device_code', 'expires_in', 'interval', 'user_code', 'verification_uri']);
    assert.equal(started.body.verification_uri, url + '/oauth/device/verify');
    const uri = new URL(started.body.verification_uri);
    assert.equal(uri.search + uri.hash + uri.username + uri.password, '');
    assert.match(started.body.user_code, USER_CODE_SHAPE);
    assert.match(started.body.user_code, /^[A-Z0-9-]{4,12}$/);
    assert.equal(started.body.expires_in, 600);
    assert.equal(started.body.interval, 0);
    assert.equal(started.body.device_code.length >= 16, true);
    const row = deviceRows(fm)[0];
    assert.equal(row.requester_ua, 'cli-test/1.0');
    assert.equal(typeof row.requester_ip, 'string');
    assert.equal(JSON.stringify(row).includes(started.body.user_code.replace('-', '')), false);

    // An anonymous GET, even carrying a code, gets the SSO link only: no
    // session cookie, no CSRF token, no form, no code echoed.
    const anon = await fetch(url + '/oauth/device/verify?code=' + encodeURIComponent(started.body.user_code));
    const anonHtml = await anon.text();
    assert.equal(anon.status, 200);
    assert.deepEqual(anon.headers.getSetCookie(), []);
    assert.equal(csrfIn(anonHtml), null);
    assert.equal(anonHtml.includes('<form'), false);
    assert.equal(anonHtml.includes(started.body.user_code), false);
    const link = /href="([^"]+)">Sign in with After Dark SSO</.exec(anonHtml);
    assert.ok(link);
    const loginUrl = new URL(link[1].replace(/&amp;/g, '&'), url);
    assert.equal(loginUrl.pathname, '/oauth/login');
    assert.equal(loginUrl.searchParams.get('return_to'), '/oauth/device/verify');
    assert.equal(row.status, 'pending');
  } finally {
    server.close();
  }
});

test('oauth device login: the owner types the code, confirms, and gets one bearer', async () => {
  const fm = fleet();
  await seed(fm);
  await fm.registry.addMember('acme', 'viewer-1', 'viewer', 'view@example');
  await fm.registry.setScopes('ak_test', OPERATOR);
  const { server, url } = await listen(appFor(fm, await ssoUser(fm, 'user-1')));
  const viewerApp = await listen(appFor(fm, await ssoUser(fm, 'viewer-1')));
  armPublic(fm, url);
  const go = browser();
  const poll = (deviceCode) => postJson(url, '/oauth/token', { grant_type: DEVICE_GRANT, device_code: deviceCode });
  try {
    const started = await call(url + '/oauth/device', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'cli-test/2.0' },
      body: 'username=user-1'
    });
    const userCode = started.body.user_code;
    assert.equal((await poll(started.body.device_code)).body.error, 'authorization_pending');

    // GET with ?code neither pre-fills nor approves.
    const pageRes = await go(url + '/oauth/device/verify?code=' + encodeURIComponent(userCode) + '&confirm=yes');
    const html = await pageRes.text();
    assert.equal(pageRes.status, 200);
    assert.equal(pageRes.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(pageRes.headers.get('cache-control'), 'no-store');
    assert.equal(pageRes.headers.get('x-content-type-options'), 'nosniff');
    assert.match(html, /name="user_code"/);
    assert.equal(html.includes(userCode), false);
    assert.equal(html.includes(userCode.replace('-', '')), false);
    assert.equal(html.includes('<script'), false);
    const csrf = csrfIn(html);
    assert.equal(typeof csrf, 'string');
    assert.equal((await poll(started.body.device_code)).body.error, 'authorization_pending');

    // The code alone (the old bypass) and a missing or wrong CSRF token are refused.
    const bare = await postJson(url, '/oauth/device/verify', { user_code: userCode, confirm: 'yes' });
    assert.equal(bare.status, 403);
    assert.equal(bare.body.error, 'csrf_denied');
    const noCsrf = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: userCode, confirm: 'yes' }));
    assert.equal(noCsrf.status, 403);
    assert.equal(noCsrf.body.error, 'csrf_denied');
    const wrongCsrf = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: userCode, csrf: 'x'.repeat(csrf.length) }));
    assert.equal(wrongCsrf.status, 403);
    assert.equal(wrongCsrf.body.error, 'csrf_denied');
    const otherBrowser = await postJson(url, '/oauth/device/verify', { user_code: userCode, csrf, confirm: 'yes' });
    assert.equal(otherBrowser.status, 403);
    assert.equal(otherBrowser.body.error, 'csrf_denied');
    assert.equal((await poll(started.body.device_code)).body.error, 'authorization_pending');

    // Yes before the confirm page was shown in this session is refused.
    const skipped = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: userCode, csrf, confirm: 'yes' }));
    assert.equal(skipped.status, 403);
    assert.equal(skipped.body.error, 'login_denied');

    // Typing the code (any case, no dash) shows who asked, then Yes approves.
    const typed = userCode.replace('-', '').toLowerCase();
    const confirm = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: typed, csrf }));
    assert.equal(confirm.status, 200);
    assert.match(confirm.body, /Only continue if you started this login yourself/);
    assert.match(confirm.body, /cli-test\/2\.0/);
    assert.match(confirm.body, /From IP: <strong>[0-9a-f:.]+<\/strong>/);
    assert.match(confirm.body, /Started: <strong>\d{4}-\d\d-\d\dT/);
    assert.equal((await poll(started.body.device_code)).body.error, 'authorization_pending');
    const yes = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: typed, csrf, confirm: 'yes' }));
    assert.equal(yes.status, 200);
    assert.match(yes.body, /Signed in/);
    assert.equal(yes.body.includes(userCode), false);
    assert.equal(yes.body.includes(started.body.device_code), false);
    const reused = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: userCode, csrf }));
    assert.equal(reused.status, 403);
    assert.match(reused.body, /not accepted/);

    const tokenRes = await poll(started.body.device_code);
    assert.equal(tokenRes.status, 200);
    assert.equal(tokenRes.body.token_type, 'Bearer');
    assert.equal(tokenRes.body.expires_in, 3600);
    const access = tokenRes.body.access_token;
    assert.equal((await poll(started.body.device_code)).body.error, 'invalid_grant');
    const wrongGrant = await postJson(url, '/oauth/token', { grant_type: 'authorization_code', device_code: started.body.device_code });
    assert.equal(wrongGrant.status, 400);
    assert.equal(wrongGrant.body.error, 'unsupported_grant_type');

    const list = await call(url + '/api/v1/fleet', { headers: { authorization: 'Bearer ' + access } });
    assert.equal(list.status, 200);
    assert.equal(list.body.hosts.length, 1);
    assert.equal(list.body.hosts[0].host_id, HOST_A);
    const spaced = await call(url + '/api/v1/fleet', { headers: { authorization: 'Bearer ' + access + ' x' } });
    assert.equal(spaced.status, 401);
    assert.equal(spaced.body.error, 'bearer_required');

    // An expired code is refused like a wrong one, and the poll says expired.
    const expiring = await postJson(url, '/oauth/device', { username: 'user-1' });
    const pendingRow = deviceRows(fm).find((row) => row.status === 'pending');
    pendingRow.expires_at = new Date(Date.now() - 1000).toISOString();
    const expiredYes = await textOf(await verifyAs(go, url, expiring.body.user_code));
    assert.equal(expiredYes.status, 403);
    assert.match(expiredYes.body, /not accepted/);
    assert.equal((await poll(expiring.body.device_code)).body.error, 'expired_token');

    const viewStart = await postJson(url, '/oauth/device', { username: 'viewer-1' });
    const viewYes = await textOf(await verifyAs(browser(), viewerApp.url, viewStart.body.user_code));
    assert.equal(viewYes.status, 200);
    const viewToken = await poll(viewStart.body.device_code);
    const denied = await call(url + '/api/v1/fleet/' + HOST_A + '/execute', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + viewToken.body.access_token },
      body: JSON.stringify({ script: 'print(1)\n' })
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error, 'scope_denied');

    const stored = [...fm.registry.oauthAccess.values()].find((row) => row.user_id === 'user-1');
    stored.expires_at = new Date(Date.now() - 1000).toISOString();
    const rejected = await call(url + '/api/v1/fleet', { headers: { authorization: 'Bearer ' + access } });
    assert.equal(rejected.status, 403);
    assert.equal(rejected.body.error, 'forbidden');

    fm.registry.pool = {
      async query() {
        const err = new Error('canary-token-leak');
        err.code = 'XX000';
        throw err;
      }
    };
    const lookup = await call(url + '/api/v1/fleet', { headers: { authorization: 'Bearer ' + 'c'.repeat(40) } });
    assert.equal(lookup.status, 503);
    assert.equal(lookup.body.error, 'oauth_unavailable');
    assert.equal(JSON.stringify(lookup.body).includes('canary-token-leak'), false);
    assert.equal(JSON.stringify(lookup.body).includes('c'.repeat(40)), false);
  } finally {
    server.close();
    viewerApp.server.close();
  }
});

test('oauth identity is the Authentik sub only: email or member-id matches are refused', async () => {
  const fm = fleet();
  await seed(fm);
  await fm.registry.addMember('acme', 'mail-1', 'operator', 'mail-1@example.test');
  const owner = await listen(appFor(fm, await ssoUser(fm, 'user-1')));
  const other = await listen(appFor(fm, await ssoUser(fm, 'user-2', { email: 'u2@example.test' })));
  const byEmail = { id: 'sub-x', email: 'mail-1@example.test', email_verified: true, name: 'mail-1' };
  const emailOnly = await listen(appFor(fm, byEmail));
  const idIsMember = await listen(appFor(fm, { id: 'mail-1', email: 'mail-1@example.test', email_verified: true }));
  armPublic(fm, owner.url);
  const poll = (deviceCode) => postJson(owner.url, '/oauth/token', { grant_type: DEVICE_GRANT, device_code: deviceCode });
  try {
    // Email (verified or not) and a sub equal to the member id do not match a
    // NULL sso_sub: unbound page, no approval, no dashboard.
    const mailStart = await postJson(owner.url, '/oauth/device', { username: 'mail-1' });
    for (const app of [emailOnly, idIsMember]) {
      const go = browser();
      const res = await go(app.url + '/oauth/device/verify');
      const html = await res.text();
      assert.equal(res.status, 403);
      assert.match(html, /not bound to a SystemAPI member/);
      assert.equal(html.includes('name="user_code"'), false);
      const forced = await textOf(await postForm(go, app.url + '/oauth/device/verify', {
        user_code: mailStart.body.user_code, csrf: csrfIn(html), confirm: 'yes'
      }));
      assert.equal(forced.status, 403);
      const dash = await call(app.url + '/api/v1/fleet');
      assert.equal(dash.status, 403);
      assert.equal(dash.body.error, 'sso_unbound');
    }
    for (const nobody of [null, undefined, {}, { id: '' }, byEmail, { id: 'mail-1' }, { email: 'mail-1@example.test', email_verified: true }]) {
      await assert.rejects(
        () => approveUserCode(fm.registry, mailStart.body.user_code, nobody),
        (err) => err.status === 403 && err.code === 'login_denied'
      );
    }
    assert.equal((await poll(mailStart.body.device_code)).body.error, 'authorization_pending');

    // Once an admin binds sub-x to mail-1, that same session is accepted.
    await fm.registry.setSsoSub({ tenantId: 'acme', userId: 'mail-1', sub: 'sub-x', actor: 'test' });
    const ok = await textOf(await verifyAs(browser(), emailOnly.url, mailStart.body.user_code));
    assert.equal(ok.status, 200);
    assert.equal((await poll(mailStart.body.device_code)).status, 200);
    assert.equal((await call(emailOnly.url + '/api/v1/fleet')).status, 200);

    // Byte-exact: case or whitespace variants of the sub never match.
    assert.equal(await sessionOwnsUser(fm.registry, { id: 'SUB-X' }, 'mail-1'), false);
    assert.equal(await sessionOwnsUser(fm.registry, { id: 'sub-x ' }, 'mail-1'), false);
    assert.equal(await sessionOwnsUser(fm.registry, { id: 'sub-x' }, 'mail-1'), true);
    assert.equal(await sessionOwnsUser(fm.registry, { id: 'sub-x' }, 'user-1'), false);
    assert.equal(await sessionOwnsUser(fm.registry, null, 'mail-1'), false);

    // A code that belongs to another member is refused like a wrong code, and
    // the page does not name that member.
    const otherStart = await postJson(owner.url, '/oauth/device', { username: 'user-2' });
    const goOwner = browser();
    const cross = await textOf(await verifyAs(goOwner, owner.url, otherStart.body.user_code));
    assert.equal(cross.status, 403);
    assert.match(cross.body, /not accepted/);
    assert.equal(cross.body.includes('user-2'), false);
    assert.equal((await poll(otherStart.body.device_code)).body.error, 'authorization_pending');
    const theirs = await textOf(await verifyAs(browser(), other.url, otherStart.body.user_code));
    assert.equal(theirs.status, 200);

    // Every membership row must carry the sub: a second, unbound tenant row
    // refuses the device login until that tenant binds it too.
    await fm.registry.addMember('beta', 'user-1', 'viewer');
    const twoTenants = await postJson(owner.url, '/oauth/device', { username: 'user-1' });
    const half = await textOf(await verifyAs(browser(), owner.url, twoTenants.body.user_code));
    assert.equal(half.status, 403);
    assert.equal((await poll(twoTenants.body.device_code)).body.error, 'authorization_pending');
    const dash = await call(owner.url + '/api/v1/fleet');
    assert.equal(dash.status, 200);
    assert.deepEqual(dash.body.hosts.map((h) => h.host_id), [HOST_A]);
    await fm.registry.setSsoSub({ tenantId: 'beta', userId: 'user-1', sub: 'sub-user-1', actor: 'test' });
    const full = await textOf(await verifyAs(browser(), owner.url, twoTenants.body.user_code));
    assert.equal(full.status, 200);
  } finally {
    for (const s of [owner, other, emailOnly, idIsMember]) s.server.close();
  }
});

test('device code entry is rate limited per session and per IP, and wrong codes invalidate', async () => {
  const fm = fleet();
  await seed(fm);
  const { server, url } = await listen(appFor(fm, await ssoUser(fm, 'user-1')));
  armPublic(fm, url);
  const poll = (deviceCode) => postJson(url, '/oauth/token', { grant_type: DEVICE_GRANT, device_code: deviceCode });
  try {
    const started = await postJson(url, '/oauth/device', { username: 'user-1' });
    const go = browser();
    const csrf = await pageCsrf(go, url);
    const wrong = ['BBBB-BBBB', 'not-a-code', '', 'ZZZZZZZZZ', 'AEIO-UAEI'];
    for (const code of wrong) {
      const res = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: code, csrf }));
      assert.equal(res.status, 403, code);
      assert.match(res.body, /not accepted/);
    }
    // Five failures: this member's pending logins are denied, and the session
    // is locked out even for the right code.
    assert.equal(deviceRows(fm)[0].status, 'denied');
    assert.equal((await poll(started.body.device_code)).body.error, 'access_denied');
    const locked = await textOf(await postForm(go, url + '/oauth/device/verify', { user_code: started.body.user_code, csrf }));
    assert.equal(locked.status, 429);
    assert.equal(locked.body.error, 'slow_down');

    // Per IP: fresh sessions from the same address share a budget of 20.
    for (let s = 0; s < 3; s += 1) {
      const g = browser();
      const c = await pageCsrf(g, url);
      for (let i = 0; i < 5; i += 1) {
        const res = await postForm(g, url + '/oauth/device/verify', { user_code: 'BBBB-BBBB', csrf: c });
        assert.equal(res.status, 403);
        await res.text();
      }
    }
    const fresh = await postJson(url, '/oauth/device', { username: 'user-1' });
    const g = browser();
    const c = await pageCsrf(g, url);
    const ipLocked = await textOf(await postForm(g, url + '/oauth/device/verify', { user_code: fresh.body.user_code, csrf: c }));
    assert.equal(ipLocked.status, 429);
    assert.equal(ipLocked.body.error, 'slow_down');
    assert.equal((await poll(fresh.body.device_code)).body.error, 'authorization_pending');
  } finally {
    server.close();
  }
});

test('the SSO return path cannot leave the origin', () => {
  const offsite = [
    'https://evil.example/', '//evil.example/x', '/\\evil.example', '/\\/evil.example',
    '\\\\evil.example', 'javascript:alert(1)', 'evil.example', '', null, 42, {},
    '/ok\r\nLocation: https://evil.example', '/\t/evil.example', '/%0d%0a', 'x'.repeat(3000),
    // Dot segments resolve to "//evil.com" only after URL parsing.
    '/.//evil.com', '/x/..//evil.com', '/%2e//evil.com', '/%2e%2e//evil.com', '/x/%2e%2e//evil.com',
    '/./\\evil.com', '/%2E%2E/%2fevil.com', '/a/b/../..//evil.com'
  ];
  for (const value of offsite) {
    const out = safeReturnPath(value);
    assert.equal(out.startsWith('/'), true, String(value));
    assert.equal(out.startsWith('//'), false, String(value));
    assert.equal(out.startsWith('/\\'), false, String(value));
    assert.equal(new URL(out, 'https://cp.example').origin, 'https://cp.example', String(value));
  }
  for (const value of ['/.//evil.com', '/x/..//evil.com', '/%2e//evil.com', '/%2e%2e//evil.com']) {
    assert.equal(safeReturnPath(value), '/', value);
  }
  assert.equal(safeReturnPath('https://evil.example/'), '/');
  assert.equal(safeReturnPath('//evil.example/x'), '/');
  assert.equal(safeReturnPath('/\\evil.example'), '/');
  assert.equal(safeReturnPath('/ok\r\nLocation: x'), '/');
  assert.equal(safeReturnPath('/oauth/device/verify'), '/oauth/device/verify');
  assert.equal(safeReturnPath('/dashboard?tab=hosts'), '/dashboard?tab=hosts');
  assert.equal(safeReturnPath('/dashboard#frag'), '/dashboard');
});

test('oauth caps pending grants and the server owns the poll interval', async () => {
  const fm = fleet();
  await seed(fm);
  const { server, url } = await listen(appFor(fm));
  armPublic(fm, url);
  try {
    for (let i = 0; i < 3; i += 1) {
      const ok = await postJson(url, '/oauth/device', { username: 'user-1' });
      assert.equal(ok.status, 200);
    }
    const extra = await postJson(url, '/oauth/device', { username: 'user-1' });
    assert.equal(extra.status, 429);
    assert.equal(extra.body.error, 'slow_down');
    assert.equal(deviceRows(fm).length, 3);
    assert.equal(new Set(deviceRows(fm).map((row) => row.user_code_hash)).size, 3);
  } finally {
    server.close();
  }

  const slow = fleet();
  await seed(slow);
  const env = { NODE_ENV: 'production', SYSTEMAPI_PUBLIC_URL: 'https://cp.example' };
  const now = 1700000000000;
  const started = await startDevice(slow.registry, 'user-1', env, {}, now);
  assert.equal(started.interval, 5);
  assert.equal(started.verification_uri, 'https://cp.example/oauth/device/verify');
  await assert.rejects(
    () => pollToken(slow.registry, started.device_code, env, now),
    (err) => err.code === 'authorization_pending'
  );
  await assert.rejects(
    () => pollToken(slow.registry, started.device_code, env, now),
    (err) => err.code === 'slow_down'
  );
  await assert.rejects(
    () => pollToken(slow.registry, 'd'.repeat(32), env, now + 6000),
    (err) => err.code === 'invalid_grant'
  );
});

test('SSO binding is admin only, audited in the chain, and one sub per member', async () => {
  const fm = fleet();
  await seed(fm);
  await fm.registry.addMember('acme', 'viewer-1', 'viewer');
  await fm.registry.addMember('acme', 'mail-1', 'operator', 'mail-1@example.test');
  const admin = await listen(appFor(fm, await ssoUser(fm, 'user-1')));
  const viewer = await listen(appFor(fm, await ssoUser(fm, 'viewer-1')));
  const bind = (base, tenant, user, body) => call(`${base}/api/v1/tenants/${tenant}/members/${user}/sso`, {
    method: body === undefined ? 'DELETE' : 'PUT',
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const rowOf = (tenant, user) => fm.registry.members.find((m) => m.tenant_id === tenant && m.user_id === user);
  try {
    const before = fm.registry.audit.length;
    const refused = await bind(viewer.url, 'acme', 'mail-1', { sso_sub: 'sub-viewer-plant' });
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error, 'scope_denied');
    const unbindRefused = await bind(viewer.url, 'acme', 'user-1');
    assert.equal(unbindRefused.status, 403);
    assert.equal(rowOf('acme', 'mail-1').sso_sub, null);
    assert.equal(rowOf('acme', 'user-1').sso_sub, 'sub-user-1');
    const otherTenant = await bind(admin.url, 'beta', 'user-2', { sso_sub: 'sub-plant' });
    assert.equal(otherTenant.status, 404);
    const noMember = await bind(admin.url, 'acme', 'user-2', { sso_sub: 'sub-plant' });
    assert.equal(noMember.status, 404);
    for (const bad of [{}, { sso_sub: '' }, { sso_sub: 'has space' }, { sso_sub: 42 }, { sso_sub: 'x'.repeat(300) }]) {
      const res = await bind(admin.url, 'acme', 'mail-1', bad);
      assert.equal(res.status, 400, JSON.stringify(bad));
      assert.equal(res.body.error, 'bad_sso_sub');
    }
    assert.equal(fm.registry.audit.length, before);

    const subMail = 'a3f1c0ffee'.repeat(6) + 'beef';
    const ok = await bind(admin.url, 'acme', 'mail-1', { sso_sub: subMail });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body, { tenant_id: 'acme', user_id: 'mail-1', bound: true });
    assert.equal(rowOf('acme', 'mail-1').sso_sub, subMail);
    const last = fm.registry.audit[fm.registry.audit.length - 1];
    assert.equal(last.action, 'sso_bind');
    assert.equal(last.actor, 'user-1');
    assert.equal(last.tenant_id, 'acme');
    assert.equal(last.payload.user_id, 'mail-1');
    assert.equal(last.payload.sso_sub_fp.length, 64);
    assert.equal(JSON.stringify(fm.registry.audit).includes(subMail), false);
    assert.equal((await fm.registry.verifyAudit()).ok, true);

    // One sub, one member id: not on a second member in any tenant.
    const twice = await bind(admin.url, 'acme', 'viewer-1', { sso_sub: subMail });
    assert.equal(twice.status, 409);
    assert.equal(twice.body.error, 'sso_sub_taken');
    assert.equal(rowOf('acme', 'viewer-1').sso_sub, 'sub-viewer-1');
    await assert.rejects(
      () => fm.registry.setSsoSub({ tenantId: 'beta', userId: 'user-2', sub: subMail, actor: 'test' }),
      (err) => err.status === 409 && err.code === 'sso_sub_taken'
    );

    // A member has one identity across tenants: another tenant cannot bind a
    // different sub to it, the same sub is fine, and a change needs every
    // row unbound first.
    await fm.registry.addMember('beta', 'mail-1', 'viewer');
    const auditAt = fm.registry.audit.length;
    await assert.rejects(
      () => fm.registry.setSsoSub({ tenantId: 'beta', userId: 'mail-1', sub: 'sub-mail-other', actor: 'test' }),
      (err) => err.status === 409 && err.code === 'sso_sub_conflict'
    );
    assert.equal(rowOf('beta', 'mail-1').sso_sub, null);
    assert.equal(fm.registry.audit.length, auditAt);
    await fm.registry.setSsoSub({ tenantId: 'beta', userId: 'mail-1', sub: subMail, actor: 'test' });
    assert.equal(rowOf('beta', 'mail-1').sso_sub, subMail);
    await assert.rejects(
      () => fm.registry.setSsoSub({ tenantId: 'acme', userId: 'mail-1', sub: 'sub-mail-new', actor: 'test' }),
      (err) => err.code === 'sso_sub_conflict'
    );
    const viaApi = await bind(admin.url, 'acme', 'mail-1', { sso_sub: 'sub-mail-new' });
    assert.equal(viaApi.status, 409);
    assert.equal(viaApi.body.error, 'sso_sub_conflict');
    await fm.registry.setSsoSub({ tenantId: 'beta', userId: 'mail-1', sub: null, actor: 'test' });

    // Unbinding is audited, and the sub stops working at once.
    const mailApp = await listen(appFor(fm, { id: subMail }));
    try {
      assert.equal((await call(mailApp.url + '/api/v1/fleet')).status, 200);
      const gone = await bind(admin.url, 'acme', 'mail-1');
      assert.equal(gone.status, 200);
      assert.equal(gone.body.bound, false);
      assert.equal(fm.registry.audit[fm.registry.audit.length - 1].action, 'sso_unbind');
      assert.equal((await call(mailApp.url + '/api/v1/fleet')).status, 403);
    } finally {
      mailApp.server.close();
    }

    // A failed audit write leaves the binding as it was.
    const realAppend = fm.registry.appendAudit;
    fm.registry.appendAudit = async () => { throw Object.assign(new Error('audit down'), { code: 'audit_down' }); };
    await assert.rejects(() => fm.registry.setSsoSub({ tenantId: 'acme', userId: 'mail-1', sub: 'sub-z', actor: 'test' }));
    assert.equal(rowOf('acme', 'mail-1').sso_sub, null);
    fm.registry.appendAudit = realAppend;

    // Server-side bootstrap for the first admin: same checks, same audit row.
    const { run, ACTOR } = require('../scripts/sso-bind');
    const boot = await run(['beta', 'user-2', 'sub-boot'], fm.registry);
    assert.deepEqual(boot, { tenant_id: 'beta', user_id: 'user-2', bound: true });
    assert.equal(fm.registry.audit[fm.registry.audit.length - 1].actor, ACTOR);
    await assert.rejects(() => run(['beta', 'user-2'], fm.registry), (err) => err.code === 'usage');
    await assert.rejects(() => run(['beta', 'nobody', 'sub-q'], fm.registry), (err) => err.status === 404);
    await assert.rejects(() => run(['acme', 'mail-1', 'sub-boot'], fm.registry), (err) => err.code === 'sso_sub_taken');
    assert.equal((await fm.registry.verifyAudit()).ok, true);
  } finally {
    admin.server.close();
    viewer.server.close();
  }
});

test('oauth external login requires a whitelist, the owner session, and binds one subject', async () => {
  const fm = fleet();
  await seed(fm);
  await fm.registry.addMember('acme', 'viewer-1', 'viewer');
  await fm.registry.addMember('acme', 'user-3', 'operator');
  const admin = await listen(appFor(fm, await ssoUser(fm, 'user-1')));
  const viewer = await listen(appFor(fm, await ssoUser(fm, 'viewer-1')));
  const third = await listen(appFor(fm, await ssoUser(fm, 'user-3')));
  const anon = await listen(appFor(fm));
  armPublic(fm, admin.url);
  const go = browser();
  const go3 = browser();
  const jump = async (goFn, base, code, provider) => verifyAs(goFn, base, code, { provider });
  const stateOf = (res) => new URL(res.headers.get('location')).searchParams.get('state');
  const lines = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...args) => {
    lines.push(args.map(String).join(' '));
    origLog.apply(console, args);
  };
  console.error = (...args) => {
    lines.push(args.map(String).join(' '));
    origErr.apply(console, args);
  };
  const idpToken = 'idp-token-canary-value';
  const subject = 'google-subject-canary-1';
  const idp = (sub) => async (target) => {
    if (String(target).includes('userinfo')) {
      return { status: 200, text: async () => JSON.stringify({ sub }) };
    }
    return { status: 200, text: async () => JSON.stringify({ access_token: idpToken }) };
  };
  try {
    const viewerWrite = await postJson(viewer.url, '/api/v1/oauth/links', { user_id: 'user-1', provider: 'google' });
    assert.equal(viewerWrite.status, 403);
    assert.equal(viewerWrite.body.error, 'scope_denied');
    const outside = await postJson(admin.url, '/api/v1/oauth/links', { user_id: 'user-2', provider: 'google' });
    assert.equal(outside.status, 404);
    assert.equal(outside.body.error, 'not_found');
    const badProvider = await postJson(admin.url, '/api/v1/oauth/links', { user_id: 'user-1', provider: 'okta' });
    assert.equal(badProvider.status, 400);
    assert.equal(badProvider.body.error, 'bad_provider');

    const created = await postJson(admin.url, '/api/v1/oauth/links', { user_id: 'user-1', provider: 'google' });
    assert.equal(created.status, 200);
    assert.equal(created.body.linked, false);
    assert.equal(created.body.subject, undefined);

    const started = await postJson(admin.url, '/oauth/device', { username: 'user-1' });
    const userCode = started.body.user_code;
    const goCsrf = await pageCsrf(go, admin.url);
    const plain = await textOf(await postForm(go, admin.url + '/oauth/device/verify', { user_code: userCode, csrf: goCsrf }));
    assert.equal(plain.status, 200);
    assert.equal(plain.body.includes('Continue with Google'), false);
    const unconfigured = await textOf(await jump(go, admin.url, userCode, 'google'));
    assert.equal(unconfigured.status, 403);
    assert.equal(unconfigured.body.error, 'link_denied');

    fm.env.SYSTEMAPI_GOOGLE_CLIENT_ID = 'google-client-canary';
    fm.env.SYSTEMAPI_GOOGLE_CLIENT_SECRET = 'google-secret-canary';
    fm.env.SYSTEMAPI_GITHUB_CLIENT_ID = 'github-client-canary';
    fm.env.SYSTEMAPI_GITHUB_CLIENT_SECRET = 'github-secret-canary';
    const offered = await textOf(await postForm(go, admin.url + '/oauth/device/verify', { user_code: userCode, csrf: goCsrf }));
    assert.match(offered.body, /Continue with Google/);
    assert.equal(offered.body.includes('Continue with GitHub'), false);
    assert.equal(offered.body.includes('google-secret-canary'), false);
    assert.equal(offered.body.includes('github-secret-canary'), false);

    const garbage = await textOf(await jump(go, admin.url, userCode, 'google.evil'));
    assert.equal(garbage.status, 403);
    assert.equal(garbage.body.error, 'link_denied');
    const noCsrfJump = await postJson(admin.url, '/oauth/device/verify', { user_code: userCode, provider: 'google' });
    assert.equal(noCsrfJump.status, 403);
    assert.equal(noCsrfJump.body.error, 'csrf_denied');
    const first = await jump(go, admin.url, userCode, 'google');
    assert.equal(first.status, 302);
    const location = first.headers.get('location');
    assert.equal(location.startsWith('https://accounts.google.com/o/oauth2/v2/auth?'), true);
    assert.equal(location.includes('google-secret-canary'), false);
    const state = new URL(location).searchParams.get('state');
    const poll = (deviceCode) => postJson(admin.url, '/oauth/token', { grant_type: DEVICE_GRANT, device_code: deviceCode });
    assert.equal((await poll(started.body.device_code)).body.error, 'authorization_pending');

    // A callback in a browser that did not start this login is refused, even
    // with a good IdP answer (the attacker sends the victim the IdP link).
    fm.oauthFetch = idp(subject);
    const foreign = await call(admin.url + '/oauth/google/callback?code=auth-code&state=' + encodeURIComponent(state));
    assert.equal(foreign.status, 403);
    assert.match(foreign.body, /Login denied/);
    assert.equal(fm.registry.oauthLinks.get('user-1\0google').subject, null);
    assert.equal((await poll(started.body.device_code)).body.error, 'authorization_pending');

    // A browser with no SSO session never gets a form token, so it cannot
    // start the IdP round trip to bind its own IdP account to user-1.
    const goAnon = browser();
    assert.equal(await pageCsrf(goAnon, anon.url), null);
    const anonJump = await textOf(await postForm(goAnon, anon.url + '/oauth/device/verify', { user_code: userCode, csrf: 'guess', provider: 'google' }));
    assert.equal(anonJump.status, 403);
    assert.equal(anonJump.body.error, 'csrf_denied');
    assert.equal(fm.registry.oauthLinks.get('user-1\0google').subject, null);

    const restart = await jump(go, admin.url, userCode, 'google');
    const restartState = stateOf(restart);
    fm.oauthFetch = undefined;
    const errorPage = await textOf(await go(admin.url + '/oauth/google/callback?error=access_denied&state=' + encodeURIComponent(restartState)));
    assert.match(errorPage.body, /Login denied/);
    const unknown = await fetch(admin.url + '/oauth/evil/callback?code=x&state=' + encodeURIComponent(state));
    assert.equal(unknown.status, 404);

    fm.oauthFetch = idp(subject);
    const bindJump = await jump(go, admin.url, userCode, 'google');
    const done = await textOf(await go(admin.url + '/oauth/google/callback?code=auth-code&state=' + encodeURIComponent(stateOf(bindJump))));
    assert.match(done.body, /Signed in/);
    assert.equal(done.body.includes(idpToken), false);
    assert.equal(done.body.includes(subject), false);
    const tokenRes = await poll(started.body.device_code);
    assert.equal(tokenRes.status, 200);
    const listed = await call(admin.url + '/api/v1/oauth/links');
    assert.equal(listed.body.links.some((row) => row.user_id === 'user-1' && row.provider === 'google' && row.linked === true), true);
    assert.equal(JSON.stringify(listed.body).includes(subject), false);
    await postJson(admin.url, '/api/v1/oauth/links', { user_id: 'user-1', provider: 'google' });
    assert.equal(fm.registry.oauthLinks.get('user-1\0google').subject, subject);

    const mismatchStart = await postJson(admin.url, '/oauth/device', { username: 'user-1' });
    fm.oauthFetch = idp('other-subject-canary');
    const mismatchJump = await jump(go, admin.url, mismatchStart.body.user_code, 'google');
    const mismatchDone = await textOf(await go(admin.url + '/oauth/google/callback?code=auth-code&state=' + encodeURIComponent(stateOf(mismatchJump))));
    assert.match(mismatchDone.body, /Login denied/);
    assert.equal(fm.registry.oauthLinks.get('user-1\0google').subject, subject);
    assert.equal((await poll(mismatchStart.body.device_code)).body.error, 'authorization_pending');

    await postJson(admin.url, '/api/v1/oauth/links', { user_id: 'user-3', provider: 'google' });
    const second = await postJson(admin.url, '/oauth/device', { username: 'user-3' });
    const secondCode = second.body.user_code;
    fm.oauthFetch = idp(subject);
    // user-1's session does not own user-3: typing user-3's code is refused
    // before any IdP redirect, so it cannot bind user-3's link.
    const notOwner = await textOf(await jump(go, admin.url, secondCode, 'google'));
    assert.equal(notOwner.status, 403);
    assert.match(notOwner.body, /not accepted/);
    assert.equal(notOwner.body.includes('user-3'), false);
    assert.equal(fm.registry.oauthLinks.get('user-3\0google').subject, null);
    // user-3's own session still cannot take a subject already bound to user-1.
    const secondJump = await jump(go3, third.url, secondCode, 'google');
    const taken = await textOf(await go3(third.url + '/oauth/google/callback?code=auth-code&state=' + encodeURIComponent(stateOf(secondJump))));
    assert.match(taken.body, /Login denied/);
    assert.equal(fm.registry.oauthLinks.get('user-3\0google').subject, null);
    assert.equal(fm.registry.oauthLinks.get('user-1\0google').subject, subject);

    const githubStart = await postJson(admin.url, '/oauth/device', { username: 'user-3' });
    const githubCode = githubStart.body.user_code;
    const noGithub = await textOf(await jump(go3, third.url, githubCode, 'github'));
    assert.equal(noGithub.status, 403);
    assert.equal(noGithub.body.error, 'link_denied');
    await postJson(admin.url, '/api/v1/oauth/links', { user_id: 'user-3', provider: 'github' });
    const githubJump = await jump(go3, third.url, githubCode, 'github');
    assert.equal(githubJump.headers.get('location').startsWith('https://github.com/login/oauth/authorize?'), true);
    assert.equal(githubJump.headers.get('location').includes('github-secret-canary'), false);
    const githubState = new URL(githubJump.headers.get('location')).searchParams.get('state');
    fm.oauthFetch = async (target) => {
      if (String(target).includes('api.github.com')) {
        return { status: 200, text: async () => JSON.stringify({ id: 42 }) };
      }
      return { status: 200, text: async () => JSON.stringify({ access_token: idpToken }) };
    };
    const githubDone = await textOf(await go3(third.url + '/oauth/github/callback?code=auth-code&state=' + encodeURIComponent(githubState)));
    assert.match(githubDone.body, /Signed in/);
    assert.equal(fm.registry.oauthLinks.get('user-3\0github').subject, '42');

    const hugeStart = await postJson(admin.url, '/oauth/device', { username: 'user-1' });
    const hugeJump = await jump(go, admin.url, hugeStart.body.user_code, 'google');
    const hugeState = stateOf(hugeJump);
    fm.oauthFetch = async (target) => {
      if (String(target).includes('userinfo')) {
        return { status: 200, text: async () => 'x'.repeat(9000) };
      }
      return { status: 200, text: async () => JSON.stringify({ access_token: idpToken }) };
    };
    const huge = await textOf(await go(admin.url + '/oauth/google/callback?code=auth-code&state=' + encodeURIComponent(hugeState)));
    assert.match(huge.body, /Login denied/);
    assert.equal(fm.registry.oauthLinks.get('user-1\0google').subject, subject);

    await assert.rejects(
      () => completeExternal(fm.registry, { provider: 'google', subject: 'abc', state: 'not-a-real-state-value' }),
      (err) => err.status === 403 && err.code === 'link_denied'
    );

    const removed = await call(admin.url + '/api/v1/oauth/links', {
      method: 'DELETE',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user_id: 'user-1', provider: 'google' })
    });
    assert.equal(removed.status, 200);
    assert.equal(removed.body.deleted, true);
    const left = await call(admin.url + '/api/v1/oauth/links');
    assert.equal(left.body.links.some((row) => row.user_id === 'user-1' && row.provider === 'google'), false);
    assert.equal(JSON.stringify(left.body).includes(subject), false);

    const blob = lines.join('\n');
    assert.equal(blob.includes(idpToken), false);
    assert.equal(blob.includes('google-secret-canary'), false);
    assert.equal(blob.includes('github-secret-canary'), false);
    assert.equal(blob.includes(subject), false);
    assert.equal(blob.includes(userCode), false);
    assert.equal(blob.includes(started.body.device_code), false);
    assert.equal(blob.includes(tokenRes.body.access_token), false);
  } finally {
    console.log = origLog;
    console.error = origErr;
    admin.server.close();
    viewer.server.close();
    third.server.close();
    anon.server.close();
  }
});

test('cli login writes a mode 0600 token and prints only the verification URI and user code', async () => {
  const fm = fleet();
  await seed(fm);
  const { server, url } = await listen(appFor(fm, await ssoUser(fm, 'user-1')));
  const tokenFile = path.join(os.tmpdir(), 'systemapi-oauth-' + process.pid + '-' + Date.now());
  const mismatchFile = tokenFile + '-mismatch';
  let child;
  try {
    fm.env.NODE_ENV = 'test';
    fm.env.SYSTEMAPI_PUBLIC_URL = 'http://127.0.0.1:9';
    const mismatch = await runCli(['login', 'user-1'], {
      PATH: process.env.PATH,
      SYSTEMAPI_URL: url,
      SYSTEMAPI_TOKEN_FILE: mismatchFile
    });
    assert.equal(mismatch.status, 1);
    assert.equal(mismatch.stderr, 'login_failed\n');
    assert.equal(mismatch.stdout, '');
    assert.equal(mismatch.stderr.includes('SYSTEMAPI_API_KEY'), false);
    assert.equal(fs.existsSync(mismatchFile), false);

    fm.env.SYSTEMAPI_PUBLIC_URL = url;
    let stdout = '';
    let stderr = '';
    child = spawn(process.execPath, [path.join(__dirname, '../cli/systemapi.js'), 'login', 'user-1'], {
      env: { PATH: process.env.PATH, SYSTEMAPI_URL: url, SYSTEMAPI_TOKEN_FILE: tokenFile }
    });
    const closed = new Promise((resolve) => child.on('close', resolve));
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('login prompt timeout ' + stderr)), 5000);
      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString();
        if (stdout.split('\n').length >= 3) {
          clearTimeout(timer);
          resolve();
        }
      });
      child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    });
    const [uri, userCode] = stdout.split('\n');
    assert.equal(uri, url + '/oauth/device/verify');
    assert.match(userCode, USER_CODE_SHAPE);
    const yes = await verifyAs(browser(), url, userCode);
    assert.equal(yes.status, 200);
    const status = await Promise.race([
      closed,
      new Promise((_, reject) => setTimeout(() => {
        child.kill();
        reject(new Error('login hung ' + stderr + ' ' + stdout));
      }, 15000))
    ]);
    assert.equal(status, 0, stderr + stdout);
    const lines = stdout.split('\n');
    assert.equal(lines[2], 'approved');
    assert.equal(lines[3], tokenFile);
    assert.equal(lines[4], '');
    assert.equal(stdout.includes('device_code'), false);
    assert.equal(stdout.includes('access_token'), false);
    assert.equal(stderr.includes('SYSTEMAPI_API_KEY'), false);
    assert.equal(fs.statSync(tokenFile).mode & 0o777, 0o600);
    const token = fs.readFileSync(tokenFile, 'utf8').replace(/\n$/, '');
    assert.equal(stdout.includes(token), false);
    assert.equal(stderr.includes(token), false);
    const list = await call(url + '/api/v1/fleet', { headers: { authorization: 'Bearer ' + token } });
    assert.equal(list.status, 200);
    assert.equal(list.body.hosts.length, 1);
    assert.equal(list.body.hosts[0].host_id, HOST_A);
  } finally {
    if (child && child.exitCode == null) child.kill();
    server.close();
    fs.rmSync(tokenFile, { force: true });
    fs.rmSync(mismatchFile, { force: true });
  }
});

test('trust proxy is a hop count or CIDR list, never true, and required in production', () => {
  assert.throws(() => trustProxySetting({ NODE_ENV: 'production' }), /required in production/);
  assert.throws(() => trustProxySetting({ NODE_ENV: 'production', SYSTEMAPI_TRUST_PROXY: ' ' }), /required in production/);
  assert.deepEqual(trustProxySetting({ NODE_ENV: 'test' }), ['127.0.0.0/8', '::1/128']);
  assert.equal(trustProxySetting({ NODE_ENV: 'production', SYSTEMAPI_TRUST_PROXY: '1' }), 1);
  assert.equal(trustProxySetting({ NODE_ENV: 'production', SYSTEMAPI_TRUST_PROXY: '0' }), 0);
  assert.deepEqual(
    trustProxySetting({ NODE_ENV: 'production', SYSTEMAPI_TRUST_PROXY: '10.0.0.0/8, fd00::/8' }),
    ['10.0.0.0/8', 'fd00::/8']
  );
  for (const bad of ['true', 'TRUE', 'false', 'loopback', '10.0.0.1', '10.0.0.0/33', '::1/129', '1.2.3.4/8,*', '-1', '100', 'x/8']) {
    assert.throws(() => trustProxySetting({ NODE_ENV: 'production', SYSTEMAPI_TRUST_PROXY: bad }), /hop count or a list of CIDRs/, bad);
  }
});

test('CORS: exact https origins only, and none at all on /oauth', async () => {
  assert.deepEqual(corsOrigins({ NODE_ENV: 'production' }), ['https://systemapi.io']);
  assert.deepEqual(corsOrigins({
    NODE_ENV: 'production',
    SYSTEMAPI_ALLOWED_ORIGINS: 'https://app.example, http://app.example,https://*.example,https://app.example/x,https://APP.example,http://localhost:5173,*,null'
  }), ['https://app.example']);
  assert.deepEqual(corsOrigins({ NODE_ENV: 'test', SYSTEMAPI_ALLOWED_ORIGINS: 'http://localhost:5173,http://dev.example' }), ['http://localhost:5173']);

  const app = express();
  app.use(corsMiddleware({ NODE_ENV: 'production', SYSTEMAPI_ALLOWED_ORIGINS: 'https://app.example' }));
  app.get('/oauth/user', (_req, res) => res.json({ csrf: 'secret' }));
  app.get('/api/v1/fleet', (_req, res) => res.json({ hosts: [] }));
  const { server, url } = await listen(app);
  try {
    const ok = await fetch(url + '/api/v1/fleet', { headers: { origin: 'https://app.example' } });
    assert.equal(ok.headers.get('access-control-allow-origin'), 'https://app.example');
    assert.equal(ok.headers.get('access-control-allow-credentials'), 'true');
    for (const origin of ['https://evil.example', 'https://sub.app.example', 'http://app.example', 'null']) {
      const res = await fetch(url + '/api/v1/fleet', { headers: { origin } });
      assert.equal(res.headers.get('access-control-allow-origin'), null, origin);
    }
    for (const method of ['GET', 'OPTIONS']) {
      const res = await fetch(url + '/oauth/user', {
        method,
        headers: { origin: 'https://app.example', 'access-control-request-method': 'POST' }
      });
      assert.equal(res.headers.get('access-control-allow-origin'), null, method);
      assert.equal(res.headers.get('access-control-allow-credentials'), null, method);
    }
  } finally {
    server.close();
  }
});

test('clampEntitlements denies host lists to operators and stars to admins', () => {
  const operator = scopesForRole('operator');
  const op = clampEntitlements({
    allow_exec: true,
    allow_fs_write: true,
    allow_k8s: true,
    allow_linux: true,
    allow_images: ['nginx:latest'],
    allow_packages: ['nginx']
  }, operator);
  assert.equal(op.allow_exec, true);
  assert.equal(typeof op.allow_exec, 'boolean');
  assert.equal(op.allow_fs_write, false);
  assert.equal(typeof op.allow_fs_write, 'boolean');
  assert.equal(op.allow_k8s, false);
  assert.equal(op.allow_linux, false);
  assert.deepEqual(op.allow_images, []);
  assert.deepEqual(op.allow_packages, []);

  const admin = scopesForRole('admin');
  const boolList = clampEntitlements({ allow_images: true, allow_packages: true }, admin);
  assert.deepEqual(boolList.allow_images, []);
  assert.deepEqual(boolList.allow_packages, []);

  const long = 'a'.repeat(257);
  const pkgs = [long];
  for (let i = 0; i < 33; i++) pkgs.push('pkg' + i);
  const filtered = clampEntitlements({
    allow_images: ['nginx:latest', '*', 'a..b', 'bad\n', 1, ''],
    allow_packages: pkgs,
    allow_sysctl: ['kernel.core_pattern', 'kernel.modprobe', 'kernel.hotplug', 'net.ipv4.ip_forward'],
    allow_linux: 'yes',
    allow_k8s: true
  }, admin);
  assert.deepEqual(filtered.allow_images, ['nginx:latest']);
  assert.equal(filtered.allow_packages.length, 32);
  assert.equal(filtered.allow_packages[0], 'pkg0');
  assert.equal(filtered.allow_packages[31], 'pkg31');
  assert.equal(filtered.allow_packages.includes('pkg32'), false);
  assert.equal(filtered.allow_packages.includes(long), false);
  assert.deepEqual(filtered.allow_sysctl, ['net.ipv4.ip_forward']);
  assert.equal(filtered.allow_linux, false);
  assert.equal(filtered.allow_k8s, true);
  assert.equal(filtered.allow_exec, false);

  for (const requested of [null, 'yes', ['allow_exec']]) {
    const denied = clampEntitlements(requested, admin);
    assert.equal(denied.allow_exec, false);
    assert.equal(denied.allow_linux, false);
    assert.equal(denied.allow_k8s, false);
    assert.deepEqual(denied.allow_images, []);
    assert.deepEqual(denied.allow_packages, []);
    assert.deepEqual(denied.allow_sysctl, []);
  }
});

test('hosts/resolve matches exactly, case-insensitively, inside the caller tenants only', async () => {
  const fm = fleet();
  const pub = await seed(fm);
  const HOST_C = '33333333-3333-4333-8333-333333333333';
  const HOST_D = '44444444-4444-4444-8444-444444444444';
  for (const [hostId, hostname] of [[HOST_C, 'dup.example'], [HOST_D, 'DUP.example']]) {
    await fm.registry.enroll({
      tenantId: 'acme', userId: 'user-1', keyId: 'k1', hostId, hostname, os: 'linux', platform: 'amd64', sshPubkey: pub
    });
  }
  await fm.registry.setScopes('ak_test', ['hosts:read']);
  fm.connectedAgents = new Map([[HOST_A, {}]]);
  const { server, url } = await listen(appFor(fm));
  const resolve = (name) => call(`${url}/api/v1/hosts/resolve?name=${encodeURIComponent(name)}`, { headers: { 'x-api-key': 'good-key' } });
  try {
    const exact = await resolve('a.example');
    assert.equal(exact.status, 200);
    assert.deepEqual(exact.body, { host_id: HOST_A, hostname: 'a.example', tenant: 'acme', status: 'online' });

    const upper = await resolve('A.EXAMPLE');
    assert.equal(upper.status, 200);
    assert.equal(upper.body.host_id, HOST_A);

    const byId = await resolve(HOST_C);
    assert.equal(byId.status, 200);
    assert.equal(byId.body.host_id, HOST_C);
    assert.equal(byId.body.status, 'offline');

    const ambiguous = await resolve('dup.example');
    assert.equal(ambiguous.status, 409);
    assert.deepEqual(ambiguous.body, { error: 'ambiguous', matches: 2 });

    for (const name of ['b.example', HOST_B, 'a.exam', 'example', 'nope.example']) {
      const miss = await resolve(name);
      assert.equal(miss.status, 404, name);
      assert.deepEqual(miss.body, { error: 'not_found' });
    }

    for (const name of ['', 'a b', 'a/b', "a'--", '%', 'x'.repeat(254)]) {
      const bad = await resolve(name);
      assert.equal(bad.status, 400, JSON.stringify(name));
      assert.deepEqual(bad.body, { error: 'invalid_name' });
    }
    const missing = await call(`${url}/api/v1/hosts/resolve`, { headers: { 'x-api-key': 'good-key' } });
    assert.equal(missing.status, 400);
    const unauth = await call(`${url}/api/v1/hosts/resolve?name=a.example`);
    assert.equal(unauth.status, 401);

    await fm.registry.setScopes('ak_test', ['metrics:read']);
    const noRead = await resolve('a.example');
    assert.equal(noRead.status, 404);
  } finally {
    server.close();
  }
});

test('terminal:root is admin only and every ticket is audited', async () => {
  assert.equal(OPERATOR.includes('terminal:root'), false);
  assert.equal(scopesForRole('operator').has('terminal:root'), false);
  assert.equal(scopesForRole('admin').has('terminal:root'), true);

  const fm = fleet();
  await seed(fm);
  await fm.registry.addMember('acme', 'op-1', 'operator', 'op@example');
  const opApp = await listen(appFor(fm, await ssoUser(fm, 'op-1', { email: 'op@example', groups: [] })));
  const adminApp = await listen(appFor(fm));
  await fm.registry.setScopes('ak_test', ['admin']);
  const ticket = (url, purpose, headers = {}) => call(`${url}/api/v1/ws-ticket`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ host_id: HOST_A, purpose })
  });
  try {
    const denied = await ticket(opApp.url, 'terminal:root');
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error, 'scope_denied');
    assert.equal(fm.tickets.size, 0);

    const open = await ticket(opApp.url, 'terminal:open');
    assert.equal(open.status, 200);
    assert.match(open.body.ticket, /^stk_/);
    assert.ok(Math.abs(Date.parse(open.body.expires_at) - Date.now() - 60_000) < 5000);

    const root = await ticket(adminApp.url, 'terminal:root', { 'x-api-key': 'good-key' });
    assert.equal(root.status, 200);
    assert.equal(fm.tickets.get(root.body.ticket).purpose, 'terminal:root');
    assert.equal(fm.tickets.get(root.body.ticket).actor, 'user-1');

    const bad = await ticket(adminApp.url, 'terminal:everything', { 'x-api-key': 'good-key' });
    assert.equal(bad.status, 400);

    const issued = fm.registry.audit.filter((row) => row.action === 'ticket_issued');
    assert.deepEqual(issued.map((row) => [row.actor, row.host_id, row.payload.purpose]), [
      ['op-1', HOST_A, 'terminal:open'],
      ['user-1', HOST_A, 'terminal:root']
    ]);
    for (const row of issued) assert.equal(JSON.stringify(row).includes('stk_'), false);
    assert.equal((await fm.registry.verifyAudit()).ok, true);
  } finally {
    opApp.server.close();
    adminApp.server.close();
  }
});

test('the audit chain covers actor, host, tenant and action; legacy rows still verify', async () => {
  const { GENESIS, chainHash } = require('../controlplane/chain');
  const reg = new MemoryRegistry({ NODE_ENV: 'test' });
  await reg.appendAudit({ tenant_id: 'acme', host_id: HOST_A, actor: 'user-1', action: 'terminal_start', payload: { session_id: 's1' } });
  await reg.appendAudit({ tenant_id: 'acme', host_id: HOST_A, actor: 'user-1', action: 'terminal_end', payload: { session_id: 's1' } });
  assert.equal((await reg.verifyAudit()).ok, true);
  for (const [column, value] of [['actor', 'someone-else'], ['host_id', HOST_B], ['tenant_id', 'beta'], ['action', 'ticket_issued']]) {
    const original = reg.audit[0][column];
    reg.audit[0][column] = value;
    const broken = await reg.verifyAudit();
    assert.equal(broken.ok, false, column);
    assert.equal(broken.broken_at, 1, column);
    reg.audit[0][column] = original;
  }
  assert.equal((await reg.verifyAudit()).ok, true);

  // A row written before every column was hashed (payload only) still verifies.
  const legacy = new MemoryRegistry({ NODE_ENV: 'test' });
  const payload = { n: 1 };
  legacy.audit.push({ seq: 1, prev_hash: GENESIS, row_hash: chainHash(GENESIS, payload), tenant_id: 'acme', host_id: null, actor: 'old', action: 'sysscript', payload });
  legacy.auditSeq = 2;
  await legacy.appendAudit({ tenant_id: 'acme', actor: 'new', action: 'sysscript', payload: { n: 2 } });
  assert.equal((await legacy.verifyAudit()).ok, true);
});

test('ws-ticket is rate limited per actor and host, with a separate privileged budget', async () => {
  const fm = fleet();
  fm.env = { NODE_ENV: 'test', SYSTEMAPI_TICKET_RATE_PER_HOST: '2', SYSTEMAPI_TICKET_RATE_PRIVILEGED: '2' };
  await seed(fm);
  await fm.registry.setScopes('ak_test', ['admin']);
  await fm.registry.addMember('acme', 'op-1', 'operator', 'op@example');
  const opApp = await listen(appFor(fm, await ssoUser(fm, 'op-1', { email: 'op@example', groups: [] })));
  const adminApp = await listen(appFor(fm));
  const ticket = (url, purpose, headers = {}) => call(`${url}/api/v1/ws-ticket`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ host_id: HOST_A, purpose })
  });
  const admin = { 'x-api-key': 'good-key' };
  try {
    // An operator floods ordinary terminal tickets for the host.
    assert.equal((await ticket(opApp.url, 'terminal:open')).status, 200);
    assert.equal((await ticket(opApp.url, 'terminal:open')).status, 200);
    for (let i = 0; i < 5; i++) {
      const limited = await ticket(opApp.url, 'terminal:open');
      assert.equal(limited.status, 429);
      assert.equal(limited.body.error, 'rate_limited');
    }
    // The admin still gets break-glass, a root terminal and an ordinary one.
    assert.equal((await ticket(adminApp.url, 'breakglass:open', admin)).status, 200);
    assert.equal((await ticket(adminApp.url, 'terminal:root', admin)).status, 200);
    assert.equal((await ticket(adminApp.url, 'terminal:open', admin)).status, 200);
    // Privileged tickets have their own budget per actor.
    assert.equal((await ticket(adminApp.url, 'breakglass:open', admin)).status, 429);
    assert.equal((await ticket(adminApp.url, 'terminal:open', admin)).status, 200);
    assert.equal((await ticket(adminApp.url, 'terminal:open', admin)).status, 429);
    assert.equal(fm.registry.audit.filter((row) => row.action === 'ticket_issued').length, 6);
  } finally {
    opApp.server.close();
    adminApp.server.close();
  }
});

test('audit verify is refused for a caller in no tenant', async () => {
  const fm = fleet();
  await fm.registry.appendAudit({ tenant_id: 'acme', action: 'sysscript', payload: { n: 1 } });
  await fm.registry.setScopes('ak_test', ['admin']);
  const { server, url } = await listen(appFor(fm));
  try {
    const res = await call(`${url}/api/v1/audit/verify`, { headers: { 'x-api-key': 'good-key' } });
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'scope_denied');
    await seed(fm);
    const member = await call(`${url}/api/v1/audit/verify`, { headers: { 'x-api-key': 'good-key' } });
    assert.equal(member.status, 200);
    assert.equal(member.body.ok, true);
  } finally {
    server.close();
  }
});
