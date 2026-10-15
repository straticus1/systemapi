'use strict';

// playground/auth.js JWT verification: openid-client 6 discovery plus a jose
// remote JWKS, both served by an in-process fetch (no network).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const AuthManager = require('../playground/auth');

const ISSUER = 'https://issuer.test/application/o/systemapi/';
const JWKS_URI = 'https://issuer.test/application/o/systemapi/jwks/';
const AUDIENCE = 'systemapi-test-audience';
const KID = 'test-key-1';

const signing = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const stranger = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...signing.publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };

function b64url(value) {
  return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
}

function sign(payload, { key = signing.privateKey, kid = KID, alg = 'RS256' } = {}) {
  const head = b64url({ alg, typ: 'JWT', kid });
  const body = b64url(payload);
  const sig = crypto.sign('sha256', Buffer.from(`${head}.${body}`), key).toString('base64url');
  return `${head}.${body}.${sig}`;
}

function claims(extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: AUDIENCE, sub: 'authentik-sub-123', iat: now, nbf: now - 5, exp: now + 300, ...extra };
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
}

// An in-process issuer. metadata overrides the discovery document; down
// lists the endpoints that fail as if unreachable.
function issuerFetch({ metadata = {}, down = [] } = {}) {
  const calls = { discovery: 0, jwks: 0 };
  const fetch = async (url) => {
    const href = String(url);
    if (href === `${ISSUER}.well-known/openid-configuration`) {
      calls.discovery += 1;
      if (down.includes('discovery')) throw new TypeError('fetch failed');
      return jsonResponse({
        issuer: ISSUER,
        jwks_uri: JWKS_URI,
        authorization_endpoint: `${ISSUER}authorize/`,
        token_endpoint: `${ISSUER}token/`,
        id_token_signing_alg_values_supported: ['RS256'],
        ...metadata
      });
    }
    if (href === JWKS_URI) {
      calls.jwks += 1;
      if (down.includes('jwks')) throw new TypeError('fetch failed');
      return jsonResponse({ keys: [publicJwk] });
    }
    throw new TypeError(`unexpected fetch ${href}`);
  };
  return { fetch, calls };
}

function manager(fetchSetup = issuerFetch(), env = { AUTHENTIK_ISSUER: ISSUER, OIDC_AUDIENCE: AUDIENCE }) {
  return new AuthManager('https://unused.test', 'unused', 'systemapi-client', 'systemapi', null, {
    env,
    customFetch: fetchSetup.fetch
  });
}

// Silence the rejection warnings; tests assert on return values.
const realWarn = console.warn;
test.before(() => { console.warn = () => {}; });
test.after(() => { console.warn = realWarn; });

test('a token signed by the issuer key, for the audience, inside its lifetime verifies', async () => {
  const auth = manager();
  const payload = await auth.verifyJWTToken(sign(claims()));
  assert.equal(payload.sub, 'authentik-sub-123');
  assert.equal(await auth.getUserFromToken(sign(claims())), 'oidc:authentik-sub-123');
});

test('rejects a token with no sub, an empty or non-string sub, and a user_id-only token', async () => {
  const auth = manager();
  const noSub = claims();
  delete noSub.sub;
  assert.equal(await auth.verifyJWTToken(sign(noSub)), null);
  assert.equal(await auth.getUserFromToken(sign(noSub)), null);
  assert.equal(await auth.getUserFromToken(sign({ ...noSub, user_id: 'ryan' })), null);
  assert.equal(await auth.getUserFromToken(sign(claims({ sub: '' }))), null);
  assert.equal(await auth.getUserFromToken(sign(claims({ sub: 42 }))), null);
  assert.equal(await auth.getUserFromToken(sign(claims({ sub: 'x'.repeat(251) }))), null);
});

test('the JWT principal is namespaced and can never be a control-plane member id', async () => {
  const { USER_RE } = require('../controlplane/oauth');
  const principal = await manager().getUserFromToken(sign(claims({ sub: 'ryan' })));
  assert.equal(principal, `${AuthManager.JWT_PRINCIPAL_PREFIX}ryan`);
  assert.equal(USER_RE.test(principal), false);
});

test('rejects a token from the wrong issuer', async () => {
  assert.equal(await manager().verifyJWTToken(sign(claims({ iss: 'https://evil.test/' }))), null);
});

test('rejects a token for the wrong audience', async () => {
  assert.equal(await manager().verifyJWTToken(sign(claims({ aud: 'some-other-client' }))), null);
});

test('rejects an expired token (beyond the 30 s clock tolerance)', async () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(await manager().verifyJWTToken(sign(claims({ iat: now - 600, nbf: now - 600, exp: now - 60 }))), null);
});

test('rejects a token that is not yet valid (nbf in the future)', async () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(await manager().verifyJWTToken(sign(claims({ nbf: now + 600 }))), null);
});

test('rejects a token with no exp', async () => {
  const c = claims();
  delete c.exp;
  assert.equal(await manager().verifyJWTToken(sign(c)), null);
});

test('rejects a tampered payload and a tampered signature', async () => {
  const auth = manager();
  const good = sign(claims());
  const [head, , sig] = good.split('.');
  const forgedBody = b64url(claims({ sub: 'admin' }));
  assert.equal(await auth.verifyJWTToken(`${head}.${forgedBody}.${sig}`), null);
  const flipped = sig.slice(0, -2) + (sig.at(-2) === 'A' ? 'B' : 'A') + sig.at(-1);
  assert.equal(await auth.verifyJWTToken(`${head}.${good.split('.')[1]}.${flipped}`), null);
});

test('rejects alg:none, with and without a trailing signature segment', async () => {
  const auth = manager();
  const head = b64url({ alg: 'none', typ: 'JWT', kid: KID });
  const body = b64url(claims());
  assert.equal(await auth.verifyJWTToken(`${head}.${body}.`), null);
  assert.equal(await auth.verifyJWTToken(`${head}.${body}`), null);
});

test('rejects HS256 signed with the public key as the HMAC secret', async () => {
  const auth = manager();
  const head = b64url({ alg: 'HS256', typ: 'JWT', kid: KID });
  const body = b64url(claims());
  for (const secret of [
    signing.publicKey.export({ format: 'pem', type: 'spki' }),
    JSON.stringify(publicJwk),
    publicJwk.n
  ]) {
    const sig = crypto.createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
    assert.equal(await auth.verifyJWTToken(`${head}.${body}.${sig}`), null);
  }
});

test('rejects an allowlisted-looking algorithm outside the allowlist (RS512)', async () => {
  const head = b64url({ alg: 'RS512', typ: 'JWT', kid: KID });
  const body = b64url(claims());
  const sig = crypto.sign('sha512', Buffer.from(`${head}.${body}`), signing.privateKey).toString('base64url');
  assert.equal(await manager().verifyJWTToken(`${head}.${body}.${sig}`), null);
});

test('rejects an unknown kid, and a known kid signed by another key', async () => {
  const auth = manager();
  assert.equal(await auth.verifyJWTToken(sign(claims(), { key: stranger.privateKey, kid: 'unknown-kid' })), null);
  assert.equal(await auth.verifyJWTToken(sign(claims(), { key: stranger.privateKey })), null);
});

test('fails closed when discovery is unreachable, and backs off instead of refetching per token', async () => {
  const setup = issuerFetch({ down: ['discovery'] });
  const auth = manager(setup);
  assert.equal(await auth.verifyJWTToken(sign(claims())), null);
  assert.equal(await auth.verifyJWTToken(sign(claims())), null);
  assert.equal(setup.calls.discovery, 1);
});

test('fails closed when the JWKS is unreachable', async () => {
  const setup = issuerFetch({ down: ['jwks'] });
  assert.equal(await manager(setup).verifyJWTToken(sign(claims())), null);
  assert.ok(setup.calls.jwks >= 1);
});

test('fails closed when the discovered issuer differs from the configured one', async () => {
  const setup = issuerFetch({ metadata: { issuer: 'https://evil.test/' } });
  assert.equal(await manager(setup).verifyJWTToken(sign(claims({ iss: 'https://evil.test/' }))), null);
});

test('fails closed when discovery names a non-https jwks_uri', async () => {
  const setup = issuerFetch({ metadata: { jwks_uri: 'http://issuer.test/jwks/' } });
  assert.equal(await manager(setup).verifyJWTToken(sign(claims())), null);
});

test('fails closed when discovery names a jwks_uri off the issuer origin', async () => {
  for (const jwks_uri of ['https://evil.test/jwks/', 'https://issuer.test:8443/application/o/systemapi/jwks/']) {
    const setup = issuerFetch({ metadata: { jwks_uri } });
    const auth = manager(setup);
    assert.equal(await auth.verifyJWTToken(sign(claims())), null);
    assert.equal(setup.calls.jwks, 0);
    await assert.rejects(auth.discoverVerifier(), (err) => err.code === 'jwks_uri_origin');
  }
});

test('refuses every token when no audience is configured', async () => {
  const setup = issuerFetch();
  const auth = new AuthManager('https://unused.test', 'unused', '', 'systemapi', null, {
    env: { AUTHENTIK_ISSUER: ISSUER },
    customFetch: setup.fetch
  });
  assert.equal(await auth.verifyJWTToken(sign(claims())), null);
  assert.equal(setup.calls.discovery, 0);
});

test('rejects oversized and non-string bearer values without fetching, and garbage after discovery', async () => {
  const setup = issuerFetch();
  const auth = manager(setup);
  assert.equal(await auth.verifyJWTToken('a'.repeat(9000)), null);
  assert.equal(await auth.verifyJWTToken(undefined), null);
  assert.equal(setup.calls.discovery, 0);
  assert.equal(await auth.verifyJWTToken('not-a-jwt'), null);
});

test('constructing an AuthManager does no network I/O', () => {
  const setup = issuerFetch();
  manager(setup);
  assert.deepEqual(setup.calls, { discovery: 0, jwks: 0 });
});

// M1: a JWT whose sub equals a member id ("ryan") must not act for that
// member through the playground key routes, and the key it mints must carry
// no tenant powers in the control plane.

const express = require('express');
const bcrypt = require('bcryptjs');
const createPlaygroundRouter = require('../playground/router');
const FleetManager = require('../playground/fleet');
const { MemoryRegistry } = require('../controlplane/registry');
const { authenticate } = require('../controlplane/router');

// Just the playground_api_keys statements the key routes and key checks run.
function keysPool() {
  const rows = [];
  async function query(sql, params = []) {
    const q = sql.replace(/\s+/g, ' ').trim();
    if (q.startsWith('INSERT INTO playground_api_keys')) {
      const [key_id, key_hash, user_id, name, api_site, description] = params;
      rows.push({ key_id, key_hash, user_id, name, api_site, description, is_active: true, is_locked: false, created_at: new Date() });
      return { rows: [], rowCount: 1 };
    }
    if (q.includes('FROM playground_api_keys WHERE key_id = $1 AND api_site = $2 AND is_active = true AND is_locked = false')) {
      const r = rows.filter((k) => k.key_id === params[0] && k.api_site === params[1] && k.is_active && !k.is_locked);
      return { rows: r, rowCount: r.length };
    }
    if (q.startsWith('SELECT user_id FROM playground_api_keys WHERE key_id = $1 AND api_site = $2')) {
      const r = rows.filter((k) => k.key_id === params[0] && k.api_site === params[1]);
      return { rows: r, rowCount: r.length };
    }
    if (q.includes('FROM playground_api_keys WHERE user_id = $1 AND api_site = $2')) {
      const r = rows.filter((k) => k.user_id === params[0] && k.api_site === params[1]);
      return { rows: r, rowCount: r.length };
    }
    if (q.includes('FROM playground_api_keys WHERE key_id = $1')) {
      const r = rows.filter((k) => k.key_id === params[0]);
      return { rows: r, rowCount: r.length };
    }
    if (q.startsWith('UPDATE playground_api_keys SET is_active = false WHERE key_id = $1')) {
      rows.filter((k) => k.key_id === params[0]).forEach((k) => { k.is_active = false; });
      return { rows: [], rowCount: 1 };
    }
    if (q.startsWith('UPDATE playground_api_keys SET is_locked = $1 WHERE key_id = $2')) {
      rows.filter((k) => k.key_id === params[1]).forEach((k) => { k.is_locked = params[0]; });
      return { rows: [], rowCount: 1 };
    }
    if (q.startsWith('UPDATE playground_api_keys SET last_used_at')) return { rows: [], rowCount: 1 };
    throw new Error(`unexpected SQL in test pool: ${q}`);
  }
  return { rows, query, async connect() { return { query, release() {} }; } };
}

test('a JWT whose sub equals a member id cannot list, lock or delete that member\'s keys, and its key has no tenant powers', async () => {
  const setup = issuerFetch();
  const realFetch = globalThis.fetch;
  const savedEnv = { AUTHENTIK_ISSUER: process.env.AUTHENTIK_ISSUER, OIDC_AUDIENCE: process.env.OIDC_AUDIENCE };
  // The router builds its own AuthManager from process.env; serve the issuer
  // in-process and pass every other request (the test's own) through.
  globalThis.fetch = (url, opts) => (String(url).startsWith('https://issuer.test/') ? setup.fetch(url, opts) : realFetch(url, opts));
  process.env.AUTHENTIK_ISSUER = ISSUER;
  process.env.OIDC_AUDIENCE = AUDIENCE;

  const pool = keysPool();
  const adminSecret = 'ak_live_ryanbootstrap0.ryanbootstrapsecret';
  pool.rows.push({
    key_id: 'ak_live_ryanbootstrap0', key_hash: await bcrypt.hash(adminSecret, 4), user_id: 'ryan',
    name: 'bootstrap', api_site: 'systemapi', is_active: true, is_locked: false, created_at: new Date()
  });
  const registry = new MemoryRegistry({ NODE_ENV: 'test' });
  await registry.enroll({ tenantId: 'acme', userId: 'ryan', keyId: 'ak_live_ryanbootstrap0', hostId: '11111111-1111-4111-8111-111111111111', hostname: 'a', os: '', platform: '', sshPubkey: 'x' });
  const fleet = { registry, db: pool, apiSite: 'systemapi', env: { NODE_ENV: 'test' } };
  fleet.verifyApiKey = FleetManager.prototype.verifyApiKey.bind(fleet);
  const principalFor = (secret) => authenticate({ query: {}, get: (h) => (h === 'x-api-key' ? secret : undefined) }, fleet);
  assert.equal((await principalFor(adminSecret)).memberships.length, 1);

  const app = express();
  app.use(express.json());
  const revoked = [];
  const onKeyRevoked = async (keyId, actor) => { revoked.push({ keyId, actor }); };
  app.use('/playground', createPlaygroundRouter({ db: pool, redis: null, keycloakURL: 'https://unused.test', keycloakRealm: 'unused', keycloakClientID: 'systemapi-client', apiSite: 'systemapi', baseURL: 'http://127.0.0.1', onKeyRevoked }));
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}/playground`;
  const headers = { authorization: `Bearer ${sign(claims({ sub: 'ryan' }))}`, 'content-type': 'application/json' };
  try {
    const list = await realFetch(`${base}/api-keys`, { headers });
    assert.equal(list.status, 200);
    assert.deepEqual((await list.json()).api_keys, []);

    const lock = await realFetch(`${base}/api-keys/ak_live_ryanbootstrap0/lock`, { method: 'PATCH', headers, body: JSON.stringify({ locked: true }) });
    assert.equal(lock.status, 403);
    const del = await realFetch(`${base}/api-keys/ak_live_ryanbootstrap0`, { method: 'DELETE', headers });
    assert.equal(del.status, 403);
    const admin = pool.rows.find((k) => k.key_id === 'ak_live_ryanbootstrap0');
    assert.equal(admin.is_locked, false);
    assert.equal(admin.is_active, true);

    const mint = await realFetch(`${base}/api-keys`, { method: 'POST', headers, body: JSON.stringify({ name: 'mine' }) });
    assert.equal(mint.status, 201);
    const minted = await mint.json();
    assert.equal(pool.rows.find((k) => k.key_id === minted.key_id).user_id, 'oidc:ryan');
    const principal = await principalFor(minted.key_secret);
    assert.equal(principal.userId, 'oidc:ryan');
    assert.deepEqual(principal.memberships, []);

    // The JWT user still owns and manages its own key.
    const own = await realFetch(`${base}/api-keys`, { headers });
    assert.deepEqual((await own.json()).api_keys.map((k) => k.key_id), [minted.key_id]);
    assert.deepEqual(revoked, [], 'refused lock and delete close nothing');
    const ownUnlock = await realFetch(`${base}/api-keys/${minted.key_id}/lock`, { method: 'PATCH', headers, body: JSON.stringify({ locked: false }) });
    assert.equal(ownUnlock.status, 200);
    assert.deepEqual(revoked, [], 'an unlock closes nothing');
    const ownLock = await realFetch(`${base}/api-keys/${minted.key_id}/lock`, { method: 'PATCH', headers, body: JSON.stringify({ locked: true }) });
    assert.equal(ownLock.status, 200);
    assert.deepEqual(revoked, [{ keyId: minted.key_id, actor: 'oidc:ryan' }]);
    const ownDel = await realFetch(`${base}/api-keys/${minted.key_id}`, { method: 'DELETE', headers });
    assert.equal(ownDel.status, 200);
    assert.deepEqual(revoked.map((r) => r.keyId), [minted.key_id, minted.key_id]);
  } finally {
    server.close();
    globalThis.fetch = realFetch;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});
