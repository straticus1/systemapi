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
  assert.equal(await auth.getUserFromToken(sign(claims())), 'authentik-sub-123');
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
