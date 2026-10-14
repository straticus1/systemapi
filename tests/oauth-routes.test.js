'use strict';

// routes/oauth.js against a mock Authentik issuer served over HTTPS (a
// throwaway self-signed certificate, trusted only by this test's fetch).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const express = require('express');
const session = require('express-session');

const { createOAuthRouter } = require('../routes/oauth');
const { MemoryRegistry } = require('../controlplane/registry');
const { mount } = require('../controlplane/router');
const { fingerprint } = require('../controlplane/token');

const CLIENT_ID = 'systemapi-test-client';
const CLIENT_SECRET = 'client-secret-canary-value';
const ADMIN_SUB = 'f3a9c1d2e4b5a6978877665544332211aabbccddeeff00112233445566778899';
const VIEWER_SUB = '0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9';
const STRANGER_SUB = '99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa';

function makeCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'systemapi-issuer-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'
  ], { stdio: 'ignore' });
  const out = { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

// A fetch that trusts exactly the test CA and nothing else.
function trustingFetch(ca) {
  return (url, opts = {}) => new Promise((resolve, reject) => {
    let body = opts.body;
    if (body instanceof URLSearchParams) body = body.toString();
    const headers = opts.headers instanceof Headers ? Object.fromEntries(opts.headers.entries()) : { ...(opts.headers || {}) };
    const req = https.request(new URL(url), { method: opts.method || 'GET', headers, ca, minVersion: 'TLSv1.3' }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const h = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) v.forEach((x) => h.append(k, x));
          else if (v != null) h.set(k, String(v));
        }
        resolve(new Response(chunks.length ? Buffer.concat(chunks) : null, { status: res.statusCode, headers: h }));
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

async function startIssuer() {
  const tls = makeCert();
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
  const codes = new Map();
  const tokens = new Map();
  const state = { issuer: '' };

  function idToken(claims, alg) {
    const header = b64url(JSON.stringify({ alg, kid: 'k1', typ: 'JWT' }));
    const payload = b64url(JSON.stringify(claims));
    const input = header + '.' + payload;
    const sig = alg === 'HS256'
      ? crypto.createHmac('sha256', CLIENT_SECRET).update(input).digest()
      : crypto.sign('sha256', Buffer.from(input), privateKey);
    return input + '.' + b64url(sig);
  }

  function json(res, status, body) {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  }

  const server = https.createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.3' }, (req, res) => {
    const url = new URL(req.url, state.issuer);
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (url.pathname === '/application/o/test/.well-known/openid-configuration') {
        json(res, 200, {
          issuer: state.issuer,
          authorization_endpoint: state.issuer + 'authorize/',
          token_endpoint: state.issuer + 'token/',
          userinfo_endpoint: state.issuer + 'userinfo/',
          end_session_endpoint: state.issuer + 'end-session/',
          jwks_uri: state.issuer + 'jwks/',
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic']
        });
        return;
      }
      if (url.pathname === '/application/o/test/jwks/') {
        json(res, 200, { keys: [jwk] });
        return;
      }
      if (url.pathname === '/application/o/test/token/' && req.method === 'POST') {
        const form = new URLSearchParams(Buffer.concat(chunks).toString());
        // RFC 6749 2.3.1: Basic credentials are form-urlencoded, then joined.
        const auth = /^Basic ([A-Za-z0-9+/=]+)$/.exec(req.headers.authorization || '');
        const pair = auth ? Buffer.from(auth[1], 'base64').toString().split(':') : [];
        const decode = (v) => decodeURIComponent(String(v).replace(/\+/g, ' '));
        const clientOk = pair.length === 2 && decode(pair[0]) === CLIENT_ID && decode(pair[1]) === CLIENT_SECRET;
        const grant = codes.get(form.get('code'));
        codes.delete(form.get('code'));
        const verifier = form.get('code_verifier') || '';
        const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
        if (!clientOk || !grant || grant.challenge !== challenge
          || form.get('grant_type') !== 'authorization_code' || form.get('redirect_uri') !== grant.redirectUri) {
          json(res, 400, { error: 'invalid_grant' });
          return;
        }
        const now = Math.floor(Date.now() / 1000);
        const access = crypto.randomBytes(24).toString('base64url');
        tokens.set(access, grant);
        json(res, 200, {
          access_token: access,
          token_type: 'Bearer',
          expires_in: 300,
          refresh_token: crypto.randomBytes(24).toString('base64url'),
          id_token: idToken({
            iss: grant.iss || state.issuer,
            sub: grant.sub,
            aud: CLIENT_ID,
            iat: now,
            exp: now + 300,
            nonce: grant.idNonce === undefined ? grant.nonce : grant.idNonce
          }, grant.alg || 'RS256')
        });
        return;
      }
      if (url.pathname === '/application/o/test/userinfo/') {
        const grant = tokens.get((req.headers.authorization || '').replace(/^Bearer /, ''));
        if (!grant) {
          json(res, 401, { error: 'invalid_token' });
          return;
        }
        json(res, 200, { sub: grant.sub, email: grant.email, name: grant.name, groups: [] });
        return;
      }
      json(res, 404, { error: 'not_found' });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  state.issuer = `https://127.0.0.1:${server.address().port}/application/o/test/`;
  return {
    server,
    issuer: state.issuer,
    fetch: trustingFetch(tls.cert),
    // What the user "does" at Authentik: the authorize URL's PKCE challenge
    // and nonce come back bound to a one-time code.
    grant(authUrl, redirectUri, extra) {
      const code = crypto.randomBytes(16).toString('hex');
      codes.set(code, {
        challenge: authUrl.searchParams.get('code_challenge'),
        nonce: authUrl.searchParams.get('nonce'),
        redirectUri,
        ...extra
      });
      return code;
    }
  };
}

function fleet() {
  const registry = new MemoryRegistry({ NODE_ENV: 'test' });
  return {
    env: { NODE_ENV: 'test' },
    tickets: new Map(),
    registry,
    metrics: { executionsTotal: { inc() {} } },
    async verifyApiKey() {
      return null;
    }
  };
}

function browser() {
  let cookie = '';
  const go = async (target, opts = {}) => {
    const headers = { ...(opts.headers || {}) };
    if (cookie) headers.cookie = cookie;
    const res = await fetch(target, { redirect: 'manual', ...opts, headers });
    for (const line of res.headers.getSetCookie()) cookie = line.split(';')[0];
    return res;
  };
  go.cookie = () => cookie;
  return go;
}

async function bodyOf(res) {
  const text = await res.text();
  try { return JSON.parse(text); } catch { return text; }
}

async function setup() {
  const idp = await startIssuer();
  const fm = fleet();
  const lines = [];
  const logger = {
    log: (...a) => lines.push(a.join(' ')),
    warn: (...a) => lines.push(a.join(' ')),
    error: (...a) => lines.push(a.join(' '))
  };
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: true, limit: '256kb' }));
  app.use(session({ secret: 'test-secret-not-production', resave: false, saveUninitialized: false }));
  // Test-only probes: plant fields before login, read the session back, and
  // tamper with the stored return path between login and callback.
  app.get('/test/plant', (req, res) => {
    req.session.planted = 'yes';
    req.session.user = { id: 'planted-sub' };
    req.session.csrf = 'planted-csrf-value';
    req.session.deviceConfirm = 'planted';
    res.json({ ok: true });
  });
  app.get('/test/peek', (req, res) => {
    const s = req.session;
    res.json({ planted: s.planted || null, csrf: s.csrf || null, deviceConfirm: s.deviceConfirm || null, user: s.user || null, oauth: s.oauth || null });
  });
  app.get('/test/taint', (req, res) => {
    req.session.oauth.return_to = String(req.query.to);
    res.json({ ok: true });
  });
  const listening = await new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
  const url = `http://127.0.0.1:${listening.address().port}`;
  const env = {
    NODE_ENV: 'test',
    AUTHENTIK_ISSUER: idp.issuer,
    AUTHENTIK_CLIENT_ID: CLIENT_ID,
    AUTHENTIK_CLIENT_SECRET: CLIENT_SECRET,
    AUTHENTIK_REDIRECT_URI: url + '/oauth/callback'
  };
  app.use('/oauth', createOAuthRouter({ env, logger, customFetch: idp.fetch }));
  mount(app, fm);

  // Starts a login in this browser and returns the authorize URL.
  async function login(go, returnTo) {
    const res = await go(url + '/oauth/login' + (returnTo === undefined ? '' : '?return_to=' + encodeURIComponent(returnTo)));
    assert.equal(res.status, 302);
    await res.text();
    return new URL(res.headers.get('location'));
  }
  // Authentik answers for this user; returns the callback response.
  async function callback(go, authUrl, user, extra = {}) {
    const code = idp.grant(authUrl, env.AUTHENTIK_REDIRECT_URI, { ...user, ...extra });
    const state = extra.state || authUrl.searchParams.get('state');
    return go(url + '/oauth/callback?code=' + code + '&state=' + encodeURIComponent(state));
  }
  async function signIn(go, user, returnTo) {
    const res = await callback(go, await login(go, returnTo), user);
    await res.text();
    return res;
  }
  return {
    idp, fm, url, lines, login, callback, signIn,
    close() {
      listening.close();
      idp.server.close();
    }
  };
}

const ADMIN = { sub: ADMIN_SUB, email: 'admin@example.test', name: 'Admin One' };
const VIEWER = { sub: VIEWER_SUB, email: 'viewer@example.test', name: 'Viewer One' };

test('login redirects with PKCE S256, state and nonce; anonymous GETs mint no session', async () => {
  const t = await setup();
  try {
    for (const p of ['/oauth/user', '/oauth/device/verify', '/oauth/callback']) {
      const res = await fetch(t.url + p, { redirect: 'manual' });
      await res.text();
      assert.deepEqual(res.headers.getSetCookie(), [], p);
    }
    const go = browser();
    const auth = await t.login(go);
    assert.equal(auth.origin + auth.pathname, t.idp.issuer + 'authorize/');
    assert.equal(auth.searchParams.get('response_type'), 'code');
    assert.equal(auth.searchParams.get('client_id'), CLIENT_ID);
    assert.equal(auth.searchParams.get('redirect_uri'), t.url + '/oauth/callback');
    assert.match(auth.searchParams.get('scope'), /\bopenid\b/);
    assert.equal(auth.searchParams.get('code_challenge_method'), 'S256');
    assert.match(auth.searchParams.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/);
    assert.ok(auth.searchParams.get('state').length >= 20);
    assert.ok(auth.searchParams.get('nonce').length >= 20);
    assert.equal(auth.searchParams.has('client_secret'), false);
    assert.equal(auth.href.includes(CLIENT_SECRET), false);
    const peek = await bodyOf(await go(t.url + '/test/peek'));
    assert.equal(peek.oauth.state, auth.searchParams.get('state'));
    assert.equal(peek.oauth.nonce, auth.searchParams.get('nonce'));
    assert.equal(crypto.createHash('sha256').update(peek.oauth.code_verifier).digest('base64url'), auth.searchParams.get('code_challenge'));
    // A second login in another browser gets fresh values.
    const other = await t.login(browser());
    assert.notEqual(other.searchParams.get('state'), auth.searchParams.get('state'));
    assert.notEqual(other.searchParams.get('nonce'), auth.searchParams.get('nonce'));
  } finally {
    t.close();
  }
});

test('callback accepts a good RS256 login and regenerate drops planted fields', async () => {
  const t = await setup();
  try {
    const go = browser();
    await (await go(t.url + '/test/plant')).text();
    const before = go.cookie();
    const auth = await t.login(go, '/dashboard?tab=hosts');
    const res = await t.callback(go, auth, ADMIN);
    await res.text();
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/dashboard?tab=hosts');
    assert.notEqual(go.cookie(), before);
    const peek = await bodyOf(await go(t.url + '/test/peek'));
    assert.equal(peek.planted, null);
    assert.equal(peek.csrf, null);
    assert.equal(peek.deviceConfirm, null);
    assert.equal(peek.oauth, null);
    assert.equal(peek.user.id, ADMIN_SUB);
    assert.equal(peek.user.email, 'admin@example.test');
    const me = await bodyOf(await go(t.url + '/oauth/user'));
    assert.equal(me.user.id, ADMIN_SUB);
    assert.equal(typeof me.csrf, 'string');
    assert.notEqual(me.csrf, 'planted-csrf-value');
    // The planted session id no longer works.
    const stale = await fetch(t.url + '/oauth/user', { headers: { cookie: before } });
    assert.equal(stale.status, 401);
    await stale.text();
  } finally {
    t.close();
  }
});

test('callback rejects a bad state, nonce, issuer and an HS256 ID token, and clears the login', async () => {
  const t = await setup();
  try {
    const cases = [
      ['state', { state: 'x'.repeat(43) }],
      ['nonce', { idNonce: 'not-the-nonce-sent' }],
      ['missing nonce', { idNonce: null }],
      ['issuer', { iss: 'https://evil.example/application/o/test/' }],
      ['HS256', { alg: 'HS256' }]
    ];
    for (const [name, extra] of cases) {
      const go = browser();
      const auth = await t.login(go);
      const res = await t.callback(go, auth, ADMIN, extra);
      const body = await bodyOf(res);
      assert.equal(res.status, 400, name);
      assert.deepEqual(Object.keys(body).sort(), ['error', 'request_id'], name);
      assert.equal(body.error, 'login_callback_failed', name);
      assert.match(body.request_id, /^[A-Za-z0-9_-]{16,}$/, name);
      const peek = await bodyOf(await go(t.url + '/test/peek'));
      assert.equal(peek.user, null, name);
      assert.equal(peek.oauth, null, name);
      // The one-shot login state is gone: the right answer now fails too.
      const again = await t.callback(go, auth, ADMIN);
      assert.equal(again.status, 400, name);
      assert.deepEqual(await bodyOf(again), { error: 'login_session_missing' });
      assert.equal((await go(t.url + '/oauth/user')).status, 401, name);
    }
    const blob = t.lines.join('\n');
    assert.match(blob, /\[oauth\] login_callback failed request_id=\S+ name=\S+ code=\S+/);
    for (const secret of [ADMIN_SUB, 'admin@example.test', CLIENT_SECRET, 'not-the-nonce-sent', 'evil.example']) {
      assert.equal(blob.includes(secret), false, secret);
    }
    assert.equal(/\n\s+at /.test(blob), false);
  } finally {
    t.close();
  }
});

test('return_to cannot leave the origin at login or at the callback', async () => {
  const t = await setup();
  const evil = ['/.//evil.com', '/x/..//evil.com', '/%2e//evil.com', '/%2e%2e//evil.com', '//evil.com', '/\\evil.com', 'https://evil.com'];
  try {
    for (const target of evil) {
      const go = browser();
      const res = await t.signIn(go, ADMIN, target);
      assert.equal(res.headers.get('location'), '/', 'login ' + target);
    }
    // A return path that reaches the session some other way is checked again
    // at the callback.
    for (const target of evil) {
      const go = browser();
      const auth = await t.login(go, '/dashboard');
      await (await go(t.url + '/test/taint?to=' + encodeURIComponent(target))).text();
      const res = await t.callback(go, auth, ADMIN);
      await res.text();
      assert.equal(res.status, 302);
      assert.equal(res.headers.get('location'), '/', 'callback ' + target);
    }
    const ok = await t.signIn(browser(), ADMIN, '/oauth/device/verify');
    assert.equal(ok.headers.get('location'), '/oauth/device/verify');
  } finally {
    t.close();
  }
});

test('SSO sessions map by sub only; binding is admin only and audited', async () => {
  const t = await setup();
  const reg = t.fm.registry;
  try {
    await reg.enroll({
      tenantId: 'acme', userId: 'admin-1', keyId: 'k1', hostId: '11111111-1111-4111-8111-111111111111',
      hostname: 'a.example', os: 'linux', platform: 'amd64',
      sshPubkey: 'ssh-ed25519 ' + Buffer.concat([
        Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), crypto.randomBytes(32)
      ]).toString('base64')
    });
    await reg.addMember('acme', 'admin-1', 'admin', 'admin@example.test');
    await reg.addMember('acme', 'viewer-1', 'viewer', 'viewer@example.test');

    // Email matches a member, but no sub is bound: refused everywhere.
    const goAdmin = browser();
    await t.signIn(goAdmin, ADMIN);
    const unbound = await goAdmin(t.url + '/api/v1/fleet');
    assert.equal(unbound.status, 403);
    assert.deepEqual(await bodyOf(unbound), { error: 'sso_unbound' });

    // Server-side bootstrap binds the first admin (audited), then the same
    // session is accepted.
    const { run } = require('../scripts/sso-bind');
    await run(['acme', 'admin-1', ADMIN_SUB], reg);
    const bound = await goAdmin(t.url + '/api/v1/fleet');
    assert.equal(bound.status, 200);
    assert.equal((await bodyOf(bound)).hosts.length, 1);

    // A different sub with the admin's email is still refused.
    const goStranger = browser();
    await t.signIn(goStranger, { sub: STRANGER_SUB, email: 'admin@example.test', name: 'Admin One' });
    assert.equal((await goStranger(t.url + '/api/v1/fleet')).status, 403);

    // The viewer's sub, once an admin binds it, maps to viewer-1; the viewer
    // cannot bind anything, the admin can, and every bind is in the chain.
    const put = (go, user, sub) => go(t.url + '/api/v1/tenants/acme/members/' + user + '/sso', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sso_sub: sub })
    });
    const auditBefore = reg.audit.length;
    const bindViewer = await put(goAdmin, 'viewer-1', VIEWER_SUB);
    assert.equal(bindViewer.status, 200);
    assert.deepEqual(await bodyOf(bindViewer), { tenant_id: 'acme', user_id: 'viewer-1', bound: true });
    const row = reg.audit[reg.audit.length - 1];
    assert.equal(reg.audit.length, auditBefore + 1);
    assert.equal(row.action, 'sso_bind');
    assert.equal(row.actor, 'admin-1');
    assert.equal(row.payload.sso_sub_fp, fingerprint(VIEWER_SUB));
    assert.equal(JSON.stringify(reg.audit).includes(VIEWER_SUB), false);

    const goViewer = browser();
    await t.signIn(goViewer, VIEWER);
    assert.equal((await goViewer(t.url + '/api/v1/fleet')).status, 200);
    const refused = await put(goViewer, 'admin-1', STRANGER_SUB);
    assert.equal(refused.status, 403);
    assert.deepEqual(await bodyOf(refused), { error: 'scope_denied' });
    assert.equal(reg.audit.length, auditBefore + 1);
    assert.equal(reg.members.find((m) => m.user_id === 'admin-1').sso_sub, ADMIN_SUB);
    assert.equal((await reg.verifyAudit()).ok, true);
  } finally {
    t.close();
  }
});

test('logout is POST with the session CSRF token', async () => {
  const t = await setup();
  try {
    const go = browser();
    await t.signIn(go, ADMIN);
    const getLogout = await go(t.url + '/oauth/logout');
    assert.equal(getLogout.status, 404);
    await getLogout.text();
    const me = await bodyOf(await go(t.url + '/oauth/user'));
    const post = (fields) => go(t.url + '/oauth/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString()
    });
    for (const fields of [{}, { csrf: '' }, { csrf: 'x'.repeat(me.csrf.length) }]) {
      const res = await post(fields);
      assert.equal(res.status, 403);
      assert.deepEqual(await bodyOf(res), { error: 'csrf_denied' });
    }
    assert.equal((await go(t.url + '/oauth/user')).status, 200);
    const cross = await fetch(t.url + '/oauth/logout', {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'csrf=' + encodeURIComponent(me.csrf)
    });
    assert.equal(cross.status, 303);
    assert.equal(cross.headers.get('location'), '/');
    assert.equal((await go(t.url + '/oauth/user')).status, 200);
    const out = await post({ csrf: me.csrf });
    assert.equal(out.status, 303);
    const loc = new URL(out.headers.get('location'));
    assert.equal(loc.origin + loc.pathname, t.idp.issuer + 'end-session/');
    assert.equal(typeof loc.searchParams.get('id_token_hint'), 'string');
    assert.equal((await go(t.url + '/oauth/user')).status, 401);
  } finally {
    t.close();
  }
});
