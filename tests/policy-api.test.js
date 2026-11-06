'use strict';

// The channel-policy HTTP API (plan sah-fleet-readiness P2b-P2d,
// controlplane/policyroutes.js) against MemoryRegistry: reads, full
// replace, clear, inherit, dry runs, if_version, revert, tenant defaults,
// the dangerous-grant gate (echo plus step-up), CSRF for cookie sessions,
// tenant isolation, the audit rows, and a narrowing that stops live tcp,
// mesh and file sessions at once. Also the step-up device flow (fresh codes).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const oauth = require('../controlplane/oauth');
const { fingerprint } = require('../controlplane/token');
const { issueTicket } = require('../controlplane/tickets');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { policyVersion } = require('../controlplane/policyrules');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const KEYS = { 'agent-key': 'k-agent', 'admin-key': 'k-admin', 'read-key': 'k-read' };
const SUB = 'sub-user-1';
const ORIGIN = 'https://systemapi.io';
const nowS = () => Math.floor(Date.now() / 1000);

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
  app.use(express.urlencoded({ extended: true, limit: '256kb' }));
  // Stands in for express-session: a test sends its browser session as JSON.
  app.use((req, res, next) => {
    const raw = req.get('x-test-session');
    if (raw) req.session = JSON.parse(raw);
    next();
  });
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test', SYSTEMAPI_PUBLIC_URL: 'https://api.systemapi.test', ...env };
  fm.signer = signer();
  fm.tickets = new Map();
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.auditRetryDelaysMs = [10, 10];
  fm.tcp.finalWaitMs = 200;
  fm.verifyApiKey = async (key) => (KEYS[key] ? { key_id: KEYS[key], user_id: 'user-1' } : null);
  mount(app, fm);
  await fm.registry.setScopes('k-admin', ['admin']);
  await fm.registry.setScopes('k-read', ['hosts:read']);
  await fm.registry.enroll({ tenantId: 'acme', userId: 'user-1', keyId: 'k-agent', hostId: HOST_A, hostname: 'web1', sshPubkey: opensshEd25519(fm.signer.publicKeyRaw) });
  await fm.registry.enroll({ tenantId: 'other', userId: 'user-2', keyId: 'k-other', hostId: HOST_B, hostname: 'theirs', sshPubkey: opensshEd25519(fm.signer.publicKeyRaw) });
  for (const m of fm.registry.members) if (m.user_id === 'user-1') m.sso_sub = SUB;
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
      for (const s of fm.tcp.sessions.values()) fm.tcp.end(s, 'stopped');
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

// headers: an API key (key), a bearer (bearer), or a browser session.
async function call(r, method, pathname, { key = 'admin-key', bearer, session, origin, body, form } = {}) {
  const headers = {};
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  else if (session) headers['x-test-session'] = JSON.stringify(session);
  else if (key) headers['x-api-key'] = key;
  if (origin) headers.origin = origin;
  let payload;
  if (form !== undefined) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    payload = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    headers['content-type'] = 'application/json';
    payload = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(`${r.url}${pathname}`, { method, headers, body: payload, redirect: 'manual' });
  const text = await res.text();
  let parsed = text;
  try { parsed = JSON.parse(text); } catch { /* text */ }
  return { status: res.status, body: parsed, location: res.headers.get('location') };
}

const P = (host = HOST_A) => `/api/v1/hosts/${host}/channel-policy`;

async function version(r, host = HOST_A) {
  const got = await call(r, 'GET', P(host));
  assert.equal(got.status, 200, JSON.stringify(got.body));
  return got.body.version;
}

// A device-flow access token in the memory store; authTime null for a
// token that never passed step-up.
async function deviceToken(r, authTime) {
  await oauth.userForAccessToken(r.fm.registry, 'x'.repeat(20));
  const token = crypto.randomBytes(24).toString('hex');
  r.fm.registry.oauthAccess.set(fingerprint(token), {
    token_hash: fingerprint(token),
    user_id: 'user-1',
    expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
    auth_time: authTime === null ? null : new Date(authTime * 1000).toISOString()
  });
  return token;
}

const policyRows = (r) => r.fm.registry.audit.filter((row) => row.action.startsWith('channel_policy_'));

test('GET shows host, tenant and effective policy, the version and the dangerous list', async () => {
  const r = await rig();
  try {
    await r.fm.registry.setTenantChannelPolicy('acme', { package_policy: { names: ['curl'] } });
    const got = await call(r, 'GET', P());
    assert.equal(got.status, 200);
    assert.equal(got.body.host_id, HOST_A);
    assert.equal(got.body.host.tcp_policy, null);
    assert.deepEqual(got.body.tenant.package_policy, { names: ['curl'] });
    assert.deepEqual(got.body.effective.package_policy, { names: ['curl'] });
    assert.deepEqual(got.body.dangerous, ['package:curl']);
    assert.equal(got.body.grants, null);
    assert.equal(got.body.version, policyVersion({}));
  } finally {
    await r.close();
  }
});

test('PUT replaces all six columns with an audit row (policy_schema 2, previous values, key fingerprint)', async () => {
  const r = await rig();
  try {
    const v0 = await version(r);
    const put = await call(r, 'PUT', P(), { body: { reason: '  CHG-1 open pg  ', if_version: v0, grants: { tcp_local: [5432, 22, 5432], file_write: ['/srv/data'], service: ['nginx.service'] } } });
    assert.equal(put.status, 200, JSON.stringify(put.body));
    assert.deepEqual(put.body.dangerous, []);
    const got = await call(r, 'GET', P());
    assert.equal(got.body.version, put.body.version);
    assert.deepEqual(got.body.host.tcp_policy, { allow: [{ local: true, ports: [22, 5432] }] });
    assert.deepEqual(got.body.host.package_policy, { names: [] });
    assert.deepEqual(got.body.grants.tcp_local, [22, 5432]);
    const [row] = policyRows(r);
    assert.equal(row.action, 'channel_policy_set');
    assert.equal(row.actor, 'user-1');
    assert.equal(row.host_id, HOST_A);
    assert.equal(row.payload.policy_schema, 2);
    assert.equal(row.payload.via, 'key');
    assert.equal(row.payload.key_fp, fingerprint('k-admin'));
    assert.equal(row.payload.reason, 'CHG-1 open pg');
    for (const kind of ['tcp', 'file', 'service', 'package', 'config', 'tweak']) {
      assert.ok(Object.hasOwn(row.payload, `previous_${kind}_policy`), kind);
      assert.ok(Object.hasOwn(row.payload, `${kind}_policy`), kind);
    }
    assert.equal(put.body.audit_seq, row.seq);
  } finally {
    await r.close();
  }
});

test('if_version is required on every write; a stale one is 409 and writes nothing', async () => {
  const r = await rig();
  try {
    const writes = [
      ['PUT', P(), { grants: { tcp_local: [22] } }],
      ['POST', `${P()}/clear`, {}],
      ['POST', `${P()}/inherit`, {}],
      ['POST', `${P()}/revert`, { audit_seq: 1, apply: true }]
    ];
    for (const [method, path, extra] of writes) {
      const missing = await call(r, method, path, { body: { reason: 'r', ...extra } });
      assert.equal(missing.status, 400, path);
      assert.equal(missing.body.error, 'if_version_required');
      const bad = await call(r, method, path, { body: { reason: 'r', if_version: 'abc', ...extra } });
      assert.equal(bad.body.error, 'if_version_required');
    }
    const v0 = await version(r);
    assert.equal((await call(r, 'PUT', P(), { body: { reason: 'r', if_version: v0, grants: { tcp_local: [22] } } })).status, 200);
    for (const [method, path, extra] of writes.slice(0, 3)) {
      const stale = await call(r, method, path, { body: { reason: 'r', if_version: v0, ...extra } });
      assert.equal(stale.status, 409, path);
      assert.equal(stale.body.error, 'version_conflict');
    }
    assert.equal(policyRows(r).length, 1);
    // The registry re-checks under the lock: a write that raced in between
    // the route's read and its write is refused too.
    await assert.rejects(r.fm.registry.setHostChannelPolicyAudited({
      tenantId: 'acme', hostId: HOST_A, tcpPolicy: null, filePolicy: null, actor: 'x', action: 'channel_policy_inherit', reason: 'r', ifVersion: v0
    }), (err) => err.status === 409 && err.code === 'version_conflict');
  } finally {
    await r.close();
  }
});

test('dry_run returns the diff, the dangerous list and the live session count, and writes nothing', async () => {
  const r = await rig();
  try {
    const v0 = await version(r);
    const dry = await call(r, 'PUT', `${P()}?dry_run=1`, { body: { reason: 'r', if_version: v0, grants: { config: ['/etc/nginx'], tcp_local: [22] } } });
    assert.equal(dry.status, 200, JSON.stringify(dry.body));
    assert.equal(dry.body.dry_run, true);
    assert.equal(dry.body.version, v0);
    assert.deepEqual(dry.body.dangerous, ['config:/etc/nginx']);
    assert.deepEqual(dry.body.diff.config_policy, { before: null, after: { paths: ['/etc/nginx'] } });
    assert.equal(dry.body.live_sessions, 0);
    for (const verb of ['clear', 'inherit']) {
      const d = await call(r, 'POST', `${P()}/${verb}?dry_run=1`, { body: { reason: 'r', if_version: v0 } });
      assert.equal(d.status, 200);
      assert.equal(d.body.dry_run, true);
    }
    assert.equal((await call(r, 'PUT', `${P()}?dry_run=maybe`, { body: { reason: 'r', if_version: v0, grants: { tcp_local: [22] } } })).body.error, 'bad_dry_run');
    assert.equal(policyRows(r).length, 0);
    assert.equal(await version(r), v0);
  } finally {
    await r.close();
  }
});

test('malformed bodies and every rule the CLI enforces are refused with a fixed code', async () => {
  const r = await rig();
  try {
    const v0 = await version(r);
    const put = (body) => call(r, 'PUT', P(), { body: { reason: 'r', if_version: v0, ...body } });
    const cases = [
      [{ grants: { tcp_local: ['1-100'] } }, 'bad_port'],
      [{ grants: { tcp_local: [0] } }, 'bad_port'],
      [{ grants: { tcp_cidr: ['10.0.0.0/8:22'] } }, 'bad_grants'],
      [{ grants: { file_root: ['/srv/x'] } }, 'bad_grants'],
      [{ grants: { file_write: ['/'] } }, 'too_wide'],
      [{ grants: { file_read: ['/srv'] } }, 'too_wide'],
      [{ grants: { file_read: ['/etc/ssh'] } }, 'system_root'],
      [{ grants: { file_read: ['/var/lib'] } }, 'system_root'],
      [{ grants: { file_read: ['/srv/../etc'] } }, 'bad_path'],
      [{ grants: { service: ['systemapi-agent'] } }, 'self_unit'],
      [{ grants: { service: ['sah-config-helper@.service'] } }, 'self_unit'],
      [{ grants: { tweak_unit: ['systemapi-agent.service'] } }, 'self_unit'],
      [{ grants: { config: ['/etc/systemapi-agent'] } }, 'protected_path'],
      [{ grants: { tweak_sysctl: ['kernel.core_pattern'] } }, 'bad_sysctl'],
      [{ grants: { package: ['*'] } }, 'bad_package'],
      [{ grants: {} }, 'empty'],
      [{ grants: { tcp_local: Array.from({ length: 17 }, (_, i) => i + 1) } }, 'too_many'],
      [{ grants: { tcp_local: Array.from({ length: 65 }, (_, i) => i + 1) } }, 'bad_grants'],
      [{ grants: 'tcp' }, 'bad_grants']
    ];
    for (const [body, rule] of cases) {
      const res = await put(body);
      assert.equal(res.status, 400, JSON.stringify(body));
      assert.deepEqual(res.body, { error: 'bad_policy', reason: rule }, JSON.stringify(body));
    }
    for (const reason of ['', '   ', 'a\nb', 'tab\there', '\u007f', 'x'.repeat(257), 42]) {
      const res = await call(r, 'POST', `${P()}/clear`, { body: { reason, if_version: v0 } });
      assert.equal(res.body.error, 'bad_reason', JSON.stringify(reason));
    }
    assert.equal((await call(r, 'POST', `${P()}/clear`, { body: '[1,2]' })).body.error, 'bad_body');
    const oversize = await call(r, 'PUT', P(), { body: JSON.stringify({ reason: 'r', if_version: v0, grants: { service: ['x'.repeat(300 * 1024)] } }) });
    assert.equal(oversize.status, 413);
    assert.equal(policyRows(r).length, 0);
  } finally {
    await r.close();
  }
});

test('auth: no key 401, a non-admin 403 before any lookup, another tenant\'s host 404 with an idor event, retired 409', async () => {
  const r = await rig();
  try {
    assert.equal((await call(r, 'GET', P(), { key: null })).status, 401);
    const read = await call(r, 'GET', P(), { key: 'read-key' });
    assert.equal(read.status, 403);
    assert.equal(read.body.error, 'scope_denied');
    const before = r.fm.registry.securityEvents.filter((e) => e.kind === 'idor').length;
    for (const [method, path] of [['GET', P(HOST_B)], ['PUT', P(HOST_B)], ['POST', `${P(HOST_B)}/clear`], ['POST', `${P(HOST_B)}/revert`]]) {
      const res = await call(r, method, path, { body: method === 'GET' ? undefined : { reason: 'r', if_version: '0'.repeat(64), audit_seq: 1 } });
      assert.equal(res.status, 404, path);
      assert.equal(res.body.error, 'not_found');
    }
    const idor = r.fm.registry.securityEvents.filter((e) => e.kind === 'idor');
    assert.equal(idor.length, before + 4);
    assert.equal(idor[idor.length - 1].detail.host_id, HOST_B);
    const t = await call(r, 'GET', '/api/v1/tenants/other/channel-policy');
    assert.equal(t.status, 404);
    assert.equal(r.fm.registry.securityEvents.filter((e) => e.kind === 'idor').length, before + 5);
    assert.equal((await r.fm.registry.channelPolicies(HOST_B)).host_tcp_policy, null);
    await r.fm.registry.retireHost({ tenantId: 'acme', hostId: HOST_A, actor: 'user-1', reason: 'gone', forced: false });
    const retired = await call(r, 'GET', P());
    assert.equal(retired.status, 409);
    assert.equal(retired.body.error, 'host_retired');
  } finally {
    await r.close();
  }
});

test('dangerous writes: the echo is required, API keys and stale sessions are refused, a fresh session passes', async () => {
  const r = await rig();
  try {
    let v = await version(r);
    const grants = { config: ['/etc/nginx'], tweak_unit: ['nginx.service'], package: ['nginx'], service: ['sshd.service', 'nginx.service'] };
    const dry = await call(r, 'PUT', `${P()}?dry_run=1`, { body: { reason: 'r', if_version: v, grants } });
    const want = ['config:/etc/nginx', 'package:nginx', 'service:sshd.service', 'tweak_unit:nginx.service'];
    assert.deepEqual(dry.body.dangerous, want);
    // An API key is refused even with the echo.
    const key = await call(r, 'PUT', P(), { body: { reason: 'r', if_version: v, grants, confirm_dangerous: want } });
    assert.equal(key.status, 403);
    assert.deepEqual(key.body, { error: 'step_up_required', reason: 'api_key' });
    // A device token that never passed step-up, and a stale one.
    for (const authTime of [null, nowS() - 301]) {
      const token = await deviceToken(r, authTime);
      const res = await call(r, 'PUT', P(), { bearer: token, body: { reason: 'r', if_version: v, grants, confirm_dangerous: want } });
      assert.deepEqual(res.body, { error: 'step_up_required', reason: 'stale_auth' }, String(authTime));
    }
    // A stale cookie session, and one with an auth_time in the future.
    for (const at of [nowS() - 600, nowS() + 3600]) {
      const res = await call(r, 'PUT', P(), { session: { user: { id: SUB, auth_time: at } }, origin: ORIGIN, body: { reason: 'r', if_version: v, grants, confirm_dangerous: want } });
      assert.equal(res.body.reason, 'stale_auth');
    }
    assert.ok(r.fm.registry.securityEvents.filter((e) => e.kind === 'step_up_deny').length >= 5);
    // Fresh, but without the echo, or with a partial one.
    const fresh = await deviceToken(r, nowS() - 10);
    for (const echo of [undefined, want.slice(1), [...want, 'package:curl'], 'all']) {
      const res = await call(r, 'PUT', P(), { bearer: fresh, body: { reason: 'r', if_version: v, grants, confirm_dangerous: echo } });
      assert.equal(res.status, 409);
      assert.equal(res.body.error, 'dangerous_unconfirmed');
      assert.deepEqual(res.body.dangerous, want);
    }
    assert.equal(policyRows(r).length, 0);
    const ok = await call(r, 'PUT', P(), { bearer: fresh, body: { reason: 'r', if_version: v, grants, confirm_dangerous: [...want].reverse() } });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.deepEqual(ok.body.dangerous, want);
    const row = policyRows(r).pop();
    assert.equal(row.payload.via, 'token');
    assert.equal(row.payload.key_fp, null);
    assert.deepEqual(row.payload.dangerous, want);
    // Keeping what is already in force is not dangerous; an API key may
    // narrow it.
    v = ok.body.version;
    const keep = await call(r, 'PUT', P(), { body: { reason: 'r', if_version: v, grants: { ...grants, service: ['nginx.service'] } } });
    assert.equal(keep.status, 200, JSON.stringify(keep.body));
    assert.deepEqual(keep.body.dangerous, []);
    // A fresh cookie session from an allowed Origin passes too.
    v = keep.body.version;
    const viaCookie = await call(r, 'PUT', P(), { session: { user: { id: SUB, auth_time: nowS() } }, origin: ORIGIN, body: { reason: 'r', if_version: v, grants: { ...grants, service: ['redis-server.service'] }, confirm_dangerous: ['service:redis-server.service'] } });
    assert.equal(viaCookie.status, 200, JSON.stringify(viaCookie.body));
    assert.equal(policyRows(r).pop().payload.via, 'session');
  } finally {
    await r.close();
  }
});

test('dangerous classes: protected unit globs, bare names and sockets; /etc config; any package or tweak unit', async () => {
  const r = await rig();
  try {
    const v = await version(r);
    const dry = (grants) => call(r, 'PUT', `${P()}?dry_run=1`, { body: { reason: 'r', if_version: v, grants } });
    const units = ['ssh', 'ssh.socket', 'sahcore.service', 'my-cloudflared-tunnel.service', 'postgresql@16-main.service',
      'redis.service', 'dbus.socket', 'systemd-networkd.service', 'networking.service', 'NetworkManager.service',
      'systemd-resolved.service', 'systemd-logind.service'];
    assert.deepEqual((await dry({ service: units })).body.dangerous, units.map((u) => `service:${u}`).sort());
    assert.deepEqual((await dry({ service: ['nginx.service', 'myssh.service'], config: ['/etc/nginx/conf.d', '/etc/nginx/sites-enabled/app'], tweak_sysctl: ['vm.swappiness'] })).body.dangerous, []);
    // Every config path outside the safe list, /etc or not.
    assert.deepEqual((await dry({ config: ['/etc/nginx', '/opt/app/etc', '/srv/app/conf', '/var/spool/cron', '/etc/nginx/conf.dx'] })).body.dangerous,
      ['config:/etc/nginx', 'config:/etc/nginx/conf.dx', 'config:/opt/app/etc', 'config:/srv/app/conf', 'config:/var/spool/cron']);
    // Targets and the firewall.
    const more = ['multi-user.target', 'nftables.service', 'ufw', 'firewalld.service', 'iptables.service', 'netfilter-persistent.service'];
    assert.deepEqual((await dry({ service: more })).body.dangerous, more.slice(0, 5).map((u) => `service:${u}`).sort());
    assert.deepEqual((await dry({ package: ['curl'], tweak_unit: ['nginx.service'] })).body.dangerous, ['package:curl', 'tweak_unit:nginx.service']);
  } finally {
    await r.close();
  }
});

test('CSRF: a cookie session needs JSON and an allowed Origin; a form body is refused for everyone', async () => {
  const r = await rig();
  try {
    const v = await version(r);
    const session = { user: { id: SUB, auth_time: nowS() } };
    const body = { reason: 'r', if_version: v };
    assert.equal((await call(r, 'POST', `${P()}/clear`, { session, body })).body.error, 'origin_denied');
    assert.equal((await call(r, 'POST', `${P()}/clear`, { session, origin: 'https://evil.example', body })).body.error, 'origin_denied');
    const formSession = await call(r, 'POST', `${P()}/clear`, { session, origin: ORIGIN, form: body });
    assert.equal(formSession.status, 415);
    const formKey = await call(r, 'POST', `${P()}/clear`, { form: body });
    assert.equal(formKey.body.error, 'json_required');
    assert.equal(policyRows(r).length, 0);
    const ok = await call(r, 'POST', `${P()}/clear`, { session, origin: ORIGIN, body });
    assert.equal(ok.status, 200);
    // A bearer token is not ambient: no Origin needed.
    const token = await deviceToken(r, null);
    assert.equal((await call(r, 'POST', `${P()}/inherit`, { bearer: token, body: { reason: 'r', if_version: ok.body.version } })).status, 200);
  } finally {
    await r.close();
  }
});

test('revert restores the columns as they were before row N, exactly, including an explicit null', async () => {
  const r = await rig();
  try {
    await r.fm.registry.setHostChannelPolicy(HOST_A, { tcp_policy: { allow: [{ local: true, ports: [8080] }] }, file_policy: null });
    const v0 = await version(r);
    const before = (await call(r, 'GET', P())).body.host;
    const set = await call(r, 'PUT', P(), { body: { reason: 'r', if_version: v0, grants: { tcp_local: [22], file_read: ['/srv/logs'] } } });
    const seq = set.body.audit_seq;
    const v1 = set.body.version;
    // Without apply it is a dry run.
    const dry = await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: seq, reason: 'undo', if_version: v1 } });
    assert.equal(dry.status, 200, JSON.stringify(dry.body));
    assert.equal(dry.body.dry_run, true);
    assert.equal(dry.body.revert_of, seq);
    assert.equal(dry.body.next_version, v0);
    assert.deepEqual(dry.body.diff.file_policy, { before: { roots: [{ path: '/srv/logs', read: true, write: false }] }, after: null });
    assert.equal(await version(r), v1);
    const done = await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: seq, reason: 'undo', if_version: v1, apply: true } });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.equal(done.body.version, v0);
    const after = (await call(r, 'GET', P())).body.host;
    assert.deepEqual(after, before);
    assert.equal(after.file_policy, null);
    const row = policyRows(r).pop();
    assert.equal(row.action, 'channel_policy_revert');
    assert.equal(row.payload.revert_of, seq);
    assert.equal(row.payload.policy_schema, 2);
    assert.equal((await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: seq, reason: 'undo', if_version: v0, apply: 'yes' } })).body.error, 'bad_apply');
    assert.equal((await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: '1', reason: 'undo', if_version: v0 } })).body.error, 'bad_audit_seq');
  } finally {
    await r.close();
  }
});

test('revert refuses another host\'s, another tenant\'s and non-policy rows (404 + idor), pre-marker rows and refused shapes (409)', async () => {
  const r = await rig();
  try {
    const reg = r.fm.registry;
    await reg.enroll({ tenantId: 'acme', userId: 'user-1', keyId: 'k-agent', hostId: '33333333-3333-4333-8333-333333333333', hostname: 'web2', sshPubkey: opensshEd25519(r.fm.signer.publicKeyRaw) });
    const other = await reg.setHostChannelPolicyAudited({ tenantId: 'acme', hostId: '33333333-3333-4333-8333-333333333333', tcpPolicy: null, filePolicy: null, actor: 'x', action: 'channel_policy_inherit', reason: 'r', extra: { policy_schema: 2 } });
    const foreign = await reg.setHostChannelPolicyAudited({ tenantId: 'other', hostId: HOST_B, tcpPolicy: null, filePolicy: null, actor: 'x', action: 'channel_policy_inherit', reason: 'r', extra: { policy_schema: 2 } });
    const tenantRow = await reg.setTenantChannelPolicyAudited({ tenantId: 'acme', ...nulls(), actor: 'x', action: 'channel_policy_tenant_inherit', reason: 'r', extra: { policy_schema: 2 } });
    const plain = await reg.appendAudit({ tenant_id: 'acme', host_id: HOST_A, actor: 'x', action: 'sysscript', payload: {} });
    const v = await version(r);
    const idorBefore = reg.securityEvents.filter((e) => e.kind === 'idor').length;
    for (const seq of [other.audit_seq, foreign.audit_seq, tenantRow.audit_seq, plain.seq, 999]) {
      const res = await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: seq, reason: 'r', if_version: v, apply: true } });
      assert.equal(res.status, 404, String(seq));
    }
    assert.equal(reg.securityEvents.filter((e) => e.kind === 'idor').length, idorBefore + 5);
    // A CLI row from before P2 has no marker.
    const legacy = await reg.setHostChannelPolicyAudited({ tenantId: 'acme', hostId: HOST_A, tcpPolicy: { allow: [] }, filePolicy: { roots: [] }, actor: 'cli:channel-policy', action: 'channel_policy_clear', reason: 'r' });
    const v2 = await version(r);
    const pre = await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: legacy.audit_seq, reason: 'r', if_version: v2 } });
    assert.equal(pre.status, 409);
    assert.equal(pre.body.error, 'revert_unsupported');
    // A marked row whose previous value the rules refuse (a CIDR).
    await reg.setHostChannelPolicy(HOST_A, { tcp_policy: { allow: [{ cidr: '10.0.0.0/8', ports: [22] }] } });
    const v3 = await version(r);
    const cidr = await reg.setHostChannelPolicyAudited({ tenantId: 'acme', hostId: HOST_A, tcpPolicy: { allow: [] }, filePolicy: null, actor: 'x', action: 'channel_policy_set', reason: 'r', ifVersion: v3, extra: { policy_schema: 2 } });
    const refused = await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: cidr.audit_seq, reason: 'r', if_version: cidr.version } });
    assert.equal(refused.status, 409);
    assert.deepEqual(refused.body, { error: 'revert_unsupported', reason: 'unrepresentable' });
  } finally {
    await r.close();
  }
});

function nulls() {
  return { tcpPolicy: null, filePolicy: null, servicePolicy: null, packagePolicy: null, configPolicy: null, tweakPolicy: null };
}

test('revert of a narrowing that removed a dangerous grant is itself dangerous', async () => {
  const r = await rig();
  try {
    await r.fm.registry.setHostChannelPolicy(HOST_A, { package_policy: { names: ['nginx'] } });
    const v0 = await version(r);
    const clear = await call(r, 'POST', `${P()}/clear`, { body: { reason: 'r', if_version: v0 } });
    assert.deepEqual(clear.body.dangerous, []);
    const dry = await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: clear.body.audit_seq, reason: 'r', if_version: clear.body.version } });
    assert.deepEqual(dry.body.dangerous, ['package:nginx']);
    const apply = await call(r, 'POST', `${P()}/revert`, { body: { audit_seq: clear.body.audit_seq, reason: 'r', if_version: clear.body.version, apply: true, confirm_dangerous: ['package:nginx'] } });
    assert.equal(apply.status, 403);
    assert.equal(apply.body.error, 'step_up_required');
  } finally {
    await r.close();
  }
});

test('tenant routes: every write is dangerous; audited with host_id null; isolation; a failed audit rolls back', async () => {
  const r = await rig();
  try {
    const T = '/api/v1/tenants/acme/channel-policy';
    const got = await call(r, 'GET', T);
    assert.equal(got.status, 200);
    const v0 = got.body.version;
    const dry = await call(r, 'PUT', `${T}?dry_run=1`, { body: { reason: 'r', if_version: v0, grants: { tcp_local: [22] } } });
    assert.deepEqual(dry.body.dangerous, ['tenant_write']);
    const key = await call(r, 'PUT', T, { body: { reason: 'r', if_version: v0, grants: { tcp_local: [22] }, confirm_dangerous: ['tenant_write'] } });
    assert.equal(key.status, 403);
    const fresh = await deviceToken(r, nowS());
    const noEcho = await call(r, 'PUT', T, { bearer: fresh, body: { reason: 'r', if_version: v0, grants: { tcp_local: [22], package: ['curl'] } } });
    assert.deepEqual(noEcho.body.dangerous, ['package:curl', 'tenant_write']);
    const ok = await call(r, 'PUT', T, { bearer: fresh, body: { reason: 'r', if_version: v0, grants: { tcp_local: [22], package: ['curl'] }, confirm_dangerous: ['tenant_write', 'package:curl'] } });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    const row = policyRows(r).pop();
    assert.equal(row.action, 'channel_policy_tenant_set');
    assert.equal(row.host_id, null);
    assert.equal(row.tenant_id, 'acme');
    assert.equal(row.payload.previous_tcp_policy, null);
    assert.deepEqual(row.payload.package_policy, { names: ['curl'] });
    // The inheriting host now sees it.
    assert.deepEqual((await call(r, 'GET', P())).body.effective.tcp_policy, { allow: [{ local: true, ports: [22] }] });
    // Stale version; a bad tenant name; a failed audit leaves the policy.
    assert.equal((await call(r, 'POST', `${T}/clear`, { bearer: fresh, body: { reason: 'r', if_version: v0, confirm_dangerous: ['tenant_write'] } })).body.error, 'version_conflict');
    assert.equal((await call(r, 'GET', '/api/v1/tenants/ACME!/channel-policy')).status, 404);
    r.fm.registry.appendAudit = async () => { throw new Error('disk full'); };
    const failed = await call(r, 'POST', `${T}/inherit`, { bearer: fresh, body: { reason: 'r', if_version: ok.body.version, confirm_dangerous: ['tenant_write'] } });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.error, 'internal');
    assert.deepEqual((await r.fm.registry.tenantChannelPolicies('acme')).package_policy, { names: ['curl'] });
  } finally {
    await r.close();
  }
});

test('a failed host audit write rolls the policy back and answers internal', async () => {
  const r = await rig();
  try {
    const v0 = await version(r);
    r.fm.registry.appendAudit = async () => { throw new Error('disk full'); };
    const res = await call(r, 'PUT', P(), { body: { reason: 'r', if_version: v0, grants: { tcp_local: [22] } } });
    assert.equal(res.status, 500);
    assert.deepEqual(res.body, { error: 'internal' });
    assert.equal((await r.fm.registry.channelPolicies(HOST_A)).host_tcp_policy, null);
  } finally {
    await r.close();
  }
});

test('the global write cap answers 429 past SYSTEMAPI_POLICY_WRITE_RATE per minute', async () => {
  const r = await rig({ SYSTEMAPI_POLICY_WRITE_RATE: '3' });
  try {
    const v0 = await version(r);
    for (let i = 0; i < 3; i += 1) {
      assert.equal((await call(r, 'POST', `${P()}/clear?dry_run=1`, { body: { reason: 'r', if_version: v0 } })).status, 200);
    }
    const capped = await call(r, 'POST', `${P()}/clear`, { body: { reason: 'r', if_version: v0 } });
    assert.equal(capped.status, 429);
    assert.equal(capped.body.error, 'rate_limited');
    // Reads are not capped.
    assert.equal((await call(r, 'GET', P())).status, 200);
  } finally {
    await r.close();
  }
});

// A fake agent with tcp and file, for the revocation test.
async function connectAgent(r) {
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': HOST_A,
      'x-systemapi-hostname': 'web1',
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      'x-systemapi-capabilities': 'pty,tcp,file'
    }
  }));
  const box = { frames: [] };
  ws.on('message', (data, isBinary) => { if (!isBinary) box.frames.push(JSON.parse(data.toString())); });
  ws.on('error', () => {});
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  return { ws, box };
}

function client(r, pathname) {
  const ws = r.track(new WebSocket(`${r.ws}${pathname}`));
  const box = { frames: [], closeCode: null };
  ws.on('message', (data, isBinary) => { if (!isBinary) box.frames.push(JSON.parse(data.toString())); });
  ws.on('close', (code) => { box.closeCode = code; });
  ws.on('error', () => {});
  return { ws, box };
}

test('a narrowing through the API stops a live tcp, mesh and file session at once (not at the 30 s renewal)', async () => {
  const r = await rig();
  try {
    const v0 = await version(r);
    const set = await call(r, 'PUT', P(), { body: { reason: 'open', if_version: v0, grants: { tcp_local: [5432], file_write: ['/srv/a'] } } });
    assert.equal(set.status, 200, JSON.stringify(set.body));
    const agent = await connectAgent(r);
    const frames = (type) => agent.box.frames.filter((f) => f.type === type);
    const send = (obj) => agent.ws.send(JSON.stringify(obj));
    // tcp
    const tcpTicket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', actor: 'user-1', auth: null, target: { host: 'local', port: 5432 } });
    const tcp = client(r, `/api/v1/systems/tcp/${HOST_A}?ticket=${tcpTicket}&purpose=tcp:open`);
    const tcpOpen = await waitUntil('tcp_open', () => frames('tcp_open')[0]);
    send({ type: 'tcp_status', session_id: tcpOpen.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } });
    await waitUntil('tcp connected', () => tcp.box.frames.find((f) => f.type === 'tcp_status' && f.payload.status === 'connected'));
    // mesh, one stream
    const meshTicket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'mesh:open', tenantId: 'acme', actor: 'user-1', auth: null, target: null });
    const mesh = client(r, `/api/v1/systems/mesh/${HOST_A}?ticket=${meshTicket}&purpose=mesh:open`);
    await waitUntil('mesh_ready', () => mesh.box.frames.find((f) => f.type === 'mesh_ready'));
    mesh.ws.send(JSON.stringify({ type: 'mesh_open', stream: 1, target: { host: 'local', port: 5432 } }));
    const meshOpen = await waitUntil('mesh tcp_open', () => frames('tcp_open')[1]);
    send({ type: 'tcp_status', session_id: meshOpen.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } });
    await waitUntil('stream connected', () => mesh.box.frames.find((f) => f.type === 'mesh_status' && f.stream === 1 && f.payload.status === 'connected'));
    // file
    const fileTicket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'file:write', tenantId: 'acme', actor: 'user-1', auth: null, root: '/srv/a' });
    const file = client(r, `/api/v1/systems/file/${HOST_A}?ticket=${fileTicket}&purpose=file:write`);
    const fileOpen = await waitUntil('file_open', () => frames('file_open')[0]);
    send({ type: 'file_status', session_id: fileOpen.session_id, payload: { status: 'ready', root: fileOpen.root, user: 'deploy', uid: 1000 } });
    await waitUntil('file ready', () => file.box.frames.find((f) => f.type === 'file_status' && f.payload.status === 'ready'));

    const dry = await call(r, 'POST', `${P()}/clear?dry_run=1`, { body: { reason: 'close', if_version: set.body.version } });
    assert.equal(dry.body.live_sessions, 4);
    const started = Date.now();
    const cleared = await call(r, 'POST', `${P()}/clear`, { body: { reason: 'close', if_version: set.body.version } });
    assert.equal(cleared.status, 200);
    // The mesh session itself passes (no target); its stream, the tcp and
    // the file session end.
    assert.equal(cleared.body.renewed, 1);
    assert.equal(cleared.body.ended, 3);
    await waitUntil('tcp stopped', () => tcp.box.frames.find((f) => f.type === 'tcp_close' && f.payload.reason === 'stopped'));
    await waitUntil('mesh stream stopped', () => mesh.box.frames.find((f) => f.type === 'mesh_close' && f.stream === 1));
    await waitUntil('file stopped', () => frames('file_stop').length > 0 || file.box.closeCode !== null);
    assert.ok(Date.now() - started < 3000);
    await waitUntil('tcp_end rows', () => r.fm.registry.audit.filter((row) => row.action === 'tcp_end' && row.payload.reason === 'stopped').length === 2);
  } finally {
    await r.close();
  }
});

// A live tcp session on port 5432 of HOST_A; returns the client box and the
// server-side session.
async function liveTcp(r, agent) {
  const frames = (type) => agent.box.frames.filter((f) => f.type === type);
  const seen = frames('tcp_open').length;
  const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', actor: 'user-1', auth: null, target: { host: 'local', port: 5432 } });
  const tcp = client(r, `/api/v1/systems/tcp/${HOST_A}?ticket=${ticket}&purpose=tcp:open`);
  const open = await waitUntil('tcp_open', () => frames('tcp_open')[seen]);
  agent.ws.send(JSON.stringify({ type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } }));
  await waitUntil('tcp connected', () => tcp.box.frames.find((f) => f.type === 'tcp_status' && f.payload.status === 'connected'));
  const s = [...r.fm.tcp.sessions.values()].find((x) => x.id === open.session_id);
  assert.ok(s);
  return { tcp, s };
}

test('a policy write that lands while a renewal is in flight re-checks after it and ends the session', async () => {
  const r = await rig();
  try {
    const v0 = await version(r);
    const set = await call(r, 'PUT', P(), { body: { reason: 'open', if_version: v0, grants: { tcp_local: [5432] } } });
    assert.equal(set.status, 200, JSON.stringify(set.body));
    const agent = await connectAgent(r);
    const { tcp, s } = await liveTcp(r, agent);
    // The periodic renewal reads the (still open) policy, then stalls.
    const reg = r.fm.registry;
    const orig = reg.channelPolicies.bind(reg);
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    let armed = true;
    let stalled = false;
    reg.channelPolicies = async (id) => {
      const value = await orig(id);
      if (armed) {
        armed = false;
        stalled = true;
        await gate;
      }
      return value;
    };
    const periodic = r.fm.tcp.renew(s);
    await waitUntil('renewal stalled', () => stalled);
    const rows = policyRows(r).length;
    const clearing = call(r, 'POST', `${P()}/clear`, { body: { reason: 'close', if_version: set.body.version } });
    await waitUntil('clear written', () => policyRows(r).length === rows + 1);
    release();
    const cleared = await clearing;
    assert.equal(cleared.status, 200, JSON.stringify(cleared.body));
    assert.deepEqual([cleared.body.renewed, cleared.body.ended], [0, 1]);
    assert.equal(await periodic, 'ended');
    await waitUntil('tcp stopped', () => tcp.box.frames.find((f) => f.type === 'tcp_close' && f.payload.reason === 'stopped'));
  } finally {
    await r.close();
  }
});

test('a failed lookup ends a session on a policy renewal (fail closed) but only skips a periodic one', async () => {
  const r = await rig();
  try {
    const v0 = await version(r);
    const set = await call(r, 'PUT', P(), { body: { reason: 'open', if_version: v0, grants: { tcp_local: [5432] } } });
    assert.equal(set.status, 200, JSON.stringify(set.body));
    const agent = await connectAgent(r);
    const { tcp, s } = await liveTcp(r, agent);
    const reg = r.fm.registry;
    const orig = reg.channelPolicies.bind(reg);
    reg.channelPolicies = async () => { throw new Error('db down'); };
    assert.equal(await r.fm.tcp.renew(s), 'skipped');
    assert.equal(s.ended, false);
    const counts = await r.fm.renewPolicySessions((hostId) => hostId === HOST_A);
    assert.deepEqual(counts, { renewed: 0, ended: 1 });
    reg.channelPolicies = orig;
    await waitUntil('tcp stopped', () => tcp.box.frames.find((f) => f.type === 'tcp_close' && f.payload.reason === 'stopped'));
  } finally {
    await r.close();
  }
});

test('step-up device flow: a fresh code needs a fresh SSO session, never Google/GitHub, and its token carries auth_time', async () => {
  const r = await rig();
  try {
    const reg = r.fm.registry;
    const env = r.fm.env;
    const sessionUser = (authTime) => ({ id: SUB, auth_time: authTime });
    // A plain code gives a token with no auth_time, whatever the session.
    const plain = await oauth.startDevice(reg, 'user-1', env, {});
    await oauth.approveUserCode(reg, plain.user_code, sessionUser(nowS()));
    const plainToken = await oauth.pollToken(reg, plain.device_code, env);
    assert.equal((await oauth.userForAccessToken(reg, plainToken.access_token)).auth_time, null);
    // A fresh code with a stale session is refused, then approved fresh.
    const fresh = await oauth.startDevice(reg, 'user-1', env, {}, Date.now(), { fresh: true });
    await assert.rejects(oauth.approveUserCode(reg, fresh.user_code, sessionUser(nowS() - 400)), (err) => err.code === 'reauth_required');
    await assert.rejects(oauth.approveUserCode(reg, fresh.user_code, sessionUser(null)), (err) => err.code === 'reauth_required');
    const linkEnv = { ...env, SYSTEMAPI_OAUTH_GOOGLE_CLIENT_ID: 'id', SYSTEMAPI_OAUTH_GOOGLE_CLIENT_SECRET: 'secret' };
    await assert.rejects(oauth.beginExternal(reg, fresh.user_code, 'google', linkEnv, sessionUser(nowS())), (err) => err.code === 'link_denied');
    const at = nowS() - 5;
    await oauth.approveUserCode(reg, fresh.user_code, sessionUser(at));
    const freshToken = await oauth.pollToken(reg, fresh.device_code, env);
    assert.equal((await oauth.userForAccessToken(reg, freshToken.access_token)).auth_time, at);
    // The verify page sends a stale session to Authentik for a fresh code.
    const again = await oauth.startDevice(reg, 'user-1', env, {}, Date.now(), { fresh: true });
    const csrf = 'c'.repeat(43);
    const res = await call(r, 'POST', '/oauth/device/verify', { session: { user: sessionUser(nowS() - 400), csrf }, form: { csrf, user_code: again.user_code } });
    assert.equal(res.status, 303);
    assert.equal(res.location, '/oauth/login?fresh=1&return_to=%2Foauth%2Fdevice%2Fverify');
    // A fresh session sees the plain warning on the confirm page.
    const page = await call(r, 'POST', '/oauth/device/verify', { session: { user: sessionUser(nowS()), csrf }, form: { csrf, user_code: again.user_code } });
    assert.equal(page.status, 200);
    assert.match(page.body, /dangerous channel-policy changes/);
    // POST /oauth/device with fresh=1 starts a fresh code.
    const started = await call(r, 'POST', '/oauth/device', { key: null, form: { username: 'user-1', fresh: '1' } });
    assert.equal(started.status, 200);
    const row = await oauth.pendingByTypedCode(reg, started.body.user_code);
    assert.equal(row.row.fresh, true);
  } finally {
    await r.close();
  }
});

// cli/systemapi.js policy against the routes: the dry run first, then the
// write; a dangerous change only with --confirm-dangerous and a step-up token.
function runCli(r, args, env = {}) {
  const { spawn } = require('node:child_process');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [require('node:path').join(__dirname, '..', 'cli', 'systemapi.js'), ...args], {
      env: { PATH: process.env.PATH, SYSTEMAPI_URL: r.url, ...env }
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

test('cli policy: set, show, diff, dangerous refusal and --confirm-dangerous with a fresh token file, revert', async () => {
  const r = await rig();
  const fs = require('node:fs');
  const os = require('node:os');
  const dir = fs.mkdtempSync(require('node:path').join(os.tmpdir(), 'policy-cli-'));
  try {
    const key = { SYSTEMAPI_API_KEY: 'admin-key' };
    const set = await runCli(r, ['policy', 'set', '--host', HOST_A, '--reason', 'cli test', '--tcp-local', '22', '--file-read', '/srv/logs'], key);
    assert.equal(set.code, 0, set.err);
    const applied = JSON.parse(set.out);
    assert.equal(applied.action, 'channel_policy_set');
    const show = await runCli(r, ['policy', 'show', '--host', HOST_A], key);
    assert.deepEqual(JSON.parse(show.out).grants.tcp_local, [22]);
    const diff = await runCli(r, ['policy', 'diff', '--host', HOST_A, '--reason', 'x', '--package', 'curl'], key);
    assert.equal(diff.code, 0, diff.err);
    assert.deepEqual(JSON.parse(diff.out).dangerous, ['package:curl']);
    const refused = await runCli(r, ['policy', 'set', '--host', HOST_A, '--reason', 'x', '--package', 'curl'], key);
    assert.equal(refused.code, 1);
    assert.match(refused.err, /dangerous_unconfirmed/);
    const keyConfirm = await runCli(r, ['policy', 'set', '--host', HOST_A, '--reason', 'x', '--package', 'curl', '--confirm-dangerous'], key);
    assert.equal(keyConfirm.code, 1);
    assert.match(keyConfirm.err, /step_up_required: api_key/);
    const tokenFile = require('node:path').join(dir, 'token');
    fs.writeFileSync(tokenFile, await deviceToken(r, nowS()) + '\n', { mode: 0o600 });
    const ok = await runCli(r, ['policy', 'set', '--host', HOST_A, '--reason', 'x', '--package', 'curl', '--confirm-dangerous'], { SYSTEMAPI_TOKEN_FILE: tokenFile });
    assert.equal(ok.code, 0, ok.err);
    assert.deepEqual(JSON.parse(ok.out).dangerous, ['package:curl']);
    const revertDry = await runCli(r, ['policy', 'revert', '--host', HOST_A, '--audit-seq', String(applied.audit_seq), '--reason', 'undo'], key);
    assert.equal(revertDry.code, 0, revertDry.err);
    assert.equal(JSON.parse(revertDry.out).dry_run, true);
    const revert = await runCli(r, ['policy', 'revert', '--host', HOST_A, '--audit-seq', String(applied.audit_seq), '--reason', 'undo', '--apply'], key);
    assert.equal(revert.code, 0, revert.err);
    assert.equal((await call(r, 'GET', P())).body.host.tcp_policy, null);
    for (const bad of [['policy', 'set', '--host', HOST_A, '--tcp-local', '22'], ['policy', 'show'], ['policy', 'show', '--host', HOST_A, '--tenant', 'acme'],
      ['policy', 'clear', '--host', HOST_A, '--reason', 'r', '--service', 'x'], ['policy', 'revert', '--tenant', 'acme', '--audit-seq', '1', '--reason', 'r']]) {
      assert.equal((await runCli(r, bad, key)).code, 2, bad.join(' '));
    }
    for (const out of [set, show, diff, refused, ok]) assert.equal(`${out.out}${out.err}`.includes('admin-key'), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    await r.close();
  }
});

test('scripts/sahpolicy.py add is GET + PUT with if_version over the API and keeps every existing grant', async (t) => {
  const { spawnSync } = require('node:child_process');
  if (spawnSync('python3', ['--version']).status !== 0) {
    t.skip('python3 not installed');
    return;
  }
  const r = await rig();
  const { spawn } = require('node:child_process');
  const py = (args) => new Promise((resolve) => {
    const child = spawn('python3', [require('node:path').join(__dirname, '..', 'scripts', 'sahpolicy.py'), ...args], {
      env: { PATH: process.env.PATH, SYSTEMAPI_URL: r.url, SYSTEMAPI_API_KEY: 'admin-key' }
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => resolve({ code, out, err }));
  });
  try {
    const first = await py(['add', '--host', 'web1', '--reason', 'py', '--tcp-local', '22']);
    assert.equal(first.code, 0, first.err);
    const second = await py(['add', '--host', HOST_A, '--reason', 'py', '--file-read', '/srv/logs', '--tcp-local', '22']);
    assert.equal(second.code, 0, second.err);
    const got = (await call(r, 'GET', P())).body;
    assert.deepEqual(got.grants.tcp_local, [22]);
    assert.deepEqual(got.grants.file_read, ['/srv/logs']);
    const dangerous = await py(['add', '--host', 'web1', '--reason', 'py', '--package', 'curl']);
    assert.notEqual(dangerous.code, 0);
    assert.match(dangerous.err, /dangerous change/);
    assert.equal(`${first.out}${second.out}${dangerous.out}${dangerous.err}`.includes('admin-key'), false);
  } finally {
    await r.close();
  }
});
