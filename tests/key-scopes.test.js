'use strict';

// POST /api/v1/keys/:keyId/scopes: only an admin of a tenant the key's owner
// belongs to may set a key's scopes, and every change writes an audit row
// with the previous scopes in the same step (a failed audit leaves the scopes
// as they were).

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
// API key -> the key row the fake verifyApiKey returns.
const KEYS = {
  'admin-acme': { key_id: 'k-admin', user_id: 'user-1' },
  'op-acme': { key_id: 'k-op', user_id: 'user-3' }
};
// key_id -> owner user id (lookupKeyOwner reads playground_api_keys).
const OWNERS = { 'k-admin': 'user-1', 'k-op': 'user-3', 'k-beta': 'user-2', 'k-self-op': 'user-3' };

async function rig() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test' };
  const key = privateKeyFromSeed(TEST_SEED);
  fm.signer = buildSigner(key, rawPublicKey(key));
  fm.tickets = new Map();
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.verifyApiKey = async (k) => KEYS[k] || null;
  fm.db = { async query(sql, params) { return { rows: OWNERS[params[0]] ? [{ user_id: OWNERS[params[0]] }] : [] }; } };
  mount(app, fm);
  const reg = fm.registry;
  await reg.enroll({ tenantId: 'acme', userId: 'user-1', keyId: 'k1', hostId: HOST_A, hostname: 'a', os: 'linux', platform: 'amd64', sshPubkey: null });
  await reg.enroll({ tenantId: 'beta', userId: 'user-2', keyId: 'k2', hostId: HOST_B, hostname: 'b', os: 'linux', platform: 'amd64', sshPubkey: null });
  await reg.addMember('beta', 'user-1', 'operator', null);
  await reg.addMember('acme', 'user-3', 'operator', null);
  await reg.setScopes('k-admin', ['admin']);
  await reg.setScopes('k-op', ['hosts:read']);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const post = (apiKey, keyId, body) => fetch(`${url}/api/v1/keys/${keyId}/scopes`, {
    method: 'POST', headers: { 'x-api-key': apiKey, 'content-type': 'application/json' }, body: JSON.stringify(body)
  }).then(async (res) => ({ status: res.status, body: await res.json() }));
  post.url = url;
  return { fm, reg, post, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}

const scopeAudits = (reg) => reg.audit.filter((a) => a.action === 'key_scopes_set');

test('an admin sets the scopes of a key owned by a member of their tenant, audited with the previous set', async () => {
  const r = await rig();
  try {
    const out = await r.post('admin-acme', 'k-op', { scopes: ['hosts:read', 'exec:run', 'exec:run'] });
    assert.equal(out.status, 200, JSON.stringify(out.body));
    assert.deepEqual(out.body.scopes, ['hosts:read', 'exec:run'], 'deduplicated');
    assert.deepEqual([...(await r.reg.scopes.get('k-op'))].sort(), ['exec:run', 'hosts:read']);
    const rows = scopeAudits(r.reg);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tenant_id, 'acme');
    assert.equal(rows[0].actor, 'user-1');
    assert.deepEqual(rows[0].payload, { key_id: 'k-op', scopes: ['exec:run', 'hosts:read'], previous_scopes: ['hosts:read'], tenants: ['acme'] });
    assert.equal((await r.reg.verifyAudit()).ok, true);
  } finally { await r.close(); }
});

test('an admin elsewhere who only shares a non-admin tenant with the owner gets 404 and changes nothing', async () => {
  const r = await rig();
  try {
    // user-1 is admin of acme and only an operator in beta; k-beta's owner is only in beta.
    const out = await r.post('admin-acme', 'k-beta', { scopes: ['admin'] });
    assert.equal(out.status, 404);
    assert.equal(r.reg.scopes.has('k-beta'), false);
    assert.equal(scopeAudits(r.reg).length, 0);
  } finally { await r.close(); }
});

test('an owner in two tenants needs an admin of both: admin of one only gets 404', async () => {
  const r = await rig();
  try {
    await r.reg.addMember('beta', 'user-3', 'operator', null); // k-op's owner is now in acme and beta
    assert.equal((await r.post('admin-acme', 'k-op', { scopes: ['exec:run'] })).status, 404);
    assert.deepEqual(r.reg.scopes.get('k-op'), ['hosts:read']);
    await r.reg.addMember('beta', 'user-1', 'admin', null); // now admin of both
    const ok = await r.post('admin-acme', 'k-op', { scopes: ['exec:run'] });
    assert.equal(ok.status, 200);
    assert.deepEqual(scopeAudits(r.reg).at(-1).payload.tenants, ['acme', 'beta']);
  } finally { await r.close(); }
});

test('a non-admin is refused, even for their own key; unknown keys and bad scopes change nothing', async () => {
  const r = await rig();
  try {
    assert.equal((await r.post('op-acme', 'k-self-op', { scopes: ['admin'] })).status, 403);
    assert.equal((await r.post('admin-acme', 'k-nobody', { scopes: ['hosts:read'] })).status, 404);
    for (const scopes of [['root'], 'admin', [7], null]) {
      assert.equal((await r.post('admin-acme', 'k-op', { scopes })).status, 400, JSON.stringify(scopes));
    }
    assert.deepEqual(r.reg.scopes.get('k-op'), ['hosts:read']);
    assert.equal(scopeAudits(r.reg).length, 0);
  } finally { await r.close(); }
});

test('if the audit row cannot be written, the scopes stay as they were', async () => {
  const r = await rig();
  try {
    r.reg.appendAudit = async () => { throw new Error('audit down'); };
    const out = await r.post('admin-acme', 'k-op', { scopes: ['admin'] });
    assert.equal(out.status, 500);
    assert.deepEqual(r.reg.scopes.get('k-op'), ['hosts:read']);
  } finally { await r.close(); }
});

// POST /api/v1/keys/:keyId/revoke: the same owner-tenant rule, the key
// deactivated and audited, live agents on it closed.
test('revoke: an admin of every owner tenant revokes the key, audited, and agents on it are closed', async () => {
  const r = await rig();
  try {
    const closed = [];
    r.fm.closeAgentsForKey = async (keyId, reason, actor) => { closed.push([keyId, reason, actor]); return 1; };
    const url = r.post.url;
    const out = await fetch(`${url}/api/v1/keys/k-op/revoke`, { method: 'POST', headers: { 'x-api-key': 'admin-acme' } })
      .then(async (res) => ({ status: res.status, body: await res.json() }));
    assert.equal(out.status, 200, JSON.stringify(out.body));
    assert.deepEqual(out.body, { key_id: 'k-op', revoked: true, agents_closed: 1 });
    assert.equal(await r.reg.keyActive('k-op'), false);
    assert.deepEqual(closed, [['k-op', 'admin_revoked', 'user-1']]);
    const rows = r.reg.audit.filter((a) => a.action === 'key_revoked');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tenant_id, 'acme');
    assert.equal(rows[0].payload.was_active, true);
    assert.equal(rows[0].payload.owner_tenant_count, 1);
    assert.equal('tenants' in rows[0].payload, false);
    assert.ok(!JSON.stringify(rows[0]).includes('"k-op"'), 'the audit row names the key by fingerprint');
    assert.equal((await r.reg.verifyAudit()).ok, true);
    // A second revoke is still audited, with was_active false.
    const again = await fetch(`${url}/api/v1/keys/k-op/revoke`, { method: 'POST', headers: { 'x-api-key': 'admin-acme' } });
    assert.equal(again.status, 200);
    const all = r.reg.audit.filter((a) => a.action === 'key_revoked');
    assert.deepEqual(all.map((a) => a.payload.was_active), [true, false]);
  } finally { await r.close(); }
});

test('revoke: refused (404) for an admin who does not administer every owner tenant, and for an unknown key; 403 with no admin anywhere', async () => {
  const r = await rig();
  try {
    const url = r.post.url;
    const call = (apiKey, keyId) => fetch(`${url}/api/v1/keys/${keyId}/revoke`, { method: 'POST', headers: { 'x-api-key': apiKey } }).then((res) => res.status);
    assert.equal(await call('admin-acme', 'k-beta'), 404);
    assert.equal(await call('admin-acme', 'k-nope'), 404);
    assert.equal(await call('op-acme', 'k-self-op'), 403);
    assert.equal(await r.reg.keyActive('k-beta'), true);
    assert.equal(r.reg.audit.filter((a) => a.action === 'key_revoked').length, 0);
  } finally { await r.close(); }
});

// The owner's memberships are read inside the revoke itself, not before it:
// an owner who joins a tenant the admin does not administer after the
// route looked the key up is refused, and the key stays active.
test('revoke: a membership the owner gains after the key lookup is seen by the revoke (404, key active, no audit row)', async () => {
  const r = await rig();
  try {
    const lookup = r.fm.db.query;
    r.fm.db.query = async (sql, params) => {
      const out = await lookup(sql, params);
      await r.reg.addMember('beta', 'user-3', 'viewer', null); // lands between lookup and revoke
      return out;
    };
    const res = await fetch(`${r.post.url}/api/v1/keys/k-op/revoke`, { method: 'POST', headers: { 'x-api-key': 'admin-acme' } });
    assert.equal(res.status, 404);
    assert.equal(await r.reg.keyActive('k-op'), true);
    assert.equal(r.reg.audit.filter((a) => a.action === 'key_revoked').length, 0);
  } finally { await r.close(); }
});

// Threats: the revoke row lives in one tenant's audit, readable by that
// tenant's members; it must not name the owner's other tenants.
test('revoke: the audit row of a key whose owner is in two tenants names neither the other tenant nor the key id', async () => {
  const r = await rig();
  try {
    await r.reg.addMember('beta', 'user-1', 'admin', null); // admin of acme and beta
    await r.reg.addMember('beta', 'user-3', 'viewer', null); // k-op's owner now in both
    const res = await fetch(`${r.post.url}/api/v1/keys/k-op/revoke`, { method: 'POST', headers: { 'x-api-key': 'admin-acme' } });
    assert.equal(res.status, 200);
    const rows = r.reg.audit.filter((a) => a.action === 'key_revoked');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tenant_id, 'acme');
    assert.equal(rows[0].payload.owner_tenant_count, 2);
    const text = JSON.stringify(rows[0]);
    assert.ok(!text.includes('beta'), text);
    assert.ok(!text.includes('"k-op"'), text);
    // An acme member reading acme's audit sees no beta row either.
    assert.equal((await r.reg.listAudit(['acme'], 100)).some((a) => JSON.stringify(a).includes('beta')), false);
  } finally { await r.close(); }
});
