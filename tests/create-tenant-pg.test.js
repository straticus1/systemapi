'use strict';

// scripts/create-tenant.js end to end against a real PostgreSQL: a fresh
// database per run, an admin made by bootstrapAdmin, then the CLI's main(),
// then the agent key used for enrollment and on control-plane routes. Needs
// SYSTEMAPI_TEST_DATABASE_URL (a role that may CREATE DATABASE); it fails,
// not skips, without it. Not part of npm test.
//
//   SYSTEMAPI_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres \
//     node --test tests/create-tenant-pg.test.js

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');

const { createRegistry, PgRegistry } = require('../controlplane/registry');
const { mount } = require('../controlplane/router');
const FleetManager = require('../playground/fleet');
const AuthManager = require('../playground/auth');
const { main } = require('../scripts/create-tenant');

const BASE = process.env.SYSTEMAPI_TEST_DATABASE_URL;
const DB = `create_tenant_${crypto.randomBytes(6).toString('hex')}`;
const ARGV = ['--tenant', 'afterdark-test', '--admin', 'ryan', '--agent-member', 'sahtest1-agent'];
let dbURL;

function withDatabase(url, name) {
  const u = new URL(url);
  u.pathname = `/${name}`;
  return u.toString();
}

test.before(async () => {
  assert.ok(BASE, 'SYSTEMAPI_TEST_DATABASE_URL is required for this test');
  const admin = new Pool({ connectionString: BASE });
  await admin.query(`CREATE DATABASE ${DB}`);
  await admin.end();
  dbURL = withDatabase(BASE, DB);
});

test.after(async () => {
  if (!BASE) return;
  const admin = new Pool({ connectionString: BASE });
  await admin.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
  await admin.end();
});

async function runCli(argv) {
  const saved = { ENV_FILE: process.env.ENV_FILE, DATABASE_URL: process.env.DATABASE_URL, DB_PASSWORD: process.env.DB_PASSWORD };
  process.env.ENV_FILE = '/dev/null';
  process.env.DATABASE_URL = dbURL;
  delete process.env.DB_PASSWORD;
  const out = [];
  const err = [];
  const realError = console.error;
  console.error = (...args) => err.push(args.join(' '));
  const stdout = { write(chunk) { out.push(String(chunk)); return true; } };
  const prevExit = process.exitCode;
  process.exitCode = undefined;
  try {
    await main(argv, stdout);
    return { out, err, exitCode: process.exitCode };
  } finally {
    process.exitCode = prevExit;
    console.error = realError;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

async function appWith(pool) {
  const registry = await createRegistry({ pool, env: { NODE_ENV: 'production' }, logger: { log() {}, warn() {}, error() {} } });
  assert.ok(registry instanceof PgRegistry);
  const keyStore = { db: pool, apiSite: 'systemapi', env: { NODE_ENV: 'production' } };
  const fleet = {
    env: { NODE_ENV: 'production' },
    db: pool,
    apiSite: 'systemapi',
    registry,
    tickets: new Map(),
    verifyApiKey: (key) => FleetManager.prototype.verifyApiKey.call(keyStore, key)
  };
  const app = express();
  app.use(express.json());
  mount(app, fleet);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  return { server, url: `http://127.0.0.1:${server.address().port}`, registry };
}

async function call(url, opts = {}) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch { /* text */ }
  return { status: res.status, body };
}

function enrollAs(registry, keyData, tenantId) {
  return registry.enroll({
    tenantId, userId: keyData.user_id, keyId: keyData.key_id, hostId: crypto.randomUUID(),
    hostname: 'sahtest1', os: 'linux', platform: 'amd64', sshPubkey: 'ssh-ed25519 AAAA test'
  });
}

test('create-tenant: an agent key that enrolls only into its tenant and reaches no API', async () => {
  const pool = new Pool({ connectionString: dbURL });
  const { server, url, registry } = await appWith(pool);
  try {
    // Before any admin exists the CLI is refused and prints no key.
    const early = await runCli(ARGV);
    assert.equal(early.exitCode, 1);
    assert.deepEqual(early.out, []);
    assert.ok(early.err.some((line) => line.includes('admin_required')), early.err.join('\n'));

    // The operator: admin of acme with an admin key.
    const keys = new AuthManager(null, null, null, 'systemapi', pool);
    const boot = await registry.bootstrapAdmin({
      tenantId: 'acme', userId: 'ryan', actor: 'bootstrap:admin',
      mintKey: (client) => keys.insertAPIKey(client, 'ryan', 'bootstrap-admin')
    });
    const adminKey = boot.key_secret;

    const first = await runCli(ARGV);
    assert.equal(first.exitCode, undefined, first.err.join('\n'));
    assert.equal(first.out.length, 1, 'stdout is written exactly once');
    const printed = JSON.parse(first.out[0]);
    const agentKey = printed.api_key;
    assert.match(agentKey, /^ak_live_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32}$/);
    const secretPart = agentKey.split('.')[1];
    assert.equal(first.err.join('').split(secretPart).length - 1, 0, 'the key went to stderr');

    // Database state.
    const keyRow = (await pool.query('SELECT user_id, tenant_id, key_hash FROM playground_api_keys WHERE key_id = $1', [printed.key_id])).rows;
    assert.deepEqual(keyRow.map((r) => [r.user_id, r.tenant_id]), [['sahtest1-agent', 'afterdark-test']]);
    assert.match(keyRow[0].key_hash, /^\$2[aby]\$10\$/);
    assert.deepEqual((await pool.query('SELECT scope FROM cp_api_scopes WHERE key_id = $1', [printed.key_id])).rows, []);
    assert.deepEqual(
      (await pool.query('SELECT tenant_id, user_id, role FROM cp_members ORDER BY tenant_id, user_id')).rows,
      [
        { tenant_id: 'acme', user_id: 'ryan', role: 'admin' },
        { tenant_id: 'afterdark-test', user_id: 'ryan', role: 'admin' },
        { tenant_id: 'afterdark-test', user_id: 'sahtest1-agent', role: 'viewer' }
      ]
    );
    const audit = (await pool.query("SELECT tenant_id, actor, payload FROM cp_audit WHERE action = 'tenant_create'")).rows;
    assert.equal(audit.length, 1);
    assert.equal(audit[0].tenant_id, 'afterdark-test');
    assert.equal(audit[0].actor, 'operator:create-tenant');
    assert.deepEqual(audit[0].payload.scopes, []);
    assert.equal((await registry.verifyAudit()).ok, true);
    const dump = JSON.stringify((await pool.query('SELECT * FROM cp_audit')).rows);
    assert.equal(dump.split(secretPart).length - 1, 0);

    // Enroll: into its own tenant, yes; into the operator's tenant or a new one, no.
    const keyData = await FleetManager.prototype.verifyApiKey.call({ db: pool, apiSite: 'systemapi', env: {} }, agentKey);
    assert.equal(keyData.tenant_id, 'afterdark-test', 'fleet sees the binding (key_tenant_mismatch elsewhere)');
    const host = await enrollAs(registry, keyData, 'afterdark-test');
    assert.equal(host.tenant_id, 'afterdark-test');
    await assert.rejects(enrollAs(registry, keyData, 'acme'), (err) => err.status === 403 && err.code === 'not_a_member');
    await assert.rejects(enrollAs(registry, keyData, 'brand-new'), (err) => err.status === 403 && err.code === 'tenant_create_denied');

    // API: no scopes in its tenant, invisible elsewhere.
    const agentHeaders = { 'x-api-key': agentKey };
    assert.equal((await call(`${url}/api/v1/fleet`, { headers: agentHeaders })).status, 403);
    assert.equal((await call(`${url}/api/v1/webhooks?tenant_id=afterdark-test`, { headers: agentHeaders })).status, 403);
    assert.equal((await call(`${url}/api/v1/webhooks?tenant_id=acme`, { headers: agentHeaders })).status, 404);

    // The operator administers the new tenant with the existing admin key.
    const admin = await call(`${url}/api/v1/webhooks?tenant_id=afterdark-test`, { headers: { 'x-api-key': adminKey } });
    assert.equal(admin.status, 200, JSON.stringify(admin.body));
    const fleet = await call(`${url}/api/v1/fleet`, { headers: { 'x-api-key': adminKey } });
    assert.equal(fleet.status, 200, JSON.stringify(fleet.body));
    assert.ok(fleet.body.hosts.some((h) => h.host_id === host.host_id));

    // /playground: the empty endpoint allowlist refuses the agent key on every
    // route the middleware checks (req.path), so it cannot mint sibling keys.
    const playgroundAuth = new AuthManager(null, null, null, 'systemapi', pool);
    for (const path of ['/api-keys', '/api-keys/' + printed.key_id + '/lock', '/execute', '/credits']) {
      assert.equal(await playgroundAuth.verifyAPIKey(printed.key_id, agentKey, null, path), null, path);
    }
    assert.equal(await playgroundAuth.verifyAPIKey(boot.key_id, adminKey, null, '/api-keys'), 'ryan', 'other keys unaffected');

    // Revoke: the agent key cannot revoke itself (no admin anywhere); the operator can.
    const self = await call(`${url}/api/v1/keys/${printed.key_id}/revoke`, { method: 'POST', headers: agentHeaders });
    assert.equal(self.status, 403);
    const revoked = await call(`${url}/api/v1/keys/${printed.key_id}/revoke`, { method: 'POST', headers: { 'x-api-key': adminKey } });
    assert.equal(revoked.status, 200, JSON.stringify(revoked.body));
    assert.equal(revoked.body.revoked, true);
    assert.equal(await registry.keyActive(printed.key_id), false);
    assert.equal(await FleetManager.prototype.verifyApiKey.call({ db: pool, apiSite: 'systemapi', env: {} }, agentKey), null);
    assert.equal((await call(`${url}/api/v1/fleet`, { headers: agentHeaders })).status, 403);
    const revokeAudit = (await pool.query("SELECT tenant_id, actor, payload FROM cp_audit WHERE action = 'key_revoked'")).rows;
    assert.equal(revokeAudit.length, 1);
    assert.equal(revokeAudit[0].tenant_id, 'afterdark-test');
    assert.equal(revokeAudit[0].actor, 'ryan');
    assert.equal(revokeAudit[0].payload.was_active, true);
    assert.equal((await registry.verifyAudit()).ok, true);

    // A would-be agent id that already holds a key is refused below.
    await keys.insertAPIKey(pool, 'stray-agent', 'stray');
  } finally {
    server.close();
    await pool.end();
  }

  // Re-runs: the tenant or the agent identity already exists, so nothing is minted.
  const again = await runCli(ARGV);
  assert.equal(again.exitCode, 1);
  assert.deepEqual(again.out, []);
  assert.ok(again.err.some((line) => line.includes('agent_member_exists')), again.err.join('\n'));
  const stray = await runCli(['--tenant', 'stray-tenant', '--admin', 'ryan', '--agent-member', 'stray-agent']);
  assert.equal(stray.exitCode, 1);
  assert.deepEqual(stray.out, []);
  assert.ok(stray.err.some((line) => line.includes('agent_identity_exists')), stray.err.join('\n'));
  const sameTenant = await runCli(['--tenant', 'afterdark-test', '--admin', 'ryan', '--agent-member', 'other-agent']);
  assert.equal(sameTenant.exitCode, 1);
  assert.ok(sameTenant.err.some((line) => line.includes('tenant_exists')), sameTenant.err.join('\n'));
  const check = new Pool({ connectionString: dbURL });
  try {
    assert.equal((await check.query("SELECT count(*)::int AS n FROM playground_api_keys WHERE user_id NOT IN ('ryan', 'stray-agent')")).rows[0].n, 1);
    assert.equal((await check.query("SELECT count(*)::int AS n FROM cp_tenants WHERE tenant_id = 'stray-tenant'")).rows[0].n, 0);
    assert.equal((await check.query("SELECT count(*)::int AS n FROM cp_members WHERE user_id = 'other-agent'")).rows[0].n, 0);
  } finally {
    await check.end();
  }
});
