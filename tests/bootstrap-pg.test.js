'use strict';

// scripts/bootstrap-admin.js end to end against a real PostgreSQL: a fresh
// database per run, the schema applied by createRegistry, the CLI's main(),
// then the minted key used on admin-only control-plane routes and for an
// agent enrollment. Needs SYSTEMAPI_TEST_DATABASE_URL (a role that may
// CREATE DATABASE); it fails, not skips, without it. Not part of npm test.
//
//   SYSTEMAPI_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres \
//     node --test tests/bootstrap-pg.test.js

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const express = require('express');
const { Pool } = require('pg');

const { createRegistry, PgRegistry } = require('../controlplane/registry');
const { mount } = require('../controlplane/router');
const FleetManager = require('../playground/fleet');
const AuthManager = require('../playground/auth');
const { main } = require('../scripts/bootstrap-admin');

const BASE = process.env.SYSTEMAPI_TEST_DATABASE_URL;
const SUB = 'f3a9c1d2e4b5a6978877665544332211aabbccddeeff00112233445566778899';
const DB = `bootstrap_${crypto.randomBytes(6).toString('hex')}`;
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

// Runs main() in-process with stdout and stderr captured and every fs write
// entry point trapped, so the test sees each place the key could go.
async function runCli(argv) {
  const saved = { ENV_FILE: process.env.ENV_FILE, DATABASE_URL: process.env.DATABASE_URL, DB_PASSWORD: process.env.DB_PASSWORD };
  process.env.ENV_FILE = '/dev/null';
  process.env.DATABASE_URL = dbURL;
  delete process.env.DB_PASSWORD;
  const out = [];
  const err = [];
  const fsWrites = [];
  const trapped = ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'writeSync', 'write'];
  const originals = Object.fromEntries(trapped.map((name) => [name, fs[name]]));
  const promiseOriginals = { writeFile: fs.promises.writeFile, appendFile: fs.promises.appendFile };
  for (const name of trapped) {
    fs[name] = function trap(...args) {
      fsWrites.push({ name, args: args.map(String) });
      return originals[name].apply(this, args);
    };
  }
  for (const name of Object.keys(promiseOriginals)) {
    fs.promises[name] = function trap(...args) {
      fsWrites.push({ name: `promises.${name}`, args: args.map(String) });
      return promiseOriginals[name].apply(this, args);
    };
  }
  const realError = console.error;
  console.error = (...args) => err.push(args.join(' '));
  const stdout = { write(chunk) { out.push(String(chunk)); return true; } };
  const prevExit = process.exitCode;
  process.exitCode = undefined;
  try {
    await main(argv, stdout);
    return { out, err, fsWrites, exitCode: process.exitCode };
  } finally {
    process.exitCode = prevExit;
    console.error = realError;
    for (const name of trapped) fs[name] = originals[name];
    for (const name of Object.keys(promiseOriginals)) fs.promises[name] = promiseOriginals[name];
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

function occurrences(haystack, needle) {
  return haystack.split(needle).length - 1;
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
  return { server, url: `http://127.0.0.1:${server.address().port}`, registry, fleet };
}

async function call(url, opts = {}) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch { /* text */ }
  return { status: res.status, body };
}

test('bootstrap on an empty database, then the key works on admin routes; a rerun is refused', async () => {
  const first = await runCli(['--tenant', 'acme', '--member', 'ryan', '--email', 'ryan@example.com', '--sso-sub', SUB]);
  assert.equal(first.exitCode, undefined, first.err.join('\n'));
  assert.equal(first.out.length, 1, 'stdout is written exactly once');
  const printed = JSON.parse(first.out[0]);
  const apiKey = printed.api_key;
  assert.match(apiKey, /^ak_live_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32}$/);
  assert.equal(printed.tenant_id, 'acme');
  assert.equal(printed.user_id, 'ryan');
  assert.equal(printed.sso_bound, true);
  assert.equal(printed.forced, false);
  // The key appears once in everything the process printed, and in no file write.
  assert.equal(occurrences(first.out.join('') + first.err.join(''), apiKey), 1);
  const secretPart = apiKey.split('.')[1];
  assert.equal(occurrences(first.err.join(''), secretPart), 0);
  for (const w of first.fsWrites) assert.ok(!w.args.some((a) => a.includes(secretPart)), `fs.${w.name} carried the key`);

  const pool = new Pool({ connectionString: dbURL });
  const { server, url, registry } = await appWith(pool);
  try {
    // Database state: only a bcrypt hash, an admin scope, an admin member bound to the sub.
    const keyRow = (await pool.query('SELECT key_id, key_hash, user_id, api_site, is_active FROM playground_api_keys')).rows;
    assert.equal(keyRow.length, 1);
    assert.equal(keyRow[0].key_id, printed.key_id);
    assert.match(keyRow[0].key_hash, /^\$2[aby]\$10\$/);
    assert.deepEqual((await pool.query('SELECT key_id, scope FROM cp_api_scopes')).rows, [{ key_id: printed.key_id, scope: 'admin' }]);
    assert.deepEqual((await pool.query('SELECT tenant_id, user_id, role, sso_sub FROM cp_members')).rows,
      [{ tenant_id: 'acme', user_id: 'ryan', role: 'admin', sso_sub: SUB }]);
    const audit = (await pool.query('SELECT actor, action, payload FROM cp_audit ORDER BY seq')).rows;
    assert.deepEqual(audit.map((r) => [r.actor, r.action]), [['bootstrap:admin', 'bootstrap_admin'], ['bootstrap:admin', 'sso_bind']]);
    assert.equal((await registry.verifyAudit()).ok, true);
    const dump = JSON.stringify((await pool.query('SELECT * FROM cp_audit')).rows) + JSON.stringify(keyRow);
    assert.equal(occurrences(dump, secretPart), 0);

    // Admin-only routes accept the key.
    const headers = { 'x-api-key': apiKey, 'content-type': 'application/json' };
    const hooks = await call(`${url}/api/v1/webhooks?tenant_id=acme`, { headers });
    assert.equal(hooks.status, 200, JSON.stringify(hooks.body));
    const member = await call(`${url}/api/v1/tenants/acme/members`, {
      method: 'POST', headers, body: JSON.stringify({ user_id: 'alice', role: 'operator' })
    });
    assert.equal(member.status, 201, JSON.stringify(member.body));
    const scopes = await call(`${url}/api/v1/keys/${printed.key_id}/scopes`, {
      method: 'POST', headers, body: JSON.stringify({ scopes: ['admin'] })
    });
    assert.equal(scopes.status, 200, JSON.stringify(scopes.body));
    const bind = await call(`${url}/api/v1/tenants/acme/members/alice/sso`, {
      method: 'PUT', headers, body: JSON.stringify({ sso_sub: 'a'.repeat(64) })
    });
    assert.equal(bind.status, 200, JSON.stringify(bind.body));
    // Bearer works too (the CLI and agents send the key as a bearer).
    const bearer = await call(`${url}/api/v1/webhooks?tenant_id=acme`, { headers: { authorization: `Bearer ${apiKey}` } });
    assert.equal(bearer.status, 200);

    // A wrong key and a tampered key are refused by the control plane (403
    // forbidden, its existing code for an unknown key) and by the playground
    // key check (null, which /playground answers with 401).
    const wrong = `${printed.key_id}.${'x'.repeat(32)}`;
    for (const bad of [wrong, apiKey.slice(0, -1) + (apiKey.endsWith('A') ? 'B' : 'A'), 'ak_live_nope.nope']) {
      const res = await call(`${url}/api/v1/webhooks?tenant_id=acme`, { headers: { 'x-api-key': bad } });
      assert.equal(res.status, 403);
      const auth = new AuthManager(null, null, null, 'systemapi', pool);
      assert.equal(await auth.verifyAPIKey(bad.split('.')[0], bad), null);
    }
    const noKey = await call(`${url}/api/v1/webhooks?tenant_id=acme`);
    assert.equal(noKey.status, 401);
    const auth = new AuthManager(null, null, null, 'systemapi', pool);
    assert.equal(await auth.verifyAPIKey(printed.key_id, apiKey), 'ryan');

    // An agent with this key can enroll into the tenant.
    const keyData = await FleetManager.prototype.verifyApiKey.call({ db: pool, apiSite: 'systemapi', env: {} }, apiKey);
    const host = await registry.enroll({
      tenantId: 'acme', userId: keyData.user_id, keyId: keyData.key_id, hostId: crypto.randomUUID(),
      hostname: 'h1.example', os: 'linux', platform: 'amd64', sshPubkey: 'ssh-ed25519 AAAA test'
    });
    assert.equal(host.tenant_id, 'acme');
  } finally {
    server.close();
    await pool.end();
  }

  // A second bootstrap without the flag is refused and prints no key.
  const second = await runCli(['--tenant', 'acme', '--member', 'ryan']);
  assert.equal(second.exitCode, 1);
  assert.deepEqual(second.out, []);
  assert.ok(second.err.some((line) => line.includes('admin_exists')), second.err.join('\n'));

  // With the flag it mints another, and the audit chain says so.
  const forced = await runCli(['--tenant', 'acme', '--member', 'ops', '--force-additional']);
  assert.equal(forced.exitCode, undefined, forced.err.join('\n'));
  assert.equal(forced.out.length, 1);
  assert.equal(JSON.parse(forced.out[0]).forced, true);
  const check = new Pool({ connectionString: dbURL });
  try {
    const last = (await check.query("SELECT payload FROM cp_audit WHERE action = 'bootstrap_admin' ORDER BY seq DESC LIMIT 1")).rows[0];
    assert.equal(last.payload.forced, true);
    assert.equal(last.payload.existing_admin_members, 1);
    assert.equal((await check.query("SELECT count(*)::int AS n FROM cp_api_scopes WHERE scope = 'admin'")).rows[0].n, 2);
  } finally {
    await check.end();
  }
});
