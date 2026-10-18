'use strict';

// PgRegistry against a real PostgreSQL: the enroll upsert, and the fleet's
// agent-key lookup (expiry and the optional tenant binding), and the
// channel-policy CLI's single-transaction write. A fresh database per run with the schema applied by
// createRegistry. Needs SYSTEMAPI_TEST_DATABASE_URL (a role that may CREATE DATABASE); it fails,
// not skips, without it. Not part of npm test.
//
//   SYSTEMAPI_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres \
//     node --test tests/registry-pg.test.js

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const { createRegistry, PgRegistry } = require('../controlplane/registry');
const FleetManager = require('../playground/fleet');
const { run: policyRun } = require('../scripts/channel-policy');

const BASE = process.env.SYSTEMAPI_TEST_DATABASE_URL;
const DB = `registry_${crypto.randomBytes(6).toString('hex')}`;
const HOST_A = '11111111-1111-4111-8111-111111111111';
let pool;
let registry;

function withDatabase(url, name) {
  const u = new URL(url);
  u.pathname = `/${name}`;
  return u.toString();
}

function opensshEd25519(fill, comment = 'test@systemapi') {
  const name = Buffer.from('ssh-ed25519');
  const buf = Buffer.alloc(4 + name.length + 4 + 32);
  buf.writeUInt32BE(name.length, 0);
  name.copy(buf, 4);
  buf.writeUInt32BE(32, 4 + name.length);
  Buffer.alloc(32, fill).copy(buf, 4 + name.length + 4);
  return `ssh-ed25519 ${buf.toString('base64')} ${comment}`;
}

test.before(async () => {
  assert.ok(BASE, 'SYSTEMAPI_TEST_DATABASE_URL is required for this test');
  const admin = new Pool({ connectionString: BASE });
  await admin.query(`CREATE DATABASE ${DB}`);
  await admin.end();
  pool = new Pool({ connectionString: withDatabase(BASE, DB) });
  registry = await createRegistry({ pool, env: { NODE_ENV: 'production' }, logger: { log() {}, warn() {}, error() {} } });
  assert.ok(registry instanceof PgRegistry);
});

test.after(async () => {
  if (pool) await pool.end();
  if (!BASE) return;
  const admin = new Pool({ connectionString: BASE });
  await admin.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
  await admin.end();
});

test('a re-enroll with the same key and host id but another SSH key is refused and the row is unchanged', async () => {
  const pub = opensshEd25519(3);
  const base = { tenantId: 'acme', userId: 'user-1', keyId: 'k1', hostId: HOST_A, os: 'linux', platform: 'amd64' };
  await registry.enroll({ ...base, hostname: 'a.example', sshPubkey: pub });
  const row = async () => (await pool.query('SELECT hostname, ssh_pubkey, key_id, tenant_id FROM cp_hosts WHERE host_id = $1', [HOST_A])).rows[0];
  const before = await row();
  await assert.rejects(
    () => registry.enroll({ ...base, hostname: 'evil.example', sshPubkey: opensshEd25519(4) }),
    (err) => err.code === 'host_key_mismatch' && err.status === 403
  );
  assert.deepEqual(await row(), before);
  // Another key id is still host_steal.
  await assert.rejects(
    () => registry.enroll({ ...base, keyId: 'k2', hostname: 'a.example', sshPubkey: pub }),
    (err) => err.code === 'host_steal'
  );
  // The same key reconnects (a changed comment included); the stored line stays.
  const again = await registry.enroll({ ...base, hostname: 'a.example', sshPubkey: opensshEd25519(3, 'renamed@host') });
  assert.equal(again.ssh_pubkey, pub);
  assert.equal(again.status, 'online');
});

test('fleet.verifyApiKey refuses an expired key and accepts an unexpired one', async () => {
  const fleet = { db: pool, apiSite: 'systemapi', env: { NODE_ENV: 'production' } };
  const add = async (keyId, secret, expiresIn) => pool.query(
    `INSERT INTO playground_api_keys (key_id, key_hash, user_id, name, api_site, expires_at)
     VALUES ($1, $2, 'user-1', 'agent', 'systemapi', CURRENT_TIMESTAMP + $3::interval)`,
    [keyId, await bcrypt.hash(secret, 4), expiresIn]
  );
  await add('ak_live_pgexpired', 'ak_live_pgexpired.s1', '-1 minute');
  await add('ak_live_pgcurrent', 'ak_live_pgcurrent.s2', '1 hour');
  await add('ak_live_pgnoexpiry', 'ak_live_pgnoexpiry.s3', null);
  assert.equal(await FleetManager.prototype.verifyApiKey.call(fleet, 'ak_live_pgexpired.s1'), null);
  assert.equal((await FleetManager.prototype.verifyApiKey.call(fleet, 'ak_live_pgcurrent.s2')).key_id, 'ak_live_pgcurrent');
  assert.equal((await FleetManager.prototype.verifyApiKey.call(fleet, 'ak_live_pgnoexpiry.s3')).key_id, 'ak_live_pgnoexpiry');
});

test('fleet.verifyApiKey returns the key\'s tenant binding, null when unset', async () => {
  const fleet = { db: pool, apiSite: 'systemapi', env: { NODE_ENV: 'production' } };
  await pool.query(
    `INSERT INTO playground_api_keys (key_id, key_hash, user_id, name, api_site, tenant_id)
     VALUES ($1, $2, 'user-1', 'agent', 'systemapi', $3)`,
    ['ak_live_pgbound', await bcrypt.hash('ak_live_pgbound.s4', 4), 'acme']
  );
  assert.equal((await FleetManager.prototype.verifyApiKey.call(fleet, 'ak_live_pgbound.s4')).tenant_id, 'acme');
  assert.equal((await FleetManager.prototype.verifyApiKey.call(fleet, 'ak_live_pgnoexpiry.s3')).tenant_id, null);
});

test('channel-policy writes the host policy and its audit row together, or neither', async () => {
  const HOST_P = '44444444-4444-4444-8444-444444444444';
  await registry.enroll({ tenantId: 'acme', userId: 'user-1', keyId: 'k1', hostId: HOST_P, hostname: 'p.example', os: '', platform: '', sshPubkey: opensshEd25519(5) });
  const audits = async () => (await pool.query("SELECT count(*)::int AS n FROM cp_audit WHERE actor = 'cli:channel-policy'")).rows[0].n;
  const cols = async () => (await pool.query('SELECT tcp_policy, file_policy FROM cp_hosts WHERE host_id = $1', [HOST_P])).rows[0];
  const set = ['set', '--tenant', 'acme', '--host', HOST_P, '--reason', 'pg test', '--tcp-local', '3003'];
  await policyRun(set, { registry });
  assert.deepEqual((await cols()).tcp_policy, { allow: [{ local: true, ports: [3003] }] });
  assert.equal(await audits(), 1);
  const audit = (await pool.query("SELECT payload FROM cp_audit WHERE actor = 'cli:channel-policy'")).rows[0];
  assert.equal(audit.payload.reason, 'pg test');
  assert.equal((await registry.verifyAudit()).ok, true);

  await pool.query(`CREATE FUNCTION test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit refused by test'; END $$`);
  await pool.query('CREATE TRIGGER test_refuse_audit BEFORE INSERT ON cp_audit FOR EACH ROW EXECUTE FUNCTION test_refuse_audit()');
  try {
    await assert.rejects(policyRun(['clear', '--tenant', 'acme', '--host', HOST_P, '--reason', 'pg test'], { registry }),
      (err) => err.code === 'write_failed');
  } finally {
    await pool.query('DROP TRIGGER test_refuse_audit ON cp_audit');
    await pool.query('DROP FUNCTION test_refuse_audit()');
  }
  assert.deepEqual((await cols()).tcp_policy, { allow: [{ local: true, ports: [3003] }] }, 'the policy rolled back with its audit row');
  assert.equal(await audits(), 1);
});

test('channel-policy main() against the database prints the summary and never the credentials', async () => {
  const { main } = require('../scripts/channel-policy');
  const secret = 'pg-secret-not-real';
  const u = new URL(withDatabase(BASE, DB));
  u.password = secret;
  const keys = ['ENV_FILE', 'DATABASE_URL', 'DB_PASSWORD'];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.ENV_FILE = '/dev/null';
  process.env.DATABASE_URL = u.toString();
  delete process.env.DB_PASSWORD;
  const out = [];
  const err = [];
  const realError = console.error;
  console.error = (...args) => err.push(args.join(' '));
  const prevExit = process.exitCode;
  process.exitCode = undefined;
  try {
    await main(['show', '--tenant', 'acme', '--host', HOST_A], { write(c) { out.push(String(c)); return true; } });
    assert.equal(process.exitCode, undefined, err.join('\n'));
  } finally {
    process.exitCode = prevExit;
    console.error = realError;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  const summary = JSON.parse(out.join(''));
  assert.equal(summary.host_id, HOST_A);
  assert.equal(out.join('').includes(secret), false);
  assert.equal(err.join('').includes(secret), false);
});

test('retireHost stamps retired_at with its host_retired row, or neither; a retired row is hidden and cannot re-enroll', async () => {
  const OLD = '55555555-5555-4555-8555-555555555555';
  const NEW = '66666666-6666-4666-8666-666666666666';
  const base = { tenantId: 'acme', userId: 'user-1', keyId: 'k1', os: '', platform: '' };
  await registry.enroll({ ...base, hostId: OLD, hostname: 'r.example', sshPubkey: opensshEd25519(6) });
  await registry.enroll({ ...base, hostId: NEW, hostname: 'r.example', sshPubkey: opensshEd25519(7) });
  const retiredRows = async () => (await pool.query("SELECT count(*)::int AS n FROM cp_audit WHERE action = 'host_retired'")).rows[0].n;

  await assert.rejects(registry.retireHost({ tenantId: 'other', hostId: OLD, actor: 'u', reason: 'x' }), (err) => err.status === 404);
  await assert.rejects(registry.retireHost({ tenantId: 'acme', hostId: OLD, actor: 'u', reason: ' ' }), (err) => err.code === 'reason_required');

  await pool.query(`CREATE FUNCTION test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit refused by test'; END $$`);
  await pool.query('CREATE TRIGGER test_refuse_audit BEFORE INSERT ON cp_audit FOR EACH ROW EXECUTE FUNCTION test_refuse_audit()');
  try {
    await assert.rejects(registry.retireHost({ tenantId: 'acme', hostId: OLD, actor: 'u', reason: 'x' }), /audit refused/);
  } finally {
    await pool.query('DROP TRIGGER test_refuse_audit ON cp_audit');
    await pool.query('DROP FUNCTION test_refuse_audit()');
  }
  assert.equal((await pool.query('SELECT retired_at FROM cp_hosts WHERE host_id = $1', [OLD])).rows[0].retired_at, null);
  assert.equal(await retiredRows(), 0);

  const row = await registry.retireHost({ tenantId: 'acme', hostId: OLD, actor: 'user-1', reason: 're-enrolled', forced: false });
  assert.ok(row.retired_at instanceof Date);
  assert.equal(row.status, 'offline');
  assert.equal(await retiredRows(), 1);
  const audit = (await pool.query("SELECT tenant_id, host_id, actor, payload FROM cp_audit WHERE action = 'host_retired'")).rows[0];
  assert.match(audit.payload.last_seen_at, /^\d{4}-\d\d-\d\dT[\d:.]+Z$/);
  assert.deepEqual({ ...audit, payload: { ...audit.payload, last_seen_at: 'x' } },
    { tenant_id: 'acme', host_id: OLD, actor: 'user-1', payload: { reason: 're-enrolled', hostname: 'r.example', forced: false, last_seen_at: 'x' } });
  assert.equal((await registry.verifyAudit()).ok, true);
  await assert.rejects(registry.retireHost({ tenantId: 'acme', hostId: OLD, actor: 'u', reason: 'x' }), (err) => err.code === 'already_retired');

  assert.deepEqual((await registry.resolveHosts(['acme'], 'r.example')).map((h) => h.host_id), [NEW]);
  assert.deepEqual(await registry.resolveHosts(['acme'], OLD), []);
  assert.equal(await registry.channelPolicies(OLD), null);
  const ids = (await registry.listHosts(['acme'])).map((h) => h.host_id);
  assert.ok(!ids.includes(OLD) && ids.includes(NEW));
  assert.ok((await registry.listHosts(['acme'], null, { includeRetired: true })).some((h) => h.host_id === OLD));
  assert.ok((await registry.getHost(['acme'], OLD)).retired_at);
  await assert.rejects(registry.enroll({ ...base, hostId: OLD, hostname: 'r.example', sshPubkey: opensshEd25519(6) }),
    (err) => err.code === 'host_retired');
});
