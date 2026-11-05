'use strict';

// PgRegistry against a real PostgreSQL: the enroll upsert, and the fleet's
// agent-key lookup (expiry and the optional tenant binding), and the
// channel-policy CLI's single-transaction write, and the sysscript job methods (cross-tenant
// getJob/listJobs/requestJobCancel/transitionJob, atomic caps, NOTIFY only after COMMIT, a
// two-registry dispatch claim, and two FleetManagers dispatching, waiting and cancelling across
// instances through LISTEN/NOTIFY), and audit checkpoints (one per interval across registries, verified
// over a read-only connection). A fresh database per run with the schema applied by
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
const listeners = [];

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
  for (const r of listeners) await r.closeJobEvents();
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
  await pool.query(
    `INSERT INTO playground_api_keys (key_id, key_hash, user_id, name, api_site)
     VALUES ($1, $2, 'user-1', 'agent', 'systemapi')`,
    ['ak_live_pgunbound', await bcrypt.hash('ak_live_pgunbound.s5', 4)]
  );
  assert.equal((await FleetManager.prototype.verifyApiKey.call(fleet, 'ak_live_pgbound.s4')).tenant_id, 'acme');
  assert.equal((await FleetManager.prototype.verifyApiKey.call(fleet, 'ak_live_pgunbound.s5')).tenant_id, null);
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
  // Its own host row, so the test does not depend on the enroll test running first.
  await registry.enroll({ tenantId: 'acme', userId: 'user-1', keyId: 'k1', hostId: HOST_A, hostname: 'a.example', os: 'linux', platform: 'amd64', sshPubkey: opensshEd25519(3) });
  // With a password in SYSTEMAPI_TEST_DATABASE_URL (npm run test:pg) the real
  // one is the secret that must not be printed; a trust-auth server takes any.
  const u = new URL(withDatabase(BASE, DB));
  if (!u.password) u.password = 'pg-secret-not-real';
  const secret = decodeURIComponent(u.password);
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

// --- sysscript jobs -------------------------------------------------------
// Every job test enrolls its own tenants, members and hosts (world()), and
// asserts only on its own rows, so the tests do not depend on their order.

async function world(n = 2) {
  const tag = crypto.randomBytes(4).toString('hex');
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const tenant = `t${tag}${i}`;
    const user = `u${tag}${i}`;
    const hosts = [crypto.randomUUID(), crypto.randomUUID()];
    for (const [j, hostId] of hosts.entries()) {
      await registry.enroll({ tenantId: tenant, userId: user, keyId: `k${tag}${i}`, hostId, hostname: `h${j}.${tenant}.example`, os: '', platform: '', sshPubkey: opensshEd25519(20 + j) });
    }
    out.push({ tenant, user, hosts });
  }
  return out;
}

function jobId() {
  return `sjb_${crypto.randomBytes(16).toString('base64url')}`;
}

function jobRow(t, hostIdx = 0, over = {}) {
  return {
    job_id: jobId(),
    tenant_id: t.tenant,
    host_id: t.hosts[hostIdx],
    actor: t.user,
    source: 'api',
    script_sha256: 'a'.repeat(64),
    entitlements_sha256: 'b'.repeat(64),
    entitlements: { allow_exec: true },
    timeout_s: 300,
    deadline_at: new Date(Date.now() + 300000),
    lease_nonce: crypto.randomBytes(16).toString('hex'),
    dispatch: { script: 'print(1)', entitlements: {}, lease: { nonce_hex: 'n' } },
    ...over
  };
}

async function listen(reg) {
  const seen = [];
  listeners.push(reg);
  const off = reg.onJobEvent((e) => seen.push(e));
  assert.equal(await off.ready, true);
  return seen;
}

async function until(fn, ms = 3000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return false;
}

const status = async (id) => (await pool.query('SELECT status, dispatch, conn_id, error FROM cp_sysscript_jobs WHERE job_id = $1', [id])).rows[0];

test('jobs: getJob, listJobs, requestJobCancel and transitionJob never cross tenants or hosts', async () => {
  const [A, B] = await world(2);
  const a = jobRow(A);
  const b = jobRow(B);
  await registry.createJob(a);
  await registry.createJob(b);
  await assert.rejects(registry.createJob(jobRow(A, 0, { host_id: B.hosts[0] })), (e) => e.status === 404, 'host of another tenant');

  // getJob
  assert.equal(await registry.getJob([B.tenant], a.job_id), null);
  assert.equal(await registry.getJob([], a.job_id), null);
  const got = await registry.getJob([A.tenant], a.job_id);
  assert.equal(got.job_id, a.job_id);
  assert.equal('dispatch' in got, false);
  // listJobs
  const beta = await registry.listJobs([B.tenant]);
  assert.deepEqual(beta.map((j) => j.job_id), [b.job_id]);
  assert.ok(beta.every((j) => !('output' in j)));
  assert.equal((await registry.listJobs([A.tenant])).some((j) => j.job_id === b.job_id), false);
  // requestJobCancel
  assert.equal(await registry.requestJobCancel([B.tenant], a.job_id, B.user), null);
  const row = (await pool.query('SELECT cancel_requested_at FROM cp_sysscript_jobs WHERE job_id = $1', [a.job_id])).rows[0];
  assert.equal(row.cancel_requested_at, null);
  // transitionJob: the job is bound to its host and to the connection it was sent on.
  const claim = await registry.markDispatched(a.job_id, A.hosts[0], 'conn-1');
  assert.deepEqual(claim.dispatch, a.dispatch);
  assert.equal(await registry.markDispatched(a.job_id, A.hosts[0], 'conn-2'), null);
  assert.equal(await registry.transitionJob(a.job_id, B.hosts[0], ['submitted'], { status: 'accepted' }), null, 'wrong host id');
  assert.equal(await registry.transitionJob(a.job_id, A.hosts[1], ['submitted'], { status: 'accepted' }), null, 'same tenant, wrong host');
  assert.equal(await registry.transitionJob(a.job_id, A.hosts[0], ['submitted'], { status: 'accepted' }, { connId: 'conn-2' }), null, 'wrong conn');
  assert.equal(await registry.transitionJob(a.job_id, A.hosts[0], ['accepted'], { status: 'running' }), null, 'wrong from');
  assert.equal((await registry.getJob([A.tenant], a.job_id)).status, 'submitted');
  assert.equal((await registry.transitionJob(a.job_id, A.hosts[0], ['submitted'], { status: 'running' }, { connId: 'conn-1' })).status, 'running');
  const done = await registry.transitionJob(a.job_id, A.hosts[0], ['submitted', 'accepted', 'running'],
    { status: 'succeeded', output: 'out', duration_ms: 42 }, { audit: { actor: 'agent' }, notify: true });
  assert.equal(done.output, 'out');
  assert.ok(done.finished_at instanceof Date);
  // A result replayed from another host, or a second result, changes nothing.
  assert.equal(await registry.transitionJob(a.job_id, B.hosts[0], ['submitted', 'accepted', 'running'], { status: 'failed', output: 'x' }), null);
  assert.equal(await registry.transitionJob(a.job_id, A.hosts[0], ['submitted', 'accepted', 'running'], { status: 'failed', output: 'x' }), null);
  assert.equal((await registry.getJob([A.tenant], a.job_id)).output, 'out');
  await assert.rejects(registry.requestJobCancel([A.tenant], a.job_id, A.user), (e) => e.code === 'job_finished');
  const audit = (await pool.query(
    "SELECT action, actor, payload FROM cp_audit WHERE payload->>'job_id' = $1 ORDER BY seq", [a.job_id])).rows;
  assert.deepEqual(audit.map((r) => r.action), ['sysscript_job_submit', 'sysscript_job_end']);
  assert.deepEqual(audit[1].payload, { job_id: a.job_id, status: 'succeeded', error_code: null, duration_ms: 42, alerts: 0 });
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('jobs: concurrent createJob holds the host cap and the tenant cap exactly; a duplicate id is 409 at the cap', async () => {
  const [A] = await world(1);
  const out = await Promise.allSettled(Array.from({ length: 20 }, () => registry.createJob(jobRow(A, 0), { hostCap: 8, tenantCap: 64 })));
  assert.equal(out.filter((r) => r.status === 'fulfilled').length, 8);
  assert.ok(out.filter((r) => r.status === 'rejected').every((r) => r.reason.status === 429 && r.reason.code === 'too_many_jobs'));
  const won = out.find((r) => r.status === 'fulfilled').value;
  await assert.rejects(registry.createJob({ ...jobRow(A, 0), job_id: won.job_id }, { hostCap: 8 }), (e) => e.status === 409);

  // Tenant cap across both hosts: 8 active already on host 0, cap 11 leaves 3.
  const t = await Promise.allSettled(Array.from({ length: 10 }, (_, i) => registry.createJob(jobRow(A, 1 - (i % 2)), { hostCap: 8, tenantCap: 11 })));
  assert.equal(t.filter((r) => r.status === 'fulfilled').length, 3);
  const n = (await pool.query("SELECT count(*)::int AS n FROM cp_sysscript_jobs WHERE tenant_id = $1 AND status = 'submitted'", [A.tenant])).rows[0].n;
  assert.equal(n, 11);
});

test('jobs: the audit chain stays linear under concurrent job writes across tenants', async () => {
  const tenants = await world(12);
  const rows = tenants.flatMap((t) => [jobRow(t, 0), jobRow(t, 1), jobRow(t, 0)]);
  await Promise.all(rows.map((r) => registry.createJob(r)));
  await Promise.all(rows.map((r) => registry.markDispatched(r.job_id, r.host_id, `c-${r.host_id}`)));
  await Promise.all(rows.map((r, i) => (i % 3 === 2
    ? registry.requestJobCancel([r.tenant_id], r.job_id, r.actor)
    : registry.transitionJob(r.job_id, r.host_id, ['submitted'], { status: 'succeeded', duration_ms: i }, { audit: { actor: 'agent' }, notify: true }))));
  const verdict = await registry.verifyAudit();
  assert.equal(verdict.ok, true, JSON.stringify(verdict));
});

test('jobs: a NOTIFY is delivered only after COMMIT, and not at all when the write rolls back', async () => {
  const [A] = await world(1);
  const reg = new PgRegistry(pool, { NODE_ENV: 'production' });
  const seen = await listen(reg);
  // Directly: notifyInTx inside an open transaction is not seen until COMMIT.
  const client = await pool.connect();
  const probe = { k: 'state', job_id: jobId(), host_id: A.hosts[0], status: 'running' };
  try {
    await client.query('BEGIN');
    await reg.notifyInTx(client, probe);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(seen.some((e) => e.job_id === probe.job_id), false, 'seen before COMMIT');
    await client.query('COMMIT');
  } finally {
    client.release();
  }
  assert.ok(await until(() => seen.some((e) => e.job_id === probe.job_id)));

  // createJob: when the event arrives the row is already visible.
  const a = jobRow(A);
  let visible = null;
  const off = reg.onJobEvent(async (e) => {
    if (e.job_id === a.job_id && e.k === 'dispatch') visible = await reg.getJob([A.tenant], a.job_id);
  });
  await registry.createJob(a);
  assert.ok(await until(() => visible !== null));
  assert.equal(visible.status, 'submitted');
  off();

  // A refused audit row rolls the insert and its NOTIFY back.
  const b = jobRow(A);
  await pool.query(`CREATE FUNCTION test_refuse_job_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit refused by test'; END $$`);
  await pool.query('CREATE TRIGGER test_refuse_job_audit BEFORE INSERT ON cp_audit FOR EACH ROW EXECUTE FUNCTION test_refuse_job_audit()');
  try {
    await assert.rejects(registry.createJob(b), /audit refused/);
  } finally {
    await pool.query('DROP TRIGGER test_refuse_job_audit ON cp_audit');
    await pool.query('DROP FUNCTION test_refuse_job_audit()');
  }
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(seen.some((e) => e.job_id === b.job_id), false);
  assert.equal(await registry.getJob([A.tenant], b.job_id), null);

  // Cancel of a dispatched job notifies cancel; malformed payloads are dropped.
  await registry.markDispatched(a.job_id, A.hosts[0], 'conn-n');
  await registry.requestJobCancel([A.tenant], a.job_id, A.user);
  assert.ok(await until(() => seen.some((e) => e.job_id === a.job_id && e.k === 'cancel')));
  const before = seen.length;
  await pool.query("SELECT pg_notify('cp_sysscript_jobs', 'not json'), pg_notify('cp_sysscript_jobs', '{\"k\":\"evil\"}')");
  await registry.publishJobEvent({ k: 'state', job_id: a.job_id, host_id: A.hosts[0], status: 'running' });
  assert.ok(await until(() => seen.length > before));
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(seen.length, before + 1);
});

test('jobs: the LISTEN client reconnects after its backend is terminated; ready settles false when closed first', async () => {
  const [A] = await world(1);
  const reg = new PgRegistry(pool, { NODE_ENV: 'production' });
  const seen = await listen(reg);
  const pids = async () => (await pool.query(
    "SELECT pid FROM pg_stat_activity WHERE datname = current_database() AND query = 'LISTEN cp_sysscript_jobs'")).rows.map((r) => r.pid);
  const mine = reg.jobListen.client.processID;
  assert.ok((await pids()).includes(mine));
  const realWarn = console.warn;
  const warned = [];
  console.warn = (m) => warned.push(m);
  try {
    await pool.query('SELECT pg_terminate_backend($1)', [mine]);
    const id = jobId();
    assert.ok(await until(async () => {
      await registry.publishJobEvent({ k: 'state', job_id: id, host_id: A.hosts[0], status: 'running' });
      return seen.some((e) => e.job_id === id);
    }, 8000), 'events flow again after the reconnect');
  } finally {
    console.warn = realWarn;
  }
  assert.ok(warned.some((m) => /job LISTEN lost/.test(m)));
  assert.notEqual(reg.jobListen.client.processID, mine);

  const closed = new PgRegistry(pool, { NODE_ENV: 'production' });
  const off = closed.onJobEvent(() => {});
  await closed.closeJobEvents();
  assert.equal(await off.ready, false);
});

test('jobs: two registries on one database: the other instance receives dispatch and exactly one claim wins', async () => {
  const [, B] = await world(2);
  const other = new PgRegistry(pool, { NODE_ENV: 'production' });
  const third = new PgRegistry(pool, { NODE_ENV: 'production' });
  const seen = await listen(other);
  const a = jobRow(B);
  await registry.createJob(a);
  assert.ok(await until(() => seen.some((e) => e.k === 'dispatch' && e.job_id === a.job_id)));
  const claims = await Promise.all([other.markDispatched(a.job_id, B.hosts[0], 'i2:c'), third.markDispatched(a.job_id, B.hosts[0], 'i3:c')]);
  const won = claims.filter(Boolean);
  assert.equal(won.length, 1);
  assert.deepEqual(won[0].dispatch, a.dispatch);
  const row = await status(a.job_id);
  assert.equal(row.dispatch, null);
  assert.equal(row.conn_id, won[0].conn_id);
});

test('jobs: cancel racing dispatch: exactly one wins and the dispatch payload is gone', async () => {
  const [A] = await world(1);
  const rows = Array.from({ length: 12 }, () => jobRow(A, 0));
  for (const r of rows) await registry.createJob(r, { hostCap: 16 });
  const results = await Promise.all(rows.map(async (r) => {
    const [cancel, claim] = await Promise.all([
      registry.requestJobCancel([A.tenant], r.job_id, A.user),
      registry.markDispatched(r.job_id, A.hosts[0], 'c-race')
    ]);
    return { r, cancel, claim };
  }));
  for (const { r, cancel, claim } of results) {
    const row = await status(r.job_id);
    assert.equal(row.dispatch, null);
    if (claim) {
      assert.equal(row.status, 'submitted', 'dispatched first: the cancel is a request for the agent');
      assert.ok(cancel.cancel_requested_at instanceof Date);
      assert.equal(row.conn_id, 'c-race');
    } else {
      assert.equal(row.status, 'cancelled', 'cancelled first: nothing to dispatch');
      assert.equal(row.error, 'cancelled_before_dispatch');
      assert.equal(row.conn_id, null);
    }
  }
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('jobs: bumpJobAlert caps at 20, reconcile ends lost rows and rebinds listed ones, sweep and output expiry', async () => {
  const [, B] = await world(2);
  const host = B.hosts[0];
  // bumpJobAlert
  const al = jobRow(B);
  await registry.createJob(al);
  assert.deepEqual(await registry.bumpJobAlert(al.job_id, host, 20), { ok: false, reason: 'unknown_execution' });
  await registry.markDispatched(al.job_id, host, 'cb');
  await registry.transitionJob(al.job_id, host, ['submitted'], { status: 'running' });
  assert.deepEqual(await registry.bumpJobAlert(al.job_id, B.hosts[1], 20), { ok: false, reason: 'unknown_execution' });
  const bumps = await Promise.all(Array.from({ length: 25 }, () => registry.bumpJobAlert(al.job_id, host, 20)));
  assert.equal(bumps.filter((r) => r.ok).length, 20);
  assert.equal(bumps.filter((r) => r.reason === 'rate_limited').length, 5);
  assert.ok(bumps.filter((r) => r.ok).every((r) => r.tenant_id === B.tenant));

  // reconcileHostJobs
  const listed = jobRow(B);
  const lost = jobRow(B);
  const unsent = jobRow(B);
  for (const r of [listed, lost, unsent]) await registry.createJob(r);
  await registry.markDispatched(listed.job_id, host, 'old');
  await registry.markDispatched(lost.job_id, host, 'old');
  const ended = await registry.reconcileHostJobs(host, 'new', [listed.job_id, al.job_id]);
  assert.deepEqual(ended.map((j) => [j.job_id, j.error]), [[lost.job_id, 'agent_lost_job']]);
  assert.equal((await status(listed.job_id)).conn_id, 'new', 'listed rows move to the new connection');
  assert.equal((await status(listed.job_id)).status, 'accepted', 'being listed in sync is an ack');
  assert.equal((await status(al.job_id)).status, 'running', 'a later status is kept');
  assert.equal((await status(al.job_id)).conn_id, 'new');
  assert.equal((await status(unsent.job_id)).status, 'submitted');
  assert.equal((await status(unsent.job_id)).conn_id, null);

  // pendingForHosts, then the sweep against the database clock (rows backdated).
  const pending = await registry.pendingForHosts([host]);
  assert.ok(pending.some((p) => p.job_id === unsent.job_id && p.dispatch_pending === true));
  await pool.query("UPDATE cp_sysscript_jobs SET created_at = now() - interval '2 minutes' WHERE job_id = $1", [unsent.job_id]);
  await pool.query("UPDATE cp_sysscript_jobs SET sent_at = now() - interval '20 seconds' WHERE job_id = $1", [listed.job_id]);
  const noAck = jobRow(B);
  await registry.createJob(noAck);
  await registry.markDispatched(noAck.job_id, host, 'new');
  await pool.query("UPDATE cp_sysscript_jobs SET sent_at = now() - interval '20 seconds' WHERE job_id = $1", [noAck.job_id]);
  await pool.query("UPDATE cp_sysscript_jobs SET deadline_at = now() - interval '2 minutes' WHERE job_id = $1", [al.job_id]);
  const fresh = jobRow(B, 1);
  await registry.createJob(fresh);
  await registry.markDispatched(fresh.job_id, B.hosts[1], 'new');
  const swept = await registry.sweepJobs(undefined, { connectedConnIds: ['new'] });
  const byId = Object.fromEntries(swept.map((j) => [j.job_id, j.error]));
  assert.equal(byId[unsent.job_id], 'dispatch_timeout');
  assert.equal(byId[noAck.job_id], 'agent_no_ack');
  assert.equal(byId[listed.job_id], undefined, 'a job the agent listed survives the sweep');
  assert.equal((await status(listed.job_id)).status, 'accepted');
  assert.equal(byId[al.job_id], 'result_lost');
  assert.equal(byId[fresh.job_id], undefined, 'inside every window');
  const endRows = (await pool.query(
    "SELECT payload->>'status' AS status, payload->>'error_code' AS code FROM cp_audit WHERE action = 'sysscript_job_end' AND payload->>'job_id' = $1",
    [al.job_id])).rows;
  assert.deepEqual(endRows, [{ status: 'failed', code: 'result_lost' }]);

  // A sweep skips a row another transaction holds.
  const held = jobRow(B, 1);
  await registry.createJob(held);
  await pool.query("UPDATE cp_sysscript_jobs SET created_at = now() - interval '2 minutes' WHERE job_id = $1", [held.job_id]);
  const holder = await pool.connect();
  try {
    await holder.query('BEGIN');
    await holder.query('SELECT 1 FROM cp_sysscript_jobs WHERE job_id = $1 FOR UPDATE', [held.job_id]);
    const skipped = await registry.sweepJobs();
    assert.equal(skipped.some((j) => j.job_id === held.job_id), false);
    await holder.query('COMMIT');
  } finally {
    holder.release();
  }
  assert.ok((await registry.sweepJobs()).some((j) => j.job_id === held.job_id));

  // expireOutput / pruneJobs
  await pool.query("UPDATE cp_sysscript_jobs SET output = 'old', finished_at = now() - interval '73 hours' WHERE job_id = $1", [al.job_id]);
  assert.ok(await registry.expireOutput(72) >= 1);
  const ex = await registry.getJob([B.tenant], al.job_id);
  assert.equal(ex.output, null);
  assert.equal(ex.output_expired, true);
  await pool.query("UPDATE cp_sysscript_jobs SET finished_at = now() - interval '31 days' WHERE job_id = $1", [al.job_id]);
  assert.ok(await registry.pruneJobs(30) >= 1);
  assert.equal(await registry.getJob([B.tenant], al.job_id), null);
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('jobs: stored output is capped at 1 MiB of UTF-8; the audit error_code is allowlisted', async () => {
  const [A] = await world(1);
  const a = jobRow(A);
  await registry.createJob(a);
  await registry.markDispatched(a.job_id, A.hosts[0], 'c');
  const done = await registry.transitionJob(a.job_id, A.hosts[0], ['submitted'],
    { status: 'failed', error: 'Free text: /etc/shadow', output: 'é'.repeat(600 * 1024) }, { audit: { actor: 'agent' } });
  assert.equal(done.output_truncated, true);
  assert.equal(Buffer.byteLength(done.output, 'utf8'), 1024 * 1024);
  assert.equal(done.error, 'Free text: /etc/shadow');
  const end = (await pool.query("SELECT payload FROM cp_audit WHERE action = 'sysscript_job_end' AND payload->>'job_id' = $1", [a.job_id])).rows[0];
  assert.equal(end.payload.error_code, 'agent_error');
});

test('jobs: one sweep ends at most 500 rows; the next tick ends the rest', async () => {
  const [A] = await world(1);
  const tag = crypto.randomBytes(3).toString('hex');
  await pool.query(
    `INSERT INTO cp_sysscript_jobs (job_id, tenant_id, host_id, actor, source, script_sha256, entitlements_sha256,
       status, timeout_s, deadline_at, lease_nonce, dispatch, created_at)
     SELECT 'sjb_' || $1 || lpad(i::text, 16, '0'), $2, $3, $4, 'api', repeat('a', 64), repeat('b', 64),
       'submitted', 300, now() + interval '5 minutes', repeat('c', 32), '{}'::jsonb, now() - interval '2 minutes'
     FROM generate_series(1, 501) AS i`,
    [tag, A.tenant, A.hosts[0], A.user]
  );
  const mine = async () => (await pool.query(
    "SELECT count(*)::int AS n FROM cp_sysscript_jobs WHERE job_id LIKE $1 AND status = 'submitted'", [`sjb_${tag}%`])).rows[0].n;
  const first = await registry.sweepJobs();
  assert.equal(first.length, 500);
  assert.ok(await mine() >= 1);
  await registry.sweepJobs();
  assert.equal(await mine(), 0);
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('jobs: two FleetManagers on one database: submit on one, the agent on the other; result, wait and cancel cross instances', async () => {
  const { rig, connectAgent, waitUntil } = require('./job-agent-rig');
  const tag = crypto.randomBytes(4).toString('hex');
  const tenant = `j${tag}`;
  const hostId = crypto.randomUUID();
  const keys = {
    'pg-agent': { key_id: `ka${tag}`, user_id: `u${tag}` },
    'pg-op': { key_id: `ko${tag}`, user_id: `u${tag}` }
  };
  const regOne = new PgRegistry(pool, { NODE_ENV: 'production' });
  const regTwo = new PgRegistry(pool, { NODE_ENV: 'production' });
  listeners.push(regOne, regTwo);
  // The test keys have no playground_api_keys row; the agent's key check
  // would close its socket.
  regTwo.keyActive = async () => true;
  const one = await rig({ registry: regOne, keys });
  const two = await rig({ registry: regTwo, keys });
  try {
    await regOne.setScopes(`ko${tag}`, ['exec:run', 'hosts:read']);
    const a = await connectAgent(two, hostId, { tenant, key: 'pg-agent' });
    assert.ok(a.frames.some((f) => f.type === 'enrolled'));
    const agentRow = await regOne.hostAgent(hostId);
    assert.equal(agentRow.instance, two.fm.jobs.instanceId);
    assert.equal(agentRow.conn_id, two.fm.jobs.connIds.get(two.fm.connectedAgents.get(hostId)));
    assert.deepEqual(agentRow.caps, ['sysscript_jobs']);
    await one.fm.jobs.listen();
    await two.fm.jobs.listen();

    const p = one.api('POST', `/api/v1/fleet/${hostId}/jobs`, 'pg-op', { script: 'print(1)', entitlements: { allow_exec: true }, wait_s: 10 });
    const { frame, lease } = await a.waitJob(undefined, 8000);
    assert.equal(lease.ok, true, lease.error);
    assert.equal(frame.entitlements.allow_exec, true);
    a.status(frame.job_id, { status: 'accepted' });
    a.result(frame.job_id, { status: 'succeeded', output: 'one' });
    const res = await p;
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.job.status, 'succeeded');
    assert.equal(res.body.job.output, 'one');
    await a.waitFor('sysscript_job_ack', frame.job_id, 8000);

    const c = await one.api('POST', `/api/v1/fleet/${hostId}/jobs`, 'pg-op', { script: 'print(2)' });
    assert.equal(c.status, 202);
    await a.waitJob(c.body.job_id, 8000);
    a.status(c.body.job_id, { status: 'running' });
    await waitUntil('running', async () => (await regOne.getJob([tenant], c.body.job_id)).status === 'running', 8000);
    assert.equal((await one.api('POST', `/api/v1/jobs/${c.body.job_id}/cancel`, 'pg-op')).status, 202);
    assert.equal((await a.waitFor('sysscript_job_cancel', c.body.job_id, 8000)).reason, 'user');
    a.result(c.body.job_id, { status: 'cancelled', error: 'script cancelled' });
    await a.waitFor('sysscript_job_ack', c.body.job_id, 8000);
    const audit = await pool.query(
      "SELECT action FROM cp_audit WHERE tenant_id = $1 AND payload->>'job_id' = $2 ORDER BY seq",
      [tenant, c.body.job_id]
    );
    assert.deepEqual(audit.rows.map((x) => x.action), ['sysscript_job_submit', 'sysscript_job_cancel', 'sysscript_job_end']);

    // U+0000 in output, error and an alert is stored as U+FFFD (Postgres
    // TEXT refuses U+0000): the result is acked, not lost.
    const n = await one.api('POST', `/api/v1/fleet/${hostId}/jobs`, 'pg-op', { script: 'print(3)' });
    await a.waitJob(n.body.job_id, 8000);
    a.status(n.body.job_id, { status: 'running' });
    a.alert(n.body.job_id, { severity: 'warning', message: 'nul\u0000here' });
    a.result(n.body.job_id, { status: 'failed', error: 'bad\u0000error', output: 'a\u0000b' });
    await a.waitFor('sysscript_job_ack', n.body.job_id, 8000);
    const nulRow = await regOne.getJob([tenant], n.body.job_id);
    assert.equal(nulRow.status, 'failed');
    assert.equal(nulRow.output, 'a\uFFFDb');
    assert.equal(nulRow.error, 'bad\uFFFDerror');
    assert.equal(nulRow.alert_count, 1);
    const alerts = await regOne.listAlerts([tenant]);
    assert.ok(alerts.some((x) => x.message === 'nul\uFFFDhere'));
    // The legacy request_id alert path too.
    two.fm.pendingExecutions.set('req-nul', { resolve() {}, reject() {}, script: 'x', hostId });
    a.send({ type: 'sysscript_alert', request_id: 'req-nul', payload: { severity: 'info', message: 'legacy\u0000nul' } });
    await waitUntil('legacy alert', async () => (await regOne.listAlerts([tenant])).some((x) => x.message === 'legacy\uFFFDnul'), 8000);
    two.fm.pendingExecutions.delete('req-nul');

    // Presence ordering: a delayed write from an older enroll, then its
    // close, leave the newer enroll in place.
    const live = await regOne.hostAgent(hostId);
    const older = { caps: ['sysscript_jobs'], instance: 'old', connId: 'old:1', enrolledAt: new Date(Date.now() - 60000) };
    assert.equal(await regOne.setAgentPresence(hostId, older), false);
    assert.equal(await regOne.clearAgentPresence(hostId, older.connId), false);
    assert.equal((await regOne.hostAgent(hostId)).conn_id, live.conn_id);

    a.ws.terminate();
    await waitUntil('presence cleared', async () => (await regOne.hostAgent(hostId)) === null, 8000);
    // Skew: a stale owner whose clock ran ahead holds the row and refuses
    // the live socket's write; once it closes, the live socket's re-assert
    // wins.
    const ahead = { caps: ['sysscript_jobs'], instance: 'ahead', connId: 'ahead:1', enrolledAt: new Date(Date.now() + 600000) };
    const liveSock = { caps: ['sysscript_jobs'], instance: 'live', connId: 'live:1', enrolledAt: new Date() };
    assert.equal(await regOne.setAgentPresence(hostId, ahead), true);
    assert.equal(await regOne.setAgentPresence(hostId, liveSock), false);
    assert.equal(await regOne.clearAgentPresence(hostId, ahead.connId), true);
    assert.equal(await regOne.setAgentPresence(hostId, liveSock), true);
    assert.equal((await regOne.hostAgent(hostId)).conn_id, liveSock.connId);
    // Freshness by the database clock: a presence last written over maxAgeS
    // ago is null with maxAgeS (still returned without it); a re-assert
    // refreshes it; a close clears agent_seen_at.
    assert.equal((await regOne.hostAgent(hostId, { maxAgeS: 90 })).conn_id, liveSock.connId);
    await regOne.pool.query(`UPDATE cp_hosts SET agent_seen_at = now() - interval '91 seconds' WHERE host_id = $1`, [hostId]);
    assert.equal(await regOne.hostAgent(hostId, { maxAgeS: 90 }), null);
    assert.equal((await regOne.hostAgent(hostId)).conn_id, liveSock.connId);
    assert.equal(await regOne.setAgentPresence(hostId, liveSock), true);
    assert.equal((await regOne.hostAgent(hostId, { maxAgeS: 90 })).conn_id, liveSock.connId);
    assert.equal(await regOne.clearAgentPresence(hostId, liveSock.connId), true);
    const seen = await regOne.pool.query('SELECT agent_seen_at FROM cp_hosts WHERE host_id = $1', [hostId]);
    assert.equal(seen.rows[0].agent_seen_at, null);
    assert.equal((await registry.verifyAudit()).ok, true);
  } finally {
    await one.close();
    await two.close();
  }
});

// --- desired state and converge runs (.omc/plans/convergence-drift.md §8) --
// Each test makes its own tenants, hosts, states and assignments.

const SCHEMA_PATH = require('node:path').join(__dirname, '..', 'controlplane', 'schema.sql');
const CONV_BUNDLE = JSON.stringify({ v: 1, files: { 'main.star': 'state.file("/etc/x", "x")' }, vars: {}, host: {} });
const CONV_SHA = crypto.createHash('sha256').update(CONV_BUNDLE, 'utf8').digest('hex');

// A tenant world with one state, one version and a host assignment on host 0.
async function cworld(n = 2, target = 'host') {
  const ts = await world(n);
  for (const t of ts) {
    t.st = await registry.createState({ tenantId: t.tenant, name: 'web', actor: t.user });
    t.v = await registry.publishVersion({ tenantId: t.tenant, stateId: t.st.state_id, files: { 'main.star': 'x = 1' }, entitlements: { allow_fs_write: ['/etc/'] }, actor: t.user });
    t.a = await registry.createAssignment({ tenantId: t.tenant, stateId: t.st.state_id, versionId: t.v.version_id, actor: t.user,
      targetKind: target, targetValue: target === 'host' ? t.hosts[0] : target === 'tag' ? 'web' : undefined });
  }
  return ts;
}

function cjob(t, kind = 'check', over = {}) {
  return jobRow(t, 0, {
    source: `converge_${kind}`,
    script_sha256: CONV_SHA,
    entitlements_sha256: t.v.entitlements_sha256,
    entitlements: t.v.entitlements,
    dispatch: { kind: 'converge', bundle_json: CONV_BUNDLE },
    ...over
  });
}

function copts(t, kind = 'check', over = {}) {
  return {
    converge: {
      kind,
      stateId: t.st.state_id,
      assignmentId: t.a.assignment_id,
      versionId: t.v.version_id,
      bundleJson: kind === 'plan' ? CONV_BUNDLE : undefined,
      expectPlanSha: kind === 'apply' ? 'c'.repeat(64) : undefined,
      ...over
    }
  };
}

function creport(kind, { drift = 0, changed = 0, truncated = false } = {}) {
  const key = 'file:/etc/x';
  const status = drift ? 'drift' : changed ? 'changed' : 'ok';
  return {
    v: 1,
    mode: kind === 'apply' ? 'apply' : 'check',
    bundle_sha256: CONV_SHA,
    plan_sha256: 'c'.repeat(64),
    truncated,
    summary: { total: 1, ok: status === 'ok' ? 1 : 0, drift: drift ? 1 : 0, changed: changed ? 1 : 0, failed: 0, denied: 0, skipped: 0 },
    plan: drift ? [{ key, status: 'drift' }] : [],
    resources: [{ key, kind: 'file', status, sensitive: false, before: { exists: true, sha256: 'd'.repeat(64) }, desired: { sha256: 'e'.repeat(64) }, diff: '', error: '', backup_id: null }]
  };
}

async function csubmit(reg, t, kind = 'check', over = {}, opts = {}) {
  const row = cjob(t, kind, over);
  await reg.createJob(row, { ...copts(t, kind, opts.conv), ...(opts.caps || {}) });
  assert.ok(await reg.markDispatched(row.job_id, row.host_id, `c-${row.job_id}`, { allowConverge: true }));
  return row;
}

async function cfinish(reg, row, rep, st = 'succeeded') {
  return reg.transitionJob(row.job_id, row.host_id, ['submitted', 'accepted', 'running'],
    { status: st, output: '' }, { audit: { actor: 'agent' }, converge: { report: rep } });
}

const hstate = async (t, host = 0) => (await pool.query(
  'SELECT * FROM cp_host_state WHERE host_id = $1 AND state_id = $2', [t.hosts[host], t.st.state_id])).rows[0];

test('converge: the schema migrates a database that already has cp_sysscript_jobs rows; the swap is idempotent and safe concurrently', async () => {
  const full = require('node:fs').readFileSync(SCHEMA_PATH, 'utf8');
  const cut = full.indexOf('-- Declarative convergence and drift');
  assert.ok(cut > 0);
  const old = full.slice(0, cut);
  const names = [`mig_${crypto.randomBytes(5).toString('hex')}`, `mig_${crypto.randomBytes(5).toString('hex')}`];
  const admin = new Pool({ connectionString: BASE });
  for (const name of names) await admin.query(`CREATE DATABASE ${name}`);
  const pools = [];
  try {
    for (const [i, name] of names.entries()) {
      const p = new Pool({ connectionString: withDatabase(BASE, name) });
      pools.push(p);
      await p.query(old);
      await p.query(`INSERT INTO cp_sysscript_jobs (job_id, tenant_id, host_id, actor, source, script_sha256, entitlements_sha256,
          status, timeout_s, deadline_at, lease_nonce) VALUES ($1, 't', 'h', 'a', 'api', $2, $2, 'succeeded', 60, now(), 'n')`,
      [`sjb_old_${i}`, 'a'.repeat(64)]);
    }
    const check = async (p) => {
      const cons = (await p.query(
        `SELECT conname, convalidated FROM pg_constraint
         WHERE conrelid = 'cp_sysscript_jobs'::regclass AND contype = 'c' AND conname LIKE 'cp_sysscript_jobs_source%'`)).rows;
      assert.deepEqual(cons, [{ conname: 'cp_sysscript_jobs_source_check_v2', convalidated: true }]);
      assert.equal((await p.query("SELECT count(*)::int AS n FROM cp_sysscript_jobs WHERE job_id LIKE 'sjb_old_%'")).rows[0].n, 1);
      const ins = (src) => p.query(`INSERT INTO cp_sysscript_jobs (job_id, tenant_id, host_id, actor, source, script_sha256,
          entitlements_sha256, status, timeout_s, deadline_at, lease_nonce) VALUES ($1, 't', 'h', 'a', $2, $3, $3, 'submitted', 60, now(), 'n')`,
      [`sjb_${crypto.randomBytes(8).toString('hex')}`, src, 'a'.repeat(64)]);
      await ins('converge_apply');
      await assert.rejects(ins('bogus'), (e) => e.code === '23514');
    };
    // Sequentially, twice, on the first database.
    await pools[0].query(full);
    await pools[0].query(full);
    await check(pools[0]);
    // Concurrently from two pools on the second.
    const other = new Pool({ connectionString: withDatabase(BASE, names[1]) });
    pools.push(other);
    await Promise.all([pools[1].query(full), other.query(full), pools[1].query(full)]);
    await check(pools[1]);
    // createRegistry over the migrated database still boots.
    const reg = await createRegistry({ pool: pools[1], env: { NODE_ENV: 'production' }, logger: { log() {}, warn() {}, error() {} } });
    assert.ok(reg instanceof PgRegistry);
  } finally {
    for (const p of pools) await p.end();
    for (const name of names) await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await admin.end();
  }
});

test('converge: the assignment CHECKs refuse what the registry refuses', async () => {
  const [A] = await cworld(1);
  const ins = (kind, value, auto, approval) => pool.query(
    `INSERT INTO cp_state_assignments (assignment_id, tenant_id, state_id, version_id, target_kind, target_value,
       auto_remediate, require_approval, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'x')`,
    [`sta_${crypto.randomBytes(8).toString('hex')}`, A.tenant, A.st.state_id, A.v.version_id, kind, value, auto, approval]
  );
  await assert.rejects(ins('tag', 'a', false, false), (e) => e.code === '23514');
  await assert.rejects(ins('tag', 'b', true, true), (e) => e.code === '23514');
  await assert.rejects(ins('host', A.hosts[1], true, true), (e) => e.code === '23514');
  await ins('host', A.hosts[1], true, false);
  await assert.rejects(registry.createAssignment({ tenantId: A.tenant, stateId: A.st.state_id, versionId: A.v.version_id, actor: A.user,
    targetKind: 'tenant', autoRemediate: true }), (e) => e.code === 'auto_remediate_host_only');
});

test('converge: states, versions, assignments, host states and runs never cross tenants', async () => {
  const [A, B] = await cworld(2);
  assert.equal(await registry.getState([B.tenant], A.st.state_id), null);
  assert.equal(await registry.getVersion([B.tenant], A.v.version_id), null);
  assert.deepEqual(await registry.listVersions([B.tenant], A.st.state_id), []);
  assert.equal(await registry.getAssignment([B.tenant], A.a.assignment_id), null);
  assert.ok((await registry.listAssignments([B.tenant])).every((x) => x.tenant_id === B.tenant));
  assert.equal(await registry.getHostState([B.tenant], A.hosts[0], A.st.state_id), null);
  assert.ok((await registry.listHostStates([B.tenant])).every((x) => x.tenant_id === B.tenant));
  assert.equal((await registry.listHostStates([A.tenant], { hostId: A.hosts[0] })).length, 1);
  await assert.rejects(registry.publishVersion({ tenantId: B.tenant, stateId: A.st.state_id, files: { 'main.star': '' }, actor: B.user }), (e) => e.status === 404);
  await assert.rejects(registry.updateAssignment({ tenantId: B.tenant, assignmentId: A.a.assignment_id, patch: { driftThreshold: 3 }, actor: B.user }), (e) => e.status === 404);
  await assert.rejects(registry.deleteAssignment({ tenantId: B.tenant, assignmentId: A.a.assignment_id, actor: B.user }), (e) => e.status === 404);
  await assert.rejects(registry.createAssignment({ tenantId: B.tenant, stateId: B.st.state_id, versionId: A.v.version_id, actor: B.user,
    targetKind: 'tag', targetValue: 'x' }), (e) => e.code === 'version_not_found');
  await assert.rejects(registry.createAssignment({ tenantId: B.tenant, stateId: B.st.state_id, versionId: B.v.version_id, actor: B.user,
    targetKind: 'host', targetValue: A.hosts[1] }), (e) => e.code === 'host_not_found');
  await assert.rejects(registry.setHostTags({ tenantId: B.tenant, hostId: A.hosts[0], tags: ['web'], actor: B.user }), (e) => e.status === 404);
  // A converge job for B's state on A's host, and A's state on B's host.
  await assert.rejects(registry.createJob(cjob(A, 'check', { host_id: B.hosts[0] }), copts(A)), (e) => e.status === 404);
  await assert.rejects(registry.createJob(cjob(A), copts(A, 'check', { stateId: B.st.state_id })), (e) => e.code === 'state_not_assigned');
  const j = await csubmit(registry, A);
  assert.equal(await registry.getConvergeRun([B.tenant], j.job_id), null);
  assert.deepEqual(await registry.listConvergeRuns([B.tenant], { hostId: A.hosts[0] }), []);
  // A result for A's job from B's host changes nothing.
  assert.equal(await registry.transitionJob(j.job_id, B.hosts[0], ['submitted'], { status: 'succeeded' }, { converge: { report: creport('check') } }), null);
  assert.equal((await registry.ingestConvergeResend(j.job_id, B.hosts[0], creport('check'))).ingested, false);
  await cfinish(registry, j, creport('plan'));
  assert.equal(await registry.approvePlan({ tenantIds: [B.tenant], runId: j.job_id, actor: B.user }), null);
  assert.equal((await registry.getConvergeRun([A.tenant], j.job_id, { withReport: true })).report.summary.ok, 1);
  assert.equal((await hstate(A)).status, 'compliant');
});

test('converge: a drifted ingest while an ack\'d drift alert exists commits, returns the row, and opens no duplicate', async () => {
  const [A] = await cworld(1);
  const j1 = await csubmit(registry, A);
  const d1 = await cfinish(registry, j1, creport('check', { drift: 1 }));
  assert.equal(d1.converge.status, 'drifted');
  assert.equal(d1.converge.alerts.length, 1);
  await registry.setAlertStatus([A.tenant], d1.converge.alerts[0].alert_id, 'ack');
  const j2 = await csubmit(registry, A);
  const d2 = await cfinish(registry, j2, creport('check', { drift: 1 }));
  assert.ok(d2, 'the transition committed (the agent is acked)');
  assert.equal(d2.status, 'succeeded');
  assert.deepEqual(d2.converge.alerts, []);
  const row = await hstate(A);
  assert.equal(row.consecutive_drift, 2);
  assert.equal(row.check_job_id, null);
  assert.equal((await status(j2.job_id)).status, 'succeeded');
  const active = (await pool.query("SELECT status FROM cp_alert_events WHERE host_id = $1 AND rule_name = $2 AND status IN ('open', 'ack')",
    [A.hosts[0], `drift:${A.st.state_id}`])).rows;
  assert.deepEqual(active, [{ status: 'ack' }]);
  // A clean check resolves the ack'd alert.
  const j3 = await csubmit(registry, A);
  const d3 = await cfinish(registry, j3, creport('check'));
  assert.deepEqual(d3.converge.alerts.map((x) => x.type), ['drift_resolved']);
  // Removing the host from the assignment deletes its row.
  const j4 = await csubmit(registry, A);
  await cfinish(registry, j4, creport('check', { drift: 1 }));
  await registry.deleteAssignment({ tenantId: A.tenant, assignmentId: A.a.assignment_id, actor: A.user });
  assert.equal(await hstate(A), undefined);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM cp_alert_events WHERE host_id = $1 AND rule_name = $2 AND status IN ('open', 'ack')",
    [A.hosts[0], `drift:${A.st.state_id}`])).rows[0].n, 0);
});

test('converge: AC 18, a late result for job A after job B took the row records A\'s run and leaves the host state alone', async () => {
  const [A] = await cworld(1);
  const jA = await csubmit(registry, A);
  const jB = await csubmit(registry, A);
  const late = await cfinish(registry, jA, creport('check', { drift: 1 }));
  assert.equal(late.converge.host_state_updated, false);
  const row = await hstate(A);
  assert.equal(row.status, 'unknown');
  assert.equal(row.check_job_id, jB.job_id);
  assert.ok((await registry.getConvergeRun([A.tenant], jA.job_id)).report_sha256);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM cp_alert_events WHERE host_id = $1', [A.hosts[0]])).rows[0].n, 0);
  const own = await cfinish(registry, jB, creport('check'));
  assert.equal(own.converge.status, 'compliant');
});

test('converge: a sweep releases the claim, a swept apply is partial, and a re-sent result is ingested once', async () => {
  const [A] = await cworld(1);
  const j = await csubmit(registry, A, 'check', { deadline_at: new Date(Date.now() + 1000) });
  await registry.transitionJob(j.job_id, A.hosts[0], ['submitted'], { status: 'running' });
  await new Promise((resolve) => setTimeout(resolve, 1200));
  const ended = await registry.sweepJobs(Date.now(), { graceMs: 0 });
  assert.ok(ended.some((x) => x.job_id === j.job_id && x.error === 'result_lost'));
  let row = await hstate(A);
  assert.equal(row.check_claimed_at, null);
  assert.equal(row.check_job_id, null);
  assert.equal(row.last_error, 'result_lost');
  assert.equal(row.status, 'unknown');
  const due = (await pool.query('SELECT extract(epoch FROM next_check_at - now())::float8 AS s FROM cp_host_state WHERE host_id = $1 AND state_id = $2',
    [A.hosts[0], A.st.state_id])).rows[0].s;
  assert.ok(due > 0.9 * 600 - 5 && due < 1.1 * 600 + 5, `a first run ended without a report is retried after 10 min (${due} s)`);
  const [r1, r2] = await Promise.all([
    registry.ingestConvergeResend(j.job_id, A.hosts[0], creport('check', { drift: 1 })),
    registry.ingestConvergeResend(j.job_id, A.hosts[0], creport('check', { drift: 1 }))
  ]);
  assert.deepEqual([r1.ingested, r2.ingested].sort(), [false, true], 'exactly once');
  assert.equal((r1.ingested ? r1 : r2).converge.host_state_updated, false);
  assert.ok((await registry.getConvergeRun([A.tenant], j.job_id)).report_sha256);

  // Plan, then an apply swept past its deadline: partial.
  const p = await csubmit(registry, A, 'plan');
  await cfinish(registry, p, creport('plan', { drift: 1 }));
  const ap = await csubmit(registry, A, 'apply', { deadline_at: new Date(Date.now() + 1000) }, { conv: { planRunId: p.job_id } });
  await registry.transitionJob(ap.job_id, A.hosts[0], ['submitted'], { status: 'running' });
  await new Promise((resolve) => setTimeout(resolve, 1200));
  await registry.sweepJobs(Date.now(), { graceMs: 0 });
  row = await hstate(A);
  assert.equal(row.status, 'partial');
  assert.equal(row.last_apply_run_id, ap.job_id);
  // Cancel before dispatch releases a claim too.
  const c = cjob(A);
  await registry.createJob(c, copts(A));
  assert.equal((await hstate(A)).check_job_id, c.job_id);
  await registry.requestJobCancel([A.tenant], c.job_id, A.user);
  assert.equal((await hstate(A)).check_job_id, null);
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('converge: the claim leaves a converge row without allowConverge (source-keyed, in one statement); a script row is claimed either way', async () => {
  const [A] = await cworld(1);
  const row = cjob(A);
  await registry.createJob(row, copts(A));
  assert.equal(await registry.markDispatched(row.job_id, A.hosts[0], 'c-no'), null);
  assert.equal(await registry.markDispatched(row.job_id, A.hosts[0], 'c-no', { allowConverge: false }), null);
  const left = (await pool.query('SELECT conn_id, dispatch IS NOT NULL AS pending FROM cp_sysscript_jobs WHERE job_id = $1', [row.job_id])).rows[0];
  assert.deepEqual([left.conn_id, left.pending], [null, true]);
  const claimed = await registry.markDispatched(row.job_id, A.hosts[0], 'c-yes', { allowConverge: true });
  assert.equal(claimed.dispatch.kind, 'converge');
  const plain = jobRow(A);
  await registry.createJob(plain);
  assert.equal((await registry.markDispatched(plain.job_id, A.hosts[0], 'c-plain')).dispatch.script, 'print(1)');
});

test('converge: an apply\'s expectPlanSha must equal the locked plan\'s hash (409 plan_stale, plan not consumed)', async () => {
  const [A] = await cworld(1);
  const p = await csubmit(registry, A, 'plan');
  await cfinish(registry, p, creport('plan', { drift: 1 }));
  await assert.rejects(csubmit(registry, A, 'apply', {}, { conv: { planRunId: p.job_id, expectPlanSha: '0'.repeat(64) } }),
    (e) => e.status === 409 && e.code === 'plan_stale');
  await assert.rejects(csubmit(registry, A, 'apply', {}, { conv: { planRunId: p.job_id, expectPlanSha: '-' } }), (e) => e.code === 'bad_job');
  await assert.rejects(csubmit(registry, A, 'check', {}, { conv: { expectPlanSha: 'c'.repeat(64) } }), (e) => e.code === 'bad_job');
  const plan = (await pool.query('SELECT consumed_by_run_id FROM cp_converge_runs WHERE run_id = $1', [p.job_id])).rows[0];
  assert.equal(plan.consumed_by_run_id, null);
  assert.equal((await hstate(A)).last_apply_run_id, null);
  const ap = await csubmit(registry, A, 'apply', {}, { conv: { planRunId: p.job_id } });
  assert.equal((await pool.query('SELECT consumed_by_run_id FROM cp_converge_runs WHERE run_id = $1', [p.job_id])).rows[0].consumed_by_run_id, ap.job_id);
});

test('retention: the check run of a pruned job is waited for when another transaction holds it, never left orphaned', async () => {
  const [A] = await cworld(1);
  const j = await csubmit(registry, A);
  await cfinish(registry, j, creport('check'));
  await pool.query("UPDATE cp_sysscript_jobs SET finished_at = now() - interval '400 days' WHERE job_id = $1", [j.job_id]);
  const x = await pool.connect();
  try {
    await x.query('BEGIN');
    await x.query('SELECT 1 FROM cp_converge_runs WHERE run_id = $1 FOR UPDATE', [j.job_id]);
    const prune = registry.pruneJobs(30);
    await new Promise((resolve) => setTimeout(resolve, 300));
    await x.query('COMMIT');
    assert.ok(await prune >= 1);
  } finally {
    x.release();
  }
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM cp_sysscript_jobs WHERE job_id = $1', [j.job_id])).rows[0].n, 0);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM cp_converge_runs WHERE run_id = $1', [j.job_id])).rows[0].n, 0, 'no orphan run');
});

test('converge: a second reportless check in a row waits the whole interval', async () => {
  const [A] = await cworld(1);
  const due = async () => (await pool.query('SELECT extract(epoch FROM next_check_at - now())::float8 AS s FROM cp_host_state WHERE host_id = $1 AND state_id = $2',
    [A.hosts[0], A.st.state_id])).rows[0].s;
  const j1 = await csubmit(registry, A);
  await registry.transitionJob(j1.job_id, A.hosts[0], ['submitted'], { status: 'failed', error: 'bad_payload' });
  const first = await due();
  assert.ok(first > 0.9 * 600 - 5 && first < 1.1 * 600 + 5, `first: ${first} s`);
  const j2 = await csubmit(registry, A);
  await registry.transitionJob(j2.job_id, A.hosts[0], ['submitted'], { status: 'failed', error: 'bad_payload' });
  assert.ok(await due() > 0.9 * 3600 - 5, 'second: one interval');
});

test('converge: a 429 does not burn the plan; approval, single consumption and the manual apply record', async () => {
  const [A] = await cworld(1, 'tag');
  await registry.setHostTags({ tenantId: A.tenant, hostId: A.hosts[0], tags: ['web'], actor: A.user });
  await registry.addMember(A.tenant, `${A.user}-2`, 'admin');
  const p = await csubmit(registry, A, 'plan');
  await cfinish(registry, p, creport('plan', { drift: 1 }));
  const applyOpts = { conv: { planRunId: p.job_id } };
  await assert.rejects(csubmit(registry, A, 'apply', {}, applyOpts), (e) => e.code === 'approval_required');
  await assert.rejects(registry.approvePlan({ tenantIds: [A.tenant], runId: p.job_id, actor: A.user }), (e) => e.code === 'self_approval');
  assert.equal((await registry.approvePlan({ tenantIds: [A.tenant], runId: p.job_id, actor: `${A.user}-2` })).approved_by, `${A.user}-2`);
  const filler = await csubmit(registry, A);
  await assert.rejects(csubmit(registry, A, 'apply', {}, { ...applyOpts, caps: { hostCap: 1 } }), (e) => e.status === 429);
  const plan = (await pool.query('SELECT consumed_by_run_id, bundle_json FROM cp_converge_runs WHERE run_id = $1', [p.job_id])).rows[0];
  assert.equal(plan.consumed_by_run_id, null);
  assert.equal(plan.bundle_json, CONV_BUNDLE);
  assert.equal((await hstate(A)).last_apply_run_id, null);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM cp_converge_runs WHERE plan_run_id = $1", [p.job_id])).rows[0].n, 0);
  await cfinish(registry, filler, creport('check', { drift: 1 }));
  // Two applies racing for one plan: exactly one wins (the other sees the
  // apply in flight on the row).
  const tries = await Promise.allSettled([csubmit(registry, A, 'apply', {}, applyOpts), csubmit(registry, A, 'apply', {}, applyOpts)]);
  assert.equal(tries.filter((x) => x.status === 'fulfilled').length, 1);
  assert.ok(['plan_consumed', 'apply_in_progress'].includes(tries.find((x) => x.status === 'rejected').reason.code));
  const ap = tries.find((x) => x.status === 'fulfilled').value;
  const done = await cfinish(registry, ap, creport('apply', { changed: 1 }));
  assert.equal(done.converge.status, 'compliant');
  const row = await hstate(A);
  assert.equal(row.manual_apply_assignment_id, A.a.assignment_id);
  assert.equal(row.manual_apply_version_id, A.v.version_id);
  assert.equal(row.last_applied_version_id, A.v.version_id);
  const actions = (await pool.query("SELECT action FROM cp_audit WHERE tenant_id = $1 AND action LIKE 'state_%' ORDER BY seq", [A.tenant])).rows.map((r) => r.action);
  for (const a of ['state_create', 'state_publish', 'state_assign', 'state_approve', 'state_report']) assert.ok(actions.includes(a), a);
});

test('converge: claimDueChecks holds the per-tenant cap exactly across two registries and skips stale or incapable agents', async () => {
  const [A, B] = await cworld(2, 'tenant');
  for (const t of [A, B]) {
    for (let i = 0; i < 8; i += 1) {
      const hostId = crypto.randomUUID();
      await registry.enroll({ tenantId: t.tenant, userId: t.user, keyId: `k${t.tenant.slice(1)}`, hostId, hostname: `x${i}.${t.tenant}`, os: '', platform: '', sshPubkey: opensshEd25519(40 + i) });
      t.hosts.push(hostId);
    }
  }
  const enrolledAt = new Date();
  for (const t of [A, B]) {
    for (const [i, h] of t.hosts.entries()) {
      await registry.setAgentPresence(h, { caps: i === 1 ? ['sysscript_jobs'] : ['sysscript_jobs', 'converge'], instance: 'i1', connId: `c-${h}`, enrolledAt });
    }
  }
  await pool.query("UPDATE cp_hosts SET agent_seen_at = now() - interval '5 minutes' WHERE host_id = $1", [A.hosts[2]]);
  await pool.query("UPDATE cp_host_state SET next_check_at = now() - interval '1 second' WHERE tenant_id = ANY($1::text[])", [[A.tenant, B.tenant]]);
  const pool2 = new Pool({ connectionString: withDatabase(BASE, DB) });
  try {
    const other = new PgRegistry(pool2, { NODE_ENV: 'production' });
    const opts = { replicaBudget: 50, perTenantCap: 3, claimExpiryS: 420 };
    const runs = await Promise.all(Array.from({ length: 6 }, (_, i) => (i % 2 ? other : registry).claimDueChecks(opts)));
    const claimed = runs.flat().filter((r) => r.tenant_id === A.tenant || r.tenant_id === B.tenant);
    const per = (t) => claimed.filter((r) => r.tenant_id === t.tenant);
    assert.equal(per(A).length, 3);
    assert.equal(per(B).length, 3);
    assert.equal(new Set(claimed.map((r) => `${r.host_id}/${r.state_id}`)).size, claimed.length, 'never double-claimed');
    assert.ok(claimed.every((r) => r.host_id !== A.hosts[1] && r.host_id !== A.hosts[2] && r.host_id !== B.hosts[1]));
    // Releasing one claim makes room for exactly one more.
    await registry.releaseCheckClaim(per(A)[0].host_id, A.st.state_id, { retryInS: 0 });
    const more = (await Promise.all([registry.claimDueChecks(opts), other.claimDueChecks(opts)])).flat().filter((r) => r.tenant_id === A.tenant);
    assert.equal(more.length, 1);
    // A claim moves next_check_at to its expiry.
    assert.ok(claimed.every((r) => r.next_check_at.getTime() - r.check_claimed_at.getTime() === 420000));
    // Real expiry: B's six unclaimed rows claimed with a 1 s expiry are due
    // again 1 s later and reclaimed (a replica budget of 2 held); B's three
    // 420 s claims are not. A's rows are moved out of the way.
    await pool.query("UPDATE cp_host_state SET next_check_at = now() + interval '1 hour' WHERE tenant_id = $1", [A.tenant]);
    const short = { replicaBudget: 50, perTenantCap: 100, claimExpiryS: 1 };
    const s1 = (await registry.claimDueChecks(short)).filter((r) => r.tenant_id === B.tenant);
    assert.equal(s1.length, 6);
    assert.deepEqual((await registry.claimDueChecks(short)).filter((r) => r.tenant_id === B.tenant), []);
    // A conflict row that has an assignment (a resource-key clash) is claimable.
    await pool.query("UPDATE cp_host_state SET status = 'conflict' WHERE host_id = $1 AND state_id = $2", [s1[0].host_id, B.st.state_id]);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const s2 = (await other.claimDueChecks({ ...short, replicaBudget: 2 })).filter((r) => r.tenant_id === B.tenant);
    assert.equal(s2.length, 2);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const s3 = (await registry.claimDueChecks(short)).filter((r) => r.tenant_id === B.tenant);
    assert.deepEqual(s3.map((r) => r.host_id).sort(), s1.map((r) => r.host_id).sort(), 'every 1 s claim, the conflict row included, comes back; the 420 s claims do not');
    // Stale after three missed intervals.
    await pool.query("UPDATE cp_host_state SET status = 'compliant', last_check_at = now() - interval '4 hours' WHERE host_id = $1", [A.hosts[3]]);
    assert.ok(await registry.markStaleHostStates() >= 1);
    assert.equal((await hstate(A, 3)).status, 'stale');
  } finally {
    await pool2.end();
  }
});

test('converge: the audit chain verifies after concurrent assignment, tag, check and approval activity', async () => {
  const ts = await cworld(6, 'tag');
  await Promise.all(ts.map((t) => registry.setHostTags({ tenantId: t.tenant, hostId: t.hosts[0], tags: ['web'], actor: t.user })));
  const jobs = await Promise.all(ts.map((t) => csubmit(registry, t)));
  await Promise.all([
    ...ts.map((t, i) => cfinish(registry, jobs[i], creport('check', { drift: i % 2 }))),
    ...ts.map((t) => registry.createAssignment({ tenantId: t.tenant, stateId: t.st.state_id, versionId: t.v.version_id, actor: t.user, targetKind: 'tag', targetValue: 'db' })),
    ...ts.map((t) => registry.setHostTags({ tenantId: t.tenant, hostId: t.hosts[1], tags: ['web', 'db'], actor: t.user }))
  ]);
  for (const t of ts) assert.equal((await hstate(t, 1)).status, 'conflict');
  const verdict = await registry.verifyAudit();
  assert.equal(verdict.ok, true, JSON.stringify(verdict));
});

test('converge: a sweep finalizing runs in reverse host order never deadlocks against syncHostStates or updateAssignment', async () => {
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  // Two converge jobs whose job_id order is the reverse of their host order,
  // and a key-ordered lock (what syncHostStatesInTx takes) held on the lower
  // host while the sweep runs.
  {
    const [A] = await cworld(1, 'tenant');
    const [lo, hi] = [...A.hosts].sort();
    const jHi = cjob(A, 'check', { job_id: `sjb_A${crypto.randomBytes(16).toString('base64url').slice(0, 21)}`, host_id: hi, deadline_at: new Date(Date.now() + 800) });
    const jLo = cjob(A, 'check', { job_id: `sjb_B${crypto.randomBytes(16).toString('base64url').slice(0, 21)}`, host_id: lo, deadline_at: new Date(Date.now() + 800) });
    for (const j of [jHi, jLo]) await registry.createJob(j, copts(A));
    await sleep(1000);
    const x = await pool.connect();
    try {
      await x.query('BEGIN');
      await x.query('SELECT 1 FROM cp_host_state WHERE host_id = $1 FOR UPDATE', [lo]);
      const sweep = registry.sweepJobs(Date.now(), { graceMs: 0 });
      await sleep(400);
      await x.query('SELECT 1 FROM cp_host_state WHERE tenant_id = $1 ORDER BY host_id, state_id FOR UPDATE', [A.tenant]);
      await x.query('COMMIT');
      const ended = await sweep;
      assert.deepEqual(ended.filter((j) => j.job_id === jHi.job_id || j.job_id === jLo.job_id).length, 2);
    } finally {
      x.release();
    }
    for (const h of [lo, hi]) {
      const row = (await pool.query('SELECT check_job_id FROM cp_host_state WHERE host_id = $1', [h])).rows[0];
      assert.equal(row.check_job_id, null);
    }
  }
  // The real race, repeated: sweep, updateAssignment and syncHostStates on one tenant.
  for (let k = 0; k < 10; k += 1) {
    const [W] = await cworld(1, 'tenant');
    for (let i = 0; i < 4; i += 1) {
      const hostId = crypto.randomUUID();
      await registry.enroll({ tenantId: W.tenant, userId: W.user, keyId: `k${W.tenant.slice(1)}`, hostId, hostname: `r${i}.${W.tenant}`, os: '', platform: '', sshPubkey: opensshEd25519(60 + i) });
      W.hosts.push(hostId);
    }
    for (const h of W.hosts) await registry.createJob(cjob(W, 'check', { host_id: h, deadline_at: new Date(Date.now() + 600) }), copts(W));
    await pool.query("UPDATE cp_host_state SET status = 'compliant', last_check_at = now() - interval '10 days' WHERE tenant_id = $1", [W.tenant]);
    await sleep(700);
    const res = await Promise.allSettled([
      registry.sweepJobs(Date.now(), { graceMs: 0 }),
      registry.updateAssignment({ tenantId: W.tenant, assignmentId: W.a.assignment_id, patch: { driftThreshold: 2 }, actor: W.user }),
      registry.syncHostStates(W.tenant),
      registry.markStaleHostStates()
    ]);
    assert.deepEqual(res.filter((r) => r.status === 'rejected').map((r) => r.reason.code), [], `round ${k}`);
  }
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('converge: across two registries, one apply at a time per host state, none beside a check, no check or plan beside an apply', async () => {
  const [A] = await cworld(1);
  const pool2 = new Pool({ connectionString: withDatabase(BASE, DB) });
  try {
    const other = new PgRegistry(pool2, { NODE_ENV: 'production' });
    const plans = [];
    for (let i = 0; i < 2; i += 1) {
      const p = await csubmit(registry, A, 'plan');
      await cfinish(registry, p, creport('plan', { drift: 1 }));
      plans.push(p);
    }
    const chk = await csubmit(other, A, 'check', {}, { conv: { bundleJson: CONV_BUNDLE } });
    await assert.rejects(csubmit(registry, A, 'apply', {}, { conv: { planRunId: plans[0].job_id } }), (e) => e.code === 'check_in_progress');
    await cfinish(other, chk, creport('check', { drift: 1 }));
    const res = await Promise.allSettled(plans.map((p, i) => csubmit(i ? other : registry, A, 'apply', {}, { conv: { planRunId: p.job_id } })));
    assert.equal(res.filter((r) => r.status === 'fulfilled').length, 1);
    assert.equal(res.find((r) => r.status === 'rejected').reason.code, 'apply_in_progress');
    const loser = plans[res.findIndex((r) => r.status === 'rejected')];
    assert.equal((await pool.query('SELECT consumed_by_run_id FROM cp_converge_runs WHERE run_id = $1', [loser.job_id])).rows[0].consumed_by_run_id, null);
    await assert.rejects(csubmit(other, A, 'check'), (e) => e.code === 'apply_in_progress');
    await assert.rejects(csubmit(registry, A, 'plan'), (e) => e.code === 'apply_in_progress');
    await assert.rejects(registry.createJob(cjob(A), copts(A, 'check', { bundleJson: '{"v":1}' })), (e) => e.code === 'bad_job');
    // Not claimable while the apply is in flight.
    await registry.setAgentPresence(A.hosts[0], { caps: ['converge'], instance: 'i', connId: 'cz', enrolledAt: new Date() });
    await pool.query("UPDATE cp_host_state SET next_check_at = now() - interval '1 second' WHERE host_id = $1", [A.hosts[0]]);
    assert.equal((await other.claimDueChecks({ replicaBudget: 50, perTenantCap: 50, claimExpiryS: 420 })).filter((r) => r.host_id === A.hosts[0]).length, 0);
    await cfinish(registry, res.find((r) => r.status === 'fulfilled').value, creport('apply', { changed: 1 }));
    await pool.query("UPDATE cp_host_state SET next_check_at = now() - interval '1 second' WHERE host_id = $1", [A.hosts[0]]);
    assert.equal((await other.claimDueChecks({ replicaBudget: 50, perTenantCap: 50, claimExpiryS: 420 })).filter((r) => r.host_id === A.hosts[0]).length, 1);
  } finally {
    await pool2.end();
  }
});

test('boot: three replicas running createRegistry at once on a fresh database, and on a migrated one, all succeed', async () => {
  const admin = new Pool({ connectionString: BASE });
  const quiet = { log() {}, warn() {}, error() {} };
  for (const scenario of ['fresh', 'migrated']) {
    for (let round = 0; round < 3; round += 1) {
      const name = `boot_${scenario}_${crypto.randomBytes(5).toString('hex')}`;
      await admin.query(`CREATE DATABASE ${name}`);
      const errors = [];
      const pools = [0, 1, 2].map(() => {
        const p = new Pool({ connectionString: withDatabase(BASE, name), max: 2 });
        p.on('error', (err) => errors.push(err.message));
        return p;
      });
      try {
        if (scenario === 'migrated') await createRegistry({ pool: pools[0], env: { NODE_ENV: 'production' }, logger: quiet });
        const out = await Promise.allSettled(pools.map((p) => createRegistry({ pool: p, env: { NODE_ENV: 'production' }, logger: quiet })));
        assert.deepEqual(out.map((r) => (r.status === 'fulfilled' ? 'ok' : `${r.reason.code} ${r.reason.message}`)), ['ok', 'ok', 'ok'], `${scenario} ${round}`);
        assert.ok(out.every((r) => r.value instanceof PgRegistry));
        // The session boot lock is not left held.
        const held = await pools[0].query("SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND classid = 1396789321 AND objid = 2");
        assert.equal(held.rows[0].n, 0);
        assert.deepEqual(errors, []);
      } finally {
        for (const p of pools) await p.end();
        await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      }
    }
  }
  await admin.end();
});

test('converge: markStaleHostStates skips rows another transaction holds and never waits on them', async () => {
  const [A] = await cworld(1, 'tenant');
  await pool.query("UPDATE cp_host_state SET status = 'compliant', last_check_at = now() - interval '10 days' WHERE tenant_id = $1", [A.tenant]);
  const [lo, hi] = [...A.hosts].sort();
  const x = await pool.connect();
  try {
    await x.query('BEGIN');
    await x.query('SELECT 1 FROM cp_host_state WHERE host_id = $1 FOR UPDATE', [lo]);
    await registry.markStaleHostStates();
    const st = async (h) => (await pool.query('SELECT status FROM cp_host_state WHERE host_id = $1', [h])).rows[0].status;
    assert.equal(await st(hi), 'stale');
    assert.equal(await st(lo), 'compliant', 'held: left for the next tick');
    await x.query('COMMIT');
  } finally {
    x.release();
  }
  await registry.markStaleHostStates();
  assert.equal((await pool.query('SELECT status FROM cp_host_state WHERE host_id = $1', [lo])).rows[0].status, 'stale');
});

test('boot: the boot lock itself is waited for past the lock timeout (another replica booting), and no lock_timeout is left behind', async () => {
  const quiet = { log() {}, warn() {}, error() {} };
  const env = { NODE_ENV: 'production', SYSTEMAPI_BOOT_LOCK_TIMEOUT_MS: '100' };
  const name = `bootadv_${crypto.randomBytes(5).toString('hex')}`;
  const admin = new Pool({ connectionString: BASE });
  await admin.query(`CREATE DATABASE ${name}`);
  const p = new Pool({ connectionString: withDatabase(BASE, name), max: 3 });
  p.on('error', () => {});
  const holder = new Pool({ connectionString: withDatabase(BASE, name), max: 1 });
  holder.on('error', () => {});
  try {
    await createRegistry({ pool: p, env, logger: quiet });
    const h = await holder.connect();
    try {
      await h.query('SELECT pg_advisory_lock(1396789321, 2)');
      const t0 = Date.now();
      const boot = createRegistry({ pool: p, env, logger: quiet });
      // Held for far longer than 5 attempts x 100 ms would allow.
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await h.query('SELECT pg_advisory_unlock(1396789321, 2)');
      assert.ok((await boot) instanceof PgRegistry);
      assert.ok(Date.now() - t0 >= 1500, 'it waited for the boot lock');
    } finally {
      h.release();
    }
    const c = await p.connect();
    try {
      assert.equal((await c.query('SHOW lock_timeout')).rows[0].lock_timeout, '0');
    } finally {
      c.release();
    }
  } finally {
    await p.end();
    await holder.end();
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await admin.end();
  }
});

test('boot: a table lock held by a long transaction fails the boot after bounded retries, and a boot retrying succeeds once it is released', async () => {
  const quiet = { log() {}, warn() {}, error() {} };
  const env = { NODE_ENV: 'production', SYSTEMAPI_BOOT_LOCK_TIMEOUT_MS: '100' };
  const name = `bootlk_${crypto.randomBytes(5).toString('hex')}`;
  const admin = new Pool({ connectionString: BASE });
  await admin.query(`CREATE DATABASE ${name}`);
  const p = new Pool({ connectionString: withDatabase(BASE, name), max: 3 });
  p.on('error', () => {});
  const holder = new Pool({ connectionString: withDatabase(BASE, name), max: 1 });
  holder.on('error', () => {});
  try {
    await createRegistry({ pool: p, env, logger: quiet });
    const h = await holder.connect();
    try {
      await h.query('BEGIN');
      // An open write transaction on cp_hosts (boot ALTERs it: ADD COLUMN IF NOT EXISTS).
      await h.query('LOCK TABLE cp_hosts IN ROW EXCLUSIVE MODE');
      const t0 = Date.now();
      await assert.rejects(createRegistry({ pool: p, env, logger: quiet }), (e) => e.code === '55P03');
      assert.ok(Date.now() - t0 < 10000, 'bounded');
      // Released while a boot is retrying: that boot succeeds.
      const boot = createRegistry({ pool: p, env, logger: quiet });
      await new Promise((resolve) => setTimeout(resolve, 250));
      await h.query('COMMIT');
      assert.ok((await boot) instanceof PgRegistry);
    } finally {
      h.release();
    }
    // No pooled connection keeps the boot lock_timeout or the boot lock.
    const c = await p.connect();
    try {
      assert.equal((await c.query('SHOW lock_timeout')).rows[0].lock_timeout, '0');
    } finally {
      c.release();
    }
    const held = await p.query("SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND classid = 1396789321 AND objid = 2");
    assert.equal(held.rows[0].n, 0);
  } finally {
    await p.end();
    await holder.end();
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await admin.end();
  }
});

test('upsertSoftwareBatch writes a whole inventory in one statement and returns only the new rows', async () => {
  const { normalizeSoftwareInventory } = require('../controlplane/software');
  const host = '33333333-3333-4333-8333-333333333333';
  const { items } = normalizeSoftwareInventory(Array.from({ length: 1500 }, (_, i) => ({ name: `pkg${i}`, version: '1.0', architecture: 'amd64' })));
  const added = await registry.upsertSoftwareBatch(host, items);
  assert.equal(added.length, 1500);
  const before = await pool.query('SELECT max(last_detected_at) AS t FROM cp_software WHERE host_id = $1', [host]);
  assert.deepEqual(await registry.upsertSoftwareBatch(host, items), [], 'a resent list adds nothing');
  const after = await pool.query('SELECT count(*)::int AS n, max(last_detected_at) AS t FROM cp_software WHERE host_id = $1', [host]);
  assert.equal(after.rows[0].n, 1500);
  assert.ok(after.rows[0].t >= before.rows[0].t, 'the resend refreshes last_detected_at');
  const more = normalizeSoftwareInventory([...items, { name: 'pkg0', version: '2.0', architecture: 'amd64' }]).items;
  assert.deepEqual(await registry.upsertSoftwareBatch(host, more), [{ name: 'pkg0', version: '2.0' }]);
  assert.deepEqual(await registry.upsertSoftwareBatch(host, []), []);
});

test('setScopesAudited replaces a key\'s scopes and writes the audit row in one transaction', async () => {
  const key = `kscope${crypto.randomBytes(3).toString('hex')}`;
  await registry.setScopes(key, ['hosts:read']);
  await registry.setScopesAudited({ keyId: key, scopes: ['exec:run', 'hosts:read'], tenantId: 'acme', actor: 'user-1' });
  const rows = (await pool.query('SELECT scope FROM cp_api_scopes WHERE key_id = $1 ORDER BY scope', [key])).rows.map((r) => r.scope);
  assert.deepEqual(rows, ['exec:run', 'hosts:read']);
  const audit = (await pool.query("SELECT payload FROM cp_audit WHERE action = 'key_scopes_set' AND payload->>'key_id' = $1", [key])).rows;
  assert.equal(audit.length, 1);
  assert.deepEqual(audit[0].payload.previous_scopes, ['hosts:read']);
  // The audit insert fails after the scope rows changed: both roll back.
  const failing = new PgRegistry({
    async connect() {
      const client = await pool.connect();
      return {
        query(sql, params) {
          if (typeof sql === 'string' && sql.startsWith('INSERT INTO cp_audit')) return Promise.reject(new Error('audit down'));
          return client.query(sql, params);
        },
        release(err) { client.release(err); }
      };
    },
    query: (sql, params) => pool.query(sql, params)
  }, { NODE_ENV: 'production' });
  await assert.rejects(failing.setScopesAudited({ keyId: key, scopes: ['admin'], tenantId: 'acme', actor: 'user-1' }), /audit down/);
  const after = (await pool.query('SELECT scope FROM cp_api_scopes WHERE key_id = $1 ORDER BY scope', [key])).rows.map((r) => r.scope);
  assert.deepEqual(after, ['exec:run', 'hosts:read']);
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('setHostCapabilities writes only changed rows in one statement, keeps since on a reason change, and returns the previous state', async () => {
  const host = '44444444-4444-4444-8444-444444444444';
  let statements = 0;
  const counting = new PgRegistry({
    query: (sql, params) => { statements += 1; return pool.query(sql, params); },
    connect: () => pool.connect()
  }, { NODE_ENV: 'production' });
  const first = await counting.setHostCapabilities(host, [
    { name: 'pty', state: 'ok', reason: '' },
    { name: 'file', state: 'degraded', reason: 'enosys_openat2' },
    { name: 'package', state: 'absent', reason: 'binary_missing' }
  ]);
  assert.equal(statements, 1);
  assert.deepEqual(first.map((r) => [r.name, r.previous_state, r.state]).sort(),
    [['file', null, 'degraded'], ['package', null, 'absent'], ['pty', null, 'ok']]);
  const rowsOf = async () => (await pool.query('SELECT name, since, last_report_at FROM cp_host_capabilities WHERE host_id = $1 ORDER BY name', [host])).rows;
  const sinceOf = (rows, name) => rows.find((r) => r.name === name).since.getTime();
  const before = await rowsOf();
  // The same rows again: one statement, nothing written.
  statements = 0;
  assert.deepEqual(await counting.setHostCapabilities(host, [
    { name: 'pty', state: 'ok', reason: '' },
    { name: 'file', state: 'degraded', reason: 'enosys_openat2' }
  ]), []);
  assert.equal(statements, 1);
  assert.deepEqual(await rowsOf(), before, 'an unchanged row is not rewritten');
  await new Promise((r) => setTimeout(r, 20));
  // file: reason only (since kept); pty: state change (since moves).
  const changed = await counting.setHostCapabilities(host, [
    { name: 'file', state: 'degraded', reason: 'probe_error' },
    { name: 'pty', state: 'degraded', reason: 'probe_error' }
  ]);
  assert.deepEqual(changed.map((r) => [r.name, r.previous_state, r.state, r.reason]).sort(),
    [['file', 'degraded', 'degraded', 'probe_error'], ['pty', 'ok', 'degraded', 'probe_error']]);
  const after = await rowsOf();
  assert.equal(sinceOf(after, 'file'), sinceOf(before, 'file'));
  assert.ok(sinceOf(after, 'pty') > sinceOf(before, 'pty'));
  const listed = await registry.listHostCapabilities(host);
  assert.deepEqual(listed.map((r) => [r.name, r.state, r.reason]).sort(),
    [['file', 'degraded', 'probe_error'], ['package', 'absent', 'binary_missing'], ['pty', 'degraded', 'probe_error']]);
  assert.deepEqual(await counting.setHostCapabilities(host, []), []);
  // The table refuses what the validator refuses.
  await assert.rejects(registry.setHostCapabilities(host, [{ name: 'file', state: 'broken', reason: '' }]));
  await assert.rejects(registry.setHostCapabilities(host, [{ name: 'Bad Name', state: 'ok', reason: '' }]));
  // clearAgentPresence leaves capability rows alone.
  await registry.clearAgentPresence(host, 'conn-x');
  assert.equal((await registry.listHostCapabilities(host)).length, 3);
});

test('capability alerts: one active alert per host and rule across registries (the partial index), audit in the same transaction, retired hosts skipped', async () => {
  const H = '77777777-7777-4777-8777-777777777777';
  const R = '88888888-8888-4888-8888-888888888888';
  const base = { tenantId: 'acme', userId: 'user-1', keyId: 'k1', os: '', platform: '' };
  await registry.enroll({ ...base, hostId: H, hostname: 'cap.example', sshPubkey: opensshEd25519(8) });
  await registry.enroll({ ...base, hostId: R, hostname: 'gone.example', sshPubkey: opensshEd25519(9) });
  const other = new PgRegistry(pool, { NODE_ENV: 'production' });
  const audit = { rule: 'capability:file', capability: 'file', state: 'degraded', reason: 'enosys_openat2' };
  const entry = { host_id: H, rule_name: 'capability:file', severity: 'warning', message: 'file degraded (enosys_openat2)', actor: 'system:capability', audit };
  const auditCount = async (action) => (await pool.query('SELECT count(*)::int AS n FROM cp_audit WHERE action = $1 AND host_id = $2', [action, H])).rows[0].n;

  // Eight concurrent opens from two registries: one row, one audit row.
  const outs = await Promise.all(Array.from({ length: 8 }, (_, i) => (i % 2 ? other : registry).openHostAlert(entry)));
  const made = outs.filter(Boolean);
  assert.equal(made.length, 1);
  assert.equal(made[0].tenant_id, 'acme', 'tenant read from cp_hosts');
  const active = async (rule) => (await pool.query(
    "SELECT id, status FROM cp_alert_events WHERE host_id = $1 AND rule_name = $2 AND status IN ('open', 'ack')", [H, rule])).rows;
  assert.equal((await active('capability:file')).length, 1);
  assert.equal(await auditCount('capability_alert_open'), 1);
  // ack still counts as active.
  await registry.setAlertStatus(['acme'], made[0].id, 'ack');
  assert.equal(await registry.openHostAlert(entry), null);
  // A plain INSERT of a second active row is refused by the index itself.
  await assert.rejects(pool.query(
    "INSERT INTO cp_alert_events (tenant_id, host_id, rule_name, status) VALUES ('acme', $1, 'capability:file', 'open')", [H]), /cp_alert_events_active_capability_idx/);
  // host:offline is covered too; other rules (anomaly, sysscript) are not.
  const offline = { ...entry, rule_name: 'host:offline', audit: { ...audit, rule: 'host:offline', capability: null } };
  assert.equal(await registry.openHostAlert(offline), null, 'host:offline never opens for a host that is online');
  await registry.setHostStatus(H, 'offline');
  assert.ok(await registry.openHostAlert(offline));
  assert.equal(await other.openHostAlert(offline), null);
  await pool.query("INSERT INTO cp_alert_events (tenant_id, host_id, rule_name, status) VALUES ('acme', $1, 'zscore:cpu', 'open'), ('acme', $1, 'zscore:cpu', 'open')", [H]);

  // Resolve: both rules in one transaction with one audit row each; again is a no-op.
  const resolved = await other.resolveHostAlerts(H, [
    { rule: 'capability:file', capability: 'file', state: 'ok', reason: '' },
    { rule: 'host:offline', capability: null, state: 'online', reason: 'reconnected' }
  ], 'system:capability');
  assert.deepEqual(resolved.map((x) => x.rule_name).sort(), ['capability:file', 'host:offline']);
  assert.equal(await auditCount('capability_alert_resolve'), 2);
  assert.deepEqual(await registry.resolveHostAlerts(H, [{ rule: 'capability:file' }], 'system:capability'), []);
  const payload = (await pool.query(
    "SELECT payload FROM cp_audit WHERE action = 'capability_alert_resolve' AND host_id = $1 AND payload->>'rule' = 'capability:file'", [H])).rows[0].payload;
  assert.deepEqual(payload, { alert_id: Number(made[0].id), rule: 'capability:file', capability: 'file', state: 'ok', reason: '' });
  // After a resolve, a new episode opens a new row.
  assert.ok(await registry.openHostAlert(entry));

  // A failing audit insert rolls the alert back (fail closed).
  await pool.query(`CREATE FUNCTION test_refuse_cap_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit refused by test'; END $$`);
  await pool.query('CREATE TRIGGER test_refuse_cap_audit BEFORE INSERT ON cp_audit FOR EACH ROW EXECUTE FUNCTION test_refuse_cap_audit()');
  try {
    await assert.rejects(registry.openHostAlert({ ...entry, rule_name: 'capability:tcp', audit: { ...audit, rule: 'capability:tcp' } }), /audit refused/);
    assert.equal((await active('capability:tcp')).length, 0);
    await assert.rejects(registry.resolveHostAlerts(H, [{ rule: 'capability:file', capability: 'file', state: 'ok', reason: '' }], 'a'), /audit refused/);
    assert.equal((await active('capability:file')).length, 1, 'resolve rolled back');
  } finally {
    await pool.query('DROP TRIGGER test_refuse_cap_audit ON cp_audit');
    await pool.query('DROP FUNCTION test_refuse_cap_audit()');
  }

  // A retired host gets no alert; a bad rule never reaches SQL.
  await registry.retireHost({ tenantId: 'acme', hostId: R, actor: 'u', reason: 'gone' });
  assert.equal(await registry.openHostAlert({ ...entry, host_id: R }), null);
  await assert.rejects(registry.openHostAlert({ ...entry, rule_name: "capability:x'; DROP TABLE cp_audit; --" }), (e) => e.code === 'bad_alert_rule');
  // The drift index is untouched.
  const idx = (await pool.query("SELECT indexdef FROM pg_indexes WHERE indexname = 'cp_alert_events_active_drift_idx'")).rows[0].indexdef;
  assert.match(idx, /rule_name ~~ 'drift:%'/);
  assert.equal((await registry.verifyAudit()).ok, true);
});

test('capability gauges from the database: health counts and state rows, retired hosts left out', async () => {
  const H = '99999999-9999-4999-8999-999999999999';
  const base = { tenantId: 'gauge', userId: 'user-g', keyId: 'kg', os: '', platform: '' };
  const empty = await registry.countHostHealth();
  await registry.enroll({ ...base, hostId: H, hostname: 'g.example', sshPubkey: opensshEd25519(10) });
  const before = await registry.countHostHealth();
  assert.equal(before.unknown, empty.unknown + 1, 'an enrolled host without a written health counts as unknown');
  await registry.setAgentPresence(H, { caps: [], instance: 'gauge-i', connId: 'gauge-i:1', enrolledAt: new Date() });
  assert.equal(await registry.setHostHealth(H, 'degraded', 'gauge-i'), true);
  await registry.setHostCapabilities(H, [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }]);
  const during = await registry.countHostHealth();
  assert.equal(during.degraded, before.degraded + 1);
  assert.equal(during.unknown, before.unknown - 1);
  assert.ok((await registry.listCapabilityStates()).some((r) => r.host_id === H && r.name === 'file' && r.state === 'degraded'));
  await assert.rejects(registry.setHostHealth(H, 'offline', 'gauge-i'), (e) => e.code === 'bad_health');
  await assert.rejects(pool.query("UPDATE cp_hosts SET capability_health = 'great' WHERE host_id = $1", [H]));
  await registry.setHostStatus(H, 'offline');
  assert.equal((await registry.countHostHealth()).offline, before.offline + 1);
  await registry.retireHost({ tenantId: 'gauge', hostId: H, actor: 'u', reason: 'gone' });
  assert.deepEqual(await registry.countHostHealth(), empty, 'a retired host is not counted');
  assert.equal((await registry.listCapabilityStates()).some((r) => r.host_id === H), false);
});

test('capability health: written only by the instance on the presence row, cleared with offline and on retire; boot releases its own rows', async () => {
  const H = 'aaaaaaa1-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
  const O = 'aaaaaaa2-aaaa-4aaa-8aaa-aaaaaaaaaaa2';
  const base = { tenantId: 'health', userId: 'user-h', keyId: 'kh', os: '', platform: '' };
  await registry.enroll({ ...base, hostId: H, hostname: 'h1.example', sshPubkey: opensshEd25519(11) });
  await registry.enroll({ ...base, hostId: O, hostname: 'h2.example', sshPubkey: opensshEd25519(12) });
  const row = async (id = H) => (await pool.query(
    'SELECT status, capability_health, agent_instance, agent_conn_id FROM cp_hosts WHERE host_id = $1', [id])).rows[0];
  assert.equal(await registry.setHostHealth(H, 'ok', 'cp-a'), false, 'no presence row: no write');
  await registry.setAgentPresence(H, { caps: [], instance: 'cp-a', connId: 'cp-a:1', enrolledAt: new Date() });
  assert.equal(await registry.setHostHealth(H, 'ok', 'cp-b'), false, 'another instance cannot write');
  assert.equal(await registry.setHostHealth(H, 'ok', null), false);
  assert.equal((await row()).capability_health, null);
  assert.equal(await registry.setHostHealth(H, 'ok', 'cp-a'), true);
  assert.equal((await row()).capability_health, 'ok');
  // The fleet list and resolve carry the column for the badge.
  assert.equal((await registry.listHosts(['health'])).find((h) => h.host_id === H).capability_health, 'ok');
  assert.equal((await registry.resolveHosts(['health'], 'h1.example'))[0].capability_health, 'ok');
  await registry.setHostStatus(H, 'online');
  assert.equal((await row()).capability_health, 'ok', 'online keeps it');
  await registry.setHostStatus(H, 'offline');
  assert.equal((await row()).capability_health, null, 'offline clears it');

  // Boot (controlplane/index.js) with a stable SYSTEMAPI_INSTANCE_ID marks
  // the rows that instance held offline before it accepts sockets.
  await registry.setHostStatus(H, 'online');
  assert.equal(await registry.setHostHealth(H, 'degraded', 'cp-a'), true);
  await registry.setAgentPresence(O, { caps: [], instance: 'cp-other', connId: 'cp-other:1', enrolledAt: new Date() });
  await registry.setHostStatus(O, 'online');
  assert.equal(await registry.setHostHealth(O, 'ok', 'cp-other'), true);
  const { boot } = require('../controlplane/index');
  const fleet = { db: pool, jobs: { instanceId: 'random', listen() {} } };
  const logs = [];
  await boot(fleet, { NODE_ENV: 'production', SYSTEMAPI_INSTANCE_ID: 'cp-a' }, { log: (m) => logs.push(m), warn() {}, error() {} });
  clearInterval(fleet.scheduleTimer);
  assert.equal(fleet.jobs.instanceId, 'cp-a');
  assert.deepEqual(await row(), { status: 'offline', capability_health: null, agent_instance: null, agent_conn_id: null });
  assert.deepEqual(await row(O), { status: 'online', capability_health: 'ok', agent_instance: 'cp-other', agent_conn_id: 'cp-other:1' }, 'another instance\'s rows are untouched');
  assert.ok(logs.some((m) => /1 host\(s\)/.test(m)));
  assert.equal(await registry.releaseInstanceHosts(''), 0);

  // Retire clears it too, and resolves the host's capability and offline
  // alerts in the same transaction with a retired resolve audit row each.
  const entry = (rule, capability) => ({
    host_id: O, rule_name: rule, severity: 'warning', message: 'm', actor: 'system:capability',
    audit: { rule, capability, state: 'degraded', reason: 'probe_error' }
  });
  assert.ok(await registry.openHostAlert(entry('capability:file', 'file')));
  assert.ok(await registry.openHostAlert(entry('capability:reports', null)));
  await pool.query("INSERT INTO cp_alert_events (tenant_id, host_id, rule_name, status) VALUES ('health', $1, 'zscore:cpu', 'open')", [O]);
  await registry.retireHost({ tenantId: 'health', hostId: O, actor: 'admin-1', reason: 'gone', forced: true });
  assert.equal((await row(O)).capability_health, null);
  const alerts = (await pool.query('SELECT rule_name, status FROM cp_alert_events WHERE host_id = $1 ORDER BY rule_name', [O])).rows;
  assert.deepEqual(alerts.map((a) => [a.rule_name, a.status]), [['capability:file', 'resolved'], ['capability:reports', 'resolved'], ['zscore:cpu', 'open']]);
  const audits = (await pool.query(
    "SELECT actor, payload FROM cp_audit WHERE host_id = $1 AND action = 'capability_alert_resolve' ORDER BY payload->>'rule'", [O])).rows;
  assert.deepEqual(audits.map((a) => [a.actor, a.payload.rule, a.payload.capability, a.payload.state, a.payload.reason]), [
    ['admin-1', 'capability:file', 'file', 'retired', 'retired'],
    ['admin-1', 'capability:reports', null, 'retired', 'retired']
  ]);
  assert.equal((await registry.verifyAudit()).ok, true);

  // A failing resolve audit rolls the whole retire back (fail closed).
  const R = 'aaaaaaa3-aaaa-4aaa-8aaa-aaaaaaaaaaa3';
  await registry.enroll({ ...base, hostId: R, hostname: 'h3.example', sshPubkey: opensshEd25519(13) });
  await registry.setHostStatus(R, 'offline');
  assert.ok(await registry.openHostAlert({ ...entry('host:offline', null), host_id: R }));
  await pool.query(`CREATE FUNCTION test_refuse_resolve_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.action = 'capability_alert_resolve' THEN RAISE EXCEPTION 'resolve audit refused by test'; END IF; RETURN NEW; END $$`);
  await pool.query('CREATE TRIGGER test_refuse_resolve_audit BEFORE INSERT ON cp_audit FOR EACH ROW EXECUTE FUNCTION test_refuse_resolve_audit()');
  try {
    await assert.rejects(registry.retireHost({ tenantId: 'health', hostId: R, actor: 'admin-1', reason: 'gone' }), /resolve audit refused/);
  } finally {
    await pool.query('DROP TRIGGER test_refuse_resolve_audit ON cp_audit');
    await pool.query('DROP FUNCTION test_refuse_resolve_audit()');
  }
  const r = (await pool.query('SELECT retired_at FROM cp_hosts WHERE host_id = $1', [R])).rows[0];
  assert.equal(r.retired_at, null, 'retire rolled back');
  assert.equal((await pool.query("SELECT status FROM cp_alert_events WHERE host_id = $1 AND rule_name = 'host:offline'", [R])).rows[0].status, 'open');
});

test('host:offline: two FleetManagers on one database; a disconnect on one and a reconnect on the other inside 5 min opens nothing', async () => {
  const { rig, connectAgent, waitUntil } = require('./job-agent-rig');
  const tag = crypto.randomBytes(4).toString('hex');
  const tenant = `o${tag}`;
  const hostId = crypto.randomUUID();
  const keys = { 'pg-agent': { key_id: `ka${tag}`, user_id: `u${tag}` } };
  const regOne = new PgRegistry(pool, { NODE_ENV: 'production' });
  const regTwo = new PgRegistry(pool, { NODE_ENV: 'production' });
  listeners.push(regOne, regTwo);
  regOne.keyActive = async () => true;
  regTwo.keyActive = async () => true;
  const one = await rig({ registry: regOne, keys });
  const two = await rig({ registry: regTwo, keys });
  let clock = Date.now();
  one.fm.capAlerts.now = () => clock;
  const offlineRows = async () => (await pool.query(
    "SELECT id FROM cp_alert_events WHERE host_id = $1 AND rule_name = 'host:offline'", [hostId])).rows;
  const hostRow = async () => (await pool.query('SELECT status, agent_instance FROM cp_hosts WHERE host_id = $1', [hostId])).rows[0];
  try {
    const a = await connectAgent(one, hostId, { tenant, key: 'pg-agent' });
    await waitUntil('presence on one', async () => (await hostRow()).agent_instance === one.fm.jobs.instanceId, 8000);
    a.ws.terminate();
    await waitUntil('offline on one', async () => {
      const h = await hostRow();
      return !one.fm.connectedAgents.has(hostId) && h.status === 'offline' && h.agent_instance === null;
    }, 8000);
    assert.ok(one.fm.capAlerts.hosts.get(hostId), 'one tracks the closed host');
    clock += 60_000;
    await connectAgent(two, hostId, { tenant, key: 'pg-agent' });
    await waitUntil('presence on two', async () => (await hostRow()).agent_instance === two.fm.jobs.instanceId, 8000);
    clock += 5 * 60_000;
    await one.fm.capAlerts.tick();
    assert.deepEqual(await offlineRows(), [], 'online on the other replica: no alert');
    assert.equal(one.fm.capAlerts.hosts.has(hostId), false);
    // A late status write from one saying offline is not enough while two's
    // presence is fresh.
    await regOne.setHostStatus(hostId, 'offline');
    one.fm.capAlerts.onDisconnect(hostId);
    clock += 5 * 60_000;
    await one.fm.capAlerts.tick();
    assert.deepEqual(await offlineRows(), []);
    // With two's presence stale (its instance gone), it opens.
    await pool.query("UPDATE cp_hosts SET agent_seen_at = now() - interval '5 minutes' WHERE host_id = $1", [hostId]);
    one.fm.capAlerts.onDisconnect(hostId);
    clock += 5 * 60_000;
    await one.fm.capAlerts.tick();
    assert.equal((await offlineRows()).length, 1);
  } finally {
    await one.close();
    await two.close();
    // The closed socket's presence clear lands before the pool ends.
    await waitUntil('presence cleared', async () => (await hostRow()).agent_instance === null, 8000);
  }
});

test('audit checkpoints: one per interval across replicas, the head read under the chain lock, verified over a read-only connection', async () => {
  const anchor = require('../controlplane/anchor');
  const verify = require('../scripts/audit-anchor-verify');
  const seed = '5a'.repeat(32);
  const deployment = `pg-${crypto.randomBytes(3).toString('hex')}`;
  const signer = anchor.anchorSigner(seed);
  const sign = (f) => anchor.signNote(signer, { deployment, ...f });
  const other = new PgRegistry(pool, {});
  const nowS = Math.floor(Date.now() / 1000);
  // Appends racing two replicas' checkpoints: each checkpoint names a
  // committed tail, and only one of the two is written for the interval.
  const appends = Array.from({ length: 10 }, (_, i) => registry.appendAudit({ tenant_id: null, actor: 'pg-test', action: 'anchor_probe', payload: { i } }));
  const [a, b] = await Promise.all([
    registry.createAuditCheckpoint({ deployment, nowS, minGapS: 3600, sign }),
    other.createAuditCheckpoint({ deployment, nowS, minGapS: 3600, sign })
  ]);
  await Promise.all(appends);
  const written = [a, b].filter(Boolean);
  assert.equal(written.length, 1);
  const cp = written[0];
  const at = await pool.query('SELECT row_hash FROM cp_audit WHERE seq = $1', [cp.seq]);
  assert.equal(at.rows[0].row_hash, cp.head);
  assert.equal(await registry.createAuditCheckpoint({ deployment, nowS: nowS + 3599, minGapS: 3600, sign }), null);
  await registry.setAuditCheckpointSinks(cp.id, { sink1: 'ok', sink2: 'put_failed' });
  const stored = await pool.query('SELECT seq, head, note, sink_status FROM cp_audit_checkpoints WHERE id = $1', [cp.id]);
  assert.deepEqual(stored.rows[0].sink_status, { sink1: 'ok', sink2: 'put_failed' });
  assert.equal(Number(stored.rows[0].seq), cp.seq);
  // The anchor loop on this database, then the verifier over a read-only
  // connection: clean, then a rewrite of an anchored row is caught.
  const objects = new Map();
  const sink = {
    id: 'sink1',
    async put(key, body) { objects.set(key, { body: Buffer.from(body), lastModified: new Date((nowS + 3600) * 1000) }); },
    async list(prefix) { return [...objects].filter(([k]) => k.startsWith(prefix)).map(([key, o]) => ({ key, size: o.body.length, lastModified: o.lastModified })); },
    async get(key) { return objects.get(key).body; }
  };
  const config = { deployment, intervalS: 3600, signer };
  const a2 = new anchor.AuditAnchor({ config, registry, sinks: [sink], logger: { log() {}, error() {} }, now: () => (nowS + 3600) * 1000 });
  const fresh = await a2.checkpoint(false);
  assert.deepEqual(fresh.sink_status, { sink1: 'ok' });
  const vkey = anchor.vkeyOf(anchor.originOf(deployment), signer.publicKeyRaw);
  const env = { SYSTEMAPI_ANCHOR_VKEY: vkey, SYSTEMAPI_ANCHOR_VERIFY_DATABASE_URL: withDatabase(BASE, DB) };
  const clean = await verify.run(['--now', String(nowS + 3600)], { env, sinks: [sink] });
  assert.deepEqual(clean.reasons, []);
  // The anchored tail edited and its hash recomputed: the chain alone
  // verifies, the anchor does not match.
  const { rowHash } = require('../controlplane/chain');
  const original = (await pool.query('SELECT * FROM cp_audit WHERE seq = $1', [fresh.seq])).rows[0];
  const edited = { ...original, payload: { i: 'edited' } };
  await pool.query('UPDATE cp_audit SET payload = $2::jsonb, row_hash = $3 WHERE seq = $1',
    [fresh.seq, JSON.stringify(edited.payload), rowHash(original.prev_hash, edited)]);
  try {
    assert.equal((await registry.verifyAudit()).ok, true);
    const caught = await verify.run(['--now', String(nowS + 3600)], { env, sinks: [sink] });
    assert.deepEqual(caught.reasons.map((r) => r.code), ['anchor_rewrite']);
  } finally {
    await pool.query('UPDATE cp_audit SET payload = $2::jsonb, row_hash = $3 WHERE seq = $1',
      [fresh.seq, JSON.stringify(original.payload), original.row_hash]);
  }
  assert.equal((await registry.verifyAudit()).ok, true);
});
