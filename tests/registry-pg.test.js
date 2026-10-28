'use strict';

// PgRegistry against a real PostgreSQL: the enroll upsert, and the fleet's
// agent-key lookup (expiry and the optional tenant binding), and the
// channel-policy CLI's single-transaction write, and the sysscript job methods (cross-tenant
// getJob/listJobs/requestJobCancel/transitionJob, atomic caps, NOTIFY only after COMMIT, a
// two-registry dispatch claim, and two FleetManagers dispatching, waiting and cancelling across
// instances through LISTEN/NOTIFY). A fresh database per run with the schema applied by
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
    assert.equal((await registry.verifyAudit()).ok, true);
  } finally {
    await one.close();
    await two.close();
  }
});
