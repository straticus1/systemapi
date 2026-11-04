'use strict';

// scripts/create-tenant.js against PgRegistry.createTenant on a recording
// fake client (no database). tests/create-tenant-pg.test.js runs the same
// path against a real PostgreSQL.

const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');

const { PgRegistry, MemoryRegistry } = require('../controlplane/registry');
const { fingerprint } = require('../controlplane/token');
const { run, parseArgs, ACTOR } = require('../scripts/create-tenant');

const ARGV = ['--tenant', 'afterdark-test', '--admin', 'ryan', '--agent-member', 'sahtest1-agent'];

function fakePool({ adminExists = true, agentExists = false, priorIdentity = 0, tenantExists = false, auditFails = false } = {}) {
  const state = { log: [], audit: [], members: [], keys: [], scopes: [], tenants: [], committed: false, rolledBack: false };
  const client = {
    async query(sql, params = []) {
      const s = sql.replace(/\s+/g, ' ').trim();
      state.log.push({ s, params });
      if (s === 'BEGIN' || s.includes('pg_advisory_xact_lock')) return { rows: [], rowCount: 0 };
      if (s === 'COMMIT') { state.committed = true; return { rows: [], rowCount: 0 }; }
      if (s === 'ROLLBACK') { state.rolledBack = true; return { rows: [], rowCount: 0 }; }
      if (s.startsWith("SELECT 1 FROM cp_members WHERE user_id = $1 AND role = 'admin'")) {
        return { rows: adminExists ? [{}] : [], rowCount: adminExists ? 1 : 0 };
      }
      if (s.startsWith('SELECT 1 FROM cp_members WHERE user_id = $1 LIMIT 1')) {
        return { rows: agentExists ? [{}] : [], rowCount: agentExists ? 1 : 0 };
      }
      if (s.startsWith('SELECT (SELECT count(*) FROM playground_api_keys WHERE user_id = $1)')) {
        return { rows: [{ n: String(priorIdentity) }], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO cp_tenants')) {
        if (tenantExists) return { rows: [], rowCount: 0 };
        state.tenants.push({ tenant_id: params[0], owner_user_id: params[1] });
        return { rows: [{ tenant_id: params[0] }], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO cp_members')) {
        state.members.push({ tenant_id: params[0], user_id: params[1], role: 'admin' }, { tenant_id: params[0], user_id: params[2], role: 'viewer' });
        return { rows: [], rowCount: 2 };
      }
      if (s.startsWith('INSERT INTO playground_api_keys')) {
        state.keys.push({ key_id: params[0], key_hash: params[1], user_id: params[2], name: params[3], api_site: params[4], tenant_id: params[9], allowed_endpoints: params[8] });
        return { rows: [], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO cp_api_scopes')) {
        state.scopes.push({ key_id: params[0] });
        return { rows: [], rowCount: 1 };
      }
      if (s.startsWith('SELECT row_hash FROM cp_audit')) {
        const last = state.audit[state.audit.length - 1];
        return { rows: last ? [{ row_hash: last.row_hash }] : [], rowCount: last ? 1 : 0 };
      }
      if (s.startsWith('INSERT INTO cp_audit')) {
        if (auditFails) throw Object.assign(new Error('audit insert failed'), { code: '57014' });
        const row = { prev_hash: params[0], row_hash: params[1], tenant_id: params[2], actor: params[4], action: params[5], payload: JSON.parse(params[6]) };
        state.audit.push(row);
        return { rows: [row], rowCount: 1 };
      }
      throw new Error(`unexpected query: ${s.slice(0, 80)}`);
    },
    release() {}
  };
  return { state, async connect() { return client; } };
}

async function create(argv, poolOpts) {
  const pool = fakePool(poolOpts);
  const registry = new PgRegistry(pool, {});
  return { pool, result: await run(argv, { registry, pool }) };
}

function assertNothingWritten(state) {
  assert.equal(state.committed, false);
  assert.equal(state.rolledBack, true);
  assert.equal(state.audit.length, 0);
}

test('parseArgs refuses missing, unknown, repeated and malformed arguments', () => {
  const bad = [
    [],
    ['--tenant', 'afterdark-test', '--admin', 'ryan'],
    ['--tenant', 'afterdark-test', '--agent-member', 'a1'],
    ['--admin', 'ryan', '--agent-member', 'a1'],
    [...ARGV, '--role', 'admin'],
    [...ARGV, '--tenant', 'other'],
    [...ARGV, '--key-name'],
    ['--tenant', 'AfterDark_Test', '--admin', 'ryan', '--agent-member', 'a1'],
    ['--tenant', 'afterdark-test', '--admin', '-ryan', '--agent-member', 'a1'],
    ['--tenant', 'afterdark-test', '--admin', 'ryan', '--agent-member', 'oidc:abc'],
    ['--tenant', 'afterdark-test', '--admin', 'ryan', '--agent-member', 'ryan'],
    [...ARGV, '--key-name', '']
  ];
  for (const argv of bad) assert.throws(() => parseArgs(argv), (err) => err.code === 'usage', argv.join(' '));
  assert.deepEqual(parseArgs(ARGV), {
    tenantId: 'afterdark-test', adminUserId: 'ryan', agentUserId: 'sahtest1-agent', keyName: 'afterdark-test-agent'
  });
});

test('creates the tenant, admin and viewer agent members, a tenant-bound key with no scopes, and one audit row', async () => {
  const { pool, result } = await create(ARGV);
  const { state } = pool;
  const { summary, apiKey } = result;
  assert.equal(state.committed, true);
  assert.equal(state.rolledBack, false);
  assert.deepEqual(summary, { tenant_id: 'afterdark-test', admin_user_id: 'ryan', agent_user_id: 'sahtest1-agent', key_id: summary.key_id });
  assert.match(apiKey, /^ak_live_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32}$/);
  assert.equal(apiKey.split('.')[0], summary.key_id);
  assert.deepEqual(state.tenants, [{ tenant_id: 'afterdark-test', owner_user_id: 'ryan' }]);
  assert.deepEqual(state.members, [
    { tenant_id: 'afterdark-test', user_id: 'ryan', role: 'admin' },
    { tenant_id: 'afterdark-test', user_id: 'sahtest1-agent', role: 'viewer' }
  ]);
  assert.equal(state.keys.length, 1);
  const key = state.keys[0];
  assert.equal(key.user_id, 'sahtest1-agent', 'the key belongs to the agent member, not the admin');
  assert.equal(key.tenant_id, 'afterdark-test', 'the key is bound to the tenant');
  assert.equal(key.api_site, 'systemapi');
  assert.deepEqual(key.allowed_endpoints, [], 'an empty allowlist: refused on every /playground route');
  assert.ok(await bcrypt.compare(apiKey, key.key_hash));
  assert.deepEqual(state.scopes, [], 'the key has no scope rows');
  assert.equal(state.audit.length, 1);
  assert.equal(state.audit[0].actor, ACTOR);
  assert.equal(state.audit[0].action, 'tenant_create');
  assert.equal(state.audit[0].tenant_id, 'afterdark-test');
  assert.deepEqual(state.audit[0].payload, {
    admin_user_id: 'ryan',
    agent_user_id: 'sahtest1-agent',
    agent_role: 'viewer',
    key_fp: fingerprint(summary.key_id),
    key_tenant: 'afterdark-test',
    scopes: []
  });
});

test('the plaintext key reaches the database only as its bcrypt hash', async () => {
  const { pool, result } = await create(ARGV);
  const secretPart = result.apiKey.split('.')[1];
  for (const { params } of pool.state.log) {
    for (const p of params) assert.ok(!String(p).includes(secretPart), 'a query parameter carries the secret');
  }
  assert.ok(!JSON.stringify(result.summary).includes(secretPart));
  assert.ok(!JSON.stringify(pool.state.audit).includes(secretPart));
});

test('refused when the admin is not an admin member anywhere; no key is minted', async () => {
  const pool = fakePool({ adminExists: false });
  await assert.rejects(run(ARGV, { registry: new PgRegistry(pool, {}), pool }), (err) => err.status === 403 && err.code === 'admin_required');
  assert.equal(pool.state.keys.length, 0);
  assert.equal(pool.state.tenants.length, 0);
  assertNothingWritten(pool.state);
});

test('refused when the agent member already belongs to a tenant', async () => {
  const pool = fakePool({ agentExists: true });
  await assert.rejects(run(ARGV, { registry: new PgRegistry(pool, {}), pool }), (err) => err.status === 409 && err.code === 'agent_member_exists');
  assert.equal(pool.state.keys.length, 0);
  assertNothingWritten(pool.state);
});

test('refused when the agent id already holds a key or an OAuth grant', async () => {
  const pool = fakePool({ priorIdentity: 1 });
  await assert.rejects(run(ARGV, { registry: new PgRegistry(pool, {}), pool }), (err) => err.status === 409 && err.code === 'agent_identity_exists');
  assert.equal(pool.state.tenants.length, 0);
  assert.equal(pool.state.keys.length, 0);
  assertNothingWritten(pool.state);
});

test('refused when the tenant exists; no members or key are written', async () => {
  const pool = fakePool({ tenantExists: true });
  await assert.rejects(run(ARGV, { registry: new PgRegistry(pool, {}), pool }), (err) => err.status === 409 && err.code === 'tenant_exists');
  assert.equal(pool.state.members.length, 0);
  assert.equal(pool.state.keys.length, 0);
  assertNothingWritten(pool.state);
});

test('a failed audit insert rolls the whole creation back', async () => {
  const pool = fakePool({ auditFails: true });
  await assert.rejects(run(ARGV, { registry: new PgRegistry(pool, {}), pool }), /audit insert failed/);
  assertNothingWritten(pool.state);
});

test('the registry refuses an agent member equal to the admin even without the CLI check', async () => {
  const pool = fakePool();
  await assert.rejects(
    new PgRegistry(pool, {}).createTenant({ tenantId: 't', adminUserId: 'ryan', agentUserId: 'ryan', actor: ACTOR, mintKey: async () => ({}) }),
    (err) => err.status === 400 && err.code === 'agent_is_admin'
  );
  assert.equal(pool.state.log.length, 0);
});

test('the memory registry is refused: keys need the database', async () => {
  await assert.rejects(
    run(ARGV, { registry: new MemoryRegistry({}), pool: null }),
    (err) => err.code === 'registry_unavailable'
  );
});
