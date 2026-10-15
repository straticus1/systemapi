'use strict';

// scripts/bootstrap-admin.js against PgRegistry.bootstrapAdmin on a
// recording fake client (no database). tests/bootstrap-pg.test.js runs the
// same path against a real PostgreSQL.

const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');

const { PgRegistry } = require('../controlplane/registry');
const { fingerprint } = require('../controlplane/token');
const { run, parseArgs, ACTOR } = require('../scripts/bootstrap-admin');

const SUB = 'f3a9c1d2e4b5a6978877665544332211aabbccddeeff00112233445566778899';

function fakePool({ adminMembers = 0, adminKeys = 0, subTaken = false } = {}) {
  const state = { log: [], audit: [], members: [], keys: [], scopes: [], committed: false, rolledBack: false };
  const client = {
    async query(sql, params = []) {
      const s = sql.replace(/\s+/g, ' ').trim();
      state.log.push({ s, params });
      if (s === 'BEGIN' || s.includes('pg_advisory_xact_lock')) return { rows: [], rowCount: 0 };
      if (s === 'COMMIT') { state.committed = true; return { rows: [], rowCount: 0 }; }
      if (s === 'ROLLBACK') { state.rolledBack = true; return { rows: [], rowCount: 0 }; }
      if (s.includes("count(*) FROM cp_members WHERE role = 'admin'")) {
        return { rows: [{ members: adminMembers, keys: adminKeys }], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO cp_tenants')) return { rows: [{ tenant_id: params[0] }], rowCount: 1 };
      if (s.startsWith('SELECT role FROM cp_members')) return { rows: [], rowCount: 0 };
      if (s.startsWith('INSERT INTO cp_members')) {
        state.members.push({ tenant_id: params[0], user_id: params[1], email: params[2] });
        return { rows: [], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO playground_api_keys')) {
        state.keys.push({ key_id: params[0], key_hash: params[1], user_id: params[2], name: params[3], api_site: params[4] });
        return { rows: [], rowCount: 1 };
      }
      if (s.startsWith('INSERT INTO cp_api_scopes')) {
        state.scopes.push({ key_id: params[0], scope: 'admin' });
        return { rows: [], rowCount: 1 };
      }
      if (s.startsWith('SELECT row_hash FROM cp_audit')) {
        const last = state.audit[state.audit.length - 1];
        return { rows: last ? [{ row_hash: last.row_hash }] : [], rowCount: last ? 1 : 0 };
      }
      if (s.startsWith('INSERT INTO cp_audit')) {
        const row = { prev_hash: params[0], row_hash: params[1], tenant_id: params[2], actor: params[4], action: params[5], payload: JSON.parse(params[6]) };
        state.audit.push(row);
        return { rows: [row], rowCount: 1 };
      }
      if (s.startsWith('SELECT sso_sub FROM cp_members')) return { rows: [{ sso_sub: null }], rowCount: 1 };
      if (s.startsWith('SELECT 1 FROM cp_members WHERE sso_sub')) return { rows: subTaken ? [{}] : [], rowCount: subTaken ? 1 : 0 };
      if (s.startsWith('SELECT 1 FROM cp_members')) return { rows: [], rowCount: 0 };
      if (s.startsWith('UPDATE cp_members SET sso_sub')) {
        state.ssoBound = { tenant_id: params[0], user_id: params[1], sub: params[2] };
        return { rows: [], rowCount: 1 };
      }
      throw new Error(`unexpected query: ${s.slice(0, 80)}`);
    },
    release() {}
  };
  return { state, async connect() { return client; } };
}

async function bootstrap(argv, poolOpts) {
  const pool = fakePool(poolOpts);
  const registry = new PgRegistry(pool, {});
  return { pool, result: await run(argv, { registry, pool }) };
}

test('parseArgs refuses missing, unknown, repeated and malformed arguments', () => {
  const bad = [
    [],
    ['--tenant', 'acme'],
    ['--member', 'ryan'],
    ['--tenant', 'acme', '--member'],
    ['--tenant', 'acme', '--member', 'ryan', '--role', 'viewer'],
    ['--tenant', 'acme', '--tenant', 'other', '--member', 'ryan'],
    ['--tenant', 'acme', '--member', 'ryan', '--force-additional', '--force-additional'],
    ['--tenant', 'Acme_Corp', '--member', 'ryan'],
    ['--tenant', 'acme', '--member', '-ryan'],
    ['--tenant', 'acme', '--member', 'ryan', '--sso-sub', 'not a sub'],
    ['--tenant', 'acme', '--member', 'ryan', '--email', 'nope'],
    ['--tenant', 'acme', '--member', 'ryan', '--key-name', '']
  ];
  for (const argv of bad) assert.throws(() => parseArgs(argv), (err) => err.code === 'usage', argv.join(' '));
  assert.deepEqual(parseArgs(['--member', 'ryan', '--tenant', 'acme']), {
    tenantId: 'acme', userId: 'ryan', email: null, sub: null, keyName: 'bootstrap-admin', force: false
  });
});

test('on an empty database: tenant, admin member, app-format key with an admin scope, and an audit row, committed', async () => {
  const { pool, result } = await bootstrap(['--tenant', 'acme', '--member', 'ryan', '--email', 'ryan@example.com']);
  const { state } = pool;
  const { summary, apiKey } = result;
  assert.equal(state.committed, true);
  assert.equal(state.rolledBack, false);
  assert.deepEqual(summary, { tenant_id: 'acme', user_id: 'ryan', key_id: summary.key_id, sso_bound: false, forced: false });
  // The app's key format: ak_live_<16>.<32>, key_id the part before the dot.
  assert.match(apiKey, /^ak_live_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32}$/);
  assert.equal(apiKey.split('.')[0], summary.key_id);
  assert.equal(state.keys.length, 1);
  const key = state.keys[0];
  assert.equal(key.key_id, summary.key_id);
  assert.equal(key.user_id, 'ryan');
  assert.equal(key.api_site, 'systemapi');
  assert.ok(await bcrypt.compare(apiKey, key.key_hash));
  assert.deepEqual(state.scopes, [{ key_id: summary.key_id, scope: 'admin' }]);
  assert.deepEqual(state.members, [{ tenant_id: 'acme', user_id: 'ryan', email: 'ryan@example.com' }]);
  assert.equal(state.audit.length, 1);
  assert.equal(state.audit[0].actor, ACTOR);
  assert.equal(state.audit[0].action, 'bootstrap_admin');
  assert.equal(state.audit[0].payload.key_fp, fingerprint(summary.key_id));
  assert.equal(state.audit[0].payload.forced, false);
  assert.equal(state.audit[0].payload.tenant_created, true);
});

test('the plaintext key reaches the database only as its bcrypt hash', async () => {
  const { pool, result } = await bootstrap(['--tenant', 'acme', '--member', 'ryan']);
  const secretPart = result.apiKey.split('.')[1];
  for (const { params } of pool.state.log) {
    for (const p of params) {
      assert.ok(!String(p).includes(secretPart), 'a query parameter carries the secret');
    }
  }
  assert.ok(!JSON.stringify(result.summary).includes(secretPart));
});

test('refused while an admin member exists; nothing is minted and the transaction rolls back', async () => {
  await assert.rejects(
    bootstrap(['--tenant', 'acme', '--member', 'ryan'], { adminMembers: 1 }),
    (err) => err.status === 409 && err.code === 'admin_exists'
  );
  const pool = fakePool({ adminMembers: 1 });
  await assert.rejects(run(['--tenant', 'acme', '--member', 'ryan'], { registry: new PgRegistry(pool, {}), pool }));
  assert.equal(pool.state.keys.length, 0);
  assert.equal(pool.state.audit.length, 0);
  assert.equal(pool.state.rolledBack, true);
  assert.equal(pool.state.committed, false);
});

test('refused while an admin-scoped key exists', async () => {
  await assert.rejects(
    bootstrap(['--tenant', 'acme', '--member', 'ryan'], { adminKeys: 1 }),
    (err) => err.code === 'admin_exists'
  );
});

test('--force-additional mints another admin and the audit row says it was forced', async () => {
  const { pool, result } = await bootstrap(['--tenant', 'acme', '--member', 'ops', '--force-additional'], { adminMembers: 1, adminKeys: 2 });
  assert.equal(result.summary.forced, true);
  const payload = pool.state.audit[0].payload;
  assert.equal(payload.forced, true);
  assert.equal(payload.existing_admin_members, 1);
  assert.equal(payload.existing_admin_keys, 2);
});

test('--sso-sub binds the admin in the same transaction, with its own sso_bind audit row', async () => {
  const { pool, result } = await bootstrap(['--tenant', 'acme', '--member', 'ryan', '--sso-sub', SUB]);
  assert.equal(result.summary.sso_bound, true);
  assert.deepEqual(pool.state.ssoBound, { tenant_id: 'acme', user_id: 'ryan', sub: SUB });
  assert.deepEqual(pool.state.audit.map((r) => r.action), ['bootstrap_admin', 'sso_bind']);
  assert.equal(pool.state.audit[1].payload.sso_sub_fp, fingerprint(SUB));
  assert.ok(!JSON.stringify(pool.state.audit).includes(SUB), 'the sub is in an audit row in clear');
  assert.equal(pool.state.committed, true);
  const commits = pool.state.log.filter((q) => q.s === 'COMMIT').length;
  assert.equal(commits, 1);
});

test('an SSO sub already bound to another member fails the whole bootstrap (no key, rolled back)', async () => {
  const pool = fakePool({ subTaken: true });
  await assert.rejects(
    run(['--tenant', 'acme', '--member', 'ryan', '--sso-sub', SUB], { registry: new PgRegistry(pool, {}), pool }),
    (err) => err.code === 'sso_sub_taken'
  );
  assert.equal(pool.state.rolledBack, true);
  assert.equal(pool.state.committed, false);
});

test('the memory registry is refused: keys need the database', async () => {
  const { MemoryRegistry } = require('../controlplane/registry');
  await assert.rejects(
    run(['--tenant', 'acme', '--member', 'ryan'], { registry: new MemoryRegistry({}), pool: null }),
    (err) => err.code === 'registry_unavailable'
  );
});
