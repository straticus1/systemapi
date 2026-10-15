'use strict';

// The playground schema files are applied at every boot (createRegistry), so
// they must be idempotent, and a failure must be fatal in production.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { createRegistry, PgRegistry, MemoryRegistry } = require('../controlplane/registry');

const ROOT = path.join(__dirname, '..');
const CP = fs.readFileSync(path.join(ROOT, 'controlplane', 'schema.sql'), 'utf8');
const KEYS = fs.readFileSync(path.join(ROOT, 'playground', 'playground_schema.sql'), 'utf8');
const FLEET = fs.readFileSync(path.join(ROOT, 'playground', 'playground_fleet_schema.sql'), 'utf8');
const quiet = { log() {}, warn() {}, error() {} };

function fakePool(failOn = null) {
  const seen = [];
  return {
    seen,
    async query(sql) {
      seen.push(sql);
      if (failOn && sql === failOn) throw new Error('permission denied for table playground_credits');
      return { rows: [], rowCount: 0 };
    }
  };
}

test('createRegistry applies the control-plane schema, then the playground keys schema, then the fleet schema', async () => {
  const pool = fakePool();
  const registry = await createRegistry({ pool, env: { NODE_ENV: 'production' }, logger: quiet });
  assert.ok(registry instanceof PgRegistry);
  assert.deepEqual(pool.seen, [CP, KEYS, FLEET]);
});

test('a playground schema failure is fatal in production', async () => {
  for (const failOn of [KEYS, FLEET]) {
    const pool = fakePool(failOn);
    await assert.rejects(
      createRegistry({ pool, env: { NODE_ENV: 'production' }, logger: quiet }),
      /permission denied/
    );
  }
});

test('outside production a playground schema failure falls back to the memory registry', async () => {
  const pool = fakePool(KEYS);
  const registry = await createRegistry({ pool, env: { NODE_ENV: 'development' }, logger: quiet });
  assert.ok(registry instanceof MemoryRegistry);
});

function statements(sql) {
  return sql.replace(/--.*$/gm, '').split(';').map((s) => s.trim()).filter(Boolean);
}

test('every playground CREATE is safe to run twice', () => {
  for (const [name, sql] of [['playground_schema.sql', KEYS], ['playground_fleet_schema.sql', FLEET]]) {
    const body = sql.replace(/--.*$/gm, '');
    for (const m of body.matchAll(/CREATE\s+(UNIQUE\s+)?(TABLE|INDEX)\s+(?!IF NOT EXISTS)(\S+)/gi)) {
      assert.fail(`${name}: CREATE ${m[2]} ${m[3]} lacks IF NOT EXISTS`);
    }
    for (const m of body.matchAll(/CREATE\s+(?!OR REPLACE)FUNCTION\s+(\S+)/gi)) {
      assert.fail(`${name}: CREATE FUNCTION ${m[1]} lacks OR REPLACE`);
    }
    const stmts = statements(sql);
    stmts.forEach((stmt, i) => {
      const m = /^CREATE\s+TRIGGER\s+(\S+)\s+.*?\bON\s+(\S+)/is.exec(stmt);
      if (!m) return;
      const drop = new RegExp(`^DROP TRIGGER IF EXISTS ${m[1]} ON ${m[2]}$`, 'i');
      assert.ok(i > 0 && drop.test(stmts[i - 1]), `${name}: trigger ${m[1]} is not dropped first`);
    });
  }
});

test('playground_hosts.key_id has the same type as playground_api_keys.key_id', () => {
  const keyType = /CREATE TABLE IF NOT EXISTS playground_api_keys \([\s\S]*?\n\s*key_id\s+([A-Z]+(?:\(\d+\))?)/.exec(KEYS);
  const hostType = /CREATE TABLE IF NOT EXISTS playground_hosts \([\s\S]*?\n\s*key_id\s+([A-Z]+(?:\(\d+\))?)/.exec(FLEET);
  assert.ok(keyType && hostType);
  assert.equal(hostType[1], keyType[1]);
});

test('the playground trigger function is namespaced, and the generic name is neither created nor dropped', () => {
  const body = KEYS.replace(/--.*$/gm, '');
  const created = [...body.matchAll(/CREATE\s+OR\s+REPLACE\s+FUNCTION\s+(\w+)/gi)].map((m) => m[1]);
  for (const name of created) assert.match(name, /playground/, `function ${name} is not namespaced`);
  const used = [...body.matchAll(/EXECUTE\s+FUNCTION\s+(\w+)/gi)].map((m) => m[1]);
  assert.ok(used.length >= 2);
  for (const name of used) assert.equal(name, 'playground_set_updated_at');
  assert.doesNotMatch(body, /update_updated_at_column/);
  assert.doesNotMatch(body, /DROP\s+FUNCTION/i);
});
