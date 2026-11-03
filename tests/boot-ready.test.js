'use strict';

// Boot waits for a database that is not accepting connections yet (a host
// reboot races PostgreSQL's start), up to SYSTEMAPI_BOOT_DB_WAIT_MS, and
// fails at once on anything else; GET /ready is 503 until boot set the
// registry.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { createRegistry, PgRegistry } = require('../controlplane/registry');
const { mount } = require('../controlplane/router');

const quiet = { log() {}, warn() {}, error() {} };

function dbError(code, message = code) {
  const err = new Error(message);
  err.code = code;
  return err;
}

// connect() throws failures[i] on attempt i, then succeeds.
function flakyPool(failures) {
  const pool = {
    connects: 0,
    async query() { return { rows: [], rowCount: 0 }; },
    async connect() {
      const err = failures[pool.connects];
      pool.connects += 1;
      if (err) throw err;
      return { query: async () => ({ rows: [], rowCount: 0 }), release() {} };
    }
  };
  return pool;
}

function warnLog() {
  const lines = [];
  return { lines, log() {}, error() {}, warn(line) { lines.push(line); } };
}

const PROD = (extra = {}) => ({ NODE_ENV: 'production', SYSTEMAPI_BOOT_DB_WAIT_MS: '5000', ...extra });

test('boot retries a refused connection and a starting-up database, then succeeds', async () => {
  for (const code of ['ECONNREFUSED', '57P03', 'ECONNRESET', 'EAI_AGAIN']) {
    const pool = flakyPool([dbError(code), dbError(code)]);
    const logger = warnLog();
    const reg = await createRegistry({ pool, env: PROD(), logger });
    assert.ok(reg instanceof PgRegistry, code);
    assert.equal(pool.connects, 3, code);
    assert.equal(logger.lines.length, 2, `${code}: one line per retry`);
    assert.match(logger.lines[0], new RegExp(`database not ready \\(${code}\\)`));
  }
});

test('boot fails at once on errors that waiting cannot fix', async () => {
  for (const code of ['28P01', '3D000', 'ENOTFOUND', '42P01']) {
    const pool = flakyPool([dbError(code)]);
    await assert.rejects(createRegistry({ pool, env: PROD(), logger: quiet }), (err) => err.code === code);
    assert.equal(pool.connects, 1, `${code} is not retried`);
  }
});

test('boot gives up when the database stays down past the wait', async () => {
  const pool = flakyPool(Array.from({ length: 100 }, () => dbError('ECONNREFUSED')));
  const started = Date.now();
  await assert.rejects(
    createRegistry({ pool, env: PROD({ SYSTEMAPI_BOOT_DB_WAIT_MS: '600' }), logger: quiet }),
    (err) => err.code === 'ECONNREFUSED'
  );
  assert.ok(Date.now() - started < 3000, 'stops near the wait, not after 100 attempts');
  assert.ok(pool.connects >= 2 && pool.connects < 10);
});

test('a wait of 0 disables the retry; a bad value falls back to the default without hanging the test', async () => {
  const pool = flakyPool([dbError('ECONNREFUSED')]);
  await assert.rejects(createRegistry({ pool, env: PROD({ SYSTEMAPI_BOOT_DB_WAIT_MS: '0' }), logger: quiet }));
  assert.equal(pool.connects, 1);
  const ok = flakyPool([dbError('ECONNREFUSED')]);
  assert.ok(await createRegistry({ pool: ok, env: PROD({ SYSTEMAPI_BOOT_DB_WAIT_MS: 'lots' }), logger: quiet }) instanceof PgRegistry);
});

test('the boot lock timeout keeps its own attempt limit', async () => {
  const pool = flakyPool(Array.from({ length: 10 }, () => dbError('55P03')));
  await assert.rejects(
    createRegistry({ pool, env: PROD({ SYSTEMAPI_BOOT_LOCK_TIMEOUT_MS: '50' }), logger: quiet }),
    (err) => err.code === '55P03'
  );
  assert.equal(pool.connects, 5);
});

test('GET /ready is 503 until the registry is set, then 200; no detail either way', async () => {
  const app = express();
  const fleet = { registry: null, env: { NODE_ENV: 'test' } };
  mount(app, fleet);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const get = () => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: server.address().port, path: '/ready' }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(body), cache: res.headers['cache-control'] }));
    }).on('error', reject);
  });
  try {
    assert.deepEqual(await get(), { status: 503, body: { ready: false }, cache: 'no-store' });
    fleet.registry = {};
    assert.deepEqual(await get(), { status: 200, body: { ready: true }, cache: 'no-store' });
  } finally {
    server.close();
  }
});
