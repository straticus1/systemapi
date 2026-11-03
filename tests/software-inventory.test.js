'use strict';

// The software inventory the agent sends with every 5 s telemetry tick:
// normalizeSoftwareInventory (controlplane/software.js) bounds and dedupes
// it, and FleetManager.processSoftwareInventory writes it once per change (or
// per SOFTWARE_REFRESH_MS), in one batch, never twice at once for a host.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const FleetManager = require('../playground/fleet');
const { MemoryRegistry } = require('../controlplane/registry');
const {
  normalizeSoftwareInventory, SOFTWARE_MAX_ITEMS, SOFTWARE_FIELD_MAX, SOFTWARE_MAX_CONCURRENT, SOFTWARE_MIN_WRITE_GAP_MS
} = require('../controlplane/software');

// Moves the host's last write back past the per-host write gap.
function pastGap(fm, host = HOST) {
  fm.softwareSeen.get(host).writtenAt -= SOFTWARE_MIN_WRITE_GAP_MS;
}

const HOST = '11111111-1111-4111-8111-111111111111';
const LIST = [
  { name: 'openssl', version: '3.0.15-1', architecture: 'amd64' },
  { name: 'bash', version: '5.2.15-2', architecture: 'amd64' }
];

function fleet() {
  const fm = new FleetManager(http.createServer(), null, 'systemapi', null);
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.batches = 0;
  const batch = fm.registry.upsertSoftwareBatch.bind(fm.registry);
  fm.registry.upsertSoftwareBatch = async (hostId, items) => { fm.batches += 1; return batch(hostId, items); };
  fm.cveChecks = [];
  fm.checkDarkAPIForCVEs = async (hostId, name, version) => { fm.cveChecks.push(`${name}@${version}`); };
  test.after(() => fm.wss.close());
  return fm;
}

test('normalize sorts, dedupes on (name, version), fills defaults, and the digest ignores order', () => {
  const a = normalizeSoftwareInventory([...LIST, { name: 'bash', version: '5.2.15-2', architecture: 'i386' }, null, 'x', {}]);
  assert.deepEqual(a.items.map((i) => `${i.name}@${i.version}/${i.architecture}`),
    ['bash@5.2.15-2/amd64', 'openssl@3.0.15-1/amd64', 'unknown@unknown/']);
  const b = normalizeSoftwareInventory([{}, LIST[1], LIST[0]]);
  assert.equal(a.digest, b.digest);
  assert.notEqual(normalizeSoftwareInventory(LIST.slice(0, 1)).digest, a.digest);
});

test('normalize refuses a list over the item limit and a non-list, and skips an item with an oversized field', () => {
  const big = Array.from({ length: SOFTWARE_MAX_ITEMS + 1 }, (_, i) => ({ name: `p${i}`, version: '1' }));
  assert.throws(() => normalizeSoftwareInventory(big), /over 20000/);
  assert.throws(() => normalizeSoftwareInventory({ length: 1 }), /not a list/);
  const r = normalizeSoftwareInventory([
    { name: 'x'.repeat(SOFTWARE_FIELD_MAX + 1), version: '1' },
    { name: 'a', version: 'v'.repeat(SOFTWARE_FIELD_MAX + 1) },
    { name: 'a', version: '1', architecture: 'z'.repeat(SOFTWARE_FIELD_MAX + 1) },
    LIST[0]
  ]);
  assert.equal(r.skipped, 3);
  assert.deepEqual(r.items, [LIST[0]]);
});

test('normalize strips NUL bytes and repairs lone surrogates, so they cannot fail or collide in the statement', () => {
  const r = normalizeSoftwareInventory([
    { name: 'app\u0000', version: '1\u00002', architecture: '\u0000' },
    { name: 'x\uD800', version: '1' },
    { name: 'x\uDC00', version: '1' },
    { name: '\u0000', version: '1' }
  ]);
  assert.deepEqual(r.items.map((i) => `${i.name}@${i.version}/${i.architecture}`),
    ['app@12/', 'unknown@1/', 'x\uFFFD@1/']);
  for (const i of r.items) assert.ok(i.name.isWellFormed() && !i.name.includes('\u0000'));
});

test('an unchanged list is written once until the refresh interval, a changed one after the write gap', async () => {
  const fm = fleet();
  await fm.processSoftwareInventory(HOST, LIST);
  await fm.processSoftwareInventory(HOST, [...LIST].reverse());
  assert.equal(fm.batches, 1);
  assert.deepEqual(fm.cveChecks.sort(), ['bash@5.2.15-2', 'openssl@3.0.15-1']);
  assert.equal((await fm.registry.listSoftware(HOST)).length, 2);

  pastGap(fm);
  await fm.processSoftwareInventory(HOST, [...LIST, { name: 'curl', version: '7.88.1-10', architecture: 'amd64' }]);
  assert.equal(fm.batches, 2);
  assert.deepEqual(fm.cveChecks.slice(2), ['curl@7.88.1-10'], 'only the new package is looked up');

  fm.softwareSeen.get(HOST).refreshAt = Date.now() - 1;
  pastGap(fm);
  await fm.processSoftwareInventory(HOST, [...LIST, { name: 'curl', version: '7.88.1-10', architecture: 'amd64' }]);
  assert.equal(fm.batches, 3, 'the refresh rewrites an unchanged list');
  assert.equal(fm.cveChecks.length, 3, 'a refresh adds no lookups');
});

test('reports for a host while its write runs are dropped, not queued', async () => {
  const fm = fleet();
  let release;
  const gate = new Promise((r) => { release = r; });
  const batch = fm.registry.upsertSoftwareBatch;
  fm.registry.upsertSoftwareBatch = async (hostId, items) => { await gate; return batch(hostId, items); };
  const first = fm.processSoftwareInventory(HOST, LIST);
  for (let i = 0; i < 20; i++) await fm.processSoftwareInventory(HOST, [...LIST, { name: `p${i}`, version: '1' }]);
  release();
  await first;
  assert.equal(fm.batches, 1);
  assert.equal(fm.softwareInFlight.size, 0);
  pastGap(fm);
  await fm.processSoftwareInventory(HOST, [...LIST, { name: 'p0', version: '1' }]);
  assert.equal(fm.batches, 2, 'the host takes a new list once the write is done');
});

test('a refused or failed inventory stores nothing new, frees the host, and waits before retrying', async () => {
  const fm = fleet();
  const big = Array.from({ length: SOFTWARE_MAX_ITEMS + 1 }, (_, i) => ({ name: `p${i}`, version: '1' }));
  await assert.rejects(fm.processSoftwareInventory(HOST, big), new RegExp(`host ${HOST}: .*over 20000`));
  assert.equal(fm.batches, 0);
  assert.equal(fm.softwareInFlight.size, 0);
  await fm.processSoftwareInventory(HOST, LIST);
  assert.equal(fm.batches, 0, 'a refused host waits SOFTWARE_RETRY_MS');

  fm.softwareSeen.get(HOST).retryAt = Date.now() - 1;
  const batch = fm.registry.upsertSoftwareBatch;
  fm.registry.upsertSoftwareBatch = async () => { fm.batches += 1; throw new Error('db down'); };
  await assert.rejects(fm.processSoftwareInventory(HOST, LIST), /db down/);
  assert.equal(fm.softwareInFlight.size, 0);
  for (let i = 0; i < 5; i++) await fm.processSoftwareInventory(HOST, LIST);
  assert.equal(fm.batches, 1, 'a failing write is not retried every tick');

  fm.registry.upsertSoftwareBatch = batch;
  fm.softwareSeen.get(HOST).retryAt = Date.now() - 1;
  await fm.processSoftwareInventory(HOST, LIST);
  assert.equal((await fm.registry.listSoftware(HOST)).length, 2, 'the same list is written once the wait is over');
});

test('at most SOFTWARE_MAX_CONCURRENT inventory writes run at once across hosts', async () => {
  const fm = fleet();
  let release;
  const gate = new Promise((r) => { release = r; });
  const batch = fm.registry.upsertSoftwareBatch;
  fm.registry.upsertSoftwareBatch = async (hostId, items) => { await gate; return batch(hostId, items); };
  const hosts = Array.from({ length: SOFTWARE_MAX_CONCURRENT + 3 }, (_, i) => `host-${i}`);
  const runs = hosts.map((h) => fm.processSoftwareInventory(h, LIST));
  assert.equal(fm.softwareInFlight.size, SOFTWARE_MAX_CONCURRENT);
  release();
  await Promise.all(runs);
  assert.equal(fm.batches, SOFTWARE_MAX_CONCURRENT);
  for (const h of hosts) await fm.processSoftwareInventory(h, LIST);
  assert.equal(fm.batches, hosts.length, 'the hosts left out are written on a later tick');
});

test('CVE lookups for new packages run after the write slot is freed', async () => {
  const fm = fleet();
  let release;
  const gate = new Promise((r) => { release = r; });
  let slotsDuringLookup = null;
  fm.checkDarkAPIForCVEs = async () => { slotsDuringLookup = fm.softwareInFlight.size; await gate; };
  const first = fm.processSoftwareInventory(HOST, LIST);
  await new Promise((r) => setImmediate(r));
  assert.equal(slotsDuringLookup, 0);
  pastGap(fm);
  const second = fm.processSoftwareInventory(HOST, [...LIST, { name: 'curl', version: '1' }]);
  await new Promise((r) => setImmediate(r));
  assert.equal(fm.batches, 2, 'a changed list is written while lookups for the last one run');
  release();
  await Promise.all([first, second]);
});

test('a host whose list changes on every tick is written at most once per write gap', async () => {
  const fm = fleet();
  await fm.processSoftwareInventory(HOST, LIST);
  for (let i = 0; i < 30; i++) await fm.processSoftwareInventory(HOST, [...LIST, { name: `churn${i}`, version: '1' }]);
  assert.equal(fm.batches, 1);
  assert.equal((await fm.registry.listSoftware(HOST)).length, 2, 'no churned rows stored inside the gap');
  pastGap(fm);
  await fm.processSoftwareInventory(HOST, [...LIST, { name: 'churn-last', version: '1' }]);
  assert.equal(fm.batches, 2, 'the latest list is written once the gap has passed');
});
