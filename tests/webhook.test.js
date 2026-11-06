'use strict';

// Webhook SSRF guard (controlplane/webhook.js over playground/egress.js): the
// URL is refused at create time on its literal host and its DNS answer, and
// every delivery connects only to a checked address, never following a
// redirect.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { assertWebhookURL, resolveWebhookURL } = require('../controlplane/webhook');
const { deliverWebhooks } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const { sealSecret } = require('../controlplane/seal');

const PROD = { NODE_ENV: 'production' };
const DEV = { NODE_ENV: 'test' };
const KEY = 'cd'.repeat(32);
const answer = (address) => (host, opts, cb) => cb(null, [{ address, family: address.includes(':') ? 6 : 4 }]);

test('create time: 127.0.0.1, 169.254.169.254, 10.x, [::1] and names resolving to them are refused in production', async () => {
  for (const u of ['https://127.0.0.1/h', 'https://169.254.169.254/latest', 'https://10.0.0.5/h', 'https://[::1]/h',
    'https://192.168.1.10/h', 'https://172.16.0.1/h', 'https://[fd00::1]/h', 'https://[::ffff:10.0.0.1]/h', 'https://localhost/h']) {
    assert.throws(() => assertWebhookURL(u, PROD), /blocked_url/, u);
  }
  for (const addr of ['127.0.0.1', '169.254.169.254', '10.1.2.3', '::1', 'fe80::1']) {
    await assert.rejects(resolveWebhookURL('https://hooks.example/in', PROD, answer(addr)), /blocked_url/, addr);
  }
  // One blocked address in the answer is enough.
  await assert.rejects(resolveWebhookURL('https://hooks.example/in', PROD,
    (h, o, cb) => cb(null, [{ address: '93.184.215.14', family: 4 }, { address: '10.0.0.1', family: 4 }])), /blocked_url/);
  // A name that does not resolve is refused (fail closed).
  await assert.rejects(resolveWebhookURL('https://nx.example/in', PROD, (h, o, cb) => cb(Object.assign(new Error('nx'), { code: 'ENOTFOUND' }))),
    /unresolvable_url/);
  assert.equal((await resolveWebhookURL('https://hooks.example/in', PROD, answer('93.184.215.14'))).hostname, 'hooks.example');
});

test('outside production loopback and private stay allowed (as before); metadata and link-local never are', async () => {
  assert.equal(assertWebhookURL('http://127.0.0.1:9/h', DEV).hostname, '127.0.0.1');
  assert.equal(assertWebhookURL('http://10.0.0.5/h', DEV).hostname, '10.0.0.5');
  for (const u of ['http://169.254.169.254/latest', 'https://[fe80::1]/h', 'https://metadata.google.internal/x']) {
    assert.throws(() => assertWebhookURL(u, DEV), /blocked_url/, u);
  }
  await assert.rejects(resolveWebhookURL('http://hooks.example/in', DEV, answer('169.254.169.254')), /blocked_url/);
});

async function receiver(handler) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}

async function fleetWith(env, url, egressResolve) {
  const registry = new MemoryRegistry(DEV);
  await registry.createWebhook({ id: 'wh_1', tenant_id: 'acme', url, secret: sealSecret('s3cret', { SYSTEMAPI_WEBHOOK_KEY: KEY }),
    secret_fingerprint: 'f', created_at: new Date().toISOString() });
  return { registry, env: { ...env, SYSTEMAPI_WEBHOOK_KEY: KEY }, egressResolve };
}

// Captures console.error lines until one matches.
function errorsUntil(re) {
  const seen = [];
  const orig = console.error;
  let resolveSeen;
  const found = new Promise((r) => { resolveSeen = r; });
  console.error = (...args) => {
    const line = args.join(' ');
    seen.push(line);
    if (re.test(line)) resolveSeen(line);
  };
  return { seen, found, restore() { console.error = orig; } };
}

test('delivery: a name that rebinds to loopback after create time is refused at connect; nothing reaches the receiver', async () => {
  let hits = 0;
  const hook = await receiver((req, res) => { hits += 1; res.end('ok'); });
  let calls = 0;
  const rebind = (host, opts, cb) => { calls += 1; cb(null, [{ address: calls === 1 ? '93.184.215.14' : '127.0.0.1', family: 4 }]); };
  const url = `https://rebind.example:${hook.port}/in`;
  await resolveWebhookURL(url, PROD, rebind); // create time: public
  const fleet = await fleetWith(PROD, url, rebind);
  const log = errorsUntil(/webhook delivery failed/);
  try {
    await deliverWebhooks(fleet, 'acme', { event: 'x' });
    const line = await log.found;
    assert.match(line, /blocked_address/);
  } finally { log.restore(); }
  assert.equal(hits, 0);
  assert.equal(calls, 2, 'one lookup per connection, the delivery one refused');
  await hook.close();
});

test('delivery: stored URLs that the current rules refuse are not sent (169.254.169.254, production 10.x and 127.0.0.1)', async () => {
  for (const url of ['https://169.254.169.254/latest', 'https://10.0.0.5/in', 'https://127.0.0.1/in']) {
    const fleet = await fleetWith(PROD, url);
    const log = errorsUntil(/webhook target refused/);
    try {
      await deliverWebhooks(fleet, 'acme', { event: 'x' });
      assert.match(await log.found, /blocked_url/, url);
    } finally { log.restore(); }
  }
});

test('delivery: a redirect is not followed (even to an address the rules allow)', async () => {
  let targetHits = 0;
  const target = await receiver((req, res) => { targetHits += 1; res.end('ok'); });
  let hookHits = 0;
  const hook = await receiver((req, res) => {
    hookHits += 1;
    res.writeHead(302, { location: `http://127.0.0.1:${target.port}/latest/meta-data/` });
    res.end();
  });
  const fleet = await fleetWith(DEV, `http://127.0.0.1:${hook.port}/in`);
  try {
    await deliverWebhooks(fleet, 'acme', { event: 'x' });
    for (let i = 0; i < 50 && hookHits === 0; i += 1) await new Promise((r) => setTimeout(r, 20));
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(hookHits, 1);
    assert.equal(targetHits, 0);
  } finally {
    await hook.close();
    await target.close();
  }
});
