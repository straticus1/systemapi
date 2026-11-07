'use strict';

// POST /playground/execute SSRF guard (playground/egress.js): the URL stays
// on the base origin, the connection reaches no internal address (checked on
// the DNS answer the socket itself uses), redirects are never followed.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const egress = require('../playground/egress');
const createPlaygroundRouter = require('../playground/router');

test('blockedAddress: loopback, private, CGNAT, link-local, metadata, ULA and IPv4-embedding IPv6 are blocked; public is not', () => {
  for (const a of ['127.0.0.1', '127.1.2.3', '10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.1', '100.64.0.1',
    '169.254.169.254', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '[::1]', '::', '::ffff:127.0.0.1',
    '::ffff:a9fe:a9fe', '::ffff:10.0.0.1', 'fe80::1', 'fe80::1%lo0', 'fd00::1', 'fc00::1', '64:ff9b::7f00:1',
    '2002:7f00:1::', '2001:0:4136:e378:8000:63bf:3fff:fdd2', 'ff02::1', 'localhost', 'not-an-ip', '']) {
    assert.equal(egress.blockedAddress(a), true, a);
  }
  for (const a of ['8.8.8.8', '1.1.1.1', '172.67.136.253', '2606:4700:4700::1111']) {
    assert.equal(egress.blockedAddress(a), false, a);
  }
  // allowPrivate admits loopback and private ranges only: link-local (metadata) and the rest stay blocked.
  for (const a of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '::1', 'fd00::1']) assert.equal(egress.blockedAddress(a, { allowPrivate: true }), false, a);
  for (const a of ['169.254.169.254', 'fe80::1', '0.0.0.0', '::', '::ffff:127.0.0.1', '224.0.0.1']) assert.equal(egress.blockedAddress(a, { allowPrivate: true }), true, a);
  // IPv4-translated (::ffff:0:a.b.c.d, RFC 2765 SIIT) embeds IPv4 too: blocked always.
  for (const a of ['::ffff:0:7f00:1', '::ffff:0:a00:1', '::ffff:0:a9fe:a9fe', '::ffff:0:808:808', '::ffff:0:127.0.0.1']) {
    assert.equal(egress.blockedAddress(a), true, a);
    assert.equal(egress.blockedAddress(a, { allowPrivate: true }), true, a);
  }
});

test('targetURL: only paths on the base origin; IP-literal bases in blocked ranges are 403', () => {
  const base = 'https://api.systemapi.io';
  assert.equal(egress.targetURL(base, '/v1/hosts?x=1'), 'https://api.systemapi.io/v1/hosts?x=1');
  for (const ep of ['@169.254.169.254/latest/meta-data', '.evil.com/x', '//evil.com/x', '/\\evil.com/x', ':8080/x',
    'http://169.254.169.254/', 'x', '/a b', '/a\nb', '', null, 7, '/' + 'a'.repeat(3000)]) {
    assert.throws(() => egress.targetURL(base, ep), (err) => err.status === 400, String(ep));
  }
  for (const b of ['http://127.0.0.1:3000', 'http://[::1]:3000', 'http://169.254.169.254', 'http://10.0.0.5', 'http://[::ffff:127.0.0.1]']) {
    assert.throws(() => egress.targetURL(b, '/x'), (err) => err.status === 403 && err.code === 'EGRESS_BLOCKED', b);
  }
  assert.equal(egress.targetURL('http://127.0.0.1:3000', '/x', { allowPrivate: true }), 'http://127.0.0.1:3000/x');
  assert.throws(() => egress.targetURL('http://169.254.169.254', '/x', { allowPrivate: true }), (err) => err.status === 403);
  assert.throws(() => egress.targetURL('file:///etc', '/passwd'), (err) => err.status === 400);
});

test('guardedLookup: any blocked address in the answer refuses the name; the socket gets exactly the vetted address', async () => {
  const run = (lookup, opts) => new Promise((resolve) => lookup('h.test', opts, (err, a, f) => resolve({ err, a, f })));
  const fixed = (list) => (host, opts, cb) => cb(null, list);
  const mixed = await run(egress.guardedLookup(fixed([{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }])), {});
  assert.equal(mixed.err.code, 'EGRESS_BLOCKED');
  const v6 = await run(egress.guardedLookup(fixed([{ address: '::1', family: 6 }])), { all: true });
  assert.equal(v6.err.code, 'EGRESS_BLOCKED');
  const empty = await run(egress.guardedLookup(fixed([])), {});
  assert.equal(empty.err.code, 'EGRESS_BLOCKED');
  const failed = await run(egress.guardedLookup((h, o, cb) => cb(Object.assign(new Error('nx'), { code: 'ENOTFOUND' }))), {});
  assert.equal(failed.err.code, 'ENOTFOUND');

  // A rebinding name: public on the first answer, loopback on the next. Each
  // socket resolves once, and gets the address that was checked.
  let calls = 0;
  const rebind = egress.guardedLookup((h, o, cb) => {
    calls += 1;
    cb(null, [{ address: calls === 1 ? '8.8.8.8' : '127.0.0.1', family: 4 }]);
  });
  const first = await run(rebind, {});
  assert.equal(first.err, null);
  assert.equal(first.a, '8.8.8.8');
  const second = await run(rebind, { all: true });
  assert.equal(second.err.code, 'EGRESS_BLOCKED');
  assert.equal(calls, 2);
});

test('forwardHeaders drops Host, hop-by-hop and forwarding headers and non-string values', () => {
  assert.deepEqual(egress.forwardHeaders({ Host: 'internal', 'X-API-Key': 'k', Connection: 'close', 'X-Forwarded-For': '10.0.0.1', n: 7 }), { 'X-API-Key': 'k' });
  assert.deepEqual(egress.forwardHeaders(null), {});
  assert.deepEqual(egress.forwardHeaders(['a']), {});
});

// The router end to end, with local servers counting what reaches them.
async function listen(handler) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, port: server.address().port, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}

async function playground(config) {
  const counts = new Map();
  const redis = {
    async get(k) { return counts.has(k) ? String(counts.get(k)) : '0'; },
    async incr(k) { counts.set(k, (counts.get(k) || 0) + 1); },
    async set(k, v) { counts.set(k, Number(v)); },
    async expireAt() {}
  };
  const db = { async connect() { return { async query() { return { rows: [] }; }, release() {} }; }, async query() { return { rows: [] }; } };
  const app = express();
  app.use(express.json());
  app.use('/playground', createPlaygroundRouter({ db, redis, keycloakURL: 'https://unused.test', keycloakRealm: 'unused', keycloakClientID: 'c', apiSite: 'systemapi', ...config }));
  const front = await listen(app);
  const execute = (body) => fetch(`http://127.0.0.1:${front.port}/playground/execute`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
  }).then(async (res) => ({ status: res.status, body: await res.json() }));
  return { execute, close: front.close };
}

test('execute: loopback, metadata, 10.x and [::1] targets, and a name resolving to loopback, are refused and never reached', async () => {
  let hits = 0;
  const internal = await listen((req, res) => { hits += 1; res.end('{}'); });
  const cases = [
    { baseURL: `http://127.0.0.1:${internal.port}`, endpoint: '/x', status: 403 },
    { baseURL: `http://[::1]:${internal.port}`, endpoint: '/x', status: 403 },
    { baseURL: 'http://169.254.169.254', endpoint: '/latest/meta-data/', status: 403 },
    { baseURL: 'http://10.0.0.5', endpoint: '/x', status: 403 },
    // The caller cannot steer the host off the base origin.
    { baseURL: 'https://api.systemapi.io', endpoint: `@127.0.0.1:${internal.port}/x`, status: 400 },
    { baseURL: 'https://api.systemapi.io', endpoint: `//127.0.0.1:${internal.port}/x`, status: 400 },
    // A DNS name (rebinding or not) that resolves to loopback.
    { baseURL: `http://rebind.test:${internal.port}`, endpoint: '/x', status: 403,
      egressResolve: (h, o, cb) => cb(null, [{ address: '127.0.0.1', family: 4 }]) }
  ];
  try {
    for (const c of cases) {
      const p = await playground({ baseURL: c.baseURL, egressResolve: c.egressResolve });
      try {
        const out = await p.execute({ endpoint: c.endpoint });
        assert.equal(out.status, c.status, `${c.baseURL} ${c.endpoint} ${JSON.stringify(out.body)}`);
        assert.equal(out.body.error, c.status === 403 ? 'egress_blocked' : 'bad_endpoint');
      } finally { await p.close(); }
    }
    assert.equal(hits, 0, 'no request reached the internal server');
  } finally { await internal.close(); }
});

test('execute: a redirect is returned, never followed (even with private egress allowed); Host and bad methods refused', async () => {
  let targetHits = 0;
  const target = await listen((req, res) => { targetHits += 1; res.end('{}'); });
  const seenHosts = [];
  const origin = await listen((req, res) => {
    seenHosts.push(req.headers.host);
    res.writeHead(302, { location: `http://127.0.0.1:${target.port}/latest/meta-data/` });
    res.end();
  });
  const p = await playground({ baseURL: `http://127.0.0.1:${origin.port}`, allowPrivateEgress: true });
  try {
    const out = await p.execute({ endpoint: '/start', headers: { Host: 'internal.example' } });
    assert.equal(out.status, 200, JSON.stringify(out.body));
    assert.equal(out.body.status_code, 302);
    assert.equal(targetHits, 0);
    assert.deepEqual(seenHosts, [`127.0.0.1:${origin.port}`]);
    assert.equal((await p.execute({ endpoint: '/start', method: 'CONNECT' })).status, 400);
    assert.equal((await p.execute({ endpoint: '/start', method: 7 })).status, 400);
  } finally {
    await p.close();
    await origin.close();
    await target.close();
  }
});
