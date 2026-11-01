'use strict';

// sys.alerts.push (systemapi-agent/sys_advanced.go): the agent sends a
// sysscript_alert frame on its stream; FleetManager.onAgentAlert stores it as
// an alert event for the connection's host and tenant.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';

function opensshEd25519(raw32) {
  const name = Buffer.from('ssh-ed25519');
  const buf = Buffer.alloc(4 + name.length + 4 + 32);
  buf.writeUInt32BE(name.length, 0);
  name.copy(buf, 4);
  buf.writeUInt32BE(32, 4 + name.length);
  raw32.copy(buf, 4 + name.length + 4);
  return `ssh-ed25519 ${buf.toString('base64')} test@systemapi`;
}

async function waitUntil(what, fn, timeout = 4000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function rig() {
  const app = express();
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test' };
  const key = privateKeyFromSeed(TEST_SEED);
  fm.signer = buildSigner(key, rawPublicKey(key));
  fm.tickets = new Map();
  fm.agentPingMs = 50; // the ping interval ends soon after the socket closes
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.verifyApiKey = async (k) => (k === 'agent-key' ? { key_id: 'k-agent', user_id: 'user-1' } : null);
  mount(app, fm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const sockets = [];
  return {
    fm,
    ws: `ws://127.0.0.1:${server.address().port}`,
    track(ws) { sockets.push(ws); return ws; },
    async close() {
      for (const ws of sockets) ws.terminate();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

async function connectAgent(r, hostId = HOST_A, tenant = 'acme') {
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': tenant,
      'x-systemapi-host-id': hostId,
      'x-systemapi-hostname': `${hostId.slice(0, 4)}.example`,
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
    }
  }));
  const frames = [];
  ws.on('message', (data, isBinary) => { if (!isBinary) frames.push(JSON.parse(data.toString())); });
  ws.on('error', () => {});
  await waitUntil('enrolled', () => frames.find((f) => f.type === 'enrolled'));
  return ws;
}

// A script this server sent to hostId and still waits on (pushSysscript's
// pendingExecutions entry, without its 30 s timer).
function pending(fm, requestId, hostId) {
  fm.pendingExecutions.set(requestId, { resolve() {}, reject() {}, script: 'x', hostId });
}

function alertFrame(requestId, payload) {
  return JSON.stringify({ type: 'sysscript_alert', request_id: requestId, payload });
}

async function stored(fm) {
  return fm.registry.listAlerts(['acme', 'beta']);
}

test('a valid alert is stored for the connection host and tenant, not the payload', async () => {
  const r = await rig();
  try {
    const ws = await connectAgent(r);
    pending(r.fm, 'req-1', HOST_A);
    ws.send(alertFrame('req-1', {
      severity: 'critical', message: 'disk full', host_id: HOST_B, tenant_id: 'beta'
    }));
    const [alert] = await waitUntil('alert stored', async () => (await stored(r.fm)).length && stored(r.fm));
    assert.equal(alert.host_id, HOST_A);
    assert.equal(alert.tenant_id, 'acme');
    assert.equal(alert.rule_name, 'sysscript');
    assert.equal(alert.severity, 'critical');
    assert.equal(alert.message, 'disk full');
    assert.equal(alert.status, 'open');
    assert.deepEqual(await r.fm.registry.listAlerts(['beta']), []);
    const audit = await waitUntil('audit row', () => r.fm.registry.audit.find((row) => row.action === 'sysscript_alert'));
    assert.equal(audit.host_id, HOST_A);
    assert.equal(audit.tenant_id, 'acme');
    assert.equal(audit.actor, 'agent');
    assert.deepEqual(audit.payload, { alert_id: alert.id, request_id: 'req-1', severity: 'critical' });
  } finally {
    await r.close();
  }
});

test('bad severity, oversize or non-string message, and unknown executions are rejected', async () => {
  const r = await rig();
  try {
    const ws = await connectAgent(r);
    pending(r.fm, 'req-1', HOST_A);
    for (const severity of ['high', 'CRITICAL', '', null, 3]) ws.send(alertFrame('req-1', { severity, message: 'x' }));
    ws.send(alertFrame('req-1', { severity: 'info', message: 'a'.repeat(4097) }));
    ws.send(alertFrame('req-1', { severity: 'info', message: '€'.repeat(1366) })); // 4098 bytes, 1366 chars
    ws.send(alertFrame('req-1', { severity: 'info', message: { text: 'x' } }));
    ws.send(alertFrame('req-1', null));
    ws.send(alertFrame('req-unknown', { severity: 'info', message: 'x' }));
    ws.send(JSON.stringify({ type: 'sysscript_alert', payload: { severity: 'info', message: 'x' } }));
    // The last frame is valid and exactly at the cap; frames are handled in order.
    ws.send(alertFrame('req-1', { severity: 'warning', message: 'b'.repeat(4096) }));
    const alerts = await waitUntil('valid alert', async () => (await stored(r.fm)).length && stored(r.fm));
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal((await stored(r.fm)).length, 1);
    assert.equal(alerts[0].severity, 'warning');
    assert.equal(alerts[0].message.length, 4096);
  } finally {
    await r.close();
  }
});

test('an alert naming another host\'s execution is rejected', async () => {
  const r = await rig();
  try {
    pending(r.fm, 'req-b', HOST_B);
    r.fm.hostTenants.set(HOST_A, 'acme');
    const out = await r.fm.onAgentAlert(HOST_A, { request_id: 'req-b', payload: { severity: 'info', message: 'x' } });
    assert.deepEqual(out, { error: 'unknown_execution' });
    assert.deepEqual(await stored(r.fm), []);
  } finally {
    await r.close();
  }
});

test('one run stores at most 20 alerts', async () => {
  const r = await rig();
  try {
    pending(r.fm, 'req-1', HOST_A);
    r.fm.hostTenants.set(HOST_A, 'acme');
    const results = [];
    for (let i = 0; i < 25; i++) {
      results.push(await r.fm.onAgentAlert(HOST_A, { request_id: 'req-1', payload: { severity: 'info', message: `n${i}` } }));
    }
    assert.equal(results.filter((x) => x.alert).length, 20);
    assert.deepEqual(results.slice(20), Array(5).fill({ error: 'rate_limited' }));
    assert.equal((await stored(r.fm)).length, 20);
  } finally {
    await r.close();
  }
});

test('pushSysscript records the target host on the pending execution', async (t) => {
  const r = await rig();
  try {
    await connectAgent(r);
    t.mock.timers.enable({ apis: ['setTimeout'] }); // pushSysscript's 30 s timeout
    const run = r.fm.pushSysscript(HOST_A, 'print(1)', {}, 'req-p', { signature: crypto.randomBytes(8).toString('hex') });
    run.catch(() => {});
    assert.equal(r.fm.pendingExecutions.get('req-p').hostId, HOST_A);
    r.fm.pendingExecutions.delete('req-p');
  } finally {
    await r.close();
  }
});

test('a command_result for another host\'s execution does not settle it', async () => {
  const r = await rig();
  try {
    const ws = await connectAgent(r, HOST_A);
    const settled = [];
    r.fm.pendingExecutions.set('req-b', { resolve: (p) => settled.push(['b', p]), reject() {}, script: 'x', hostId: HOST_B });
    r.fm.pendingExecutions.set('req-a', { resolve: (p) => settled.push(['a', p]), reject() {}, script: 'x', hostId: HOST_A });
    ws.send(JSON.stringify({ type: 'command_result', request_id: 'req-b', payload: { forged: true } }));
    // Frames are handled in order; the valid result for HOST_A follows.
    ws.send(JSON.stringify({ type: 'command_result', request_id: 'req-a', payload: { ok: true } }));
    await waitUntil('own result settled', () => settled.length);
    assert.deepEqual(settled, [['a', { ok: true }]]);
    assert.ok(r.fm.pendingExecutions.has('req-b'));
    assert.ok(!r.fm.pendingExecutions.has('req-a'));
    r.fm.pendingExecutions.delete('req-b');
  } finally {
    await r.close();
  }
});
