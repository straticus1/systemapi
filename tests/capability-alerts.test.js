'use strict';

// Capability and host-offline alerts, their webhooks, audit rows and
// metrics (plan sah-fleet-readiness P1b, controlplane/capalerts.js). A real
// FleetManager over WebSocket with the memory registry; the alert clock is
// driven by hand (capAlerts.now) and the rules by capAlerts.tick().

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const express = require('express');
const WebSocket = require('ws');
const promClient = require('prom-client');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { refreshGauges } = require('../controlplane/index');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { sealSecret } = require('../controlplane/seal');
const { capabilityIntervalMs, OFFLINE_AFTER_MS } = require('../controlplane/capalerts');
const { stableInstanceId } = require('../controlplane/index');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const KEYS = {
  'agent-key': { key_id: 'k-agent', user_id: 'user-1' },
  'admin-key': { key_id: 'k-admin', user_id: 'user-1' }
};
const N = 600_000;
const T0 = Date.parse('2026-11-03T12:00:00Z');
const WEBHOOK_KEY = 'ab'.repeat(32);
const HOOK_SECRET = 'hook-secret-for-tests';

function report(caps, over = {}) {
  return { type: 'capability_report', v: 1, probed_at: '2026-11-03T12:00:00Z', caps, ...over };
}

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
const pause = (ms = 50) => new Promise((r) => setTimeout(r, ms));

function newMetrics() {
  const register = new promClient.Registry();
  return {
    register,
    capabilityStateGauge: new promClient.Gauge({ name: 'systemapi_capability_state', help: 'h', labelNames: ['host_id', 'capability', 'state'], registers: [register] }),
    hostsHealthGauge: new promClient.Gauge({ name: 'systemapi_hosts_health', help: 'h', labelNames: ['state'], registers: [register] }),
    agentUnsupportedTotal: new promClient.Counter({ name: 'systemapi_agent_unsupported_total', help: 'h', labelNames: ['capability'], registers: [register] }),
    capabilityReportDroppedTotal: new promClient.Counter({ name: 'systemapi_capability_report_dropped_total', help: 'h', labelNames: ['reason'], registers: [register] }),
    capabilityAlertCappedTotal: new promClient.Counter({ name: 'systemapi_capability_alert_capped_total', help: 'h', labelNames: ['rule'], registers: [register] }),
    hostTotalGauge: new promClient.Gauge({ name: 'systemapi_hosts_total', help: 'h', registers: [register] }),
    hostOnlineGauge: new promClient.Gauge({ name: 'systemapi_hosts_online', help: 'h', registers: [register] }),
    hostOfflineGauge: new promClient.Gauge({ name: 'systemapi_hosts_offline', help: 'h', registers: [register] })
  };
}

async function series(metrics, name) {
  const all = await metrics.register.getMetricsAsJSON();
  const m = all.find((x) => x.name === name);
  return m ? m.values : [];
}

async function rig({ registry = null } = {}) {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  const server = http.createServer(app);
  const metrics = newMetrics();
  const fm = new FleetManager(server, null, 'systemapi', metrics);
  fm.env = { NODE_ENV: 'test', SYSTEMAPI_WEBHOOK_KEY: WEBHOOK_KEY, SYSTEMAPI_WEBHOOK_ALLOW_PRIVATE: '1' };
  const key = privateKeyFromSeed(TEST_SEED);
  fm.signer = buildSigner(key, rawPublicKey(key));
  fm.tickets = new Map();
  fm.registry = registry || new MemoryRegistry({ NODE_ENV: 'test' });
  fm.verifyApiKey = async (k) => KEYS[k] || null;
  fm.capReportGapMs = 0;
  let clock = T0;
  fm.capAlerts.now = () => clock;
  fm.capAlerts.intervalMs = N;
  mount(app, fm);
  await fm.registry.setScopes('k-admin', ['admin']);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  // The tenant's webhook receiver.
  const hooks = [];
  const hookServer = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => { hooks.push({ raw, signature: req.headers['x-systemapi-signature'] }); res.end('ok'); });
  });
  await new Promise((resolve) => hookServer.listen(0, '127.0.0.1', resolve));
  const sockets = [];
  return {
    fm,
    metrics,
    hooks,
    hookUrl: `http://127.0.0.1:${hookServer.address().port}/hook`,
    url: `http://127.0.0.1:${port}`,
    base: `ws://127.0.0.1:${port}`,
    advance(ms) { clock += ms; },
    track(ws) { sockets.push(ws); return ws; },
    async close() {
      for (const ws of sockets) if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.terminate();
      server.closeAllConnections();
      hookServer.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await new Promise((resolve) => hookServer.close(resolve));
    }
  };
}

async function addWebhook(r, tenant = 'acme') {
  await r.fm.registry.createWebhook({
    id: crypto.randomUUID(), tenant_id: tenant, url: r.hookUrl,
    secret: sealSecret(HOOK_SECRET, r.fm.env), secret_fingerprint: 'fp'
  });
}

function dial(r, { hostId = HOST_A, caps = 'pty,file,tcp,xfer,config,sysscript_jobs' } = {}) {
  const headers = {
    authorization: 'Bearer agent-key',
    'x-systemapi-tenant': 'acme',
    'x-systemapi-host-id': hostId,
    'x-systemapi-hostname': hostId === HOST_A ? 'a.example' : 'b.example',
    'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
    'x-systemapi-capabilities': caps
  };
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, { headers }));
  const box = { frames: [] };
  ws.on('message', (data, isBinary) => { if (!isBinary) box.frames.push(JSON.parse(data.toString())); });
  ws.on('error', () => {});
  return { ws, box };
}

async function connectAgent(r, opts = {}) {
  const agent = dial(r, opts);
  await waitUntil('enrolled', () => agent.box.frames.find((f) => f.type === 'enrolled'));
  const hostId = opts.hostId || HOST_A;
  await waitUntil('alert state', () => r.fm.capAlerts.hosts.get(hostId) && r.fm.capAlerts.hosts.get(hostId).caps);
  return agent;
}

// Sends a report and waits until the alert pass for it has run.
async function sendReport(r, agent, caps, hostId = HOST_A, over = {}) {
  const st = r.fm.capAlerts.hosts.get(hostId);
  const before = st.reports;
  const evaluated = r.fm.capAlerts.evaluate.bind(r.fm.capAlerts);
  let done = false;
  r.fm.capAlerts.evaluate = async (...args) => { try { return await evaluated(...args); } finally { done = true; } };
  try {
    agent.ws.send(JSON.stringify(report(caps, over)));
    await waitUntil('report evaluated', () => st.reports === before + 1 && done);
  } finally {
    r.fm.capAlerts.evaluate = evaluated;
  }
}

const alertsOf = (r, rule) => r.fm.registry.alerts.filter((a) => !rule || a.rule_name === rule);
const auditsOf = (r, action) => r.fm.registry.audit.filter((a) => a.action === action);
const verifySignature = (hook) => {
  const mac = crypto.createHmac('sha256', HOOK_SECRET).update(hook.raw).digest('hex');
  return hook.signature === `sha256=${mac}`;
};

async function filePolicy(r, hostId = HOST_A) {
  // file only (read-only root: no xfer); tcp is not expected.
  await r.fm.registry.setHostChannelPolicy(hostId, { file_policy: { roots: [{ path: '/srv/data', read: true, write: false }] } });
}

test('SYSTEMAPI_CAPABILITY_INTERVAL_S: default 600 s, bounded 60..3600 (the agent\'s own range)', () => {
  assert.equal(capabilityIntervalMs({}), 600_000);
  assert.equal(capabilityIntervalMs({ SYSTEMAPI_CAPABILITY_INTERVAL_S: '120' }), 120_000);
  assert.equal(capabilityIntervalMs({ SYSTEMAPI_CAPABILITY_INTERVAL_S: '3600' }), 3_600_000);
  for (const bad of ['59', '3601', '86400', '1.5', 'ten', '-600']) {
    assert.equal(capabilityIntervalMs({ SYSTEMAPI_CAPABILITY_INTERVAL_S: bad }), 600_000, bad);
  }
});

test('an expected capability degraded opens capability:<name> only after 2 x N, once; an unexpected one never; signed webhook without paths; audit row', async () => {
  const r = await rig();
  try {
    await addWebhook(r);
    const agent = await connectAgent(r);
    await filePolicy(r);
    await sendReport(r, agent, [
      { name: 'file', state: 'degraded', reason: 'enosys_openat2' },
      { name: 'tcp', state: 'degraded', reason: 'probe_error' },
      { name: 'pty', state: 'ok' }
    ]);
    r.advance(2 * N - 1);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r).length, 0, 'not before 2 x N');
    r.advance(1);
    await r.fm.capAlerts.tick();
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r).map((a) => [a.rule_name, a.status, a.tenant_id]), [['capability:file', 'open', 'acme']]);
    assert.equal(alertsOf(r, 'capability:tcp').length, 0, 'tcp is not expected');
    const opened = auditsOf(r, 'capability_alert_open');
    assert.equal(opened.length, 1);
    assert.deepEqual(opened[0].payload, {
      alert_id: alertsOf(r)[0].id, rule: 'capability:file', capability: 'file', state: 'degraded', reason: 'enosys_openat2'
    });
    assert.equal(opened[0].actor, 'system:capability');
    await waitUntil('webhook', () => r.hooks.length === 1);
    const body = JSON.parse(r.hooks[0].raw);
    assert.deepEqual(body, {
      type: 'capability_alert', status: 'open', rule: 'capability:file', alert_id: alertsOf(r)[0].id, host_id: HOST_A,
      capability: 'file', state: 'degraded', reason: 'enosys_openat2', ts: new Date(T0 + 2 * N).toISOString()
    });
    assert.ok(verifySignature(r.hooks[0]), 'HMAC-SHA256 over the exact body');
    assert.equal(r.hooks[0].raw.includes('/'), false, 'no path in the webhook body');
    assert.equal(JSON.stringify(opened[0].payload).includes('/'), false, 'no path in the audit row');
    assert.equal(alertsOf(r)[0].message.includes('/'), false, 'no path in the alert message');
    // A tampered body does not verify.
    assert.equal(verifySignature({ raw: r.hooks[0].raw.replace('file', 'tcp!'), signature: r.hooks[0].signature }), false);
  } finally { await r.close(); }
});

test('a reportless (unknown) agent never alerts, even with an expected capability withdrawn at dial', async () => {
  const r = await rig();
  try {
    await addWebhook(r);
    const agent = dial(r, { caps: 'pty,tcp' });
    await waitUntil('enrolled', () => agent.box.frames.find((f) => f.type === 'enrolled'));
    await filePolicy(r);
    for (let i = 0; i < 10; i += 1) {
      r.advance(N);
      await r.fm.capAlerts.tick();
    }
    assert.equal(alertsOf(r).length, 0);
    assert.equal(await r.fm.hostHealth(HOST_A), 'unknown');
    await pause();
    assert.equal(r.hooks.length, 0);
    assert.equal(r.fm.registry.hosts.get(HOST_A).capability_health, 'unknown');
  } finally { await r.close(); }
});

test('no report for 3 x N after one opens capability:reports; two reports resolve it', async () => {
  const r = await rig();
  try {
    await addWebhook(r);
    const agent = await connectAgent(r);
    await sendReport(r, agent, [{ name: 'pty', state: 'ok' }]);
    r.advance(3 * N - 1);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r).length, 0);
    r.advance(1);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r).map((a) => [a.rule_name, a.status]), [['capability:reports', 'open']]);
    await waitUntil('open webhook', () => r.hooks.length === 1);
    assert.deepEqual(JSON.parse(r.hooks[0].raw), {
      type: 'capability_alert', status: 'open', rule: 'capability:reports', alert_id: alertsOf(r)[0].id, host_id: HOST_A,
      capability: null, state: 'unknown', reason: 'report_missing', ts: new Date(T0 + 3 * N).toISOString()
    });
    await sendReport(r, agent, [{ name: 'pty', state: 'ok' }]);
    assert.equal(alertsOf(r)[0].status, 'open', 'one report is not enough');
    await sendReport(r, agent, [{ name: 'pty', state: 'ok' }]);
    assert.equal(alertsOf(r)[0].status, 'resolved');
    assert.equal(auditsOf(r, 'capability_alert_resolve').length, 1);
    await waitUntil('resolve webhook', () => r.hooks.length === 2);
    assert.equal(JSON.parse(r.hooks[1].raw).status, 'resolved');
    assert.ok(verifySignature(r.hooks[1]));
  } finally { await r.close(); }
});

test('capability:<name> resolves after 2 consecutive ok reports, not after one, and an ok between degraded reports restarts the clock', async () => {
  const r = await rig();
  try {
    await addWebhook(r);
    const agent = await connectAgent(r);
    await filePolicy(r);
    const degraded = [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }];
    const ok = [{ name: 'file', state: 'ok' }];
    await sendReport(r, agent, degraded);
    r.advance(N);
    await sendReport(r, agent, ok);
    r.advance(N);
    await sendReport(r, agent, degraded);
    r.advance(N);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r).length, 0, 'not continuous for 2 x N');
    r.advance(N);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'capability:file').length, 1);
    await sendReport(r, agent, ok);
    assert.equal(alertsOf(r, 'capability:file')[0].status, 'open');
    await sendReport(r, agent, ok);
    assert.equal(alertsOf(r, 'capability:file')[0].status, 'resolved');
    const resolved = auditsOf(r, 'capability_alert_resolve');
    assert.equal(resolved.length, 1);
    assert.deepEqual(resolved[0].payload, {
      alert_id: alertsOf(r, 'capability:file')[0].id, rule: 'capability:file', capability: 'file', state: 'ok', reason: ''
    });
    await waitUntil('two webhooks', () => r.hooks.length === 2);
    assert.deepEqual(JSON.parse(r.hooks[1].raw), {
      type: 'capability_alert', status: 'resolved', rule: 'capability:file', alert_id: alertsOf(r, 'capability:file')[0].id, host_id: HOST_A,
      capability: 'file', state: 'ok', reason: '', ts: new Date(T0 + 4 * N).toISOString()
    });
    // Degraded again for 2 x N: a new alert opens (the old one is resolved).
    await sendReport(r, agent, degraded);
    r.advance(2 * N);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r, 'capability:file').map((a) => a.status), ['resolved', 'open']);
    assert.equal(r.fm.registry.hosts.get(HOST_A).capability_health, 'degraded');
  } finally { await r.close(); }
});

test('host:offline opens 5 min after the last socket closed, not on a 30 s reconnect, and resolves on reconnect', async () => {
  const r = await rig();
  try {
    await addWebhook(r);
    let agent = await connectAgent(r);
    // A brief reconnect.
    agent.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    r.advance(30_000);
    await r.fm.capAlerts.tick();
    agent = await connectAgent(r);
    r.advance(OFFLINE_AFTER_MS);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'host:offline').length, 0, 'a 30 s reconnect opens nothing');
    // A real outage.
    agent.ws.close();
    await waitUntil('offline again', () => !r.fm.connectedAgents.has(HOST_A));
    r.advance(OFFLINE_AFTER_MS - 1);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'host:offline').length, 0);
    r.advance(1);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r, 'host:offline').map((a) => [a.status, a.severity]), [['open', 'critical']]);
    assert.equal(r.fm.capAlerts.hosts.has(HOST_A), false, 'the host leaves memory once its offline alert is tried');
    await waitUntil('offline webhook', () => r.hooks.length === 1);
    assert.deepEqual(JSON.parse(r.hooks[0].raw), {
      type: 'host_offline', status: 'open', rule: 'host:offline', alert_id: alertsOf(r, 'host:offline')[0].id, host_id: HOST_A,
      capability: null, state: 'offline', reason: 'no_socket', ts: new Date(T0 + 30_000 + 2 * OFFLINE_AFTER_MS).toISOString()
    });
    await connectAgent(r);
    await waitUntil('resolved', () => alertsOf(r, 'host:offline')[0].status === 'resolved');
    await waitUntil('resolve webhook', () => r.hooks.length === 2);
    assert.deepEqual(JSON.parse(r.hooks[1].raw), {
      type: 'host_offline', status: 'resolved', rule: 'host:offline', alert_id: alertsOf(r, 'host:offline')[0].id, host_id: HOST_A,
      capability: null, state: 'online', reason: 'reconnected', ts: new Date(T0 + 30_000 + 2 * OFFLINE_AFTER_MS).toISOString()
    });
    assert.ok(r.hooks.every(verifySignature));
    assert.deepEqual(auditsOf(r, 'capability_alert_open').map((a) => a.payload.rule), ['host:offline']);
    assert.deepEqual(auditsOf(r, 'capability_alert_resolve').map((a) => a.payload.rule), ['host:offline']);
  } finally { await r.close(); }
});

test('alert state stays bounded: hosts closed past the window leave memory; retire drops the host and its gauge series', async () => {
  const r = await rig();
  try {
    const a = await connectAgent(r, { hostId: HOST_A });
    const b = await connectAgent(r, { hostId: HOST_B });
    assert.equal(r.fm.capAlerts.hosts.size, 2);
    b.ws.close();
    await waitUntil('b offline', () => !r.fm.connectedAgents.has(HOST_B));
    r.advance(OFFLINE_AFTER_MS);
    await r.fm.capAlerts.tick();
    assert.deepEqual([...r.fm.capAlerts.hosts.keys()], [HOST_A]);
    // Retire A: state dropped at once; a later tick opens nothing for it.
    await sendReport(r, a, [{ name: 'file', state: 'degraded', reason: 'probe_error' }]);
    await refreshGauges(r.fm);
    assert.ok((await series(r.metrics, 'systemapi_capability_state')).some((v) => v.labels.host_id === HOST_A));
    const res = await fetch(`${r.url}/api/v1/hosts/${HOST_A}/retire`, {
      method: 'POST', headers: { 'x-api-key': 'admin-key', 'content-type': 'application/json' },
      body: JSON.stringify({ reason: 'decommissioned', force: true })
    });
    assert.equal(res.status, 200, await res.text());
    assert.equal((await series(r.metrics, 'systemapi_capability_state')).some((v) => v.labels.host_id === HOST_A), false,
      'series removed on retire');
    await waitUntil('a closed', () => !r.fm.connectedAgents.has(HOST_A));
    await pause();
    assert.equal(r.fm.capAlerts.hosts.has(HOST_A), false, 'the close after the retire does not bring the host back');
    r.advance(OFFLINE_AFTER_MS);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'host:offline').filter((x) => x.host_id === HOST_A).length, 0, 'no alert for a retired host');
    assert.equal(r.fm.capAlerts.hosts.size, 0);
    await refreshGauges(r.fm);
    assert.equal((await series(r.metrics, 'systemapi_capability_state')).some((v) => v.labels.host_id === HOST_A), false,
      'refreshGauges leaves a retired host out');
  } finally { await r.close(); }
});

test('gauges come from the registry: capability state rows and hosts by health', async () => {
  const r = await rig();
  try {
    const a = await connectAgent(r, { hostId: HOST_A });
    await connectAgent(r, { hostId: HOST_B });
    await filePolicy(r, HOST_A);
    await sendReport(r, a, [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }, { name: 'pty', state: 'ok' }]);
    await refreshGauges(r.fm);
    const states = (await series(r.metrics, 'systemapi_capability_state')).map((v) => [v.labels.host_id, v.labels.capability, v.labels.state, v.value]).sort();
    assert.deepEqual(states, [[HOST_A, 'file', 'degraded', 1], [HOST_A, 'pty', 'ok', 1]]);
    const health = Object.fromEntries((await series(r.metrics, 'systemapi_hosts_health')).map((v) => [v.labels.state, v.value]));
    assert.deepEqual(health, { ok: 0, degraded: 1, unknown: 1, offline: 0 });
    // A state change replaces the old series (one row per host and name).
    await sendReport(r, a, [{ name: 'file', state: 'ok' }]);
    await refreshGauges(r.fm);
    const after = (await series(r.metrics, 'systemapi_capability_state')).filter((v) => v.labels.capability === 'file');
    assert.deepEqual(after.map((v) => v.labels.state), ['ok']);
    assert.equal(Object.fromEntries((await series(r.metrics, 'systemapi_hosts_health')).map((v) => [v.labels.state, v.value])).ok, 1);
    // The gauge reads the registry, not this instance's sockets: another
    // replica's host counts the same.
    r.fm.registry.hosts.get(HOST_B).capability_health = 'degraded';
    await refreshGauges(r.fm);
    assert.equal(Object.fromEntries((await series(r.metrics, 'systemapi_hosts_health')).map((v) => [v.labels.state, v.value])).degraded, 1);
  } finally { await r.close(); }
});

test('counters: agent_unsupported by capability where routing refuses, dropped reports by reason', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, { caps: 'pty,file,xfer' });
    await sendReport(r, agent, [{ name: 'xfer', state: 'degraded', reason: 'binary_missing' }]);
    r.fm.env = { ...r.fm.env, SYSTEMAPI_XFER_PEER_UDP: '127.0.0.1:9' };
    const host = await r.fm.registry.getHost(['acme'], HOST_A);
    const err = await r.fm.xfer.grant({ principal: { userId: 'user-1' }, host, request: { dir: 'put', transport: 'udp' } }).catch((e) => e);
    assert.equal(err.code, 'agent_unsupported');
    const unsupported = await series(r.metrics, 'systemapi_agent_unsupported_total');
    assert.deepEqual(unsupported.map((v) => [v.labels.capability, v.value]), [['xfer', 1]]);
    agent.ws.send(JSON.stringify({ type: 'capability_report', v: 9 }));
    agent.ws.send(JSON.stringify(report([{ name: 'file', state: 'degraded', reason: '/etc/shadow' }])));
    await waitUntil('drops', () => r.fm.capReportDrops.get('bad_reason') === 1 && r.fm.capReportDrops.get('bad_version') === 1);
    const dropped = Object.fromEntries((await series(r.metrics, 'systemapi_capability_report_dropped_total')).map((v) => [v.labels.reason, v.value]));
    assert.deepEqual(dropped, { bad_version: 1, bad_reason: 1 });
  } finally { await r.close(); }
});

test('fail closed: the alert registry refuses a rule outside the fixed set and a health outside ok/degraded/unknown', async () => {
  const reg = new MemoryRegistry({ NODE_ENV: 'test' });
  await reg.enroll({ tenantId: 'acme', userId: 'u', keyId: 'k', hostId: HOST_A, hostname: 'a', os: '', platform: '', sshPubkey: null });
  const audit = { rule: 'x', capability: null, state: 'x', reason: '' };
  for (const rule of ['drift:web', 'capability:/etc/passwd', 'capability:', 'host:online', 'zscore:cpu', '']) {
    await assert.rejects(reg.openHostAlert({ host_id: HOST_A, rule_name: rule, actor: 'a', audit }), (e) => e.code === 'bad_alert_rule', rule);
  }
  await assert.rejects(reg.resolveHostAlerts(HOST_A, [{ rule: 'drift:web' }], 'a'), (e) => e.code === 'bad_alert_rule');
  await assert.rejects(reg.setHostHealth(HOST_A, 'offline'), (e) => e.code === 'bad_health');
  assert.equal(reg.alerts.length, 0);
  assert.equal(reg.audit.length, 0);
  // A second open of an active rule is a no-op; an unknown host gets nothing.
  const first = await reg.openHostAlert({ host_id: HOST_A, rule_name: 'capability:file', severity: 'warning', message: 'm', actor: 'a', audit });
  assert.ok(first);
  assert.equal(await reg.openHostAlert({ host_id: HOST_A, rule_name: 'capability:file', actor: 'a', audit }), null);
  assert.equal(await reg.openHostAlert({ host_id: HOST_B, rule_name: 'capability:file', actor: 'a', audit }), null);
  assert.equal(reg.audit.length, 1);
});

// --- P1 code-review fixes ---

const presenceOf = (reg, hostId = HOST_A) => reg.hosts.get(hostId);
const getJSON = async (r, path, key = 'admin-key') => {
  const res = await fetch(`${r.url}${path}`, { headers: { 'x-api-key': key } });
  return { status: res.status, body: await res.json() };
};

test('a disconnect on one replica and a reconnect on another inside 5 min opens no host:offline (shared registry)', async () => {
  const r1 = await rig();
  const r2 = await rig({ registry: r1.fm.registry });
  try {
    const reg = r1.fm.registry;
    const a = await connectAgent(r1);
    a.ws.close();
    await waitUntil('offline on r1', () => !r1.fm.connectedAgents.has(HOST_A));
    await waitUntil('r1 presence cleared', () => presenceOf(reg).agent_conn_id == null && presenceOf(reg).status === 'offline');
    r1.advance(60_000);
    await r1.fm.capAlerts.tick();
    await connectAgent(r2);
    await waitUntil('r2 holds the presence', () => presenceOf(reg).agent_instance === r2.fm.jobs.instanceId);
    r1.advance(OFFLINE_AFTER_MS);
    await r1.fm.capAlerts.tick();
    assert.equal(alertsOf(r1, 'host:offline').length, 0, 'the host is online on r2');
    assert.equal(r1.fm.capAlerts.hosts.has(HOST_A), false, 'r1 settled the host and dropped it');
    // A late offline status write from r1 does not open one either while r2's
    // presence is fresh.
    presenceOf(reg).status = 'offline';
    r1.fm.capAlerts.onDisconnect(HOST_A);
    r1.advance(OFFLINE_AFTER_MS);
    await r1.fm.capAlerts.tick();
    assert.equal(alertsOf(r1, 'host:offline').length, 0, 'a fresh presence on another replica holds it off');
    // A stale presence (its instance gone) no longer does.
    presenceOf(reg).agent_seen_at = new Date(Date.now() - 120_000);
    r1.fm.capAlerts.onDisconnect(HOST_A);
    r1.advance(OFFLINE_AFTER_MS);
    await r1.fm.capAlerts.tick();
    assert.equal(alertsOf(r1, 'host:offline').length, 1);
  } finally { await r1.close(); await r2.close(); }
});

test('retire resolves the host\'s active capability and host:offline alerts in the retire step, audit reason retired; health cleared', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    await filePolicy(r);
    await sendReport(r, agent, [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }]);
    r.advance(3 * N);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r).map((a) => [a.rule_name, a.status]).sort(), [['capability:file', 'open'], ['capability:reports', 'open']]);
    assert.equal(r.fm.registry.hosts.get(HOST_A).capability_health, 'degraded');
    // A sysscript alert of the same host is not ended by the retire.
    r.fm.registry.alerts.push({ id: 999, tenant_id: 'acme', host_id: HOST_A, rule_name: 'sysscript', status: 'open' });
    const res = await fetch(`${r.url}/api/v1/hosts/${HOST_A}/retire`, {
      method: 'POST', headers: { 'x-api-key': 'admin-key', 'content-type': 'application/json' },
      body: JSON.stringify({ reason: 'decommissioned', force: true })
    });
    assert.equal(res.status, 200, await res.text());
    assert.deepEqual(alertsOf(r).map((a) => [a.rule_name, a.status]).sort(),
      [['capability:file', 'resolved'], ['capability:reports', 'resolved'], ['sysscript', 'open']]);
    const resolved = auditsOf(r, 'capability_alert_resolve').map((a) => a.payload).sort((x, y) => (x.rule < y.rule ? -1 : 1));
    assert.deepEqual(resolved.map((p) => [p.rule, p.capability, p.state, p.reason]), [
      ['capability:file', 'file', 'retired', 'retired'],
      ['capability:reports', null, 'retired', 'retired']
    ]);
    const seqOf = (action) => r.fm.registry.audit.findIndex((a) => a.action === action);
    assert.ok(seqOf('host_retired') < seqOf('capability_alert_resolve'), 'after the host_retired row');
    assert.equal(r.fm.registry.hosts.get(HOST_A).capability_health, null);
    assert.equal(r.fm.registry.hosts.get(HOST_A).status, 'offline');
  } finally { await r.close(); }
});

test('N follows the agent\'s interval_s when it is longer than the control plane\'s', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    await filePolicy(r);
    await sendReport(r, agent, [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }], HOST_A, { interval_s: 3600 });
    r.advance(2 * N);
    await r.fm.capAlerts.tick();
    r.advance(3 * N);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r).length, 0, 'an hourly agent is not late after 2 x 600 s or 3 x 600 s');
    r.advance(2 * 3_600_000 - 5 * N);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r).map((a) => a.rule_name), ['capability:file']);
    r.advance(3 * 3_600_000 - 2 * 3_600_000);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r).map((a) => a.rule_name).sort(), ['capability:file', 'capability:reports']);
    // A shorter agent interval never shortens N below the control plane's.
    assert.equal(r.fm.capAlerts.nMs({ intervalS: 60 }), N);
    assert.equal(r.fm.capAlerts.nMs({ intervalS: 1200 }), 1_200_000);
    assert.equal(r.fm.capAlerts.nMs(null), N);
  } finally { await r.close(); }
});

test('a failed open or resolve leaves the alert state unmoved; the next tick writes it', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    await filePolicy(r);
    const reg = r.fm.registry;
    const open = reg.openHostAlert.bind(reg);
    const resolve = reg.resolveHostAlerts.bind(reg);
    let failOpen = 1;
    let failResolve = 0;
    reg.openHostAlert = async (e) => { if (failOpen > 0) { failOpen -= 1; throw Object.assign(new Error('db down'), { code: 'db_down' }); } return open(e); };
    reg.resolveHostAlerts = async (...a) => { if (failResolve > 0) { failResolve -= 1; throw Object.assign(new Error('db down'), { code: 'db_down' }); } return resolve(...a); };
    await sendReport(r, agent, [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }]);
    r.advance(2 * N);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r).length, 0, 'the open failed');
    assert.equal(r.fm.capAlerts.hosts.get(HOST_A).caps.get('file').opened, false);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r, 'capability:file').map((a) => a.status), ['open'], 'the next tick opened it');
    // Two ok reports: the resolve fails, then the tick resolves it.
    await sendReport(r, agent, [{ name: 'file', state: 'ok' }]);
    failResolve = 1;
    await sendReport(r, agent, [{ name: 'file', state: 'ok' }]);
    assert.equal(failResolve, 0, 'the resolve was tried');
    assert.equal(alertsOf(r, 'capability:file')[0].status, 'open', 'the resolve failed');
    assert.equal(r.fm.capAlerts.hosts.get(HOST_A).caps.get('file').resolveDone, false);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'capability:file')[0].status, 'resolved');
    // host:offline: a failed open keeps the host in memory for the next tick.
    agent.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    await waitUntil('presence cleared', () => reg.hosts.get(HOST_A).agent_conn_id == null);
    failOpen = 1;
    r.advance(OFFLINE_AFTER_MS);
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'host:offline').length, 0);
    assert.equal(r.fm.capAlerts.hosts.has(HOST_A), true, 'kept for a retry');
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'host:offline').length, 1);
    assert.equal(r.fm.capAlerts.hosts.has(HOST_A), false);
  } finally { await r.close(); }
});

test('webhooks: a resolve whose open webhook the cooldown suppressed sends none; at most 6 opens per host per hour, the rest counted', async () => {
  const r = await rig();
  try {
    await addWebhook(r);
    const agent = await connectAgent(r);
    await filePolicy(r);
    const degraded = [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }];
    const ok = [{ name: 'file', state: 'ok' }];
    const cycle = async () => {
      await sendReport(r, agent, degraded);
      r.advance(2 * N);
      await r.fm.capAlerts.tick();
      await sendReport(r, agent, ok);
      await sendReport(r, agent, ok);
    };
    await cycle();
    await waitUntil('open and resolve webhooks', () => r.hooks.length === 2);
    // Second episode inside the cooldown: no open webhook, so no resolve one.
    await cycle();
    assert.deepEqual(alertsOf(r, 'capability:file').map((a) => a.status), ['resolved', 'resolved']);
    await pause(100);
    assert.equal(r.hooks.length, 2);
    assert.deepEqual(r.hooks.map((h) => JSON.parse(h.raw).status), ['open', 'resolved']);
    assert.equal(r.fm.capAlerts.suppressedWebhooks.size, 0, 'the suppressed mark ends with its alert');
    // The hourly cap: a host flapping fast opens 6 alerts per hour at most.
    r.fm.capAlerts.opens.set(HOST_A, []);
    for (let i = 0; i < 6; i += 1) {
      await sendReport(r, agent, degraded);
      r.advance(2 * N);
      await r.fm.capAlerts.tick();
      await r.fm.capAlerts.tick();
      await sendReport(r, agent, ok);
      await sendReport(r, agent, ok);
    }
    const opened = alertsOf(r, 'capability:file').length;
    assert.equal(opened, 2 + 6);
    // Six opens inside the last hour: the seventh is held back.
    const now = T0 + 999;
    r.fm.capAlerts.now = () => now;
    r.fm.capAlerts.opens.set(HOST_A, Array.from({ length: 6 }, () => now - 1000));
    await sendReport(r, agent, degraded);
    r.fm.capAlerts.hosts.get(HOST_A).caps.get('file').since = now - 2 * N;
    await r.fm.capAlerts.tick();
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'capability:file').length, opened, 'held back');
    assert.equal(r.fm.capAlerts.cappedTotal, 1, 'counted once, not once per tick');
    assert.deepEqual((await series(r.metrics, 'systemapi_capability_alert_capped_total')).map((v) => [v.labels.rule, v.value]), [['capability:file', 1]]);
    // An hour later it opens.
    r.fm.capAlerts.now = () => now + 3_600_000;
    await r.fm.capAlerts.tick();
    assert.equal(alertsOf(r, 'capability:file').length, opened + 1);
    assert.equal(r.fm.capAlerts.capped.size, 0);
  } finally { await r.close(); }
});

test('capability_health: cleared on disconnect; written only by the instance on the presence row; boot releases this instance\'s rows', async () => {
  const r = await rig();
  try {
    const reg = r.fm.registry;
    const agent = await connectAgent(r);
    await sendReport(r, agent, [{ name: 'pty', state: 'ok' }]);
    await waitUntil('health ok', () => reg.hosts.get(HOST_A).capability_health === 'ok');
    // Another instance (not on the presence row) cannot overwrite it.
    assert.equal(await reg.setHostHealth(HOST_A, 'degraded', 'some-other-instance'), false);
    assert.equal(await reg.setHostHealth(HOST_A, 'degraded', null), false);
    assert.equal(reg.hosts.get(HOST_A).capability_health, 'ok');
    assert.equal(await reg.setHostHealth(HOST_A, 'degraded', r.fm.jobs.instanceId), true);
    assert.equal(await reg.setHostHealth(HOST_A, 'ok', r.fm.jobs.instanceId), true);
    agent.ws.close();
    await waitUntil('offline', () => reg.hosts.get(HOST_A).status === 'offline');
    assert.equal(reg.hosts.get(HOST_A).capability_health, null, 'no stale ok on an offline host');
    assert.equal(await reg.setHostHealth(HOST_A, 'ok', r.fm.jobs.instanceId), false, 'no presence: no write');
    // Boot: the rows a restarted instance held are offline with no health.
    await reg.setAgentPresence(HOST_A, { caps: [], instance: 'cp-1', connId: 'cp-1:x', enrolledAt: new Date() });
    reg.hosts.get(HOST_A).status = 'online';
    reg.hosts.get(HOST_A).capability_health = 'ok';
    assert.equal(await reg.releaseInstanceHosts('cp-2'), 0);
    assert.equal(await reg.releaseInstanceHosts(''), 0);
    assert.equal(await reg.releaseInstanceHosts('cp-1'), 1);
    const row = reg.hosts.get(HOST_A);
    assert.deepEqual([row.status, row.capability_health, row.agent_instance, row.agent_conn_id], ['offline', null, null, null]);
    assert.equal(stableInstanceId({ SYSTEMAPI_INSTANCE_ID: 'cp-1.example_2' }), 'cp-1.example_2');
    for (const bad of [undefined, '', 'a b', 'x'.repeat(65), 'cp;1', '../x/']) {
      assert.equal(stableInstanceId({ SYSTEMAPI_INSTANCE_ID: bad }), null, String(bad));
    }
  } finally { await r.close(); }
});

test('health badge across replicas: a host held elsewhere shows its row\'s health; the fleet list reads no policy for hosts held here', async () => {
  const r1 = await rig();
  const r2 = await rig({ registry: r1.fm.registry });
  try {
    const agent = await connectAgent(r2);
    await filePolicy(r2);
    await sendReport(r2, agent, [{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }]);
    await waitUntil('degraded written', () => r1.fm.registry.hosts.get(HOST_A).capability_health === 'degraded');
    const list = await getJSON(r1, '/api/v1/fleet');
    assert.equal(list.status, 200, JSON.stringify(list.body));
    const row = list.body.hosts.find((h) => h.host_id === HOST_A);
    assert.equal(row.health, 'degraded', 'from the row, not offline');
    assert.equal('capability_health' in row, false);
    const resolved = await getJSON(r1, `/api/v1/hosts/resolve?name=${HOST_A}`);
    assert.equal(resolved.body.health, 'degraded');
    // On the holder: computed locally from the cached expected set.
    let reads = 0;
    const expected = r2.fm.expectedCapabilities.bind(r2.fm);
    r2.fm.expectedCapabilities = async (h) => { reads += 1; return expected(h); };
    const local = await getJSON(r2, '/api/v1/fleet');
    assert.equal(local.body.hosts.find((h) => h.host_id === HOST_A).health, 'degraded');
    assert.equal(reads, 0, 'no per-host policy read in the list');
    // A host offline per its row is offline.
    agent.ws.close();
    await waitUntil('offline', () => r1.fm.registry.hosts.get(HOST_A).status === 'offline');
    assert.equal((await getJSON(r1, '/api/v1/fleet')).body.hosts.find((h) => h.host_id === HOST_A).health, 'offline');
  } finally { await r1.close(); await r2.close(); }
});

test('a sysscript_jobs refusal counts systemapi_agent_unsupported_total like the channels', async () => {
  const r = await rig();
  try {
    await connectAgent(r, { caps: 'pty,file' });
    await assert.rejects(r.fm.jobs.requireAgent(HOST_A), (e) => e.status === 501 && e.code === 'agent_unsupported');
    const unsupported = await series(r.metrics, 'systemapi_agent_unsupported_total');
    assert.deepEqual(unsupported.map((v) => [v.labels.capability, v.value]), [['sysscript_jobs', 1]]);
    // The reason lookup alone counts nothing.
    r.fm.agentUnsupportedReason(HOST_A, 'tcp');
    assert.deepEqual((await series(r.metrics, 'systemapi_agent_unsupported_total')).map((v) => v.value), [1]);
  } finally { await r.close(); }
});

test('host:offline is never held back by the hourly cap, and health is re-asserted after another writer cleared it', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    await sendReport(r, agent, [{ name: 'pty', state: 'ok' }]);
    await waitUntil('health ok', () => r.fm.registry.hosts.get(HOST_A).capability_health === 'ok');
    // Another writer clears it (a late offline from another replica); the next evaluation repairs it.
    r.fm.registry.hosts.get(HOST_A).capability_health = null;
    await r.fm.capAlerts.tick();
    assert.equal(r.fm.registry.hosts.get(HOST_A).capability_health, 'ok', 're-asserted');
    // The cap is full, then the host goes offline: the critical alert still opens.
    agent.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    const now = r.fm.capAlerts.now();
    r.fm.capAlerts.opens.set(HOST_A, Array.from({ length: 6 }, () => now - 1000));
    r.advance(OFFLINE_AFTER_MS);
    await r.fm.capAlerts.tick();
    assert.deepEqual(alertsOf(r, 'host:offline').map((a) => a.status), ['open']);
  } finally { await r.close(); }
});
