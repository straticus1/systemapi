'use strict';

// Agent capability health (plan sah-fleet-readiness P1b), control plane:
// the capability_report validator, its rate limits and disconnect, routing
// (supported header minus degraded header minus reported degradations), the
// sys write tokens, storage only on change, expected capabilities, host
// health, and GET/POST /api/v1/hosts/:id/capabilities.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { issueTicket } = require('../controlplane/tickets');
const { parseFilePolicy, parseConfigPolicy, parseServicePolicy, parsePackagePolicy, parseTweakPolicy, parseTcpPolicy } = require('../controlplane/channels');
const {
  validateCapabilityReport, ConnectionCapabilities, expectedCapabilities, hostHealth, KNOWN_CAPABILITIES
} = require('../controlplane/capabilities');
const { requiredCapability, SYS_RESOURCES } = require('../playground/sys');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const KEYS = {
  'agent-key': { key_id: 'k-agent', user_id: 'user-1' },
  'admin-key': { key_id: 'k-admin', user_id: 'user-1' },
  'read-key': { key_id: 'k-read', user_id: 'user-1' },
  'beta-key': { key_id: 'k-beta', user_id: 'user-2' }
};
const NOW = '2026-11-03T12:00:00Z';
const CFG_PATH = '/etc/nginx/nginx.conf';
const SYSCTL_KEY = 'net.ipv4.ip_forward';

function report(caps, over = {}) {
  return { type: 'capability_report', v: 1, probed_at: NOW, caps, ...over };
}
const bytesOf = (msg) => Buffer.byteLength(JSON.stringify(msg));
const validate = (msg) => validateCapabilityReport(msg, bytesOf(msg));

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

const tick = (ms = 50) => new Promise((r) => setTimeout(r, ms));

// --- pure: the validator ---

test('a valid report is accepted; unknown names are dropped, not refused', () => {
  const out = validate(report([
    { name: 'file', state: 'degraded', reason: 'enosys_openat2' },
    { name: 'pty', state: 'ok', reason: '' },
    { name: 'tcp', state: 'ok' },
    { name: 'teleport', state: 'ok', reason: '' }
  ]));
  assert.equal(out.ok, true);
  assert.equal(out.dropped, 1);
  assert.deepEqual(out.report.caps, [
    { name: 'file', state: 'degraded', reason: 'enosys_openat2' },
    { name: 'pty', state: 'ok', reason: '' },
    { name: 'tcp', state: 'ok', reason: '' }
  ]);
  assert.equal(out.report.probedAt, '2026-11-03T12:00:00.000Z');
});

test('the validator refuses the whole frame: >16 entries, bad or ok-with reason, bad state, v, probed_at, duplicates, size', () => {
  const many = Array.from({ length: 17 }, () => ({ name: 'nope', state: 'ok', reason: '' }));
  const cases = [
    [report(many), 'too_many'],
    [report([{ name: 'file', state: 'degraded', reason: 'disk_on_fire' }]), 'bad_reason'],
    [report([{ name: 'file', state: 'degraded', reason: '/etc/passwd: EACCES' }]), 'bad_reason'],
    [report([{ name: 'file', state: 'ok', reason: 'probe_error' }]), 'bad_reason'],
    [report([{ name: 'file', state: 'degraded', reason: 7 }]), 'bad_reason'],
    [report([{ name: 'file', state: 'broken', reason: '' }]), 'bad_state'],
    [report([{ name: 'file', state: 'ok' }, { name: 'file', state: 'degraded', reason: 'probe_error' }]), 'duplicate'],
    [report([{ state: 'ok' }]), 'bad_entry'],
    [report(['file']), 'bad_entry'],
    [report([], { v: 2 }), 'bad_version'],
    [report([], { v: '1' }), 'bad_version'],
    [report([], { probed_at: 'yesterday' }), 'bad_probed_at'],
    [report([], { probed_at: '2026-13-45T99:00:00Z' }), 'bad_probed_at'],
    [report([], { probed_at: 1730635200 }), 'bad_probed_at'],
    [report({}), 'bad_caps']
  ];
  for (const [msg, error] of cases) assert.deepEqual(validate(msg), { ok: false, error }, JSON.stringify(msg));
  assert.deepEqual(validateCapabilityReport(report([]), 9000), { ok: false, error: 'too_large' });
  assert.deepEqual(validateCapabilityReport(null, 10), { ok: false, error: 'bad_frame' });
  // Exactly 16 is fine.
  assert.equal(validate(report(many.slice(0, 16))).ok, true);
});

// --- pure: routing ---

test('routing: degraded header before any report, a report cannot add, a missing name keeps its state', () => {
  const c = new ConnectionCapabilities(new Set(['pty', 'file', 'tcp', 'config']), new Set(['file', 'package']));
  assert.deepEqual(c.effective(), ['config', 'pty', 'tcp'], 'header minus degraded header');
  assert.equal(c.supports('file'), false);
  assert.equal(c.unsupportedReason('file'), 'probe_error');
  assert.equal(c.supports('package'), false, 'a degraded name never in the header stays out');
  c.applyReport({ probedAt: NOW, caps: [
    { name: 'package', state: 'ok', reason: '' },
    { name: 'tcp', state: 'degraded', reason: 'probe_error' },
    { name: 'file', state: 'degraded', reason: 'enosys_openat2' }
  ] });
  assert.equal(c.supports('package'), false, 'a report cannot add a name the header lacks');
  assert.deepEqual(c.effective(), ['config', 'pty']);
  assert.equal(c.unsupportedReason('file'), 'enosys_openat2');
  assert.equal(c.reported.get('package').state, 'ok', 'kept for health');
  // A later report that omits tcp and file keeps them withdrawn; file ok again
  // restores it.
  c.applyReport({ probedAt: NOW, caps: [{ name: 'pty', state: 'ok', reason: '' }] });
  assert.deepEqual(c.effective(), ['config', 'pty']);
  c.applyReport({ probedAt: NOW, caps: [{ name: 'file', state: 'ok', reason: '' }] });
  assert.deepEqual(c.effective(), ['config', 'file', 'pty']);
  assert.equal(c.unsupportedReason('tcp'), 'probe_error');
  assert.equal(c.unsupportedReason('xfer'), null, 'never advertised: no reason, as before');
});

test('routing: sysscript_jobs and converge follow the header only', () => {
  const c = new ConnectionCapabilities(new Set(['sysscript_jobs', 'converge']), new Set(['sysscript_jobs', 'converge']));
  assert.equal(c.supports('sysscript_jobs'), true);
  assert.equal(c.supports('converge'), true);
  c.applyReport({ probedAt: NOW, caps: [
    { name: 'sysscript_jobs', state: 'degraded', reason: 'probe_error' },
    { name: 'converge', state: 'absent', reason: 'flag_off' }
  ] });
  assert.equal(c.supports('sysscript_jobs'), true);
  assert.equal(c.supports('converge'), true);
  assert.deepEqual(c.effective(), ['converge', 'sysscript_jobs']);
});

test('sys write verbs need their *_write token from a new agent, config/tweak from an old one', () => {
  const cfg = SYS_RESOURCES['sys:config'];
  const twk = SYS_RESOURCES['sys:tweak'];
  const fresh = new Set(['config', 'tweak', 'config_write']);
  const old = new Set(['config', 'tweak']);
  assert.equal(requiredCapability(cfg, { action: 'write' }, fresh), 'config_write');
  assert.equal(requiredCapability(cfg, { action: 'read' }, fresh), 'config');
  assert.equal(requiredCapability(cfg, { action: 'reload' }, fresh), 'config');
  assert.equal(requiredCapability(twk, { verb: 'sysctl-set' }, fresh), 'sysctl_write');
  assert.equal(requiredCapability(twk, { verb: 'sysctl-get' }, fresh), 'tweak');
  assert.equal(requiredCapability(twk, { verb: 'unit-override-set' }, fresh), 'override_write');
  assert.equal(requiredCapability(twk, { verb: 'resource-limit-set' }, fresh), 'override_write');
  assert.equal(requiredCapability(cfg, { action: 'write' }, old), 'config');
  assert.equal(requiredCapability(twk, { verb: 'sysctl-set' }, old), 'tweak');
  assert.equal(requiredCapability(SYS_RESOURCES['sys:service'], { unit: 'x.service', action: 'restart' }, fresh), 'service');
  const c = new ConnectionCapabilities(fresh, new Set());
  assert.equal(c.unsupportedReason('sysctl_write'), 'helper_unit_missing');
  c.applyReport({ probedAt: NOW, caps: [{ name: 'sysctl_write', state: 'absent', reason: 'no_systemd' }] });
  assert.equal(c.unsupportedReason('sysctl_write'), 'no_systemd', 'the reported reason wins');
  assert.equal(new ConnectionCapabilities(old, new Set()).unsupportedReason('config_write'), null);
});

// --- pure: expected and health ---

test('expected capabilities follow each policy kind', () => {
  const none = { tcp: parseTcpPolicy(null), file: parseFilePolicy(null), service: parseServicePolicy(null), package: parsePackagePolicy(null), config: parseConfigPolicy(null), tweak: parseTweakPolicy(null) };
  assert.deepEqual(expectedCapabilities(none), []);
  assert.deepEqual(expectedCapabilities({}), []);
  assert.deepEqual(expectedCapabilities({ ...none, file: parseFilePolicy({ roots: [{ path: '/srv', read: true }] }) }), ['file']);
  assert.deepEqual(expectedCapabilities({ ...none, file: parseFilePolicy({ roots: [{ path: '/srv', read: true, write: true }] }) }), ['file', 'xfer']);
  assert.deepEqual(expectedCapabilities({ ...none, config: parseConfigPolicy({ paths: ['/etc/nginx'] }) }), ['config', 'config_write']);
  assert.deepEqual(expectedCapabilities({ ...none, service: parseServicePolicy({ units: ['nginx.service'] }) }), ['service']);
  assert.deepEqual(expectedCapabilities({ ...none, tweak: parseTweakPolicy({ sysctls: [SYSCTL_KEY] }) }), ['sysctl_write', 'tweak']);
  assert.deepEqual(expectedCapabilities({ ...none, tweak: parseTweakPolicy({ units: ['nginx.service'] }) }), ['override_write', 'tweak']);
  assert.deepEqual(expectedCapabilities({ ...none, package: parsePackagePolicy({ names: ['nginx'] }) }), ['package']);
  assert.deepEqual(expectedCapabilities({ ...none, tcp: parseTcpPolicy({ allow: [{ local: true, ports: [5432] }] }) }), ['tcp']);
  // A malformed policy parses to null (deny-all) and expects nothing.
  assert.deepEqual(expectedCapabilities({ ...none, file: parseFilePolicy('bad'), tcp: null }), []);
  for (const name of expectedCapabilities({
    file: parseFilePolicy({ roots: [{ path: '/srv', read: true, write: true }] }),
    config: parseConfigPolicy({ paths: ['/etc/nginx'] }),
    service: parseServicePolicy({ units: ['a.service'] }),
    package: parsePackagePolicy({ names: ['a'] }),
    tweak: parseTweakPolicy({ sysctls: [SYSCTL_KEY], units: ['a.service'] }),
    tcp: parseTcpPolicy({ allow: [{ local: true, ports: [1] }] })
  })) assert.ok(KNOWN_CAPABILITIES.includes(name), name);
});

test('health: offline, unknown before a report, ok, degraded on an expected capability only', () => {
  const c = new ConnectionCapabilities(new Set(['file', 'tcp']), new Set());
  assert.equal(hostHealth({ connected: false, conn: c, expected: ['file'] }), 'offline');
  assert.equal(hostHealth({ connected: true, conn: c, expected: ['file'] }), 'unknown');
  assert.equal(hostHealth({ connected: true, conn: null, expected: [] }), 'unknown');
  c.applyReport({ probedAt: NOW, caps: [{ name: 'tcp', state: 'degraded', reason: 'probe_error' }] });
  assert.equal(hostHealth({ connected: true, conn: c, expected: ['file'] }), 'ok', 'tcp is not expected');
  assert.equal(hostHealth({ connected: true, conn: c, expected: ['file', 'tcp'] }), 'degraded');
  assert.equal(hostHealth({ connected: true, conn: c, expected: ['file', 'xfer'] }), 'degraded', 'expected but never advertised');
});

// --- integration: FleetManager over WebSocket, the router mounted ---

function signer() {
  const key = privateKeyFromSeed(TEST_SEED);
  return buildSigner(key, rawPublicKey(key));
}

async function rig() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test' };
  fm.signer = signer();
  fm.tickets = new Map();
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.auditRetryDelaysMs = [10, 10];
  fm.sys.resultWaitMs = 500;
  fm.verifyApiKey = async (key) => KEYS[key] || null;
  fm.changes = [];
  fm.onCapabilityChange = (hostId, changes) => fm.changes.push({ hostId, changes });
  const writes = [];
  const set = fm.registry.setHostCapabilities.bind(fm.registry);
  fm.registry.setHostCapabilities = async (hostId, rows) => { writes.push(rows.map((r) => r.name)); return set(hostId, rows); };
  mount(app, fm);
  await fm.registry.setScopes('k-admin', ['admin']);
  await fm.registry.setScopes('k-read', ['hosts:read']);
  await fm.registry.setScopes('k-beta', ['admin']);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const sockets = [];
  return {
    fm,
    writes,
    url: `http://127.0.0.1:${port}`,
    base: `ws://127.0.0.1:${port}`,
    track(ws) { sockets.push(ws); return ws; },
    async close() {
      for (const ws of sockets) if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.terminate();
      for (const s of fm.sys.sessions.values()) fm.sys.end(s, 'stopped', {});
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

function collect(ws) {
  const box = { frames: [], closeCode: null };
  ws.on('message', (data, isBinary) => { if (!isBinary) box.frames.push(JSON.parse(data.toString())); });
  ws.on('close', (code) => { box.closeCode = code; });
  ws.on('error', () => {});
  return box;
}

function dial(r, { hostId = HOST_A, tenant = 'acme', caps = 'pty,file,tcp,xfer,config,tweak,config_write,sysctl_write,override_write,sysscript_jobs', degraded, key = 'agent-key' } = {}) {
  const headers = {
    authorization: `Bearer ${key}`,
    'x-systemapi-tenant': tenant,
    'x-systemapi-host-id': hostId,
    'x-systemapi-hostname': hostId === HOST_A ? 'a.example' : 'b.example',
    'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
  };
  if (caps !== null) headers['x-systemapi-capabilities'] = caps;
  if (degraded !== undefined) headers['x-systemapi-capabilities-degraded'] = degraded;
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, { headers }));
  return { ws, box: collect(ws) };
}

async function connectAgent(r, opts = {}) {
  const agent = dial(r, opts);
  await waitUntil('enrolled', () => agent.box.frames.find((f) => f.type === 'enrolled'));
  return agent;
}

const send = (agent, msg) => agent.ws.send(JSON.stringify(msg));

async function call(r, method, pathname, key = 'admin-key') {
  const res = await fetch(`${r.url}${pathname}`, { method, headers: { 'x-api-key': key } });
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch { /* text */ }
  return { status: res.status, body };
}

test('a report before enroll is ignored and counted', async () => {
  const r = await rig();
  try {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const enroll = r.fm.registry.enroll.bind(r.fm.registry);
    r.fm.registry.enroll = async (args) => { await gate; return enroll(args); };
    const agent = dial(r);
    await new Promise((resolve) => agent.ws.once('open', resolve));
    send(agent, report([{ name: 'file', state: 'degraded', reason: 'probe_error' }]));
    await waitUntil('pre-enroll drop', () => r.fm.capReportDrops.get('pre_enroll') === 1);
    release();
    await waitUntil('enrolled', () => agent.box.frames.find((f) => f.type === 'enrolled'));
    assert.equal(r.fm.agentSupports(HOST_A, 'file'), true, 'the early frame changed nothing');
    assert.deepEqual(r.writes, []);
  } finally { await r.close(); }
});

test('flood: one in flight, a 60 s gap, every refusal counted, 10 violations in 10 min close 1008', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    // The first report is in flight (its write is held).
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const set = r.fm.registry.setHostCapabilities;
    r.fm.registry.setHostCapabilities = async (h, rows) => { await gate; return set(h, rows); };
    send(agent, report([{ name: 'file', state: 'ok' }]));
    await waitUntil('in flight', () => r.fm.capReportLimits.get(HOST_A) && r.fm.capReportLimits.get(HOST_A).inFlight);
    send(agent, report([{ name: 'file', state: 'ok' }]));
    await waitUntil('in_flight drop', () => r.fm.capReportDrops.get('in_flight') === 1);
    release();
    await waitUntil('first stored', () => !r.fm.capReportLimits.get(HOST_A).inFlight);
    assert.equal(r.writes.length, 1);
    // Inside the gap: dropped and counted.
    send(agent, report([{ name: 'file', state: 'degraded', reason: 'probe_error' }]));
    await waitUntil('too_soon drop', () => r.fm.capReportDrops.get('too_soon') === 1);
    assert.equal(r.fm.agentSupports(HOST_A, 'file'), true, 'a dropped report changes nothing');
    // Refused frames count as violations too (with the gap out of the way,
    // they reach the validator); the 10th closes the socket.
    r.fm.capReportGapMs = 0;
    for (let i = 0; i < 7; i += 1) send(agent, { type: 'capability_report', v: 9 });
    await waitUntil('bad_version drops', () => r.fm.capReportDrops.get('bad_version') === 7);
    assert.equal(agent.box.closeCode, null, 'nine violations: still open');
    send(agent, report([], { probed_at: 'x' }));
    await waitUntil('closed 1008', () => agent.box.closeCode === 1008);
    await waitUntil('security event', () => r.fm.registry.securityEvents.find((e) => e.kind === 'agent_capability_flood'));
    // Unknown frame types still fall through silently.
    assert.equal(r.fm.capReportDrops.get('bad_probed_at'), 1);
  } finally { await r.close(); }
});

test('violations older than the window are forgotten; after the gap a report is accepted', async () => {
  const r = await rig();
  try {
    r.fm.capReportGapMs = 150;
    r.fm.capViolationWindowMs = 100;
    r.fm.capViolationMax = 3;
    const agent = await connectAgent(r);
    send(agent, { type: 'some_future_frame', x: 1 });
    send(agent, { type: 'capability_report', v: 2 });
    send(agent, { type: 'capability_report', v: 2 });
    await waitUntil('two drops', () => r.fm.capReportDrops.get('bad_version') === 2);
    await tick(150);
    send(agent, { type: 'capability_report', v: 2 });
    await waitUntil('third drop', () => r.fm.capReportDrops.get('bad_version') === 3);
    await tick(50);
    assert.equal(agent.box.closeCode, null, 'the first two aged out');
    send(agent, report([{ name: 'file', state: 'ok' }]));
    await waitUntil('stored', () => r.writes.length === 1);
    send(agent, report([{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }]));
    await waitUntil('too soon', () => r.fm.capReportDrops.get('too_soon') === 1);
    await tick(200);
    send(agent, report([{ name: 'file', state: 'degraded', reason: 'enosys_openat2' }]));
    await waitUntil('second stored', () => r.writes.length === 2);
    assert.equal(r.fm.agentSupports(HOST_A, 'file'), false);
  } finally { await r.close(); }
});

test('storage: only changed rows are written, one call per report; health rows for names outside the header', async () => {
  const r = await rig();
  try {
    r.fm.capReportGapMs = 0;
    const agent = await connectAgent(r, { caps: 'pty,file' });
    send(agent, report([
      { name: 'pty', state: 'ok' },
      { name: 'file', state: 'degraded', reason: 'enosys_openat2' },
      { name: 'package', state: 'absent', reason: 'binary_missing' }
    ]));
    await waitUntil('first write', () => r.writes.length === 1);
    assert.deepEqual(r.writes[0], ['pty', 'file', 'package']);
    await waitUntil('change hook', () => r.fm.changes.length === 1);
    assert.deepEqual(r.fm.changes[0].changes.map((c) => [c.name, c.previous_state, c.state]),
      [['file', null, 'degraded'], ['package', null, 'absent'], ['pty', null, 'ok']]);
    // The same report again: nothing written, no hook.
    send(agent, report([
      { name: 'pty', state: 'ok' },
      { name: 'file', state: 'degraded', reason: 'enosys_openat2' },
      { name: 'package', state: 'absent', reason: 'binary_missing' }
    ]));
    await waitUntil('second accepted', () => r.fm.agentCapState.get(r.fm.connectedAgents.get(HOST_A)).reportCount === 2);
    await tick();
    assert.equal(r.writes.length, 1);
    send(agent, report([{ name: 'pty', state: 'ok' }, { name: 'file', state: 'ok' }]));
    await waitUntil('third write', () => r.writes.length === 2);
    assert.deepEqual(r.writes[1], ['file']);
    await waitUntil('second hook', () => r.fm.changes.length === 2);
    assert.deepEqual(r.fm.changes[1].changes.map((c) => [c.name, c.previous_state, c.state]), [['file', 'degraded', 'ok']]);
    const rows = await r.fm.registry.listHostCapabilities(HOST_A);
    assert.deepEqual(rows.map((c) => [c.name, c.state, c.reason]),
      [['file', 'ok', ''], ['package', 'absent', 'binary_missing'], ['pty', 'ok', '']]);
    assert.equal(r.fm.agentSupports(HOST_A, 'package'), false, 'stored, never routed');
  } finally { await r.close(); }
});

test('a failed write is logged, routing keeps the report, and the next report writes every row again', async () => {
  const r = await rig();
  try {
    r.fm.capReportGapMs = 0;
    const agent = await connectAgent(r, { caps: 'pty,file' });
    const set = r.fm.registry.setHostCapabilities;
    let fail = true;
    r.fm.registry.setHostCapabilities = async (h, rows) => {
      if (fail) { fail = false; r.writes.push('failed'); throw Object.assign(new Error('db down'), { code: 'ECONNRESET' }); }
      return set(h, rows);
    };
    send(agent, report([{ name: 'pty', state: 'ok' }, { name: 'file', state: 'degraded', reason: 'probe_error' }]));
    await waitUntil('failed write', () => r.writes.length === 1);
    assert.equal(r.fm.agentSupports(HOST_A, 'file'), false);
    send(agent, report([{ name: 'pty', state: 'ok' }, { name: 'file', state: 'degraded', reason: 'probe_error' }]));
    await waitUntil('retried write', () => r.writes.length === 2);
    assert.deepEqual(r.writes[1], ['pty', 'file']);
  } finally { await r.close(); }
});

test('routing on a live agent: degraded header before a report, then a report, with the reason on 501', async () => {
  const r = await rig();
  try {
    r.fm.capReportGapMs = 0;
    const agent = await connectAgent(r, { caps: 'pty,file,tcp,xfer,sysscript_jobs,converge', degraded: 'file,sysscript_jobs,converge' });
    assert.equal(r.fm.agentSupports(HOST_A, 'file'), false);
    assert.equal(r.fm.agentUnsupportedReason(HOST_A, 'file'), 'probe_error');
    assert.equal(r.fm.agentSupports(HOST_A, 'sysscript_jobs'), true, 'jobs follow the header');
    assert.equal(r.fm.jobs.capable(HOST_A), true);
    assert.deepEqual([...r.fm.agentCaps.get(r.fm.connectedAgents.get(HOST_A))].sort(),
      ['converge', 'file', 'pty', 'sysscript_jobs', 'tcp', 'xfer'], 'presence keeps the whole header');
    send(agent, report([
      { name: 'file', state: 'degraded', reason: 'enosys_openat2' },
      { name: 'tcp', state: 'degraded', reason: 'probe_error' },
      { name: 'sysscript_jobs', state: 'degraded', reason: 'probe_error' }
    ]));
    await waitUntil('report applied', () => !r.fm.agentSupports(HOST_A, 'tcp'));
    assert.equal(r.fm.agentUnsupportedReason(HOST_A, 'file'), 'enosys_openat2');
    assert.equal(r.fm.jobs.capable(HOST_A), true);
    // A file channel open answers agent_unsupported with the reason.
    await r.fm.registry.setHostChannelPolicy(HOST_A, { file_policy: { roots: [{ path: '/srv', read: true }] } });
    const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'file:read', tenantId: 'acme', actor: 'user-1', root: '/srv' });
    const client = collect(r.track(new WebSocket(`${r.base}/api/v1/systems/file/${HOST_A}?ticket=${ticket}&purpose=file:read`)));
    const status = await waitUntil('file_status', () => client.frames.find((f) => f.type === 'file_status' && f.payload.error));
    assert.deepEqual(status.payload, { error: 'agent_unsupported', reason: 'enosys_openat2' });
  } finally { await r.close(); }
});

// sys channel: a fake agent that answers every sys_config/sys_tweak ok.
async function sysAgent(r, caps) {
  const agent = await connectAgent(r, { caps });
  agent.requests = [];
  agent.ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const msg = JSON.parse(data.toString());
    if (msg.type !== 'sys_config' && msg.type !== 'sys_tweak') return;
    agent.requests.push(msg);
    agent.ws.send(JSON.stringify({ type: 'sys_result', request_id: msg.request_id, payload: { ok: true } }));
  });
  await r.fm.registry.setHostChannelPolicy(HOST_A, {
    config_policy: { paths: ['/etc/nginx'] },
    tweak_policy: { sysctls: [SYSCTL_KEY], units: ['nginx.service'] }
  });
  return agent;
}

async function sysOpen(r, purpose, sys) {
  const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose, tenantId: 'acme', actor: 'user-1', sys });
  const box = collect(r.track(new WebSocket(`${r.base}/api/v1/systems/sys/${HOST_A}?ticket=${ticket}&purpose=${purpose}`)));
  return waitUntil('sys_result', () => box.frames.find((f) => f.type === 'sys_result'));
}

test('sys writes on a new agent gate on the *_write tokens; reads stay on config/tweak', async () => {
  const r = await rig();
  try {
    r.fm.capReportGapMs = 0;
    const agent = await sysAgent(r, 'pty,config,tweak,config_write');
    assert.equal((await sysOpen(r, 'sys:config', { action: 'write', target: CFG_PATH, content: 'x\n' })).payload.ok, true);
    assert.deepEqual((await sysOpen(r, 'sys:tweak', { verb: 'sysctl-set', key: SYSCTL_KEY, value: '1' })).payload,
      { ok: false, error: 'agent_unsupported', reason: 'helper_unit_missing' });
    assert.deepEqual((await sysOpen(r, 'sys:tweak', { verb: 'unit-override-set', unit: 'nginx.service', name: 'limits', content: '[Service]\n' })).payload,
      { ok: false, error: 'agent_unsupported', reason: 'helper_unit_missing' });
    assert.equal((await sysOpen(r, 'sys:tweak', { verb: 'sysctl-get', key: SYSCTL_KEY })).payload.ok, true);
    assert.equal((await sysOpen(r, 'sys:config', { action: 'read', target: CFG_PATH })).payload.ok, true);
    assert.deepEqual(agent.requests.map((m) => m.action || m.verb), ['write', 'sysctl-get', 'read']);
    // The agent reports config_write degraded: writes are refused with that
    // reason, reads go on.
    send(agent, report([{ name: 'config_write', state: 'degraded', reason: 'helper_trust_missing' }]));
    await waitUntil('withdrawn', () => !r.fm.agentSupports(HOST_A, 'config_write'));
    assert.deepEqual((await sysOpen(r, 'sys:config', { action: 'write', target: CFG_PATH, content: 'x\n' })).payload,
      { ok: false, error: 'agent_unsupported', reason: 'helper_trust_missing' });
    assert.equal((await sysOpen(r, 'sys:config', { action: 'read', target: CFG_PATH })).payload.ok, true);
  } finally { await r.close(); }
});

test('sys writes on an old agent (no *_write token) gate on config/tweak as before', async () => {
  const r = await rig();
  try {
    const agent = await sysAgent(r, 'pty,config,tweak');
    assert.equal((await sysOpen(r, 'sys:config', { action: 'write', target: CFG_PATH, content: 'x\n' })).payload.ok, true);
    assert.equal((await sysOpen(r, 'sys:tweak', { verb: 'sysctl-set', key: SYSCTL_KEY, value: '1' })).payload.ok, true);
    assert.equal((await sysOpen(r, 'sys:tweak', { verb: 'resource-limit-set', unit: 'nginx.service', limit: 'LimitNOFILE', value: '4096' })).payload.ok, true);
    assert.equal(agent.requests.length, 3);
  } finally { await r.close(); }
});

test('API: capabilities and health through unknown, ok, degraded, offline; health in resolve and the fleet list', async () => {
  const r = await rig();
  try {
    r.fm.capReportGapMs = 0;
    const agent = await connectAgent(r, { caps: 'pty,file,xfer,sysscript_jobs' });
    await r.fm.registry.setHostChannelPolicy(HOST_A, { file_policy: { roots: [{ path: '/srv', read: true, write: true }] } });
    let out = await call(r, 'GET', `/api/v1/hosts/${HOST_A}/capabilities`, 'read-key');
    assert.equal(out.status, 200, JSON.stringify(out.body));
    assert.deepEqual(out.body, {
      host_id: HOST_A, health: 'unknown', supported: ['file', 'pty', 'sysscript_jobs', 'xfer'],
      effective: ['file', 'pty', 'sysscript_jobs', 'xfer'], expected: ['file', 'xfer'], caps: []
    });
    send(agent, report([{ name: 'file', state: 'ok' }, { name: 'xfer', state: 'ok' }, { name: 'pty', state: 'ok' }]));
    await waitUntil('ok', async () => (await call(r, 'GET', `/api/v1/hosts/${HOST_A}/capabilities`, 'read-key')).body.health === 'ok');
    send(agent, report([{ name: 'xfer', state: 'degraded', reason: 'binary_missing' }]));
    await waitUntil('degraded', async () => (await call(r, 'GET', `/api/v1/hosts/${HOST_A}/capabilities`, 'read-key')).body.health === 'degraded');
    out = await call(r, 'GET', `/api/v1/hosts/${HOST_A}/capabilities`, 'read-key');
    assert.deepEqual(out.body.effective, ['file', 'pty', 'sysscript_jobs']);
    const xfer = out.body.caps.find((c) => c.name === 'xfer');
    assert.equal(xfer.state, 'degraded');
    assert.equal(xfer.reason, 'binary_missing');
    assert.ok(xfer.since && xfer.last_report_at);
    const resolved = await call(r, 'GET', '/api/v1/hosts/resolve?name=a.example', 'read-key');
    assert.equal(resolved.body.health, 'degraded');
    const list = await call(r, 'GET', '/api/v1/fleet', 'read-key');
    assert.equal(list.body.hosts[0].health, 'degraded');
    agent.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    out = await call(r, 'GET', `/api/v1/hosts/${HOST_A}/capabilities`, 'read-key');
    assert.equal(out.body.health, 'offline');
    assert.deepEqual(out.body.supported, []);
    assert.equal(out.body.caps.length, 3, 'stored health outlives the socket');
    // A new connection starts unknown again.
    await connectAgent(r, { caps: 'pty,file,xfer' });
    assert.equal((await call(r, 'GET', `/api/v1/hosts/${HOST_A}/capabilities`, 'read-key')).body.health, 'unknown');
  } finally { await r.close(); }
});

test('API: another tenant gets 404 with an idor event; probe is admin-only and 409 host_offline without a socket', async () => {
  const r = await rig();
  try {
    await r.fm.registry.enroll({ tenantId: 'beta', userId: 'user-2', keyId: 'k2', hostId: HOST_B, hostname: 'b.example', os: '', platform: '', sshPubkey: null });
    const agent = await connectAgent(r);
    const before = r.fm.registry.securityEvents.filter((e) => e.kind === 'idor').length;
    const stranger = await call(r, 'GET', `/api/v1/hosts/${HOST_A}/capabilities`, 'beta-key');
    assert.deepEqual(stranger, { status: 404, body: { error: 'not_found' } });
    assert.equal((await call(r, 'POST', `/api/v1/hosts/${HOST_A}/capabilities/probe`, 'beta-key')).status, 404);
    assert.equal(r.fm.registry.securityEvents.filter((e) => e.kind === 'idor').length, before + 2);
    assert.equal(agent.box.frames.filter((f) => f.type === 'capability_probe').length, 0);
    assert.equal((await call(r, 'POST', `/api/v1/hosts/${HOST_A}/capabilities/probe`, 'read-key')).status, 403);
    const probe = await call(r, 'POST', `/api/v1/hosts/${HOST_A}/capabilities/probe`, 'admin-key');
    assert.deepEqual(probe, { status: 202, body: { host_id: HOST_A, probe: 'sent' } });
    await waitUntil('probe frame', () => agent.box.frames.find((f) => f.type === 'capability_probe'));
    // The answer to a probe is not held to the gap.
    send(agent, report([{ name: 'file', state: 'ok' }]));
    await waitUntil('first', () => r.writes.length === 1);
    assert.equal((await call(r, 'POST', `/api/v1/hosts/${HOST_A}/capabilities/probe`, 'admin-key')).status, 202);
    send(agent, report([{ name: 'file', state: 'degraded', reason: 'probe_error' }]));
    await waitUntil('probe answer stored', () => r.writes.length === 2);
    assert.equal(r.fm.capReportDrops.get('too_soon'), undefined);
    send(agent, report([{ name: 'file', state: 'ok' }]));
    await waitUntil('no credit left', () => r.fm.capReportDrops.get('too_soon') === 1);
    // B is beta's and offline: 409 for beta's admin.
    assert.deepEqual(await call(r, 'POST', `/api/v1/hosts/${HOST_B}/capabilities/probe`, 'beta-key'),
      { status: 409, body: { error: 'host_offline' } });
  } finally { await r.close(); }
});

test('xfer answers 501 agent_unsupported with the reason when xfer is withdrawn', async () => {
  const r = await rig();
  try {
    await connectAgent(r, { caps: 'pty,file,xfer', degraded: 'xfer' });
    r.fm.env = { NODE_ENV: 'test', SYSTEMAPI_XFER_PEER_UDP: '127.0.0.1:9' };
    const host = await r.fm.registry.getHost(['acme'], HOST_A);
    const err = await r.fm.xfer.grant({ principal: { userId: 'user-1' }, host, request: { dir: 'put', transport: 'udp' } }).catch((e) => e);
    assert.equal(err.status, 501);
    assert.equal(err.code, 'agent_unsupported');
    assert.equal(err.reason, 'probe_error');
  } finally { await r.close(); }
});

test('the report and probe frames never carry more than names, states and reason codes', () => {
  const out = validate(report([{ name: 'file', state: 'degraded', reason: 'enosys_openat2', detail: '/srv/secret: EPERM' }]));
  assert.equal(out.ok, true);
  assert.deepEqual(Object.keys(out.report.caps[0]).sort(), ['name', 'reason', 'state']);
});
