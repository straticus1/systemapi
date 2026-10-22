'use strict';

// Service-management channel (docs/sah-os-management-design.md Phase 1):
// client <-> FleetManager <-> fake agent. The server side of the restart
// slice — ticket, signed lease, forward, result, and the intent/result audit
// rows. The agent's own lease verify and policy gate are in
// systemapi-agent/sys_test.go.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { issueTicket } = require('../controlplane/tickets');
const { verifyLease, sysServicePayload, sysPackagePayload, sysConfigPayload, sysTweakPayload } = require('../controlplane/lease');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));
const UNIT = 'nginx.service';
const POLICY = { units: [UNIT] };
const PKG = 'nginx';
const PKG_POLICY = { names: [PKG] };
const CFG_PATH = '/etc/nginx/nginx.conf';
const CFG_POLICY = { paths: ['/etc/nginx'] };
const SYSCTL_KEY = 'net.ipv4.ip_forward';
const TWEAK_POLICY = { sysctls: [SYSCTL_KEY], units: [UNIT] };
const sha256Hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function signer() {
  const key = privateKeyFromSeed(TEST_SEED);
  return buildSigner(key, rawPublicKey(key));
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
    const value = fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

function collect(ws) {
  const box = { frames: [], closeCode: null };
  ws.on('message', (data, isBinary) => {
    if (!isBinary) box.frames.push(JSON.parse(data.toString()));
  });
  ws.on('close', (code) => { box.closeCode = code; });
  ws.on('error', () => {});
  return box;
}

async function rig(env = {}) {
  const server = http.createServer();
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test', ...env };
  fm.signer = signer();
  fm.tickets = new Map();
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.auditRetryDelaysMs = [10, 10];
  fm.sys.resultWaitMs = 500;
  fm.verifyApiKey = async (key) => (key === 'agent-key' ? { key_id: 'k1', user_id: 'user-1' } : null);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `ws://127.0.0.1:${server.address().port}`;
  const sockets = [];
  return {
    fm,
    base,
    track(ws) { sockets.push(ws); return ws; },
    async close() {
      for (const ws of sockets) if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.terminate();
      for (const s of fm.sys.sessions.values()) fm.sys.end(s, 'stopped', {});
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

// Connects a fake agent. autoRestart: the agent answers every sys_service with
// a sys_result (ok unless opts.fail).
async function connectAgent(r, { caps = 'pty,service', policy = POLICY, autoRestart = true, fail = false } = {}) {
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': HOST_A,
      'x-systemapi-hostname': 'a.example',
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      ...(caps === null ? {} : { 'x-systemapi-capabilities': caps })
    }
  }));
  const box = collect(ws);
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  if (policy) await r.fm.registry.setHostChannelPolicy(HOST_A, { service_policy: policy });
  const agent = { ws, box, requests: [] };
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const msg = JSON.parse(data.toString());
    if (msg.type !== 'sys_service') return;
    agent.requests.push(msg);
    if (!autoRestart) return;
    ws.send(JSON.stringify({
      type: 'sys_result',
      request_id: msg.request_id,
      payload: fail
        ? { ok: false, unit: msg.unit, action: msg.action, error: 'action_failed' }
        : { ok: true, unit: msg.unit, action: msg.action, active: true, state: 'active', output: 'restarted' }
    }));
  });
  return agent;
}

function ticketFor(r, { unit = UNIT, action = 'restart', actor = 'user-1', auth = null } = {}) {
  return issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'sys:service', tenantId: 'acme', actor, auth, sys: { unit, action } });
}

function openRaw(r, { ticket, purpose = 'sys:service' } = {}) {
  const t = ticket || ticketFor(r);
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/sys/${HOST_A}?ticket=${t}&purpose=${purpose}`));
  return { ws, box: collect(ws), ticket: t };
}

function resultError(box) {
  const f = box.frames.find((x) => x.type === 'sys_result' && x.payload && x.payload.error);
  return f ? f.payload.error : null;
}

function okResult(box) {
  return box.frames.find((x) => x.type === 'sys_result' && x.payload && x.payload.ok === true);
}

async function failsWith(client, code) {
  await waitUntil(`error ${code}`, () => resultError(client.box) && client.box.closeCode !== null);
  assert.equal(resultError(client.box), code);
  assert.equal(client.box.closeCode, 1011);
}

function auditRows(r, action) {
  return r.fm.registry.audit.filter((row) => row.action === action);
}

test('restart runs end to end: signed lease, agent result, intent and result audit rows', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openRaw(r);
    const req = await waitUntil('sys_service frame', () => agent.requests[0]);
    // The lease signs the exact unit and action.
    assert.equal(req.unit, UNIT);
    assert.equal(req.action, 'restart');
    const v = verifyLease(PUBLIC_KEY, req.lease, sysServicePayload(UNIT, 'restart'));
    assert.equal(v.ok, true);
    assert.equal(req.lease.action, 'sys_service');

    const result = await waitUntil('sys_result', () => okResult(client.box));
    assert.equal(result.payload.unit, UNIT);
    assert.equal(result.payload.state, 'active');
    assert.equal(result.payload.active, true);

    // The intent row is written before the request is forwarded; the result
    // row after. Both are on the chain.
    await waitUntil('audit rows', () => auditRows(r, 'sys_service_result').length === 1);
    const intent = auditRows(r, 'sys_service_intent');
    const done = auditRows(r, 'sys_service_result');
    assert.equal(intent.length, 1);
    assert.deepEqual([intent[0].payload.unit, intent[0].payload.action], [UNIT, 'restart']);
    assert.equal(done.length, 1);
    assert.equal(done[0].payload.ok, true);
    assert.equal(done[0].payload.result_state, 'active');
    assert.equal(done[0].payload.request_id, intent[0].payload.request_id);
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
  } finally {
    await r.close();
  }
});

test('a stop verb runs end to end and the lease binds stop', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openRaw(r, { ticket: ticketFor(r, { action: 'stop' }) });
    const req = await waitUntil('sys_service frame', () => agent.requests[0]);
    assert.equal(req.action, 'stop');
    // The lease signs stop; it does not verify as any other verb.
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysServicePayload(UNIT, 'stop')).ok, true);
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysServicePayload(UNIT, 'restart')).ok, false);
    await waitUntil('sys_result', () => okResult(client.box));
    await waitUntil('result row', () => auditRows(r, 'sys_service_result').length === 1);
    assert.equal(auditRows(r, 'sys_service_intent')[0].payload.action, 'stop');
  } finally {
    await r.close();
  }
});

test('a verb outside the channel set is refused at the upgrade', async () => {
  const r = await rig();
  try {
    await connectAgent(r);
    // A ticket whose bound action is not a channel verb is refused at consume.
    const client = openRaw(r, { ticket: ticketFor(r, { action: 'reload' }) });
    await failsWith(client, 'ticket_invalid');
    assert.equal(auditRows(r, 'sys_service_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a failed restart still records ok:false and a result row', async () => {
  const r = await rig();
  try {
    await connectAgent(r, { fail: true });
    const client = openRaw(r);
    await waitUntil('sys_result', () => client.box.frames.find((f) => f.type === 'sys_result'));
    const f = client.box.frames.find((x) => x.type === 'sys_result');
    assert.equal(f.payload.ok, false);
    assert.equal(f.payload.error, 'action_failed');
    await waitUntil('result row', () => auditRows(r, 'sys_service_result').length === 1);
    assert.equal(auditRows(r, 'sys_service_result')[0].payload.ok, false);
  } finally {
    await r.close();
  }
});

test('a unit the host policy does not allow is refused at the upgrade', async () => {
  const r = await rig();
  try {
    await connectAgent(r); // policy allows only nginx.service
    const client = openRaw(r, { ticket: ticketFor(r, { unit: 'postgresql.service' }) });
    await failsWith(client, 'unit_denied');
    // Nothing was forwarded and no intent row written.
    assert.equal(auditRows(r, 'sys_service_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a host that does not advertise the service capability is refused', async () => {
  const r = await rig();
  try {
    await connectAgent(r, { caps: 'pty,tcp' }); // no service capability
    const client = openRaw(r);
    await failsWith(client, 'agent_unsupported');
    assert.equal(auditRows(r, 'sys_service_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a single-use ticket cannot be replayed', async () => {
  const r = await rig();
  try {
    await connectAgent(r);
    const first = openRaw(r);
    await waitUntil('first result', () => first.box.frames.find((f) => f.type === 'sys_result'));
    // The same ticket a second time is refused (already consumed).
    const replay = openRaw(r, { ticket: first.ticket });
    await failsWith(replay, 'ticket_invalid');
  } finally {
    await r.close();
  }
});

test('the agent going away ends an in-flight request and writes its result row', async () => {
  const r = await rig();
  try {
    // The agent takes the request but never answers.
    const agent = await connectAgent(r, { autoRestart: false });
    const client = openRaw(r);
    await waitUntil('request forwarded', () => agent.requests[0]);
    agent.ws.terminate();
    await failsWith(client, 'agent_disconnected');
    await waitUntil('result row', () => auditRows(r, 'sys_service_result').length === 1);
    assert.equal(auditRows(r, 'sys_service_result')[0].payload.reason, 'agent_disconnected');
  } finally {
    await r.close();
  }
});

// --- sys:package ---

// Connects a fake package-capable agent that answers every sys_package with a
// sys_result (ok unless opts.fail).
async function connectPackageAgent(r, { caps = 'pty,package', policy = PKG_POLICY, autoAnswer = true, fail = false } = {}) {
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': HOST_A,
      'x-systemapi-hostname': 'a.example',
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      ...(caps === null ? {} : { 'x-systemapi-capabilities': caps })
    }
  }));
  const box = collect(ws);
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  if (policy) await r.fm.registry.setHostChannelPolicy(HOST_A, { package_policy: policy });
  const agent = { ws, box, requests: [] };
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const msg = JSON.parse(data.toString());
    if (msg.type !== 'sys_package') return;
    agent.requests.push(msg);
    if (!autoAnswer) return;
    ws.send(JSON.stringify({
      type: 'sys_result',
      request_id: msg.request_id,
      payload: fail
        ? { ok: false, name: msg.name, action: msg.action, error: 'action_failed' }
        : { ok: true, name: msg.name, action: msg.action, output: `ran ${msg.action} ${msg.name}` }
    }));
  });
  return agent;
}

function pkgTicketFor(r, { name = PKG, action = 'install', actor = 'user-1', auth = null } = {}) {
  return issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'sys:package', tenantId: 'acme', actor, auth, sys: { name, action } });
}

function openPkg(r, { ticket, name, action } = {}) {
  const t = ticket || pkgTicketFor(r, { name, action });
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/sys/${HOST_A}?ticket=${t}&purpose=sys:package`));
  return { ws, box: collect(ws), ticket: t };
}

test('package install runs end to end: signed lease, agent result, intent and result audit rows', async () => {
  const r = await rig();
  try {
    const agent = await connectPackageAgent(r);
    const client = openPkg(r, { action: 'install' });
    const req = await waitUntil('sys_package frame', () => agent.requests[0]);
    assert.equal(req.name, PKG);
    assert.equal(req.action, 'install');
    // The lease signs the exact name and verb.
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysPackagePayload(PKG, 'install')).ok, true);
    assert.equal(req.lease.action, 'sys_package');
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysPackagePayload(PKG, 'remove')).ok, false);

    const result = await waitUntil('sys_result', () => okResult(client.box));
    assert.equal(result.payload.name, PKG);

    await waitUntil('audit rows', () => auditRows(r, 'sys_package_result').length === 1);
    const intent = auditRows(r, 'sys_package_intent');
    const done = auditRows(r, 'sys_package_result');
    assert.equal(intent.length, 1);
    assert.deepEqual([intent[0].payload.name, intent[0].payload.action], [PKG, 'install']);
    assert.equal(done.length, 1);
    assert.equal(done[0].payload.ok, true);
    assert.equal(done[0].payload.request_id, intent[0].payload.request_id);
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
  } finally {
    await r.close();
  }
});

test('package query (a read) still rides the lease and writes both audit rows', async () => {
  const r = await rig();
  try {
    const agent = await connectPackageAgent(r);
    const client = openPkg(r, { action: 'query' });
    const req = await waitUntil('sys_package frame', () => agent.requests[0]);
    assert.equal(req.action, 'query');
    await waitUntil('sys_result', () => okResult(client.box));
    await waitUntil('result row', () => auditRows(r, 'sys_package_result').length === 1);
    assert.equal(auditRows(r, 'sys_package_intent')[0].payload.action, 'query');
  } finally {
    await r.close();
  }
});

test('a package the host policy does not allow is refused at the upgrade', async () => {
  const r = await rig();
  try {
    await connectPackageAgent(r); // policy allows only nginx
    const client = openPkg(r, { ticket: pkgTicketFor(r, { name: 'curl' }) });
    await failsWith(client, 'package_denied');
    assert.equal(auditRows(r, 'sys_package_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a host that does not advertise the package capability is refused', async () => {
  const r = await rig();
  try {
    await connectPackageAgent(r, { caps: 'pty,service' }); // no package capability
    const client = openPkg(r);
    await failsWith(client, 'agent_unsupported');
    assert.equal(auditRows(r, 'sys_package_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a single-use package ticket cannot be replayed', async () => {
  const r = await rig();
  try {
    await connectPackageAgent(r);
    const first = openPkg(r);
    await waitUntil('first result', () => first.box.frames.find((f) => f.type === 'sys_result'));
    const replay = openPkg(r, { ticket: first.ticket });
    await failsWith(replay, 'ticket_invalid');
  } finally {
    await r.close();
  }
});

test('a failed package op records ok:false and a result row', async () => {
  const r = await rig();
  try {
    await connectPackageAgent(r, { fail: true });
    const client = openPkg(r);
    await waitUntil('sys_result', () => client.box.frames.find((f) => f.type === 'sys_result'));
    const f = client.box.frames.find((x) => x.type === 'sys_result');
    assert.equal(f.payload.ok, false);
    assert.equal(f.payload.error, 'action_failed');
    await waitUntil('result row', () => auditRows(r, 'sys_package_result').length === 1);
    assert.equal(auditRows(r, 'sys_package_result')[0].payload.ok, false);
  } finally {
    await r.close();
  }
});

// --- sys:config ---

// Connects a fake config-capable agent. It answers read with content, write
// with ok, reload with ok+output. configPolicy gates read/write paths; the
// reload path reuses servicePolicy (a reload acts on a unit).
async function connectConfigAgent(r, { caps = 'pty,config', configPolicy = CFG_POLICY, servicePolicy = POLICY, autoAnswer = true, fail = false } = {}) {
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': HOST_A,
      'x-systemapi-hostname': 'a.example',
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      ...(caps === null ? {} : { 'x-systemapi-capabilities': caps })
    }
  }));
  const box = collect(ws);
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  const pol = {};
  if (configPolicy) pol.config_policy = configPolicy;
  if (servicePolicy) pol.service_policy = servicePolicy;
  if (Object.keys(pol).length) await r.fm.registry.setHostChannelPolicy(HOST_A, pol);
  const agent = { ws, box, requests: [] };
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const msg = JSON.parse(data.toString());
    if (msg.type !== 'sys_config') return;
    agent.requests.push(msg);
    if (!autoAnswer) return;
    const payload = fail
      ? { ok: false, action: msg.action, target: msg.target, error: 'action_failed' }
      : msg.action === 'read'
        ? { ok: true, action: msg.action, target: msg.target, output: 'listen 80;\n' }
        : msg.action === 'reload'
          ? { ok: true, action: msg.action, target: msg.target, output: 'reloaded' }
          : { ok: true, action: msg.action, target: msg.target };
    ws.send(JSON.stringify({ type: 'sys_result', request_id: msg.request_id, payload }));
  });
  return agent;
}

function cfgTicketFor(r, { action = 'read', path = CFG_PATH, unit = UNIT, content, actor = 'user-1' } = {}) {
  const cfg = action === 'reload' ? { action, target: unit } : { action, target: path };
  if (action === 'write') cfg.content = content ?? 'server {}\n';
  return issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'sys:config', tenantId: 'acme', actor, sys: cfg });
}

function openCfg(r, opts = {}) {
  const t = opts.ticket || cfgTicketFor(r, opts);
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/sys/${HOST_A}?ticket=${t}&purpose=sys:config`));
  return { ws, box: collect(ws), ticket: t };
}

test('config read runs end to end and audits a content hash, not the body', async () => {
  const r = await rig();
  try {
    const agent = await connectConfigAgent(r);
    const client = openCfg(r, { action: 'read' });
    const req = await waitUntil('sys_config frame', () => agent.requests[0]);
    assert.equal(req.action, 'read');
    assert.equal(req.target, CFG_PATH);
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysConfigPayload('read', CFG_PATH)).ok, true);
    const result = await waitUntil('sys_result', () => okResult(client.box));
    assert.equal(result.payload.output, 'listen 80;\n');
    await waitUntil('result row', () => auditRows(r, 'sys_config_result').length === 1);
    const done = auditRows(r, 'sys_config_result')[0].payload;
    // The audit stores the hash/size of the returned body, never the body.
    assert.equal(done.content_sha256, sha256Hex('listen 80;\n'));
    assert.equal(JSON.stringify(done).includes('listen 80'), false);
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
  } finally {
    await r.close();
  }
});

test('config write binds the content hash and audits only the hash', async () => {
  const r = await rig();
  try {
    const agent = await connectConfigAgent(r);
    const content = 'server { listen 8080; }\n';
    const client = openCfg(r, { action: 'write', content });
    const req = await waitUntil('sys_config frame', () => agent.requests[0]);
    assert.equal(req.action, 'write');
    assert.equal(req.content, content);
    // The lease signs write\n<path>\n<sha256(content)>.
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysConfigPayload('write', CFG_PATH, sha256Hex(content))).ok, true);
    await waitUntil('sys_result', () => okResult(client.box));
    await waitUntil('result row', () => auditRows(r, 'sys_config_result').length === 1);
    const intent = auditRows(r, 'sys_config_intent')[0].payload;
    assert.equal(intent.content_sha256, sha256Hex(content));
    assert.equal(intent.content_bytes, Buffer.byteLength(content, 'utf8'));
    assert.equal(JSON.stringify(intent).includes('listen 8080'), false);
  } finally {
    await r.close();
  }
});

test('config reload targets a unit gated by the service allowlist', async () => {
  const r = await rig();
  try {
    const agent = await connectConfigAgent(r);
    const client = openCfg(r, { action: 'reload', unit: UNIT });
    const req = await waitUntil('sys_config frame', () => agent.requests[0]);
    assert.equal(req.action, 'reload');
    assert.equal(req.target, UNIT);
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysConfigPayload('reload', UNIT)).ok, true);
    await waitUntil('sys_result', () => okResult(client.box));
  } finally {
    await r.close();
  }
});

test('a config path the host policy does not allow is refused at the upgrade', async () => {
  const r = await rig();
  try {
    await connectConfigAgent(r); // allows only /etc/nginx
    const client = openCfg(r, { ticket: cfgTicketFor(r, { action: 'read', path: '/etc/postfix/main.cf' }) });
    await failsWith(client, 'path_denied');
    assert.equal(auditRows(r, 'sys_config_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a config reload for a unit the service policy does not allow is refused', async () => {
  const r = await rig();
  try {
    await connectConfigAgent(r); // service policy allows only nginx.service
    const client = openCfg(r, { ticket: cfgTicketFor(r, { action: 'reload', unit: 'postgresql.service' }) });
    await failsWith(client, 'unit_denied');
    assert.equal(auditRows(r, 'sys_config_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a host that does not advertise the config capability is refused', async () => {
  const r = await rig();
  try {
    await connectConfigAgent(r, { caps: 'pty,service' });
    const client = openCfg(r, { action: 'read' });
    await failsWith(client, 'agent_unsupported');
    assert.equal(auditRows(r, 'sys_config_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a single-use config ticket cannot be replayed', async () => {
  const r = await rig();
  try {
    await connectConfigAgent(r);
    const first = openCfg(r, { action: 'read' });
    await waitUntil('first result', () => first.box.frames.find((f) => f.type === 'sys_result'));
    const replay = openCfg(r, { ticket: first.ticket });
    await failsWith(replay, 'ticket_invalid');
  } finally {
    await r.close();
  }
});

// --- sys:tweak ---

async function connectTweakAgent(r, { caps = 'pty,tweak', tweakPolicy = TWEAK_POLICY, autoAnswer = true, fail = false } = {}) {
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': HOST_A,
      'x-systemapi-hostname': 'a.example',
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      ...(caps === null ? {} : { 'x-systemapi-capabilities': caps })
    }
  }));
  const box = collect(ws);
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  if (tweakPolicy) await r.fm.registry.setHostChannelPolicy(HOST_A, { tweak_policy: tweakPolicy });
  const agent = { ws, box, requests: [] };
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const msg = JSON.parse(data.toString());
    if (msg.type !== 'sys_tweak') return;
    agent.requests.push(msg);
    if (!autoAnswer) return;
    const base = { ok: !fail, verb: msg.verb };
    if (fail) base.error = 'action_failed';
    else if (msg.verb === 'sysctl-get') base.output = '1\n';
    ws.send(JSON.stringify({ type: 'sys_result', request_id: msg.request_id, payload: base }));
  });
  return agent;
}

function twkTicketFor(r, tweak, actor = 'user-1') {
  return issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'sys:tweak', tenantId: 'acme', actor, sys: tweak });
}

function openTwk(r, opts = {}) {
  const t = opts.ticket || twkTicketFor(r, opts.tweak || { verb: 'sysctl-get', key: SYSCTL_KEY });
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/sys/${HOST_A}?ticket=${t}&purpose=sys:tweak`));
  return { ws, box: collect(ws), ticket: t };
}

test('tweak sysctl-set runs end to end and the lease binds key and value', async () => {
  const r = await rig();
  try {
    const agent = await connectTweakAgent(r);
    const client = openTwk(r, { tweak: { verb: 'sysctl-set', key: SYSCTL_KEY, value: '1' } });
    const req = await waitUntil('sys_tweak frame', () => agent.requests[0]);
    assert.equal(req.verb, 'sysctl-set');
    assert.equal(req.key, SYSCTL_KEY);
    assert.equal(req.value, '1');
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysTweakPayload({ verb: 'sysctl-set', key: SYSCTL_KEY, value: '1' })).ok, true);
    // The value is bound: a lease for value 1 does not verify for value 0.
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysTweakPayload({ verb: 'sysctl-set', key: SYSCTL_KEY, value: '0' })).ok, false);
    await waitUntil('sys_result', () => okResult(client.box));
    await waitUntil('result row', () => auditRows(r, 'sys_tweak_result').length === 1);
    assert.equal(auditRows(r, 'sys_tweak_intent')[0].payload.value, '1');
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
  } finally {
    await r.close();
  }
});

test('tweak unit-override binds the body by hash and never audits it', async () => {
  const r = await rig();
  try {
    const agent = await connectTweakAgent(r);
    const content = '[Service]\nLimitNOFILE=65536\n';
    const client = openTwk(r, { tweak: { verb: 'unit-override-set', unit: UNIT, name: 'limit-nofile', content } });
    const req = await waitUntil('sys_tweak frame', () => agent.requests[0]);
    assert.equal(req.content, content);
    assert.equal(verifyLease(PUBLIC_KEY, req.lease, sysTweakPayload({ verb: 'unit-override-set', unit: UNIT, name: 'limit-nofile' }, sha256Hex(content))).ok, true);
    await waitUntil('sys_result', () => okResult(client.box));
    await waitUntil('result row', () => auditRows(r, 'sys_tweak_result').length === 1);
    const intent = auditRows(r, 'sys_tweak_intent')[0].payload;
    assert.equal(intent.content_sha256, sha256Hex(content));
    assert.equal(JSON.stringify(intent).includes('LimitNOFILE'), false);
  } finally {
    await r.close();
  }
});

test('a sysctl key the host policy does not allow is refused at the upgrade', async () => {
  const r = await rig();
  try {
    await connectTweakAgent(r); // allows only net.ipv4.ip_forward
    const client = openTwk(r, { ticket: twkTicketFor(r, { verb: 'sysctl-set', key: 'vm.swappiness', value: '10' }) });
    await failsWith(client, 'sysctl_denied');
    assert.equal(auditRows(r, 'sys_tweak_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a tweak unit the host policy does not allow is refused at the upgrade', async () => {
  const r = await rig();
  try {
    await connectTweakAgent(r); // units allow only nginx.service
    const client = openTwk(r, { ticket: twkTicketFor(r, { verb: 'resource-limit-set', unit: 'postgresql.service', limit: 'LimitNOFILE', value: '65536' }) });
    await failsWith(client, 'unit_denied');
    assert.equal(auditRows(r, 'sys_tweak_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a host that does not advertise the tweak capability is refused', async () => {
  const r = await rig();
  try {
    await connectTweakAgent(r, { caps: 'pty,service' });
    const client = openTwk(r);
    await failsWith(client, 'agent_unsupported');
    assert.equal(auditRows(r, 'sys_tweak_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('a single-use tweak ticket cannot be replayed', async () => {
  const r = await rig();
  try {
    await connectTweakAgent(r);
    const first = openTwk(r);
    await waitUntil('first result', () => first.box.frames.find((f) => f.type === 'sys_result'));
    const replay = openTwk(r, { ticket: first.ticket });
    await failsWith(replay, 'ticket_invalid');
  } finally {
    await r.close();
  }
});
