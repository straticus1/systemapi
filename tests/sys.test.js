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
const { verifyLease, sysServicePayload } = require('../controlplane/lease');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));
const UNIT = 'nginx.service';
const POLICY = { units: [UNIT] };

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
