'use strict';

// Terminal WebSocket sessions: client <-> FleetManager <-> fake agent.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { issueTicket } = require('../controlplane/tickets');
const { verifyLease, terminalPayload } = require('../controlplane/lease');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));

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

async function waitUntil(what, fn, timeout = 3000) {
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
    box.frames.push(isBinary ? { binary: Buffer.from(data) } : JSON.parse(data.toString()));
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
  fm.ptyFinalWaitMs = 200;
  fm.auditRetryDelaysMs = [10, 10];
  fm.verifyApiKey = async (key) => (key === 'agent-key' ? { key_id: 'k1', user_id: 'user-1' } : null);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `ws://127.0.0.1:${server.address().port}`;
  const sockets = [];
  return {
    fm,
    base,
    track(ws) { sockets.push(ws); return ws; },
    async close() {
      for (const ws of sockets) if (ws.readyState === WebSocket.OPEN) ws.terminate();
      for (const s of fm.terminalSessions.values()) { clearInterval(s.renewTimer); clearTimeout(s.maxTimer); }
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

async function connectAgent(r, extraHeaders = {}) {
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': HOST_A,
      'x-systemapi-hostname': 'a.example',
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      ...extraHeaders
    }
  }));
  const box = collect(ws);
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  return { ws, box };
}

function openClient(r, { purpose = 'terminal:open', query = '' } = {}) {
  const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose, tenantId: 'acme', actor: 'user-1' });
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=${ticket}&purpose=${purpose}${query}`));
  return { ws, box: collect(ws) };
}

function agentFrames(agent, type) {
  return agent.box.frames.filter((f) => f.type === type);
}

function sendStarted(agent, sessionId, extra = {}) {
  agent.ws.send(JSON.stringify({
    type: 'pty_status',
    session_id: sessionId,
    payload: { status: 'started', session_id: sessionId, pty_user: 'ops', recording: 'agent', ...extra }
  }));
}

function output(sessionId, text) {
  const id = Buffer.from(sessionId, 'latin1');
  return Buffer.concat([Buffer.from([id.length]), id, Buffer.from(text)]);
}

function textOf(box) {
  return Buffer.concat(box.frames.filter((f) => f.binary).map((f) => f.binary)).toString();
}

async function startSession(r, agent, opts) {
  const before = agentFrames(agent, 'pty_start').length;
  const client = openClient(r, opts);
  const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[before]);
  sendStarted(agent, start.session_id);
  await waitUntil('started', () => client.box.frames.find((f) => f.type === 'pty_status' && f.payload.status === 'started'));
  return { client, start };
}

test('pty_start carries a signed, session-bound lease, sizes and a deadline', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openClient(r, { query: '&rows=40&cols=120' });
    const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[0]);
    assert.match(start.session_id, /^pts_[A-Za-z0-9_-]{16,64}$/);
    assert.equal(start.action, 'pty');
    assert.equal(start.rows, 40);
    assert.equal(start.cols, 120);
    const now = Math.floor(Date.now() / 1000);
    assert.ok(Math.abs(start.deadline_unix - (now + 28800)) <= 2);
    const ok = verifyLease(PUBLIC_KEY, start.lease, terminalPayload(start.session_id, start.deadline_unix, 'start'));
    assert.equal(ok.ok, true);
    assert.equal(start.lease.action, 'pty');
    assert.equal(start.lease.host_id, HOST_A);
    assert.deepEqual(client.box.frames[0], { type: 'pty_status', payload: { status: 'starting' } });

    const root = openClient(r, { purpose: 'terminal:root' });
    const rootStart = await waitUntil('root start', () => agentFrames(agent, 'pty_start')[1]);
    assert.equal(rootStart.action, 'pty_root');
    assert.equal(rootStart.lease.action, 'pty_root');
    root.ws.close();
  } finally {
    await r.close();
  }
});

test('two sessions on one host do not collide', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const one = await startSession(r, agent);
    const two = await startSession(r, agent);
    assert.notEqual(one.start.session_id, two.start.session_id);

    agent.ws.send(output(one.start.session_id, 'out-one'));
    agent.ws.send(output(two.start.session_id, 'out-two'));
    await waitUntil('output one', () => textOf(one.client.box) === 'out-one');
    await waitUntil('output two', () => textOf(two.client.box) === 'out-two');

    two.client.ws.send(JSON.stringify({ type: 'pty_input', data_b64: Buffer.from('ls\n').toString('base64') }));
    one.client.ws.send(JSON.stringify({ type: 'pty_input', data: 'pwd\n' }));
    one.client.ws.send(JSON.stringify({ type: 'pty_resize', rows: 50, cols: 132 }));
    one.client.ws.send(JSON.stringify({ type: 'pty_resize', rows: 0, cols: 132 }));
    one.client.ws.send(JSON.stringify({ type: 'pty_eof' }));
    one.client.ws.send(JSON.stringify({ type: 'something_new' }));
    await waitUntil('eof', () => agentFrames(agent, 'pty_eof').length === 1);
    const inputs = agentFrames(agent, 'pty_input');
    assert.deepEqual(inputs.map((f) => [f.session_id, Buffer.from(f.data_b64, 'base64').toString()]).sort(), [
      [one.start.session_id, 'pwd\n'],
      [two.start.session_id, 'ls\n']
    ].sort());
    assert.deepEqual(agentFrames(agent, 'pty_resize'), [{ type: 'pty_resize', session_id: one.start.session_id, rows: 50, cols: 132 }]);
    assert.equal(agentFrames(agent, 'pty_eof')[0].session_id, one.start.session_id);

    one.client.ws.close();
    await waitUntil('stop one', () => agentFrames(agent, 'pty_stop').length === 1);
    assert.equal(agentFrames(agent, 'pty_stop')[0].session_id, one.start.session_id);
    agent.ws.send(output(two.start.session_id, '-still'));
    await waitUntil('two still live', () => textOf(two.client.box) === 'out-two-still');
  } finally {
    await r.close();
  }
});

test('a frame over 64 KiB closes the socket with 1009', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    client.ws.send(JSON.stringify({ type: 'pty_input', data_b64: 'A'.repeat(64 * 1024 + 4) }));
    await waitUntil('1009', () => client.box.closeCode === 1009);
    await waitUntil('pty_stop', () => agentFrames(agent, 'pty_stop').find((f) => f.session_id === start.session_id));
    assert.equal(agentFrames(agent, 'pty_input').length, 0);
  } finally {
    await r.close();
  }
});

test('exit code and reason pass through, then the server closes 1000 and audits', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    agent.ws.send(output(start.session_id, 'bye'));
    agent.ws.send(JSON.stringify({ type: 'pty_exit', session_id: start.session_id, payload: { session_id: start.session_id, code: 3, reason: 'exited' } }));
    await waitUntil('close', () => client.box.closeCode === 1000);
    const exit = client.box.frames.find((f) => f.type === 'pty_exit');
    assert.deepEqual(exit, { type: 'pty_exit', payload: { session_id: start.session_id, code: 3, reason: 'exited' } });
    assert.equal(textOf(client.box), 'bye');

    const rows = r.fm.registry.audit;
    const began = rows.find((row) => row.action === 'terminal_start');
    assert.deepEqual(began.payload, { session_id: start.session_id, purpose: 'terminal:open', pty_user: 'ops', recording: 'agent', pty_user_privileged_groups: [] });
    assert.equal(began.host_id, HOST_A);
    assert.equal(began.actor, 'user-1');
    const ended = await waitUntil('end audit', () => r.fm.registry.audit.find((row) => row.action === 'terminal_end'));
    assert.equal(ended.payload.session_id, start.session_id);
    assert.equal(ended.payload.reason, 'exited');
    assert.equal(ended.payload.exit_code, 3);
    assert.equal(typeof ended.payload.duration_s, 'number');
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
  } finally {
    await r.close();
  }
});

test('the server renews the lease while the session is live', async () => {
  const r = await rig();
  r.fm.ptyRenewMs = 40;
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    const renewals = await waitUntil('renewals', () => {
      const got = agentFrames(agent, 'pty_renew');
      return got.length >= 2 ? got : null;
    });
    const nonces = new Set([start.lease.nonce_hex]);
    for (const renew of renewals) {
      assert.equal(renew.session_id, start.session_id);
      const ok = verifyLease(PUBLIC_KEY, renew.lease, terminalPayload(start.session_id, start.deadline_unix, 'renew'));
      assert.equal(verifyLease(PUBLIC_KEY, renew.lease, terminalPayload(start.session_id, start.deadline_unix, 'start')).ok, false);
      assert.equal(ok.ok, true);
      assert.equal(renew.lease.action, 'pty');
      nonces.add(renew.lease.nonce_hex);
    }
    assert.equal(nonces.size, renewals.length + 1);
    client.ws.close();
    await waitUntil('stop', () => agentFrames(agent, 'pty_stop').length === 1);
    const count = agentFrames(agent, 'pty_renew').length;
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(agentFrames(agent, 'pty_renew').length, count);
  } finally {
    await r.close();
  }
});

test('the maximum duration ends the session with reason max_duration', async () => {
  const r = await rig({ SYSTEMAPI_PTY_MAX_SECONDS: '1' });
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    assert.ok(start.deadline_unix - Math.floor(Date.now() / 1000) <= 1);
    await waitUntil('close', () => client.box.closeCode === 1000, 4000);
    const exit = client.box.frames.find((f) => f.type === 'pty_exit');
    assert.deepEqual(exit.payload, { session_id: start.session_id, code: -1, reason: 'max_duration' });
    assert.ok(agentFrames(agent, 'pty_stop').find((f) => f.session_id === start.session_id));
    const ended = await waitUntil('end audit', () => r.fm.registry.audit.find((row) => row.action === 'terminal_end'));
    assert.equal(ended.payload.reason, 'max_duration');
  } finally {
    await r.close();
  }
});

test('an agent disconnect ends its sessions with agent_disconnected', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    agent.ws.close();
    await waitUntil('close', () => client.box.closeCode === 1000);
    const exit = client.box.frames.find((f) => f.type === 'pty_exit');
    assert.deepEqual(exit.payload, { session_id: start.session_id, code: -1, reason: 'agent_disconnected' });
  } finally {
    await r.close();
  }
});

test('start failures are pty_status errors closed with 1011', async () => {
  const r = await rig();
  try {
    // Ticket problems.
    const bogus = r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=stk_nope`));
    const bogusBox = collect(bogus);
    await waitUntil('bogus close', () => bogusBox.closeCode === 1011);
    assert.deepEqual(bogusBox.frames, [{ type: 'pty_status', payload: { error: 'ticket_invalid' } }]);

    const wrongPurpose = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme' });
    const wp = r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=${wrongPurpose}&purpose=terminal:root`));
    const wpBox = collect(wp);
    await waitUntil('purpose close', () => wpBox.closeCode === 1011);
    assert.equal(wpBox.frames[0].payload.error, 'ticket_invalid');

    // Agent offline.
    const offline = openClient(r);
    await waitUntil('offline close', () => offline.box.closeCode === 1011);
    assert.equal(offline.box.frames[0].payload.error, 'agent_offline');

    // Bad sizes are refused before the ticket is spent.
    const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme' });
    const sized = r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=${ticket}&rows=1001`));
    const sizedErr = await new Promise((resolve) => sized.on('unexpected-response', (_req, res) => resolve(res.statusCode)));
    assert.equal(sizedErr, 400);
    assert.ok(r.fm.tickets.has(ticket));

    // Agent-reported refusal, and an unknown code is reported as internal.
    const agent = await connectAgent(r);
    for (const [reported, expected] of [['pty_user_unset', 'pty_user_unset'], ['recording_unavailable', 'recording_unavailable'], ['root_unavailable', 'root_unavailable'], ['bad_signature', 'internal']]) {
      const before = agentFrames(agent, 'pty_start').length;
      const c = openClient(r);
      const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[before]);
      agent.ws.send(JSON.stringify({ type: 'pty_status', session_id: start.session_id, payload: { error: reported } }));
      await waitUntil('refusal close', () => c.box.closeCode === 1011);
      assert.deepEqual(c.box.frames, [
        { type: 'pty_status', payload: { status: 'starting' } },
        { type: 'pty_status', payload: { error: expected } }
      ]);
    }
  } finally {
    await r.close();
  }
});

test('an agent cannot write into a session it does not own', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    const fake = { readyState: WebSocket.OPEN, send() {} };
    r.fm.onAgentOutput(fake, HOST_A, output(start.session_id, 'injected'));
    r.fm.onAgentPtyExit(fake, HOST_A, { session_id: start.session_id, payload: { code: 0, reason: 'exited' } });
    r.fm.onAgentOutput(agent.ws, '22222222-2222-4222-8222-222222222222', output(start.session_id, 'injected'));
    agent.ws.send(output(start.session_id, 'real'));
    await waitUntil('real output', () => textOf(client.box) === 'real');
    assert.equal(client.box.frames.some((f) => f.type === 'pty_exit'), false);
  } finally {
    await r.close();
  }
});

test('large agent output reaches the client in frames of at most 64 KiB', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    agent.ws.send(output(start.session_id, 'x'.repeat(200 * 1024)));
    await waitUntil('all output', () => textOf(client.box).length === 200 * 1024);
    for (const f of client.box.frames.filter((frame) => frame.binary)) assert.ok(f.binary.length <= 64 * 1024);
  } finally {
    await r.close();
  }
});

function serverSide(r, sessionId) {
  return r.fm.terminalSessions.get(sessionId);
}

test('a slow client is ended instead of buffering without bound', async () => {
  const r = await rig({ SYSTEMAPI_PTY_CLIENT_BUFFER_MAX: String(64 * 1024) });
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    Object.defineProperty(serverSide(r, start.session_id).client, 'bufferedAmount', { get: () => 10 * 1024 * 1024 });
    agent.ws.send(output(start.session_id, 'more output'));
    await waitUntil('1011', () => client.box.closeCode === 1011);
    assert.deepEqual(client.box.frames.at(-1), { type: 'pty_status', payload: { error: 'internal' } });
    await waitUntil('pty_stop', () => agentFrames(agent, 'pty_stop').find((f) => f.session_id === start.session_id));
    const ended = await waitUntil('end audit', () => r.fm.registry.audit.find((row) => row.action === 'terminal_end'));
    assert.equal(ended.payload.reason, 'client_too_slow');
  } finally {
    await r.close();
  }
});

test('an agent that floods its terminal queue is disconnected', async () => {
  const r = await rig();
  r.fm.agentQueueMaxItems = 5;
  const append = r.fm.registry.appendAudit.bind(r.fm.registry);
  r.fm.registry.appendAudit = async (entry) => {
    if (entry.action === 'terminal_start') await new Promise((resolve) => setTimeout(resolve, 300));
    return append(entry);
  };
  try {
    const agent = await connectAgent(r);
    const client = openClient(r);
    const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[0]);
    sendStarted(agent, start.session_id);
    for (let i = 0; i < 20; i++) agent.ws.send(output(start.session_id, `chunk${i}`));
    await waitUntil('agent dropped', () => agent.box.closeCode !== null);
    await waitUntil('client ended', () => client.box.closeCode !== null);
  } finally {
    await r.close();
  }
});

test('the per-actor session cap refuses another session', async () => {
  const r = await rig({ SYSTEMAPI_PTY_MAX_PER_ACTOR: '1' });
  try {
    const agent = await connectAgent(r);
    await startSession(r, agent);
    const second = openClient(r);
    await waitUntil('refused', () => second.box.closeCode === 1011);
    assert.deepEqual(second.box.frames, [{ type: 'pty_status', payload: { error: 'pty_start_failed' } }]);
    assert.equal(agentFrames(agent, 'pty_start').length, 1);
  } finally {
    await r.close();
  }
});

test('a start the agent never answers times out as internal', async () => {
  const r = await rig();
  r.fm.ptyStartTimeoutMs = 100;
  try {
    const agent = await connectAgent(r);
    const client = openClient(r);
    const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[0]);
    await waitUntil('timeout', () => client.box.closeCode === 1011);
    assert.equal(client.box.frames.at(-1).payload.error, 'internal');
    await waitUntil('pty_stop', () => agentFrames(agent, 'pty_stop').find((f) => f.session_id === start.session_id));
    const ended = await waitUntil('end audit', () => r.fm.registry.audit.find((row) => row.action === 'terminal_end'));
    assert.equal(ended.payload.reason, 'start_timeout');
  } finally {
    await r.close();
  }
});

test('a renewal rejected as unknown_session ends the session; other rejections do not', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const one = await startSession(r, agent);
    const two = await startSession(r, agent);
    agent.ws.send(JSON.stringify({ type: 'pty_renew_rejected', session_id: two.start.session_id, payload: { error: 'replay' } }));
    agent.ws.send(JSON.stringify({ type: 'pty_renew_rejected', session_id: one.start.session_id, payload: { error: 'unknown_session' } }));
    await waitUntil('one closed', () => one.client.box.closeCode === 1000);
    assert.deepEqual(one.client.box.frames.at(-1).payload, { session_id: one.start.session_id, code: -1, reason: 'stopped' });
    assert.equal(two.client.box.closeCode, null);
  } finally {
    await r.close();
  }
});

test('an error from an older agent that tags only request_id is still routed', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openClient(r);
    const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[0]);
    agent.ws.send(JSON.stringify({ type: 'pty_status', request_id: start.session_id, payload: { error: 'bad_signature' } }));
    await waitUntil('closed', () => client.box.closeCode === 1011);
    assert.equal(client.box.frames.at(-1).payload.error, 'internal');
  } finally {
    await r.close();
  }
});

test('terminal:root is refused unless the agent records it', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    for (const recording of ['user_owned', 'off', true]) {
      const before = agentFrames(agent, 'pty_start').length;
      const client = openClient(r, { purpose: 'terminal:root' });
      const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[before]);
      sendStarted(agent, start.session_id, { recording });
      await waitUntil('refused', () => client.box.closeCode === 1011);
      assert.equal(client.box.frames.at(-1).payload.error, 'root_unavailable', String(recording));
      assert.equal(client.box.frames.some((f) => f.payload && f.payload.status === 'started'), false);
      await waitUntil('pty_stop', () => agentFrames(agent, 'pty_stop').find((f) => f.session_id === start.session_id));
    }
    const ok = await startSession(r, agent, { purpose: 'terminal:root' });
    assert.ok(ok.start.session_id);
  } finally {
    await r.close();
  }
});

test('the end audit row carries the agent recording digest after a client close', async () => {
  const r = await rig();
  r.fm.ptyFinalWaitMs = 2000;
  try {
    const agent = await connectAgent(r);
    const { client, start } = await startSession(r, agent);
    client.ws.close();
    await waitUntil('pty_stop', () => agentFrames(agent, 'pty_stop').length === 1);
    const digest = 'ab'.repeat(32);
    agent.ws.send(JSON.stringify({
      type: 'pty_exit',
      session_id: start.session_id,
      payload: { session_id: start.session_id, code: -1, reason: 'stopped', record: { path: '/var/lib/systemapi/recordings/x.rec', digest, bytes_in: 10, bytes_out: 20 } }
    }));
    const ended = await waitUntil('end audit', () => r.fm.registry.audit.find((row) => row.action === 'terminal_end'));
    assert.equal(ended.payload.reason, 'client_closed');
    assert.equal(ended.payload.recording, 'agent');
    assert.deepEqual(ended.payload.agent_exit.record, { path: '/var/lib/systemapi/recordings/x.rec', digest, bytes_in: 10, bytes_out: 20 });
    assert.equal(r.fm.registry.audit.filter((row) => row.action === 'terminal_end').length, 1);
  } finally {
    await r.close();
  }
});

test('a failing end audit is retried, then counted and raised', async () => {
  const r = await rig();
  let calls = 0;
  let incs = 0;
  r.fm.metrics = { terminalAuditFailures: { inc: () => { incs += 1; } } };
  const append = r.fm.registry.appendAudit.bind(r.fm.registry);
  r.fm.registry.appendAudit = async (entry) => {
    if (entry.action === 'terminal_end') {
      calls += 1;
      throw new Error('db down');
    }
    return append(entry);
  };
  try {
    const agent = await connectAgent(r);
    const { start } = await startSession(r, agent);
    agent.ws.send(JSON.stringify({ type: 'pty_exit', session_id: start.session_id, payload: { code: 0, reason: 'exited' } }));
    await waitUntil('failure counted', () => r.fm.terminalAuditFailures === 1);
    assert.equal(calls, 3);
    assert.equal(incs, 1);
    await waitUntil('security event', () => r.fm.registry.securityEvents.find((e) => e.kind === 'audit_write_failed'));
  } finally {
    await r.close();
  }
});

test('an expired API key cannot open the agent stream', async () => {
  const bcrypt = require('bcryptjs');
  const r = await rig();
  try {
    const keys = [
      { key_id: 'ak_live_expired', secret: 'ak_live_expired.s1', expires_at: new Date(Date.now() - 60_000) },
      { key_id: 'ak_live_current', secret: 'ak_live_current.s2', expires_at: new Date(Date.now() + 3_600_000) }
    ];
    for (const k of keys) k.key_hash = await bcrypt.hash(k.secret, 4);
    // Answers the key lookup as PostgreSQL would, honouring only the
    // conditions the query actually states.
    r.fm.db = {
      async query(sql, params) {
        if (!sql.includes('FROM playground_api_keys')) return { rows: [], rowCount: 0 };
        const checksExpiry = /expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP/.test(sql);
        const rows = keys
          .filter((k) => k.key_id === params[0] && (!checksExpiry || k.expires_at > new Date()))
          .map((k) => ({ key_id: k.key_id, user_id: 'user-1', key_hash: k.key_hash }));
        return { rows, rowCount: rows.length };
      }
    };
    r.fm.verifyApiKey = FleetManager.prototype.verifyApiKey.bind(r.fm);
    const dial = (secret) => new Promise((resolve) => {
      const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
        headers: {
          authorization: `Bearer ${secret}`,
          'x-systemapi-tenant': 'acme',
          'x-systemapi-host-id': HOST_A,
          'x-systemapi-hostname': 'a.example',
          'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
        }
      }));
      ws.on('unexpected-response', (_req, res) => { resolve(res.statusCode); ws.terminate(); });
      ws.on('message', (data) => { if (JSON.parse(data.toString()).type === 'enrolled') resolve('enrolled'); });
      ws.on('error', () => {});
    });
    assert.equal(await dial('ak_live_expired.s1'), 403);
    assert.equal(r.fm.connectedAgents.has(HOST_A), false);
    assert.equal(await dial('ak_live_current.s2'), 'enrolled');
  } finally {
    await r.close();
  }
});

test('revoking a key closes its live agent sockets with 4403 and an audit row', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    assert.equal(await r.fm.closeAgentsForKey('k-other', 'key_revoked', 'user-1'), 0);
    assert.equal(agent.box.closeCode, null);
    assert.equal(await r.fm.closeAgentsForKey('k1', 'key_revoked', 'user-1'), 1);
    await waitUntil('agent closed', () => agent.box.closeCode !== null);
    assert.equal(agent.box.closeCode, 4403);
    await waitUntil('agent gone', () => !r.fm.connectedAgents.has(HOST_A));
    const row = r.fm.registry.audit.find((a) => a.action === 'agent_key_revoked');
    assert.equal(row.host_id, HOST_A);
    assert.equal(row.tenant_id, 'acme');
    assert.equal(row.actor, 'user-1');
    assert.equal(row.payload.reason, 'key_revoked');
    assert.equal(row.payload.close_code, 4403);
    assert.equal(JSON.stringify(row).includes('k1"'), false, 'the key id is fingerprinted');
  } finally {
    await r.close();
  }
});

test('a key revoked by another path closes its agent within one ping', async () => {
  const r = await rig();
  r.fm.agentPingMs = 50;
  try {
    const agent = await connectAgent(r);
    await new Promise((resolve) => setTimeout(resolve, 120));
    assert.equal(agent.box.closeCode, null, 'an active key stays connected');
    await r.fm.registry.revokeKey('k1');
    const t0 = Date.now();
    await waitUntil('agent closed', () => agent.box.closeCode !== null, 1000);
    assert.ok(Date.now() - t0 < 1000);
    assert.equal(agent.box.closeCode, 4403);
    const row = r.fm.registry.audit.find((a) => a.action === 'agent_key_revoked');
    assert.equal(row.actor, 'system:key_check');
    assert.equal(row.payload.reason, 'key_inactive');
  } finally {
    await r.close();
  }
});

test('a key check that errors twice in a row closes the agent', async () => {
  const r = await rig();
  r.fm.agentPingMs = 50;
  try {
    const agent = await connectAgent(r);
    r.fm.registry.keyActive = async () => { throw new Error('db down'); };
    await waitUntil('agent closed', () => agent.box.closeCode !== null, 1000);
    assert.equal(agent.box.closeCode, 4403);
    assert.equal(r.fm.registry.audit.find((a) => a.action === 'agent_key_revoked').payload.reason, 'key_check_failed');
  } finally {
    await r.close();
  }
});

test('a key bound to a tenant enrolls only into that tenant', async () => {
  const r = await rig();
  try {
    r.fm.verifyApiKey = async (key) => (key === 'agent-key' ? { key_id: 'k1', user_id: 'user-1', tenant_id: 'other' } : null);
    const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
      headers: {
        authorization: 'Bearer agent-key',
        'x-systemapi-tenant': 'acme',
        'x-systemapi-host-id': HOST_A,
        'x-systemapi-hostname': 'a.example',
        'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
      }
    }));
    const box = collect(ws);
    const refused = await waitUntil('enroll_error', () => box.frames.find((f) => f.type === 'enroll_error'));
    assert.equal(refused.error, 'key_tenant_mismatch');
    await waitUntil('closed', () => box.closeCode !== null);
    assert.equal(await r.fm.registry.getHost(['acme'], HOST_A), null);
    assert.equal(r.fm.registry.tenants.has('acme'), false, 'no tenant was created');
    r.fm.verifyApiKey = async (key) => (key === 'agent-key' ? { key_id: 'k1', user_id: 'user-1', tenant_id: 'acme' } : null);
    await connectAgent(r);
    assert.equal(r.fm.connectedAgents.has(HOST_A), true);
  } finally {
    await r.close();
  }
});

test('an agent dialing with the same key and host id but another SSH key is refused', async () => {
  const r = await rig();
  try {
    const first = await connectAgent(r);
    first.ws.close();
    await waitUntil('first gone', () => !r.fm.connectedAgents.has(HOST_A));
    const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
      headers: {
        authorization: 'Bearer agent-key',
        'x-systemapi-tenant': 'acme',
        'x-systemapi-host-id': HOST_A,
        'x-systemapi-hostname': 'a.example',
        'x-systemapi-ssh-pubkey': opensshEd25519(Buffer.alloc(32, 9))
      }
    }));
    const box = collect(ws);
    const refused = await waitUntil('enroll_error', () => box.frames.find((f) => f.type === 'enroll_error'));
    assert.equal(refused.error, 'host_key_mismatch');
    await waitUntil('closed', () => box.closeCode !== null);
    assert.equal(r.fm.connectedAgents.has(HOST_A), false);
    assert.equal((await r.fm.registry.getHost(['acme'], HOST_A)).ssh_pubkey, opensshEd25519(r.fm.signer.publicKeyRaw));
    assert.ok(r.fm.registry.securityEvents.find((e) => e.kind === 'enroll_rejected' && e.detail.error === 'host_key_mismatch'));
  } finally {
    await r.close();
  }
});

test('a second agent connection is refused while the live one answers pings', async () => {
  const r = await rig({ SYSTEMAPI_AGENT_PROBE_MS: '200' });
  try {
    const first = await connectAgent(r);
    const live = r.fm.connectedAgents.get(HOST_A);
    const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
      headers: {
        authorization: 'Bearer agent-key',
        'x-systemapi-tenant': 'acme',
        'x-systemapi-host-id': HOST_A,
        'x-systemapi-hostname': 'a.example',
        'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
      }
    }));
    const box = collect(ws);
    const refused = await waitUntil('enroll_error', () => box.frames.find((f) => f.type === 'enroll_error'));
    assert.equal(refused.error, 'host_connected');
    await waitUntil('newcomer closed', () => box.closeCode !== null);
    assert.equal(box.closeCode, 1008);
    assert.equal(r.fm.connectedAgents.get(HOST_A), live);
    assert.equal(first.box.closeCode, null);
    assert.ok(r.fm.registry.securityEvents.find((e) => e.kind === 'agent_displace_refused'));
  } finally {
    await r.close();
  }
});

test('a newcomer replaces a live socket that misses its ping; the replaced close does not mark the host offline', async () => {
  const r = await rig({ SYSTEMAPI_AGENT_PROBE_MS: '200' });
  try {
    // A half-open socket: it stays open but never answers a ping.
    const stale = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
      autoPong: false,
      headers: {
        authorization: 'Bearer agent-key',
        'x-systemapi-tenant': 'acme',
        'x-systemapi-host-id': HOST_A,
        'x-systemapi-hostname': 'a.example',
        'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
      }
    }));
    const staleBox = collect(stale);
    await waitUntil('enrolled', () => staleBox.frames.find((f) => f.type === 'enrolled'));
    const second = await connectAgent(r);
    await waitUntil('stale dropped', () => staleBox.closeCode !== null);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(r.fm.connectedAgents.size, 1);
    assert.notEqual(r.fm.connectedAgents.get(HOST_A), undefined);
    assert.equal((await r.fm.registry.getHost(['acme'], HOST_A)).status, 'online');
    second.ws.close();
    await waitUntil('offline', () => r.fm.connectedAgents.size === 0);
  } finally {
    await r.close();
  }
});

test('an oversized agent frame closes the agent connection with 1009', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    agent.ws.send(Buffer.alloc(4 * 1024 * 1024 + 16));
    await waitUntil('1009', () => agent.box.closeCode === 1009, 5000);
  } finally {
    await r.close();
  }
});

test('client input is held until the shell is announced', async () => {
  const r = await rig();
  let releaseAudit;
  const gate = new Promise((resolve) => { releaseAudit = resolve; });
  const append = r.fm.registry.appendAudit.bind(r.fm.registry);
  r.fm.registry.appendAudit = async (entry) => {
    if (entry.action === 'terminal_start') await gate;
    return append(entry);
  };
  try {
    const agent = await connectAgent(r);
    const client = openClient(r);
    const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[0]);
    await waitUntil('open', () => client.ws.readyState === WebSocket.OPEN);
    client.ws.send(JSON.stringify({ type: 'pty_input', data: 'early-1\n' }));
    sendStarted(agent, start.session_id);
    client.ws.send(JSON.stringify({ type: 'pty_input', data: 'early-2\n' }));
    client.ws.send(JSON.stringify({ type: 'pty_eof' }));
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(agentFrames(agent, 'pty_input').length, 0);
    assert.equal(agentFrames(agent, 'pty_eof').length, 0);
    releaseAudit();
    await waitUntil('flushed', () => agentFrames(agent, 'pty_eof').length === 1);
    assert.deepEqual(agentFrames(agent, 'pty_input').map((f) => Buffer.from(f.data_b64, 'base64').toString()), ['early-1\n', 'early-2\n']);
    const started = client.box.frames.findIndex((f) => f.type === 'pty_status' && f.payload.status === 'started');
    assert.ok(started > 0);
  } finally {
    await r.close();
  }
});

test('input sent to a root session that fails the recording check never reaches the agent', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openClient(r, { purpose: 'terminal:root' });
    const start = await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[0]);
    await waitUntil('open', () => client.ws.readyState === WebSocket.OPEN);
    client.ws.send(JSON.stringify({ type: 'pty_input', data: 'id\n' }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    sendStarted(agent, start.session_id, { recording: 'off' });
    await waitUntil('refused', () => client.box.closeCode === 1011);
    assert.equal(client.box.frames.at(-1).payload.error, 'root_unavailable');
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(agentFrames(agent, 'pty_input').length, 0);
  } finally {
    await r.close();
  }
});

test('held client input over its cap ends the session', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openClient(r);
    await waitUntil('pty_start', () => agentFrames(agent, 'pty_start')[0]);
    await waitUntil('open', () => client.ws.readyState === WebSocket.OPEN);
    const chunk = JSON.stringify({ type: 'pty_input', data_b64: 'A'.repeat(60 * 1024) });
    for (let i = 0; i < 6; i++) client.ws.send(chunk);
    await waitUntil('ended', () => client.box.closeCode === 1011);
    assert.equal(client.box.frames.at(-1).payload.error, 'internal');
    assert.equal(agentFrames(agent, 'pty_input').length, 0);
  } finally {
    await r.close();
  }
});

test('telemetry never renames the enrolled host', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    agent.ws.send(JSON.stringify({ type: 'telemetry', payload: { host: { hostname: 'renamed-by-os', os: 'darwin', platform: 'arm64' } } }));
    await waitUntil('os recorded', () => r.fm.registry.hosts.get(HOST_A).os === 'darwin');
    assert.equal(r.fm.registry.hosts.get(HOST_A).hostname, 'a.example');
    assert.equal((await r.fm.registry.resolveHosts(['acme'], 'a.example')).length, 1);
    assert.equal((await r.fm.registry.resolveHosts(['acme'], 'renamed-by-os')).length, 0);
  } finally {
    await r.close();
  }
});

test('a terminal WebSocket from a foreign Origin is refused; no Origin and allowed origins pass', async () => {
  const r = await rig({ NODE_ENV: 'production', SYSTEMAPI_PUBLIC_URL: 'https://app.systemapi.io/x' });
  try {
    const agent = await connectAgent(r);
    const status = (origin) => new Promise((resolve) => {
      const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme', actor: 'user-1' });
      const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=${ticket}`, origin ? { origin } : {}));
      ws.on('unexpected-response', (_req, res) => resolve({ code: res.statusCode, ticket }));
      ws.on('open', () => { resolve({ code: 101, ticket }); ws.close(); });
      ws.on('error', () => {});
    });
    for (const bad of ['https://evil.example', 'http://localhost:5173', 'https://systemapi.io.evil.example', 'null']) {
      const res = await status(bad);
      assert.equal(res.code, 403, bad);
      assert.ok(r.fm.tickets.has(res.ticket), 'ticket not spent by a refused origin');
    }
    for (const good of [undefined, 'https://systemapi.io', 'https://app.systemapi.io']) {
      assert.equal((await status(good)).code, 101, String(good));
    }
    await waitUntil('three starts', () => agentFrames(agent, 'pty_start').length === 3);
  } finally {
    await r.close();
  }
  const custom = await rig({ SYSTEMAPI_ALLOWED_ORIGINS: 'https://ops.example.com' });
  try {
    await connectAgent(custom);
    const { originAllowed } = require('../controlplane/httpauth');
    assert.equal(originAllowed('https://ops.example.com', custom.fm.env), true);
    assert.equal(originAllowed('https://systemapi.io', custom.fm.env), false);
    assert.equal(originAllowed('http://localhost:5173', { NODE_ENV: 'development' }), true);
  } finally {
    await custom.close();
  }
});

test('agent capabilities are recorded per live connection; an old agent advertises nothing', async () => {
  const r = await rig();
  try {
    const old = await connectAgent(r);
    assert.equal(r.fm.agentSupports(HOST_A, 'pty'), false);
    assert.equal(r.fm.agentSupports(HOST_A, 'tcp'), false);
    old.ws.close();
    await waitUntil('old agent gone', () => !r.fm.connectedAgents.has(HOST_A));
    const fresh = await connectAgent(r, { 'x-systemapi-capabilities': 'pty,tcp' });
    assert.equal(r.fm.agentSupports(HOST_A, 'pty'), true);
    assert.equal(r.fm.agentSupports(HOST_A, 'tcp'), true);
    assert.equal(r.fm.agentSupports(HOST_A, 'file'), false);
    assert.equal(r.fm.agentSupports('33333333-3333-4333-8333-333333333333', 'pty'), false);
    fresh.ws.close();
    await waitUntil('agent gone', () => !r.fm.connectedAgents.has(HOST_A));
    assert.equal(r.fm.agentSupports(HOST_A, 'pty'), false);
  } finally {
    await r.close();
  }
});

test('an agent that overruns its channel credit is disconnected', async () => {
  const r = await rig();
  try {
    await connectAgent(r, { 'x-systemapi-capabilities': 'pty,tcp' });
    const ws = r.fm.connectedAgents.get(HOST_A);
    const ledger = r.fm.agentCreditLedger(ws);
    assert.equal(r.fm.agentCreditLedger(ws), ledger, 'one ledger per socket');
    ledger.open('tcs_aaaaaaaaaaaaaaaa', { window: 1024 });
    assert.equal(ledger.receive('tcs_aaaaaaaaaaaaaaaa', 1024), true);
    assert.equal(ledger.receive('tcs_aaaaaaaaaaaaaaaa', 1), false);
    await waitUntil('agent disconnected', () => !r.fm.connectedAgents.has(HOST_A));
  } finally {
    await r.close();
  }
});
