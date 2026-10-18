'use strict';

// Terminal session watching (docs/sahconnect-terminal-protocol.md §7.2,
// playground/watch.js): watcher HTTP + WebSocket -> control plane -> fake
// agent. The fake agent answers watch_request the way systemapi-agent/watch.go
// does, after checking the signed lease.

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
const { issueTicket } = require('../controlplane/tickets');
const { verifyLease, watchPayload, watchReasonOk, payloadHash } = require('../controlplane/lease');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));
// user-1 is admin of acme (it enrolled the agent), so each key's own scopes
// decide: support holds only terminal:watch.
const KEYS = { 'agent-key': 'k-agent', 'admin-key': 'k-admin', 'support-key': 'k-support', 'op-key': 'k-op' };

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
    box.frames.push(isBinary ? { binary: Buffer.from(data) } : JSON.parse(data.toString()));
  });
  ws.on('close', (code) => { box.closeCode = code; });
  ws.on('error', () => {});
  return box;
}

function textOf(box) {
  return Buffer.concat(box.frames.filter((f) => f.binary).map((f) => f.binary)).toString();
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
  fm.ptyFinalWaitMs = 100;
  fm.auditRetryDelaysMs = [10, 10];
  fm.verifyApiKey = async (key) => (KEYS[key] ? { key_id: KEYS[key], user_id: 'user-1' } : null);
  mount(app, fm);
  await fm.registry.setScopes('k-admin', ['admin']);
  await fm.registry.setScopes('k-support', ['terminal:watch']);
  await fm.registry.setScopes('k-op', ['hosts:read', 'terminal:open']);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const sockets = [];
  return {
    fm,
    url: `http://127.0.0.1:${port}`,
    ws: `ws://127.0.0.1:${port}`,
    track(ws) { sockets.push(ws); return ws; },
    async close() {
      for (const ws of sockets) if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.terminate();
      for (const s of fm.terminalSessions.values()) { clearInterval(s.renewTimer); clearTimeout(s.maxTimer); }
      for (const w of fm.watch.watches.values()) clearTimeout(w.ticketTimer);
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

// The fake agent: answer(frame) returns the watch_consent payload for a
// watch_request, or null for silence. Every request's lease is checked.
async function connectAgent(r, answer = () => null) {
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': HOST_A,
      'x-systemapi-hostname': 'a.example',
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
    }
  }));
  const agent = { ws, frames: [], answer, leaseOk: [] };
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const f = JSON.parse(data.toString());
    agent.frames.push(f);
    if (f.type !== 'watch_request') return;
    const s = r.fm.terminalSessions.get(f.session_id);
    const payload = watchPayload(f.session_id, s.deadlineUnix, f.watch_id, f.mode, f.override, f.reason);
    agent.leaseOk.push(verifyLease(PUBLIC_KEY, f.lease, payload).ok === true && f.lease.action === s.action);
    const reply = agent.answer(f);
    if (reply) ws.send(JSON.stringify({ type: 'watch_consent', session_id: f.session_id, payload: { watch_id: f.watch_id, ...reply } }));
  });
  ws.on('error', () => {});
  await waitUntil('enrolled', () => agent.frames.find((f) => f.type === 'enrolled'));
  return agent;
}

function frames(agent, type) {
  return agent.frames.filter((f) => f.type === type);
}

// A live terminal session of alice's, started on the fake agent.
async function startSession(r, agent) {
  const before = frames(agent, 'pty_start').length;
  const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme', actor: 'alice' });
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/terminal/${HOST_A}?ticket=${ticket}&purpose=terminal:open`));
  const box = collect(ws);
  const start = await waitUntil('pty_start', () => frames(agent, 'pty_start')[before]);
  agent.ws.send(JSON.stringify({ type: 'pty_status', session_id: start.session_id, payload: { status: 'started', session_id: start.session_id, pty_user: 'alice', recording: 'agent' } }));
  await waitUntil('started', () => box.frames.find((f) => f.type === 'pty_status' && f.payload.status === 'started'));
  return { id: start.session_id, ws, box };
}

function output(sessionId, text) {
  const id = Buffer.from(sessionId, 'latin1');
  return Buffer.concat([Buffer.from([id.length]), id, Buffer.from(text)]);
}

async function ask(r, body, key = 'support-key') {
  const res = await fetch(`${r.url}/api/v1/ws-ticket`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': key },
    body: JSON.stringify({ purpose: 'terminal:watch', reason: 'INC-42 disk alarm', ...body })
  });
  return { status: res.status, body: await res.json() };
}

function openWatcher(r, granted) {
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/terminal/${HOST_A}?ticket=${granted.ticket}&purpose=${granted.purpose}`));
  return { ws, box: collect(ws) };
}

function rows(r, action) {
  return r.fm.registry.audit.filter((row) => row.action === action);
}

const yes = (f) => ({ granted: true, consent: true, result: 'granted', mode: f.mode, actor: f.actor, reason: f.reason });

test('watchPayload pins the §7.2 string and refuses malformed fields', () => {
  const sid = 'pts_AAAAAAAAAAAAAAAAAAAAAA';
  const wid = 'wch_BBBBBBBBBBBBBBBBBBBBBB';
  const golden = 'pts_AAAAAAAAAAAAAAAAAAAAAA\n1760000000\nwatch\nwch_BBBBBBBBBBBBBBBBBBBBBB\nro\ntrue\nINC-42 disk alarm';
  assert.equal(watchPayload(sid, 1760000000, wid, 'ro', true, 'INC-42 disk alarm'), golden);
  assert.equal(watchPayload(sid, 1760000000, wid, 'rw', false, 'pair on deploy'),
    'pts_AAAAAAAAAAAAAAAAAAAAAA\n1760000000\nwatch\nwch_BBBBBBBBBBBBBBBBBBBBBB\nrw\nfalse\npair on deploy');
  // The lease hash covers "<action>\n<payload>" like the start lease.
  assert.equal(payloadHash('pty', golden), crypto.createHash('sha256').update(`pty\n${golden}`).digest('hex'));
  const bad = [
    ['pts_short', 1, wid, 'ro', false, 'r'],
    [sid, 0, wid, 'ro', false, 'r'],
    [sid, 1, 'wch_short', 'ro', false, 'r'],
    [sid, 1, 'xyz_BBBBBBBBBBBBBBBBBBBBBB', 'ro', false, 'r'],
    [sid, 1, wid, 'view', false, 'r'],
    [sid, 1, wid, 'ro', 'true', 'r'],
    [sid, 1, wid, 'ro', false, ''],
    [sid, 1, wid, 'ro', false, '   '],
    [sid, 1, wid, 'ro', false, 'a\nb'],
    [sid, 1, wid, 'ro', false, 'a\tb'],
    [sid, 1, wid, 'ro', false, 'a\u001b[2Jb'],
    [sid, 1, wid, 'ro', false, 'x'.repeat(257)]
  ];
  for (const args of bad) assert.throws(() => watchPayload(...args), /bad_payload/, JSON.stringify(args));
  assert.equal(watchReasonOk('ü'.repeat(128)), true);
  assert.equal(watchReasonOk('ü'.repeat(129)), false);
  assert.equal(watchReasonOk(' x'), false);
});

test('a granted view-only watch writes watch_started, then relays output read-only', async () => {
  const r = await rig();
  try {
    let startedFirst = null;
    const agent = await connectAgent(r, (f) => yes(f));
    const session = await startSession(r, agent);
    const res = await ask(r, { session_id: session.id });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.match(res.body.ticket, /^stk_/);
    assert.equal(res.body.purpose, 'terminal:watch');
    assert.equal(res.body.host_id, HOST_A);
    assert.equal(res.body.session_id, session.id);
    assert.match(res.body.watch_id, /^wch_[A-Za-z0-9_-]{16,64}$/);
    assert.equal(res.body.mode, 'ro');
    assert.equal(res.body.consent, true);

    const req = frames(agent, 'watch_request')[0];
    assert.deepEqual(agent.leaseOk, [true]);
    assert.equal(req.session_id, session.id);
    assert.equal(req.mode, 'ro');
    assert.equal(req.override, false);
    assert.equal(req.actor, 'user-1');
    assert.equal(req.reason, 'INC-42 disk alarm');

    const started = rows(r, 'watch_started');
    assert.equal(started.length, 1);
    assert.deepEqual(started[0].payload, {
      session_id: session.id, host_id: HOST_A, watch_id: res.body.watch_id, mode: 'ro',
      actor: 'user-1', reason: 'INC-42 disk alarm', consent: true
    });
    assert.equal(started[0].actor, 'user-1');
    assert.equal(started[0].tenant_id, 'acme');

    const watcher = openWatcher(r, res.body);
    watcher.ws.on('message', (d, isBinary) => { if (isBinary && startedFirst === null) startedFirst = rows(r, 'watch_started').length === 1; });
    await waitUntil('watching', () => watcher.box.frames.find((f) => f.type === 'pty_status'));
    assert.deepEqual(watcher.box.frames[0], { type: 'pty_status', payload: { status: 'started', session_id: session.id, watch_id: res.body.watch_id, mode: 'ro' } });
    agent.ws.send(output(session.id, 'hello'));
    await waitUntil('relayed', () => textOf(watcher.box) === 'hello');
    await waitUntil('own client', () => textOf(session.box) === 'hello');
    assert.equal(startedFirst, true);

    // A view-only watcher's keystrokes never reach the agent.
    watcher.ws.send(JSON.stringify({ type: 'pty_input', data_b64: Buffer.from('rm -rf /\n').toString('base64') }));
    watcher.ws.send(JSON.stringify({ type: 'pty_input', data: 'whoami\n' }));
    watcher.ws.send(JSON.stringify({ type: 'pty_resize', rows: 10, cols: 10 }));
    session.ws.send(JSON.stringify({ type: 'pty_input', data: 'ls\n' }));
    await waitUntil('owner input', () => frames(agent, 'pty_input').length === 1);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.deepEqual(frames(agent, 'pty_input').map((f) => [f.watch_id, Buffer.from(f.data_b64, 'base64').toString()]), [[undefined, 'ls\n']]);
    assert.equal(frames(agent, 'pty_resize').length, 0);

    // The ticket is single-use.
    const again = openWatcher(r, res.body);
    await waitUntil('reuse refused', () => again.box.closeCode === 1011);
    assert.deepEqual(again.box.frames[0], { type: 'pty_status', payload: { error: 'ticket_invalid' } });
  } finally {
    await r.close();
  }
});

test('the watcher closing sends watch_stop and writes watch_stopped with bytes relayed', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, (f) => yes(f));
    const session = await startSession(r, agent);
    const res = await ask(r, { session_id: session.id });
    const watcher = openWatcher(r, res.body);
    await waitUntil('watching', () => watcher.box.frames.find((f) => f.type === 'pty_status'));
    agent.ws.send(output(session.id, '0123456789'));
    await waitUntil('relayed', () => textOf(watcher.box).length === 10);
    watcher.ws.close();
    const stop = await waitUntil('watch_stop', () => frames(agent, 'watch_stop')[0]);
    assert.deepEqual(stop, { type: 'watch_stop', session_id: session.id, watch_id: res.body.watch_id });
    const stopped = await waitUntil('watch_stopped', () => rows(r, 'watch_stopped')[0]);
    assert.equal(stopped.actor, 'user-1');
    assert.equal(typeof stopped.payload.duration, 'number');
    assert.deepEqual({ ...stopped.payload, duration: 0 }, {
      session_id: session.id, watch_id: res.body.watch_id, actor: 'user-1', mode: 'ro',
      reason: 'watcher_closed', duration: 0, bytes_relayed: 10
    });
    // The session itself goes on, unwatched.
    agent.ws.send(output(session.id, '!'));
    await waitUntil('owner still served', () => textOf(session.box) === '0123456789!');
    assert.equal(frames(agent, 'pty_stop').length, 0);
  } finally {
    await r.close();
  }
});

test('a denial or an agent timeout writes watch_refused and returns 403 watch_denied', async () => {
  const r = await rig();
  try {
    let result = 'denied';
    const agent = await connectAgent(r, (f) => ({ granted: false, consent: false, result, mode: f.mode, actor: f.actor, reason: f.reason }));
    const session = await startSession(r, agent);
    const denied = await ask(r, { session_id: session.id });
    assert.deepEqual(denied, { status: 403, body: { error: 'watch_denied' } });
    result = 'timeout';
    const timedOut = await ask(r, { session_id: session.id });
    assert.deepEqual(timedOut, { status: 403, body: { error: 'watch_denied' } });
    const refused = rows(r, 'watch_refused');
    assert.deepEqual(refused.map((row) => row.payload.result), ['denied', 'timeout']);
    assert.deepEqual(Object.keys(refused[0].payload).sort(), ['actor', 'mode', 'reason', 'result', 'session_id', 'watch_id']);
    assert.equal(refused[0].payload.session_id, session.id);
    assert.equal(rows(r, 'watch_started').length, 0);
    assert.equal(rows(r, 'ticket_issued').filter((row) => row.payload.purpose === 'terminal:watch').length, 0);
  } finally {
    await r.close();
  }
});

test('no answer within the server wait withdraws the request and returns 403', async () => {
  const r = await rig();
  try {
    r.fm.watch.consentTimeoutMs = 150;
    const agent = await connectAgent(r, () => null);
    const session = await startSession(r, agent);
    const res = await ask(r, { session_id: session.id });
    assert.deepEqual(res, { status: 403, body: { error: 'watch_denied' } });
    const req = frames(agent, 'watch_request')[0];
    const stop = await waitUntil('withdrawn', () => frames(agent, 'watch_stop')[0]);
    assert.equal(stop.watch_id, req.watch_id);
    assert.equal(rows(r, 'watch_refused')[0].payload.result, 'timeout');
    assert.equal(r.fm.watch.pending.size, 0);
  } finally {
    await r.close();
  }
});

test('a second request while a prompt is open is 409 busy', async () => {
  const r = await rig();
  try {
    r.fm.watch.consentTimeoutMs = 400;
    const agent = await connectAgent(r, () => null);
    const session = await startSession(r, agent);
    const first = ask(r, { session_id: session.id });
    await waitUntil('first asked', () => frames(agent, 'watch_request').length === 1);
    const second = await ask(r, { session_id: session.id }, 'admin-key');
    assert.deepEqual(second, { status: 409, body: { error: 'busy' } });
    assert.equal(frames(agent, 'watch_request').length, 1);
    assert.equal((await first).status, 403);
    // The agent's own busy refusal maps to 409 too.
    agent.answer = () => ({ granted: false, consent: false, error: 'busy' });
    const third = await ask(r, { session_id: session.id });
    assert.deepEqual(third, { status: 409, body: { error: 'busy' } });
    assert.equal(rows(r, 'watch_refused').at(-1).payload.result, 'busy');
  } finally {
    await r.close();
  }
});

test('scopes: support may ask view-only; override and read-write are admin only; operators are refused', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, (f) => yes(f));
    const session = await startSession(r, agent);
    assert.deepEqual(await ask(r, { session_id: session.id }, 'op-key'), { status: 403, body: { error: 'scope_denied' } });
    assert.deepEqual(await ask(r, { session_id: session.id, override: true }), { status: 403, body: { error: 'scope_denied' } });
    assert.deepEqual(await ask(r, { session_id: session.id, purpose: 'terminal:watch_rw' }), { status: 403, body: { error: 'scope_denied' } });
    assert.equal(frames(agent, 'watch_request').length, 0);
    const list = await fetch(`${r.url}/api/v1/systems/terminal/sessions`, { headers: { 'x-api-key': 'op-key' } });
    assert.equal(list.status, 403);
  } finally {
    await r.close();
  }
});

test('reasons: override without a reason is 400 reason_required; control characters are 400', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, (f) => yes(f));
    const session = await startSession(r, agent);
    assert.deepEqual(await ask(r, { session_id: session.id, override: true, reason: '' }, 'admin-key'), { status: 400, body: { error: 'reason_required' } });
    assert.deepEqual(await ask(r, { session_id: session.id, override: true, reason: undefined }, 'admin-key'), { status: 400, body: { error: 'reason_required' } });
    assert.deepEqual(await ask(r, { session_id: session.id, reason: 'x\u001b[2J' }), { status: 400, body: { error: 'bad_reason' } });
    assert.deepEqual(await ask(r, { session_id: session.id, override: 'yes' }, 'admin-key'), { status: 400, body: { error: 'bad_override' } });
    assert.deepEqual(await ask(r, { session_id: session.id, mode: 'rw' }), { status: 400, body: { error: 'bad_mode' } });
    assert.equal(frames(agent, 'watch_request').length, 0);
  } finally {
    await r.close();
  }
});

test('an admin override (view only, with a reason) is audited with consent false', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, (f) => (f.override
      ? { granted: true, consent: false, result: 'override', mode: f.mode, actor: f.actor, reason: f.reason }
      : null));
    const session = await startSession(r, agent);
    const res = await ask(r, { session_id: session.id, override: true }, 'admin-key');
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.consent, false);
    assert.equal(frames(agent, 'watch_request')[0].override, true);
    assert.deepEqual(agent.leaseOk, [true]);
    assert.equal(rows(r, 'watch_started')[0].payload.consent, false);
  } finally {
    await r.close();
  }
});

test('read-write with override still asks; input is forwarded with the watch id', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, (f) => yes(f));
    const session = await startSession(r, agent);
    const res = await ask(r, { session_id: session.id, purpose: 'terminal:watch_rw', override: true }, 'admin-key');
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const req = frames(agent, 'watch_request')[0];
    assert.equal(req.mode, 'rw');
    assert.equal(req.override, false);
    assert.deepEqual(agent.leaseOk, [true]);
    assert.equal(rows(r, 'watch_started')[0].payload.consent, true);

    const watcher = openWatcher(r, res.body);
    await waitUntil('watching', () => watcher.box.frames.find((f) => f.type === 'pty_status'));
    watcher.ws.send(JSON.stringify({ type: 'pty_input', data_b64: Buffer.from('uptime\n').toString('base64') }));
    const input = await waitUntil('forwarded', () => frames(agent, 'pty_input')[0]);
    assert.deepEqual(input, { type: 'pty_input', session_id: session.id, watch_id: res.body.watch_id, data_b64: Buffer.from('uptime\n').toString('base64') });

    // A read-write grant without the user's yes is never relayed.
    agent.answer = (f) => ({ granted: true, consent: false, result: 'override', mode: f.mode, actor: f.actor, reason: f.reason });
    const forged = await ask(r, { session_id: session.id, purpose: 'terminal:watch_rw', override: true }, 'admin-key');
    assert.deepEqual(forged, { status: 502, body: { error: 'agent_error' } });
    const second = frames(agent, 'watch_request')[1];
    await waitUntil('stopped', () => frames(agent, 'watch_stop').find((f) => f.watch_id === second.watch_id));
    assert.equal(rows(r, 'watch_refused').at(-1).payload.result, 'invalid_grant');
  } finally {
    await r.close();
  }
});

test('an unknown session is 404; the session list shows live sessions to support', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, (f) => yes(f));
    assert.deepEqual(await ask(r, { session_id: 'pts_AAAAAAAAAAAAAAAAAAAAAA' }), { status: 404, body: { error: 'unknown_session' } });
    agent.answer = () => ({ granted: false, consent: false, error: 'unknown_session' });
    const session = await startSession(r, agent);
    assert.deepEqual(await ask(r, { session_id: session.id }), { status: 404, body: { error: 'unknown_session' } });

    const list = await fetch(`${r.url}/api/v1/systems/terminal/sessions?host_id=${HOST_A}`, { headers: { 'x-api-key': 'support-key' } });
    assert.equal(list.status, 200);
    const body = await list.json();
    assert.equal(body.sessions.length, 1);
    const [s] = body.sessions;
    assert.equal(s.session_id, session.id);
    assert.equal(s.actor, 'alice');
    assert.equal(s.host_id, HOST_A);
    assert.equal(s.hostname, 'a.example');
    assert.equal(s.purpose, 'terminal:open');
    assert.ok(!Number.isNaN(Date.parse(s.started_at)));
    const other = await fetch(`${r.url}/api/v1/systems/terminal/sessions?host_id=22222222-2222-4222-8222-222222222222`, { headers: { 'x-api-key': 'support-key' } });
    assert.equal(other.status, 404);
  } finally {
    await r.close();
  }
});

test('the session ending closes its watchers with pty_exit and writes watch_stopped', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, (f) => yes(f));
    const session = await startSession(r, agent);
    const res = await ask(r, { session_id: session.id });
    const watcher = openWatcher(r, res.body);
    await waitUntil('watching', () => watcher.box.frames.find((f) => f.type === 'pty_status'));
    agent.ws.send(JSON.stringify({ type: 'pty_exit', session_id: session.id, payload: { session_id: session.id, code: 0, reason: 'exited' } }));
    await waitUntil('watcher closed', () => watcher.box.closeCode === 1000);
    assert.deepEqual(watcher.box.frames.find((f) => f.type === 'pty_exit'), { type: 'pty_exit', payload: { session_id: session.id, code: 0, reason: 'exited' } });
    const stopped = await waitUntil('watch_stopped', () => rows(r, 'watch_stopped')[0]);
    assert.equal(stopped.payload.reason, 'session_ended');
    assert.equal(frames(agent, 'watch_stop').length, 0);
  } finally {
    await r.close();
  }
});

test('a granted watch whose ticket is never opened is stopped', async () => {
  const r = await rig();
  try {
    r.fm.watch.ticketTtlMs = 0;
    const agent = await connectAgent(r, (f) => yes(f));
    const session = await startSession(r, agent);
    const res = await ask(r, { session_id: session.id });
    assert.equal(res.status, 200);
    await waitUntil('stopped', () => frames(agent, 'watch_stop').find((f) => f.watch_id === res.body.watch_id), 3000);
    assert.equal((await waitUntil('row', () => rows(r, 'watch_stopped')[0])).payload.reason, 'ticket_unused');
  } finally {
    await r.close();
  }
});
