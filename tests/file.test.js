'use strict';

// File channel (docs/sah-file-protocol.md): client <-> FleetManager <-> fake
// agent. Every negative case of FILE §12 that lives on the server; the
// path, symlink, FIFO, sha256, resume and identity cases on the host are in
// systemapi-agent/file_linux_test.go.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { issueTicket } = require('../controlplane/tickets');
const { verifyLease, filePayload } = require('../controlplane/lease');
const { FILE_WINDOW } = require('../controlplane/credit');
const { checkPath, parseExact, stringifyExact } = require('../playground/file');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));
const POLICY = { roots: [{ path: '/srv/a', read: true, write: true }, { path: '/srv/b', read: true, write: false }, { path: '/etc', read: true, write: true, root: true }] };
const MTIME = '1700000000123456789';
const SHA = 'a'.repeat(64);
const MiB = 1024 * 1024;

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function collect(ws) {
  const box = { frames: [], raw: [], closeCode: null, binaries: [] };
  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      const b = Buffer.from(data);
      box.frames.push({ binary: b });
      box.binaries.push(b);
    } else {
      box.raw.push(data.toString());
      box.frames.push(JSON.parse(data.toString()));
    }
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
  fm.file.finalWaitMs = 200;
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
      for (const s of fm.file.sessions.values()) fm.file.end(s, 'stopped');
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

async function connectAgent(r, { caps = 'pty,tcp,file', hostId = HOST_A, policy = POLICY } = {}) {
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/stream`, {
    headers: {
      authorization: 'Bearer agent-key',
      'x-systemapi-tenant': 'acme',
      'x-systemapi-host-id': hostId,
      'x-systemapi-hostname': `${hostId.slice(0, 4)}.example`,
      'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw),
      ...(caps === null ? {} : { 'x-systemapi-capabilities': caps })
    }
  }));
  const box = collect(ws);
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  if (policy) await r.fm.registry.setHostChannelPolicy(hostId, { file_policy: policy });
  const agent = { ws, box, data: new Map() };
  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    const b = Buffer.from(data);
    const sid = b.toString('latin1', 1, 1 + b[0]);
    const prev = agent.data.get(sid) || [];
    prev.push(b.subarray(1 + b[0]));
    agent.data.set(sid, prev);
  });
  return agent;
}

function ticketFor(r, { hostId = HOST_A, purpose = 'file:write', root = '/srv/a', actor = 'user-1', auth = null } = {}) {
  return issueTicket(r.fm.tickets, { hostId, purpose, tenantId: 'acme', actor, auth, root });
}

function openRaw(r, { ticket, hostId = HOST_A, purpose = 'file:write', root = '/srv/a', actor, query = '', headers = {} } = {}) {
  const t = ticket || ticketFor(r, { hostId, purpose, root, actor });
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/file/${hostId}?ticket=${t}&purpose=${purpose}${query}`, { headers }));
  return { ws, box: collect(ws), ticket: t };
}

function agentFrames(agent, type) {
  return agent.box.frames.filter((f) => f.type === type);
}

function statusError(box) {
  const f = box.frames.find((x) => x.type === 'file_status' && x.payload && x.payload.error);
  return f ? f.payload.error : null;
}

async function failsWith(client, code) {
  await waitUntil(`error ${code}`, () => statusError(client.box) && client.box.closeCode !== null);
  assert.equal(statusError(client.box), code);
  assert.equal(client.box.closeCode, 1011);
}

function data(sid, bytes) {
  const id = Buffer.from(sid, 'latin1');
  return Buffer.concat([Buffer.from([id.length]), id, Buffer.from(bytes)]);
}

function sendJSON(ws, obj) {
  ws.send(typeof obj === 'string' ? obj : JSON.stringify(obj));
}

function auditRows(r, action) {
  return r.fm.registry.audit.filter((row) => row.action === action);
}

// Opens a session and has the fake agent report ready.
async function ready(r, agent, opts = {}) {
  const before = agentFrames(agent, 'file_open').length;
  const client = openRaw(r, opts);
  const open = await waitUntil('file_open', () => agentFrames(agent, 'file_open')[before]);
  const root = opts.canonRoot || open.root;
  sendJSON(agent.ws, { type: 'file_status', session_id: open.session_id, payload: { status: 'ready', root, user: opts.user || 'deploy', uid: opts.uid === undefined ? 1000 : opts.uid } });
  const rdy = await waitUntil('ready', () => client.box.frames.find((f) => f.type === 'file_status' && f.payload.status === 'ready'));
  return { client, open, sid: open.session_id, ready: rdy };
}

function agentReqs(agent, sid) {
  return agentFrames(agent, 'file_req').filter((f) => f.session_id === sid).map((f) => f.request);
}

function result(box, rid, op) {
  return box.frames.find((f) => f.type === 'file_result' && f.request_id === rid && (!op || f.op === op));
}

async function waitResult(box, rid, op) {
  return waitUntil(`result ${rid}`, () => result(box, rid, op));
}

function agentResult(agent, sid, rid, op, fields = {}, error = null) {
  sendJSON(agent.ws, { type: 'file_result', session_id: sid, request_id: rid, op, status: error ? 'error' : 'ok', error, ...fields });
}

function closeFrame(box) {
  return box.frames.find((f) => f.type === 'file_close');
}

test('path rules on the server: FILE §12 shapes are bad_path, temp names reserved', () => {
  for (const p of ['../../etc/shadow', '/etc/shadow', 'a/../../x', 'a//b', 'a/./b', '', 'a/', '..', 'a\\b', 'a\u0000b', 'a\u001fb', 'a\u007fb', '\ud800', 'a'.repeat(256), 'a/'.repeat(2048) + 'a', 17, null]) {
    assert.equal(checkPath(p), 'bad_path', JSON.stringify(p));
  }
  for (const p of ['.sahsync-x.part', 'd/.sahsync-upl_1.part']) assert.equal(checkPath(p), 'reserved_name');
  for (const p of ['.', 'a', 'a/b', '%2e%2e', '.hidden', '...', 'é', 'a'.repeat(255)]) assert.equal(checkPath(p), null, p);
});

test('exact integers: mtime_ns survives parse and stringify', () => {
  const text = `{"a":${MTIME},"b":"x\\"${MTIME}","c":[1,-${MTIME}],"d":1.5e3,"e":123}`;
  const v = parseExact(text);
  assert.equal(typeof v.a, 'bigint');
  assert.equal(v.b, `x"${MTIME}`);
  assert.equal(v.e, 123);
  assert.equal(v.d, 1500);
  assert.equal(stringifyExact(v), `{"a":${MTIME},"b":"x\\"${MTIME}","c":[1,-${MTIME}],"d":1500,"e":123}`);
});

test('ready only after file_session_start; signed mode/root lease; limits exactly as §3', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openRaw(r);
    const open = await waitUntil('file_open', () => agentFrames(agent, 'file_open')[0]);
    assert.match(open.session_id, /^fls_[A-Za-z0-9_-]{16,64}$/);
    assert.equal(open.action, 'file');
    assert.equal(open.mode, 'write');
    assert.equal(open.root, '/srv/a');
    assert.equal(open.idle_s, 900);
    assert.equal(open.file_max, 16 * 1024 ** 3);
    assert.equal(open.actor, 'user-1');
    const now = Math.floor(Date.now() / 1000);
    assert.ok(Math.abs(open.deadline_unix - (now + 28800)) <= 2);
    assert.equal(open.lease.action, 'file');
    assert.ok(open.lease.expires_unix - now <= 61);
    const payload = filePayload(open.session_id, open.deadline_unix, 'start', 'write', '/srv/a');
    assert.equal(verifyLease(PUBLIC_KEY, open.lease, payload).ok, true);
    // FILE §12: a ticket for /srv/a cannot reach /srv/b; the lease cannot read-mode either.
    assert.equal(verifyLease(PUBLIC_KEY, open.lease, filePayload(open.session_id, open.deadline_unix, 'start', 'write', '/srv/b')).error, 'payload_mismatch');
    assert.equal(verifyLease(PUBLIC_KEY, open.lease, filePayload(open.session_id, open.deadline_unix, 'start', 'read', '/srv/a')).error, 'payload_mismatch');
    assert.deepEqual(client.box.frames[0], { type: 'file_status', payload: { status: 'starting' } });
    assert.equal(auditRows(r, 'file_session_start').length, 0);
    // A request before ready is a protocol_error.
    sendJSON(agent.ws, { type: 'file_status', session_id: open.session_id, payload: { status: 'ready', root: '/srv/a', user: 'deploy', uid: 1000 } });
    const rdy = await waitUntil('ready', () => client.box.frames.find((f) => f.type === 'file_status' && f.payload.status === 'ready'));
    assert.deepEqual(rdy.payload, {
      status: 'ready', session_id: open.session_id, root: '/srv/a', user: 'deploy',
      limits: { chunk_max: 1048576, read_max: 8388608, write_window: 8, file_max: 17179869184, list_max: 1000 }
    });
    const start = auditRows(r, 'file_session_start');
    assert.equal(start.length, 1);
    assert.deepEqual(start[0].payload, { session_id: open.session_id, purpose: 'file:write', root: '/srv/a', user: 'deploy', uid: 1000 });
    assert.equal(start[0].actor, 'user-1');
    assert.equal(start[0].host_id, HOST_A);
  } finally {
    await r.close();
  }
});

test('a request before ready is a protocol_error; a wrong canonical root ends the session', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const early = openRaw(r);
    await waitUntil('file_open', () => agentFrames(agent, 'file_open').length === 1);
    sendJSON(early.ws, { type: 'file_request', request_id: 'r1', op: 'stat', path: '.' });
    await failsWith(early, 'protocol_error');
    await waitUntil('file_stop', () => agentFrames(agent, 'file_stop').length === 1);

    const c = openRaw(r);
    const open = await waitUntil('file_open', () => agentFrames(agent, 'file_open')[1]);
    sendJSON(agent.ws, { type: 'file_status', session_id: open.session_id, payload: { status: 'ready', root: '/srv/b', user: 'deploy', uid: 1000 } });
    await failsWith(c, 'internal');
    assert.equal(auditRows(r, 'file_session_start').length, 0);
  } finally {
    await r.close();
  }
});

test('tickets: reused fails, host-A cannot open host B, purposes and roots do not cross', async () => {
  const r = await rig();
  try {
    await connectAgent(r);
    await connectAgent(r, { hostId: HOST_B });
    const agentA = r.fm.connectedAgents.get(HOST_A);
    assert.ok(agentA);
    const first = openRaw(r);
    await waitUntil('starting', () => first.box.frames.length > 0);
    // FILE §12: a reused ticket fails.
    await failsWith(openRaw(r, { ticket: first.ticket }), 'ticket_invalid');
    // FILE §12: a host-A ticket cannot touch host B (and is spent).
    const t = ticketFor(r);
    await failsWith(openRaw(r, { ticket: t, hostId: HOST_B }), 'ticket_invalid');
    await failsWith(openRaw(r, { ticket: t }), 'ticket_invalid');
    // Purpose in the URL must equal the ticket's.
    await failsWith(openRaw(r, { ticket: ticketFor(r, { purpose: 'file:read' }), purpose: 'file:write' }), 'ticket_invalid');
    await failsWith(openRaw(r, { ticket: ticketFor(r, { purpose: 'file:read' }), purpose: '' }), 'ticket_invalid');
    // A terminal or tcp ticket is not a file ticket.
    const term = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme', actor: 'user-1' });
    await failsWith(openRaw(r, { ticket: term, purpose: 'terminal:open' }), 'ticket_invalid');
    // A file ticket presented on the terminal path is spent and refused.
    const ft = ticketFor(r);
    const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=${ft}&purpose=file:write`));
    const box = collect(ws);
    await waitUntil('pty error', () => box.closeCode !== null);
    await failsWith(openRaw(r, { ticket: ft }), 'ticket_invalid');
  } finally {
    await r.close();
  }
});

test('upgrade rules: api_key in the query is 401, a foreign Origin 403', async () => {
  const r = await rig();
  try {
    await connectAgent(r);
    const status = (url, headers = {}) => new Promise((resolve) => {
      const ws = new WebSocket(url, { headers });
      ws.on('unexpected-response', (req, res) => resolve(res.statusCode));
      ws.on('open', () => { ws.close(); resolve(101); });
      ws.on('error', () => {});
    });
    const t = ticketFor(r);
    assert.equal(await status(`${r.base}/api/v1/systems/file/${HOST_A}?ticket=${t}&purpose=file:write&api_key=x`), 401);
    assert.equal(await status(`${r.base}/api/v1/systems/file/${HOST_A}?ticket=${ticketFor(r)}&purpose=file:write`, { origin: 'https://evil.example' }), 403);
  } finally {
    await r.close();
  }
});

test('re-check at the upgrade: policy, root flag, operator cannot get file:root, lost scope', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, { policy: null });
    // Empty policy denies.
    await failsWith(openRaw(r), 'root_denied');
    await r.fm.registry.setHostChannelPolicy(HOST_A, { file_policy: POLICY });
    // /srv/b is read-only in the policy: a write ticket is refused at the upgrade.
    await failsWith(openRaw(r, { root: '/srv/b' }), 'root_denied');
    // A root outside every entry.
    await failsWith(openRaw(r, { root: '/var' }), 'root_denied');
    // file:root needs the entry's root flag.
    await failsWith(openRaw(r, { purpose: 'file:root', root: '/srv/a' }), 'root_denied');
    // FILE §12: an operator cannot get file:root (re-checked here too).
    await r.fm.registry.addMember('acme', 'op-1', 'operator', null);
    await failsWith(openRaw(r, { purpose: 'file:root', root: '/etc', actor: 'op-1' }), 'scope_denied');
    // A viewer has no file:read.
    await r.fm.registry.addMember('acme', 'viewer-1', 'viewer', null);
    await failsWith(openRaw(r, { purpose: 'file:read', root: '/srv/b', actor: 'viewer-1' }), 'scope_denied');
    // An API key without file:write cannot write.
    await r.fm.registry.setScopes('k9', ['file:read']);
    const keyTicket = ticketFor(r, { auth: { kind: 'key', keyId: 'k9' } });
    await failsWith(openRaw(r, { ticket: keyTicket }), 'scope_denied');
    // A "~" ticket is never valid for file:root.
    await failsWith(openRaw(r, { purpose: 'file:root', root: '~' }), 'ticket_invalid');
    // An operator gets file:write; the admin-only file:root session runs as root.
    await ready(r, agent, { actor: 'op-1' });
    const rootSess = await ready(r, agent, { purpose: 'file:root', root: '/etc', uid: 0, user: 'root' });
    assert.equal(rootSess.open.action, 'file_root');
    assert.equal(rootSess.open.mode, 'write');
    // A file:root session whose helper is not uid 0 is refused.
    const notRoot = openRaw(r, { purpose: 'file:root', root: '/etc' });
    const open = await waitUntil('file_open', () => agentFrames(agent, 'file_open').find((f) => f.action === 'file_root' && f.session_id !== rootSess.sid));
    sendJSON(agent.ws, { type: 'file_status', session_id: open.session_id, payload: { status: 'ready', root: '/etc', user: 'deploy', uid: 1000 } });
    await failsWith(notRoot, 'internal');
  } finally {
    await r.close();
  }
});

test('agent_offline, agent_unsupported, lease_required, cap_reached, agent start errors', async () => {
  const r = await rig({ SYSTEMAPI_FILE_MAX_PER_ACTOR: '1' });
  try {
    const gone = await connectAgent(r);
    gone.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    await failsWith(openRaw(r), 'agent_offline');
    const old = await connectAgent(r, { caps: 'pty,tcp' });
    await failsWith(openRaw(r), 'agent_unsupported');
    old.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));

    const agent = await connectAgent(r);
    const signerWas = r.fm.signer;
    r.fm.signer = null;
    await failsWith(openRaw(r), 'lease_required');
    r.fm.signer = signerWas;

    for (const code of ['root_invalid', 'pty_user_unset', 'root_unavailable', 'agent_unsupported', 'bogus']) {
      const c = openRaw(r);
      const open = await waitUntil('file_open', () => agentFrames(agent, 'file_open').find((f) => !f.seen && (f.seen = true)));
      sendJSON(agent.ws, { type: 'file_status', session_id: open.session_id, payload: { error: code } });
      await failsWith(c, code === 'bogus' ? 'internal' : code);
    }
    assert.equal(auditRows(r, 'file_session_start').length, 0);
    assert.equal(auditRows(r, 'file_session_end').length, 0);

    await ready(r, agent);
    await failsWith(openRaw(r), 'cap_reached');
  } finally {
    await r.close();
  }
});

test('one op at a time: pipelined request, reused id, bad request_id and non-JSON are protocol_error', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    // FILE §12: a pipelined request gives protocol_error.
    const a = await ready(r, agent);
    sendJSON(a.client.ws, { type: 'file_request', request_id: 'r1', op: 'stat', path: '.' });
    sendJSON(a.client.ws, { type: 'file_request', request_id: 'r2', op: 'stat', path: '.' });
    await failsWith(a.client, 'protocol_error');
    await waitUntil('file_stop', () => agentFrames(agent, 'file_stop').some((f) => f.session_id === a.sid));

    // A reused request_id.
    const b = await ready(r, agent);
    sendJSON(b.client.ws, { type: 'file_request', request_id: 'r1', op: 'stat', path: '.' });
    const req = await waitUntil('forwarded', () => agentReqs(agent, b.sid)[0]);
    assert.deepEqual(req, { request_id: 'r1', op: 'stat', path: '.' });
    agentResult(agent, b.sid, 'r1', 'stat', { entry: { name: '.', type: 'dir', size: 4096, mode: '0755', mtime_ns: 1 } });
    await waitResult(b.client.box, 'r1');
    sendJSON(b.client.ws, { type: 'file_request', request_id: 'r1', op: 'stat', path: '.' });
    await failsWith(b.client, 'protocol_error');

    for (const bad of ['not json', '[]', JSON.stringify({ type: 'file_request', request_id: 'bad id!', op: 'stat', path: '.' }),
      JSON.stringify({ type: 'file_request', op: 'stat', path: '.' }), JSON.stringify({ type: 'other', request_id: 'r9', op: 'stat', path: '.' })]) {
      const c = await ready(r, agent);
      sendJSON(c.client.ws, bad);
      await failsWith(c.client, 'protocol_error');
    }
    // A binary frame with no write_chunk header.
    const d = await ready(r, agent);
    d.client.ws.send(Buffer.from('x'));
    await failsWith(d.client, 'protocol_error');
  } finally {
    await r.close();
  }
});

test('unknown op and malformed fields are bad_request; bad paths never reach the agent; the session stays open', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    let n = 0;
    const ask = async (obj) => {
      const rid = `q${n += 1}`;
      sendJSON(s.client.ws, { type: 'file_request', request_id: rid, ...obj });
      return (await waitResult(s.client.box, rid)).error;
    };
    assert.equal(await ask({ op: 'chmod', path: 'x' }), 'bad_request');
    for (const p of ['../../etc/shadow', '/etc/shadow', 'a/../../x', 'a//b', 'a/./b']) {
      assert.equal(await ask({ op: 'stat', path: p }), 'bad_path');
      assert.equal(await ask({ op: 'remove', path: p }), 'bad_path');
      assert.equal(await ask({ op: 'write_open', path: p, size: 1, sha256: SHA, overwrite: false }), 'bad_path');
    }
    assert.equal(await ask({ op: 'stat', path: 'd/.sahsync-x.part' }), 'reserved_name');
    assert.equal(await ask({ op: 'read', path: 'f', offset: 0, length: 8 * MiB + 1 }), 'bad_request');
    assert.equal(await ask({ op: 'read', path: 'f', offset: -1, length: 1 }), 'bad_request');
    assert.equal(await ask({ op: 'read', path: 'f', offset: 0, length: 1, if_match: { size: 1 } }), 'bad_request');
    assert.equal(await ask({ op: 'list', path: '.', limit: 1001 }), 'bad_request');
    assert.equal(await ask({ op: 'write_open', path: 'f', size: 1, sha256: 'A'.repeat(64), overwrite: false }), 'bad_request');
    assert.equal(await ask({ op: 'write_open', path: 'f', size: 1, sha256: SHA }), 'bad_request');
    assert.equal(await ask({ op: 'write_open', path: 'f', size: 1, sha256: SHA, overwrite: false, mode: '4755' }), 'bad_request');
    assert.equal(await ask({ op: 'write_open', path: 'f', size: 16 * 1024 ** 3 + 1, sha256: SHA, overwrite: false }), 'too_large');
    assert.equal(await ask({ op: 'mkdir', path: 'd', mode: '0644x' }), 'bad_request');
    assert.equal(await ask({ op: 'write_abort' }), 'upload_not_found');
    assert.equal(await ask({ op: 'write_commit' }), 'upload_not_found');
    assert.equal(agentReqs(agent, s.sid).length, 0);
    // The session is still open: the op-name-as-type spelling works too.
    sendJSON(s.client.ws, { type: 'stat', request_id: 'ok1', path: 'f' });
    const fwd = await waitUntil('forwarded', () => agentReqs(agent, s.sid)[0]);
    assert.deepEqual(fwd, { request_id: 'ok1', op: 'stat', path: 'f' });
  } finally {
    await r.close();
  }
});

test('a file:read ticket cannot write: read_only from the server, never forwarded; the lease says read', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent, { purpose: 'file:read', root: '/srv/b' });
    assert.equal(s.open.mode, 'read');
    assert.equal(verifyLease(PUBLIC_KEY, s.open.lease, filePayload(s.sid, s.open.deadline_unix, 'start', 'read', '/srv/b')).ok, true);
    let n = 0;
    for (const req of [
      { op: 'write_open', path: 'f', size: 1, sha256: SHA, overwrite: true },
      { op: 'mkdir', path: 'd' },
      { op: 'remove', path: 'f' },
      { op: 'write_commit' },
      { op: 'write_abort' }
    ]) {
      const rid = `w${n += 1}`;
      sendJSON(s.client.ws, { type: 'file_request', request_id: rid, ...req });
      assert.equal((await waitResult(s.client.box, rid)).error, 'read_only');
    }
    // A write_chunk with no open write is a framing error.
    sendJSON(s.client.ws, { type: 'write_chunk', request_id: 'w1', offset: 0, length: 1 });
    await failsWith(s.client, 'protocol_error');
    assert.equal(agentReqs(agent, s.sid).length, 0);
    assert.equal(auditRows(r, 'file_intent').length, 0);
  } finally {
    await r.close();
  }
});

test('stat/list relay mtime_ns exactly and are counted, not audited per op', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    s.client.ws.send(`{"type":"file_request","request_id":"h1","op":"hash","path":"f","if_match":{"size":5,"mtime_ns":${MTIME}}}`);
    await waitUntil('forwarded', () => agentReqs(agent, s.sid)[0]);
    // The agent socket got the exact digits.
    const rawReq = agent.box.frames.length && agentFrames(agent, 'file_req')[0];
    assert.ok(rawReq);
    agent.ws.send(`{"type":"file_result","session_id":"${s.sid}","request_id":"h1","op":"hash","status":"ok","error":null,"sha256":"${SHA}","size":5,"mtime_ns":${MTIME}}`);
    await waitResult(s.client.box, 'h1');
    assert.ok(s.client.box.raw.find((t) => t.includes(`"mtime_ns":${MTIME}`)), 'client got exact mtime_ns');
    sendJSON(s.client.ws, { type: 'file_request', request_id: 's1', op: 'stat', path: 'f' });
    await waitUntil('stat fwd', () => agentReqs(agent, s.sid)[1]);
    agent.ws.send(`{"type":"file_result","session_id":"${s.sid}","request_id":"s1","op":"stat","status":"ok","error":null,"entry":{"name":"f","type":"file","size":5,"mode":"0644","mtime_ns":${MTIME}}}`);
    await waitResult(s.client.box, 's1');
    sendJSON(s.client.ws, { type: 'file_request', request_id: 'l1', op: 'list', path: '.' });
    const lreq = await waitUntil('list fwd', () => agentReqs(agent, s.sid)[2]);
    assert.deepEqual(lreq, { request_id: 'l1', op: 'list', path: '.', cursor: null, limit: 500 });
    agentResult(agent, s.sid, 'l1', 'list', { entries: [], next_cursor: null });
    await waitResult(s.client.box, 'l1');
    s.client.ws.close();
    const end = await waitUntil('end row', () => auditRows(r, 'file_session_end')[0]);
    assert.equal(end.payload.reason, 'client_closed');
    assert.equal(end.payload.ops, 3);
    assert.equal(end.payload.stat_count, 1);
    assert.equal(end.payload.list_count, 1);
    const read = auditRows(r, 'file_read');
    assert.equal(read.length, 1);
    assert.deepEqual(read[0].payload, { session_id: s.sid, path: 'f', bytes: 0, ranges: 0, sha256: SHA });
    assert.equal(auditRows(r, 'file_op').length, 0);
  } finally {
    await r.close();
  }
});

test('read: read_chunk pairs of at most chunk_max, then file_result; one coalesced file_read row per path', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    const content = crypto.randomBytes(MiB + MiB / 2);
    const doRead = async (rid, offset, bytes) => {
      sendJSON(s.client.ws, { type: 'file_request', request_id: rid, op: 'read', path: 'dir/f.bin', offset, length: 2 * MiB });
      await waitUntil('read fwd', () => agentReqs(agent, s.sid).find((q) => q.request_id === rid));
      for (let off = 0; off < bytes.length; off += 64 * 1024) agent.ws.send(data(s.sid, bytes.subarray(off, off + 64 * 1024)));
      agentResult(agent, s.sid, rid, 'read', { bytes: bytes.length, eof: true, size: content.length, mtime_ns: 1 });
      return waitResult(s.client.box, rid);
    };
    const res = await doRead('rd1', 0, content);
    assert.equal(res.bytes, content.length);
    const pairs = [];
    const frames = s.client.box.frames;
    for (let i = 0; i < frames.length; i += 1) {
      if (frames[i].type === 'read_chunk') {
        assert.ok(frames[i + 1].binary, 'a binary frame follows each read_chunk');
        assert.equal(frames[i + 1].binary.length, frames[i].length);
        pairs.push(frames[i]);
      }
    }
    assert.deepEqual(pairs.map((p) => [p.offset, p.length]), [[0, MiB], [MiB, MiB / 2]]);
    assert.ok(frames.indexOf(res) > frames.indexOf(pairs[1]) + 1, 'the result follows the data');
    assert.ok(Buffer.concat(s.client.box.binaries).equals(content));
    // Every delivered byte is drained for credit (returned in quarter-window batches).
    const stream = r.fm.file.sessions.get(s.sid).stream;
    await waitUntil('drained', () => stream.drainedUnreturned === content.length);
    // A second read of the same path coalesces.
    await doRead('rd2', 10, content.subarray(0, 100));
    // Data with no read in flight ends the session.
    agent.ws.send(data(s.sid, Buffer.from('stray')));
    await failsWith(s.client, 'internal');
    const rows = await waitUntil('file_read', () => auditRows(r, 'file_read').length && auditRows(r, 'file_read'));
    assert.equal(rows.length, 1);
    assert.deepEqual(rows[0].payload, { session_id: s.sid, path: 'dir/f.bin', bytes: content.length + 100, ranges: 2, sha256: null });
    const end = await waitUntil('end', () => auditRows(r, 'file_session_end')[0]);
    assert.equal(end.payload.bytes_read, content.length + 100);
  } finally {
    await r.close();
  }
});

// Opens a write and returns its request id.
async function openWrite(r, agent, s, { rid = 'w1', size = 3 * MiB, offset = 0, path = 'up/f.bin' } = {}) {
  sendJSON(s.client.ws, { type: 'file_request', request_id: rid, op: 'write_open', path, size, sha256: SHA, overwrite: false });
  const fwd = await waitUntil('write_open fwd', () => agentReqs(agent, s.sid).find((q) => q.request_id === rid && q.op === 'write_open'));
  assert.deepEqual(fwd, { request_id: rid, op: 'write_open', path, size, sha256: SHA, overwrite: false, resume: false });
  agentResult(agent, s.sid, rid, 'write_open', { upload_id: 'upl_AAAAAAAAAAAAAAAAAAAAAAAA', offset, ...(offset ? { prefix_sha256: SHA } : {}) });
  const res = await waitResult(s.client.box, rid, 'write_open');
  assert.equal(res.status, 'ok');
  return rid;
}

function chunk(s, rid, offset, bytes) {
  sendJSON(s.client.ws, { type: 'write_chunk', request_id: rid, offset, length: bytes.length });
  s.client.ws.send(bytes);
}

test('write: chunks go to the agent in order with headers, acks relay, intent row before commit, result row after', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    const rid = await openWrite(r, agent, s, { size: 2 * MiB + 10 });
    const openRow = auditRows(r, 'file_op').find((x) => x.payload.op === 'write_open');
    assert.deepEqual(openRow.payload, { session_id: s.sid, op: 'write_open', path: 'up/f.bin', size: 2 * MiB + 10, sha256: SHA, overwrite: false, upload_id: 'upl_AAAAAAAAAAAAAAAAAAAAAAAA', offset: 0, result: 'ok' });
    const body = crypto.randomBytes(2 * MiB + 10);
    chunk(s, rid, 0, body.subarray(0, MiB));
    chunk(s, rid, MiB, body.subarray(MiB, 2 * MiB));
    chunk(s, rid, 2 * MiB, body.subarray(2 * MiB));
    await waitUntil('all bytes at the agent', () => Buffer.concat(agent.data.get(s.sid) || []).length === body.length);
    assert.ok(Buffer.concat(agent.data.get(s.sid)).equals(body));
    const heads = agentFrames(agent, 'file_chunk').filter((f) => f.session_id === s.sid);
    assert.deepEqual(heads.map((h) => [h.request_id, h.offset, h.length]), [[rid, 0, MiB], [rid, MiB, MiB], [rid, 2 * MiB, 10]]);
    for (const off of [MiB, 2 * MiB, 2 * MiB + 10]) sendJSON(agent.ws, { type: 'file_write_ack', session_id: s.sid, request_id: rid, offset: off });
    await waitUntil('acks', () => s.client.box.frames.filter((f) => f.type === 'write_ack').length === 3);
    assert.deepEqual(s.client.box.frames.find((f) => f.type === 'write_ack'), { type: 'write_ack', request_id: rid, offset: MiB });

    // write_commit: the intent row is written before the agent sees it.
    let commitSeenWithIntent = null;
    sendJSON(s.client.ws, { type: 'file_request', request_id: rid, op: 'write_commit' });
    const commitReq = await waitUntil('commit fwd', () => agentReqs(agent, s.sid).find((q) => q.op === 'write_commit'));
    commitSeenWithIntent = auditRows(r, 'file_intent').length;
    assert.deepEqual(commitReq, { request_id: rid, op: 'write_commit' });
    assert.equal(commitSeenWithIntent, 1);
    assert.deepEqual(auditRows(r, 'file_intent')[0].payload, { session_id: s.sid, op: 'write_commit', path: 'up/f.bin', size: 2 * MiB + 10, sha256: SHA, upload_id: 'upl_AAAAAAAAAAAAAAAAAAAAAAAA' });
    agentResult(agent, s.sid, rid, 'write_commit', { sha256: SHA, size: 2 * MiB + 10, path: 'up/f.bin' });
    const res = await waitResult(s.client.box, rid, 'write_commit');
    assert.deepEqual(res, { type: 'file_result', request_id: rid, op: 'write_commit', status: 'ok', error: null, sha256: SHA, size: 2 * MiB + 10, path: 'up/f.bin' });
    const commitRow = auditRows(r, 'file_op').find((x) => x.payload.op === 'write_commit');
    assert.deepEqual(commitRow.payload, { session_id: s.sid, op: 'write_commit', path: 'up/f.bin', size: 2 * MiB + 10, upload_id: 'upl_AAAAAAAAAAAAAAAAAAAAAAAA', result: 'ok', sha256: SHA });
    // The write is closed: a chunk for it now is a framing error... after the commit it is dropped as in flight.
    // mkdir and remove get intent and result rows.
    sendJSON(s.client.ws, { type: 'file_request', request_id: 'm1', op: 'mkdir', path: 'nd', parents: true, mode: '0750' });
    const mk = await waitUntil('mkdir fwd', () => agentReqs(agent, s.sid).find((q) => q.op === 'mkdir'));
    assert.deepEqual(mk, { request_id: 'm1', op: 'mkdir', path: 'nd', parents: true, mode: '0750' });
    agentResult(agent, s.sid, 'm1', 'mkdir', {}, 'exists');
    assert.equal((await waitResult(s.client.box, 'm1')).error, 'exists');
    sendJSON(s.client.ws, { type: 'file_request', request_id: 'x1', op: 'remove', path: 'old' });
    await waitUntil('remove fwd', () => agentReqs(agent, s.sid).find((q) => q.op === 'remove'));
    agentResult(agent, s.sid, 'x1', 'remove', {});
    await waitResult(s.client.box, 'x1');
    assert.deepEqual(auditRows(r, 'file_intent').map((x) => x.payload.op), ['write_commit', 'mkdir', 'remove']);
    const ops = auditRows(r, 'file_op').map((x) => [x.payload.op, x.payload.result]);
    assert.deepEqual(ops, [['write_open', 'ok'], ['write_commit', 'ok'], ['mkdir', 'exists'], ['remove', 'ok']]);
    s.client.ws.close();
    const end = await waitUntil('end', () => auditRows(r, 'file_session_end')[0]);
    assert.equal(end.payload.bytes_written, 2 * MiB + 10);
    assert.equal(end.payload.ops, 4);
    // No row carries file content.
    assert.equal(JSON.stringify(r.fm.registry.audit).includes(body.subarray(0, 32).toString('base64')), false);
  } finally {
    await r.close();
  }
});

test('a failed intent row refuses the op with internal and nothing is forwarded', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    const append = r.fm.registry.appendAudit.bind(r.fm.registry);
    r.fm.registry.appendAudit = async (entry) => {
      if (entry.action === 'file_intent') throw new Error('db down');
      return append(entry);
    };
    sendJSON(s.client.ws, { type: 'file_request', request_id: 'm1', op: 'remove', path: 'f' });
    assert.equal((await waitResult(s.client.box, 'm1')).error, 'internal');
    await sleep(50);
    assert.equal(agentReqs(agent, s.sid).length, 0);
    // The session stays open.
    sendJSON(s.client.ws, { type: 'file_request', request_id: 's1', op: 'stat', path: 'f' });
    await waitUntil('stat fwd', () => agentReqs(agent, s.sid).length === 1);
  } finally {
    await r.close();
  }
});

test('write framing: offset_mismatch and too_large end the write; write_window and length are enforced; abort', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    let rid = await openWrite(r, agent, s, { size: 10 * MiB, rid: 'w1' });
    chunk(s, rid, 5, Buffer.alloc(10, 1));
    assert.equal((await waitResult(s.client.box, rid, 'write_chunk')).error, 'offset_mismatch');
    await waitUntil('release', () => agentReqs(agent, s.sid).find((q) => q.op === 'write_release'));
    // A chunk still in flight for the ended write is dropped; commit is upload_not_found under a new id.
    chunk(s, rid, 15, Buffer.alloc(10, 1));
    sendJSON(s.client.ws, { type: 'file_request', request_id: 'c2', op: 'write_commit' });
    assert.equal((await waitResult(s.client.box, 'c2')).error, 'upload_not_found');
    assert.equal(agentFrames(agent, 'file_chunk').length, 0);

    rid = await openWrite(r, agent, s, { size: 4, rid: 'w2' });
    chunk(s, rid, 0, Buffer.alloc(5, 1));
    assert.equal((await waitResult(s.client.box, rid, 'write_chunk')).error, 'too_large');

    // Resume: the next offset is the agent's durable offset.
    rid = await openWrite(r, agent, s, { size: 3 * MiB, rid: 'w3', offset: 2 * MiB });
    chunk(s, rid, 0, Buffer.alloc(10, 1));
    assert.equal((await waitResult(s.client.box, rid, 'write_chunk')).error, 'offset_mismatch');

    // Abort deletes at the agent and gets one row with the upload_id.
    rid = await openWrite(r, agent, s, { size: 3 * MiB, rid: 'w4' });
    chunk(s, rid, 0, Buffer.alloc(100, 1));
    sendJSON(s.client.ws, { type: 'file_request', request_id: rid, op: 'write_abort' });
    await waitUntil('abort fwd', () => agentReqs(agent, s.sid).find((q) => q.op === 'write_abort'));
    agentResult(agent, s.sid, rid, 'write_abort', {});
    assert.equal((await waitResult(s.client.box, rid, 'write_abort')).status, 'ok');
    const abortRow = auditRows(r, 'file_op').find((x) => x.payload.op === 'write_abort');
    assert.equal(abortRow.payload.upload_id, 'upl_AAAAAAAAAAAAAAAAAAAAAAAA');
    // The agent saw the header before the abort, and the data before both.
    const order = agent.box.frames.filter((f) => f.session_id === s.sid && (f.type === 'file_chunk' || (f.type === 'file_req' && f.request.op === 'write_abort'))).map((f) => f.type);
    assert.deepEqual(order, ['file_chunk', 'file_req']);

    // write_window: a ninth unacknowledged chunk is a protocol_error.
    rid = await openWrite(r, agent, s, { size: 100, rid: 'w5' });
    for (let i = 0; i < 9; i += 1) chunk(s, rid, i, Buffer.alloc(1, 1));
    await failsWith(s.client, 'protocol_error');

    // A binary frame whose length differs from the header.
    const t = await ready(r, agent);
    rid = await openWrite(r, agent, t, { size: 100, rid: 'w6' });
    sendJSON(t.client.ws, { type: 'write_chunk', request_id: rid, offset: 0, length: 10 });
    t.client.ws.send(Buffer.alloc(9));
    await failsWith(t.client, 'protocol_error');

    // Another request while a write is open.
    const u = await ready(r, agent);
    await openWrite(r, agent, u, { size: 100, rid: 'w7' });
    sendJSON(u.client.ws, { type: 'file_request', request_id: 'z', op: 'stat', path: '.' });
    await failsWith(u.client, 'protocol_error');
  } finally {
    await r.close();
  }
});

test('an agent chunk failure ends the write; the error reaches the client', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    const rid = await openWrite(r, agent, s, { size: 100 });
    chunk(s, rid, 0, Buffer.alloc(10, 1));
    await waitUntil('chunk', () => agentFrames(agent, 'file_chunk').length === 1);
    agentResult(agent, s.sid, rid, 'write_chunk', {}, 'no_space');
    assert.equal((await waitResult(s.client.box, rid, 'write_chunk')).error, 'no_space');
    sendJSON(s.client.ws, { type: 'file_request', request_id: 'n1', op: 'stat', path: '.' });
    await waitUntil('next op', () => agentReqs(agent, s.sid).find((q) => q.request_id === 'n1'));
  } finally {
    await r.close();
  }
});

test('1009 past 64 KiB of text or chunk_max of binary', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    s.client.ws.send(JSON.stringify({ type: 'file_request', request_id: 'r1', op: 'stat', path: 'a', pad: 'x'.repeat(64 * 1024) }));
    await waitUntil('1009', () => s.client.box.closeCode === 1009);
    const t = await ready(r, agent);
    t.client.ws.send(Buffer.alloc(MiB + 1));
    await waitUntil('1009', () => t.client.box.closeCode === 1009);
    const ends = await waitUntil('ends', () => auditRows(r, 'file_session_end').length === 2 && auditRows(r, 'file_session_end'));
    assert.deepEqual(ends.map((e) => e.payload.reason), ['frame_too_large', 'frame_too_large']);
  } finally {
    await r.close();
  }
});

test('limits: idle_timeout, max_duration, op_cap, byte_cap', async () => {
  const r = await rig({ SYSTEMAPI_FILE_IDLE_SECONDS: '1', SYSTEMAPI_FILE_MAX_OPS: '2', SYSTEMAPI_FILE_SESSION_BYTES: String(MiB), SYSTEMAPI_FILE_MAX_PER_ACTOR: '10' });
  try {
    const agent = await connectAgent(r);
    const idle = await ready(r, agent);
    await waitUntil('idle', () => closeFrame(idle.client.box), 3000);
    assert.equal(closeFrame(idle.client.box).payload.reason, 'idle_timeout');
    assert.equal(idle.client.box.closeCode, 1000);

    const ops = await ready(r, agent);
    for (const rid of ['a', 'b']) {
      sendJSON(ops.client.ws, { type: 'file_request', request_id: rid, op: 'nope' });
      await waitResult(ops.client.box, rid);
    }
    sendJSON(ops.client.ws, { type: 'file_request', request_id: 'c', op: 'nope' });
    await waitUntil('op_cap', () => closeFrame(ops.client.box));
    assert.deepEqual(closeFrame(ops.client.box).payload, { session_id: ops.sid, reason: 'op_cap', ops: 2, bytes_read: 0, bytes_written: 0 });

    const bytes = await ready(r, agent);
    sendJSON(bytes.client.ws, { type: 'file_request', request_id: 'r', op: 'read', path: 'f', offset: 0, length: MiB + 1 });
    await waitUntil('byte_cap', () => closeFrame(bytes.client.box));
    assert.equal(closeFrame(bytes.client.box).payload.reason, 'byte_cap');
    assert.equal(agentReqs(agent, bytes.sid).length, 0);
  } finally {
    await r.close();
  }
  const r2 = await rig({ SYSTEMAPI_FILE_MAX_SECONDS: '1' });
  try {
    const agent = await connectAgent(r2);
    const s = await ready(r2, agent);
    await waitUntil('max', () => closeFrame(s.client.box), 3000);
    assert.equal(closeFrame(s.client.box).payload.reason, 'max_duration');
    await waitUntil('file_stop', () => agentFrames(agent, 'file_stop').some((f) => f.session_id === s.sid));
  } finally {
    await r2.close();
  }
});

test('the lease is renewed with a renew-phase, mode- and root-bound lease', async () => {
  const r = await rig();
  r.fm.file.renewMs = 50;
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent, { purpose: 'file:read', root: '/srv/b' });
    const renew = await waitUntil('renew', () => agentFrames(agent, 'file_renew').find((f) => f.session_id === s.sid));
    assert.equal(verifyLease(PUBLIC_KEY, renew.lease, filePayload(s.sid, s.open.deadline_unix, 'renew', 'read', '/srv/b')).ok, true);
    assert.equal(verifyLease(PUBLIC_KEY, renew.lease, filePayload(s.sid, s.open.deadline_unix, 'start', 'read', '/srv/b')).ok, false);
  } finally {
    await r.close();
  }
});

test('a failed file_session_start write ends the session with internal before ready', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const append = r.fm.registry.appendAudit.bind(r.fm.registry);
    r.fm.registry.appendAudit = async (entry) => {
      if (entry.action === 'file_session_start') throw new Error('db down');
      return append(entry);
    };
    const c = openRaw(r);
    const open = await waitUntil('file_open', () => agentFrames(agent, 'file_open')[0]);
    sendJSON(agent.ws, { type: 'file_status', session_id: open.session_id, payload: { status: 'ready', root: '/srv/a', user: 'deploy', uid: 1000 } });
    await failsWith(c, 'internal');
    assert.equal(c.box.frames.some((f) => f.payload && f.payload.status === 'ready'), false);
  } finally {
    await r.close();
  }
});

test('agent disconnect, agent close reasons, agent credit overrun', async () => {
  const r = await rig({ SYSTEMAPI_FILE_MAX_PER_ACTOR: '10' });
  try {
    const agent = await connectAgent(r);
    const a = await ready(r, agent);
    sendJSON(agent.ws, { type: 'file_closed', session_id: a.sid, payload: { reason: 'idle_timeout', ops: 0, bytes_read: 0, bytes_written: 0 } });
    await waitUntil('close', () => closeFrame(a.client.box));
    assert.equal(closeFrame(a.client.box).payload.reason, 'idle_timeout');

    const b = await ready(r, agent);
    sendJSON(b.client.ws, { type: 'file_request', request_id: 'r', op: 'read', path: 'f', offset: 0, length: 8 * MiB });
    await waitUntil('read fwd', () => agentReqs(agent, b.sid).length === 1);
    r.fm.file.sessions.get(b.sid).sink.maxBuffered = 0;
    for (let i = 0; i < FILE_WINDOW / (64 * 1024); i += 1) agent.ws.send(data(b.sid, Buffer.alloc(64 * 1024, 1)));
    agent.ws.send(data(b.sid, Buffer.alloc(1, 1)));
    await waitUntil('agent terminated', () => agent.ws.readyState === WebSocket.CLOSED);
    assert.ok(r.fm.registry.securityEvents.find((e) => e.kind === 'agent_credit_violation' && e.detail.reason === 'credit_overrun'));
    await waitUntil('close', () => closeFrame(b.client.box));
    assert.equal(closeFrame(b.client.box).payload.reason, 'agent_disconnected');
  } finally {
    await r.close();
  }
});

test('client -> agent write data leaves only inside agent credit; the client is paused, nothing dropped', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const s = await ready(r, agent);
    const size = 12 * MiB;
    const rid = await openWrite(r, agent, s, { size });
    const body = crypto.randomBytes(size);
    const sentTo = (n) => {
      for (let i = 0; i < n; i += 1) chunk(s, rid, i * MiB, body.subarray(i * MiB, (i + 1) * MiB));
    };
    sentTo(8);
    await waitUntil('window full', () => Buffer.concat(agent.data.get(s.sid) || []).length === FILE_WINDOW);
    await sleep(100);
    assert.equal(Buffer.concat(agent.data.get(s.sid)).length, FILE_WINDOW);
    // Acks for 4 chunks and credit for 4 MiB let 4 more through.
    for (let i = 1; i <= 4; i += 1) sendJSON(agent.ws, { type: 'file_write_ack', session_id: s.sid, request_id: rid, offset: i * MiB });
    await waitUntil('acks', () => s.client.box.frames.filter((f) => f.type === 'write_ack').length === 4);
    for (let i = 8; i < 12; i += 1) chunk(s, rid, i * MiB, body.subarray(i * MiB, (i + 1) * MiB));
    await sleep(100);
    assert.equal(Buffer.concat(agent.data.get(s.sid)).length, FILE_WINDOW);
    sendJSON(agent.ws, { type: 'file_credit', session_id: s.sid, bytes: 4 * MiB });
    await waitUntil('all bytes', () => Buffer.concat(agent.data.get(s.sid)).length === size);
    assert.ok(Buffer.concat(agent.data.get(s.sid)).equals(body));
  } finally {
    await r.close();
  }
});

test('ticket values and content never reach the logs', async () => {
  const r = await rig();
  const lines = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(orig)) console[k] = (...args) => { lines.push(args.join(' ')); };
  try {
    const agent = await connectAgent(r);
    const t = ticketFor(r);
    await failsWith(openRaw(r, { ticket: t, hostId: HOST_B }), 'ticket_invalid');
    const c = await ready(r, agent);
    c.client.ws.send('nope');
    await failsWith(c.client, 'protocol_error');
    const all = lines.join('\n');
    assert.equal(all.includes(t), false);
    assert.equal(all.includes(c.client.ticket), false);
    assert.equal(/stk_/.test(all), false);
  } finally {
    Object.assign(console, orig);
    await r.close();
  }
});
