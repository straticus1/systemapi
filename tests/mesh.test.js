'use strict';

// Mesh channel (docs/sah-mesh-protocol.md): sahmesh <-> FleetManager <->
// fake agent. Every negative case of MESH §14 that lives on the server, plus
// the handshake, credit, audit and session-end cases. Helpers mirror
// tests/tcp.test.js (not imported: that file must stay unchanged).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { issueTicket } = require('../controlplane/tickets');
const { verifyLease, tcpPayload } = require('../controlplane/lease');
const { TCP_WINDOW } = require('../controlplane/credit');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));
const LOCAL_PG = { host: 'local', port: 5432 };
const LOCAL_SSH = { host: 'local', port: 22 };
const POLICY = { allow: [{ local: true, ports: [22, 5432] }, { cidr: '10.0.0.0/24', ports: [3389] }] };

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

// Collects a mesh client's frames: text frames as objects, binary frames
// demultiplexed per stream id.
function collect(ws) {
  const box = { frames: [], closeCode: null, streams: new Map(), binaryErrors: 0 };
  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      const b = Buffer.from(data);
      if (b.length < 4) { box.binaryErrors += 1; return; }
      const id = b.readUInt32BE(0);
      const prev = box.streams.get(id) || Buffer.alloc(0);
      box.streams.set(id, Buffer.concat([prev, b.subarray(4)]));
      box.frames.push({ binary: id, length: b.length - 4 });
    } else {
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
  fm.tcp.finalWaitMs = 200;
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
      for (const m of [...fm.mesh.sessions.values()]) fm.mesh.endSession(m, 'stopped');
      for (const s of [...fm.tcp.sessions.values()]) fm.tcp.end(s, 'stopped');
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

async function connectAgent(r, { caps = 'pty,tcp', hostId = HOST_A, policy = POLICY } = {}) {
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
  const box = { frames: [], closeCode: null };
  ws.on('message', (data, isBinary) => { if (!isBinary) box.frames.push(JSON.parse(data.toString())); });
  ws.on('close', (code) => { box.closeCode = code; });
  ws.on('error', () => {});
  await waitUntil('enrolled', () => box.frames.find((f) => f.type === 'enrolled'));
  if (policy) await r.fm.registry.setHostChannelPolicy(hostId, { tcp_policy: policy });
  const agent = { ws, box, data: new Map() };
  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    const b = Buffer.from(data);
    const sid = b.toString('latin1', 1, 1 + b[0]);
    const prev = agent.data.get(sid) || Buffer.alloc(0);
    agent.data.set(sid, Buffer.concat([prev, b.subarray(1 + b[0])]));
  });
  return agent;
}

function meshTicket(r, { hostId = HOST_A, purpose = 'mesh:open', actor = 'user-1', auth = null, target = null } = {}) {
  return issueTicket(r.fm.tickets, { hostId, purpose, tenantId: 'acme', actor, auth, target });
}

function openRaw(r, { ticket, hostId = HOST_A, purpose = 'mesh:open', path = 'mesh', headers = {} } = {}) {
  const t = ticket || meshTicket(r, { hostId });
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/${path}/${hostId}?ticket=${t}&purpose=${purpose}`, { headers }));
  return { ws, box: collect(ws), ticket: t };
}

async function ready(r, opts = {}) {
  const c = openRaw(r, opts);
  const f = await waitUntil('mesh_ready', () => c.box.frames.find((x) => x.type === 'mesh_ready'));
  c.sessionId = f.payload.session_id;
  return c;
}

function sendJSON(ws, obj) {
  ws.send(JSON.stringify(obj));
}

function data(id, bytes) {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(id, 0);
  return Buffer.concat([head, Buffer.from(bytes)]);
}

function agentData(sid, bytes) {
  const id = Buffer.from(sid, 'latin1');
  return Buffer.concat([Buffer.from([id.length]), id, Buffer.from(bytes)]);
}

function agentFrames(agent, type) {
  return agent.box.frames.filter((f) => f.type === type);
}

function streamFrames(box, id, type) {
  return box.frames.filter((f) => f.type === type && f.stream === id);
}

function streamStatus(box, id) {
  return streamFrames(box, id, 'mesh_status');
}

function streamError(box, id) {
  const f = streamStatus(box, id).find((x) => x.payload && x.payload.error);
  return f ? f.payload.error : null;
}

function sessionError(box) {
  const f = box.frames.find((x) => x.type === 'mesh_status' && x.stream === undefined && x.payload && x.payload.error);
  return f ? f.payload.error : null;
}

function closeFrame(box, id) {
  return streamFrames(box, id, 'mesh_close')[0];
}

function endFrame(box) {
  return box.frames.find((f) => f.type === 'mesh_end');
}

function creditSum(box, id) {
  return streamFrames(box, id, 'mesh_credit').reduce((n, f) => n + f.bytes, 0);
}

async function failsWith(c, code) {
  await waitUntil(`session error ${code}`, () => sessionError(c.box) && c.box.closeCode !== null);
  assert.equal(sessionError(c.box), code);
  assert.equal(c.box.closeCode, 1011);
}

// Opens stream id on an existing mesh client and has the fake agent report
// connected. Returns the agent-side tcs_ session id.
async function openStream(r, c, agent, id, target = LOCAL_PG, peer = '127.0.0.1:5432') {
  const before = agentFrames(agent, 'tcp_open').length;
  sendJSON(c.ws, { type: 'mesh_open', stream: id, target });
  const open = await waitUntil(`tcp_open ${id}`, () => agentFrames(agent, 'tcp_open')[before]);
  sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer } });
  await waitUntil(`connected ${id}`, () => streamStatus(c.box, id).find((f) => f.payload.status === 'connected'));
  return { sid: open.session_id, open };
}

function auditRows(r, action) {
  return r.fm.registry.audit.filter((row) => row.action === action);
}

test('handshake: mesh_start before mesh_ready; a stream carries a target-bound tcp lease; rows name the mesh', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = openRaw(r);
    const readyFrame = await waitUntil('mesh_ready', () => c.box.frames.find((f) => f.type === 'mesh_ready'));
    assert.match(readyFrame.payload.session_id, /^msh_[A-Za-z0-9_-]{16,64}$/);
    assert.equal(readyFrame.payload.window, TCP_WINDOW);
    assert.equal(c.box.frames.indexOf(readyFrame), 0);
    const starts = auditRows(r, 'mesh_start');
    assert.equal(starts.length, 1);
    assert.deepEqual(starts[0].payload, { session_id: readyFrame.payload.session_id });
    assert.equal(starts[0].actor, 'user-1');
    assert.equal(starts[0].host_id, HOST_A);

    sendJSON(c.ws, { type: 'mesh_open', stream: 7, target: LOCAL_PG });
    const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[0]);
    assert.match(open.session_id, /^tcs_[A-Za-z0-9_-]{16,64}$/);
    assert.deepEqual(open.target, LOCAL_PG);
    assert.equal(open.lease.action, 'tcp');
    const payload = tcpPayload(open.session_id, open.deadline_unix, 'start', 'local', 5432);
    assert.equal(verifyLease(PUBLIC_KEY, open.lease, payload).ok, true);
    const other = tcpPayload(open.session_id, open.deadline_unix, 'start', 'local', 22);
    assert.equal(verifyLease(PUBLIC_KEY, open.lease, other).error, 'payload_mismatch');
    assert.deepEqual(streamStatus(c.box, 7)[0], { type: 'mesh_status', stream: 7, payload: { status: 'connecting' } });
    assert.equal(auditRows(r, 'tcp_start').length, 0);

    sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } });
    const conn = await waitUntil('connected', () => streamStatus(c.box, 7).find((f) => f.payload.status === 'connected'));
    assert.deepEqual(conn.payload, { status: 'connected', session_id: open.session_id, peer: '127.0.0.1:5432' });
    const start = auditRows(r, 'tcp_start');
    assert.equal(start.length, 1);
    assert.deepEqual(start[0].payload, {
      session_id: open.session_id, target: LOCAL_PG, peer: '127.0.0.1:5432', via: false,
      mesh: readyFrame.payload.session_id, stream: 7
    });

    c.ws.send(data(7, 'SELECT 1;'));
    await waitUntil('agent got bytes', () => String(agent.data.get(open.session_id) || '') === 'SELECT 1;');
    agent.ws.send(agentData(open.session_id, 'row 1'));
    await waitUntil('client got bytes', () => String(c.box.streams.get(7) || '') === 'row 1');

    // mesh_close from the client: tcp_stop to the agent, client_closed, no frame.
    sendJSON(c.ws, { type: 'mesh_close', stream: 7 });
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
    sendJSON(agent.ws, { type: 'tcp_closed', session_id: open.session_id, payload: { reason: 'stopped', bytes_in: 5, bytes_out: 9 } });
    const end = await waitUntil('tcp_end', () => auditRows(r, 'tcp_end')[0]);
    assert.equal(end.payload.reason, 'client_closed');
    assert.equal(end.payload.mesh, readyFrame.payload.session_id);
    assert.equal(end.payload.stream, 7);
    assert.equal(end.payload.bytes_out, 9);
    assert.equal(end.payload.bytes_in, 5);
    assert.equal(end.payload.agent_bytes_in, 5);
    assert.equal(closeFrame(c.box, 7), undefined);
    // The session is still up: the next id opens.
    await openStream(r, c, agent, 8, LOCAL_SSH, '127.0.0.1:22');
    assert.equal(r.fm.mesh.sessions.size, 1);
    // Nothing in the audit log carries a ticket.
    for (const row of r.fm.registry.audit) assert.equal(JSON.stringify(row).includes('stk_'), false);
  } finally {
    await r.close();
  }
});

test('two streams on one socket carry bytes both ways without mixing; half-close per stream', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    const a = await openStream(r, c, agent, 1);
    const b = await openStream(r, c, agent, 2, LOCAL_SSH, '127.0.0.1:22');
    c.ws.send(data(1, 'to-a'));
    c.ws.send(data(2, 'to-b'));
    c.ws.send(data(1, '-more'));
    await waitUntil('agent a', () => String(agent.data.get(a.sid) || '') === 'to-a-more');
    await waitUntil('agent b', () => String(agent.data.get(b.sid) || '') === 'to-b');
    agent.ws.send(agentData(b.sid, 'from-b'));
    agent.ws.send(agentData(a.sid, 'from-a'));
    await waitUntil('client a', () => String(c.box.streams.get(1) || '') === 'from-a');
    await waitUntil('client b', () => String(c.box.streams.get(2) || '') === 'from-b');

    // Client FIN on a: tcp_eof reaches the agent for a only; b still flows.
    sendJSON(c.ws, { type: 'mesh_eof', stream: 1 });
    await waitUntil('tcp_eof a', () => agentFrames(agent, 'tcp_eof').some((f) => f.session_id === a.sid));
    assert.equal(agentFrames(agent, 'tcp_eof').some((f) => f.session_id === b.sid), false);
    agent.ws.send(agentData(a.sid, '!'));
    await waitUntil('a still reads', () => String(c.box.streams.get(1) || '') === 'from-a!');
    c.ws.send(data(2, '+'));
    await waitUntil('b still writes', () => String(agent.data.get(b.sid) || '') === 'to-b+');
    // Target FIN on a: mesh_eof for a, then both seen -> mesh_close closed.
    sendJSON(agent.ws, { type: 'tcp_eof', session_id: a.sid });
    await waitUntil('mesh_eof a', () => streamFrames(c.box, 1, 'mesh_eof').length === 1);
    const closed = await waitUntil('mesh_close a', () => closeFrame(c.box, 1));
    assert.equal(closed.payload.reason, 'closed');
    assert.equal(closed.payload.session_id, a.sid);
    assert.equal(closed.payload.bytes_out, 9);
    assert.equal(closed.payload.bytes_in, 7);
    assert.equal(closeFrame(c.box, 2), undefined);
    assert.equal(c.box.closeCode, null);
    sendJSON(agent.ws, { type: 'tcp_closed', session_id: a.sid, payload: { reason: 'closed', bytes_in: 7, bytes_out: 9 } });
    const end = await waitUntil('tcp_end a', () => auditRows(r, 'tcp_end')[0]);
    assert.equal(end.payload.reason, 'closed');
    assert.equal(end.payload.stream, 1);
    // A late frame for the closed id is ignored (MESH §3.2).
    c.ws.send(data(1, 'late'));
    sendJSON(c.ws, { type: 'mesh_eof', stream: 1 });
    sendJSON(c.ws, { type: 'mesh_credit', stream: 1, bytes: 5 });
    await sleep(100);
    assert.equal(c.box.closeCode, null);
    assert.equal(sessionError(c.box), null);
    // Both FINs on b too, then the socket is still open with no streams.
    sendJSON(c.ws, { type: 'mesh_eof', stream: 2 });
    sendJSON(agent.ws, { type: 'tcp_eof', session_id: b.sid });
    await waitUntil('mesh_close b', () => closeFrame(c.box, 2));
    assert.equal(r.fm.tcp.sessions.size, 0);
    assert.equal(r.fm.mesh.sessions.size, 1);
  } finally {
    await r.close();
  }
});

test('a stream denied by policy, a bad target or a refused class fails alone; the other stream keeps flowing', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    const a = await openStream(r, c, agent, 1);
    sendJSON(c.ws, { type: 'mesh_open', stream: 2, target: { host: 'local', port: 80 } });
    await waitUntil('denied', () => streamError(c.box, 2) === 'target_denied');
    sendJSON(c.ws, { type: 'mesh_open', stream: 3, target: { host: '169.254.169.254', port: 80 } });
    await waitUntil('forbidden', () => streamError(c.box, 3) === 'target_forbidden');
    sendJSON(c.ws, { type: 'mesh_open', stream: 4, target: { host: 'db.internal', port: 80 } });
    await waitUntil('bad_target', () => streamError(c.box, 4) === 'bad_target');
    sendJSON(c.ws, { type: 'mesh_open', stream: 5, target: { host: '127.0.0.1', port: 5432 } });
    await waitUntil('loopback literal', () => streamError(c.box, 5) === 'bad_target');
    sendJSON(c.ws, { type: 'mesh_open', stream: 6, target: { host: '10.0.0.7', port: 22 } });
    await waitUntil('not in policy', () => streamError(c.box, 6) === 'target_denied');
    // The first stream still flows.
    c.ws.send(data(1, 'still'));
    await waitUntil('a flows', () => String(agent.data.get(a.sid) || '') === 'still');
    // Only one tcp_open ever reached the agent.
    assert.equal(agentFrames(agent, 'tcp_open').length, 1);
    assert.equal(c.box.closeCode, null);
    // A failed id is spent: it cannot be opened again.
    sendJSON(c.ws, { type: 'mesh_open', stream: 6, target: LOCAL_SSH });
    await failsWith(c, 'protocol_error');
  } finally {
    await r.close();
  }
});

test('stream ids: equal or lower is protocol_error, every live stream ends with protocol_error, mesh_end row', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    const a = await openStream(r, c, agent, 10);
    const b = await openStream(r, c, agent, 11, LOCAL_SSH, '127.0.0.1:22');
    sendJSON(c.ws, { type: 'mesh_open', stream: 5, target: LOCAL_PG });
    await failsWith(c, 'protocol_error');
    // The streams got mesh_close protocol_error before the session error.
    for (const id of [10, 11]) assert.equal(closeFrame(c.box, id).payload.reason, 'protocol_error');
    const errIdx = c.box.frames.findIndex((f) => f.type === 'mesh_status' && f.stream === undefined);
    assert.ok(c.box.frames.findIndex((f) => f.type === 'mesh_close' && f.stream === 11) < errIdx);
    await waitUntil('tcp_stop x2', () => agentFrames(agent, 'tcp_stop').length === 2);
    for (const sid of [a.sid, b.sid]) {
      sendJSON(agent.ws, { type: 'tcp_closed', session_id: sid, payload: { reason: 'stopped', bytes_in: 0, bytes_out: 0 } });
    }
    const ends = await waitUntil('tcp_end x2', () => auditRows(r, 'tcp_end').length === 2 && auditRows(r, 'tcp_end'));
    assert.deepEqual(ends.map((e) => e.payload.reason), ['protocol_error', 'protocol_error']);
    const meshEnd = await waitUntil('mesh_end row', () => auditRows(r, 'mesh_end')[0]);
    assert.equal(meshEnd.payload.session_id, c.sessionId);
    assert.equal(meshEnd.payload.reason, 'protocol_error');
    // The refused mesh_open (id 5) is not an opened stream.
    assert.equal(meshEnd.payload.streams, 2);
    assert.equal(typeof meshEnd.payload.duration_s, 'number');
    assert.equal(r.fm.mesh.sessions.size, 0);
    assert.equal(r.fm.tcp.sessions.size, 0);
  } finally {
    await r.close();
  }
});

test('framing: a never-opened id, bytes before connected, a short frame, non-JSON text, a frame before mesh_ready', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    // A binary frame for an id above the last opened one.
    let c = await ready(r);
    await openStream(r, c, agent, 1);
    c.ws.send(data(2, 'x'));
    await failsWith(c, 'protocol_error');
    // Bytes before connected.
    c = await ready(r);
    sendJSON(c.ws, { type: 'mesh_open', stream: 1, target: LOCAL_PG });
    await waitUntil('connecting', () => streamStatus(c.box, 1).length === 1);
    c.ws.send(data(1, 'early'));
    await failsWith(c, 'protocol_error');
    // A binary frame shorter than the header; a zero id.
    c = await ready(r);
    c.ws.send(Buffer.from([0, 0, 1]));
    await failsWith(c, 'protocol_error');
    c = await ready(r);
    c.ws.send(data(0, 'x'));
    await failsWith(c, 'protocol_error');
    // Text that is not a JSON object.
    c = await ready(r);
    c.ws.send('not json');
    await failsWith(c, 'protocol_error');
    c = await ready(r);
    c.ws.send('[1,2]');
    await failsWith(c, 'protocol_error');
    // Bytes after the client's own mesh_eof.
    c = await ready(r);
    await openStream(r, c, agent, 1);
    sendJSON(c.ws, { type: 'mesh_eof', stream: 1 });
    c.ws.send(data(1, 'after-eof'));
    await failsWith(c, 'protocol_error');
    // An unknown type is ignored.
    c = await ready(r);
    sendJSON(c.ws, { type: 'mesh_ping' });
    await sleep(100);
    assert.equal(c.box.closeCode, null);
    // A frame before mesh_ready: hold the upgrade re-check so the frame
    // certainly arrives during setup.
    const fast = r.fm.registry.membershipsForUser.bind(r.fm.registry);
    r.fm.registry.membershipsForUser = async (u) => { await sleep(150); return fast(u); };
    const early = openRaw(r);
    early.ws.on('open', () => sendJSON(early.ws, { type: 'mesh_open', stream: 1, target: LOCAL_PG }));
    await waitUntil('closed', () => early.box.closeCode !== null);
    assert.equal(early.box.closeCode, 1011);
    assert.equal(sessionError(early.box), 'protocol_error');
    assert.equal(early.box.frames.some((f) => f.type === 'mesh_ready'), false);
    r.fm.registry.membershipsForUser = fast;
    // The agent was asked to open exactly the streams that were valid: 1 + 1 + 1.
    assert.equal(agentFrames(agent, 'tcp_open').length, 3);
  } finally {
    await r.close();
  }
});

test('oversized frame closes with 1009 and the stream is audited frame_too_large', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    const a = await openStream(r, c, agent, 1);
    c.ws.send(data(1, Buffer.alloc(64 * 1024 + 1)));
    await waitUntil('1009', () => c.box.closeCode === 1009);
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
    sendJSON(agent.ws, { type: 'tcp_closed', session_id: a.sid, payload: { reason: 'stopped', bytes_in: 0, bytes_out: 0 } });
    const end = await waitUntil('tcp_end', () => auditRows(r, 'tcp_end')[0]);
    assert.equal(end.payload.reason, 'frame_too_large');
    const meshEnd = await waitUntil('mesh_end', () => auditRows(r, 'mesh_end')[0]);
    assert.equal(meshEnd.payload.reason, 'frame_too_large');
    // Exactly 64 KiB of payload is fine.
    const c2 = await ready(r);
    const b = await openStream(r, c2, agent, 1);
    c2.ws.send(data(1, Buffer.alloc(64 * 1024, 1)));
    await waitUntil('64k arrived', () => (agent.data.get(b.sid) || Buffer.alloc(0)).length === 64 * 1024);
    assert.equal(c2.box.closeCode, null);
  } finally {
    await r.close();
  }
});

test('tickets: reused, host-A on host B, tcp:open on the mesh path and the reverse, agent_offline, agent_unsupported, session cap', async () => {
  const r = await rig({ SYSTEMAPI_MESH_MAX_PER_ACTOR: '1' });
  try {
    const agent = await connectAgent(r);
    await connectAgent(r, { hostId: HOST_B });
    const c = await ready(r);
    // Reused.
    await failsWith(openRaw(r, { ticket: c.ticket }), 'ticket_invalid');
    // Host A ticket cannot open host B; it is consumed anyway.
    const crossed = meshTicket(r);
    await failsWith(openRaw(r, { ticket: crossed, hostId: HOST_B }), 'ticket_invalid');
    await failsWith(openRaw(r, { ticket: crossed }), 'ticket_invalid');
    // A tcp:open ticket cannot open a mesh socket, under either purpose string.
    await failsWith(openRaw(r, { ticket: meshTicket(r, { purpose: 'tcp:open', target: LOCAL_PG }), purpose: 'tcp:open' }), 'ticket_invalid');
    await failsWith(openRaw(r, { ticket: meshTicket(r, { purpose: 'tcp:open', target: LOCAL_PG }) }), 'ticket_invalid');
    // A mesh ticket cannot open a tcp socket (the tcp handler answers).
    const onTcp = openRaw(r, { ticket: meshTicket(r), path: 'tcp' });
    await waitUntil('tcp refused', () => onTcp.box.closeCode === 1011);
    assert.equal(onTcp.box.frames[0].payload.error, 'ticket_invalid');
    // A second session for the same actor is over SYSTEMAPI_MESH_MAX_PER_ACTOR=1.
    await failsWith(openRaw(r), 'cap_reached');
    // Another actor is fine.
    await r.fm.registry.addMember('acme', 'op-1', 'operator', null);
    const c2 = await ready(r, { ticket: meshTicket(r, { actor: 'op-1' }) });
    assert.notEqual(c2.sessionId, c.sessionId);
    // agent_offline, then agent_unsupported for an agent without tcp.
    await r.fm.registry.addMember('acme', 'op-2', 'operator', null);
    agent.ws.close();
    await waitUntil('agent gone', () => !r.fm.connectedAgents.has(HOST_A));
    await failsWith(openRaw(r, { ticket: meshTicket(r, { actor: 'op-2' }) }), 'agent_offline');
    await connectAgent(r, { caps: 'pty' });
    await failsWith(openRaw(r, { ticket: meshTicket(r, { actor: 'op-2' }) }), 'agent_unsupported');
  } finally {
    await r.close();
  }
});

test('scopes: tcp:open alone is scope_denied at the upgrade; mesh:open alone opens a mesh; a lost scope ends the session at the re-check', async () => {
  const r = await rig();
  try {
    r.fm.mesh.recheckMs = 50;
    r.fm.tcp.renewMs = 50;
    const agent = await connectAgent(r);
    await r.fm.registry.addMember('acme', 'viewer', 'viewer', null);
    await failsWith(openRaw(r, { ticket: meshTicket(r, { actor: 'viewer' }) }), 'scope_denied');
    await failsWith(openRaw(r, { ticket: meshTicket(r, { actor: 'stranger' }) }), 'scope_denied');
    // An API key with tcp:open but not mesh:open.
    await r.fm.registry.setScopes('k9', ['tcp:open']);
    await failsWith(openRaw(r, { ticket: meshTicket(r, { auth: { kind: 'key', keyId: 'k9' } }) }), 'scope_denied');
    // A key with mesh:open only opens a mesh and its streams.
    await r.fm.registry.setScopes('k9', ['mesh:open']);
    const c = await ready(r, { ticket: meshTicket(r, { auth: { kind: 'key', keyId: 'k9' } }) });
    const a = await openStream(r, c, agent, 1);
    await waitUntil('renewed', () => agentFrames(agent, 'tcp_renew').some((f) => f.session_id === a.sid));
    // The key loses mesh:open mid-session: every stream stops, then mesh_end stopped.
    await r.fm.registry.setScopes('k9', ['tcp:open']);
    await waitUntil('stream stopped', () => closeFrame(c.box, 1));
    assert.equal(closeFrame(c.box, 1).payload.reason, 'stopped');
    await waitUntil('mesh_end', () => endFrame(c.box) && c.box.closeCode === 1000);
    assert.deepEqual(endFrame(c.box).payload, { session_id: c.sessionId, reason: 'stopped', streams: 1 });
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').some((f) => f.session_id === a.sid));
    const row = await waitUntil('mesh_end row', () => auditRows(r, 'mesh_end')[0]);
    assert.equal(row.payload.reason, 'stopped');
    // A member removed mid-session: same path, no key involved.
    await r.fm.registry.addMember('acme', 'op-1', 'operator', null);
    const c2 = await ready(r, { ticket: meshTicket(r, { actor: 'op-1' }) });
    r.fm.registry.members = r.fm.registry.members.filter((m) => m.user_id !== 'op-1');
    await waitUntil('mesh_end 2', () => endFrame(c2.box));
    assert.equal(endFrame(c2.box).payload.reason, 'stopped');
  } finally {
    await r.close();
  }
});

test('credit toward the client: the server stops at the window until mesh_credit; bad credit ends the session', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    const a = await openStream(r, c, agent, 1);
    // The agent may send a full 256 KiB window; the server forwards exactly
    // that much and holds the rest.
    const chunk = Buffer.alloc(64 * 1024, 7);
    for (let i = 0; i < 4; i++) agent.ws.send(agentData(a.sid, chunk));
    await waitUntil('window delivered', () => (c.box.streams.get(1) || Buffer.alloc(0)).length === TCP_WINDOW);
    // Agent credit came back for the forwarded bytes, so the agent may send more.
    await waitUntil('agent credit', () => agentFrames(agent, 'tcp_credit').reduce((n, f) => n + f.bytes, 0) >= TCP_WINDOW);
    agent.ws.send(agentData(a.sid, Buffer.alloc(1000, 8)));
    await sleep(150);
    assert.equal((c.box.streams.get(1) || Buffer.alloc(0)).length, TCP_WINDOW);
    assert.equal(c.box.closeCode, null);
    // Returning credit releases the held bytes.
    sendJSON(c.ws, { type: 'mesh_credit', stream: 1, bytes: 1000 });
    await waitUntil('released', () => (c.box.streams.get(1) || Buffer.alloc(0)).length === TCP_WINDOW + 1000);
    assert.equal(c.box.streams.get(1)[TCP_WINDOW], 8);
    // Credit past what the server could owe is a violation (the server
    // holds exactly a window of outstanding credit at most).
    sendJSON(c.ws, { type: 'mesh_credit', stream: 1, bytes: TCP_WINDOW + 1 });
    await failsWith(c, 'protocol_error');
    // Malformed credit too.
    const c2 = await ready(r);
    await openStream(r, c2, agent, 1);
    sendJSON(c2.ws, { type: 'mesh_credit', stream: 1, bytes: -1 });
    await failsWith(c2, 'protocol_error');
  } finally {
    await r.close();
  }
});

test('credit from the client: bytes past the window end the session; credit returns as bytes reach the agent', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    const a = await openStream(r, c, agent, 1);
    const chunk = Buffer.alloc(64 * 1024, 3);
    for (let i = 0; i < 4; i++) c.ws.send(data(1, chunk));
    await waitUntil('agent got window', () => (agent.data.get(a.sid) || Buffer.alloc(0)).length === TCP_WINDOW);
    // Everything the server forwarded is credited back to the client.
    await waitUntil('client credit', () => creditSum(c.box, 1) >= TCP_WINDOW);
    assert.equal(creditSum(c.box, 1), TCP_WINDOW);
    // The fake agent returns no credit, so the agent window is now full:
    // the next 256 KiB queue at the server and no client credit comes back.
    for (let i = 0; i < 4; i++) c.ws.send(data(1, chunk));
    await sleep(150);
    assert.equal(creditSum(c.box, 1), TCP_WINDOW);
    assert.equal((agent.data.get(a.sid) || Buffer.alloc(0)).length, TCP_WINDOW);
    assert.equal(c.box.closeCode, null);
    // One byte past the window is a violation.
    c.ws.send(data(1, 'x'));
    await failsWith(c, 'protocol_error');
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
    // A fresh session that ignores credit entirely is cut once the agent
    // window (forwarded) plus the client window (queued) are both full.
    const c2 = await ready(r);
    const b = await openStream(r, c2, agent, 1);
    for (let i = 0; i < 9; i++) c2.ws.send(data(1, chunk));
    await failsWith(c2, 'protocol_error');
    assert.ok((agent.data.get(b.sid) || Buffer.alloc(0)).length <= TCP_WINDOW);
  } finally {
    await r.close();
  }
});

test('caps are shared with tcp:open sessions', async () => {
  const r = await rig({ SYSTEMAPI_TCP_MAX_PER_ACTOR: '2' });
  try {
    const agent = await connectAgent(r);
    // One plain tcp:open session for user-1.
    const t = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', actor: 'user-1', target: LOCAL_PG });
    const tcpClient = r.track(new WebSocket(`${r.base}/api/v1/systems/tcp/${HOST_A}?ticket=${t}&purpose=tcp:open`));
    const tcpBox = collect(tcpClient);
    const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[0]);
    sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } });
    await waitUntil('tcp connected', () => tcpBox.frames.find((f) => f.type === 'tcp_status' && f.payload.status === 'connected'));
    // One mesh stream: the actor is now at 2 of 2.
    const c = await ready(r);
    await openStream(r, c, agent, 1);
    sendJSON(c.ws, { type: 'mesh_open', stream: 2, target: LOCAL_SSH });
    await waitUntil('cap', () => streamError(c.box, 2) === 'cap_reached');
    // And a new tcp:open is refused too.
    const t2 = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', actor: 'user-1', target: LOCAL_PG });
    const tcp2 = r.track(new WebSocket(`${r.base}/api/v1/systems/tcp/${HOST_A}?ticket=${t2}&purpose=tcp:open`));
    const box2 = collect(tcp2);
    await waitUntil('tcp cap', () => box2.closeCode === 1011);
    assert.equal(box2.frames[0].payload.error, 'cap_reached');
    assert.equal(agentFrames(agent, 'tcp_open').length, 2);
    // Closing the mesh stream frees a slot.
    sendJSON(c.ws, { type: 'mesh_close', stream: 1 });
    await waitUntil('freed', () => r.fm.tcp.sessions.size === 1);
    await openStream(r, c, agent, 3, LOCAL_SSH, '127.0.0.1:22');
  } finally {
    await r.close();
  }
});

test('session idle timeout fires only with no live stream; agent gone; client close', async () => {
  const r = await rig({ SYSTEMAPI_MESH_IDLE_SECONDS: '1' });
  try {
    const agent = await connectAgent(r);
    // Idle with no stream: mesh_end idle_timeout within ~1 s.
    const idle = await ready(r);
    await waitUntil('idle end', () => endFrame(idle.box) && idle.box.closeCode === 1000, 3000);
    assert.deepEqual(endFrame(idle.box).payload, { session_id: idle.sessionId, reason: 'idle_timeout', streams: 0 });
    // Not idle while a stream lives.
    const busy = await ready(r);
    await openStream(r, busy, agent, 1);
    await sleep(1300);
    assert.equal(endFrame(busy.box), undefined);
    assert.equal(busy.box.closeCode, null);
    // Agent gone: the stream closes agent_disconnected, then mesh_end agent_disconnected.
    agent.ws.close();
    await waitUntil('stream agent_disconnected', () => closeFrame(busy.box, 1));
    assert.equal(closeFrame(busy.box, 1).payload.reason, 'agent_disconnected');
    await waitUntil('mesh_end', () => endFrame(busy.box) && busy.box.closeCode === 1000);
    assert.equal(endFrame(busy.box).payload.reason, 'agent_disconnected');
    // Client close: every stream client_closed, mesh_end row client_closed, no frames needed.
    const agent2 = await connectAgent(r);
    const c = await ready(r);
    const b = await openStream(r, c, agent2, 1);
    const d = await openStream(r, c, agent2, 2, LOCAL_SSH, '127.0.0.1:22');
    c.ws.close();
    await waitUntil('tcp_stop x2', () => agentFrames(agent2, 'tcp_stop').length === 2);
    for (const sid of [b.sid, d.sid]) sendJSON(agent2.ws, { type: 'tcp_closed', session_id: sid, payload: { reason: 'stopped', bytes_in: 0, bytes_out: 0 } });
    const mine = () => auditRows(r, 'tcp_end').filter((e) => e.payload.mesh === c.sessionId);
    const ends = await waitUntil('tcp_end x2', () => mine().length === 2 && mine());
    assert.deepEqual(ends.map((e) => e.payload.reason), ['client_closed', 'client_closed']);
    const meshEnd = await waitUntil('mesh_end row', () => auditRows(r, 'mesh_end').find((e) => e.payload.session_id === c.sessionId));
    assert.equal(meshEnd.payload.reason, 'client_closed');
    assert.equal(meshEnd.payload.streams, 2);
    assert.equal((await r.fm.registry.verifyAudit()).ok, true);
  } finally {
    await r.close();
  }
});

test('max duration ends the session and its streams', async () => {
  const r = await rig({ SYSTEMAPI_MESH_MAX_SECONDS: '1' });
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    await openStream(r, c, agent, 1);
    await waitUntil('max', () => endFrame(c.box) && c.box.closeCode === 1000, 3000);
    assert.equal(endFrame(c.box).payload.reason, 'max_duration');
    assert.equal(closeFrame(c.box, 1).payload.reason, 'max_duration');
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
  } finally {
    await r.close();
  }
});

test('a mesh_close before connected abandons the pending stream; a mesh_eof before connected is honoured after', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const c = await ready(r);
    // Policy lookups are async; abandon while pending.
    const slow = r.fm.registry.channelPolicies.bind(r.fm.registry);
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    r.fm.registry.channelPolicies = async (hostId) => { await gate; return slow(hostId); };
    sendJSON(c.ws, { type: 'mesh_open', stream: 1, target: LOCAL_PG });
    sendJSON(c.ws, { type: 'mesh_close', stream: 1 });
    await sleep(50);
    release();
    await sleep(100);
    assert.equal(agentFrames(agent, 'tcp_open').length, 0);
    assert.equal(r.fm.mesh.sessions.get(c.sessionId).streams.size, 0);
    r.fm.registry.channelPolicies = slow;
    // mesh_eof before connected: tcp_eof follows connected.
    sendJSON(c.ws, { type: 'mesh_open', stream: 2, target: LOCAL_PG });
    sendJSON(c.ws, { type: 'mesh_eof', stream: 2 });
    const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[0]);
    assert.equal(agentFrames(agent, 'tcp_eof').length, 0);
    sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } });
    await waitUntil('tcp_eof', () => agentFrames(agent, 'tcp_eof').some((f) => f.session_id === open.session_id));
  } finally {
    await r.close();
  }
});
