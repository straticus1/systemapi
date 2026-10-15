'use strict';

// TCP-forward channel (docs/sah-tcp-protocol.md): client <-> FleetManager
// <-> fake agent. Every negative case of TCP §14 that lives on the server.

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
const { CLIENT_BUFFER_MAX } = require('../playground/channel');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const PUBLIC_KEY = crypto.createPublicKey(privateKeyFromSeed(TEST_SEED));
const LOCAL_PG = { host: 'local', port: 5432 };
const POLICY = { allow: [{ local: true, ports: [5432] }, { cidr: '10.0.0.0/24', ports: [3389] }] };

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
  const box = { frames: [], closeCode: null, bytes: 0, chunks: [] };
  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      const b = Buffer.from(data);
      box.frames.push({ binary: b });
      box.chunks.push(b);
      box.bytes += b.length;
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
      for (const s of fm.tcp.sessions.values()) fm.tcp.end(s, 'stopped');
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
  const box = collect(ws);
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

function ticketFor(r, { hostId = HOST_A, purpose = 'tcp:open', target = LOCAL_PG, actor = 'user-1', auth = null } = {}) {
  return issueTicket(r.fm.tickets, { hostId, purpose, tenantId: 'acme', actor, auth, target: purpose === 'tcp:open' ? target : null });
}

function openRaw(r, { ticket, hostId = HOST_A, purpose = 'tcp:open', query = '', headers = {} } = {}) {
  const t = ticket || ticketFor(r, { hostId });
  const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/tcp/${hostId}?ticket=${t}&purpose=${purpose}${query}`, { headers }));
  return { ws, box: collect(ws), ticket: t };
}

function agentFrames(agent, type) {
  return agent.box.frames.filter((f) => f.type === type);
}

function statusError(box) {
  const f = box.frames.find((x) => x.type === 'tcp_status' && x.payload && x.payload.error);
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
  ws.send(JSON.stringify(obj));
}

// Opens a stream and has the fake agent report "connected".
async function connected(r, agent, opts = {}) {
  const before = agentFrames(agent, 'tcp_open').length;
  const client = openRaw(r, opts);
  const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[before]);
  sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: opts.peer || '127.0.0.1:5432' } });
  await waitUntil('connected', () => client.box.frames.find((f) => f.type === 'tcp_status' && f.payload.status === 'connected'));
  return { client, open, sid: open.session_id };
}

function closeFrame(box) {
  return box.frames.find((f) => f.type === 'tcp_close');
}

function auditRows(r, action) {
  return r.fm.registry.audit.filter((row) => row.action === action);
}

test('tcp_open carries a target-bound signed lease; connected only after tcp_start; bytes flow both ways', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openRaw(r);
    const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[0]);
    assert.match(open.session_id, /^tcs_[A-Za-z0-9_-]{16,64}$/);
    assert.deepEqual(open.target, LOCAL_PG);
    assert.equal(open.idle_s, 900);
    assert.equal(open.max_bytes, 10 * 1024 * 1024 * 1024);
    const now = Math.floor(Date.now() / 1000);
    assert.ok(Math.abs(open.deadline_unix - (now + 28800)) <= 2);
    assert.equal(open.lease.action, 'tcp');
    assert.equal(open.lease.host_id, HOST_A);
    assert.ok(open.lease.expires_unix - now <= 61);
    const payload = tcpPayload(open.session_id, open.deadline_unix, 'start', 'local', 5432);
    assert.equal(verifyLease(PUBLIC_KEY, open.lease, payload).ok, true);
    // The lease signs the target: it cannot dial another one (TCP §14 target X -> Y).
    for (const [host, port] of [['local', 5433], ['10.0.0.7', 5432]]) {
      const other = tcpPayload(open.session_id, open.deadline_unix, 'start', host, port);
      assert.equal(verifyLease(PUBLIC_KEY, open.lease, other).error, 'payload_mismatch');
    }
    assert.deepEqual(client.box.frames[0], { type: 'tcp_status', payload: { status: 'connecting' } });
    assert.equal(auditRows(r, 'tcp_start').length, 0);

    sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } });
    const conn = await waitUntil('connected', () => client.box.frames.find((f) => f.type === 'tcp_status' && f.payload.status === 'connected'));
    assert.deepEqual(conn.payload, { status: 'connected', session_id: open.session_id, peer: '127.0.0.1:5432' });
    const start = auditRows(r, 'tcp_start');
    assert.equal(start.length, 1);
    assert.deepEqual(start[0].payload, { session_id: open.session_id, target: LOCAL_PG, peer: '127.0.0.1:5432', via: false });
    assert.equal(start[0].actor, 'user-1');

    client.ws.send(Buffer.from('SELECT 1;'));
    await waitUntil('agent got bytes', () => String(agent.data.get(open.session_id) || '') === 'SELECT 1;');
    agent.ws.send(data(open.session_id, 'row 1'));
    await waitUntil('client got bytes', () => Buffer.concat(client.box.chunks).toString() === 'row 1');

    client.ws.close();
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
    sendJSON(agent.ws, { type: 'tcp_closed', session_id: open.session_id, payload: { reason: 'stopped', bytes_in: 5, bytes_out: 9 } });
    const end = await waitUntil('tcp_end', () => auditRows(r, 'tcp_end')[0]);
    assert.equal(end.payload.reason, 'client_closed');
    assert.equal(end.payload.bytes_out, 9);
    assert.equal(end.payload.bytes_in, 5);
    assert.equal(end.payload.agent_bytes_in, 5);
    assert.equal(end.payload.agent_bytes_out, 9);
    assert.equal(end.payload.connected, true);
    assert.equal(end.payload.peer, '127.0.0.1:5432');
    // A client close sends no frame.
    assert.equal(closeFrame(client.box), undefined);
  } finally {
    await r.close();
  }
});

test('via: an IPv6 target reports [addr]:port and audits via=true', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, { policy: { allow: [{ cidr: '2001:db8::/32', ports: [22] }] } });
    const target = { host: '2001:db8::7', port: 22 };
    const c = await connected(r, agent, { ticket: ticketFor(r, { target }), peer: '[2001:db8::7]:22' });
    assert.equal(c.client.box.frames[1].payload.peer, '[2001:db8::7]:22');
    assert.equal(auditRows(r, 'tcp_start')[0].payload.via, true);
  } finally {
    await r.close();
  }
});

test('a peer other than the signed target ends the stream before connected', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const client = openRaw(r);
    const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[0]);
    sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: '10.0.0.9:5432' } });
    await failsWith(client, 'internal');
    assert.equal(auditRows(r, 'tcp_start').length, 0);
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
  } finally {
    await r.close();
  }
});

test('tickets: reused fails, host-A cannot open host B, purposes do not cross, consumed on mismatch', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    await connectAgent(r, { hostId: HOST_B });

    // Reused.
    const first = await connected(r, agent);
    const again = openRaw(r, { ticket: first.client.ticket });
    await failsWith(again, 'ticket_invalid');

    // A host-A ticket on host B, then on A: spent by the first try.
    const t = ticketFor(r);
    await failsWith(openRaw(r, { ticket: t, hostId: HOST_B }), 'ticket_invalid');
    await failsWith(openRaw(r, { ticket: t }), 'ticket_invalid');

    // A terminal:open ticket cannot open TCP, either way it is presented.
    const term = ticketFor(r, { purpose: 'terminal:open' });
    await failsWith(openRaw(r, { ticket: term }), 'ticket_invalid');
    assert.equal(r.fm.tickets.has(term), false);
    const term2 = ticketFor(r, { purpose: 'terminal:open' });
    await failsWith(openRaw(r, { ticket: term2, purpose: 'terminal:open' }), 'ticket_invalid');
    assert.equal(r.fm.tickets.has(term2), false);

    // A tcp:open ticket cannot open a terminal, and is spent there.
    const tcpT = ticketFor(r);
    const ws = r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=${tcpT}&purpose=tcp:open`));
    const box = collect(ws);
    await waitUntil('pty error', () => box.frames.find((f) => f.type === 'pty_status'));
    assert.equal(box.frames[0].payload.error, 'ticket_invalid');
    assert.equal(r.fm.tickets.has(tcpT), false);

    // Missing or malformed ticket.
    const bad = r.track(new WebSocket(`${r.base}/api/v1/systems/tcp/${HOST_A}?purpose=tcp:open`));
    const badBox = collect(bad);
    await failsWith({ box: badBox }, 'ticket_invalid');
    assert.equal(agentFrames(agent, 'tcp_open').length, 1);
  } finally {
    await r.close();
  }
});

test('upgrade rules: api_key in the query is 401, a foreign Origin 403, no Origin accepted', async () => {
  const r = await rig({ SYSTEMAPI_ALLOWED_ORIGINS: 'https://systemapi.io' });
  try {
    await connectAgent(r);
    const status = (ws) => new Promise((resolve) => {
      ws.on('unexpected-response', (req, res) => resolve(res.statusCode));
      ws.on('error', () => {});
      ws.on('open', () => resolve('open'));
    });
    const t = ticketFor(r);
    assert.equal(await status(new WebSocket(`${r.base}/api/v1/systems/tcp/${HOST_A}?ticket=${t}&purpose=tcp:open&api_key=ak_x.y`)), 401);
    assert.equal(await status(new WebSocket(`${r.base}/api/v1/systems/tcp/${HOST_A}?ticket=${t}&purpose=tcp:open`, {
      headers: { origin: 'https://evil.example' }
    })), 403);
    // Neither touched the ticket.
    assert.equal(r.fm.tickets.has(t), true);
    const ok = r.track(new WebSocket(`${r.base}/api/v1/systems/tcp/${HOST_A}?ticket=${t}&purpose=tcp:open`, {
      headers: { origin: 'https://systemapi.io' }
    }));
    const box = collect(ok);
    await waitUntil('connecting', () => box.frames.find((f) => f.type === 'tcp_status'));
    assert.equal(box.frames[0].payload.status, 'connecting');
  } finally {
    await r.close();
  }
});

test('re-check at the upgrade: empty policy, refused class, lost scope, downgraded key, revoked key', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r, { policy: null });
    // TCP §14: an empty server policy gives target_denied.
    await failsWith(openRaw(r), 'target_denied');
    await r.fm.registry.setHostChannelPolicy(HOST_A, { tcp_policy: POLICY });
    // Not in the policy.
    await failsWith(openRaw(r, { ticket: ticketFor(r, { target: { host: '10.0.0.7', port: 22 } }) }), 'target_denied');
    // TCP §14: 169.254.169.254 gives target_forbidden, even past issue.
    const meta = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', actor: 'user-1', target: { host: '169.254.169.254', port: 80 } });
    await failsWith(openRaw(r, { ticket: meta }), 'target_forbidden');
    // A loopback literal never passes (bad_target at issue; ticket_invalid here).
    const loop = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', actor: 'user-1', target: { host: '127.0.0.1', port: 5432 } });
    await failsWith(openRaw(r, { ticket: loop }), 'ticket_invalid');

    // The actor is now a viewer.
    await r.fm.registry.addMember('acme', 'user-2', 'viewer', null);
    await failsWith(openRaw(r, { ticket: ticketFor(r, { actor: 'user-2' }) }), 'scope_denied');
    // Not a member at all.
    await failsWith(openRaw(r, { ticket: ticketFor(r, { actor: 'stranger' }) }), 'scope_denied');
    // An API key whose scopes no longer include tcp:open.
    await r.fm.registry.setScopes('k9', ['hosts:read']);
    await failsWith(openRaw(r, { ticket: ticketFor(r, { auth: { kind: 'key', keyId: 'k9' } }) }), 'scope_denied');
    await r.fm.registry.setScopes('k9', ['tcp:open']);
    // A key revoked after the ticket was issued fails the upgrade re-check.
    const revokedTicket = ticketFor(r, { auth: { kind: 'key', keyId: 'k8' } });
    await r.fm.registry.setScopes('k8', ['tcp:open']);
    await r.fm.registry.revokeKey('k8');
    await failsWith(openRaw(r, { ticket: revokedTicket }), 'scope_denied');
    await connected(r, agent, { ticket: ticketFor(r, { auth: { kind: 'key', keyId: 'k9' } }) });
    assert.equal(agentFrames(agent, 'tcp_open').length, 1);
  } finally {
    await r.close();
  }
});

test('agent_offline, agent_unsupported, lease_required, cap_reached', async () => {
  const r = await rig({ SYSTEMAPI_TCP_MAX_PER_ACTOR: '1' });
  try {
    // Host enrolled, policy set, then the agent leaves.
    const gone = await connectAgent(r);
    gone.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    await failsWith(openRaw(r), 'agent_offline');

    // An agent that does not advertise tcp (an old agent sends no header).
    const old = await connectAgent(r, { caps: null });
    await failsWith(openRaw(r), 'agent_unsupported');
    old.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));
    const ptyOnly = await connectAgent(r, { caps: 'pty' });
    await failsWith(openRaw(r), 'agent_unsupported');
    ptyOnly.ws.close();
    await waitUntil('offline', () => !r.fm.connectedAgents.has(HOST_A));

    const agent = await connectAgent(r);
    await connected(r, agent);
    // Per actor cap (1 here).
    await failsWith(openRaw(r), 'cap_reached');
    // Another actor is not affected.
    await r.fm.registry.addMember('acme', 'user-1b', 'operator', null);
    await connected(r, agent, { ticket: ticketFor(r, { actor: 'user-1b' }) });

    const signerWas = r.fm.signer;
    r.fm.signer = null;
    await failsWith(openRaw(r), 'lease_required');
    r.fm.signer = signerWas;
  } finally {
    await r.close();
  }
});

test('64 streams per agent, separate from PTY slots; one actor can never fill an agent', async () => {
  const r = await rig({ SYSTEMAPI_TCP_MAX_PER_ACTOR: '63' });
  try {
    const agent = await connectAgent(r);
    await r.fm.registry.addMember('acme', 'op-1', 'operator', null);
    for (let i = 0; i < 63; i += 1) openRaw(r);
    await waitUntil('63 opens', () => agentFrames(agent, 'tcp_open').length === 63);
    // The per-actor cap is below the per-agent cap: another actor still gets a stream.
    await failsWith(openRaw(r), 'cap_reached');
    openRaw(r, { ticket: ticketFor(r, { actor: 'op-1' }) });
    await waitUntil('64 opens', () => agentFrames(agent, 'tcp_open').length === 64);
    await failsWith(openRaw(r, { ticket: ticketFor(r, { actor: 'op-1' }) }), 'cap_reached');
    // A terminal still opens.
    const ticket = issueTicket(r.fm.tickets, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme', actor: 'user-1' });
    r.track(new WebSocket(`${r.base}/api/v1/systems/terminal/${HOST_A}?ticket=${ticket}&purpose=terminal:open`));
    await waitUntil('pty_start', () => agentFrames(agent, 'pty_start').length === 1);
  } finally {
    await r.close();
  }
});

test('a per-actor TCP cap at or above the per-agent cap is refused and the default 32 applies', async () => {
  const r = await rig({ SYSTEMAPI_TCP_MAX_PER_ACTOR: '64' });
  try {
    const agent = await connectAgent(r);
    for (let i = 0; i < 32; i += 1) openRaw(r);
    await waitUntil('32 opens', () => agentFrames(agent, 'tcp_open').length === 32);
    await failsWith(openRaw(r), 'cap_reached');
  } finally {
    await r.close();
  }
});

test('agent errors map to tcp_status codes and still write tcp_end', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    for (const code of ['target_denied_agent', 'target_forbidden', 'connect_refused', 'connect_timeout', 'host_unreachable', 'bogus']) {
      const client = openRaw(r);
      const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open').find((f) => !f.seen && (f.seen = true)));
      sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { error: code } });
      await failsWith(client, code === 'bogus' ? 'internal' : code);
    }
    await waitUntil('tcp_end rows', () => auditRows(r, 'tcp_end').length === 6);
    assert.equal(auditRows(r, 'tcp_end')[0].payload.reason, 'target_denied_agent');
    assert.equal(auditRows(r, 'tcp_end')[0].payload.connected, false);
    assert.equal(auditRows(r, 'tcp_start').length, 0);
  } finally {
    await r.close();
  }
});

test('protocol_error: bytes before connected, bytes after tcp_eof, non-JSON text; 1009 for an oversized frame', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    // Before connected.
    const early = openRaw(r);
    await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open').length === 1);
    early.ws.send(Buffer.from('too soon'));
    await failsWith(early, 'protocol_error');
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);

    // After tcp_eof.
    const a = await connected(r, agent);
    sendJSON(a.client.ws, { type: 'tcp_eof' });
    a.client.ws.send(Buffer.from('late'));
    await failsWith(a.client, 'protocol_error');

    // Text that is not JSON.
    const b = await connected(r, agent);
    b.client.ws.send('not json');
    await failsWith(b.client, 'protocol_error');

    // An unknown type is ignored.
    const c = await connected(r, agent);
    sendJSON(c.client.ws, { type: 'tcp_something' });
    c.client.ws.send(Buffer.from('ok'));
    await waitUntil('bytes', () => String(agent.data.get(c.sid) || '') === 'ok');

    // 64 KiB passes; one byte more closes with 1009.
    c.client.ws.send(Buffer.alloc(64 * 1024, 1));
    await waitUntil('64 KiB', () => (agent.data.get(c.sid) || Buffer.alloc(0)).length === 2 + 64 * 1024);
    c.client.ws.send(Buffer.alloc(64 * 1024 + 1, 1));
    await waitUntil('1009', () => c.client.box.closeCode === 1009);
    const end = await waitUntil('tcp_end', () => auditRows(r, 'tcp_end').find((row) => row.payload.session_id === c.sid));
    assert.equal(end.payload.reason, 'frame_too_large');
  } finally {
    await r.close();
  }
});

test('half-close: after one FIN data still flows the other way; both FINs give tcp_close closed', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, sid } = await connected(r, agent);
    // Client FIN after its bytes: the agent sees the bytes, then tcp_eof.
    client.ws.send(Buffer.from('request'));
    sendJSON(client.ws, { type: 'tcp_eof' });
    await waitUntil('agent eof', () => agentFrames(agent, 'tcp_eof').length === 1);
    assert.equal(String(agent.data.get(sid)), 'request');
    assert.equal(agentFrames(agent, 'tcp_eof')[0].session_id, sid);
    // The target keeps sending after the client's FIN.
    agent.ws.send(data(sid, 'response part 1, '));
    agent.ws.send(data(sid, 'part 2'));
    await waitUntil('response', () => Buffer.concat(client.box.chunks).toString() === 'response part 1, part 2');
    assert.equal(closeFrame(client.box), undefined);
    // Target FIN: the client gets tcp_eof, then tcp_close closed.
    sendJSON(agent.ws, { type: 'tcp_eof', session_id: sid });
    await waitUntil('close', () => closeFrame(client.box) && client.box.closeCode === 1000);
    const types = client.box.frames.map((f) => f.type || 'bytes');
    assert.ok(types.indexOf('tcp_eof') < types.indexOf('tcp_close'));
    assert.ok(types.lastIndexOf('bytes') < types.indexOf('tcp_eof'));
    assert.deepEqual(closeFrame(client.box).payload, { session_id: sid, reason: 'closed', bytes_in: 23, bytes_out: 7 });
    sendJSON(agent.ws, { type: 'tcp_closed', session_id: sid, payload: { reason: 'closed', bytes_in: 23, bytes_out: 7 } });
    const end = await waitUntil('tcp_end', () => auditRows(r, 'tcp_end')[0]);
    assert.equal(end.payload.reason, 'closed');
    assert.equal(end.payload.agent_bytes_in, 23);
    assert.equal(agentFrames(agent, 'tcp_stop').length, 0);

    // The other order: target FIN first, client data still reaches the agent.
    const two = await connected(r, agent);
    sendJSON(agent.ws, { type: 'tcp_eof', session_id: two.sid });
    await waitUntil('client eof', () => two.client.box.frames.find((f) => f.type === 'tcp_eof'));
    two.client.ws.send(Buffer.from('still sending'));
    await waitUntil('agent bytes', () => String(agent.data.get(two.sid) || '') === 'still sending');
    // The agent reports both FINs itself: tcp_closed closed.
    sendJSON(two.client.ws, { type: 'tcp_eof' });
    await waitUntil('agent eof', () => agentFrames(agent, 'tcp_eof').length === 2);
    sendJSON(agent.ws, { type: 'tcp_closed', session_id: two.sid, payload: { reason: 'closed', bytes_in: 0, bytes_out: 13 } });
    await waitUntil('close', () => closeFrame(two.client.box));
    assert.equal(closeFrame(two.client.box).payload.reason, 'closed');
  } finally {
    await r.close();
  }
});

test('RST from the target ends the stream at once with reset', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, sid } = await connected(r, agent);
    sendJSON(agent.ws, { type: 'tcp_closed', session_id: sid, payload: { reason: 'reset', bytes_in: 0, bytes_out: 0 } });
    await waitUntil('close', () => closeFrame(client.box) && client.box.closeCode === 1000);
    assert.equal(closeFrame(client.box).payload.reason, 'reset');
  } finally {
    await r.close();
  }
});

test('idle timeout fires', async () => {
  const r = await rig({ SYSTEMAPI_TCP_IDLE_SECONDS: '1' });
  try {
    const agent = await connectAgent(r);
    const { client, sid, open } = await connected(r, agent);
    assert.equal(open.idle_s, 1);
    // Activity keeps it alive past one idle period.
    for (let i = 0; i < 4; i += 1) {
      await sleep(300);
      client.ws.send(Buffer.from('k'));
    }
    assert.equal(closeFrame(client.box), undefined);
    await waitUntil('idle close', () => closeFrame(client.box), 3000);
    assert.equal(closeFrame(client.box).payload.reason, 'idle_timeout');
    await waitUntil('close code', () => client.box.closeCode !== null);
    assert.equal(client.box.closeCode, 1000);
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').find((f) => f.session_id === sid));
    const end = await waitUntil('tcp_end', () => auditRows(r, 'tcp_end')[0]);
    assert.equal(end.payload.reason, 'idle_timeout');
  } finally {
    await r.close();
  }
});

test('byte cap fires in either direction', async () => {
  const r = await rig({ SYSTEMAPI_TCP_MAX_BYTES: '10' });
  try {
    const agent = await connectAgent(r);
    const one = await connected(r, agent);
    assert.equal(one.open.max_bytes, 10);
    one.client.ws.send(Buffer.from('123456'));
    await waitUntil('6 bytes', () => (agent.data.get(one.sid) || '').length === 6);
    agent.ws.send(data(one.sid, '1234'));
    await waitUntil('4 bytes', () => one.client.box.bytes === 4);
    assert.equal(closeFrame(one.client.box), undefined);
    one.client.ws.send(Buffer.from('x'));
    await waitUntil('cap', () => closeFrame(one.client.box));
    assert.equal(closeFrame(one.client.box).payload.reason, 'byte_cap');
    assert.equal((agent.data.get(one.sid) || '').length, 6);

    const two = await connected(r, agent);
    agent.ws.send(data(two.sid, '12345678901'));
    await waitUntil('cap', () => closeFrame(two.client.box));
    assert.equal(closeFrame(two.client.box).payload.reason, 'byte_cap');
    assert.equal(two.client.box.bytes, 0);
    await waitUntil('tcp_end rows', () => auditRows(r, 'tcp_end').length === 2);
    assert.deepEqual(auditRows(r, 'tcp_end').map((row) => row.payload.reason), ['byte_cap', 'byte_cap']);
  } finally {
    await r.close();
  }
});

test('max duration fires', async () => {
  const r = await rig({ SYSTEMAPI_TCP_MAX_SECONDS: '1' });
  try {
    const agent = await connectAgent(r);
    const { client, open } = await connected(r, agent);
    assert.ok(open.deadline_unix - Math.floor(Date.now() / 1000) <= 1);
    await waitUntil('max', () => closeFrame(client.box), 3000);
    assert.equal(closeFrame(client.box).payload.reason, 'max_duration');
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
  } finally {
    await r.close();
  }
});

test('the lease is renewed with a renew-phase, target-bound lease; start times out to internal', async () => {
  const r = await rig();
  try {
    r.fm.tcp.renewMs = 50;
    r.fm.tcp.startTimeoutMs = 300;
    const agent = await connectAgent(r);
    const client = openRaw(r);
    const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[0]);
    const renew = await waitUntil('tcp_renew', () => agentFrames(agent, 'tcp_renew')[0]);
    assert.equal(renew.session_id, open.session_id);
    const payload = tcpPayload(open.session_id, open.deadline_unix, 'renew', 'local', 5432);
    assert.equal(verifyLease(PUBLIC_KEY, renew.lease, payload).ok, true);
    assert.equal(verifyLease(PUBLIC_KEY, renew.lease, tcpPayload(open.session_id, open.deadline_unix, 'start', 'local', 5432)).ok, false);
    await failsWith(client, 'internal');
    await waitUntil('tcp_stop', () => agentFrames(agent, 'tcp_stop').length === 1);
    const end = await waitUntil('tcp_end', () => auditRows(r, 'tcp_end')[0]);
    assert.equal(end.payload.reason, 'start_timeout');
  } finally {
    await r.close();
  }
});

test('revocation reaches a live stream: the next renewal re-checks and ends it with stopped, unsigned', async () => {
  const r = await rig();
  try {
    r.fm.tcp.renewMs = 50;
    const agent = await connectAgent(r);
    const renewsFor = (sid) => agentFrames(agent, 'tcp_renew').filter((f) => f.session_id === sid).length;
    // The member is removed mid-stream.
    await r.fm.registry.addMember('acme', 'op-1', 'operator', null);
    const a = await connected(r, agent, { ticket: ticketFor(r, { actor: 'op-1' }) });
    await waitUntil('a renewed', () => renewsFor(a.sid) >= 1);
    r.fm.registry.members = r.fm.registry.members.filter((m) => m.user_id !== 'op-1');
    await waitUntil('a stopped', () => closeFrame(a.client.box));
    assert.equal(closeFrame(a.client.box).payload.reason, 'stopped');
    await waitUntil('a tcp_stop', () => agentFrames(agent, 'tcp_stop').some((f) => f.session_id === a.sid));
    // The policy is emptied mid-stream.
    const b = await connected(r, agent);
    await waitUntil('b renewed', () => renewsFor(b.sid) >= 1);
    await r.fm.registry.setHostChannelPolicy(HOST_A, { tcp_policy: { allow: [] } });
    await waitUntil('b stopped', () => closeFrame(b.client.box));
    assert.equal(closeFrame(b.client.box).payload.reason, 'stopped');
    const renewedA = renewsFor(a.sid);
    const renewedB = renewsFor(b.sid);
    await sleep(200);
    assert.equal(renewsFor(a.sid), renewedA);
    assert.equal(renewsFor(b.sid), renewedB);
    const ends = await waitUntil('ends', () => auditRows(r, 'tcp_end').length === 2 && auditRows(r, 'tcp_end'));
    assert.deepEqual(ends.map((e) => e.payload.reason), ['stopped', 'stopped']);
  } finally {
    await r.close();
  }
});

test('a failed tcp_start audit write ends the stream with internal; no byte flows', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const append = r.fm.registry.appendAudit.bind(r.fm.registry);
    r.fm.registry.appendAudit = async (entry) => {
      if (entry.action === 'tcp_start') throw new Error('db down');
      return append(entry);
    };
    const client = openRaw(r);
    const open = await waitUntil('tcp_open', () => agentFrames(agent, 'tcp_open')[0]);
    sendJSON(agent.ws, { type: 'tcp_status', session_id: open.session_id, payload: { status: 'connected', peer: '127.0.0.1:5432' } });
    agent.ws.send(data(open.session_id, 'early bytes'));
    await failsWith(client, 'internal');
    assert.equal(client.box.bytes, 0);
    assert.equal(client.box.frames.some((f) => f.payload && f.payload.status === 'connected'), false);
  } finally {
    await r.close();
  }
});

test('tcp_end is retried and a final failure is recorded', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client } = await connected(r, agent);
    let tries = 0;
    r.fm.registry.appendAudit = async (entry) => {
      if (entry.action === 'tcp_end') tries += 1;
      throw new Error('db down');
    };
    client.ws.close();
    await waitUntil('failure counted', () => r.fm.tcp.auditFailures === 1);
    assert.equal(tries, 3);
    assert.ok(r.fm.registry.securityEvents.find((e) => e.kind === 'audit_write_failed' && e.detail.action === 'tcp_end'));
  } finally {
    await r.close();
  }
});

test('agent disconnect ends its streams with agent_disconnected', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client } = await connected(r, agent);
    agent.ws.close();
    await waitUntil('close', () => closeFrame(client.box));
    assert.equal(closeFrame(client.box).payload.reason, 'agent_disconnected');
    await waitUntil('close code', () => client.box.closeCode !== null);
    assert.equal(client.box.closeCode, 1000);
  } finally {
    await r.close();
  }
});

test('an agent that overruns its credit is disconnected', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, sid } = await connected(r, agent);
    // A client that never drains: no byte goes out, no credit comes back.
    r.fm.tcp.sessions.get(sid).sink.maxBuffered = 0;
    const chunk = Buffer.alloc(64 * 1024, 7);
    for (let i = 0; i < 4; i += 1) agent.ws.send(data(sid, chunk));
    agent.ws.send(data(sid, Buffer.alloc(16, 1)));
    await waitUntil('agent terminated', () => agent.ws.readyState === WebSocket.CLOSED);
    assert.ok(r.fm.registry.securityEvents.find((e) => e.kind === 'agent_credit_violation' && e.detail.reason === 'credit_overrun'));
    await waitUntil('close', () => closeFrame(client.box));
    assert.equal(closeFrame(client.box).payload.reason, 'agent_disconnected');

    // Credit returned past what it could owe is a violation too.
    const again = await connectAgent(r, { policy: null });
    const two = await connected(r, again);
    sendJSON(again.ws, { type: 'tcp_credit', session_id: two.sid, bytes: 1 });
    await waitUntil('agent terminated', () => again.ws.readyState === WebSocket.CLOSED);
  } finally {
    await r.close();
  }
});

test('client -> agent: bytes leave only inside agent credit; the client is paused, nothing dropped', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, sid } = await connected(r, agent);
    const total = 3 * TCP_WINDOW + 12345;
    const payload = crypto.randomBytes(total);
    for (let off = 0; off < total; off += 64 * 1024) client.ws.send(payload.subarray(off, off + 64 * 1024));
    await waitUntil('one window', () => (agent.data.get(sid) || Buffer.alloc(0)).length === TCP_WINDOW);
    await sleep(200);
    // No credit back: exactly one window reached the agent, and the server
    // stopped reading the client.
    assert.equal(agent.data.get(sid).length, TCP_WINDOW);
    const s = r.fm.tcp.sessions.get(sid);
    assert.equal(s.client.isPaused, true);
    assert.ok(s.source.queuedBytes <= 1024 * 1024);
    // The agent drains and returns credit in quarters.
    let credited = 0;
    while ((agent.data.get(sid) || Buffer.alloc(0)).length < total) {
      const have = agent.data.get(sid).length;
      if (have > credited) {
        sendJSON(agent.ws, { type: 'tcp_credit', session_id: sid, bytes: have - credited });
        credited = have;
      }
      await sleep(5);
    }
    assert.ok(agent.data.get(sid).equals(payload));
    await waitUntil('resumed', () => s.client.isPaused === false);
  } finally {
    await r.close();
  }
});

test('a slow client stalls its stream without growing server memory, and gets every byte later', async () => {
  const r = await rig();
  try {
    const agent = await connectAgent(r);
    const { client, sid } = await connected(r, agent);
    // The client stops reading.
    client.ws._socket.pause();
    // A well-behaved agent: sends while it has credit, refills on tcp_credit.
    let credit = TCP_WINDOW;
    let sent = 0;
    const total = 24 * 1024 * 1024;
    const pattern = (off, n) => {
      const b = Buffer.alloc(n);
      for (let i = 0; i < n; i += 1) b[i] = (off + i) % 251;
      return b;
    };
    const pumpAgent = () => {
      while (credit > 0 && sent < total) {
        const n = Math.min(credit, 64 * 1024, total - sent);
        agent.ws.send(data(sid, pattern(sent, n)));
        sent += n;
        credit -= n;
      }
    };
    agent.ws.on('message', (m, isBinary) => {
      if (isBinary) return;
      const f = JSON.parse(m.toString());
      if (f.type === 'tcp_credit' && f.session_id === sid) {
        credit += f.bytes;
        pumpAgent();
      }
    });
    pumpAgent();
    // Let it stall: the agent stops getting credit.
    let last = -1;
    for (let i = 0; i < 100; i += 1) {
      await sleep(50);
      if (sent === last) break;
      last = sent;
    }
    await sleep(300);
    const stalledAt = sent;
    await sleep(300);
    assert.equal(sent, stalledAt, 'agent kept getting credit while the client was not reading');
    assert.ok(sent < total, 'the stream should have stalled before the end');
    const s = r.fm.tcp.sessions.get(sid);
    assert.ok(s.client.bufferedAmount <= CLIENT_BUFFER_MAX + 64 * 1024, `bufferedAmount ${s.client.bufferedAmount}`);
    assert.ok(s.sink.queuedBytes <= TCP_WINDOW, `queued ${s.sink.queuedBytes}`);
    // A paused client is still alive; other streams are unaffected.
    const other = await connected(r, agent);
    agent.ws.send(data(other.sid, 'other stream'));
    await waitUntil('other stream', () => Buffer.concat(other.client.box.chunks).toString() === 'other stream');

    // Resume: every byte arrives, in order.
    client.ws._socket.resume();
    await waitUntil('all bytes', () => client.box.bytes === total, 20000);
    const got = Buffer.concat(client.box.chunks);
    assert.ok(got.equals(pattern(0, total)));
  } finally {
    await r.close();
  }
});

test('ticket values never reach the logs', async () => {
  const r = await rig();
  const lines = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(orig)) console[k] = (...args) => { lines.push(args.join(' ')); };
  try {
    const agent = await connectAgent(r);
    const t = ticketFor(r);
    await failsWith(openRaw(r, { ticket: t, hostId: HOST_B }), 'ticket_invalid');
    const c = await connected(r, agent);
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
