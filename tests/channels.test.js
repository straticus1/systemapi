'use strict';

// SAH channels phase 0, stage 1: target/root validation, server policy,
// ticket binding, scopes and ws-ticket issue for tcp:open and file:*.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');
const { issueTicket, consumeTicket } = require('../controlplane/tickets');
const { scopesForRole, OPERATOR } = require('../controlplane/authz');
const ch = require('../controlplane/channels');

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

test('tcp target: shapes, normalization, loopback and DNS names', () => {
  const ok = (t) => {
    const r = ch.validateTcpTarget(t);
    assert.equal(r.ok, true, JSON.stringify(t));
    return r.target;
  };
  const err = (t) => ch.validateTcpTarget(t).error;
  assert.deepEqual(ok({ host: 'local', port: 5432 }), { host: 'local', port: 5432 });
  assert.deepEqual(ok({ host: '10.0.0.7', port: 3389 }), { host: '10.0.0.7', port: 3389 });
  assert.deepEqual(ok({ host: '2001:DB8:0:0:0:0:0:1', port: 22 }), { host: '2001:db8::1', port: 22 });
  assert.deepEqual(ok({ host: '2001:db8:0:1:0:0:0:0', port: 22 }), { host: '2001:db8:0:1::', port: 22 });
  assert.deepEqual(ok({ host: '::ffff:10.0.0.7', port: 80 }), { host: '10.0.0.7', port: 80 });
  assert.deepEqual(ok({ host: '::ffff:a00:7', port: 80 }), { host: '10.0.0.7', port: 80 });
  assert.deepEqual(ok({ host: '2001:db8::1:0:0:1', port: 1 }), { host: '2001:db8::1:0:0:1', port: 1 });
  assert.deepEqual(ok({ host: '10.0.0.7', port: 65535 }), { host: '10.0.0.7', port: 65535 });

  // TCP §14: 127.0.0.1 gives bad_target; a DNS name gives bad_target.
  for (const host of ['127.0.0.1', '127.9.9.9', '::1', '::ffff:127.0.0.1', '0:0:0:0:0:0:0:1']) {
    assert.equal(err({ host, port: 22 }), 'bad_target', host);
  }
  for (const host of ['db.internal', 'localhost', 'LOCAL', '[::1]', 'fe80::1%eth0', '[2001:db8::1]', '10.0.0.07',
    '10.0.0', '10.0.0.256', '1.2.3.4.5', '', ' 10.0.0.7', '2001:db8::1::2', ':::', '1:2:3:4:5:6:7:8:9', '0x7f.0.0.1']) {
    assert.equal(err({ host, port: 22 }), 'bad_target', host);
  }
  for (const port of [0, 65536, -1, 22.5, '22', null, undefined]) {
    assert.equal(err({ host: '10.0.0.7', port }), 'bad_target', String(port));
  }
  for (const target of [null, undefined, 'local:22', [], { port: 22 }]) {
    assert.equal(err(target), 'bad_target');
  }
});

test('tcp target: always-refused classes give target_forbidden', () => {
  // TCP §14: 169.254.169.254 gives target_forbidden.
  for (const host of ['169.254.169.254', '0.0.0.0', '0.1.2.3', '224.0.0.1', '239.255.255.250', '255.255.255.255',
    '240.0.0.1', '100.100.100.200', '::', 'fe80::1', 'febf::1', 'ff02::1', 'fd00:ec2::254',
    '::ffff:169.254.169.254', '::ffff:0.0.0.0']) {
    assert.equal(ch.validateTcpTarget({ host, port: 80 }).error, 'target_forbidden', host);
  }
  for (const host of ['100.100.100.201', '169.255.0.1', 'fec0::1', 'fd00:ec2::253', '223.255.255.255']) {
    assert.equal(ch.validateTcpTarget({ host, port: 80 }).ok, true, host);
  }
});

test('tcp policy: deny by default, local vs CIDR, port ranges, malformed denies', () => {
  const check = (policy, host, port) => ch.tcpPolicyAllows(ch.parseTcpPolicy(policy), ch.validateTcpTarget({ host, port }));
  // TCP §14: an empty server policy gives target_denied.
  assert.equal(check(undefined, 'local', 5432), false);
  assert.equal(check({ allow: [] }, 'local', 5432), false);
  const policy = { allow: [{ local: true, ports: [5432] }, { cidr: '10.0.0.0/24', ports: [3389, '8000-8099'] }, { cidr: '2001:db8::/32', ports: [22] }] };
  assert.equal(check(policy, 'local', 5432), true);
  assert.equal(check(policy, 'local', 3389), false);
  assert.equal(check(policy, '10.0.0.7', 3389), true);
  assert.equal(check(policy, '10.0.0.7', 8050), true);
  assert.equal(check(policy, '10.0.0.7', 8100), false);
  assert.equal(check(policy, '10.0.1.7', 3389), false);
  assert.equal(check(policy, '::ffff:10.0.0.9', 3389), true);
  assert.equal(check(policy, '2001:db8:1::5', 22), true);
  assert.equal(check(policy, '2001:db9::5', 22), false);
  // A CIDR entry never matches "local".
  assert.equal(check({ allow: [{ cidr: '0.0.0.0/0', ports: ['1-65535'] }] }, 'local', 22), false);
  assert.equal(check({ allow: [{ cidr: '0.0.0.0/0', ports: ['1-65535'] }] }, '8.8.8.8', 53), true);
  // Mapped CIDR is normalized to IPv4.
  assert.equal(check({ allow: [{ cidr: '::ffff:10.0.0.0/120', ports: [80] }] }, '10.0.0.4', 80), true);
  for (const bad of [[], 'x', { allow: 'x' }, { allow: [{ ports: [1] }] }, { allow: [{ local: true, cidr: '10.0.0.0/8', ports: [1] }] },
    { allow: [{ local: false, ports: [1] }] }, { allow: [{ local: true, ports: [] }] }, { allow: [{ local: true, ports: [0] }] },
    { allow: [{ local: true, ports: ['9-1'] }] }, { allow: [{ local: true, ports: ['1-70000'] }] }, { allow: [{ cidr: '10.0.0.0/33', ports: [1] }] },
    { allow: [{ cidr: 'example.com/8', ports: [1] }] }, { allow: [{ cidr: '10.0.0.0', ports: [1] }] }]) {
    assert.equal(ch.parseTcpPolicy(bad), null, JSON.stringify(bad));
    assert.equal(ch.tcpPolicyAllows(ch.parseTcpPolicy(bad), ch.validateTcpTarget({ host: 'local', port: 1 })), false);
  }
});

test('file root: shape rules and "~"', () => {
  for (const root of ['/', '/srv/app', '/srv/app.d/x', '/srv/%2e%2e', '/srv/ünïcode']) {
    assert.deepEqual(ch.validateFileRoot(root, 'file:read'), { ok: true, root });
  }
  assert.deepEqual(ch.validateFileRoot('~', 'file:write'), { ok: true, root: '~' });
  assert.equal(ch.validateFileRoot('~', 'file:root').error, 'bad_root');
  for (const root of ['', 'srv', 'srv/app', '/srv/', '/srv//app', '/srv/./app', '/srv/..', '/..', '/.', '/srv/a\u0000b',
    '/srv/a\nb', '/srv/a\u007fb', '~/x', '~user', '/' + 'a'.repeat(4096), '/srv/\ud800', null, 7, ['/srv']]) {
    assert.equal(ch.validateFileRoot(root, 'file:read').error, 'bad_root', JSON.stringify(root));
  }
});

test('file policy: component boundary, mode and root flag, deny by default', () => {
  const allows = (policy, purpose, root) => ch.filePolicyAllows(ch.parseFilePolicy(policy), purpose, root);
  assert.equal(allows(undefined, 'file:read', '/srv/app'), false);
  assert.equal(allows({ roots: [] }, 'file:read', '/srv/app'), false);
  const p = { roots: [{ path: '/srv/app', read: true, write: true }, { path: '/var/log', read: true }, { path: '/etc', read: true, write: true, root: true }, { path: '~', read: true }] };
  assert.equal(allows(p, 'file:read', '/srv/app'), true);
  assert.equal(allows(p, 'file:write', '/srv/app/sub'), true);
  // FILE §14: a ticket for root /srv/a cannot reach /srv/b (boundary).
  assert.equal(allows(p, 'file:read', '/srv/application'), false);
  assert.equal(allows(p, 'file:read', '/srv'), false);
  assert.equal(allows(p, 'file:read', '/var/log/nginx'), true);
  assert.equal(allows(p, 'file:write', '/var/log'), false);
  assert.equal(allows(p, 'file:root', '/srv/app'), false);
  assert.equal(allows(p, 'file:root', '/etc/ssh'), true);
  assert.equal(allows(p, 'file:read', '~'), true);
  assert.equal(allows(p, 'file:write', '~'), false);
  assert.equal(allows({ roots: [{ path: '/', read: true }] }, 'file:read', '/anything/below'), true);
  assert.equal(allows({ roots: [{ path: '/', read: true }] }, 'file:read', '~'), false);
  for (const bad of [{ roots: 'x' }, { roots: [{ path: 'srv', read: true }] }, { roots: [{ path: '/srv/', read: true }] },
    { roots: [{ path: '/srv', read: 'yes' }] }, [], 'x']) {
    assert.equal(ch.parseFilePolicy(bad), null, JSON.stringify(bad));
  }
});

test('tickets are bound to target / root; a channel ticket without a binding is refused', () => {
  const store = new Map();
  const t = issueTicket(store, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', target: { host: '10.0.0.7', port: 3389 } });
  // TCP §14: a target-X ticket cannot dial target Y.
  assert.equal(consumeTicket(store, t, HOST_A, 'tcp:open', Date.now(), { target: { host: '10.0.0.8', port: 3389 } }), null);
  assert.equal(store.has(t), false, 'consumed even on mismatch');
  const t2 = issueTicket(store, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', target: { host: '10.0.0.7', port: 3389 } });
  const row = consumeTicket(store, t2, HOST_A, 'tcp:open', Date.now(), { target: { host: '10.0.0.7', port: 3389 } });
  assert.deepEqual(row.target, { host: '10.0.0.7', port: 3389 });
  // TCP §14: a reused ticket fails.
  assert.equal(consumeTicket(store, t2, HOST_A, 'tcp:open'), null);
  // A host-A ticket cannot open host B; terminal and TCP tickets do not cross.
  const t3 = issueTicket(store, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', target: { host: 'local', port: 22 } });
  assert.equal(consumeTicket(store, t3, HOST_B, 'tcp:open'), null);
  const t4 = issueTicket(store, { hostId: HOST_A, purpose: 'terminal:open', tenantId: 'acme' });
  assert.equal(consumeTicket(store, t4, HOST_A, 'tcp:open'), null);
  const t5 = issueTicket(store, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', target: { host: 'local', port: 22 } });
  assert.equal(consumeTicket(store, t5, HOST_A, 'terminal:open'), null);
  // No binding stored: refused.
  const t6 = issueTicket(store, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme' });
  assert.equal(consumeTicket(store, t6, HOST_A, 'tcp:open'), null);
  const t7 = issueTicket(store, { hostId: HOST_A, purpose: 'file:read', tenantId: 'acme' });
  assert.equal(consumeTicket(store, t7, HOST_A, 'file:read'), null);

  const f = issueTicket(store, { hostId: HOST_A, purpose: 'file:read', tenantId: 'acme', root: '/srv/a' });
  assert.equal(consumeTicket(store, f, HOST_A, 'file:read', Date.now(), { root: '/srv/b' }), null);
  const f2 = issueTicket(store, { hostId: HOST_A, purpose: 'file:read', tenantId: 'acme', root: '/srv/a' });
  // FILE §14: a file:read ticket cannot be used as file:write.
  assert.equal(consumeTicket(store, f2, HOST_A, 'file:write'), null);
  const f3 = issueTicket(store, { hostId: HOST_A, purpose: 'file:write', tenantId: 'acme', root: '/srv/a' });
  assert.equal(consumeTicket(store, f3, HOST_A, 'file:write').root, '/srv/a');
  const f4 = issueTicket(store, { hostId: HOST_A, purpose: 'file:read', tenantId: 'acme', root: '/srv/a' });
  assert.equal(consumeTicket(store, f4, HOST_A, 'file:read', Date.now() + 61_000), null);
  // The stored binding cannot be mutated by the issuer afterwards.
  const target = { host: '10.0.0.7', port: 1 };
  const f5 = issueTicket(store, { hostId: HOST_A, purpose: 'tcp:open', tenantId: 'acme', target });
  target.host = '10.0.0.8';
  assert.equal(store.get(f5).target.host, '10.0.0.7');
});

test('scopes: operators get tcp:open, file:read, file:write; file:root is admin only', () => {
  const op = scopesForRole('operator');
  for (const s of ['tcp:open', 'file:read', 'file:write']) assert.equal(op.has(s), true, s);
  assert.equal(op.has('file:root'), false);
  assert.equal(OPERATOR.includes('file:root'), false);
  assert.equal(scopesForRole('admin').has('file:root'), true);
  assert.equal(scopesForRole('viewer').has('tcp:open'), false);
  assert.deepEqual(ch.PURPOSE_SCOPES['file:write'], ['file:read', 'file:write']);
});

test('capability header parsing', () => {
  assert.deepEqual([...ch.parseCapabilities('pty, tcp,file')], ['pty', 'tcp', 'file']);
  assert.deepEqual([...ch.parseCapabilities(undefined)], []);
  assert.deepEqual([...ch.parseCapabilities('PTY,tcp;rm,ok_1')], ['ok_1']);
  assert.deepEqual([...ch.parseCapabilities('x'.repeat(300))], []);
});

function fleet(env = {}) {
  const key = privateKeyFromSeed(TEST_SEED);
  return {
    env: { NODE_ENV: 'test', ...env },
    signer: buildSigner(key, rawPublicKey(key)),
    tickets: new Map(),
    registry: new MemoryRegistry({ NODE_ENV: 'test' }),
    metrics: { executionsTotal: { inc() {} } },
    async verifyApiKey(k) {
      if (k === 'admin-key') return { key_id: 'ak_admin', user_id: 'admin-1' };
      if (k === 'op-key') return { key_id: 'ak_op', user_id: 'op-1' };
      if (k === 'viewer-key') return { key_id: 'ak_viewer', user_id: 'viewer-1' };
      return null;
    }
  };
}

async function rig(env) {
  const fm = fleet(env);
  const pub = opensshEd25519(fm.signer.publicKeyRaw);
  for (const [tenantId, hostId, user] of [['acme', HOST_A, 'admin-1'], ['beta', HOST_B, 'other']]) {
    await fm.registry.enroll({ tenantId, userId: user, keyId: `k-${hostId}`, hostId, hostname: `${tenantId}.example`, os: 'linux', platform: 'amd64', sshPubkey: pub });
  }
  await fm.registry.addMember('acme', 'op-1', 'operator', 'op@example');
  await fm.registry.addMember('acme', 'viewer-1', 'viewer', 'v@example');
  await fm.registry.setScopes('ak_admin', ['admin']);
  await fm.registry.setScopes('ak_op', OPERATOR);
  await fm.registry.setScopes('ak_viewer', ['hosts:read']);
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  mount(app, fm);
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const ticket = async (key, body) => {
    const res = await fetch(`${url}/api/v1/ws-ticket`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key },
      body: JSON.stringify({ host_id: HOST_A, ...body })
    });
    return { status: res.status, body: await res.json() };
  };
  return { fm, server, ticket };
}

test('ws-ticket tcp:open: validation, scope, refused classes, policy, audit', async () => {
  const { fm, server, ticket } = await rig();
  try {
    const tcp = (key, target) => ticket(key, { purpose: 'tcp:open', target });
    assert.deepEqual(await tcp('op-key', { host: '127.0.0.1', port: 22 }), { status: 400, body: { error: 'bad_target' } });
    assert.deepEqual(await tcp('op-key', { host: 'db.internal', port: 22 }), { status: 400, body: { error: 'bad_target' } });
    assert.deepEqual(await tcp('op-key', undefined), { status: 400, body: { error: 'bad_target' } });
    assert.deepEqual(await tcp('viewer-key', { host: 'local', port: 22 }), { status: 403, body: { error: 'scope_denied' } });
    assert.deepEqual(await tcp('op-key', { host: '169.254.169.254', port: 80 }), { status: 403, body: { error: 'target_forbidden' } });
    // Empty (absent) policy denies.
    assert.deepEqual(await tcp('op-key', { host: 'local', port: 5432 }), { status: 403, body: { error: 'target_denied' } });
    // A reverse forward has no purpose.
    assert.deepEqual(await ticket('op-key', { purpose: 'tcp:listen', target: { host: 'local', port: 22 } }), { status: 400, body: { error: 'bad_purpose' } });
    assert.equal((await ticket('op-key', { purpose: 'tcp:open', host_id: HOST_B, target: { host: 'local', port: 22 } })).status, 404);

    // Tenant default allows local:5432; the host override replaces it.
    await fm.registry.setTenantChannelPolicy('acme', { tcp_policy: { allow: [{ local: true, ports: [5432] }] } });
    const ok = await tcp('op-key', { host: 'local', port: 5432 });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.purpose, 'tcp:open');
    assert.deepEqual(fm.tickets.get(ok.body.ticket).target, { host: 'local', port: 5432 });
    // A port is an integer or an "a-b" range string; "3389" is malformed.
    await assert.rejects(fm.registry.setHostChannelPolicy(HOST_A, { tcp_policy: { allow: [{ cidr: '10.0.0.0/24', ports: ['3389'] }] } }), /bad_policy/);
    await fm.registry.setHostChannelPolicy(HOST_A, { tcp_policy: { allow: [{ cidr: '10.0.0.0/24', ports: [3389] }] } });
    assert.equal((await tcp('op-key', { host: 'local', port: 5432 })).status, 403);
    const mapped = await tcp('op-key', { host: '::ffff:10.0.0.7', port: 3389 });
    assert.equal(mapped.status, 200);
    assert.deepEqual(fm.tickets.get(mapped.body.ticket).target, { host: '10.0.0.7', port: 3389 });
    // Clearing the host column falls back to the tenant default.
    await fm.registry.setHostChannelPolicy(HOST_A, { tcp_policy: null });
    assert.equal((await tcp('op-key', { host: 'local', port: 5432 })).status, 200);

    const issued = fm.registry.audit.filter((r) => r.action === 'ticket_issued');
    assert.deepEqual(issued.map((r) => r.payload), [
      { purpose: 'tcp:open', target: { host: 'local', port: 5432 } },
      { purpose: 'tcp:open', target: { host: '10.0.0.7', port: 3389 } },
      { purpose: 'tcp:open', target: { host: 'local', port: 5432 } }
    ]);
    for (const row of issued) assert.equal(JSON.stringify(row).includes('stk_'), false);
    assert.equal((await fm.registry.verifyAudit()).ok, true);
    await assert.rejects(fm.registry.setHostChannelPolicy(HOST_A, { tcp_policy: { allow: 'all' } }), /bad_policy/);
  } finally {
    server.close();
  }
});

test('ws-ticket file:*: root validation, scopes, policy, audit', async () => {
  const { fm, server, ticket } = await rig();
  try {
    const file = (key, purpose, root) => ticket(key, { purpose, root });
    for (const root of ['srv', '/srv/../etc', '/srv/', undefined]) {
      assert.deepEqual(await file('op-key', 'file:read', root), { status: 400, body: { error: 'bad_root' } });
    }
    assert.deepEqual(await file('admin-key', 'file:root', '~'), { status: 400, body: { error: 'bad_root' } });
    assert.deepEqual(await file('viewer-key', 'file:read', '/srv/app'), { status: 403, body: { error: 'scope_denied' } });
    // FILE §14: an operator cannot get file:root.
    assert.deepEqual(await file('op-key', 'file:root', '/srv/app'), { status: 403, body: { error: 'scope_denied' } });
    assert.deepEqual(await file('op-key', 'file:read', '/srv/app'), { status: 403, body: { error: 'root_denied' } });

    await fm.registry.setHostChannelPolicy(HOST_A, { file_policy: { roots: [{ path: '/srv/app', read: true }, { path: '/etc', read: true, write: true, root: true }] } });
    const ok = await file('op-key', 'file:read', '/srv/app/sub');
    assert.equal(ok.status, 200);
    assert.equal(fm.tickets.get(ok.body.ticket).root, '/srv/app/sub');
    assert.deepEqual(await file('op-key', 'file:write', '/srv/app'), { status: 403, body: { error: 'root_denied' } });
    assert.deepEqual(await file('op-key', 'file:read', '/srv/apps'), { status: 403, body: { error: 'root_denied' } });
    assert.equal((await file('op-key', 'file:write', '/etc')).status, 200);
    assert.equal((await file('admin-key', 'file:root', '/etc/ssh')).status, 200);

    // file:write needs file:read as well as file:write.
    await fm.registry.setScopes('ak_op', ['hosts:read', 'file:write']);
    assert.deepEqual(await file('op-key', 'file:write', '/etc'), { status: 403, body: { error: 'scope_denied' } });

    const issued = fm.registry.audit.filter((r) => r.action === 'ticket_issued').map((r) => r.payload);
    assert.deepEqual(issued, [
      { purpose: 'file:read', root: '/srv/app/sub' },
      { purpose: 'file:write', root: '/etc' },
      { purpose: 'file:root', root: '/etc/ssh' }
    ]);
  } finally {
    server.close();
  }
});

test('ws-ticket budgets: tcp has its own (default 120), file:root is privileged, file:read/write share terminal', async () => {
  const { fm, server, ticket } = await rig({ SYSTEMAPI_TICKET_RATE_PER_HOST: '2', SYSTEMAPI_TICKET_RATE_PRIVILEGED: '1' });
  try {
    await fm.registry.setHostChannelPolicy(HOST_A, {
      tcp_policy: { allow: [{ local: true, ports: [22] }] },
      file_policy: { roots: [{ path: '/', read: true, write: true, root: true }] }
    });
    for (let i = 0; i < 120; i++) assert.equal((await ticket('admin-key', { purpose: 'tcp:open', target: { host: 'local', port: 22 } })).status, 200, `tcp ${i}`);
    assert.equal((await ticket('admin-key', { purpose: 'tcp:open', target: { host: 'local', port: 22 } })).status, 429);
    assert.equal((await ticket('admin-key', { purpose: 'file:read', root: '/srv' })).status, 200);
    assert.equal((await ticket('admin-key', { purpose: 'terminal:open' })).status, 200);
    assert.equal((await ticket('admin-key', { purpose: 'file:write', root: '/srv' })).status, 429);
    assert.equal((await ticket('admin-key', { purpose: 'file:root', root: '/srv' })).status, 200);
    assert.equal((await ticket('admin-key', { purpose: 'terminal:root' })).status, 429);
  } finally {
    server.close();
  }
});
