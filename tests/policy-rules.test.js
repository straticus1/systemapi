'use strict';

// controlplane/policyrules.js: the one rules module behind the break-glass
// CLI (scripts/channel-policy.js) and the HTTP routes. The parity test feeds
// the same grants to both front ends and wants the same stored columns, or
// the same rule refusal.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const rules = require('../controlplane/policyrules');
const { parseArgs } = require('../scripts/channel-policy');
const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');

const HOST = '11111111-1111-4111-8111-111111111111';
const PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

// Each vector is a grants object; the CLI gets it as flags (ports as
// strings), the route as JSON (ports as integers).
const VECTORS = [
  { tcp_local: ['3003'], file_write: ['/var/tmp/sah-filetest'] },
  { tcp_local: ['8080', '3003', '8080'] },
  { file_read: ['/srv/logs', '/srv/data'], file_write: ['/srv/data'] },
  { service: ['postgresql.service', 'nginx.service'], package: ['nginx', 'curl'] },
  { config: ['/etc/postfix', '/etc/nginx', '/etc/systemd/system/nginx.service.d'] },
  { tweak_sysctl: ['net.ipv4.ip_forward'], tweak_unit: ['nginx.service'] },
  { service: ['systemapi-agent-other.service'] },
  // refusals
  { tcp_local: ['0'] },
  { tcp_local: ['65536'] },
  { tcp_local: ['03003'] },
  { tcp_local: ['1-100'] },
  { file_write: ['/'] },
  { file_read: ['~'] },
  { file_write: ['var/tmp/x'] },
  { file_write: ['/var/tmp/../etc'] },
  { file_write: ['/var//tmp'] },
  { file_write: ['/var/tmp/'] },
  { file_read: ['/srv'] },
  { file_read: ['/etc/ssh'] },
  { file_read: ['/var/lib'] },
  { file_read: ['/var/lib/postgresql/16'] },
  { service: ['bad unit'] },
  { service: ['systemapi-agent'] },
  { service: ['sah-sysctl-helper@0123456789abcdef0123456789abcdef.service'] },
  { package: ['*'] },
  { config: ['/etc'] },
  { config: ['/etc/systemapi-agent'] },
  { config: ['/etc/systemd/system'] },
  { tweak_sysctl: ['kernel.core_pattern'] },
  { tweak_sysctl: ['kernel..core_pattern'] },
  { tweak_unit: ['sah-config-helper@abc.service'] },
  {},
  { tcp_local: Array.from({ length: 17 }, (_, i) => String(i + 1)) },
  { file_read: Array.from({ length: 17 }, (_, i) => `/srv/d${i}`) }
];

function cliResult(grants) {
  const argv = ['set', '--tenant', 'acme', '--host', 'web1', '--reason', 'parity'];
  for (const [key, list] of Object.entries(grants)) for (const v of list) argv.push(rules.cliLabel(key), v);
  try {
    const out = parseArgs(argv);
    return { ok: { tcp_policy: out.tcpPolicy, file_policy: out.filePolicy, service_policy: out.servicePolicy, package_policy: out.packagePolicy, config_policy: out.configPolicy, tweak_policy: out.tweakPolicy } };
  } catch (err) {
    assert.equal(err.code, 'usage');
    return { rule: err.rule };
  }
}

test('parity: the CLI and PUT .../channel-policy store the same columns or refuse with the same rule', async () => {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test', SYSTEMAPI_POLICY_WRITE_RATE_PRINCIPAL: '600', SYSTEMAPI_POLICY_WRITE_RATE: '600' };
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.verifyApiKey = async (key) => (key === 'admin-key' ? { key_id: 'k-admin', user_id: 'user-1' } : null);
  mount(app, fm);
  await fm.registry.setScopes('k-admin', ['admin']);
  await fm.registry.enroll({ tenantId: 'acme', userId: 'user-1', keyId: 'k-agent', hostId: HOST, hostname: 'web1', sshPubkey: PUB });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/api/v1/hosts/${HOST}/channel-policy?dry_run=1`;
  try {
    for (const grants of VECTORS) {
      const cli = cliResult(grants);
      const json = Object.fromEntries(Object.entries(grants).map(([k, v]) => [k, k === 'tcp_local' ? v.map((p) => (/^[0-9]+$/.test(p) && !p.startsWith('0') ? Number(p) : p)) : v]));
      const res = await fetch(url, {
        method: 'PUT',
        headers: { 'x-api-key': 'admin-key', 'content-type': 'application/json' },
        body: JSON.stringify({ reason: 'parity', if_version: rules.policyVersion({}), grants: json })
      });
      const body = await res.json();
      if (cli.ok) {
        assert.equal(res.status, 200, JSON.stringify({ grants, body }));
        const after = Object.fromEntries(Object.entries(body.diff).map(([col, d]) => [col, d.after]));
        assert.deepEqual(after, cli.ok, JSON.stringify(grants));
      } else {
        assert.ok(cli.rule, JSON.stringify(grants));
        assert.equal(res.status, 400, JSON.stringify(grants));
        assert.deepEqual(body, { error: 'bad_policy', reason: cli.rule }, JSON.stringify(grants));
      }
    }
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('policyVersion is canonical (key order, absent = null) and changes with any column', () => {
  const a = rules.policyVersion({ tcp_policy: { allow: [{ local: true, ports: [22] }] } });
  const b = rules.policyVersion({ tweak_policy: null, tcp_policy: { allow: [{ ports: [22], local: true }] } });
  assert.equal(a, b);
  assert.match(a, rules.VERSION_RE);
  assert.notEqual(a, rules.policyVersion({}));
  assert.notEqual(rules.policyVersion(rules.clearPolicy()), rules.policyVersion(rules.inheritPolicy()));
});

test('normalizeColumns keeps null as inherit and refuses what the rules refuse', () => {
  const cols = { ...rules.inheritPolicy(), tcp_policy: { allow: [{ local: true, ports: [8080, 22] }] }, file_policy: { roots: [] } };
  assert.deepEqual(rules.normalizeColumns(cols), { ...rules.inheritPolicy(), tcp_policy: { allow: [{ local: true, ports: [22, 8080] }] }, file_policy: { roots: [] } });
  for (const bad of [
    { tcp_policy: { allow: [{ cidr: '10.0.0.0/8', ports: [22] }] } },
    { tcp_policy: { allow: [{ local: true, ports: [[1, 100]] }] } },
    { file_policy: { roots: [{ path: '/srv/a', read: true, write: true, root: true }] } },
    { file_policy: { roots: [{ path: '/', read: true, write: false }] } },
    { service_policy: { units: ['systemapi-agent.service'] } },
    { config_policy: { paths: ['/etc/sahcore'], extra: 1 } }
  ]) {
    assert.throws(() => rules.normalizeColumns({ ...rules.inheritPolicy(), ...bad }), (err) => typeof err.rule === 'string', JSON.stringify(bad));
  }
});

test('grantsOf round-trips what buildPolicy writes; null when any column is null or refused', () => {
  const grants = { tcp_local: ['22'], file_write: ['/srv/a'], file_read: ['/srv/b'], service: ['nginx.service'], package: ['curl'], config: ['/etc/nginx'], tweak_sysctl: ['vm.swappiness'], tweak_unit: ['nginx.service'] };
  const cols = rules.buildPolicy(grants);
  const back = rules.grantsOf(cols);
  assert.deepEqual(back, { ...grants, tcp_local: [22] });
  assert.deepEqual(rules.buildPolicy(back, rules.apiLabel), cols);
  assert.equal(rules.grantsOf(rules.inheritPolicy()), null);
  assert.equal(rules.grantsOf({ ...cols, tcp_policy: { allow: [{ cidr: '10.0.0.0/8', ports: [22] }] } }), null);
});

test('dangerousEntries names only what a write newly grants', () => {
  const eff = (cols) => rules.effectiveOf(cols, null);
  const before = eff(rules.buildPolicy({ package: ['curl'], config: ['/etc/nginx'] }));
  const after = eff(rules.buildPolicy({ package: ['curl', 'nginx'], config: ['/etc/nginx', '/opt/x/conf'], service: ['ssh.service', 'nginx'] }));
  assert.deepEqual(rules.dangerousEntries(before, after), ['config:/opt/x/conf', 'package:nginx', 'service:ssh.service']);
  assert.deepEqual(rules.dangerousEntries(after, before), []);
  for (const u of ['sshd', 'sshd@1.service', 'dbus-broker.service', 'cloudflared.service', 'networkmanager.service']) assert.equal(rules.unitProtected(u), true, u);
  for (const u of ['nginx', 'openssh-backup.timer', 'myredis.service', 'nginx.timer', 'nft-helper.service']) assert.equal(rules.unitProtected(u), false, u);
});
