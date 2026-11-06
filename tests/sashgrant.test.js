'use strict';

// Negative tests for the sash/1 login grant. The seed is the cross-language
// fixture (0x22 fleet, 0x33 emergency), not a production key.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const { privateKeyFromSeed, rawPublicKey } = require('../controlplane/keys');
const {
  buildSashTerminalGrant, verifySashGrant, signSashDocument, goPathClean
} = require('../controlplane/sashgrant');

const SEED = '22'.repeat(32);
const EMER = '33'.repeat(32);
const NOW = 1_700_000_000;

function pub(hex) {
  return rawPublicKey(privateKeyFromSeed(Buffer.from(hex, 'hex')));
}

const FLEET = pub(SEED);
const EMERGENCY = pub(EMER);

function policies() {
  return {
    service: { units: ['nginx', '*'] },
    package: { names: ['curl'] },
    config: { paths: ['/etc/ssh/sshd_config', '/'] },
    tweak: { sysctls: ['net.ipv4.ip_forward', 'kernel.core_pattern'] },
    file: {
      roots: [
        { path: '/var/log', read: true },
        { path: '/tmp', read: false, write: true },
        { path: '~', read: true },
        { path: '/var/log/../log', read: true }
      ]
    }
  };
}

function sample(extra = {}) {
  return buildSashTerminalGrant(SEED, {
    actor: 'alice',
    host: 'host-1',
    purpose: 'terminal:open',
    exp: NOW + 60,
    lease_id: 'lease-1',
    policies: policies(),
    ...extra
  });
}

function check(doc, fleet = FLEET, emer = EMERGENCY, now = NOW) {
  const raw = Buffer.isBuffer(doc) || typeof doc === 'string' ? doc : JSON.stringify(doc);
  return verifySashGrant(raw, fleet, emer, now);
}

test('goPathClean matches Go path.Clean on a leading double slash', () => {
  assert.equal(goPathClean('//foo'), '/foo');
  assert.equal(goPathClean('/var/log/../log'), '/var/log');
  assert.equal(goPathClean('/'), '/');
});

test('the login fixture filters stars, slash, denied sysctls and unclean paths', () => {
  const built = sample();
  assert.equal(built.document, built.grant);
  assert.deepEqual(built.grant.entitlements, [
    'ps', 'unit.status', 'unit.restart', 'package.query', 'package.install',
    'sysctl.get', 'sysctl.set', 'config.read', 'file.read', 'file.write'
  ]);
  assert.deepEqual(built.grant.file_read, ['/var/log']);
  assert.deepEqual(built.grant.file_write, ['/tmp']);
  assert.equal(built.grant.allow_private, false);
  assert.deepEqual(built.targets, {
    units: ['nginx'],
    packages: ['curl'],
    configs: ['/etc/ssh/sshd_config'],
    sysctls: ['net.ipv4.ip_forward'],
    files: ['/var/log'],
    files_write: ['/tmp']
  });
  const ok = check(built.grant);
  assert.equal(ok.ok, true, ok.error);
  assert.equal(ok.grant.actor, 'alice');
  assert.equal(ok.grant.exp, NOW + 60);
});

test('a tampered actor fails the signature', () => {
  const raw = JSON.stringify(sample().grant);
  const at = raw.indexOf('"alice"');
  assert.ok(at > 0);
  const tampered = `${raw.slice(0, at + 1)}b${raw.slice(at + 2)}`;
  assert.equal(tampered.includes('"blice"'), true);
  assert.equal(check(tampered).error, 'grant_bad_sig');
});

test('exp in the past is expired and exp equal to now is valid', () => {
  const expired = sample({ exp: NOW - 1 });
  assert.equal(check(expired.grant).error, 'grant_expired');
  const live = buildSashTerminalGrant(SEED, {
    actor: 'alice', host: 'host-1', purpose: 'terminal:open',
    exp: NOW, lease_id: 'lease-1', policies: null
  });
  const ok = check(live.grant, FLEET, EMERGENCY, NOW);
  assert.equal(ok.ok, true, ok.error);
  assert.deepEqual(ok.grant.entitlements, ['ps']);
});

test('identical pubs, an empty document and an oversize document fail closed', () => {
  const grant = sample().grant;
  assert.equal(check(grant, FLEET, FLEET).error, 'grant_bad_sig');
  assert.equal(check(Buffer.alloc(0)).error, 'grant_missing');
  assert.equal(check('').error, 'grant_missing');
  assert.equal(check(Buffer.alloc(64 * 1024 + 1)).error, 'grant_bad_shape');
});

test('emergency verifies with the emergency key and fails with the fleet key', () => {
  const doc = signSashDocument({
    v: 'sash/1', actor: 'alice', host: 'host-1', purpose: 'emergency',
    exp: NOW + 60, lease_id: 'lease-1', entitlements: ['ps'],
    file_read: [], file_write: [], allow_private: false
  }, EMER);
  assert.equal(check(doc).ok, true);
  const fleetSigned = signSashDocument({
    v: 'sash/1', actor: 'alice', host: 'host-1', purpose: 'emergency',
    exp: NOW + 60, lease_id: 'lease-1', entitlements: ['ps'],
    file_read: [], file_write: [], allow_private: false
  }, SEED);
  assert.equal(check(fleetSigned).error, 'grant_bad_sig');
  assert.equal(check(doc, EMERGENCY, FLEET).error, 'grant_bad_sig');
});

test('a star entitlement is grant_star after a valid signature; a star file root is bad shape', () => {
  const starred = signSashDocument({
    v: 'sash/1', actor: 'alice', host: 'host-1', purpose: 'terminal:open',
    exp: NOW + 60, lease_id: 'lease-1', entitlements: ['*'],
    file_read: [], file_write: [], allow_private: false
  }, SEED);
  assert.equal(starred.entitlements[0], '*');
  assert.equal(check(starred).error, 'grant_star');
  const root = signSashDocument({
    v: 'sash/1', actor: 'alice', host: 'host-1', purpose: 'terminal:open',
    exp: NOW + 60, lease_id: 'lease-1', entitlements: ['ps'],
    file_read: ['*'], file_write: [], allow_private: false
  }, SEED);
  assert.equal(check(root).error, 'grant_bad_shape');
});

test('an unknown field and a lease-domain signature do not verify', () => {
  const raw = JSON.stringify(sample().grant);
  const extra = raw.replace(/}$/, ',"extra":1}');
  assert.equal(check(extra).error, 'grant_bad_shape');

  const grant = sample().grant;
  const body = JSON.stringify({
    v: grant.v, actor: grant.actor, host: grant.host, purpose: grant.purpose,
    exp: grant.exp, lease_id: grant.lease_id, entitlements: grant.entitlements,
    file_read: grant.file_read, file_write: grant.file_write, allow_private: false
  });
  const priv = privateKeyFromSeed(Buffer.from(SEED, 'hex'));
  const sig = crypto.sign(null, Buffer.concat([
    Buffer.from('systemapi-lease-v1\n', 'utf8'),
    Buffer.from(body, 'utf8')
  ]), priv).toString('base64');
  const swapped = JSON.parse(body);
  swapped.sig = sig;
  assert.equal(check(swapped).error, 'grant_bad_sig');
});

test('an empty unit name is grant_bad_shape', () => {
  assert.throws(() => buildSashTerminalGrant(SEED, {
    actor: 'alice', host: 'host-1', purpose: 'terminal:open',
    exp: NOW, lease_id: 'lease-1',
    policies: { service: { units: [''] } }
  }), (err) => err.code === 'grant_bad_shape');
});

test('the CLI writes the signed document and a fixed error', () => {
  const script = path.join(__dirname, '../controlplane/sashgrant.js');
  const input = {
    seed: SEED, actor: 'alice', host: 'host-1', purpose: 'terminal:open',
    exp: NOW + 60, lease_id: 'lease-1', policies: policies()
  };
  const ok = spawnSync(process.execPath, [script], { input: JSON.stringify(input) });
  assert.equal(ok.status, 0, ok.stderr.toString());
  assert.equal(ok.stdout.includes(10), false);
  const parsed = JSON.parse(ok.stdout.toString('utf8'));
  assert.equal(check(ok.stdout).ok, true);
  assert.deepEqual(parsed.entitlements, [
    'ps', 'unit.status', 'unit.restart', 'package.query', 'package.install',
    'sysctl.get', 'sysctl.set', 'config.read', 'file.read', 'file.write'
  ]);
  assert.deepEqual(parsed.file_write, ['/tmp']);

  const bad = spawnSync(process.execPath, [script], { input: '{' });
  assert.equal(bad.status, 1);
  assert.equal(bad.stderr.toString(), 'grant_bad_shape');
  assert.equal(bad.stdout.length, 0);
});
