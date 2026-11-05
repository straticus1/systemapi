'use strict';

// scripts/control-pubkey.js prints the control plane's public key from the
// lease signing seed in an env file, for provision-helper-trust.sh --pubkey.
// Threats: the seed reaching stdout or stderr; a sourced or evaluated env
// file; a planted, swapped, shared or oversized file; an ambiguous pin. Every
// run here uses a FAKE seed in a temp dir (HOME is pointed there too), never
// a real env file. The not-owned-by-caller refusal needs a second uid and is
// not exercised here.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { privateKeyFromSeed, rawPublicKey } = require('../controlplane/keys');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'control-pubkey.js');
// A fake seed: a fixed, recognisable pattern that is not any real key.
const SEED_HEX = 'f00dfacecafebeef'.repeat(4);
const SEED = Buffer.from(SEED_HEX, 'hex');
const PUB = rawPublicKey(privateKeyFromSeed(Buffer.from(SEED))).toString('base64');
const OTHER_SECRET = 'SESSION_SECRET=do-not-print-this-session-secret';

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'control-pubkey-'));
  fs.chmodSync(dir, 0o700);
  const cfg = path.join(dir, '.config', 'sahcore');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const write = (name, body, mode = 0o600) => {
    const p = path.join(cfg, name);
    fs.writeFileSync(p, body, { mode });
    fs.chmodSync(p, mode);
    return p;
  };
  const run = (args) => spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf8', env: { PATH: process.env.PATH, HOME: dir }, cwd: dir
  });
  return { dir, cfg, write, run };
}

const good = (seedLine = `SYSTEMAPI_ED25519_SEED=${SEED_HEX}`) => [
  '# fake production env for the test',
  'NODE_ENV=production',
  OTHER_SECRET,
  seedLine,
  'DB_PASSWORD=also-not-printed',
  ''
].join('\n');

// Every form in which the seed (or any part of the file's secrets) could leak.
function assertNoLeak(r, label) {
  const both = `${r.stdout}\n${r.stderr}`;
  const forms = [SEED_HEX, SEED_HEX.toUpperCase(), SEED.toString('base64'), SEED.toString('base64url'),
    SEED_HEX.slice(0, 16), SEED_HEX.slice(-16), 'do-not-print-this-session-secret', 'also-not-printed'];
  for (const f of forms) assert.ok(!both.includes(f), `${label}: output holds secret material (${f.slice(0, 6)}...)`);
}

test('control-pubkey: prints only the public key of the seed in --env FILE', () => {
  const t = sandbox();
  const f = t.write('prod.env', good());
  const r = t.run(['--env', f]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${PUB}\n`);
  assert.equal(r.stderr, '');
  assertNoLeak(r, 'happy path');
  // The encoding provision-helper-trust.sh accepts: 43 base64 chars and "=".
  assert.match(r.stdout.trim(), /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/);
});

test('control-pubkey: defaults to ~/.config/sahcore/sahcore.env', () => {
  const t = sandbox();
  t.write('sahcore.env', good());
  const r = t.run([]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${PUB}\n`);
  assertNoLeak(r, 'default path');
});

test('control-pubkey: accepts an upper-case seed (the server does) and gives the same key', () => {
  const t = sandbox();
  const r = t.run(['--env', t.write('prod.env', good(`SYSTEMAPI_ED25519_SEED=${SEED_HEX.toUpperCase()}`))]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${PUB}\n`);
  assertNoLeak(r, 'upper case');
});

test('control-pubkey: never runs the file (no sourcing, no eval)', () => {
  const t = sandbox();
  const marker = path.join(t.dir, 'pwned');
  const body = `X=$(touch ${marker})\n\`touch ${marker}\`\ntouch ${marker}\n${good()}`;
  const r = t.run(['--env', t.write('prod.env', body)]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${PUB}\n`);
  assert.equal(fs.existsSync(marker), false, 'a line of the env file was executed');
});

test('control-pubkey: refuses, prints nothing on stdout and no secret on stderr', () => {
  const cases = [
    ['no seed line', () => good('# no seed here')],
    ['seed set twice', () => `${good()}SYSTEMAPI_ED25519_SEED=${SEED_HEX}\n`],
    ['seed set twice, second malformed', () => `${good()}SYSTEMAPI_ED25519_SEED=${SEED_HEX}00\n`],
    ['63 hex characters', () => good(`SYSTEMAPI_ED25519_SEED=${SEED_HEX.slice(1)}`)],
    ['65 hex characters', () => good(`SYSTEMAPI_ED25519_SEED=${SEED_HEX}a`)],
    ['not hex', () => good(`SYSTEMAPI_ED25519_SEED=${SEED_HEX.slice(1)}g`)],
    ['double-quoted', () => good(`SYSTEMAPI_ED25519_SEED="${SEED_HEX}"`)],
    ['single-quoted', () => good(`SYSTEMAPI_ED25519_SEED='${SEED_HEX}'`)],
    ['trailing CR', () => good(`SYSTEMAPI_ED25519_SEED=${SEED_HEX}\r`)],
    ['trailing space', () => good(`SYSTEMAPI_ED25519_SEED=${SEED_HEX} `)],
    ['export prefix', () => good(`export SYSTEMAPI_ED25519_SEED=${SEED_HEX}`)],
    ['leading space', () => good(` SYSTEMAPI_ED25519_SEED=${SEED_HEX}`)],
    ['command substitution', () => good('SYSTEMAPI_ED25519_SEED=$(cat /etc/passwd)')],
    ['empty value', () => good('SYSTEMAPI_ED25519_SEED=')]
  ];
  for (const [label, body] of cases) {
    const t = sandbox();
    const r = t.run(['--env', t.write('prod.env', body())]);
    assert.equal(r.status, 1, `${label}: exit ${r.status}`);
    assert.equal(r.stdout, '', `${label}: stdout not empty`);
    assert.match(r.stderr, /^control-pubkey: [^\n]+\n$/, `${label}: stderr is not one fixed line`);
    assertNoLeak(r, label);
  }
});

test('control-pubkey: refuses a file others can read or write, a symlink, a directory, a missing or oversized file', () => {
  const cases = [
    ['group-readable (0640)', (t) => t.write('prod.env', good(), 0o640)],
    ['other-readable (0604)', (t) => t.write('prod.env', good(), 0o604)],
    ['group-writable (0620)', (t) => t.write('prod.env', good(), 0o620)],
    ['symlink to a good file', (t) => {
      const real = t.write('real.env', good());
      const link = path.join(t.cfg, 'link.env');
      fs.symlinkSync(real, link);
      return link;
    }],
    ['directory', (t) => {
      const d = path.join(t.cfg, 'dir.env');
      fs.mkdirSync(d, { mode: 0o700 });
      return d;
    }],
    ['missing', (t) => path.join(t.cfg, 'absent.env')],
    ['over 64 KiB', (t) => t.write('big.env', `${good()}${'# pad\n'.repeat(12000)}`)]
  ];
  for (const [label, make] of cases) {
    const t = sandbox();
    const r = t.run(['--env', make(t)]);
    assert.equal(r.status, 1, `${label}: exit ${r.status}`);
    assert.equal(r.stdout, '', `${label}: stdout not empty`);
    assert.match(r.stderr, /^control-pubkey: [^\n]+\n$/, `${label}: stderr is not one fixed line`);
    assertNoLeak(r, label);
  }
});

test('control-pubkey: refuses bad arguments before reading anything', () => {
  for (const args of [['--env'], ['--env', ''], ['--seed', SEED_HEX], ['extra'], ['--env', 'a', 'b']]) {
    const t = sandbox();
    t.write('sahcore.env', good());
    const r = t.run(args);
    assert.equal(r.status, 1, `${args.join(' ')}: exit ${r.status}`);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /^control-pubkey: usage: /);
    assertNoLeak(r, args.join(' '));
  }
});

test('control-pubkey: a different seed gives a different key (the key is derived, not fixed)', () => {
  const t = sandbox();
  const other = crypto.randomBytes(32).toString('hex');
  const r = t.run(['--env', t.write('prod.env', good(`SYSTEMAPI_ED25519_SEED=${other}`))]);
  assert.equal(r.status, 0, r.stderr);
  assert.notEqual(r.stdout, `${PUB}\n`);
  assert.equal(r.stdout, `${rawPublicKey(privateKeyFromSeed(Buffer.from(other, 'hex'))).toString('base64')}\n`);
  assert.ok(!r.stdout.includes(other) && !r.stderr.includes(other));
});
