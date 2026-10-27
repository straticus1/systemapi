'use strict';

// Negative tests for scripts/provision-helper-trust.sh, the install step that
// writes the mutation helpers' trust anchor (/etc/systemapi-agent/helper-trust.json).
// Threats: a control_pubkey taken from the agent-writable agent.json instead of
// an out-of-band pinned value; a planted symlink at the trust file, its
// directory or the state file; a non-root run; a missing or malformed pin.
// `id` and `chown` are shimmed on PATH so the test runs unprivileged; `mv` is
// shimmed with GNU -T semantics (the script targets Linux hosts) so it also
// runs on BSD/macOS, and logs its argv so the -T use is pinned.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'provision-helper-trust.sh');
const PUB = Buffer.alloc(32, 7).toString('base64');
const OTHER = Buffer.alloc(32, 9).toString('base64');
const HOST = '11111111-1111-4111-8111-111111111111';

function setup({ uid = 0, gnuMv = true, state = { host_id: HOST, ed25519_seed: 'SECRET-SEED', control_pubkey: PUB, tenant: 't' } } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trust-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'id'), `#!/bin/sh\n[ "$1" = "-u" ] && echo ${uid} && exit 0\nexit 1\n`, { mode: 0o755 });
  const chownLog = path.join(dir, 'chown.log');
  fs.writeFileSync(path.join(bin, 'chown'), `#!/bin/sh\necho "$@" >> '${chownLog}'\n`, { mode: 0o755 });
  const mvLog = path.join(dir, 'mv.log');
  // -T: never move INTO a directory at the destination; refuse instead.
  fs.writeFileSync(path.join(bin, 'mv'), gnuMv
    ? `#!/bin/sh\necho "$@" >> '${mvLog}'\n[ "$1" = "-T" ] && [ "$2" = "--help" ] && exit 0\n[ "$1" = "-fT" ] || exit 2\n[ -d "$3" ] && exit 1\nexec /bin/mv -f "$2" "$3"\n`
    : `#!/bin/sh\necho "$@" >> '${mvLog}'\ncase "$1" in -*T*) exit 64 ;; esac\nexec /bin/mv "$@"\n`, { mode: 0o755 });
  const statePath = path.join(dir, 'agent.json');
  fs.writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
  const out = path.join(dir, 'etc', 'systemapi-agent', 'helper-trust.json');
  const run = (args) => spawnSync('bash', [SCRIPT, '--state', statePath, '--out', out, ...args], {
    encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }
  });
  return { dir, statePath, out, chownLog, mvLog, run };
}

test('provision-helper-trust: writes the pinned key when agent.json agrees', () => {
  const t = setup();
  const r = t.run(['--pubkey', PUB, '--host-id', HOST]);
  assert.equal(r.status, 0, r.stderr);
  const body = JSON.parse(fs.readFileSync(t.out, 'utf8'));
  assert.deepEqual(body, { host_id: HOST, control_pubkey: PUB }, 'only the two public fields, never the seed');
  assert.equal(fs.lstatSync(t.out).mode & 0o777, 0o644);
  assert.equal(fs.lstatSync(path.dirname(t.out)).mode & 0o022, 0);
  assert.match(fs.readFileSync(t.chownLog, 'utf8'), /^root:root /m);
  assert.deepEqual(fs.readdirSync(path.dirname(t.out)), ['helper-trust.json'], 'no temp file left');
  assert.match(fs.readFileSync(t.mvLog, 'utf8'), /^-fT \S+ \S+helper-trust\.json$/m, 'rename uses mv -T');
  // Re-running replaces the file atomically.
  assert.equal(t.run(['--pubkey', PUB, '--host-id', HOST]).status, 0);
});

test('provision-helper-trust: never moves the new file into a directory at the trust path', () => {
  const t = setup();
  fs.mkdirSync(t.out, { recursive: true });
  assert.notEqual(t.run(['--pubkey', PUB, '--host-id', HOST]).status, 0);
  assert.deepEqual(fs.readdirSync(t.out), [], 'file moved into the directory');
  assert.deepEqual(fs.readdirSync(path.dirname(t.out)), ['helper-trust.json'], 'temp file left behind');
});

test('provision-helper-trust: refuses without a mv that supports -T', () => {
  const t = setup({ gnuMv: false });
  const r = t.run(['--pubkey', PUB, '--host-id', HOST]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /mv -T/);
  assert.equal(fs.existsSync(t.out), false);
});

test('provision-helper-trust: refuses and writes nothing on every failure', () => {
  const cases = [
    ['pubkey mismatch with agent.json', {}, ['--pubkey', OTHER, '--host-id', HOST]],
    ['missing --pubkey', {}, ['--host-id', HOST]],
    ['missing --host-id', {}, ['--pubkey', PUB]],
    ['malformed --host-id', {}, ['--pubkey', PUB, '--host-id', 'x']],
    ['malformed --pubkey', {}, ['--pubkey', 'not-base64', '--host-id', HOST]],
    ['short --pubkey', {}, ['--pubkey', Buffer.alloc(31, 7).toString('base64'), '--host-id', HOST]],
    ['host id mismatch', {}, ['--pubkey', PUB, '--host-id', '22222222-2222-4222-8222-222222222222']],
    ['not root', { uid: 1000 }, ['--pubkey', PUB, '--host-id', HOST]],
    ['agent.json without control_pubkey', { state: { host_id: HOST } }, ['--pubkey', PUB, '--host-id', HOST]],
    ['agent.json with a bad host id', { state: { host_id: 'x', control_pubkey: PUB } }, ['--pubkey', PUB, '--host-id', HOST]],
    ['unknown flag', {}, ['--pubkey', PUB, '--host-id', HOST, '--force']]
  ];
  for (const [name, opts, args] of cases) {
    const t = setup(opts);
    const r = t.run(args);
    assert.notEqual(r.status, 0, name);
    assert.equal(fs.existsSync(t.out), false, `${name}: trust file written`);
  }
});

test('provision-helper-trust: refuses symlinks at the trust file, its dir and the state file', () => {
  {
    const t = setup();
    fs.mkdirSync(path.dirname(t.out), { recursive: true });
    const target = path.join(t.dir, 'elsewhere');
    fs.symlinkSync(target, t.out);
    assert.notEqual(t.run(['--pubkey', PUB, '--host-id', HOST]).status, 0, 'symlinked trust file');
    assert.equal(fs.existsSync(target), false, 'symlink followed');
  }
  {
    const t = setup();
    fs.mkdirSync(path.join(t.dir, 'etc'));
    const realDir = path.join(t.dir, 'real');
    fs.mkdirSync(realDir);
    fs.symlinkSync(realDir, path.dirname(t.out));
    assert.notEqual(t.run(['--pubkey', PUB, '--host-id', HOST]).status, 0, 'symlinked trust dir');
    assert.deepEqual(fs.readdirSync(realDir), []);
  }
  {
    const t = setup();
    const real = path.join(t.dir, 'agent-real.json');
    fs.renameSync(t.statePath, real);
    fs.symlinkSync(real, t.statePath);
    assert.notEqual(t.run(['--pubkey', PUB, '--host-id', HOST]).status, 0, 'symlinked state file');
    assert.equal(fs.existsSync(t.out), false);
  }
});
