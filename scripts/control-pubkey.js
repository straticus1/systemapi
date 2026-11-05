#!/usr/bin/env node
// Print the control plane's Ed25519 public key (standard base64 of the raw 32
// bytes, the agent.json `control_pubkey` encoding) from the lease signing seed
// in the operator's copy of the production env file, so the mutation helpers'
// trust anchor (scripts/provision-helper-trust.sh --pubkey) is pinned out of
// band and never taken from the agent-writable agent.json.
//
//   node scripts/control-pubkey.js [--env FILE]
//
// FILE defaults to ~/.config/sahcore/sahcore.env. It is parsed, never sourced
// or evaluated: only the one line SYSTEMAPI_ED25519_SEED=<64 hex> is read;
// every other line is skipped unread past its key. stdout gets the public key
// and a newline, nothing else; stderr gets a fixed message per failure and
// exit 1.
//
// Threats: the seed reaching stdout, stderr, argv or the environment (it is
// read from the file only, never echoed; errors are fixed strings that name
// no value and no line; the file and seed buffers are zeroed after use, though
// the decoded text, a JS string, cannot be and lives until the process exits
// a moment later), a shell-style
// env file running code (no sourcing, no eval), a swapped or planted env file
// (refused unless a regular file, not a symlink, owned by the caller, and not
// group/other writable or readable), an oversized file (64 KiB cap), and an
// ambiguous pin (refused unless exactly one well-formed seed line). Does NOT
// protect against someone who can already read the file (they hold the seed),
// and does NOT prove the running control plane uses this seed: compare the
// printed key with agent.json's control_pubkey (provision-helper-trust.sh
// does, and refuses on a mismatch).
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { privateKeyFromSeed, rawPublicKey } = require('../controlplane/keys');

const MAX_BYTES = 64 * 1024;
const KEY = 'SYSTEMAPI_ED25519_SEED';
const SEED_LINE_RE = /^SYSTEMAPI_ED25519_SEED=([0-9a-fA-F]{64})$/;
const USAGE = 'usage: node scripts/control-pubkey.js [--env FILE]';

class Refusal extends Error {}

function refuse(message) {
  throw new Refusal(message);
}

function parseArgs(argv) {
  if (argv.length === 0) return path.join(os.homedir(), '.config', 'sahcore', 'sahcore.env');
  if (argv.length === 2 && argv[0] === '--env' && argv[1] !== '') return argv[1];
  return refuse(USAGE);
}

// Opens without following a final symlink and checks the open file itself, so
// what is checked is what is read.
function readEnvFile(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (err) {
    if (err && err.code === 'ELOOP') refuse('the env file is a symlink; refused');
    if (err && err.code === 'ENOENT') refuse('no env file at the given path');
    refuse('cannot open the env file');
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) refuse('the env file is not a regular file');
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) refuse('the env file is not owned by you; refused');
    if ((st.mode & 0o077) !== 0) refuse('the env file is readable or writable by group or others; chmod 600 it');
    if (st.size > MAX_BYTES) refuse('the env file is over 64 KiB; refused');
    const buf = Buffer.alloc(MAX_BYTES + 1);
    let n = 0;
    for (;;) {
      const r = fs.readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
      if (n > MAX_BYTES) {
        buf.fill(0);
        refuse('the env file is over 64 KiB; refused');
      }
    }
    return { buf, n };
  } finally {
    fs.closeSync(fd);
  }
}

// The seed as 32 bytes from exactly one well-formed line. Lines for other
// keys are compared only on their key; no value is kept or printed.
function seedFrom(buf, n) {
  const text = buf.toString('latin1', 0, n);
  let seed = null;
  let count = 0;
  for (const line of text.split('\n')) {
    const eq = line.indexOf('=');
    const key = (eq < 0 ? line : line.slice(0, eq)).trim().replace(/^export\s+/, '');
    if (key !== KEY) continue;
    count += 1;
    const m = SEED_LINE_RE.exec(line);
    if (!m) {
      if (seed) seed.fill(0);
      refuse(`the ${KEY} line is not ${KEY}=<64 hex characters>`);
    }
    if (count > 1) {
      if (seed) seed.fill(0);
      refuse(`${KEY} is set more than once; refused`);
    }
    seed = Buffer.from(m[1], 'hex');
  }
  if (!seed) refuse(`no ${KEY} line in the env file`);
  return seed;
}

function controlPubkey(file) {
  const { buf, n } = readEnvFile(file);
  let seed;
  try {
    seed = seedFrom(buf, n);
  } finally {
    buf.fill(0);
  }
  try {
    return rawPublicKey(privateKeyFromSeed(seed)).toString('base64');
  } finally {
    seed.fill(0);
  }
}

function main(argv) {
  try {
    process.stdout.write(`${controlPubkey(parseArgs(argv))}\n`);
    return 0;
  } catch (err) {
    // Only our own fixed messages are printed; anything else is a bare code.
    const msg = err instanceof Refusal ? err.message : 'internal error (no details printed)';
    process.stderr.write(`control-pubkey: ${msg}\n`);
    return 1;
  }
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));

module.exports = { controlPubkey };
