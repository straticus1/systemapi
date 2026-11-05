#!/usr/bin/env node
// Threats: the checkpoint seed copied to the verifier host, or printed while
// fetching the key the verifier needs. Prints ONLY the verifier key line
// (<origin>+<key hash>+<public key>, C2SP signed-note vkey) for
// SYSTEMAPI_AUDIT_CHECKPOINT_SEED and SYSTEMAPI_AUDIT_DEPLOYMENT, read from
// ENV_FILE or .env.production beside server.js (variables already set win).
// Errors print a fixed code, never the seed. Does NOT check the rest of the
// anchoring config (sinks, the lease-key refusal): boot does that.
//
// Usage: node scripts/audit-checkpoint-pubkey.js
'use strict';

const path = require('node:path');
const { anchorSigner, originOf, vkeyOf } = require('../controlplane/anchor');

const SEED_RE = /^[0-9a-fA-F]{64}$/;
const DEPLOYMENT_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// Returns the vkey line, or throws an error whose code is fixed.
function vkeyFromEnv(env) {
  const seed = env.SYSTEMAPI_AUDIT_CHECKPOINT_SEED;
  const deployment = env.SYSTEMAPI_AUDIT_DEPLOYMENT;
  const fail = (code) => Object.assign(new Error(code), { code });
  if (!seed || !SEED_RE.test(seed)) throw fail('anchor_seed_invalid');
  if (!deployment || !DEPLOYMENT_RE.test(deployment)) throw fail('anchor_deployment_invalid');
  return vkeyOf(originOf(deployment), anchorSigner(seed).publicKeyRaw);
}

function main() {
  if (process.argv.length !== 2) {
    process.stderr.write('usage: node scripts/audit-checkpoint-pubkey.js\n');
    process.exit(2);
  }
  if (process.env.ENV_FILE !== undefined && process.env.ENV_FILE.trim() === '') {
    process.stderr.write('env_file_empty\n');
    process.exit(2);
  }
  require('dotenv').config({ path: process.env.ENV_FILE || path.join(__dirname, '..', '.env.production'), quiet: true });
  try {
    process.stdout.write(`${vkeyFromEnv(process.env)}\n`);
  } catch (err) {
    process.stderr.write(`${err.code === 'anchor_deployment_invalid' ? err.code : 'anchor_seed_invalid'}\n`);
    process.exit(2);
  }
}

if (require.main === module) main();

module.exports = { vkeyFromEnv };
