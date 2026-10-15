#!/usr/bin/env node
// Threats: a fresh database with no way to mint the first credential (so
// someone reaches for a manual INSERT with a hand-rolled hash), a second
// "first admin" minted silently on a live install, and the first key leaking
// through logs, files or a retried run. Run ON the server as the service
// user with the production env file. It mints the key through the app's own
// AuthManager.insertAPIKey (same generator, ak_live_ prefix, bcrypt hash,
// api_site "systemapi") and writes, in ONE transaction: the tenant (created
// when missing), an admin membership, the key, its admin scope row, an
// audit-chain row (actor "bootstrap:admin", action "bootstrap_admin", key as
// a fingerprint) and, with --sso-sub, the SSO binding through the same
// registry code PUT .../members/:user/sso and scripts/sso-bind.js use. It is
// refused while any admin member or admin-scoped key exists, unless
// --force-additional, which the audit row records. The plaintext key is
// written once to stdout after COMMIT and nowhere else: not to stderr, a log
// or a file; errors print only a code. Does NOT check who runs it: whoever
// can read the env file can already write the database. Does NOT expire the
// key; revoke it with DELETE /playground/api-keys/:keyId once named admins
// have their own.
//
// Usage: node scripts/bootstrap-admin.js --tenant <tenant> --member <user_id>
//          [--email <email>] [--sso-sub <authentik_sub>] [--key-name <name>]
//          [--force-additional]
// Database and env file: as scripts/sso-bind.js (ENV_FILE, else
// .env.production beside server.js).
'use strict';

const path = require('node:path');
const AuthManager = require('../playground/auth');
const { validateTenant } = require('../controlplane/sshkey');
const { validSsoSub, USER_RE } = require('../controlplane/oauth');
const { poolFor } = require('./sso-bind');

const ACTOR = 'bootstrap:admin';
const API_SITE = 'systemapi';
const USAGE = 'usage: node scripts/bootstrap-admin.js --tenant <tenant> --member <user_id> '
  + '[--email <email>] [--sso-sub <authentik_sub>] [--key-name <name>] [--force-additional]';
const VALUE_FLAGS = new Set(['--tenant', '--member', '--email', '--sso-sub', '--key-name']);

function usage(message = USAGE) {
  const err = new Error(message);
  err.code = 'usage';
  return err;
}

function parseArgs(argv) {
  const out = { force: false };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (flag === '--force-additional') {
      if (out.force) throw usage();
      out.force = true;
      continue;
    }
    if (!VALUE_FLAGS.has(flag) || i + 1 >= argv.length) throw usage();
    const key = flag.slice(2);
    if (Object.prototype.hasOwnProperty.call(out, key)) throw usage();
    out[key] = argv[(i += 1)];
  }
  if (out.tenant === undefined || out.member === undefined) throw usage();
  try {
    validateTenant(out.tenant);
  } catch {
    throw usage('bad --tenant: lowercase letters, digits and "-", at most 63');
  }
  if (!USER_RE.test(out.member)) throw usage('bad --member: letters, digits and . _ @ -, at most 129');
  if (out.email !== undefined && (out.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(out.email))) {
    throw usage('bad --email');
  }
  if (out['sso-sub'] !== undefined && !validSsoSub(out['sso-sub'])) throw usage('bad --sso-sub');
  const keyName = out['key-name'] === undefined ? 'bootstrap-admin' : out['key-name'];
  if (keyName.length === 0 || keyName.length > 255) throw usage('bad --key-name');
  return {
    tenantId: out.tenant,
    userId: out.member,
    email: out.email || null,
    sub: out['sso-sub'] === undefined ? null : out['sso-sub'],
    keyName,
    force: out.force
  };
}

// Returns { summary, apiKey }. The caller prints apiKey once.
async function run(argv, { registry, pool }) {
  const args = parseArgs(argv);
  if (!registry || typeof registry.bootstrapAdmin !== 'function') {
    const err = new Error('registry_unavailable');
    err.code = 'registry_unavailable';
    throw err;
  }
  const keys = new AuthManager(null, null, null, API_SITE, pool);
  const out = await registry.bootstrapAdmin({
    tenantId: args.tenantId,
    userId: args.userId,
    email: args.email,
    sub: args.sub,
    force: args.force,
    actor: ACTOR,
    mintKey: (client) => keys.insertAPIKey(client, args.userId, args.keyName, {
      description: args.force ? 'additional admin (bootstrap --force-additional)' : 'first admin (bootstrap)'
    })
  });
  const { key_secret: apiKey, ...summary } = out;
  return { summary, apiKey };
}

async function main(argv = process.argv.slice(2), stdout = process.stdout) {
  if (process.env.ENV_FILE !== undefined && process.env.ENV_FILE.trim() === '') {
    console.error('ENV_FILE is set but empty; unset it or name a file');
    process.exitCode = 2;
    return;
  }
  try {
    parseArgs(argv);
  } catch (err) {
    console.error(err.message);
    process.exitCode = 2;
    return;
  }
  require('dotenv').config({ path: process.env.ENV_FILE || path.join(__dirname, '..', '.env.production'), quiet: true });
  const pool = poolFor(process.env);
  if (!pool) {
    console.error('no database configured (DB_PASSWORD or DATABASE_URL)');
    process.exitCode = 2;
    return;
  }
  try {
    const { createRegistry } = require('../controlplane/registry');
    const registry = await createRegistry({
      pool,
      env: { ...process.env, NODE_ENV: 'production' },
      logger: { log() {}, warn() {}, error() {} }
    });
    const { summary, apiKey } = await run(argv, { registry, pool });
    if (summary.forced) console.error('bootstrap-admin: --force-additional used; recorded in the audit chain');
    console.error('bootstrap-admin: the api_key below is shown once and stored only as a bcrypt hash');
    stdout.write(JSON.stringify({ ...summary, api_key: apiKey }) + '\n');
  } catch (err) {
    console.error(err.code === 'usage' ? err.message : 'bootstrap-admin failed: ' + (err.code || err.name || 'error'));
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) main();

module.exports = { run, main, parseArgs, ACTOR };
