#!/usr/bin/env node
// Threats: a new tenant created by hand-written SQL with no audit row, and
// an agent key for it that reaches the operator's other tenants. Run ON the
// server as the service user with the production env file. In ONE
// transaction (PgRegistry.createTenant) it writes: the tenant (refused if it
// exists), the named admin as its admin member (refused unless already an
// admin member somewhere), a fresh agent member as a viewer (refused if that
// id belongs to any tenant), an API key for the agent member minted through
// AuthManager.insertAPIKey, bound to the tenant (playground_api_keys.tenant_id,
// so it enrolls only there), with no scope rows (no API scopes) and an empty
// endpoint allowlist (refused on every /playground route, so it cannot mint
// sibling keys), and an audit-chain row (actor "operator:create-tenant", action "tenant_create",
// key as a fingerprint). The plaintext key is written once to stdout after
// COMMIT and nowhere else; errors print only a code. Does NOT check who runs
// it: whoever can read the env file can already write the database. Does NOT
// expire the key; an admin of the tenant revokes it with
// POST /api/v1/keys/:keyId/revoke (key_id is in the printed line).
//
// Usage: node scripts/create-tenant.js --tenant <tenant> --admin <user_id>
//          --agent-member <user_id> [--key-name <name>]
// Database and env file: as scripts/sso-bind.js (ENV_FILE, else
// .env.production beside server.js).
'use strict';

const path = require('node:path');
const AuthManager = require('../playground/auth');
const { validateTenant } = require('../controlplane/sshkey');
const { USER_RE } = require('../controlplane/oauth');
const { poolFor } = require('./sso-bind');

const ACTOR = 'operator:create-tenant';
const API_SITE = 'systemapi';
const USAGE = 'usage: node scripts/create-tenant.js --tenant <tenant> --admin <user_id> '
  + '--agent-member <user_id> [--key-name <name>]';
const VALUE_FLAGS = new Set(['--tenant', '--admin', '--agent-member', '--key-name']);

function usage(message = USAGE) {
  const err = new Error(message);
  err.code = 'usage';
  return err;
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!VALUE_FLAGS.has(flag) || i + 1 >= argv.length) throw usage();
    const key = flag.slice(2);
    if (Object.prototype.hasOwnProperty.call(out, key)) throw usage();
    out[key] = argv[(i += 1)];
  }
  if (out.tenant === undefined || out.admin === undefined || out['agent-member'] === undefined) throw usage();
  try {
    validateTenant(out.tenant);
  } catch {
    throw usage('bad --tenant: lowercase letters, digits and "-", at most 63');
  }
  if (!USER_RE.test(out.admin)) throw usage('bad --admin: letters, digits and . _ @ -, at most 129');
  if (!USER_RE.test(out['agent-member'])) throw usage('bad --agent-member: letters, digits and . _ @ -, at most 129');
  if (out.admin === out['agent-member']) throw usage('--agent-member must differ from --admin');
  const keyName = out['key-name'] === undefined ? `${out.tenant}-agent` : out['key-name'];
  if (keyName.length === 0 || keyName.length > 255) throw usage('bad --key-name');
  return { tenantId: out.tenant, adminUserId: out.admin, agentUserId: out['agent-member'], keyName };
}

// Returns { summary, apiKey }. The caller prints apiKey once.
async function run(argv, { registry, pool }) {
  const args = parseArgs(argv);
  if (!registry || typeof registry.createTenant !== 'function') {
    const err = new Error('registry_unavailable');
    err.code = 'registry_unavailable';
    throw err;
  }
  const keys = new AuthManager(null, null, null, API_SITE, pool);
  const out = await registry.createTenant({
    tenantId: args.tenantId,
    adminUserId: args.adminUserId,
    agentUserId: args.agentUserId,
    actor: ACTOR,
    mintKey: (client) => keys.insertAPIKey(client, args.agentUserId, args.keyName, {
      description: `agent enroll key for tenant ${args.tenantId} (create-tenant)`,
      tenantId: args.tenantId,
      // Matches no /playground route, so the key cannot mint, list, lock or
      // unlock keys there; FleetManager.verifyApiKey (enroll, control plane)
      // does not read it.
      allowedEndpoints: []
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
    console.error('create-tenant: the api_key below is shown once and stored only as a bcrypt hash');
    stdout.write(JSON.stringify({ ...summary, api_key: apiKey }) + '\n');
  } catch (err) {
    console.error(err.code === 'usage' ? err.message : 'create-tenant failed: ' + (err.code || err.name || 'error'));
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) main();

module.exports = { run, main, parseArgs, ACTOR };
