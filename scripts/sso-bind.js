#!/usr/bin/env node
// Threats: an SSO identity bound to a member with no audit trail, and one
// Authentik sub moved silently onto a second member id. Server-side bootstrap
// for the first admin (after that, admins use PUT
// /api/v1/tenants/:tenant/members/:user/sso). It writes through the registry,
// so the binding and its audit-chain row commit together (actor
// "bootstrap:sso-bind"); a sub already bound to another member id is refused
// (sso_sub_taken). Does NOT check who runs it: whoever can read the env file
// can already write the database. Prints no sub, email or credential.
//
// Usage: node scripts/sso-bind.js <tenant> <member_user_id> <authentik_sub>
// Database: the one server.js uses (DB_PASSWORD with DB_HOST/DB_PORT/DB_USER/
// DB_NAME, else DATABASE_URL), read from ENV_FILE or .env.production beside
// server.js. The sub is the Authentik "sub" claim with the provider's
// sub_mode set to hashed_user_id.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { setSsoSubAudited } = require('../controlplane/oauth');

const ACTOR = 'bootstrap:sso-bind';
const USAGE = 'usage: node scripts/sso-bind.js <tenant> <member_user_id> <authentik_sub>';

async function run(argv, registry) {
  if (argv.length !== 3) {
    const err = new Error(USAGE);
    err.code = 'usage';
    throw err;
  }
  const [tenantId, userId, sub] = argv;
  return setSsoSubAudited(registry, { tenantId, userId, sub, actor: ACTOR });
}

function poolFor(env) {
  const { Pool } = require('pg');
  if (env.DB_PASSWORD) {
    const ssl = env.DB_SSL === 'disable' ? false : { rejectUnauthorized: true, minVersion: 'TLSv1.3' };
    if (ssl && env.DB_SSL_CA) ssl.ca = fs.readFileSync(env.DB_SSL_CA);
    return new Pool({
      host: env.DB_HOST || 'db.systemapi.io',
      port: env.DB_PORT || 5432,
      user: env.DB_USER || 'playground_user',
      password: env.DB_PASSWORD,
      database: env.DB_NAME || 'systemapi_playground',
      ssl
    });
  }
  if (env.DATABASE_URL) return new Pool({ connectionString: env.DATABASE_URL });
  return null;
}

async function main() {
  if (process.argv.length !== 5) {
    console.error(USAGE);
    process.exit(2);
  }
  if (process.env.ENV_FILE !== undefined && process.env.ENV_FILE.trim() === '') {
    console.error('ENV_FILE is set but empty; unset it or name a file');
    process.exit(2);
  }
  require('dotenv').config({ path: process.env.ENV_FILE || path.join(__dirname, '..', '.env.production'), quiet: true });
  const pool = poolFor(process.env);
  if (!pool) {
    console.error('no database configured (DB_PASSWORD or DATABASE_URL)');
    process.exit(2);
  }
  try {
    const { createRegistry } = require('../controlplane/registry');
    const registry = await createRegistry({
      pool,
      env: { ...process.env, NODE_ENV: 'production' },
      logger: { log() {}, warn() {}, error() {} }
    });
    console.log(JSON.stringify(await run(process.argv.slice(2), registry)));
  } catch (err) {
    console.error(err.code === 'usage' ? err.message : 'sso-bind failed: ' + (err.code || err.name || 'error'));
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) main();

module.exports = { run, ACTOR };
