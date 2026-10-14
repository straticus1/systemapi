#!/usr/bin/env node
// Threats: an SSO identity bound to a member with no audit trail, and a sub
// moved silently from one member to another. Server-side bootstrap only: it
// needs the control plane's database credentials (the same env file as
// server.js) and writes through the registry, so every binding gets the same
// audit-chain rows as the admin API (actor "bootstrap:sso-bind"). A sub
// already bound to another member is refused (409). Does NOT check who runs
// it; whoever can read the env file can already write the database.
//
// Usage: node scripts/sso-bind.js bind <member_user_id> <authentik_sub>
//        node scripts/sso-bind.js unbind <member_user_id>
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { bindSsoAudited, unbindSsoAudited } = require('../controlplane/oauth');

const ACTOR = 'bootstrap:sso-bind';

async function run(argv, registry) {
  const [command, userId, sub] = argv;
  if (command === 'bind' && argv.length === 3) {
    return bindSsoAudited(registry, { userId, sub, actor: ACTOR });
  }
  if (command === 'unbind' && argv.length === 2) {
    return unbindSsoAudited(registry, { userId, actor: ACTOR });
  }
  const err = new Error('usage: sso-bind.js bind <member_user_id> <authentik_sub> | unbind <member_user_id>');
  err.code = 'usage';
  throw err;
}

async function main() {
  if (process.env.ENV_FILE !== undefined && process.env.ENV_FILE.trim() === '') {
    console.error('ENV_FILE is set but empty; unset it or name a file');
    process.exit(2);
  }
  require('dotenv').config({ path: process.env.ENV_FILE || path.join(__dirname, '..', '.env.production'), quiet: true });
  const { Pool } = require('pg');
  const { createRegistry } = require('../controlplane/registry');
  const env = process.env;
  let pool;
  if (env.DB_PASSWORD) {
    const ssl = env.DB_SSL === 'disable' ? false : { rejectUnauthorized: true, minVersion: 'TLSv1.3' };
    if (ssl && env.DB_SSL_CA) ssl.ca = fs.readFileSync(env.DB_SSL_CA);
    pool = new Pool({
      host: env.DB_HOST || 'db.systemapi.io',
      port: env.DB_PORT || 5432,
      user: env.DB_USER || 'playground_user',
      password: env.DB_PASSWORD,
      database: env.DB_NAME || 'systemapi_playground',
      ssl
    });
  } else if (env.DATABASE_URL) {
    pool = new Pool({ connectionString: env.DATABASE_URL });
  } else {
    console.error('no database configured (DB_PASSWORD or DATABASE_URL)');
    process.exit(2);
  }
  try {
    const registry = await createRegistry({ pool, env: { ...env, NODE_ENV: 'production' }, logger: { log() {}, warn() {}, error: console.error } });
    const out = await run(process.argv.slice(2), registry);
    console.log(JSON.stringify(out));
  } catch (err) {
    console.error(err.code === 'usage' ? err.message : 'sso-bind failed: ' + (err.code || err.name || 'error'));
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) main();

module.exports = { run, ACTOR };
