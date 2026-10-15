#!/usr/bin/env node
// Threats: a TCP or file channel opened wider than the operator meant (a CIDR
// pivot, a file root of "/" or the agent's own state, file:root), a policy
// written to a host in another tenant, and a policy change with no audit
// trail. There is no HTTP route that sets cp_hosts.tcp_policy or file_policy;
// this CLI is the server-side way to set ONE host's policy, run ON the server
// as the service user with the production env file (like
// scripts/bootstrap-admin.js). It is deliberately narrow: TCP entries are
// only "local" ports (the agent dials 127.0.0.1; no CIDR, no remote address),
// file entries are absolute directories with read, or read and write (never
// "/", "~" or root), and the host must resolve to exactly one host of the
// named tenant. `set` replaces BOTH host columns, so nothing from an earlier
// policy lingers; `clear` is an explicit deny on the host (tcp_policy
// {allow:[]}, file_policy {roots:[]}), which a tenant default does not
// override; `inherit` sets both to null (back to the tenant default, else
// deny). Every set, clear and inherit appends an audit-chain row (actor
// "cli:channel-policy", the old and new policies) in the same transaction as
// the write, on one client with the host row locked (SELECT ... FOR UPDATE):
// both land or neither does. Does NOT check who runs
// it: whoever can read the env file can already write the database. Does NOT
// change what the agent itself allows: its --tcp-allow list and the file
// helper's openat2 checks still apply on the host. Does NOT set tenant
// defaults. Note: createRegistry applies the (idempotent) schema on connect,
// so even `show` runs the boot-time DDL, as every script here does.
//
// Usage: node scripts/channel-policy.js show  --tenant <t> --host <hostname|host_id>
//        node scripts/channel-policy.js set   --tenant <t> --host <hostname|host_id>
//               [--tcp-local <port>]... [--file-read <dir>]... [--file-write <dir>]...
//        node scripts/channel-policy.js clear --tenant <t> --host <hostname|host_id>
//        node scripts/channel-policy.js inherit --tenant <t> --host <hostname|host_id>
// Database and env file: as scripts/sso-bind.js (ENV_FILE, else
// .env.production beside server.js).
'use strict';

const path = require('node:path');
const { validateTenant } = require('../controlplane/sshkey');
const { validateFileRoot, effectivePolicies } = require('../controlplane/channels');

const ACTOR = 'cli:channel-policy';
const MAX_ENTRIES = 16;
const HOST_RE = /^[A-Za-z0-9._-]{1,253}$/;
const USAGE = 'usage: node scripts/channel-policy.js show|set|clear|inherit --tenant <t> --host <hostname|host_id> '
  + '[--tcp-local <port>]... [--file-read <dir>]... [--file-write <dir>]...';
const COMMANDS = new Set(['show', 'set', 'clear', 'inherit']);
// What each writing command stores in the two host columns and its audit
// action. clear is an explicit deny; inherit (null) defers to the tenant.
const WRITES = {
  clear: { action: 'channel_policy_clear', policy: () => ({ tcp_policy: { allow: [] }, file_policy: { roots: [] } }) },
  inherit: { action: 'channel_policy_inherit', policy: () => ({ tcp_policy: null, file_policy: null }) }
};
const ONCE_FLAGS = new Set(['--tenant', '--host']);
const LIST_FLAGS = new Set(['--tcp-local', '--file-read', '--file-write']);

function fail(code, message = code) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function usage(message = USAGE) {
  return fail('usage', message);
}

function parsePort(text) {
  if (typeof text !== 'string' || !/^[1-9][0-9]{0,4}$/.test(text)) throw usage(`bad --tcp-local: ${JSON.stringify(text)} is not a port 1-65535`);
  const port = Number(text);
  if (port > 65535) throw usage(`bad --tcp-local: ${text} is not a port 1-65535`);
  return port;
}

function parseDir(flag, text) {
  if (text === '/' || text === '~') throw usage(`bad ${flag}: "${text}" is too wide; name one directory`);
  const checked = validateFileRoot(text, 'file:write');
  if (!checked.ok) throw usage(`bad ${flag}: an absolute directory with no "..", ".", "//", trailing "/" or control bytes`);
  return checked.root;
}

function parseArgs(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || !COMMANDS.has(argv[0])) throw usage();
  const command = argv[0];
  const once = {};
  const lists = { '--tcp-local': [], '--file-read': [], '--file-write': [] };
  for (let i = 1; i < argv.length; i += 1) {
    const flag = argv[i];
    if (i + 1 >= argv.length) throw usage();
    const value = argv[(i += 1)];
    if (ONCE_FLAGS.has(flag)) {
      if (Object.prototype.hasOwnProperty.call(once, flag)) throw usage(`${flag} given twice`);
      once[flag] = value;
    } else if (LIST_FLAGS.has(flag)) {
      if (command !== 'set') throw usage(`${flag} is only for set`);
      lists[flag].push(value);
    } else {
      throw usage();
    }
  }
  if (once['--tenant'] === undefined || once['--host'] === undefined) throw usage();
  try {
    validateTenant(once['--tenant']);
  } catch {
    throw usage('bad --tenant: lowercase letters, digits and "-", at most 63');
  }
  if (!HOST_RE.test(once['--host'])) throw usage('bad --host: a hostname or host id');

  const out = { command, tenantId: once['--tenant'], host: once['--host'] };
  if (command !== 'set') return out;

  const ports = [...new Set(lists['--tcp-local'].map(parsePort))].sort((a, b) => a - b);
  const writes = [...new Set(lists['--file-write'].map((d) => parseDir('--file-write', d)))];
  const reads = [...new Set(lists['--file-read'].map((d) => parseDir('--file-read', d)))]
    .filter((d) => !writes.includes(d));
  if (ports.length === 0 && reads.length === 0 && writes.length === 0) {
    throw usage('set needs at least one --tcp-local, --file-read or --file-write; use clear to deny all, inherit for the tenant default');
  }
  if (ports.length > MAX_ENTRIES || reads.length + writes.length > MAX_ENTRIES) {
    throw usage(`at most ${MAX_ENTRIES} ports and ${MAX_ENTRIES} directories`);
  }
  out.tcpPolicy = { allow: ports.length ? [{ local: true, ports }] : [] };
  out.filePolicy = {
    roots: [
      ...writes.map((p) => ({ path: p, read: true, write: true })),
      ...reads.map((p) => ({ path: p, read: true, write: false }))
    ]
  };
  return out;
}

async function resolveOne(registry, tenantId, host) {
  const matches = await registry.resolveHosts([tenantId], host);
  if (!matches || matches.length === 0) throw fail('not_found', `no host ${host} in tenant ${tenantId}`);
  if (matches.length > 1) throw fail('ambiguous', `${matches.length} hosts named ${host} in tenant ${tenantId}; pass the host id`);
  const found = await registry.getHost([tenantId], matches[0].host_id);
  if (!found || found.tenant_id !== tenantId) throw fail('not_found', `no host ${host} in tenant ${tenantId}`);
  return found;
}

async function summary(registry, host) {
  const raw = (await registry.channelPolicies(host.host_id)) || {};
  const effective = await effectivePolicies(registry, host.host_id);
  return {
    tenant_id: host.tenant_id,
    host_id: host.host_id,
    hostname: host.hostname,
    host_tcp_policy: raw.host_tcp_policy ?? null,
    host_file_policy: raw.host_file_policy ?? null,
    effective_tcp_policy: effective.tcp,
    effective_file_policy: effective.file
  };
}

// Returns the summary object the CLI prints. registry is a MemoryRegistry or
// PgRegistry.
async function run(argv, { registry }) {
  const args = parseArgs(argv);
  for (const fn of ['resolveHosts', 'getHost', 'channelPolicies', 'setHostChannelPolicyAudited']) {
    if (!registry || typeof registry[fn] !== 'function') throw fail('registry_unavailable');
  }
  const host = await resolveOne(registry, args.tenantId, args.host);
  if (args.command === 'show') return summary(registry, host);

  const next = args.command === 'set'
    ? { tcp_policy: args.tcpPolicy, file_policy: args.filePolicy }
    : WRITES[args.command].policy();
  const action = args.command === 'set' ? 'channel_policy_set' : WRITES[args.command].action;
  try {
    await registry.setHostChannelPolicyAudited({
      tenantId: host.tenant_id,
      hostId: host.host_id,
      tcpPolicy: next.tcp_policy,
      filePolicy: next.file_policy,
      actor: ACTOR,
      action
    });
  } catch (err) {
    if (err.code === 'not_found' || err.code === 'bad_policy') throw err;
    throw fail('write_failed', 'the policy write or its audit row failed; the transaction was rolled back');
  }
  return summary(registry, host);
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
  const { poolFor } = require('./sso-bind');
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
    stdout.write(JSON.stringify(await run(argv, { registry })) + '\n');
  } catch (err) {
    const known = ['usage', 'not_found', 'ambiguous', 'write_failed', 'bad_policy'];
    console.error(known.includes(err.code) ? `channel-policy: ${err.code}: ${err.message}` : 'channel-policy failed: ' + (err.code || err.name || 'error'));
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) main();

module.exports = { run, main, parseArgs, ACTOR, MAX_ENTRIES };
