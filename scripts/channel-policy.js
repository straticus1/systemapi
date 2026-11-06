#!/usr/bin/env node
// Threats: a TCP or file channel opened wider than the operator meant (a CIDR
// pivot, a file root of "/" or the agent's own state, file:root), a policy
// written to a host in another tenant, and a policy change with no audit
// trail. There is no HTTP route that sets cp_hosts.tcp_policy or file_policy;
// this CLI is the server-side way to set ONE host's policy, run ON the server
// as the service user with the production env file (like
// scripts/bootstrap-admin.js). It is deliberately narrow: TCP entries are
// only "local" ports (the agent dials 127.0.0.1; no CIDR, no remote address),
// file entries are absolute directories of at least two components with
// read, or read and write (never file:root), that are neither a system root
// (SYSTEM_ROOTS: /proc /sys /dev /boot /etc /root, the agent's and the
// server's own state and config, PostgreSQL's data), beneath one, nor a
// parent of one (so /var/lib is refused too), and --service entries are unit
// names on a per-host allowlist (deny by default; the sys:service channel may
// act only on a listed unit; never the agent's own unit or a sah-*-helper@
// unit), and --package entries are package names on a
// per-host allowlist (deny by default; each must match the package-name shape
// so "*" is never allow-all; the sys:package channel may act only on a listed
// name),
// and --config entries are config-path prefixes on a per-host allowlist
// (deny by default; sys:config may read or write only at or beneath a listed
// path, and may never touch the agent's or server's own config), and
// --tweak-sysctl / --tweak-unit entries are the sysctl keys and units the
// sys:tweak channel may act on (deny by default; hard-denied sysctl keys are
// refused), and the host must resolve to exactly one host of the
// named tenant. `set` replaces ALL host policy columns, so nothing from an earlier
// policy lingers; `clear` is an explicit deny on the host (tcp_policy
// {allow:[]}, file_policy {roots:[]}, service_policy {units:[]}, package_policy {names:[]}),
// which a tenant default does not
// override; `inherit` sets all three to null (back to the tenant default, else
// deny). Every set, clear and inherit appends an audit-chain row (actor
// "cli:channel-policy", the operator's required --reason, the old and new
// policies) in the same transaction as
// the write, on one client with the host row locked (SELECT ... FOR UPDATE):
// both land or neither does. Does NOT check who runs
// it: whoever can read the env file can already write the database. Does NOT
// change what the agent itself allows: its --tcp-allow list and the file
// helper's openat2 checks still apply on the host. Does NOT set tenant
// defaults. Note: createRegistry applies the (idempotent) schema on connect,
// so even `show` runs the boot-time DDL, as every script here does.
//
// Usage: node scripts/channel-policy.js show  --tenant <t> --host <hostname|host_id>
//        node scripts/channel-policy.js set   --tenant <t> --host <hostname|host_id> --reason <text>
//               [--tcp-local <port>]... [--file-read <dir>]... [--file-write <dir>]... [--service <unit>]... [--package <name>]... [--config <dir>]... [--tweak-sysctl <key>]... [--tweak-unit <unit>]...
//        node scripts/channel-policy.js clear --tenant <t> --host <hostname|host_id> --reason <text>
//        node scripts/channel-policy.js inherit --tenant <t> --host <hostname|host_id> --reason <text>
// Database and env file: as scripts/sso-bind.js (ENV_FILE, else
// .env.production beside server.js).
'use strict';

const path = require('node:path');
const { validateTenant } = require('../controlplane/sshkey');
const { effectivePolicies, CONFIG_SELF_ROOTS, configSelfDenied } = require('../controlplane/channels');
// Every rule this CLI enforces lives in controlplane/policyrules.js, shared
// with the HTTP routes (controlplane/policyroutes.js).
const { MAX_ENTRIES, REASON_MAX, SYSTEM_ROOTS, GRANT_KEYS, ruleError, cliLabel, buildPolicy, clearPolicy, inheritPolicy,
  normalizeReason, POLICY_SCHEMA } = require('../controlplane/policyrules');

const ACTOR = 'cli:channel-policy';
const HOST_RE = /^[A-Za-z0-9._-]{1,253}$/;
const USAGE = 'usage: node scripts/channel-policy.js show|set|clear|inherit --tenant <t> --host <hostname|host_id> '
  + '[--reason <text>, required except for show] [--tcp-local <port>]... [--file-read <dir>]... [--file-write <dir>]... [--service <unit>]... [--package <name>]... [--config <dir>]... [--tweak-sysctl <key>]... [--tweak-unit <unit>]...';
const COMMANDS = new Set(['show', 'set', 'clear', 'inherit']);
// What each writing command stores in the host columns and its audit
// action. clear is an explicit deny; inherit (null) defers to the tenant.
const WRITES = {
  clear: { action: 'channel_policy_clear', policy: clearPolicy },
  inherit: { action: 'channel_policy_inherit', policy: inheritPolicy }
};
const ONCE_FLAGS = new Set(['--tenant', '--host', '--reason']);
const LIST_FLAGS = new Set(GRANT_KEYS.map(cliLabel));
function fail(code, message = code) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function usage(message = USAGE) {
  return ruleError('usage', message);
}

function parseArgs(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || !COMMANDS.has(argv[0])) throw usage();
  const command = argv[0];
  const once = {};
  const lists = {};
  for (const key of GRANT_KEYS) lists[cliLabel(key)] = [];
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
  const reason = once['--reason'];
  if (command === 'show') {
    if (reason !== undefined) throw usage('--reason is only for set, clear and inherit');
  } else if (normalizeReason(reason) === null) {
    throw usage(`${command} needs --reason "<why>": 1-${REASON_MAX} characters, no control bytes`);
  }

  const out = { command, tenantId: once['--tenant'], host: once['--host'] };
  if (command !== 'show') out.reason = normalizeReason(reason);
  if (command !== 'set') return out;

  const grants = {};
  for (const key of GRANT_KEYS) grants[key] = lists[cliLabel(key)];
  const policy = buildPolicy(grants, cliLabel);
  out.tcpPolicy = policy.tcp_policy;
  out.filePolicy = policy.file_policy;
  out.servicePolicy = policy.service_policy;
  out.packagePolicy = policy.package_policy;
  out.configPolicy = policy.config_policy;
  out.tweakPolicy = policy.tweak_policy;
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
    host_service_policy: raw.host_service_policy ?? null,
    host_package_policy: raw.host_package_policy ?? null,
    host_config_policy: raw.host_config_policy ?? null,
    host_tweak_policy: raw.host_tweak_policy ?? null,
    effective_tcp_policy: effective.tcp,
    effective_file_policy: effective.file,
    effective_service_policy: effective.service,
    effective_package_policy: effective.package,
    effective_config_policy: effective.config,
    effective_tweak_policy: effective.tweak
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
    ? { tcp_policy: args.tcpPolicy, file_policy: args.filePolicy, service_policy: args.servicePolicy, package_policy: args.packagePolicy, config_policy: args.configPolicy, tweak_policy: args.tweakPolicy }
    : WRITES[args.command].policy();
  const action = args.command === 'set' ? 'channel_policy_set' : WRITES[args.command].action;
  try {
    await registry.setHostChannelPolicyAudited({
      tenantId: host.tenant_id,
      hostId: host.host_id,
      tcpPolicy: next.tcp_policy,
      filePolicy: next.file_policy,
      servicePolicy: next.service_policy,
      packagePolicy: next.package_policy,
      configPolicy: next.config_policy,
      tweakPolicy: next.tweak_policy,
      actor: ACTOR,
      action,
      reason: args.reason,
      extra: { policy_schema: POLICY_SCHEMA, via: 'cli' }
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
  // poolFor reads DB_SSL_CA; an unreadable file is an error code, not a
  // stack trace.
  let pool;
  try {
    pool = poolFor(process.env);
  } catch (err) {
    console.error('channel-policy failed: ' + (err.code || err.name || 'error'));
    process.exitCode = 1;
    return;
  }
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

module.exports = { run, main, parseArgs, ACTOR, MAX_ENTRIES, SYSTEM_ROOTS, CONFIG_SELF_ROOTS, configSelfDenied };
