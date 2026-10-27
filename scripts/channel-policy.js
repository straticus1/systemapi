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
// act only on a listed unit), and --package entries are package names on a
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
const { validateFileRoot, effectivePolicies, SERVICE_UNIT_RE, PACKAGE_NAME_RE, SYSCTL_KEY_RE, sysctlDenied } = require('../controlplane/channels');

const ACTOR = 'cli:channel-policy';
const MAX_ENTRIES = 16;
const HOST_RE = /^[A-Za-z0-9._-]{1,253}$/;
const SYSTEM_ROOTS = ['/proc', '/sys', '/dev', '/boot', '/etc', '/root', '/var/lib/systemapi-agent',
  '/etc/systemapi-agent', '/var/lib/postgresql', '/etc/sahcore'];
const USAGE = 'usage: node scripts/channel-policy.js show|set|clear|inherit --tenant <t> --host <hostname|host_id> '
  + '[--reason <text>, required except for show] [--tcp-local <port>]... [--file-read <dir>]... [--file-write <dir>]... [--service <unit>]... [--package <name>]... [--config <dir>]... [--tweak-sysctl <key>]... [--tweak-unit <unit>]...';
const REASON_MAX = 256;
const COMMANDS = new Set(['show', 'set', 'clear', 'inherit']);
// What each writing command stores in the two host columns and its audit
// action. clear is an explicit deny; inherit (null) defers to the tenant.
const WRITES = {
  clear: { action: 'channel_policy_clear', policy: () => ({ tcp_policy: { allow: [] }, file_policy: { roots: [] }, service_policy: { units: [] }, package_policy: { names: [] }, config_policy: { paths: [] }, tweak_policy: { sysctls: [], units: [] } }) },
  inherit: { action: 'channel_policy_inherit', policy: () => ({ tcp_policy: null, file_policy: null, service_policy: null, package_policy: null, config_policy: null, tweak_policy: null }) }
};
const ONCE_FLAGS = new Set(['--tenant', '--host', '--reason']);
const LIST_FLAGS = new Set(['--tcp-local', '--file-read', '--file-write', '--service', '--package', '--config', '--tweak-sysctl', '--tweak-unit']);
// The agent's and server's own config/state: never an allowed sys:config path,
// so the config channel can never rewrite the agent's own config (a lockout
// risk the design calls out) or the server's.
// Also the mutation helpers' replay store and trust file and the agent's unit.
// Mirrors systemapi-agent/config_helper.go configSelfRoots; the shared vectors
// in controlplane/testdata/config-self-vectors.json keep the two in parity.
const CONFIG_SELF_ROOTS = ['/proc', '/sys', '/dev', '/boot', '/var/lib/systemapi-agent',
  '/etc/systemapi-agent', '/var/lib/postgresql', '/etc/sahcore',
  '/var/lib/sah-helper', '/etc/systemapi-agent/helper-trust.json',
  '/etc/systemd/system/systemapi-agent.service', '/etc/systemd/system/systemapi-agent.service.d'];
// Unit dirs whose entries systemd applies to the agent and helpers; entries
// are matched by pattern (systemdSelfEntry), mirroring configSystemdUnitDirs,
// configHelperUnitRE and configSystemdSelfEntry in config_helper.go.
const SYSTEMD_UNIT_DIRS = ['/etc/systemd/system', '/etc/systemd/system.control'];
const HELPER_UNIT_RE = /^sah-[^/]*-helper@[^/]*\.service$/;

// systemdSelfEntry: name (one entry directly under a unit dir) is the agent's
// or a helper's unit, or a drop-in dir that applies to one (<unit>.d, the
// top-level service.d, or a prefix drop-in <p>-.service.d covering them).
function systemdSelfEntry(name) {
  const unit = name.endsWith('.d') ? name.slice(0, -2) : name;
  if (unit === 'systemapi-agent.service' || unit === 'service' || HELPER_UNIT_RE.test(unit)) return true;
  if (unit !== name && unit.endsWith('-.service')) {
    const p = unit.slice(0, -'.service'.length);
    return 'systemapi-agent'.startsWith(p) || p.startsWith('sah-');
  }
  return false;
}

// configSelfDenied: path is, or sits beneath, a self-root or a systemd entry
// that applies to the agent or a helper. The same check the helper applies to
// a write target (configTargetDenied).
function configSelfDenied(path) {
  if (CONFIG_SELF_ROOTS.some((s) => path === s || path.startsWith(`${s}/`))) return true;
  for (const d of SYSTEMD_UNIT_DIRS) {
    if (path.startsWith(`${d}/`) && systemdSelfEntry(path.slice(d.length + 1).split('/')[0])) return true;
  }
  return false;
}

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

function parseUnit(text) {
  if (typeof text !== 'string' || !SERVICE_UNIT_RE.test(text)) {
    throw usage(`bad --service: ${JSON.stringify(text)} is not a unit name (letters, digits, "@._:-", at most 128)`);
  }
  return text;
}

function parsePackage(text) {
  if (typeof text !== 'string' || !PACKAGE_NAME_RE.test(text)) {
    throw usage(`bad --package: ${JSON.stringify(text)} is not a package name (letters, digits, ".+_-", at most 128; no "*")`);
  }
  return text;
}

// A --config path prefix: an absolute directory of at least two components
// (so /etc alone is too broad), not the agent's or server's own config/state.
// Unlike --file-* it may sit under /etc, which is the point of sys:config.
function parseConfigDir(text) {
  if (text === '/' || text === '~') throw usage(`bad --config: "${text}" is too wide; name one directory`);
  const checked = validateFileRoot(text, 'file:write');
  if (!checked.ok) throw usage('bad --config: an absolute directory with no "..", ".", "//", trailing "/" or control bytes');
  const root = checked.root;
  if (root.split('/').length - 1 < 2) throw usage(`bad --config: "${root}" is too wide; name a directory at least two levels down`);
  // A grant at or above a unit dir would contain the agent's and helpers' units.
  const self = configSelfDenied(root) ? root
    : [...CONFIG_SELF_ROOTS, ...SYSTEMD_UNIT_DIRS].find((s) => s === root || s.startsWith(`${root}/`));
  if (self) throw usage(`bad --config: "${root}" is, sits in or contains the protected path ${self}`);
  return root;
}

function parseTweakSysctl(text) {
  if (typeof text !== 'string' || !SYSCTL_KEY_RE.test(text) || sysctlDenied(text)) {
    throw usage(`bad --tweak-sysctl: ${JSON.stringify(text)} is not an allowable sysctl key (lowercase letters, digits, ".", "_"; not a hard-denied key)`);
  }
  return text;
}

function parseTweakUnit(text) {
  if (typeof text !== 'string' || !SERVICE_UNIT_RE.test(text)) {
    throw usage(`bad --tweak-unit: ${JSON.stringify(text)} is not a unit name`);
  }
  // Same refusal as the override helper's overrideResolve: never the agent's
  // or a helper's unit, nor a drop-in that applies to them.
  if (systemdSelfEntry(`${text}.d`)) throw usage(`bad --tweak-unit: ${JSON.stringify(text)} is the agent's or a helper's unit`);
  return text;
}

function parseDir(flag, text) {
  if (text === '/' || text === '~') throw usage(`bad ${flag}: "${text}" is too wide; name one directory`);
  const checked = validateFileRoot(text, 'file:write');
  if (!checked.ok) throw usage(`bad ${flag}: an absolute directory with no "..", ".", "//", trailing "/" or control bytes`);
  const root = checked.root;
  if (root.split('/').length - 1 < 2) throw usage(`bad ${flag}: "${root}" is too wide; name a directory at least two levels down`);
  const sys = SYSTEM_ROOTS.find((s) => root === s || root.startsWith(`${s}/`) || s.startsWith(`${root}/`));
  if (sys) throw usage(`bad ${flag}: "${root}" is, sits in or contains the system path ${sys}`);
  return root;
}

function parseArgs(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || !COMMANDS.has(argv[0])) throw usage();
  const command = argv[0];
  const once = {};
  const lists = { '--tcp-local': [], '--file-read': [], '--file-write': [], '--service': [], '--package': [], '--config': [], '--tweak-sysctl': [], '--tweak-unit': [] };
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
  } else if (typeof reason !== 'string' || reason.trim() === '' || reason.length > REASON_MAX
    || /[\u0000-\u001f\u007f]/.test(reason)) {
    throw usage(`${command} needs --reason "<why>": 1-${REASON_MAX} characters, no control bytes`);
  }

  const out = { command, tenantId: once['--tenant'], host: once['--host'] };
  if (command !== 'show') out.reason = reason.trim();
  if (command !== 'set') return out;

  const ports = [...new Set(lists['--tcp-local'].map(parsePort))].sort((a, b) => a - b);
  const writes = [...new Set(lists['--file-write'].map((d) => parseDir('--file-write', d)))];
  const reads = [...new Set(lists['--file-read'].map((d) => parseDir('--file-read', d)))]
    .filter((d) => !writes.includes(d));
  const units = [...new Set(lists['--service'].map(parseUnit))].sort();
  const names = [...new Set(lists['--package'].map(parsePackage))].sort();
  const configs = [...new Set(lists['--config'].map(parseConfigDir))].sort();
  const tweakSysctls = [...new Set(lists['--tweak-sysctl'].map(parseTweakSysctl))].sort();
  const tweakUnits = [...new Set(lists['--tweak-unit'].map(parseTweakUnit))].sort();
  if (ports.length === 0 && reads.length === 0 && writes.length === 0 && units.length === 0 && names.length === 0
    && configs.length === 0 && tweakSysctls.length === 0 && tweakUnits.length === 0) {
    throw usage('set needs at least one --tcp-local, --file-read, --file-write, --service, --package, --config, --tweak-sysctl or --tweak-unit; use clear to deny all, inherit for the tenant default');
  }
  if (ports.length > MAX_ENTRIES || reads.length + writes.length > MAX_ENTRIES || units.length > MAX_ENTRIES
    || names.length > MAX_ENTRIES || configs.length > MAX_ENTRIES || tweakSysctls.length > MAX_ENTRIES || tweakUnits.length > MAX_ENTRIES) {
    throw usage(`at most ${MAX_ENTRIES} entries of each kind`);
  }
  out.tcpPolicy = { allow: ports.length ? [{ local: true, ports }] : [] };
  out.filePolicy = {
    roots: [
      ...writes.map((p) => ({ path: p, read: true, write: true })),
      ...reads.map((p) => ({ path: p, read: true, write: false }))
    ]
  };
  out.servicePolicy = { units };
  out.packagePolicy = { names };
  out.configPolicy = { paths: configs };
  out.tweakPolicy = { sysctls: tweakSysctls, units: tweakUnits };
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
      reason: args.reason
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
