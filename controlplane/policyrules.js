'use strict';

// Channel-policy rules (plan sah-fleet-readiness P2a): what a host or tenant
// channel policy may hold beyond the storage parse* shapes of channels.js.
// The break-glass CLI (scripts/channel-policy.js) and the HTTP routes
// (controlplane/policyroutes.js) build every policy through buildPolicy or
// normalizeColumns here, so the two front ends cannot drift
// (tests/policy-rules.test.js feeds both the same inputs).
//
// Threats: a channel opened wider than meant (a CIDR, range or remote TCP
// target, file:root, "/" or a system root for file, the agent's or a
// helper's own unit, the agent's or server's own config, a hard-denied
// sysctl), an unbounded policy (16 entries of each kind), a reason that
// carries control bytes into the audit log, a lost update between two
// admins (policyVersion pins exactly what a write replaces) and a
// root-equivalent grant slipping through unnoticed (dangerousEntries names
// each one for the routes' step-up gate). A refusal carries a fixed rule
// code (err.rule) and a message that names only the operator's own input.
// Does NOT authenticate, authorize or store anything; does NOT see what the
// agent itself allows (its --tcp-allow list and openat2 checks still apply).

const crypto = require('node:crypto');
const { canonicalJSON } = require('./chain');
const {
  validateFileRoot, SERVICE_UNIT_RE, PACKAGE_NAME_RE, SYSCTL_KEY_RE, sysctlDenied, systemdSelfEntry,
  configPrefixProtected, parseTcpPolicy, parseFilePolicy, parseServicePolicy, parsePackagePolicy,
  parseConfigPolicy, parseTweakPolicy
} = require('./channels');

const MAX_ENTRIES = 16;
const REASON_MAX = 256;
const SYSTEM_ROOTS = ['/proc', '/sys', '/dev', '/boot', '/etc', '/root', '/var/lib/systemapi-agent',
  '/etc/systemapi-agent', '/var/lib/postgresql', '/etc/sahcore'];
// The six policy kinds, in column order, and their cp_hosts / cp_tenants
// columns.
const POLICY_KINDS = Object.freeze(['tcp', 'file', 'service', 'package', 'config', 'tweak']);
const COLUMNS = Object.freeze(POLICY_KINDS.map((k) => `${k}_policy`));
// The grant lists a policy is built from, in the order they are checked.
// The CLI spells each as a flag (tcp_local is --tcp-local).
const GRANT_KEYS = Object.freeze(['tcp_local', 'file_write', 'file_read', 'service', 'package', 'config', 'tweak_sysctl', 'tweak_unit']);
// The order the "needs at least one" message names them in.
const GRANT_NAMES = Object.freeze(['tcp_local', 'file_read', 'file_write', 'service', 'package', 'config', 'tweak_sysctl', 'tweak_unit']);
// Units whose service grant is dangerous (P2c): they hold the way back in
// (ssh, the agent, its helpers, the tunnel, networking, D-Bus, logind) or the
// control plane's own state. Globs over full unit names; a trailing "*" also
// covers the .socket and @-instances. Until host profiles (P3a) add a host's
// NEIGHBOURS, this fixed list is all.
// Targets (*.target: isolating or stopping one stops what it pulls in) and
// the host firewall (nftables, ufw, firewalld, iptables) are protected too.
const PROTECTED_UNIT_GLOBS = Object.freeze(['ssh*', 'sshd*', 'sahcore*', '*cloudflared*', 'postgresql*', 'redis*',
  'systemapi-agent*', 'sah-*-helper@*', 'dbus*', 'systemd-networkd*', 'networking*', 'NetworkManager*',
  'systemd-resolved*', 'systemd-logind*', '*.target', 'nftables*', 'ufw*', 'firewalld*', 'iptables*']);
// Config prefixes whose grant is not dangerous (P2c): nginx's site and
// conf.d dirs, included only inside its http block (no load_module, no
// user directive there). Every other config path, under /etc or not, is
// dangerous: a root-run service reads it. Lower risk, not no risk: a site
// can still proxy or serve what nginx can reach.
const SAFE_CONFIG_PREFIXES = Object.freeze(['/etc/nginx/sites-available', '/etc/nginx/sites-enabled', '/etc/nginx/conf.d']);
const PROTECTED_UNIT_RES = PROTECTED_UNIT_GLOBS.map((g) => new RegExp(`^${g.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 'i'));
// The marker every policy audit row carries from P2 on: all six previous
// and new kinds are recorded explicitly, so a revert never reads "not
// recorded" as "inherit".
const POLICY_SCHEMA = 2;
const TENANT_WRITE = 'tenant_write';

function ruleError(rule, message) {
  const err = new Error(message);
  err.code = 'usage';
  err.rule = rule;
  return err;
}

// The CLI's flag for a grant key; the routes name the key itself.
function cliLabel(key) {
  return `--${key.replace(/_/g, '-')}`;
}

function apiLabel(key) {
  return key;
}

function parsePort(text, label = '--tcp-local') {
  if (typeof text !== 'string' || !/^[1-9][0-9]{0,4}$/.test(text)) throw ruleError('bad_port', `bad ${label}: ${JSON.stringify(text)} is not a port 1-65535`);
  const port = Number(text);
  if (port > 65535) throw ruleError('bad_port', `bad ${label}: ${text} is not a port 1-65535`);
  return port;
}

function parseUnit(text, label = '--service') {
  if (typeof text !== 'string' || !SERVICE_UNIT_RE.test(text)) {
    throw ruleError('bad_unit', `bad ${label}: ${JSON.stringify(text)} is not a unit name (letters, digits, "@._:-", at most 128)`);
  }
  // Never the agent's own unit nor a mutation helper's: stopping or disabling
  // the agent cuts the host off, and a helper unit is started only by the
  // agent's handoff. systemctl reads a bare name as <name>.service.
  if (systemdSelfEntry(text) || systemdSelfEntry(`${text}.service`)) {
    throw ruleError('self_unit', `bad ${label}: ${JSON.stringify(text)} is the agent's or a helper's unit`);
  }
  return text;
}

function parsePackage(text, label = '--package') {
  if (typeof text !== 'string' || !PACKAGE_NAME_RE.test(text)) {
    throw ruleError('bad_package', `bad ${label}: ${JSON.stringify(text)} is not a package name (letters, digits, ".+_-", at most 128; no "*")`);
  }
  return text;
}

// An absolute directory of at least two components; the shared shape of
// file and config grants. "/" and "~" are refused by name.
function parseTwoLevelDir(text, label, rule) {
  if (text === '/' || text === '~') throw ruleError('too_wide', `bad ${label}: "${text}" is too wide; name one directory`);
  const checked = validateFileRoot(text, 'file:write');
  if (!checked.ok) throw ruleError(rule, `bad ${label}: an absolute directory with no "..", ".", "//", trailing "/" or control bytes`);
  const root = checked.root;
  if (root.split('/').length - 1 < 2) throw ruleError('too_wide', `bad ${label}: "${root}" is too wide; name a directory at least two levels down`);
  return root;
}

// A config path prefix: not the agent's or server's own config/state. Unlike
// a file grant it may sit under /etc, which is the point of sys:config.
function parseConfigDir(text, label = '--config') {
  const root = parseTwoLevelDir(text, label, 'bad_path');
  // A grant at or above a unit dir would contain the agent's and helpers' units.
  const self = configPrefixProtected(root);
  if (self) throw ruleError('protected_path', `bad ${label}: "${root}" is, sits in or contains the protected path ${self}`);
  return root;
}

function parseTweakSysctl(text, label = '--tweak-sysctl') {
  if (typeof text !== 'string' || !SYSCTL_KEY_RE.test(text) || sysctlDenied(text)) {
    throw ruleError('bad_sysctl', `bad ${label}: ${JSON.stringify(text)} is not an allowable sysctl key (dot-separated non-empty segments of lowercase letters, digits, "_"; not a hard-denied key)`);
  }
  return text;
}

function parseTweakUnit(text, label = '--tweak-unit') {
  if (typeof text !== 'string' || !SERVICE_UNIT_RE.test(text)) {
    throw ruleError('bad_unit', `bad ${label}: ${JSON.stringify(text)} is not a unit name`);
  }
  // Same refusal as the override helper's overrideResolve: never the agent's
  // or a helper's unit, nor a drop-in that applies to them.
  if (systemdSelfEntry(`${text}.d`)) throw ruleError('self_unit', `bad ${label}: ${JSON.stringify(text)} is the agent's or a helper's unit`);
  return text;
}

// A file grant: never a system root, beneath one, nor a parent of one (so
// /var/lib is refused too).
function parseDir(text, label) {
  const root = parseTwoLevelDir(text, label, 'bad_path');
  const sys = SYSTEM_ROOTS.find((s) => root === s || root.startsWith(`${s}/`) || s.startsWith(`${root}/`));
  if (sys) throw ruleError('system_root', `bad ${label}: "${root}" is, sits in or contains the system path ${sys}`);
  return root;
}

// The grant lists, each checked, de-duplicated and (except file roots, kept
// in the order given) sorted. A missing list is empty; anything but an array
// of strings is refused.
function normalizeGrants(grants, labelOf = cliLabel) {
  if (!grants || typeof grants !== 'object' || Array.isArray(grants)) throw ruleError('bad_grants', 'grants must be an object of lists');
  for (const key of Object.keys(grants)) {
    if (!GRANT_KEYS.includes(key)) throw ruleError('bad_grants', `unknown grant ${JSON.stringify(key.slice(0, 32))}`);
  }
  const list = (key) => {
    const value = grants[key] === undefined ? [] : grants[key];
    if (!Array.isArray(value) || value.length > 4 * MAX_ENTRIES) throw ruleError('bad_grants', `${labelOf(key)} must be a list of at most ${MAX_ENTRIES} entries`);
    return value;
  };
  // The routes send ports as JSON integers; the CLI as argv strings.
  const ports = [...new Set(list('tcp_local').map((p) => parsePort(Number.isInteger(p) ? String(p) : p, labelOf('tcp_local'))))].sort((a, b) => a - b);
  const writes = [...new Set(list('file_write').map((d) => parseDir(d, labelOf('file_write'))))];
  const reads = [...new Set(list('file_read').map((d) => parseDir(d, labelOf('file_read'))))]
    .filter((d) => !writes.includes(d));
  const units = [...new Set(list('service').map((u) => parseUnit(u, labelOf('service'))))].sort();
  const names = [...new Set(list('package').map((n) => parsePackage(n, labelOf('package'))))].sort();
  const configs = [...new Set(list('config').map((c) => parseConfigDir(c, labelOf('config'))))].sort();
  const tweakSysctls = [...new Set(list('tweak_sysctl').map((k) => parseTweakSysctl(k, labelOf('tweak_sysctl'))))].sort();
  const tweakUnits = [...new Set(list('tweak_unit').map((u) => parseTweakUnit(u, labelOf('tweak_unit'))))].sort();
  return { ports, writes, reads, units, names, configs, tweakSysctls, tweakUnits };
}

function capEntries(g) {
  if (g.ports.length > MAX_ENTRIES || g.reads.length + g.writes.length > MAX_ENTRIES || g.units.length > MAX_ENTRIES
    || g.names.length > MAX_ENTRIES || g.configs.length > MAX_ENTRIES || g.tweakSysctls.length > MAX_ENTRIES || g.tweakUnits.length > MAX_ENTRIES) {
    throw ruleError('too_many', `at most ${MAX_ENTRIES} entries of each kind`);
  }
}

function columnsOf(g) {
  return {
    tcp_policy: { allow: g.ports.length ? [{ local: true, ports: g.ports }] : [] },
    file_policy: {
      roots: [
        ...g.writes.map((p) => ({ path: p, read: true, write: true })),
        ...g.reads.map((p) => ({ path: p, read: true, write: false }))
      ]
    },
    service_policy: { units: g.units },
    package_policy: { names: g.names },
    config_policy: { paths: g.configs },
    tweak_policy: { sysctls: g.tweakSysctls, units: g.tweakUnits }
  };
}

// A full replace (the CLI's set, PUT .../channel-policy): all six columns,
// at least one grant (an empty policy is clear, a null one inherit).
function buildPolicy(grants, labelOf = cliLabel) {
  const g = normalizeGrants(grants, labelOf);
  const empty = Object.values(g).every((list) => list.length === 0);
  if (empty) {
    const names = GRANT_NAMES.map(labelOf);
    throw ruleError('empty', `set needs at least one ${names.slice(0, -1).join(', ')} or ${names[names.length - 1]}; use clear to deny all, inherit for the tenant default`);
  }
  capEntries(g);
  return columnsOf(g);
}

// The grant lists one stored column holds. Refuses (rule unrepresentable)
// any shape the rules above could not have written: a CIDR or a range, a
// file:root or write-only root, an unknown key.
function grantsOfColumn(kind, value) {
  const bad = () => ruleError('unrepresentable', `the stored ${kind} policy holds an entry these rules refuse`);
  const plain = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).every((k) => keys.includes(k));
  const strings = (v) => {
    if (!Array.isArray(v) || !v.every((s) => typeof s === 'string')) throw bad();
    return v;
  };
  if (!plain(value, kind === 'tweak' ? ['sysctls', 'units'] : [{ tcp: 'allow', file: 'roots', service: 'units', package: 'names', config: 'paths' }[kind]])) throw bad();
  if (kind === 'tcp') {
    if (!Array.isArray(value.allow)) throw bad();
    const ports = [];
    for (const entry of value.allow) {
      if (!plain(entry, ['local', 'ports']) || entry.local !== true || !Array.isArray(entry.ports)) throw bad();
      for (const p of entry.ports) {
        if (!Number.isInteger(p)) throw bad();
        ports.push(String(p));
      }
    }
    return { tcp_local: ports };
  }
  if (kind === 'file') {
    if (!Array.isArray(value.roots)) throw bad();
    const out = { file_write: [], file_read: [] };
    for (const entry of value.roots) {
      if (!plain(entry, ['path', 'read', 'write']) || entry.read !== true || typeof entry.write !== 'boolean' || typeof entry.path !== 'string') throw bad();
      out[entry.write ? 'file_write' : 'file_read'].push(entry.path);
    }
    return out;
  }
  if (kind === 'service') return { service: strings(value.units) };
  if (kind === 'package') return { package: strings(value.names) };
  if (kind === 'config') return { config: strings(value.paths) };
  return { tweak_sysctl: strings(value.sysctls || []), tweak_unit: strings(value.units || []) };
}

// Six stored columns (a revert's restore) checked column by column through
// the same rules: null stays null (inherit), anything else must be what
// buildPolicy could have written. Returns the normalized columns.
function normalizeColumns(cols, labelOf = apiLabel) {
  if (!cols || typeof cols !== 'object') throw ruleError('bad_grants', 'policy columns missing');
  const out = {};
  for (const kind of POLICY_KINDS) {
    const col = `${kind}_policy`;
    const value = cols[col];
    if (value === null || value === undefined) {
      out[col] = null;
      continue;
    }
    const g = normalizeGrants(grantsOfColumn(kind, value), labelOf);
    capEntries(g);
    out[col] = columnsOf(g)[col];
  }
  return out;
}

// clear is an explicit deny a tenant default does not override; inherit (all
// null) defers to the tenant default, else deny.
function clearPolicy() {
  return { tcp_policy: { allow: [] }, file_policy: { roots: [] }, service_policy: { units: [] }, package_policy: { names: [] }, config_policy: { paths: [] }, tweak_policy: { sysctls: [], units: [] } };
}

function inheritPolicy() {
  return { tcp_policy: null, file_policy: null, service_policy: null, package_policy: null, config_policy: null, tweak_policy: null };
}

// 1-256 characters without control bytes, trimmed; null when refused.
function normalizeReason(reason) {
  if (typeof reason !== 'string' || reason.trim() === '' || reason.length > REASON_MAX
    || /[\u0000-\u001f\u007f]/.test(reason)) return null;
  return reason.trim();
}

// The six columns exactly as stored (absent is null), in one fixed shape.
function pickColumns(raw, prefix = '') {
  const out = {};
  for (const col of COLUMNS) {
    const v = raw ? raw[prefix + col] : undefined;
    out[col] = v === undefined ? null : v;
  }
  return out;
}

// sha256 over the canonical JSON of the six columns: the if_version every
// write must name, checked again under the row lock.
function policyVersion(cols) {
  return crypto.createHash('sha256').update(canonicalJSON(pickColumns(cols))).digest('hex');
}

const VERSION_RE = /^[0-9a-f]{64}$/;

// Host column when set, else the tenant's, parsed; malformed denies (as
// channels.effectivePolicies).
function effectiveOf(hostCols, tenantCols) {
  const pick = (col) => {
    const h = hostCols ? hostCols[col] : null;
    return h !== null && h !== undefined ? h : (tenantCols ? tenantCols[col] : null);
  };
  return {
    tcp: parseTcpPolicy(pick('tcp_policy')) || { allow: [] },
    file: parseFilePolicy(pick('file_policy')) || { roots: [] },
    service: parseServicePolicy(pick('service_policy')) || { units: [] },
    package: parsePackagePolicy(pick('package_policy')) || { names: [] },
    config: parseConfigPolicy(pick('config_policy')) || { paths: [] },
    tweak: parseTweakPolicy(pick('tweak_policy')) || { sysctls: [], units: [] }
  };
}

// The columns as the effective (raw, unparsed) values: what GET shows.
function effectiveColumns(hostCols, tenantCols) {
  const out = {};
  for (const col of COLUMNS) {
    const h = hostCols ? hostCols[col] : null;
    out[col] = h !== null && h !== undefined ? h : (tenantCols && tenantCols[col] !== undefined ? tenantCols[col] : null);
  }
  return out;
}

// A unit name as systemctl reads it: a bare name is <name>.service.
function unitProtected(unit) {
  if (typeof unit !== 'string') return false;
  const full = /\.[a-z]+$/.test(unit) ? unit : `${unit}.service`;
  return PROTECTED_UNIT_RES.some((re) => re.test(unit) || re.test(full));
}

function configSafe(p) {
  return SAFE_CONFIG_PREFIXES.some((a) => p === a || p.startsWith(`${a}/`));
}

// Every root-equivalent entry an effective policy holds (P2c): a config path
// outside SAFE_CONFIG_PREFIXES, any tweak unit (a drop-in can override
// ExecStart), any package (maintainer scripts run as root), a service grant
// on a protected unit.
function dangerousOf(eff) {
  const out = new Set();
  for (const p of eff.config.paths) if (!configSafe(p)) out.add(`config:${p}`);
  for (const u of eff.tweak.units) out.add(`tweak_unit:${u}`);
  for (const n of eff.package.names) out.add(`package:${n}`);
  for (const u of eff.service.units) if (unitProtected(u)) out.add(`service:${u}`);
  return out;
}

// The dangerous entries a write grants: in the effective policy after it
// and not before it, sorted. A write that keeps a dangerous grant already
// in force, or narrows, is not dangerous; restoring one (a revert) is.
function dangerousEntries(beforeEff, afterEff) {
  const before = beforeEff ? dangerousOf(beforeEff) : new Set();
  return [...dangerousOf(afterEff)].filter((e) => !before.has(e)).sort();
}

// The dangerous entries a host write grants: newly effective, or newly
// explicit at host level. Pinning a tenant-granted dangerous entry on the
// host is dangerous too: the pin keeps it after the tenant narrows.
function hostDangerousEntries(hostBefore, hostAfter, tenantCols) {
  const effective = dangerousEntries(effectiveOf(hostBefore, tenantCols), effectiveOf(hostAfter, tenantCols));
  const explicit = dangerousEntries(effectiveOf(hostBefore, null), effectiveOf(hostAfter, null));
  return [...new Set([...effective, ...explicit])].sort();
}

// The columns that change, with their old and new stored values.
function diffColumns(before, after) {
  const out = {};
  for (const col of COLUMNS) {
    const a = before ? before[col] ?? null : null;
    const b = after ? after[col] ?? null : null;
    if (canonicalJSON(a) !== canonicalJSON(b)) out[col] = { before: a, after: b };
  }
  return out;
}

// The grant lists of host columns, for a client that edits (GET, then PUT);
// null when any column is null or holds what the rules refuse.
function grantsOf(cols) {
  const out = {};
  for (const key of GRANT_KEYS) out[key] = [];
  for (const kind of POLICY_KINDS) {
    const value = cols ? cols[`${kind}_policy`] : null;
    if (value === null || value === undefined) return null;
    let g;
    try {
      g = grantsOfColumn(kind, value);
    } catch {
      return null;
    }
    for (const [k, v] of Object.entries(g)) out[k] = v.map((x) => (k === 'tcp_local' ? Number(x) : x));
  }
  return out;
}

module.exports = {
  MAX_ENTRIES,
  REASON_MAX,
  SYSTEM_ROOTS,
  POLICY_KINDS,
  COLUMNS,
  GRANT_KEYS,
  PROTECTED_UNIT_GLOBS,
  SAFE_CONFIG_PREFIXES,
  POLICY_SCHEMA,
  TENANT_WRITE,
  VERSION_RE,
  ruleError,
  cliLabel,
  apiLabel,
  parsePort,
  parseUnit,
  parsePackage,
  parseConfigDir,
  parseTweakSysctl,
  parseTweakUnit,
  parseDir,
  normalizeGrants,
  buildPolicy,
  grantsOfColumn,
  normalizeColumns,
  clearPolicy,
  inheritPolicy,
  normalizeReason,
  pickColumns,
  policyVersion,
  effectiveOf,
  effectiveColumns,
  unitProtected,
  dangerousEntries,
  hostDangerousEntries,
  diffColumns,
  grantsOf
};
