// Threats: a TCP-forward ticket used as an SSRF pivot (cloud metadata,
// link-local, multicast, loopback spelled as a literal, DNS rebinding) and a
// file ticket naming a root outside what the host's policy allows (traversal
// in the root, an empty or relative root, control bytes). Validation is
// syntactic and runs at ticket issue; stages 2 and 3 run it again at the
// upgrade. Policies are deny by default and fail closed: a malformed stored
// policy denies everything. A host policy replaces (never merges with) the
// tenant default. Does NOT resolve names (phase 0 refuses DNS names), does
// NOT see what the agent finally dials (the agent re-checks with its own
// allowlist and the refused classes), and does NOT know the pty_user's home
// directory, so "~" matches only a policy entry whose path is literally "~".
// Contracts: docs/sah-tcp-protocol.md §2, §4 and docs/sah-file-protocol.md §2.
'use strict';

const TCP_PURPOSES = new Set(['tcp:open']);
// A mesh session (docs/sah-mesh-protocol.md §2) has no binding at ticket
// time; each stream names its target at mesh_open and is checked as TCP.
const MESH_PURPOSES = new Set(['mesh:open']);
const FILE_PURPOSES = new Set(['file:read', 'file:write', 'file:root']);
const CHANNEL_PURPOSES = new Set([...TCP_PURPOSES, ...MESH_PURPOSES, ...FILE_PURPOSES]);
// SAH OS-management channels (docs/sah-os-management-design.md). Kept out of
// CHANNEL_PURPOSES: each carries a resource binding, not a target or root.
const SYS_PURPOSES = new Set(['sys:service', 'sys:package', 'sys:config', 'sys:tweak']);
const ROOT_MAX_BYTES = 4096;
const POLICY_MAX_ENTRIES = 256;
const POLICY_MAX_PORTS = 256;
// Service/unit name guard; mirrors systemapi-agent/platform.go serviceNameRE
// and controlplane/lease.js SERVICE_UNIT_RE.
const SERVICE_UNIT_RE = /^[a-zA-Z0-9][a-zA-Z0-9@._:-]{0,127}$/;
// The sys:service channel exposes the mutating lifecycle verbs; status is
// the agent's confirm read, not a channel verb. The lease binds the exact
// { unit, action } so a lease for one verb can never perform another.
const SERVICE_ACTIONS = new Set(['start', 'stop', 'restart', 'enable', 'disable']);
// Package name guard; mirrors systemapi-agent/grant.go packageNameRE.
const PACKAGE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}$/;
// The sys:package channel verbs. query is a read; the rest are mutations.
const PACKAGE_ACTIONS = new Set(['query', 'install', 'remove', 'upgrade']);
// The sys:config channel verbs. read is a read; write/reload are mutations.
// read/write target an absolute config path (gated by the config-path
// allowlist); reload targets a unit (gated by the service allowlist, since a
// reload acts on a service). write carries content, bound by its SHA-256 in
// the lease (the file/xfer content-by-hash pattern).
const CONFIG_ACTIONS = new Set(['read', 'write', 'reload']);
const CONFIG_CONTENT_MAX = 64 * 1024;
// The sys:tweak channel verbs. sysctl-get is a read; the rest are mutations.
// Kernel modules and firewall rules are out of v1 (design Decision 2).
const TWEAK_VERBS = new Set(['sysctl-get', 'sysctl-set', 'resource-limit-set', 'unit-override-set']);
// Mirrors systemapi-agent/grant.go sysctlKeyOK (sysctlKeyRE + sysctlKeyMax),
// sysctlDenied, sysctlValueCap and platform_tweak.go resourceLimits,
// overrideNameRE, limitValueRE, overrideContentCap.
// A sysctl key is one or more non-empty segments separated by single dots,
// starting with a letter, at most 128 chars. An empty segment ("a..b",
// "a.b.") would map onto a different /proc/sys file after the agent's path
// cleaning and dodge the deny list.
const SYSCTL_KEY_RE = /^(?=.{1,128}$)[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/;
const SYSCTL_VALUE_MAX = 256;
// The hard sysctl deny list: keys that run a root helper or weaken kernel
// hardening. Mirrors systemapi-agent/grant.go deniedSysctlExact and
// deniedSysctlPrefixes; testdata/sysctl-deny-vectors.json keeps them in
// parity. Always check through sysctlDenied.
const DENIED_SYSCTL = new Set(['kernel.core_pattern', 'kernel.modprobe', 'kernel.hotplug', 'kernel.poweroff_cmd',
  'kernel.kptr_restrict', 'kernel.dmesg_restrict', 'kernel.unprivileged_bpf_disabled', 'kernel.kexec_load_disabled',
  'kernel.modules_disabled', 'kernel.sysrq', 'kernel.perf_event_paranoid', 'kernel.randomize_va_space',
  'kernel.unprivileged_userns_clone', 'kernel.io_uring_disabled', 'vm.mmap_min_addr', 'fs.suid_dumpable',
  'net.core.bpf_jit_harden', 'user.max_user_namespaces', 'vm.unprivileged_userfaultfd',
  'kernel.apparmor_restrict_unprivileged_userns', 'dev.tty.ldisc_autoload', 'kernel.ftrace_enabled',
  'net.core.bpf_jit_enable']);
// A prefix ending in "." also denies the bare subtree name (fs.binfmt_misc).
const DENIED_SYSCTL_PREFIXES = ['fs.binfmt_misc.', 'kernel.usermodehelper.', 'fs.protected_', 'kernel.yama.'];
function sysctlDenied(key) {
  if (typeof key !== 'string') return true;
  if (DENIED_SYSCTL.has(key)) return true;
  return DENIED_SYSCTL_PREFIXES.some((p) => key.startsWith(p) || `${key}.` === p);
}
const OVERRIDE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const LIMIT_VALUE_RE = /^[a-zA-Z0-9:._]{1,64}$/;
const OVERRIDE_CONTENT_MAX = 64 * 1024;
const RESOURCE_LIMITS = new Set(['LimitCPU', 'LimitFSIZE', 'LimitDATA', 'LimitSTACK', 'LimitCORE', 'LimitRSS',
  'LimitNOFILE', 'LimitAS', 'LimitNPROC', 'LimitMEMLOCK', 'LimitLOCKS', 'LimitSIGPENDING', 'LimitMSGQUEUE',
  'LimitNICE', 'LimitRTPRIO', 'LimitRTTIME']);

// Scopes each purpose needs. file:write needs file:read too (FILE §2). A
// service restart is root-equivalent but bounded by the per-host unit
// allowlist (deny by default); it is an operator scope like tcp:open.
const PURPOSE_SCOPES = Object.freeze({
  'tcp:open': ['tcp:open'],
  'mesh:open': ['mesh:open'],
  'file:read': ['file:read'],
  'file:write': ['file:read', 'file:write'],
  'file:root': ['file:root'],
  'sys:service': ['sys:service'],
  'sys:package': ['sys:package'],
  'sys:config': ['sys:config'],
  'sys:tweak': ['sys:tweak']
});

const IPV4_OCTET = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])';
const IPV4_RE = new RegExp(`^${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}$`);
const HEX16_RE = /^[0-9a-fA-F]{1,4}$/;

function parseIPv4(s) {
  if (typeof s !== 'string' || !IPV4_RE.test(s)) return null;
  return Buffer.from(s.split('.').map(Number));
}

// Strict IPv6 literal: no brackets, no zone id, optional dotted-quad tail.
function parseIPv6(s) {
  if (typeof s !== 'string' || s.length < 2 || s.length > 45) return null;
  if (!/^[0-9a-fA-F:.]+$/.test(s)) return null;
  let tail = null;
  let body = s;
  if (s.includes('.')) {
    const idx = s.lastIndexOf(':');
    tail = parseIPv4(s.slice(idx + 1));
    if (!tail) return null;
    body = s.slice(0, idx + 1);
    // "::1.2.3.4" leaves "::"; "a:b:...:1.2.3.4" leaves a trailing ':'.
    if (body.endsWith(':') && !body.endsWith('::')) body = body.slice(0, -1);
  }
  const want = tail ? 6 : 8;
  const halves = body.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (part) => {
    if (part === '') return [];
    const groups = part.split(':');
    for (const g of groups) if (!HEX16_RE.test(g)) return null;
    return groups.map((g) => parseInt(g, 16));
  };
  let groups;
  if (halves.length === 2) {
    const left = parseGroups(halves[0]);
    const right = parseGroups(halves[1]);
    if (!left || !right || left.length + right.length > want - 1) return null;
    groups = [...left, ...new Array(want - left.length - right.length).fill(0), ...right];
  } else {
    groups = parseGroups(body);
    if (!groups || groups.length !== want) return null;
  }
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(g, i * 2));
  if (tail) tail.copy(out, 12);
  return out;
}

const MAPPED_PREFIX = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);

// Returns a 4-byte buffer for IPv4 (including IPv4-mapped IPv6) or a 16-byte
// buffer for IPv6, else null.
function parseIP(s) {
  const v4 = parseIPv4(s);
  if (v4) return v4;
  const v6 = parseIPv6(s);
  if (!v6) return null;
  if (v6.subarray(0, 12).equals(MAPPED_PREFIX)) return Buffer.from(v6.subarray(12));
  return v6;
}

// RFC 5952 text form: lowercase, longest zero run (>= 2 groups) compressed.
function formatIP(buf) {
  if (buf.length === 4) return [...buf].join('.');
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i += 1; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

function parseCIDR(s) {
  if (typeof s !== 'string') return null;
  const slash = s.indexOf('/');
  if (slash < 0 || slash !== s.lastIndexOf('/')) return null;
  const lenText = s.slice(slash + 1);
  if (!/^(0|[1-9][0-9]{0,2})$/.test(lenText)) return null;
  let bits = Number(lenText);
  const text = s.slice(0, slash);
  let addr = parseIPv4(text);
  if (addr) {
    if (bits > 32) return null;
  } else {
    const v6 = parseIPv6(text);
    if (!v6 || bits > 128) return null;
    if (v6.subarray(0, 12).equals(MAPPED_PREFIX) && bits >= 96) {
      addr = Buffer.from(v6.subarray(12));
      bits -= 96;
    } else {
      addr = v6;
    }
  }
  return { addr, bits };
}

function inCIDR(ip, cidr) {
  if (!ip || !cidr || ip.length !== cidr.addr.length) return false;
  let bits = cidr.bits;
  for (let i = 0; i < ip.length && bits > 0; i += 1) {
    const take = Math.min(8, bits);
    const mask = (0xff << (8 - take)) & 0xff;
    if ((ip[i] & mask) !== (cidr.addr[i] & mask)) return false;
    bits -= take;
  }
  return true;
}

// TCP §4.1. Loopback is listed separately: as a literal it is bad_target
// (TCP §2), reached any other way it is target_forbidden. The IPv6 ranges
// that embed an IPv4 address (NAT64 64:ff9b::/96 and 64:ff9b:1::/48, 6to4
// 2002::/16, IPv4-compatible ::/96) are refused whole, so no refused IPv4
// class is reachable through them. Keep in sync with tcpForbiddenPrefixes
// in systemapi-agent/tcp_policy.go.
const FORBIDDEN_V4 = ['0.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32', '100.100.100.200/32',
    '168.63.129.16/32'].map(parseCIDR);
const FORBIDDEN_V6 = ['::/96', 'fe80::/10', 'ff00::/8', 'fd00:ec2::254/128', '64:ff9b::/96', '64:ff9b:1::/48', '2002::/16'].map(parseCIDR);
const LOOPBACK = ['127.0.0.0/8', '::1/128'].map(parseCIDR);

function isLoopback(ip) {
  return LOOPBACK.some((c) => inCIDR(ip, c));
}

function isForbidden(ip) {
  const list = ip.length === 4 ? FORBIDDEN_V4 : FORBIDDEN_V6;
  return list.some((c) => inCIDR(ip, c)) || isLoopback(ip);
}

// validateTcpTarget checks a ws-ticket `target` (TCP §2, §4.1). On success
// the target is normalized: IPv4-mapped IPv6 becomes dotted quad and IPv6 is
// written in RFC 5952 form, so ticket binding, lease payload and policy all
// see one spelling.
function validateTcpTarget(target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) return { ok: false, error: 'bad_target' };
  const { host, port } = target;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, error: 'bad_target' };
  if (host === 'local') return { ok: true, target: { host: 'local', port }, local: true, ip: null };
  if (typeof host !== 'string' || host.length === 0 || host.length > 64) return { ok: false, error: 'bad_target' };
  const ip = parseIP(host);
  if (!ip) return { ok: false, error: 'bad_target' };
  if (isLoopback(ip)) return { ok: false, error: 'bad_target' };
  if (isForbidden(ip)) return { ok: false, error: 'target_forbidden' };
  return { ok: true, target: { host: formatIP(ip), port }, local: false, ip };
}

function parsePortSpec(spec) {
  if (Number.isInteger(spec) && spec >= 1 && spec <= 65535) return [spec, spec];
  if (typeof spec !== 'string') return null;
  const m = /^([1-9][0-9]{0,4})-([1-9][0-9]{0,4})$/.exec(spec);
  if (!m) return null;
  const lo = Number(m[1]);
  const hi = Number(m[2]);
  if (lo > hi || hi > 65535) return null;
  return [lo, hi];
}

// parseTcpPolicy returns the normalized allow list, or null when the policy
// is malformed. Callers treat null as deny-all.
function parseTcpPolicy(raw) {
  if (raw === null || raw === undefined) return { allow: [] };
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const allow = raw.allow;
  if (!Array.isArray(allow) || allow.length > POLICY_MAX_ENTRIES) return null;
  const out = [];
  for (const entry of allow) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
    const hasLocal = entry.local !== undefined;
    const hasCidr = entry.cidr !== undefined;
    if (hasLocal === hasCidr) return null;
    if (hasLocal && entry.local !== true) return null;
    let cidr = null;
    if (hasCidr) {
      cidr = parseCIDR(entry.cidr);
      if (!cidr) return null;
    }
    if (!Array.isArray(entry.ports) || entry.ports.length === 0 || entry.ports.length > POLICY_MAX_PORTS) return null;
    const ports = [];
    for (const spec of entry.ports) {
      const range = parsePortSpec(spec);
      if (!range) return null;
      ports.push(range);
    }
    out.push({ local: hasLocal, cidr, ports });
  }
  return { allow: out };
}

// tcpPolicyAllows takes a validateTcpTarget result. "local" matches only
// local entries; an address matches only CIDR entries of its family.
function tcpPolicyAllows(policy, checked) {
  if (!policy || !Array.isArray(policy.allow) || !checked || !checked.ok) return false;
  const port = checked.target.port;
  for (const entry of policy.allow) {
    const portOk = entry.ports.some(([lo, hi]) => port >= lo && port <= hi);
    if (!portOk) continue;
    if (checked.local && entry.local) return true;
    if (!checked.local && entry.cidr && inCIDR(checked.ip, entry.cidr)) return true;
  }
  return false;
}

function rootShapeOk(root) {
  if (typeof root !== 'string' || !root.isWellFormed()) return false;
  if (!root.startsWith('/')) return false;
  if (Buffer.byteLength(root, 'utf8') > ROOT_MAX_BYTES) return false;
  // NUL, C0 controls and DEL.
  if (/[\u0000-\u001f\u007f]/.test(root)) return false;
  if (root === '/') return true;
  if (root.endsWith('/')) return false;
  for (const part of root.slice(1).split('/')) {
    if (part === '' || part === '.' || part === '..') return false;
  }
  return true;
}

// validateFileRoot checks a ws-ticket `root` (FILE §2). "~" is refused for
// file:root.
function validateFileRoot(root, purpose) {
  if (root === '~') {
    if (purpose === 'file:root') return { ok: false, error: 'bad_root' };
    return { ok: true, root: '~' };
  }
  if (!rootShapeOk(root)) return { ok: false, error: 'bad_root' };
  return { ok: true, root };
}

function parseFilePolicy(raw) {
  if (raw === null || raw === undefined) return { roots: [] };
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const roots = raw.roots;
  if (!Array.isArray(roots) || roots.length > POLICY_MAX_ENTRIES) return null;
  const out = [];
  for (const entry of roots) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
    if (entry.path !== '~' && !rootShapeOk(entry.path)) return null;
    for (const flag of ['read', 'write', 'root']) {
      if (entry[flag] !== undefined && typeof entry[flag] !== 'boolean') return null;
    }
    out.push({ path: entry.path, read: entry.read === true, write: entry.write === true, root: entry.root === true });
  }
  return { roots: out };
}

function beneath(root, base) {
  if (root === base) return true;
  if (base === '~' || root === '~') return false;
  if (base === '/') return true;
  return root.startsWith(`${base}/`);
}

// filePolicyAllows: the requested root equals or sits beneath an entry on a
// component boundary, and that entry permits the purpose. file:read needs
// read; file:write needs read and write (its session allows every op);
// file:root needs read, write and root.
function filePolicyAllows(policy, purpose, root) {
  if (!policy || !Array.isArray(policy.roots) || !FILE_PURPOSES.has(purpose)) return false;
  for (const entry of policy.roots) {
    if (!beneath(root, entry.path)) continue;
    if (!entry.read) continue;
    if (purpose === 'file:read') return true;
    if (!entry.write) continue;
    if (purpose === 'file:write') return true;
    if (entry.root) return true;
  }
  return false;
}

// validateServiceBinding checks a ws-ticket `service` object (the sys:service
// binding): { unit, action }. action is one of SERVICE_ACTIONS.
function validateServiceBinding(service) {
  if (!service || typeof service !== 'object' || Array.isArray(service)) return { ok: false, error: 'bad_unit' };
  const { unit, action } = service;
  if (typeof unit !== 'string' || !SERVICE_UNIT_RE.test(unit)) return { ok: false, error: 'bad_unit' };
  if (!SERVICE_ACTIONS.has(action)) return { ok: false, error: 'bad_action' };
  return { ok: true, service: { unit, action } };
}

// parseServicePolicy returns the normalized unit allowlist, or null when the
// policy is malformed (callers treat null as deny-all). The allowlist is the
// tight gate: a unit not listed is denied (the --service grant of
// scripts/channel-policy.js).
function parseServicePolicy(raw) {
  if (raw === null || raw === undefined) return { units: [] };
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const units = raw.units;
  if (!Array.isArray(units) || units.length > POLICY_MAX_ENTRIES) return null;
  const out = [];
  for (const unit of units) {
    if (typeof unit !== 'string' || !SERVICE_UNIT_RE.test(unit)) return null;
    out.push(unit);
  }
  return { units: out };
}

// servicePolicyAllows: the requested unit is listed exactly. Deny by default.
function servicePolicyAllows(policy, unit) {
  if (!policy || !Array.isArray(policy.units)) return false;
  return policy.units.includes(unit);
}

// validateServiceBinding's package counterpart: { name, action }. name
// mirrors the agent's packageNameRE (grant.go); action is a channel verb.
function validatePackageBinding(pkg) {
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) return { ok: false, error: 'bad_package' };
  const { name, action } = pkg;
  if (typeof name !== 'string' || !PACKAGE_NAME_RE.test(name)) return { ok: false, error: 'bad_package' };
  if (!PACKAGE_ACTIONS.has(action)) return { ok: false, error: 'bad_action' };
  return { ok: true, package: { name, action } };
}

// parsePackagePolicy returns the normalized package-name allowlist, or null
// when malformed (callers treat null as deny-all). Each name must match
// PACKAGE_NAME_RE, so "*" is never a name and the list is never allow-all:
// this mirrors the agent's exactGrant semantics (grant.go). The allowlist is
// the tight gate (the --package grant of scripts/channel-policy.js).
function parsePackagePolicy(raw) {
  if (raw === null || raw === undefined) return { names: [] };
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const names = raw.names;
  if (!Array.isArray(names) || names.length > POLICY_MAX_ENTRIES) return null;
  const out = [];
  for (const name of names) {
    if (typeof name !== 'string' || !PACKAGE_NAME_RE.test(name)) return null;
    out.push(name);
  }
  return { names: out };
}

// packagePolicyAllows: the requested name is listed exactly. Deny by default.
function packagePolicyAllows(policy, name) {
  if (!policy || !Array.isArray(policy.names)) return false;
  return policy.names.includes(name);
}

// validateConfigBinding checks a sys:config binding { action, target,
// content? }. It is idempotent (its output re-validates), so the same function
// guards the ticket body at issue and the stored binding at the upgrade. For
// read/write target is an absolute config path; for reload target is a unit.
// write also carries content, a UTF-8 string of at most CONFIG_CONTENT_MAX
// bytes, whose SHA-256 is signed into the lease (sys.js): the binding keeps the
// bytes, the lease binds them.
function validateConfigBinding(cfg) {
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return { ok: false, error: 'bad_config' };
  const { action, target } = cfg;
  if (!CONFIG_ACTIONS.has(action)) return { ok: false, error: 'bad_action' };
  if (action === 'reload') {
    if (typeof target !== 'string' || !SERVICE_UNIT_RE.test(target)) return { ok: false, error: 'bad_config' };
    return { ok: true, config: { action, target } };
  }
  if (typeof target !== 'string' || !rootShapeOk(target) || target === '/') return { ok: false, error: 'bad_config' };
  if (action === 'read') return { ok: true, config: { action, target } };
  // write: content required, a bounded UTF-8 string.
  if (typeof cfg.content !== 'string' || !cfg.content.isWellFormed()) return { ok: false, error: 'bad_config' };
  if (Buffer.byteLength(cfg.content, 'utf8') > CONFIG_CONTENT_MAX) return { ok: false, error: 'bad_config' };
  return { ok: true, config: { action, target, content: cfg.content } };
}

// The agent's and server's own config/state: never an allowed sys:config path,
// so the config channel can never rewrite the agent's own config (a lockout
// risk the design calls out) or the server's.
// Also the mutation helpers' replay store and trust file and the agent's unit,
// /etc/ld.so.preload (loaded into every process, the agent's included) and the
// system manager config system.conf(.d) (applies to every service).
// Mirrors systemapi-agent/config_helper.go configSelfRoots; the shared vectors
// in controlplane/testdata/config-self-vectors.json keep the two in parity.
// parseConfigPolicy and configPolicyAllows enforce it here; the agent
// (checkSysConfigPolicy) and the config helper enforce it again.
const CONFIG_SELF_ROOTS = ['/proc', '/sys', '/dev', '/boot', '/var/lib/systemapi-agent',
  '/etc/systemapi-agent', '/var/lib/postgresql', '/etc/sahcore',
  '/var/lib/sah-helper', '/etc/systemapi-agent/helper-trust.json',
  '/etc/systemd/system/systemapi-agent.service', '/etc/systemd/system/systemapi-agent.service.d',
  '/etc/ld.so.preload', '/etc/systemd/system.conf', '/etc/systemd/system.conf.d'];
// Unit dirs whose entries systemd applies to the agent and helpers; entries
// are matched by pattern (systemdSelfEntry), mirroring configSystemdUnitDirs,
// configHelperUnitRE and configSystemdSelfEntry in config_helper.go.
// The runtime and vendor dirs too (/run, /usr/lib, /lib): a unit or drop-in
// there applies to the agent and helpers just the same.
const SYSTEMD_UNIT_DIRS = ['/etc/systemd/system', '/etc/systemd/system.control', '/run/systemd/system',
  '/run/systemd/system.control', '/run/systemd/transient', '/usr/lib/systemd/system', '/lib/systemd/system'];
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
// that applies to the agent or a helper. The same check the agent applies to
// a read or write target (configTargetDenied).
function configSelfDenied(path) {
  if (CONFIG_SELF_ROOTS.some((s) => path === s || path.startsWith(`${s}/`))) return true;
  for (const d of SYSTEMD_UNIT_DIRS) {
    if (path.startsWith(`${d}/`) && systemdSelfEntry(path.slice(d.length + 1).split('/')[0])) return true;
  }
  return false;
}

// configPrefixProtected: a config-path grant that is, sits in, or contains a
// protected path (a self-root or a systemd unit dir); the grant rule of
// scripts/channel-policy.js --config. Returns the protected path or null.
function configPrefixProtected(root) {
  if (configSelfDenied(root)) return root;
  return [...CONFIG_SELF_ROOTS, ...SYSTEMD_UNIT_DIRS].find((s) => s === root || s.startsWith(`${root}/`)) || null;
}

// parseConfigPolicy returns the normalized config-path allowlist, or null when
// malformed (deny-all). Each entry is an absolute path prefix (the file-root
// allowlist shape); a requested read/write path must sit at or beneath one.
// An entry that is, sits in or contains a config self-root or a systemd unit
// dir (configPrefixProtected) makes the whole policy malformed, so a policy
// written around the CLI can never grant the agent's own config or units.
function parseConfigPolicy(raw) {
  if (raw === null || raw === undefined) return { paths: [] };
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const paths = raw.paths;
  if (!Array.isArray(paths) || paths.length > POLICY_MAX_ENTRIES) return null;
  const out = [];
  for (const p of paths) {
    if (typeof p !== 'string' || !rootShapeOk(p) || p === '/' || configPrefixProtected(p)) return null;
    out.push(p);
  }
  return { paths: out };
}

// configPolicyAllows: the requested path equals or sits beneath an allowed
// prefix on a component boundary and is not a config self-root. Deny by
// default.
function configPolicyAllows(policy, path) {
  if (!policy || !Array.isArray(policy.paths)) return false;
  if (typeof path !== 'string' || configSelfDenied(path)) return false;
  return policy.paths.some((base) => beneath(path, base));
}

// validateTweakBinding checks a sys:tweak binding. The canonical shape is a
// flat { verb, ... } with only the fields that verb uses; it is idempotent, so
// the same function guards the ticket body and the stored binding. sysctl
// values and resource-limit values ride the lease directly (short, newline-
// free); a unit-override body rides the agent frame bound by SHA-256 in the
// lease (sys.js). A hard-denied sysctl key is refused here as well as on the
// agent. Mirrors systemapi-agent/sys_policy.go checkSysTweakPolicy and
// platform_tweak.go.
function validateTweakBinding(tw) {
  if (!tw || typeof tw !== 'object' || Array.isArray(tw)) return { ok: false, error: 'bad_tweak' };
  const { verb } = tw;
  if (!TWEAK_VERBS.has(verb)) return { ok: false, error: 'bad_action' };
  if (verb === 'sysctl-get' || verb === 'sysctl-set') {
    if (typeof tw.key !== 'string' || !SYSCTL_KEY_RE.test(tw.key) || sysctlDenied(tw.key)) return { ok: false, error: 'bad_tweak' };
    if (verb === 'sysctl-get') return { ok: true, tweak: { verb, key: tw.key } };
    if (typeof tw.value !== 'string' || tw.value.length === 0 || tw.value.length > SYSCTL_VALUE_MAX
      || /[\n\r\u0000]/.test(tw.value)) return { ok: false, error: 'bad_tweak' };
    return { ok: true, tweak: { verb, key: tw.key, value: tw.value } };
  }
  if (verb === 'resource-limit-set') {
    if (typeof tw.unit !== 'string' || !SERVICE_UNIT_RE.test(tw.unit)) return { ok: false, error: 'bad_tweak' };
    if (typeof tw.limit !== 'string' || !RESOURCE_LIMITS.has(tw.limit)) return { ok: false, error: 'bad_tweak' };
    if (typeof tw.value !== 'string' || !LIMIT_VALUE_RE.test(tw.value)) return { ok: false, error: 'bad_tweak' };
    return { ok: true, tweak: { verb, unit: tw.unit, limit: tw.limit, value: tw.value } };
  }
  // unit-override-set
  if (typeof tw.unit !== 'string' || !SERVICE_UNIT_RE.test(tw.unit)) return { ok: false, error: 'bad_tweak' };
  if (typeof tw.name !== 'string' || !OVERRIDE_NAME_RE.test(tw.name)) return { ok: false, error: 'bad_tweak' };
  if (typeof tw.content !== 'string' || !tw.content.isWellFormed() || tw.content.length === 0
    || Buffer.byteLength(tw.content, 'utf8') > OVERRIDE_CONTENT_MAX || tw.content.includes('\u0000')) return { ok: false, error: 'bad_tweak' };
  return { ok: true, tweak: { verb, unit: tw.unit, name: tw.name, content: tw.content } };
}

// parseTweakPolicy returns the normalized allowlists, or null when malformed
// (deny-all): { sysctls: [keys], units: [units] }. sysctl get/set are gated by
// sysctls; resource-limit/unit-override by units. A hard-denied sysctl can
// never be listed. Deny by default.
function parseTweakPolicy(raw) {
  if (raw === null || raw === undefined) return { sysctls: [], units: [] };
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const sysctls = raw.sysctls === undefined ? [] : raw.sysctls;
  const units = raw.units === undefined ? [] : raw.units;
  if (!Array.isArray(sysctls) || !Array.isArray(units) || sysctls.length > POLICY_MAX_ENTRIES || units.length > POLICY_MAX_ENTRIES) return null;
  const outKeys = [];
  for (const k of sysctls) {
    if (typeof k !== 'string' || !SYSCTL_KEY_RE.test(k) || sysctlDenied(k)) return null;
    outKeys.push(k);
  }
  const outUnits = [];
  for (const u of units) {
    if (typeof u !== 'string' || !SERVICE_UNIT_RE.test(u)) return null;
    outUnits.push(u);
  }
  return { sysctls: outKeys, units: outUnits };
}

// tweakPolicyAllows returns null when allowed, else the deny code. Deny by
// default. sysctl verbs are gated by the sysctl allowlist, the override verbs
// by the unit allowlist.
function tweakPolicyAllows(policy, tweak) {
  if (!policy || !Array.isArray(policy.sysctls) || !Array.isArray(policy.units) || !tweak) return 'tweak_denied';
  if (tweak.verb === 'sysctl-get' || tweak.verb === 'sysctl-set') {
    return policy.sysctls.includes(tweak.key) ? null : 'sysctl_denied';
  }
  return policy.units.includes(tweak.unit) ? null : 'unit_denied';
}

// validateBinding parses the purpose-specific part of a ws-ticket body.
// Returns { ok, binding } where binding is { target } or { root }, or
// { ok:false, error }. target_forbidden is reported separately in
// `forbidden` so the route can answer scope errors first.
function validateBinding(purpose, body) {
  // MESH §2: no binding; a target or root in the body is ignored.
  if (MESH_PURPOSES.has(purpose)) return { ok: true, forbidden: false, binding: null, checked: null };
  if (TCP_PURPOSES.has(purpose)) {
    const checked = validateTcpTarget(body && body.target);
    if (!checked.ok && checked.error === 'bad_target') return { ok: false, error: 'bad_target' };
    if (!checked.ok) return { ok: true, forbidden: true, binding: null, checked };
    return { ok: true, forbidden: false, binding: { target: checked.target }, checked };
  }
  if (FILE_PURPOSES.has(purpose)) {
    const checked = validateFileRoot(body && body.root, purpose);
    if (!checked.ok) return { ok: false, error: 'bad_root' };
    return { ok: true, forbidden: false, binding: { root: checked.root }, checked };
  }
  if (purpose === 'sys:service') {
    const checked = validateServiceBinding(body && body.service);
    if (!checked.ok) return { ok: false, error: checked.error };
    return { ok: true, forbidden: false, binding: { sys: checked.service }, checked };
  }
  if (purpose === 'sys:package') {
    const checked = validatePackageBinding(body && body.package);
    if (!checked.ok) return { ok: false, error: checked.error };
    return { ok: true, forbidden: false, binding: { sys: checked.package }, checked };
  }
  if (purpose === 'sys:config') {
    const checked = validateConfigBinding(body && body.config);
    if (!checked.ok) return { ok: false, error: checked.error };
    return { ok: true, forbidden: false, binding: { sys: checked.config }, checked };
  }
  if (purpose === 'sys:tweak') {
    const checked = validateTweakBinding(body && body.tweak);
    if (!checked.ok) return { ok: false, error: checked.error };
    return { ok: true, forbidden: false, binding: { sys: checked.tweak }, checked };
  }
  return { ok: true, forbidden: false, binding: null, checked: null };
}

// Resolves the effective policies for a host: the host column when set,
// else the tenant default, else deny-all. A registry without channel policy
// support denies everything.
async function effectivePolicies(registry, hostId) {
  if (!registry || typeof registry.channelPolicies !== 'function') {
    return { tcp: { allow: [] }, file: { roots: [] }, service: { units: [] }, package: { names: [] }, config: { paths: [] }, tweak: { sysctls: [], units: [] } };
  }
  const raw = await registry.channelPolicies(hostId);
  const pick = (hostVal, tenantVal) => (hostVal !== null && hostVal !== undefined ? hostVal : tenantVal);
  return {
    tcp: parseTcpPolicy(pick(raw && raw.host_tcp_policy, raw && raw.tenant_tcp_policy)),
    file: parseFilePolicy(pick(raw && raw.host_file_policy, raw && raw.tenant_file_policy)),
    service: parseServicePolicy(pick(raw && raw.host_service_policy, raw && raw.tenant_service_policy)),
    package: parsePackagePolicy(pick(raw && raw.host_package_policy, raw && raw.tenant_package_policy)),
    config: parseConfigPolicy(pick(raw && raw.host_config_policy, raw && raw.tenant_config_policy)),
    tweak: parseTweakPolicy(pick(raw && raw.host_tweak_policy, raw && raw.tenant_tweak_policy))
  };
}

// policyDecision: null when the binding is allowed, else the error code.
// Run at ticket issue and again at the upgrade (TCP §4.2, FILE §2).
async function policyDecision(registry, hostId, purpose, binding) {
  // MESH: the session itself has no target (null); a stream's target is
  // checked exactly like a TCP target (MESH §4).
  if (MESH_PURPOSES.has(purpose) && (binding === null || binding === undefined)) return null;
  if (TCP_PURPOSES.has(purpose) || MESH_PURPOSES.has(purpose)) {
    const checked = validateTcpTarget(binding && binding.target);
    if (!checked.ok) return checked.error;
    const { tcp } = await effectivePolicies(registry, hostId);
    return tcpPolicyAllows(tcp, checked) ? null : 'target_denied';
  }
  if (FILE_PURPOSES.has(purpose)) {
    const checked = validateFileRoot(binding && binding.root, purpose);
    if (!checked.ok) return checked.error;
    const { file } = await effectivePolicies(registry, hostId);
    return filePolicyAllows(file, purpose, checked.root) ? null : 'root_denied';
  }
  if (purpose === 'sys:service') {
    const checked = validateServiceBinding(binding && binding.sys);
    if (!checked.ok) return checked.error;
    const { service } = await effectivePolicies(registry, hostId);
    return servicePolicyAllows(service, checked.service.unit) ? null : 'unit_denied';
  }
  if (purpose === 'sys:package') {
    const checked = validatePackageBinding(binding && binding.sys);
    if (!checked.ok) return checked.error;
    const { package: pkg } = await effectivePolicies(registry, hostId);
    return packagePolicyAllows(pkg, checked.package.name) ? null : 'package_denied';
  }
  if (purpose === 'sys:config') {
    const checked = validateConfigBinding(binding && binding.sys);
    if (!checked.ok) return checked.error;
    const pols = await effectivePolicies(registry, hostId);
    // reload acts on a service, gated by the unit allowlist; read/write act on
    // a path, gated by the config-path allowlist.
    if (checked.config.action === 'reload') {
      return servicePolicyAllows(pols.service, checked.config.target) ? null : 'unit_denied';
    }
    return configPolicyAllows(pols.config, checked.config.target) ? null : 'path_denied';
  }
  if (purpose === 'sys:tweak') {
    const checked = validateTweakBinding(binding && binding.sys);
    if (!checked.ok) return checked.error;
    const { tweak } = await effectivePolicies(registry, hostId);
    return tweakPolicyAllows(tweak, checked.tweak);
  }
  return null;
}

// assertPolicyShape throws 400 bad_policy for a policy an admin tries to
// store; null clears the column.
function assertPolicyShape(kind, raw) {
  if (raw === null) return;
  const parsed = kind === 'tcp' ? parseTcpPolicy(raw)
    : kind === 'service' ? parseServicePolicy(raw)
      : kind === 'package' ? parsePackagePolicy(raw)
        : kind === 'config' ? parseConfigPolicy(raw)
          : kind === 'tweak' ? parseTweakPolicy(raw)
            : parseFilePolicy(raw);
  if (!parsed || raw === undefined) {
    const err = new Error('bad_policy');
    err.status = 400;
    err.code = 'bad_policy';
    throw err;
  }
}

// Agent capability advertisement: X-SystemAPI-Capabilities, a comma list of
// short lowercase tokens. Anything malformed is dropped; an absent header is
// an old agent with no advertised capabilities.
const CAPABILITY_RE = /^[a-z][a-z0-9_]{0,15}$/;
function parseCapabilities(header) {
  const out = new Set();
  if (typeof header !== 'string' || header.length > 256) return out;
  for (const raw of header.split(',')) {
    const tok = raw.trim();
    if (CAPABILITY_RE.test(tok) && out.size < 16) out.add(tok);
  }
  return out;
}

module.exports = {
  TCP_PURPOSES,
  MESH_PURPOSES,
  FILE_PURPOSES,
  CHANNEL_PURPOSES,
  SYS_PURPOSES,
  PURPOSE_SCOPES,
  SERVICE_UNIT_RE,
  parseIP,
  formatIP,
  parseCIDR,
  inCIDR,
  validateTcpTarget,
  parseTcpPolicy,
  tcpPolicyAllows,
  validateFileRoot,
  parseFilePolicy,
  filePolicyAllows,
  validateServiceBinding,
  parseServicePolicy,
  servicePolicyAllows,
  PACKAGE_NAME_RE,
  validatePackageBinding,
  parsePackagePolicy,
  packagePolicyAllows,
  CONFIG_CONTENT_MAX,
  validateConfigBinding,
  parseConfigPolicy,
  configPolicyAllows,
  CONFIG_SELF_ROOTS,
  SYSTEMD_UNIT_DIRS,
  systemdSelfEntry,
  configSelfDenied,
  configPrefixProtected,
  OVERRIDE_CONTENT_MAX,
  SYSCTL_KEY_RE,
  DENIED_SYSCTL,
  DENIED_SYSCTL_PREFIXES,
  sysctlDenied,
  validateTweakBinding,
  parseTweakPolicy,
  tweakPolicyAllows,
  validateBinding,
  effectivePolicies,
  policyDecision,
  assertPolicyShape,
  parseCapabilities
};
