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
const ROOT_MAX_BYTES = 4096;
const POLICY_MAX_ENTRIES = 256;
const POLICY_MAX_PORTS = 256;

// Scopes each purpose needs. file:write needs file:read too (FILE §2).
const PURPOSE_SCOPES = Object.freeze({
  'tcp:open': ['tcp:open'],
  'mesh:open': ['mesh:open'],
  'file:read': ['file:read'],
  'file:write': ['file:read', 'file:write'],
  'file:root': ['file:root']
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
  return { ok: true, forbidden: false, binding: null, checked: null };
}

// Resolves the effective policies for a host: the host column when set,
// else the tenant default, else deny-all. A registry without channel policy
// support denies everything.
async function effectivePolicies(registry, hostId) {
  if (!registry || typeof registry.channelPolicies !== 'function') return { tcp: { allow: [] }, file: { roots: [] } };
  const raw = await registry.channelPolicies(hostId);
  const pick = (hostVal, tenantVal) => (hostVal !== null && hostVal !== undefined ? hostVal : tenantVal);
  return {
    tcp: parseTcpPolicy(pick(raw && raw.host_tcp_policy, raw && raw.tenant_tcp_policy)),
    file: parseFilePolicy(pick(raw && raw.host_file_policy, raw && raw.tenant_file_policy))
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
  return null;
}

// assertPolicyShape throws 400 bad_policy for a policy an admin tries to
// store; null clears the column.
function assertPolicyShape(kind, raw) {
  if (raw === null) return;
  const parsed = kind === 'tcp' ? parseTcpPolicy(raw) : parseFilePolicy(raw);
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
  PURPOSE_SCOPES,
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
  validateBinding,
  effectivePolicies,
  policyDecision,
  assertPolicyShape,
  parseCapabilities
};
