// Canonical entitlements v1, bound into the sysscript_job lease
// (controlplane/lease.js sysscriptJobPayload; the agent's mirror is
// canonicalEntitlements in systemapi-agent/lease.go).
// Threats: entitlements swapped or widened in transit between the control
// plane and the agent. The lease signs the SHA-256 of this text, and the
// agent recomputes it from its own parse of the frame, so a frame whose
// entitlements differ in any granted item or flag fails as
// payload_mismatch. To agree byte for byte, parseEntitlements mirrors the
// agent's Entitlements.UnmarshalJSON (systemapi-agent/sysscript.go) and
// exactItemOK/listCap/dropDeniedSysctl (grant.go): byte lengths, not UTF-16
// lengths; a non-string element drops the whole list; a JSON null element of
// a path list becomes "". List items are deduplicated and sorted by UTF-8
// byte order. An item with "\n" or "\r", a list over 64 items, or a string
// that is not well-formed UTF-16 is refused (bad_entitlements, 400) before
// anything is signed. Does NOT decide what a principal may be granted
// (router.js clampEntitlements does that first).
'use strict';

const crypto = require('node:crypto');

const ENTITLEMENTS_PREFIX = 'systemapi-entitlements-v1\n';
// Go struct order of systemapi-agent/sysscript.go Entitlements.
const FIELDS = [
  ['allow_fs_write', 'paths'],
  ['allow_fs_read', 'paths'],
  ['allow_net_outbound', 'paths'],
  ['allow_exec', 'bool'],
  ['allow_config_write', 'paths'],
  ['allow_service_reload', 'paths'],
  ['allow_containers', 'bool'],
  ['allow_k3s', 'bool'],
  ['allow_linux', 'bool'],
  ['allow_k8s', 'bool'],
  ['allow_packages', 'exact'],
  ['allow_images', 'exact'],
  ['allow_k3s_namespaces', 'exact'],
  ['allow_k8s_namespaces', 'exact'],
  ['allow_net_manage', 'exact'],
  ['allow_mount_targets', 'exact'],
  ['allow_sysctl', 'sysctl']
];
const LIST_CAP = 32; // grant.go listCap
const EXACT_ITEM_MAX = 256; // grant.go exactItemMax, in bytes
const CANONICAL_LIST_MAX = 64;
const DENIED_SYSCTL = new Set(['kernel.core_pattern', 'kernel.modprobe', 'kernel.hotplug']);

function badEntitlements() {
  const err = new Error('bad_entitlements');
  err.status = 400;
  return err;
}

// Go json.Unmarshal into []string: an array whose elements are strings or
// null (null leaves ""); anything else fails and the list is nil.
function stringList(value) {
  if (!Array.isArray(value)) return null;
  const out = [];
  for (const item of value) {
    if (item === null) out.push('');
    else if (typeof item === 'string') out.push(item);
    else return null;
  }
  return out;
}

function entitlementPaths(value) {
  return stringList(value);
}

function entitlementBool(value) {
  return value === true;
}

function exactItemOK(s) {
  if (s === '' || Buffer.byteLength(s, 'utf8') > EXACT_ITEM_MAX) return false;
  return !(s.includes('*') || s.includes('..') || /[\u0000\n\r]/.test(s));
}

function entitlementExactList(value) {
  const items = stringList(value);
  if (!items) return null;
  const out = [];
  for (const item of items) {
    if (!exactItemOK(item)) continue;
    out.push(item);
    if (out.length >= LIST_CAP) break;
  }
  return out.length ? out : null;
}

function dropDeniedSysctl(list) {
  if (!list) return null;
  const out = list.filter((item) => !DENIED_SYSCTL.has(item));
  return out.length ? out : null;
}

// parseEntitlements returns what the agent's UnmarshalJSON makes of the
// object once it is sent as JSON.
function parseEntitlements(obj) {
  const raw = obj === undefined ? null : JSON.parse(JSON.stringify(obj));
  // The agent fails to parse a frame whose entitlements are not an object.
  if (raw !== null && (typeof raw !== 'object' || Array.isArray(raw))) throw badEntitlements();
  const src = raw || {};
  const out = {};
  for (const [name, kind] of FIELDS) {
    const v = Object.hasOwn(src, name) ? src[name] : null;
    if (kind === 'bool') out[name] = entitlementBool(v);
    else if (kind === 'paths') out[name] = entitlementPaths(v);
    else if (kind === 'exact') out[name] = entitlementExactList(v);
    else out[name] = dropDeniedSysctl(entitlementExactList(v));
  }
  return out;
}

// canonicalEntitlements is the v1 text of parsed entitlements (the output
// of parseEntitlements).
function canonicalEntitlements(parsed) {
  let text = ENTITLEMENTS_PREFIX;
  for (const [name, kind] of FIELDS) {
    const v = parsed[name];
    if (kind === 'bool') {
      text += `${name}=${v === true}\n`;
      continue;
    }
    const list = v || [];
    if (list.length > CANONICAL_LIST_MAX) throw badEntitlements();
    for (const item of list) {
      if (typeof item !== 'string' || !item.isWellFormed() || /[\n\r]/.test(item)) throw badEntitlements();
    }
    const sorted = [...new Set(list)].map((s) => Buffer.from(s, 'utf8')).sort(Buffer.compare);
    text += `${name}#${sorted.length}\n`;
    for (const b of sorted) text += `${b.toString('utf8')}\n`;
  }
  return text;
}

// entitlementsSha256 is the hex SHA-256 of the canonical text of obj as the
// agent will parse it.
function entitlementsSha256(obj) {
  const text = canonicalEntitlements(parseEntitlements(obj));
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

module.exports = {
  ENTITLEMENTS_PREFIX,
  parseEntitlements,
  canonicalEntitlements,
  entitlementsSha256,
  entitlementPaths,
  entitlementBool,
  entitlementExactList,
  exactItemOK,
  dropDeniedSysctl
};
