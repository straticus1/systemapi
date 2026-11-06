// Threats: a forged sash/1 grant, a lease signature reused as a grant, a
// fleet signature on purpose emergency (and the reverse), a "*", an expired
// exp, a relative or unclean file root, identical purpose keys, and a policy
// list that smuggles a write or a journal entitlement onto a login grant.
// The seed is an argument, never read from the environment here, and it is
// never logged. Does NOT sign with the lease key. Does NOT import the sash
// module. Verification fails closed. A "*" is refused after the signature
// matches, not before.
'use strict';

const crypto = require('node:crypto');
const { privateKeyFromSeed } = require('./keys');
const { sysctlDenied, filePolicyAllows } = require('./channels');

const SASH_DOMAIN = Buffer.from('sash-grant-v1\n', 'utf8');
const SASH_MAX_DOCUMENT = 64 * 1024;
const SEED_RE = /^[0-9a-fA-F]{64}$/;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PURPOSES = new Set(['terminal:open', 'terminal:root', 'emergency']);
const BUILD_PURPOSES = new Set(['terminal:open', 'terminal:root']);
const KNOWN_FIELDS = new Set([
  'v', 'actor', 'host', 'purpose', 'exp', 'lease_id', 'entitlements',
  'file_read', 'file_write', 'allow_private', 'sig'
]);

function shape() {
  const err = new Error('grant_bad_shape');
  err.code = 'grant_bad_shape';
  return err;
}

function canonOK(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e || c === 0x3c || c === 0x3e || c === 0x26) return false;
  }
  return true;
}

// Matches path.Clean in the agent (the path package, not filepath).
function goPathClean(p) {
  if (typeof p !== 'string' || p === '') return '.';
  const rooted = p.charCodeAt(0) === 0x2f;
  const parts = [];
  let dotdot = 0;
  for (const part of p.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (parts.length > dotdot) parts.pop();
      else if (!rooted) {
        parts.push('..');
        dotdot = parts.length;
      }
      continue;
    }
    parts.push(part);
  }
  const body = parts.join('/');
  if (rooted) return body === '' ? '/' : `/${body}`;
  return body === '' ? '.' : body;
}

function publicKeyFromRaw(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) return null;
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, raw]),
      format: 'der',
      type: 'spki'
    });
  } catch {
    return null;
  }
}

function distinctKeys(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== 32 || b.length !== 32) return false;
  return !crypto.timingSafeEqual(a, b);
}

function sashBody(g) {
  return JSON.stringify({
    v: g.v,
    actor: g.actor,
    host: g.host,
    purpose: g.purpose,
    exp: g.exp,
    lease_id: g.lease_id,
    entitlements: g.entitlements || [],
    file_read: g.file_read || [],
    file_write: g.file_write || [],
    allow_private: g.allow_private === true
  });
}

function sashMessage(g) {
  return Buffer.concat([SASH_DOMAIN, Buffer.from(sashBody(g), 'utf8')]);
}

function signSashDocument(g, seedHex) {
  if (typeof seedHex !== 'string' || !SEED_RE.test(seedHex)) throw shape();
  const fields = [g.v, g.actor, g.host, g.purpose, g.lease_id];
  for (const list of [g.entitlements, g.file_read, g.file_write]) {
    if (!Array.isArray(list)) throw shape();
    for (const item of list) fields.push(item);
  }
  for (const field of fields) {
    if (!canonOK(field)) throw shape();
  }
  if (!Number.isSafeInteger(g.exp)) throw shape();
  const priv = privateKeyFromSeed(Buffer.from(seedHex, 'hex'));
  const sig = crypto.sign(null, sashMessage(g), priv).toString('base64');
  return {
    v: g.v,
    actor: g.actor,
    host: g.host,
    purpose: g.purpose,
    exp: g.exp,
    lease_id: g.lease_id,
    entitlements: g.entitlements.slice(),
    file_read: g.file_read.slice(),
    file_write: g.file_write.slice(),
    allow_private: g.allow_private === true,
    sig
  };
}

function takeNames(list) {
  if (list == null) return [];
  if (!Array.isArray(list)) throw shape();
  const out = [];
  for (const item of list) {
    if (typeof item !== 'string' || item.length === 0 || !canonOK(item)) throw shape();
    if (item === '*') continue;
    out.push(item);
  }
  return out;
}

function sectionList(policies, section, key) {
  if (!policies || typeof policies !== 'object') return [];
  const sec = policies[section];
  if (sec == null) return [];
  if (typeof sec !== 'object' || Array.isArray(sec)) throw shape();
  return takeNames(sec[key]);
}

function takeConfigs(policies) {
  const list = sectionList(policies, 'config', 'paths');
  const out = [];
  for (const item of list) {
    if (!item.startsWith('/') || item === '/' || goPathClean(item) !== item) continue;
    out.push(item);
  }
  return out;
}

function takeSysctls(policies) {
  const out = [];
  for (const item of sectionList(policies, 'tweak', 'sysctls')) {
    if (sysctlDenied(item)) continue;
    out.push(item);
  }
  return out;
}

function takeFileRoots(policies) {
  if (!policies || typeof policies !== 'object') return [];
  const file = policies.file;
  if (file == null) return [];
  if (typeof file !== 'object' || Array.isArray(file)) throw shape();
  if (file.roots == null) return [];
  if (!Array.isArray(file.roots)) throw shape();
  return file.roots;
}

function takeFiles(policies) {
  const out = [];
  for (const entry of takeFileRoots(policies)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw shape();
    const p = entry.path;
    if (typeof p !== 'string' || p.length === 0 || !canonOK(p)) throw shape();
    if (p === '~' || p === '*' || !p.startsWith('/') || goPathClean(p) !== p) continue;
    if (entry.read !== true) continue;
    if (!filePolicyAllows(policies.file, 'file:read', p)) continue;
    out.push(p);
  }
  return out;
}

// sash file.write is not a file-channel session. That session can also read,
// which is why filePolicyAllows('file:write') requires entry.read. A
// write-only root (the fleet fixture /tmp) is a real write root, so this
// keeps entry.write === true and does not call filePolicyAllows.
function takeWriteFiles(policies) {
  const out = [];
  for (const entry of takeFileRoots(policies)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw shape();
    const p = entry.path;
    if (typeof p !== 'string' || p.length === 0 || !canonOK(p)) throw shape();
    if (p === '~' || p === '*' || !p.startsWith('/') || goPathClean(p) !== p) continue;
    if (entry.write !== true) continue;
    out.push(p);
  }
  return out;
}

// buildSashTerminalGrant signs a login grant. journal is omitted. A write
// entitlement is present only when its delivered list is non-empty.
// policies may be the effectivePolicies object (null sections are empty) or
// a fixture that still contains "*".
function buildSashTerminalGrant(seedHex, opts) {
  const o = opts || {};
  if (!BUILD_PURPOSES.has(o.purpose)) throw shape();
  if (typeof o.actor !== 'string' || o.actor.length === 0 || !canonOK(o.actor)) throw shape();
  if (typeof o.host !== 'string' || o.host.length === 0 || !canonOK(o.host)) throw shape();
  if (typeof o.lease_id !== 'string' || o.lease_id.length === 0 || !canonOK(o.lease_id)) throw shape();
  if (!Number.isSafeInteger(o.exp)) throw shape();
  const units = sectionList(o.policies, 'service', 'units');
  const packages = sectionList(o.policies, 'package', 'names');
  const configs = takeConfigs(o.policies);
  const sysctls = takeSysctls(o.policies);
  const files = takeFiles(o.policies);
  const writeFiles = takeWriteFiles(o.policies);
  const entitlements = ['ps'];
  if (units.length) entitlements.push('unit.status', 'unit.restart');
  if (packages.length) entitlements.push('package.query', 'package.install');
  if (sysctls.length) entitlements.push('sysctl.get', 'sysctl.set');
  if (configs.length) entitlements.push('config.read');
  if (files.length) entitlements.push('file.read');
  if (writeFiles.length) entitlements.push('file.write');
  const document = signSashDocument({
    v: 'sash/1',
    actor: o.actor,
    host: o.host,
    purpose: o.purpose,
    exp: o.exp,
    lease_id: o.lease_id,
    entitlements,
    file_read: files,
    file_write: writeFiles,
    allow_private: false
  }, seedHex);
  return {
    document,
    grant: document,
    targets: { units, packages, configs, sysctls, files, files_write: writeFiles }
  };
}

function fail(error) {
  return { ok: false, error, grant: null };
}

function asBuffer(doc) {
  if (Buffer.isBuffer(doc)) return doc;
  if (typeof doc === 'string') return Buffer.from(doc, 'utf8');
  return null;
}

function rootList(value, present) {
  if (!present) return [];
  if (!Array.isArray(value)) return null;
  for (const root of value) {
    if (typeof root !== 'string' || goPathClean(root) !== root || !root.startsWith('/')) return null;
  }
  return value.slice();
}

// verifySashGrant checks a sash/1 document. nowUnix defaults to the current
// second. exp equal to nowUnix is still valid. Returns { ok, error, grant }.
function verifySashGrant(doc, fleetRaw, emerRaw, nowUnix = Math.floor(Date.now() / 1000)) {
  const raw = asBuffer(doc);
  if (raw == null) return fail('grant_bad_shape');
  if (raw.length === 0) return fail('grant_missing');
  if (raw.length > SASH_MAX_DOCUMENT) return fail('grant_bad_shape');
  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    return fail('grant_bad_shape');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return fail('grant_bad_shape');
  for (const key of Object.keys(parsed)) {
    if (!KNOWN_FIELDS.has(key)) return fail('grant_bad_shape');
  }
  for (const key of ['v', 'actor', 'host', 'purpose', 'exp', 'lease_id', 'entitlements', 'sig']) {
    if (!Object.prototype.hasOwnProperty.call(parsed, key)) return fail('grant_bad_shape');
  }
  if (parsed.v !== 'sash/1' || typeof parsed.actor !== 'string' || parsed.actor === '') return fail('grant_bad_shape');
  if (typeof parsed.host !== 'string' || parsed.host === '') return fail('grant_bad_shape');
  if (typeof parsed.lease_id !== 'string' || parsed.lease_id === '') return fail('grant_bad_shape');
  if (typeof parsed.sig !== 'string' || parsed.sig === '') return fail('grant_bad_shape');
  if (!PURPOSES.has(parsed.purpose)) return fail('grant_bad_shape');
  if (!Number.isSafeInteger(parsed.exp)) return fail('grant_bad_shape');
  if (!Array.isArray(parsed.entitlements)) return fail('grant_bad_shape');
  for (const name of parsed.entitlements) {
    if (typeof name !== 'string' || name === '') return fail('grant_bad_shape');
  }
  const hasRead = Object.prototype.hasOwnProperty.call(parsed, 'file_read');
  const hasWrite = Object.prototype.hasOwnProperty.call(parsed, 'file_write');
  const fileRead = rootList(parsed.file_read, hasRead);
  const fileWrite = rootList(parsed.file_write, hasWrite);
  if (!fileRead || !fileWrite) return fail('grant_bad_shape');
  let allowPrivate = false;
  if (Object.prototype.hasOwnProperty.call(parsed, 'allow_private')) {
    if (typeof parsed.allow_private !== 'boolean') return fail('grant_bad_shape');
    allowPrivate = parsed.allow_private;
  }
  const grant = {
    v: parsed.v,
    actor: parsed.actor,
    host: parsed.host,
    purpose: parsed.purpose,
    exp: parsed.exp,
    lease_id: parsed.lease_id,
    entitlements: parsed.entitlements.slice(),
    file_read: fileRead,
    file_write: fileWrite,
    allow_private: allowPrivate
  };
  if (!distinctKeys(fleetRaw, emerRaw)) return fail('grant_bad_sig');
  const keyRaw = grant.purpose === 'emergency' ? emerRaw : fleetRaw;
  const key = publicKeyFromRaw(keyRaw);
  if (!key) return fail('grant_bad_sig');
  let sig;
  try {
    sig = Buffer.from(parsed.sig, 'base64');
  } catch {
    return fail('grant_bad_sig');
  }
  if (sig.length !== 64) return fail('grant_bad_sig');
  let ok = false;
  try {
    ok = crypto.verify(null, sashMessage(grant), key, sig);
  } catch {
    ok = false;
  }
  if (!ok) return fail('grant_bad_sig');
  if (grant.entitlements.includes('*')) return fail('grant_star');
  if (grant.exp < nowUnix) return fail('grant_expired');
  return { ok: true, error: null, grant };
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    process.stdin.on('data', (chunk) => {
      n += chunk.length;
      if (n > 1024 * 1024) {
        process.stdin.destroy();
        reject(shape());
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', () => reject(shape()));
  });
}

function main() {
  readStdin().then((buf) => {
    let input;
    try {
      input = JSON.parse(buf.toString('utf8'));
    } catch {
      throw shape();
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw shape();
    const built = buildSashTerminalGrant(input.seed, {
      actor: input.actor,
      host: input.host,
      purpose: input.purpose,
      exp: input.exp,
      lease_id: input.lease_id,
      policies: input.policies
    });
    process.stdout.write(JSON.stringify(built.document));
  }).catch(() => {
    process.stderr.write('grant_bad_shape');
    process.exit(1);
  });
}

module.exports = {
  buildSashTerminalGrant,
  verifySashGrant,
  signSashDocument,
  goPathClean
};

if (require.main === module) main();
