// Threats: SSRF from a user-configured webhook: cloud metadata and
// link-local (always), and in production loopback, RFC 1918, CGNAT, ULA and
// every other range playground/egress.js refuses; a DNS name that resolves
// (or later rebinds) to one of them. The URL is checked at create time on
// its literal host and on its DNS answer (unresolvable is refused), and every
// delivery re-checks the stored URL and connects through egress agents whose
// lookup refuses a blocked answer and pins the checked address. Production
// requires https. One shot, no redirects, no env proxy. Loopback and private
// addresses are allowed only when SYSTEMAPI_WEBHOOK_ALLOW_PRIVATE=1 outside
// production (local receivers, tests); unset, they are refused everywhere. Does NOT store the secret. The router seals it with
// controlplane/seal.js before insert. GET never returns the secret.
'use strict';

const dns = require('node:dns');
const net = require('node:net');
const egress = require('../playground/egress');

function parseIPv4(host) {
  const match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host);
  if (!match) return null;
  const parts = match.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

// Used by controlplane/oauth.js.
function hostIPv4(host) {
  const direct = parseIPv4(host);
  if (direct != null) return direct;
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!mapped) return null;
  const hi = Number.parseInt(mapped[1], 16);
  const lo = Number.parseInt(mapped[2], 16);
  return ((hi << 16) | lo) >>> 0;
}

function blocked() {
  return Object.assign(new Error('blocked_url'), { status: 400 });
}

// Opt-in: loopback and private targets only with
// SYSTEMAPI_WEBHOOK_ALLOW_PRIVATE=1, and never in production.
function allowPrivate(env) {
  return env.SYSTEMAPI_WEBHOOK_ALLOW_PRIVATE === '1' && env.NODE_ENV !== 'production';
}

// The synchronous part: shape, scheme, names and IP literals.
function assertWebhookURL(raw, env) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw Object.assign(new Error('invalid_url'), { status: 400 });
  }
  if (url.username || url.password) throw Object.assign(new Error('invalid_url'), { status: 400 });
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw Object.assign(new Error('invalid_url'), { status: 400 });
  }
  const prod = env.NODE_ENV === 'production';
  if (prod && url.protocol !== 'https:') {
    throw Object.assign(new Error('https_required'), { status: 400 });
  }
  // A trailing dot names the same host (localhost., metadata.google.internal.).
  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (host === 'metadata.google.internal' || host.endsWith('.internal')) throw blocked();
  if (!allowPrivate(env) && (host === 'localhost' || host.endsWith('.localhost'))) throw blocked();
  if (net.isIP(host) && egress.blockedAddress(host, { allowPrivate: allowPrivate(env) })) throw blocked();
  return url;
}

// Create time: assertWebhookURL, then the name's DNS answer (one lookup,
// every address checked; a name that does not resolve is refused).
async function resolveWebhookURL(raw, env, resolve = dns.lookup) {
  const url = assertWebhookURL(raw, env);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) return url;
  const addresses = await new Promise((done) => {
    resolve(host, { all: true, verbatim: true }, (err, list) => done(err ? null : list));
  });
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw Object.assign(new Error('unresolvable_url'), { status: 400 });
  }
  if (addresses.some((a) => egress.blockedAddress(a.address, { allowPrivate: allowPrivate(env) }))) throw blocked();
  return url;
}

// Delivery agents: the socket's lookup refuses a blocked answer and connects
// to the address it checked.
function webhookAgents(env, resolve) {
  return egress.agents({ allowPrivate: allowPrivate(env), resolve });
}

module.exports = { assertWebhookURL, resolveWebhookURL, webhookAgents, hostIPv4 };
