/**
 * Outbound guard for POST /playground/execute.
 *
 * Threats: SSRF through the playground proxy. The caller's endpoint must
 * resolve, against the configured base URL, to that base's exact origin
 * (so "@host", ".host", "//host", "/\host", ":port" and absolute URLs are
 * refused), and the connection is made only to an address that is not
 * loopback, private (RFC 1918, ULA), CGNAT, link-local (cloud metadata
 * 169.254.169.254 included), multicast, reserved, documentation or an IPv6
 * form that embeds or tunnels IPv4 (mapped, compat, NAT64, 6to4, Teredo).
 * The check runs on the DNS answer inside the socket's own lookup, and the
 * socket connects to the address that lookup returned (no second
 * resolution, so a rebinding name cannot swap in a blocked address after
 * the check); any blocked address in the answer refuses the whole name. IP
 * literals (which skip lookup) are checked before the request. Redirects
 * are never followed and env proxies are ignored.
 * Does NOT limit which public hosts are reached beyond the base origin, or
 * defend against a hostile operator-set base URL; allowPrivate (tests, local
 * development, never production) turns the address check off.
 */

'use strict';

const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

// Two lists: net.BlockList matches an IPv4 query against an IPv4-mapped
// IPv6 rule (::ffff:0:0/96 would block every IPv4 address), so each family
// is checked only against its own rules.
const BLOCKED_V4 = new net.BlockList();
const BLOCKED_V6 = new net.BlockList();
for (const [addr, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
]) BLOCKED_V4.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of [
  ['::', 96], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64],
  ['2001::', 32], ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
]) BLOCKED_V6.addSubnet(addr, prefix, 'ipv6');

function blockedAddress(address) {
  const host = String(address).replace(/^\[(.*)\]$/, '$1').replace(/%.*$/, '');
  const family = net.isIP(host);
  if (family === 0) return true;
  return family === 4 ? BLOCKED_V4.check(host, 'ipv4') : BLOCKED_V6.check(host, 'ipv6');
}

function egressError(code) {
  return Object.assign(new Error(code), { code: 'EGRESS_BLOCKED', egress: code });
}

// A net/tls lookup that resolves once, refuses the name if any answer is
// blocked, and hands the socket exactly the vetted addresses.
function guardedLookup(resolve = dns.lookup) {
  return (hostname, options, callback) => {
    if (typeof options === 'function') { callback = options; options = {}; }
    const opts = typeof options === 'number' ? { family: options } : (options || {});
    resolve(hostname, { family: opts.family || 0, all: true, verbatim: true }, (err, addresses) => {
      if (err) return callback(err);
      const list = Array.isArray(addresses) ? addresses : [];
      if (list.length === 0 || list.some((a) => blockedAddress(a.address))) return callback(egressError('blocked_address'));
      if (opts.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    });
  };
}

// The request URL for a caller's endpoint: refused (400) unless it stays on
// the base URL's origin; an IP-literal base in a blocked range is refused
// (403). Returns the URL string.
function targetURL(baseURL, endpoint, { allowPrivate = false } = {}) {
  const bad = () => Object.assign(new Error('bad_endpoint'), { status: 400 });
  if (typeof endpoint !== 'string' || endpoint.length === 0 || endpoint.length > 2048) throw bad();
  if (!endpoint.startsWith('/') || endpoint.startsWith('//') || /[\\\s\x00-\x1f\x7f]/.test(endpoint)) throw bad();
  const base = new URL(baseURL);
  if (base.protocol !== 'http:' && base.protocol !== 'https:') throw bad();
  let url;
  try {
    url = new URL(base.origin + endpoint);
  } catch {
    throw bad();
  }
  if (url.origin !== base.origin || url.username || url.password) throw bad();
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1');
  if (!allowPrivate && net.isIP(host) && blockedAddress(host)) {
    throw Object.assign(egressError('blocked_address'), { status: 403 });
  }
  return url.toString();
}

// Agents whose sockets connect only through guardedLookup.
function agents({ allowPrivate = false, resolve } = {}) {
  if (allowPrivate) return { httpAgent: new http.Agent(), httpsAgent: new https.Agent() };
  const lookup = guardedLookup(resolve);
  return { httpAgent: new http.Agent({ lookup }), httpsAgent: new https.Agent({ lookup }) };
}

// Hop-by-hop and routing headers the caller may not set on the proxied call.
const DROPPED_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authorization', 'proxy-connection', 'proxy-authenticate',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'forwarded', 'x-forwarded-for',
  'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip'
]);

function forwardHeaders(headers) {
  const out = {};
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return out;
  for (const [name, value] of Object.entries(headers)) {
    if (DROPPED_HEADERS.has(name.toLowerCase())) continue;
    if (typeof value !== 'string') continue;
    out[name] = value;
  }
  return out;
}

module.exports = { blockedAddress, guardedLookup, targetURL, agents, forwardHeaders };
