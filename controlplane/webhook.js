// Threats: SSRF from a user-configured webhook (cloud metadata, link-local,
// and, in production, loopback). Production requires https. One shot, no
// redirects. Does NOT store the secret. The router seals it with
// controlplane/seal.js before insert. GET never returns the secret.
'use strict';

function parseIPv4(host) {
  const match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host);
  if (!match) return null;
  const parts = match.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function hostIPv4(host) {
  const direct = parseIPv4(host);
  if (direct != null) return direct;
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!mapped) return null;
  const hi = Number.parseInt(mapped[1], 16);
  const lo = Number.parseInt(mapped[2], 16);
  return ((hi << 16) | lo) >>> 0;
}

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
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'metadata.google.internal' || host.endsWith('.internal')) {
    throw Object.assign(new Error('blocked_url'), { status: 400 });
  }
  const v4 = hostIPv4(host);
  if (v4 != null) {
    const linkLocal = (v4 >>> 16) === 0xa9fe;
    const loop = (v4 >>> 24) === 0x7f;
    if (linkLocal || host === '169.254.169.254') {
      throw Object.assign(new Error('blocked_url'), { status: 400 });
    }
    if (prod && loop) throw Object.assign(new Error('blocked_url'), { status: 400 });
  }
  if (prod && (host === 'localhost' || host === '::1')) {
    throw Object.assign(new Error('blocked_url'), { status: 400 });
  }
  if (host.startsWith('fe80:') || host.startsWith('fe80%')) {
    throw Object.assign(new Error('blocked_url'), { status: 400 });
  }
  return url;
}

module.exports = { assertWebhookURL, hostIPv4 };
