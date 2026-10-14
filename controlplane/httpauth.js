// Threats: demo credentials accepted in production, and long-lived API keys
// placed in WebSocket query strings (logs, proxies, Referer), and a
// cross-site page opening a terminal WebSocket (Origin allowlist). Does NOT
// authenticate the key itself; callers still verify the bearer against the store.
'use strict';

function demoKeyAllowed(env) {
  return env.SYSTEMAPI_ALLOW_DEMO === '1' && env.NODE_ENV !== 'production';
}

function agentAuthFromRequest(url, headers) {
  const params = url.searchParams;
  if (params.has('api_key')) {
    return { ok: false, status: 401, error: 'query_key_rejected' };
  }
  const auth = headers.authorization || headers.Authorization || '';
  if (!auth.startsWith('Bearer ')) {
    return { ok: false, status: 401, error: 'bearer_required' };
  }
  const token = auth.slice('Bearer '.length);
  if (!token || token !== token.trim() || /\s/.test(token)) {
    return { ok: false, status: 401, error: 'bearer_required' };
  }
  return { ok: true, token };
}

function ticketFromRequest(url) {
  const params = url.searchParams;
  if (params.has('api_key')) {
    return { ok: false, status: 401, error: 'query_key_rejected' };
  }
  const ticket = params.get('ticket');
  if (typeof ticket !== 'string' || !ticket.startsWith('stk_')) {
    return { ok: false, status: 401, error: 'ticket_required' };
  }
  return { ok: true, ticket };
}

// Browser origins that may open a terminal WebSocket. SYSTEMAPI_ALLOWED_ORIGINS
// (comma-separated exact origins) replaces the default, which is
// https://systemapi.io, the SYSTEMAPI_PUBLIC_URL origin, and the local dev
// servers outside production.
function allowedOrigins(env = {}) {
  if (typeof env.SYSTEMAPI_ALLOWED_ORIGINS === 'string' && env.SYSTEMAPI_ALLOWED_ORIGINS.trim() !== '') {
    return new Set(env.SYSTEMAPI_ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean));
  }
  const out = new Set(['https://systemapi.io']);
  if (env.SYSTEMAPI_PUBLIC_URL) {
    try {
      out.add(new URL(env.SYSTEMAPI_PUBLIC_URL).origin);
    } catch {
      // An invalid public URL adds nothing.
    }
  }
  if (env.NODE_ENV !== 'production') {
    out.add('http://localhost:5173');
    out.add('http://localhost:3000');
  }
  return out;
}

// A missing Origin (the CLI, agents) is allowed: the ticket is the
// credential. A present Origin must match the allowlist exactly, so a page
// on another site cannot ride a leaked ticket.
function originAllowed(origin, env = {}) {
  if (origin === undefined) return true;
  if (typeof origin !== 'string') return false;
  return allowedOrigins(env).has(origin);
}

// Credentialed CORS origins: the same list as allowedOrigins, but only exact
// origins (scheme://host[:port], no path, no wildcard) and https only, except
// http://localhost / 127.0.0.1 outside production. Anything else is dropped.
function corsOrigins(env = {}) {
  const prod = env.NODE_ENV === 'production';
  const out = [];
  for (const raw of allowedOrigins(env)) {
    let url;
    try {
      url = new URL(raw);
    } catch {
      continue;
    }
    if (url.origin !== raw || raw.includes('*')) continue;
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (url.protocol === 'https:' || (url.protocol === 'http:' && local && !prod)) out.push(raw);
  }
  return out;
}

// Threats: another site reading credentialed responses. No CORS headers at
// all on /oauth (login, callback, device verify, user and its CSRF token);
// elsewhere only the exact origins from corsOrigins.
function corsMiddleware(env = {}) {
  const cors = require('cors');
  const allow = new Set(corsOrigins(env));
  const handler = cors({
    origin: (origin, cb) => cb(null, typeof origin === 'string' && allow.has(origin)),
    credentials: true
  });
  return (req, res, next) => {
    if (req.path === '/oauth' || req.path.startsWith('/oauth/')) {
      next();
      return;
    }
    handler(req, res, next);
  };
}

module.exports = { demoKeyAllowed, agentAuthFromRequest, ticketFromRequest, allowedOrigins, originAllowed, corsOrigins, corsMiddleware };
