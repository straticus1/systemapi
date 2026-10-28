// Threats: missing auth, query-string API keys, cross-tenant object access,
// and a viewer running exec. A non-admin must not receive allow_k8s or an
// image list, and "*" is not copied as allow-all. Each handler authenticates.
// Unknown hosts in another tenant are 404. Does NOT expire API keys; that stays in the key store.
// OAuth access tokens are session principals. Device and IdP secrets stay in
// controlplane/oauth.js and are not written to the audit log.
// Host retirement is admin-only in the host's tenant, needs a reason, refuses
// a connected host (409 host_online) unless force, and is one audited
// registry write; a retired row never resolves by name or id.
'use strict';

const express = require('express');
const axios = require('axios');
const { hasScope, roleFromGroups, scopesForRole, intersectScopes, ALL } = require('./authz');
const oauth = require('./oauth');
const { issueLease, PTY_SESSION_RE, watchReasonOk } = require('./lease');
const { issueTicket, TTL_MS: TICKET_TTL_MS } = require('./tickets');
const { CHANNEL_PURPOSES, PURPOSE_SCOPES, validateBinding, policyDecision } = require('./channels');
const { fingerprint, randomToken, tokenEqual } = require('./token');
const { sealSecret, openSecret } = require('./seal');
const { assertWebhookURL } = require('./webhook');
const { bucketName, linearForecast, toCSV, cronValid, zscore } = require('./stats');
const { listPlaybooks, readPlaybook } = require('./playbooks');
const xfer = require('../playground/xfer');
const { WATCH_PURPOSES, watchScopes } = require('../playground/watch');
const { jobView, TERMINAL_JOB_STATUSES } = require('../playground/jobs');
const { entitlementsSha256 } = require('./entitlements');

const SCRIPT_MAX = 64 * 1024;
const JOB_TIMEOUT_DEFAULT_S = 300;
const JOB_MAX_DEFAULT_S = 1800;
const JOB_MAX_CAP_S = 3600;
const JOB_WAIT_MAX_S = 25;
const COOLDOWN_MS = 5 * 60 * 1000;
const USER_RE = /^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,128}$/;
const RESOLVE_NAME_RE = /^[A-Za-z0-9._-]{1,253}$/;
const RESOLVE_STALE_HOURS_DEFAULT = 24;
const RETIRE_REASON_MAX = 256;
const TICKET_PURPOSES = new Set(['terminal:open', 'terminal:root', 'breakglass:open', ...CHANNEL_PURPOSES, ...WATCH_PURPOSES.keys()]);
const TICKET_RATE_DEFAULT = 20;
const TICKET_RATE_TCP_DEFAULT = 120;
const PRIVILEGED_PURPOSES = new Set(['breakglass:open', 'terminal:root', 'file:root']);
const formBody = express.urlencoded({ extended: false, limit: '8kb' });
const BOOL_ENTITLEMENTS = [
  'allow_fs_write',
  'allow_fs_read',
  'allow_net_outbound',
  'allow_exec',
  'allow_config_write',
  'allow_service_reload',
  'allow_containers',
  'allow_k3s'
];
const HOST_BOOL_ENTITLEMENTS = ['allow_linux', 'allow_k8s'];
const LIST_ENTITLEMENTS = [
  'allow_packages',
  'allow_images',
  'allow_k3s_namespaces',
  'allow_k8s_namespaces',
  'allow_net_manage',
  'allow_mount_targets',
  'allow_sysctl'
];
const DENIED_SYSCTL = new Set(['kernel.core_pattern', 'kernel.modprobe', 'kernel.hotplug']);

function http(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function sendError(res, err) {
  const status = err.status && err.status >= 400 && err.status < 600 ? err.status : 500;
  if (status >= 500) console.error('[control]', err.message);
  // A 500 body carries only a deliberate API code (an error thrown with its
  // status set and a lowercase code, such as xfer's "io"); anything else,
  // such as a Postgres error and its SQLSTATE, is "internal".
  const deliberate = Number.isInteger(err.status) && typeof err.code === 'string' && /^[a-z_]{1,64}$/.test(err.code);
  res.status(status).json({ error: status === 500 && !deliberate ? 'internal' : (err.code || err.message || 'error') });
}

function noStore(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Content-Security-Policy', "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
}

function bodyString(body, name) {
  if (!body || typeof body !== 'object') return '';
  const value = body[name];
  return typeof value === 'string' ? value : '';
}

function parseForm(req, res, next) {
  formBody(req, res, (err) => {
    if (!err) {
      next();
      return;
    }
    noStore(res);
    res.status(400).json({ error: 'login_denied' });
  });
}

// CSRF for the device verify page is a synchronizer token kept in the
// server-side session (oauth.sessionCsrf) and compared in constant time.
// SameSite cannot carry this alone: it is configurable
// (SESSION_COOKIE_SAMESITE) and the SSO round trips need Lax.
function sessionUserOf(req) {
  const user = req.session && req.session.user;
  return user && typeof user === 'object' ? user : null;
}

function adminTenantIds(principal) {
  return principal.memberships
    .filter((member) => hasScope(scopesFor(principal, member.tenant_id), 'admin'))
    .map((member) => member.tenant_id);
}

async function requireLinkUser(fleet, principal, userId) {
  const admins = adminTenantIds(principal);
  if (admins.length === 0) throw http(403, 'scope_denied');
  if (typeof userId !== 'string' || !USER_RE.test(userId)) throw http(404, 'not_found');
  const ids = await oauth.memberIds(fleet.registry, admins);
  if (!ids.includes(userId)) throw http(404, 'not_found');
}

function scopesFor(principal, tenantId) {
  const member = principal.memberships.find((m) => m.tenant_id === tenantId);
  if (!member) return new Set();
  if (principal.kind === 'session') return scopesForRole(member.effective_role);
  return intersectScopes(principal.keyScopes, member.effective_role);
}

async function authenticate(req, fleet) {
  if (!fleet.registry) throw http(503, 'registry_unavailable');
  if (req.query && Object.prototype.hasOwnProperty.call(req.query, 'api_key')) {
    throw http(401, 'query_key_rejected');
  }
  const headerKey = req.get('x-api-key');
  const authorization = req.get('authorization') || '';
  let presented = headerKey;
  if (!presented && authorization.startsWith('Bearer ')) presented = authorization.slice('Bearer '.length);
  if (presented) {
    if (presented !== presented.trim() || /\s/.test(presented)) throw http(401, 'bearer_required');
    let oauthUser = null;
    try {
      oauthUser = await oauth.userForAccessToken(fleet.registry, presented);
    } catch (err) {
      console.error('[control] oauth lookup failed:', err.code || 'oauth_lookup_failed');
      throw http(503, 'oauth_unavailable');
    }
    if (oauthUser && oauthUser.user_id) {
      const memberships = await fleet.registry.membershipsForUser(oauthUser.user_id);
      return {
        kind: 'session',
        userId: oauthUser.user_id,
        keyScopes: null,
        memberships: memberships.map((m) => ({ ...m, effective_role: m.role }))
      };
    }
    const keyData = await fleet.verifyApiKey(presented);
    if (!keyData) {
      await safeSecurity(fleet, {
        kind: 'auth_fail',
        actor_fingerprint: fingerprint(presented),
        detail: { path: req.path }
      });
      throw http(403, 'forbidden');
    }
    const keyScopes = await fleet.registry.scopesForKey(keyData.key_id);
    const memberships = await fleet.registry.membershipsForUser(keyData.user_id);
    return {
      kind: 'key',
      userId: keyData.user_id,
      keyId: keyData.key_id,
      keyScopes,
      memberships: memberships.map((m) => ({ ...m, effective_role: m.role }))
    };
  }
  const sessionUser = req.session && req.session.user;
  if (sessionUser && sessionUser.id) {
    // Sub-only identity: only membership rows whose sso_sub is exactly the
    // session's Authentik sub count. Email is display data only; an unbound
    // sub is refused.
    const userId = await oauth.sessionMember(fleet.registry, sessionUser);
    if (!userId) throw http(403, 'sso_unbound');
    const memberships = (await fleet.registry.membershipsForSub(sessionUser.id))
      .filter((m) => m.user_id === userId && m.sso_sub === sessionUser.id);
    const boosted = roleFromGroups(sessionUser.groups);
    return {
      kind: 'session',
      userId,
      email: sessionUser.email,
      keyScopes: null,
      groupRole: boosted || null,
      memberships: memberships.map((m) => ({ ...m, effective_role: boosted || m.role }))
    };
  }
  throw http(401, 'unauthorized');
}

async function safeSecurity(fleet, event) {
  try {
    if (fleet.registry) await fleet.registry.recordSecurity(event);
  } catch (err) {
    console.error('[control] security event failed:', err.message);
  }
}

function tenantIds(principal) {
  return principal.memberships.map((m) => m.tenant_id);
}

async function requireHost(fleet, principal, hostId) {
  const host = await fleet.registry.getHost(tenantIds(principal), hostId);
  if (!host) {
    await safeSecurity(fleet, {
      kind: 'idor',
      tenant_id: null,
      actor_fingerprint: principal.keyId ? fingerprint(principal.keyId) : fingerprint(principal.userId),
      detail: { host_id: hostId }
    });
    throw http(404, 'not_found');
  }
  return host;
}

function requireScope(fleet, principal, tenantId, scope) {
  if (!hasScope(scopesFor(principal, tenantId), scope)) {
    safeSecurity(fleet, {
      kind: 'scope_deny',
      tenant_id: tenantId,
      actor_fingerprint: fingerprint(principal.userId),
      detail: { scope }
    });
    throw http(403, 'scope_denied');
  }
}

// Scope before host: a principal that holds every scope in none of its
// tenants is refused (403) before any host lookup, so a key without the scope
// cannot tell which host ids exist. The host's own tenant is checked again
// with requireScope once the host is found.
function requireScopeAnywhere(fleet, principal, scopes) {
  const held = tenantIds(principal).some((id) => {
    const have = scopesFor(principal, id);
    return scopes.every((scope) => hasScope(have, scope));
  });
  if (!held) {
    safeSecurity(fleet, {
      kind: 'scope_deny',
      tenant_id: null,
      actor_fingerprint: fingerprint(principal.userId),
      detail: { scope: scopes.join(',') }
    });
    throw http(403, 'scope_denied');
  }
}

// SYSTEMAPI_RESOLVE_STALE_HOURS: how long an offline row may have been
// silent and still make its name ambiguous. Default 24; a value that is not
// a number from 0 to 8760 falls back to the default.
function resolveStaleMs(env) {
  const raw = env && env.SYSTEMAPI_RESOLVE_STALE_HOURS;
  const hours = raw === undefined || raw === '' ? NaN : Number(raw);
  const ok = Number.isFinite(hours) && hours >= 0 && hours <= 8760;
  return (ok ? hours : RESOLVE_STALE_HOURS_DEFAULT) * 3600 * 1000;
}

// One row for a name: the only match, or the single online match when every
// other match is offline and last seen more than staleMs ago (never seen
// counts as stale). Retired rows never reach here. Null means ambiguous.
function pickResolved(matches, isOnline, staleMs, now = Date.now()) {
  if (matches.length === 1) return matches[0];
  const online = matches.filter(isOnline);
  if (online.length !== 1) return null;
  const stale = (row) => {
    const seen = row.last_seen_at ? new Date(row.last_seen_at).getTime() : NaN;
    return !Number.isFinite(seen) || now - seen > staleMs;
  };
  return matches.every((row) => row === online[0] || stale(row)) ? online[0] : null;
}

function clampList(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const item of value) {
    if (typeof item !== 'string') continue;
    if (item.length === 0 || item.length > 256) continue;
    if (item.includes('*') || item.includes('..') || item.includes('\0') || item.includes('\n') || item.includes('\r')) continue;
    out.push(item);
    if (out.length >= 32) break;
  }
  return out;
}

function clampEntitlements(requested, scopes) {
  const out = {};
  for (const key of BOOL_ENTITLEMENTS) out[key] = false;
  for (const key of HOST_BOOL_ENTITLEMENTS) out[key] = false;
  for (const key of LIST_ENTITLEMENTS) out[key] = [];
  if (!requested || typeof requested !== 'object' || Array.isArray(requested)) return out;
  const admin = hasScope(scopes, 'admin');
  for (const key of BOOL_ENTITLEMENTS) {
    if (!requested[key]) continue;
    if (key === 'allow_exec' && hasScope(scopes, 'exec:run')) out[key] = true;
    else if (admin) out[key] = true;
  }
  if (admin) {
    for (const key of HOST_BOOL_ENTITLEMENTS) {
      if (requested[key] === true) out[key] = true;
    }
    for (const key of LIST_ENTITLEMENTS) {
      let items = clampList(requested[key]);
      if (key === 'allow_sysctl') items = items.filter((item) => !DENIED_SYSCTL.has(item));
      out[key] = items;
    }
  }
  return out;
}

async function runScript(fleet, principal, host, script, entitlements) {
  if (typeof script !== 'string' || script.length === 0 || script.length > SCRIPT_MAX) {
    throw http(400, 'bad_script');
  }
  const scopes = scopesFor(principal, host.tenant_id);
  requireScope(fleet, principal, host.tenant_id, 'exec:run');
  if (!fleet.signer) throw http(503, 'signer_unavailable');
  const lease = issueLease(fleet.signer, {
    hostId: host.host_id,
    action: 'sysscript',
    payload: script,
    ttl: 60
  });
  const requestId = randomToken(16);
  let result;
  try {
    result = await fleet.pushSysscript(host.host_id, script, clampEntitlements(entitlements, scopes), requestId, lease);
    if (fleet.metrics && fleet.metrics.executionsTotal) fleet.metrics.executionsTotal.inc({ status: 'ok' });
  } catch (err) {
    if (fleet.metrics && fleet.metrics.executionsTotal) fleet.metrics.executionsTotal.inc({ status: 'error' });
    throw http(err.status || 409, err.code || 'agent_rejected');
  }
  await fleet.registry.appendAudit({
    tenant_id: host.tenant_id,
    host_id: host.host_id,
    actor: principal.userId,
    action: 'sysscript',
    payload: { request_id: requestId, lease_nonce: lease.nonce_hex }
  });
  return { request_id: requestId, result };
}

// Ticket rate, per actor and host, per minute. Four separate budgets:
// - terminal: terminal:open, file:read, file:write;
//   SYSTEMAPI_TICKET_RATE_PER_HOST (default 20);
// - privileged: breakglass:open, terminal:root, file:root, xfer:root,
//   terminal:watch, terminal:watch_rw (one request is one prompt on
//   somebody's terminal);
//   SYSTEMAPI_TICKET_RATE_PRIVILEGED (default 20), so one operator cannot
//   starve another user or an admin's break-glass;
// - tcp: tcp:open and mesh:open; SYSTEMAPI_TICKET_RATE_TCP (default 120),
//   because one RDP or HTTP session opens several connections (TCP §2); a
//   mesh session costs one ticket however many streams it carries (MESH §2);
// - xfer: xfer:put, xfer:get grants; SYSTEMAPI_TICKET_RATE_XFER (default
//   20), so a scripted put loop cannot lock the operator out of the shell
//   or file session needed to diagnose it.
// In process memory, like the tickets themselves.
function ticketBudget(purpose) {
  if (PRIVILEGED_PURPOSES.has(purpose) || purpose === 'xfer:root' || WATCH_PURPOSES.has(purpose)) return 'privileged';
  if (purpose === 'tcp:open' || purpose === 'mesh:open') return 'tcp';
  if (purpose === 'xfer:put' || purpose === 'xfer:get') return 'xfer';
  return 'terminal';
}

function ticketAllowed(fleet, actor, hostId, purpose, now = Date.now()) {
  const env = fleet.env || {};
  const budget = ticketBudget(purpose);
  const setting = {
    privileged: 'SYSTEMAPI_TICKET_RATE_PRIVILEGED', tcp: 'SYSTEMAPI_TICKET_RATE_TCP', terminal: 'SYSTEMAPI_TICKET_RATE_PER_HOST', xfer: 'SYSTEMAPI_TICKET_RATE_XFER'
  }[budget];
  const raw = Number(env[setting]);
  const fallback = budget === 'tcp' ? TICKET_RATE_TCP_DEFAULT : TICKET_RATE_DEFAULT;
  const limit = Number.isInteger(raw) && raw > 0 ? raw : fallback;
  const key = JSON.stringify([String(actor), hostId, budget]);
  if (!fleet.ticketRate) fleet.ticketRate = new Map();
  const recent = (fleet.ticketRate.get(key) || []).filter((t) => now - t < 60_000);
  if (recent.length >= limit) {
    fleet.ticketRate.set(key, recent);
    return false;
  }
  recent.push(now);
  fleet.ticketRate.set(key, recent);
  if (fleet.ticketRate.size > 10_000) {
    for (const [k, times] of fleet.ticketRate) {
      if (!times.some((t) => now - t < 60_000)) fleet.ticketRate.delete(k);
    }
  }
  return true;
}

// The audit row is written before the ticket exists, so a failed audit write
// issues nothing. The ticket itself is never written to the audit log.
// binding is null, { target } (tcp:open) or { root } (file:*); it is
// audited and stored on the ticket.
// binding.watch ({ sessionId, watchId, mode }) is a granted watch whose
// rate budget the route already spent.
async function issueAuditedTicket(fleet, principal, host, purpose, binding = null) {
  if (!fleet.tickets) throw http(503, 'tickets_unavailable');
  const watch = binding && binding.watch;
  if (!watch && !ticketAllowed(fleet, principal.userId, host.host_id, purpose)) throw http(429, 'rate_limited');
  const payload = { purpose };
  if (watch) Object.assign(payload, { session_id: watch.sessionId, watch_id: watch.watchId, mode: watch.mode });
  if (binding && binding.target) payload.target = { host: binding.target.host, port: binding.target.port };
  if (binding && binding.root) payload.root = binding.root;
  await fleet.registry.appendAudit({
    tenant_id: host.tenant_id,
    host_id: host.host_id,
    actor: principal.userId,
    action: 'ticket_issued',
    payload
  });
  const ticket = issueTicket(fleet.tickets, {
    hostId: host.host_id,
    purpose,
    tenantId: host.tenant_id,
    actor: principal.userId,
    auth: { kind: principal.kind, keyId: principal.keyId || null, groupRole: principal.groupRole || null },
    target: binding && binding.target,
    root: binding && binding.root,
    watch
  });
  return {
    ticket,
    expires_at: new Date(Date.now() + TICKET_TTL_MS).toISOString(),
    expires_in: TICKET_TTL_MS / 1000,
    host_id: host.host_id,
    purpose
  };
}

async function deliverWebhooks(fleet, tenantId, body) {
  if (!fleet.registry.webhooksForTenant) return;
  let hooks = [];
  try {
    hooks = await fleet.registry.webhooksForTenant(tenantId);
  } catch (err) {
    console.error('[control] webhook list failed:', err.message);
    return;
  }
  const raw = JSON.stringify(body);
  for (const hook of hooks) {
    let secret;
    try {
      secret = openSecret(hook.secret, fleet.env || {});
    } catch (err) {
      console.error('[control] webhook secret unusable:', err.code || 'webhook_secret_rejected');
      continue;
    }
    const mac = require('node:crypto').createHmac('sha256', secret).update(raw).digest('hex');
    axios.post(hook.url, raw, {
      timeout: 5000,
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/json',
        'X-SystemAPI-Signature': `sha256=${mac}`
      },
      validateStatus: () => true
    }).catch((err) => {
      console.error('[control] webhook delivery failed:', err.message);
    });
  }
}

// §7.2 watch request. Order: body shape (400), scope in some tenant (403),
// the session visible to the actor (404), scope in the session's tenant
// (403), the privileged rate budget (429), then the agent's answer: a grant
// returns the ticket; denied or no answer in 35 s is 403 watch_denied, a
// prompt already open is 409 busy. A view-only watch with consent needs
// terminal:watch; override (view only) and read-write need admin, and
// override needs a reason. Every request needs a reason.
async function watchTicket(fleet, principal, purpose, body, res) {
  const mode = WATCH_PURPOSES.get(purpose);
  const sessionId = body.session_id;
  if (typeof sessionId !== 'string' || !PTY_SESSION_RE.test(sessionId)) throw http(400, 'bad_session_id');
  if (body.mode !== undefined && body.mode !== mode) throw http(400, 'bad_mode');
  if (body.override !== undefined && typeof body.override !== 'boolean') throw http(400, 'bad_override');
  const override = body.override === true;
  const reason = body.reason;
  if (reason === undefined || reason === null || (typeof reason === 'string' && reason.trim() === '')) throw http(400, 'reason_required');
  if (!watchReasonOk(reason)) throw http(400, 'bad_reason');
  const scopes = watchScopes(mode, override);
  requireScopeAnywhere(fleet, principal, scopes);
  const session = fleet.terminalSessions.get(sessionId);
  if (!session || session.ended || !session.announced) throw http(404, 'unknown_session');
  let host;
  try {
    host = await requireHost(fleet, principal, session.hostId);
  } catch (err) {
    if (err.status === 404) throw http(404, 'unknown_session');
    throw err;
  }
  if (host.tenant_id !== session.tenantId) throw http(404, 'unknown_session');
  for (const scope of scopes) requireScope(fleet, principal, session.tenantId, scope);
  if (!fleet.watch) throw http(501, 'agent_unsupported');
  if (!fleet.tickets) throw http(503, 'tickets_unavailable');
  if (!ticketAllowed(fleet, principal.userId, host.host_id, purpose)) throw http(429, 'rate_limited');
  // A client that hangs up while the user is being asked withdraws the request.
  const client = { gone: false, onGone: null };
  res.on('close', () => {
    if (res.writableFinished) return;
    client.gone = true;
    if (client.onGone) client.onGone();
  });
  const w = await fleet.watch.request({ actor: principal.userId, session, mode, override, reason, client });
  let out;
  try {
    out = await issueAuditedTicket(fleet, principal, host, purpose, { watch: { sessionId: session.id, watchId: w.id, mode } });
  } catch (err) {
    await fleet.watch.stop(w, 'ticket_failed');
    throw err;
  }
  if (client.gone) {
    fleet.tickets.delete(out.ticket);
    await fleet.watch.stop(w, 'client_gone');
    throw http(499, 'client_gone');
  }
  return { ...out, session_id: session.id, watch_id: w.id, mode, consent: w.consent };
}

// SYSTEMAPI_SYSSCRIPT_JOBS=0 turns the /jobs routes off (503 jobs_disabled).
function requireJobs(fleet) {
  const raw = fleet.env && fleet.env.SYSTEMAPI_SYSSCRIPT_JOBS;
  if (String(raw === undefined || raw === null || raw === '' ? '1' : raw).trim() === '0' || !fleet.jobs) {
    throw http(503, 'jobs_disabled');
  }
}

// SYSTEMAPI_SYSSCRIPT_JOB_MAX_S: the largest timeout_s a job may ask for.
// Default 1800; a value that is not an integer from 1 to 3600 falls back to
// the default.
function jobMaxSeconds(env) {
  const raw = env && env.SYSTEMAPI_SYSSCRIPT_JOB_MAX_S;
  const n = raw === undefined || raw === '' ? NaN : Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= JOB_MAX_CAP_S ? n : JOB_MAX_DEFAULT_S;
}

function intField(body, name, fallback, min, max, code) {
  const value = body[name] === undefined || body[name] === null ? fallback : body[name];
  if (!Number.isInteger(value) || value < min || value > max) throw http(400, code);
  return value;
}

// A job's output, and its cancel, belong to its submitter and the admins
// of its tenant.
function jobOwnerOrAdmin(principal, job) {
  return job.actor === String(principal.userId) || hasScope(scopesFor(principal, job.tenant_id), 'admin');
}

// A job of the principal's tenants with exec:run in the job's tenant. A
// missing job, or one in another tenant, is the same 404 with an idor
// event (as requireHost).
async function requireJob(fleet, principal, jobId) {
  const job = typeof jobId === 'string' ? await fleet.registry.getJob(tenantIds(principal), jobId) : null;
  if (!job) {
    await safeSecurity(fleet, {
      kind: 'idor',
      tenant_id: null,
      actor_fingerprint: principal.keyId ? fingerprint(principal.keyId) : fingerprint(principal.userId),
      detail: { job_id: typeof jobId === 'string' ? jobId.slice(0, 64) : null }
    });
    throw http(404, 'not_found');
  }
  requireScope(fleet, principal, job.tenant_id, 'exec:run');
  return job;
}

function mount(app, fleet) {
  const wrap = (fn) => async (req, res) => {
    try {
      await fn(req, res);
    } catch (err) {
      if (!res.headersSent) sendError(res, err);
    }
  };

  app.post('/oauth/device', parseForm, wrap(async (req, res) => {
    noStore(res);
    const out = await oauth.startDevice(fleet.registry, bodyString(req.body, 'username'), fleet.env || {}, {
      ip: req.ip,
      ua: req.get('user-agent')
    });
    res.json(out);
  }));

  // RFC 8628 entry page. The query string is ignored: a code never arrives in
  // a URL. With no SSO session nothing is stored (no session, no token).
  app.get('/oauth/device/verify', wrap(async (req, res) => {
    noStore(res);
    const sessionUser = sessionUserOf(req);
    if (!sessionUser) {
      res.type('html').send(oauth.ssoPage());
      return;
    }
    const csrf = oauth.sessionCsrf(req);
    const member = await oauth.sessionMember(fleet.registry, sessionUser);
    if (!member || !(await oauth.sessionOwnsUser(fleet.registry, sessionUser, member))) {
      res.status(403).type('html').send(oauth.unboundPage(sessionUser, csrf));
      return;
    }
    res.type('html').send(oauth.entryPage(sessionUser, member, csrf));
  }));

  // Never approves on possession of the code alone: the CSRF token must match
  // this browser session, the session's sub must be bound to the member that
  // owns the typed code, and a separate confirm step shows who asked.
  app.post('/oauth/device/verify', parseForm, wrap(async (req, res) => {
    noStore(res);
    if (!oauth.csrfValid(req, bodyString(req.body, 'csrf'))) throw http(403, 'csrf_denied');
    const sessionUser = sessionUserOf(req);
    const csrf = req.session.csrf;
    const member = await oauth.sessionMember(fleet.registry, sessionUser);
    if (!member || !(await oauth.sessionOwnsUser(fleet.registry, sessionUser, member))) {
      res.status(403).type('html').send(sessionUser ? oauth.unboundPage(sessionUser, csrf) : oauth.ssoPage());
      return;
    }
    if (!fleet.codeTries) fleet.codeTries = new Map();
    const sessionKey = 'session:' + req.sessionID;
    const ipKey = 'ip:' + (req.ip || 'unknown');
    if (!oauth.codeEntryAllowed(fleet.codeTries, sessionKey, ipKey)) throw http(429, 'slow_down');
    const typed = bodyString(req.body, 'user_code');
    // A wrong, expired or used code and a code for another member get the
    // same answer and the same failure count; the page never names the
    // other member.
    const found = await oauth.pendingByTypedCode(fleet.registry, typed);
    if (!found || !(await oauth.sessionOwnsUser(fleet.registry, sessionUser, found.row.user_id))) {
      if (oauth.recordCodeFailure(fleet.codeTries, sessionKey, ipKey)) await oauth.denyPending(fleet.registry, member);
      res.status(403).type('html').send(oauth.entryPage(sessionUser, member, csrf, 'That code was not accepted (login_denied).'));
      return;
    }
    // Approving (here or through Google/GitHub) needs the confirm page for
    // this code to have been shown in this session first, so the person saw
    // the requester's IP, client and start time.
    const rawProvider = req.body && req.body.provider;
    const approving = (rawProvider != null && rawProvider !== '') || bodyString(req.body, 'confirm') === 'yes';
    if (approving) {
      const shown = req.session.deviceConfirm;
      delete req.session.deviceConfirm;
      if (typeof shown !== 'string' || !tokenEqual(shown, fingerprint(found.code))) throw http(403, 'login_denied');
    }
    if (rawProvider != null && rawProvider !== '') {
      if (typeof rawProvider !== 'string') throw http(403, 'link_denied');
      const started = await oauth.beginExternal(fleet.registry, typed, rawProvider, fleet.env || {}, sessionUser);
      req.session.deviceState = fingerprint(started.state);
      res.redirect(302, started.location);
      return;
    }
    if (approving) {
      await oauth.approveUserCode(fleet.registry, typed, sessionUser);
      res.type('html').send(oauth.donePage());
      return;
    }
    req.session.deviceConfirm = fingerprint(found.code);
    res.type('html').send(await oauth.confirmPage(fleet.registry, found.row, found.code, csrf, fleet.env || {}));
  }));

  app.post('/oauth/token', parseForm, wrap(async (req, res) => {
    noStore(res);
    if (bodyString(req.body, 'grant_type') !== oauth.DEVICE_GRANT) throw http(400, 'unsupported_grant_type');
    res.json(await oauth.pollToken(fleet.registry, bodyString(req.body, 'device_code'), fleet.env || {}));
  }));

  app.get('/oauth/:provider/callback', wrap(async (req, res) => {
    noStore(res);
    const provider = req.params.provider;
    if (provider !== 'google' && provider !== 'github') {
      res.status(404).type('html').send(oauth.denialPage());
      return;
    }
    if (req.query && req.query.error) {
      res.type('html').send(oauth.denialPage());
      return;
    }
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const bound = req.session && req.session.deviceState;
    if (req.session) delete req.session.deviceState;
    if (typeof bound !== 'string' || !state || !tokenEqual(bound, fingerprint(state))) {
      res.status(403).type('html').send(oauth.denialPage());
      return;
    }
    try {
      await oauth.exchangeExternal(fleet, { code, state, provider, sessionUser: sessionUserOf(req) });
    } catch (err) {
      if (err.status === 403) {
        res.type('html').send(oauth.denialPage());
        return;
      }
      throw err;
    }
    res.type('html').send(oauth.donePage());
  }));

  app.post('/api/v1/ws-ticket', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const purpose = req.body && req.body.purpose;
    const hostId = req.body && req.body.host_id;
    if (typeof purpose !== 'string' || !TICKET_PURPOSES.has(purpose)) throw http(400, 'bad_purpose');
    if (WATCH_PURPOSES.has(purpose)) {
      noStore(res);
      res.json(await watchTicket(fleet, principal, purpose, req.body || {}, res));
      return;
    }
    // Channel purposes: shape first (400), then scope in some tenant (403),
    // host (404), scope in the host's tenant (403), refused classes and
    // server policy (403), then the rate budget (429).
    const parsed = validateBinding(purpose, req.body);
    if (!parsed.ok) throw http(400, parsed.error);
    const scopes = PURPOSE_SCOPES[purpose] || [purpose];
    requireScopeAnywhere(fleet, principal, scopes);
    const host = await requireHost(fleet, principal, hostId);
    for (const scope of scopes) requireScope(fleet, principal, host.tenant_id, scope);
    if (CHANNEL_PURPOSES.has(purpose)) {
      if (parsed.forbidden) throw http(403, 'target_forbidden');
      const denied = await policyDecision(fleet.registry, host.host_id, purpose, parsed.binding);
      if (denied) throw http(denied === 'bad_target' || denied === 'bad_root' ? 400 : 403, denied);
    }
    res.json(await issueAuditedTicket(fleet, principal, host, purpose, parsed.binding));
  }));

  // sahxfer grant (sahxfer docs/design.md §3; playground/xfer.js). Same
  // order as a file ticket: shape (400), scope in some tenant (403), host
  // (404), scope in the host's tenant (403), the file policy root (403), then
  // the xfer rate budget (429; xfer:root spends the privileged budget).
  // Scopes and policy: xfer:put is checked as file:write, xfer:get as
  // file:read, xfer:root as file:root.
  app.post('/api/v1/xfer/grant', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    const parsed = xfer.parseGrantRequest(req.body, fleet.env || {});
    if (!parsed.ok) throw http(parsed.status, parsed.error);
    const request = parsed.request;
    const filePurpose = xfer.PURPOSES[request.purpose];
    const scopes = PURPOSE_SCOPES[filePurpose];
    requireScopeAnywhere(fleet, principal, scopes);
    const host = await requireHost(fleet, principal, request.host_id);
    for (const scope of scopes) requireScope(fleet, principal, host.tenant_id, scope);
    const denied = await policyDecision(fleet.registry, host.host_id, filePurpose, { root: request.root });
    if (denied) throw http(denied === 'bad_root' ? 400 : 403, denied);
    if (!fleet.xfer) throw http(501, 'agent_unsupported');
    if (!ticketAllowed(fleet, principal.userId, host.host_id, request.purpose)) throw http(429, 'rate_limited');
    // A client that hangs up before the response is written cancels the
    // grant, so no key stays live for a caller that never received it.
    const client = { gone: false, onGone: null };
    res.on('close', () => {
      if (res.writableFinished) return;
      client.gone = true;
      if (client.onGone) client.onGone();
    });
    res.json(await fleet.xfer.grant({ principal, host, request, client }));
  }));

  // Live terminal sessions a support or admin actor may ask to watch
  // (terminal:watch in the session's tenant). host_id narrows to one host.
  app.get('/api/v1/systems/terminal/sessions', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    requireScopeAnywhere(fleet, principal, ['terminal:watch']);
    const hostId = req.query && req.query.host_id;
    if (hostId !== undefined) {
      if (typeof hostId !== 'string' || !hostId) throw http(400, 'bad_host_id');
      const host = await requireHost(fleet, principal, hostId);
      requireScope(fleet, principal, host.tenant_id, 'terminal:watch');
    }
    const tenants = new Set(tenantIds(principal).filter((id) => hasScope(scopesFor(principal, id), 'terminal:watch')));
    const live = [...fleet.terminalSessions.values()].filter((s) => s.announced && !s.ended && tenants.has(s.tenantId) &&
      (hostId === undefined || s.hostId === hostId));
    const hosts = new Map();
    for (const s of live) {
      if (!hosts.has(s.hostId)) hosts.set(s.hostId, await fleet.registry.getHost([s.tenantId], s.hostId));
    }
    res.json({
      sessions: live.map((s) => ({
        session_id: s.id,
        host_id: s.hostId,
        hostname: hosts.get(s.hostId) ? hosts.get(s.hostId).hostname : null,
        tenant: s.tenantId,
        actor: s.actor,
        purpose: s.purpose,
        started_at: new Date(s.startedMs).toISOString(),
        watchers: s.watchers ? s.watchers.size : 0
      }))
    });
  }));

  app.get('/api/v1/hosts/resolve', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const name = req.query.name;
    if (typeof name !== 'string' || !RESOLVE_NAME_RE.test(name)) throw http(400, 'invalid_name');
    const ids = tenantIds(principal).filter((id) => hasScope(scopesFor(principal, id), 'hosts:read'));
    const matches = ids.length ? await fleet.registry.resolveHosts(ids, name) : [];
    if (matches.length === 0) throw http(404, 'not_found');
    const isOnline = (row) => (fleet.connectedAgents ? fleet.connectedAgents.has(row.host_id) : row.status === 'online');
    const host = pickResolved(matches, isOnline, resolveStaleMs(fleet.env));
    if (!host) {
      res.status(409).json({ error: 'ambiguous', matches: matches.length });
      return;
    }
    res.json({ host_id: host.host_id, hostname: host.hostname, tenant: host.tenant_id, status: isOnline(host) ? 'online' : 'offline' });
  }));

  // Retire a host record (a re-enrolled agent left the old row behind). The
  // row stays for audit with retired_at set. A connected host is refused
  // 409 host_online unless {"force": true}, which also closes its agent
  // socket (and with it every live channel session of that host).
  app.post('/api/v1/hosts/:hostId/retire', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    requireScopeAnywhere(fleet, principal, ['admin']);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'admin');
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
    if (!reason) throw http(400, 'reason_required');
    if (reason.length > RETIRE_REASON_MAX) throw http(400, 'bad_reason');
    if (body.force !== undefined && typeof body.force !== 'boolean') throw http(400, 'bad_force');
    if (host.retired_at) throw http(409, 'already_retired');
    const online = fleet.connectedAgents ? fleet.connectedAgents.has(host.host_id) : host.status === 'online';
    if (online && body.force !== true) {
      res.status(409).json({ error: 'host_online', host_id: host.host_id });
      return;
    }
    const row = await fleet.registry.retireHost({
      tenantId: host.tenant_id,
      hostId: host.host_id,
      actor: String(principal.userId),
      reason,
      forced: online
    });
    // Also closes an agent that connected after the check above.
    const agentClosed = typeof fleet.retireAgent === 'function' ? fleet.retireAgent(host.host_id) : false;
    res.json({
      host_id: row.host_id,
      hostname: row.hostname,
      tenant: row.tenant_id,
      retired_at: row.retired_at,
      forced: online,
      agent_closed: agentClosed
    });
  }));

  app.get('/api/v1/fleet/export', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'hosts:read');
    const hosts = await fleet.registry.listHosts(ids, req.query.q);
    if (req.query.format === 'csv') {
      res.type('text/csv').send(toCSV(hosts, ['host_id', 'tenant_id', 'hostname', 'status', 'os', 'last_seen_at']));
      return;
    }
    res.json({ hosts });
  }));

  app.get('/api/v1/fleet/efficiency', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'metrics:read');
    res.json(await fleet.registry.efficiency(ids));
  }));

  app.post('/api/v1/fleet/execute', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const hostIds = req.body && req.body.host_ids;
    if (!Array.isArray(hostIds) || hostIds.length === 0 || hostIds.length > 50) throw http(400, 'bad_hosts');
    const script = req.body.script;
    requireScopeAnywhere(fleet, principal, ['exec:run']);
    const results = [];
    for (const hostId of hostIds) {
      const host = await requireHost(fleet, principal, hostId);
      results.push({ host_id: hostId, ...(await runScript(fleet, principal, host, script, req.body.entitlements)) });
    }
    res.json({ results });
  }));

  app.get('/api/v1/fleet', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'hosts:read');
    const includeRetired = req.query.include_retired === '1' || req.query.include_retired === 'true';
    const hosts = await fleet.registry.listHosts(ids, typeof req.query.q === 'string' ? req.query.q : null, { includeRetired });
    res.json({ hosts, user: principal.kind === 'session' ? { id: principal.userId, email: principal.email } : null });
  }));

  app.get('/api/v1/fleet/:hostId/metrics', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'metrics:read');
    const metric = req.query.metric || 'cpu.usage_percent';
    const bucket = bucketName(req.query.bucket || 'minute');
    if (!bucket) throw http(400, 'bad_bucket');
    const from = req.query.from ? Date.parse(req.query.from) : null;
    const to = req.query.to ? Date.parse(req.query.to) : null;
    const points = await fleet.registry.metricAggregate(host.host_id, metric, bucket, from, to);
    res.json({ host_id: host.host_id, metric, bucket, points });
  }));

  app.get('/api/v1/fleet/:hostId/forecast', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'metrics:read');
    const metric = req.query.metric || 'cpu.usage_percent';
    const series = await fleet.registry.metricSeries(host.host_id, metric, 60);
    res.json({
      host_id: host.host_id,
      metric,
      forecast: linearForecast(series.map((p) => p.value), 1),
      samples: series.length
    });
  }));

  app.get('/api/v1/fleet/:hostId/anomalies', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'metrics:read');
    const metric = req.query.metric || 'cpu.usage_percent';
    const series = await fleet.registry.metricSeries(host.host_id, metric, 60);
    res.json({ host_id: host.host_id, metric, ...zscore(series.map((p) => p.value)) });
  }));

  app.get('/api/v1/fleet/:hostId/software', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'hosts:read');
    res.json({ software: await fleet.registry.listSoftware(host.host_id) });
  }));

  app.get('/api/v1/fleet/:hostId/cves', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'hosts:read');
    res.json({ cves: await fleet.registry.listCVEs(host.host_id) });
  }));

  app.post('/api/v1/fleet/:hostId/execute', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    requireScopeAnywhere(fleet, principal, ['exec:run']);
    const host = await requireHost(fleet, principal, req.params.hostId);
    const out = await runScript(fleet, principal, host, req.body && req.body.script, req.body && req.body.entitlements);
    res.json({ success: true, ...out, executed_by: principal.email || principal.userId });
  }));

  // Async sysscript jobs (.omc/plans/async-sysscript-jobs.md §8). 202 with
  // the job id; wait_s (0..25) waits for the end and answers 200 {job} if
  // it ends in time.
  app.post('/api/v1/fleet/:hostId/jobs', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    requireJobs(fleet);
    requireScopeAnywhere(fleet, principal, ['exec:run']);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'exec:run');
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const script = body.script;
    // U+0000 cannot be stored in the dispatch JSONB.
    if (typeof script !== 'string' || script.length === 0 || !script.isWellFormed() || script.includes('\u0000')
      || Buffer.byteLength(script, 'utf8') > SCRIPT_MAX) {
      throw http(400, 'bad_script');
    }
    const requested = body.entitlements;
    if (requested !== undefined && requested !== null && (typeof requested !== 'object' || Array.isArray(requested))) {
      throw http(400, 'bad_entitlements');
    }
    const maxS = jobMaxSeconds(fleet.env);
    const timeoutS = intField(body, 'timeout_s', Math.min(JOB_TIMEOUT_DEFAULT_S, maxS), 1, maxS, 'bad_timeout');
    const waitS = intField(body, 'wait_s', 0, 0, JOB_WAIT_MAX_S, 'bad_wait');
    const entitlements = clampEntitlements(requested, scopesFor(principal, host.tenant_id));
    try {
      entitlementsSha256(entitlements);
    } catch {
      throw http(400, 'bad_entitlements');
    }
    await fleet.jobs.requireAgent(host.host_id);
    const { job, deadlineUnix } = await fleet.jobs.submit({
      host,
      actor: principal.userId,
      source: 'api',
      script,
      entitlements,
      timeoutS
    });
    let latest = job;
    if (waitS > 0) {
      latest = (await fleet.jobs.waitFor([host.tenant_id], job.job_id, waitS * 1000)) || job;
      if (TERMINAL_JOB_STATUSES.has(latest.status)) {
        res.status(200).json({ job: jobView(latest, { visible: true }) });
        return;
      }
    }
    res.status(202).json({ job_id: job.job_id, status: latest.status, deadline_unix: deadlineUnix });
  }));

  app.get('/api/v1/jobs/:jobId', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    requireJobs(fleet);
    const job = await requireJob(fleet, principal, req.params.jobId);
    res.json({ job: jobView(job, { visible: jobOwnerOrAdmin(principal, job) }) });
  }));

  // Jobs of the tenants where the principal holds exec:run, never output.
  app.get('/api/v1/jobs', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    requireJobs(fleet);
    requireScopeAnywhere(fleet, principal, ['exec:run']);
    const ids = tenantIds(principal).filter((id) => hasScope(scopesFor(principal, id), 'exec:run'));
    const q = req.query || {};
    for (const name of ['host_id', 'status', 'limit']) {
      if (q[name] !== undefined && typeof q[name] !== 'string') throw http(400, `bad_${name}`);
    }
    let limit;
    if (q.limit !== undefined) {
      if (!/^[0-9]{1,3}$/.test(q.limit)) throw http(400, 'bad_limit');
      limit = Number(q.limit);
    }
    const jobs = await fleet.registry.listJobs(ids, { hostId: q.host_id || null, status: q.status || null, limit });
    res.json({ jobs: jobs.map((job) => jobView(job, { output: false })) });
  }));

  // Submitter or tenant admin. 202 {job}, or 409 job_finished.
  app.post('/api/v1/jobs/:jobId/cancel', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    requireJobs(fleet);
    const job = await requireJob(fleet, principal, req.params.jobId);
    if (!jobOwnerOrAdmin(principal, job)) {
      await safeSecurity(fleet, {
        kind: 'scope_deny',
        tenant_id: job.tenant_id,
        actor_fingerprint: principal.keyId ? fingerprint(principal.keyId) : fingerprint(principal.userId),
        detail: { scope: 'job:cancel' }
      });
      throw http(403, 'scope_denied');
    }
    const row = await fleet.registry.requestJobCancel([job.tenant_id], job.job_id, String(principal.userId), 'user');
    if (!row) throw http(404, 'not_found');
    fleet.jobs.cancelRequested(row);
    res.status(202).json({ job: jobView(row, { visible: true }) });
  }));

  app.post('/api/v1/fleet/:hostId/breakglass', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    requireScopeAnywhere(fleet, principal, ['breakglass:open']);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'breakglass:open');
    res.json(await issueAuditedTicket(fleet, principal, host, 'breakglass:open'));
  }));

  app.get('/api/v1/fleet/:hostId/comments', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'hosts:read');
    res.json({ comments: await fleet.registry.listComments(host.tenant_id, host.host_id) });
  }));

  app.post('/api/v1/fleet/:hostId/comments', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'hosts:write');
    const row = await fleet.registry.addComment({
      tenant_id: host.tenant_id,
      host_id: host.host_id,
      author: principal.email || principal.userId,
      body: req.body && req.body.body
    });
    res.status(201).json(row);
  }));

  app.get('/api/v1/alerts', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'hosts:read');
    const status = ['open', 'ack', 'resolved'].includes(req.query.status) ? req.query.status : null;
    res.json({ alerts: await fleet.registry.listAlerts(ids, status) });
  }));

  app.post('/api/v1/alerts/:id/ack', wrap(async (req, res) => {
    await setAlert(req, res, fleet, 'ack');
  }));

  app.post('/api/v1/alerts/:id/resolve', wrap(async (req, res) => {
    await setAlert(req, res, fleet, 'resolved');
  }));

  app.get('/api/v1/audit', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'audit:read');
    res.json({ events: await fleet.registry.listAudit(ids) });
  }));

  app.get('/api/v1/audit/verify', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    // A caller in no tenant has no audit:read anywhere.
    if (tenantIds(principal).length === 0) throw http(403, 'scope_denied');
    for (const id of tenantIds(principal)) requireScope(fleet, principal, id, 'audit:read');
    res.json(await fleet.registry.verifyAudit());
  }));

  app.get('/api/v1/audit/export', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'audit:read');
    const events = await fleet.registry.listAudit(ids, 1000);
    if (req.query.format === 'csv') {
      res.type('text/csv').send(toCSV(events, ['seq', 'tenant_id', 'host_id', 'actor', 'action', 'created_at']));
      return;
    }
    res.json({ events });
  }));

  app.get('/api/v1/security-events', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'audit:read');
    res.json({ events: await fleet.registry.listSecurity(ids) });
  }));

  app.get('/api/v1/compliance/export', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const ids = tenantIds(principal);
    for (const id of ids) requireScope(fleet, principal, id, 'audit:read');
    const body = {
      generated_at: new Date().toISOString(),
      hosts: await fleet.registry.listHosts(ids),
      open_alerts: await fleet.registry.listAlerts(ids, 'open'),
      audit: await fleet.registry.verifyAudit()
    };
    if (req.query.format === 'csv') {
      res.type('text/csv').send(toCSV(body.hosts, ['host_id', 'tenant_id', 'hostname', 'status']));
      return;
    }
    res.json(body);
  }));

  app.post('/api/v1/webhooks', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const tenantId = req.body && req.body.tenant_id;
    if (!tenantIds(principal).includes(tenantId)) throw http(404, 'not_found');
    requireScope(fleet, principal, tenantId, 'admin');
    const url = assertWebhookURL(req.body.url, fleet.env || process.env);
    const secret = randomToken(32);
    const row = {
      id: `wh_${randomToken(16)}`,
      tenant_id: tenantId,
      url: url.toString(),
      secret: sealSecret(secret, fleet.env || {}),
      secret_fingerprint: fingerprint(secret),
      created_at: new Date().toISOString()
    };
    const pub = await fleet.registry.createWebhook(row);
    res.status(201).json({ ...pub, secret });
  }));

  app.get('/api/v1/webhooks', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const tenantId = req.query.tenant_id;
    if (!tenantIds(principal).includes(tenantId)) throw http(404, 'not_found');
    requireScope(fleet, principal, tenantId, 'admin');
    res.json({ webhooks: await fleet.registry.listWebhooks(tenantId) });
  }));

  app.delete('/api/v1/webhooks/:id', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const tenantId = req.query.tenant_id;
    if (!tenantIds(principal).includes(tenantId)) throw http(404, 'not_found');
    requireScope(fleet, principal, tenantId, 'admin');
    const ok = await fleet.registry.deleteWebhook(tenantId, req.params.id);
    if (!ok) throw http(404, 'not_found');
    res.json({ deleted: true });
  }));

  app.post('/api/v1/schedules', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.body && req.body.host_id);
    requireScope(fleet, principal, host.tenant_id, 'exec:run');
    const cron = req.body.cron;
    if (!cronValid(cron)) throw http(400, 'bad_cron');
    const script = req.body.script;
    if (typeof script !== 'string' || script.length === 0 || script.length > SCRIPT_MAX) throw http(400, 'bad_script');
    const row = {
      id: `sch_${randomToken(16)}`,
      tenant_id: host.tenant_id,
      host_id: host.host_id,
      cron,
      script,
      created_at: new Date().toISOString()
    };
    res.status(201).json(await fleet.registry.createSchedule(row));
  }));

  app.get('/api/v1/schedules', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const tenantId = req.query.tenant_id;
    if (!tenantIds(principal).includes(tenantId)) throw http(404, 'not_found');
    requireScope(fleet, principal, tenantId, 'hosts:read');
    res.json({ schedules: await fleet.registry.listSchedules(tenantId) });
  }));

  app.delete('/api/v1/schedules/:id', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const tenantId = req.query.tenant_id;
    if (!tenantIds(principal).includes(tenantId)) throw http(404, 'not_found');
    requireScope(fleet, principal, tenantId, 'exec:run');
    const ok = await fleet.registry.deleteSchedule(tenantId, req.params.id);
    if (!ok) throw http(404, 'not_found');
    res.json({ deleted: true });
  }));

  app.get('/api/v1/playbooks', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    if (tenantIds(principal).length === 0) {
      res.json({ playbooks: [] });
      return;
    }
    res.json({ playbooks: listPlaybooks() });
  }));

  app.post('/api/v1/playbooks/:id/run', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    requireScopeAnywhere(fleet, principal, ['exec:run']);
    const host = await requireHost(fleet, principal, req.body && req.body.host_id);
    const script = readPlaybook(req.params.id);
    const out = await runScript(fleet, principal, host, script, { allow_exec: true });
    res.json({ playbook: req.params.id, ...out });
  }));

  app.post('/api/v1/tenants/:tenant/members', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const tenantId = req.params.tenant;
    if (!tenantIds(principal).includes(tenantId)) throw http(404, 'not_found');
    requireScope(fleet, principal, tenantId, 'admin');
    const role = req.body && req.body.role;
    const userId = req.body && req.body.user_id;
    // USER_RE has no colon, so a member id can never be a JWT principal
    // ("oidc:<sub>", playground/auth.js).
    if (typeof userId !== 'string' || !USER_RE.test(userId)) throw http(400, 'bad_user');
    const row = await fleet.registry.addMember(tenantId, userId, role, req.body.email);
    res.status(201).json(row);
  }));

  // Admin of the tenant only. Binds one membership row; every bind and unbind
  // is an audit-chain row in that tenant (oauth.setSsoSubAudited).
  const ssoBind = (unbind) => wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const tenantId = req.params.tenant;
    if (!tenantIds(principal).includes(tenantId)) throw http(404, 'not_found');
    requireScope(fleet, principal, tenantId, 'admin');
    const sub = unbind ? null : req.body && req.body.sso_sub;
    if (!unbind && typeof sub !== 'string') throw http(400, 'bad_sso_sub');
    res.json(await oauth.setSsoSubAudited(fleet.registry, {
      tenantId,
      userId: req.params.user,
      sub,
      actor: String(principal.userId)
    }));
  });
  app.put('/api/v1/tenants/:tenant/members/:user/sso', ssoBind(false));
  app.delete('/api/v1/tenants/:tenant/members/:user/sso', ssoBind(true));

  app.post('/api/v1/keys/:keyId/scopes', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const adminTenant = principal.memberships.find((m) => hasScope(scopesFor(principal, m.tenant_id), 'admin'));
    if (!adminTenant) throw http(403, 'scope_denied');
    const owner = await lookupKeyOwner(fleet, req.params.keyId);
    if (!owner) throw http(404, 'not_found');
    const ownerMemberships = await fleet.registry.membershipsForUser(owner.user_id);
    const shared = ownerMemberships.some((m) => tenantIds(principal).includes(m.tenant_id));
    if (!shared && owner.user_id !== principal.userId) throw http(404, 'not_found');
    const requested = Array.isArray(req.body && req.body.scopes) ? req.body.scopes : null;
    if (!requested || requested.some((s) => !ALL.includes(s))) throw http(400, 'bad_scope');
    await fleet.registry.setScopes(req.params.keyId, requested);
    res.json({ key_id: req.params.keyId, scopes: requested });
  }));

  app.post('/api/v1/oauth/links', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    if (adminTenantIds(principal).length === 0) throw http(403, 'scope_denied');
    const provider = bodyString(req.body, 'provider');
    if (provider !== 'google' && provider !== 'github') throw http(400, 'bad_provider');
    const userId = bodyString(req.body, 'user_id');
    await requireLinkUser(fleet, principal, userId);
    res.json(await oauth.createLink(fleet.registry, userId, provider));
  }));

  app.get('/api/v1/oauth/links', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const admins = adminTenantIds(principal);
    if (admins.length === 0) throw http(403, 'scope_denied');
    const ids = await oauth.memberIds(fleet.registry, admins);
    const links = await oauth.listLinks(fleet.registry, ids);
    res.json({
      links: links.map((row) => ({ user_id: row.user_id, provider: row.provider, linked: row.linked === true }))
    });
  }));

  app.delete('/api/v1/oauth/links', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    if (adminTenantIds(principal).length === 0) throw http(403, 'scope_denied');
    const provider = bodyString(req.body, 'provider');
    if (provider !== 'google' && provider !== 'github') throw http(400, 'bad_provider');
    const userId = bodyString(req.body, 'user_id');
    await requireLinkUser(fleet, principal, userId);
    const removed = await oauth.removeLink(fleet.registry, userId, provider);
    if (!removed) throw http(404, 'not_found');
    res.json({ deleted: true });
  }));
}

async function setAlert(req, res, fleet, status) {
  const principal = await authenticate(req, fleet);
  const ids = tenantIds(principal);
  for (const id of ids) requireScope(fleet, principal, id, 'alerts:write');
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) throw http(400, 'bad_alert');
  const row = await fleet.registry.setAlertStatus(ids, id, status);
  if (!row) throw http(404, 'not_found');
  res.json(row);
}

async function lookupKeyOwner(fleet, keyId) {
  if (!fleet.db || typeof fleet.db.query !== 'function') return null;
  try {
    const res = await fleet.db.query(
      'SELECT user_id FROM playground_api_keys WHERE key_id = $1 AND api_site = $2',
      [keyId, fleet.apiSite || 'systemapi']
    );
    return res.rows[0] || null;
  } catch {
    return null;
  }
}

module.exports = {
  mount,
  authenticate,
  deliverWebhooks,
  clampEntitlements,
  COOLDOWN_MS
};
