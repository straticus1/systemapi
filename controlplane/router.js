// Threats: missing auth, query-string API keys, cross-tenant object access,
// and a viewer running exec. Each handler authenticates. Unknown hosts in
// another tenant are 404. Does NOT expire API keys; that stays in the key store.
// OAuth access tokens are session principals. Device and IdP secrets stay in
// controlplane/oauth.js and are not written to the audit log.
'use strict';

const express = require('express');
const axios = require('axios');
const { hasScope, roleFromGroups, scopesForRole, ALL } = require('./authz');
const oauth = require('./oauth');
const { issueLease } = require('./lease');
const { issueTicket } = require('./tickets');
const { fingerprint, randomToken } = require('./token');
const { sealSecret, openSecret } = require('./seal');
const { assertWebhookURL } = require('./webhook');
const { bucketName, linearForecast, toCSV, cronValid, zscore } = require('./stats');
const { listPlaybooks, readPlaybook } = require('./playbooks');

const SCRIPT_MAX = 64 * 1024;
const COOLDOWN_MS = 5 * 60 * 1000;
const USER_RE = /^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,128}$/;
const formBody = express.urlencoded({ extended: false, limit: '8kb' });
const ENTITLEMENTS = [
  'allow_fs_write',
  'allow_fs_read',
  'allow_net_outbound',
  'allow_exec',
  'allow_config_write',
  'allow_service_reload',
  'allow_containers',
  'allow_k3s'
];

function http(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function sendError(res, err) {
  const status = err.status && err.status >= 400 && err.status < 600 ? err.status : 500;
  if (status >= 500) console.error('[control]', err.message);
  res.status(status).json({ error: err.code || err.message || 'error' });
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

function intersectScopes(keyScopes, role) {
  const roleScopes = scopesForRole(role);
  if (keyScopes.has('admin') && roleScopes.has('admin')) return new Set(ALL);
  const left = keyScopes.has('admin') ? new Set(ALL) : keyScopes;
  const right = roleScopes.has('admin') ? new Set(ALL) : roleScopes;
  const out = new Set();
  for (const scope of left) if (right.has(scope)) out.add(scope);
  return out;
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
    const memberships = await fleet.registry.membershipsForUser(sessionUser.id, sessionUser.email);
    const boosted = roleFromGroups(sessionUser.groups);
    return {
      kind: 'session',
      userId: sessionUser.id,
      email: sessionUser.email,
      keyScopes: null,
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

function clampEntitlements(requested, scopes) {
  const out = {};
  for (const key of ENTITLEMENTS) out[key] = false;
  if (!requested || typeof requested !== 'object') return out;
  const admin = hasScope(scopes, 'admin');
  for (const key of ENTITLEMENTS) {
    if (!requested[key]) continue;
    if (key === 'allow_exec' && hasScope(scopes, 'exec:run')) out[key] = true;
    else if (admin) out[key] = true;
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
    const out = await oauth.startDevice(fleet.registry, bodyString(req.body, 'username'), fleet.env || {});
    res.json(out);
  }));

  app.get('/oauth/device/verify', wrap(async (req, res) => {
    noStore(res);
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    res.type('html').send(await oauth.verifyPage(fleet.registry, code, fleet.env || {}));
  }));

  app.post('/oauth/device/verify', parseForm, wrap(async (req, res) => {
    noStore(res);
    const code = bodyString(req.body, 'code');
    const rawProvider = req.body && req.body.provider;
    if (rawProvider == null || rawProvider === '') {
      await oauth.approveUserCode(fleet.registry, code);
      res.type('html').send(oauth.donePage());
      return;
    }
    if (typeof rawProvider !== 'string') throw http(403, 'link_denied');
    const location = await oauth.beginExternal(fleet.registry, code, rawProvider, fleet.env || {});
    res.redirect(302, location);
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
    try {
      await oauth.exchangeExternal(fleet, { code, state, provider });
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
    if (purpose !== 'terminal:open' && purpose !== 'breakglass:open') throw http(400, 'bad_purpose');
    const host = await requireHost(fleet, principal, hostId);
    requireScope(fleet, principal, host.tenant_id, purpose);
    if (!fleet.tickets) throw http(503, 'tickets_unavailable');
    const ticket = issueTicket(fleet.tickets, { hostId: host.host_id, purpose, tenantId: host.tenant_id });
    res.json({ ticket, expires_in: 60, host_id: host.host_id, purpose });
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
    const hosts = await fleet.registry.listHosts(ids, typeof req.query.q === 'string' ? req.query.q : null);
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
    const host = await requireHost(fleet, principal, req.params.hostId);
    const out = await runScript(fleet, principal, host, req.body && req.body.script, req.body && req.body.entitlements);
    res.json({ success: true, ...out, executed_by: principal.email || principal.userId });
  }));

  app.post('/api/v1/fleet/:hostId/breakglass', wrap(async (req, res) => {
    const principal = await authenticate(req, fleet);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'breakglass:open');
    if (!fleet.tickets) throw http(503, 'tickets_unavailable');
    const ticket = issueTicket(fleet.tickets, {
      hostId: host.host_id,
      purpose: 'breakglass:open',
      tenantId: host.tenant_id
    });
    res.json({ ticket, expires_in: 60, host_id: host.host_id, purpose: 'breakglass:open' });
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
    if (typeof userId !== 'string' || userId.length === 0 || userId.length > 200) throw http(400, 'bad_user');
    const row = await fleet.registry.addMember(tenantId, userId, role, req.body.email);
    res.status(201).json(row);
  }));

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
  runScript,
  deliverWebhooks,
  scopesFor,
  clampEntitlements,
  COOLDOWN_MS
};
