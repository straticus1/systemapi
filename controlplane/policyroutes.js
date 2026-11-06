'use strict';

// Channel-policy HTTP API (plan sah-fleet-readiness P2b-P2d): read, replace,
// clear, inherit and revert a host's channel policy, and a tenant's default,
// without ssh to the control plane. scripts/channel-policy.js stays as the
// break-glass path on the host; both build policies through
// controlplane/policyrules.js.
//
// Threats: a policy written to another tenant's host or tenant (admin only,
// tenant-filtered lookup, 404 plus an idor security event, as the retire and
// capabilities routes), a lost update between two admins (if_version on
// every write, checked again under the row lock: 409 version_conflict), a
// write with no trail (one transaction with its audit row: policy_schema 2,
// all six previous and new kinds, the reason, the actor and its key
// fingerprint), a root-equivalent grant from a stolen API key or a
// one-click confirm (dangerous writes must echo the server's list in
// confirm_dangerous and come from a session whose auth_time is at most 5 min
// old; API keys are refused), cross-site writes riding a browser cookie
// (JSON bodies only; a cookie session also needs an Origin in
// SYSTEMAPI_ALLOWED_ORIGINS), a revert that reaches another host's or
// tenant's row or reads "not recorded" as "inherit" (host, tenant and action
// must match, only policy_schema 2 rows), live sessions outliving a
// narrowing (every write renews this replica's sessions on the affected
// hosts at once), and write floods (SYSTEMAPI_POLICY_WRITE_RATE per minute,
// default 60). Webhooks and logs carry classes and counts, never paths,
// units or raw errors. Does NOT fan out to other replicas (one today), does
// NOT require a second approver (a follow-up once there is a second admin),
// and does NOT stop a compromised admin session inside its 5 min step-up
// window.

const { fingerprint } = require('./token');
const { allowedOrigins } = require('./httpauth');
const oauth = require('./oauth');
const rules = require('./policyrules');

const TENANT_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const WRITE_RATE_DEFAULT = 60;
const WRITE_RATE_CAP = 600;
const WRITE_WINDOW_MS = 60 * 1000;

// SYSTEMAPI_POLICY_WRITE_RATE: policy write requests (dry runs included) per
// minute on this replica. Default 60; anything but an integer 1-600 falls
// back to it.
function writeRate(env) {
  const raw = env && env.SYSTEMAPI_POLICY_WRITE_RATE;
  const n = raw === undefined || raw === '' ? NaN : Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= WRITE_RATE_CAP ? n : WRITE_RATE_DEFAULT;
}

function mountPolicyRoutes(app, fleet, h) {
  const { wrap, http, noStore, authenticate, requireScopeAnywhere, requireHost, requireScope, safeSecurity, tenantIds, deliverWebhooks } = h;

  function rateGate() {
    const now = Date.now();
    if (!fleet.policyWriteTimes) fleet.policyWriteTimes = [];
    const times = fleet.policyWriteTimes;
    while (times.length && now - times[0] >= WRITE_WINDOW_MS) times.shift();
    if (times.length >= writeRate(fleet.env)) throw http(429, 'rate_limited');
    times.push(now);
  }

  // Writes take a JSON object only (a form post is refused for every
  // principal); a browser cookie session also needs an allowed Origin.
  function writeBody(req, principal) {
    if (!req.is('application/json')) throw http(415, 'json_required');
    if (principal.cookie === true) {
      const origin = req.get('origin');
      if (typeof origin !== 'string' || !allowedOrigins(fleet.env || {}).has(origin)) throw http(403, 'origin_denied');
    }
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw http(400, 'bad_body');
    return body;
  }

  function dryRunOf(req) {
    const raw = req.query && req.query.dry_run;
    if (raw === undefined) return false;
    if (raw === '1' || raw === 'true') return true;
    if (raw === '0' || raw === 'false') return false;
    throw http(400, 'bad_dry_run');
  }

  function reasonOf(body) {
    const reason = rules.normalizeReason(body.reason);
    if (reason === null) throw http(400, 'bad_reason');
    return reason;
  }

  function ifVersionOf(body) {
    if (typeof body.if_version !== 'string' || !rules.VERSION_RE.test(body.if_version)) throw http(400, 'if_version_required');
    return body.if_version;
  }

  // A rule refusal is 400 bad_policy with the rule's fixed code.
  function ruled(fn) {
    try {
      return fn();
    } catch (err) {
      if (typeof err.rule !== 'string') throw err;
      const out = http(400, 'bad_policy');
      out.reason = err.rule;
      throw out;
    }
  }

  function actorFields(principal) {
    return {
      via: principal.kind === 'key' ? 'key' : principal.cookie === true ? 'session' : 'token',
      key_fp: principal.keyId ? fingerprint(principal.keyId) : null
    };
  }

  function refuse(res, status, body) {
    res.status(status).json(body);
  }

  // P2c. Returns false once it has answered.
  async function dangerousGate(req, res, principal, body, dangerous, tenantId) {
    if (dangerous.length === 0) return true;
    let reason = null;
    if (principal.kind !== 'session') reason = 'api_key';
    else if (!oauth.authTimeFresh(principal.authTime)) reason = 'stale_auth';
    if (reason) {
      await safeSecurity(fleet, {
        kind: 'step_up_deny',
        tenant_id: tenantId,
        actor_fingerprint: principal.keyId ? fingerprint(principal.keyId) : fingerprint(principal.userId),
        detail: { reason, count: dangerous.length }
      });
      refuse(res, 403, { error: 'step_up_required', reason });
      return false;
    }
    const echo = body.confirm_dangerous;
    const same = Array.isArray(echo) && echo.length === dangerous.length && echo.every((e) => typeof e === 'string')
      && [...echo].sort().every((e, i) => e === dangerous[i]);
    if (!same) {
      refuse(res, 409, { error: 'dangerous_unconfirmed', dangerous });
      return false;
    }
    return true;
  }

  // Classes only (config, package, ...): no path or unit leaves in a webhook.
  function notifyDangerous(tenantId, hostId, dangerous, auditSeq, action) {
    if (dangerous.length === 0 || typeof deliverWebhooks !== 'function') return;
    const classes = [...new Set(dangerous.map((d) => d.split(':')[0]))].sort();
    deliverWebhooks(fleet, tenantId, { type: 'channel_policy_dangerous', tenant: tenantId, host_id: hostId, action, audit_seq: auditSeq, classes, count: dangerous.length })
      .catch((err) => console.error('[control] policy webhook failed:', err.code || 'webhook_failed'));
  }

  function liveCount(match) {
    return typeof fleet.policySessions === 'function' ? fleet.policySessions(match).length : 0;
  }

  // Resolves to {renewed, ended} once every matching session was re-checked.
  async function renew(match) {
    if (typeof fleet.renewPolicySessions !== 'function') return { renewed: 0, ended: 0 };
    return fleet.renewPolicySessions(match);
  }

  async function hostPolicyState(host) {
    if (host.retired_at) throw http(409, 'host_retired');
    const raw = await fleet.registry.channelPolicies(host.host_id);
    if (!raw) throw http(409, 'host_retired');
    return { hostCols: rules.pickColumns(raw, 'host_'), tenantCols: rules.pickColumns(raw, 'tenant_') };
  }

  async function loadHost(req, principal) {
    requireScopeAnywhere(fleet, principal, ['admin']);
    const host = await requireHost(fleet, principal, req.params.hostId);
    requireScope(fleet, principal, host.tenant_id, 'admin');
    if (host.retired_at) throw http(409, 'host_retired');
    return host;
  }

  async function loadTenant(req, principal) {
    requireScopeAnywhere(fleet, principal, ['admin']);
    const tenantId = req.params.tenant;
    if (typeof tenantId !== 'string' || !TENANT_RE.test(tenantId) || !tenantIds(principal).includes(tenantId)) {
      await safeSecurity(fleet, {
        kind: 'idor',
        tenant_id: null,
        actor_fingerprint: principal.keyId ? fingerprint(principal.keyId) : fingerprint(principal.userId),
        detail: { tenant: typeof tenantId === 'string' ? tenantId.slice(0, 64) : null }
      });
      throw http(404, 'not_found');
    }
    requireScope(fleet, principal, tenantId, 'admin');
    const cols = await fleet.registry.tenantChannelPolicies(tenantId);
    if (!cols) throw http(404, 'not_found');
    return { tenantId, cols };
  }

  // The shared write path of a host: dry run, dangerous gate, the audited
  // write, the webhook and the renewal.
  async function hostWrite(req, res, principal, host, body, next, action, { dryRun, revertOf = null }) {
    const reason = reasonOf(body);
    const ifVersion = ifVersionOf(body);
    const { hostCols, tenantCols } = await hostPolicyState(host);
    const version = rules.policyVersion(hostCols);
    if (version !== ifVersion) {
      refuse(res, 409, { error: 'version_conflict', version });
      return;
    }
    const dangerous = rules.hostDangerousEntries(hostCols, next, tenantCols);
    const match = (hostId) => hostId === host.host_id;
    if (dryRun) {
      res.json({
        dry_run: true,
        host_id: host.host_id,
        tenant: host.tenant_id,
        action,
        version,
        next_version: rules.policyVersion(next),
        diff: rules.diffColumns(hostCols, next),
        dangerous,
        live_sessions: liveCount(match),
        ...(revertOf === null ? {} : { revert_of: revertOf })
      });
      return;
    }
    if (!(await dangerousGate(req, res, principal, body, dangerous, host.tenant_id))) return;
    let out;
    try {
      out = await fleet.registry.setHostChannelPolicyAudited({
        tenantId: host.tenant_id,
        hostId: host.host_id,
        tcpPolicy: next.tcp_policy,
        filePolicy: next.file_policy,
        servicePolicy: next.service_policy,
        packagePolicy: next.package_policy,
        configPolicy: next.config_policy,
        tweakPolicy: next.tweak_policy,
        actor: String(principal.userId),
        action,
        reason,
        ifVersion,
        // The dangerous list was computed against these tenant columns; the
        // registry checks them again under the lock.
        tenantVersion: rules.policyVersion(tenantCols),
        extra: { policy_schema: rules.POLICY_SCHEMA, ...actorFields(principal), dangerous, ...(revertOf === null ? {} : { revert_of: revertOf }) }
      });
    } catch (err) {
      if (err.code === 'version_conflict') {
        refuse(res, 409, { error: 'version_conflict' });
        return;
      }
      throw err;
    }
    notifyDangerous(host.tenant_id, host.host_id, dangerous, out.audit_seq, action);
    const counts = await renew(match);
    res.json({
      host_id: host.host_id,
      tenant: host.tenant_id,
      action,
      version: out.version,
      audit_seq: out.audit_seq,
      dangerous,
      renewed: counts.renewed,
      ended: counts.ended,
      ...(revertOf === null ? {} : { revert_of: revertOf })
    });
  }

  app.get('/api/v1/hosts/:hostId/channel-policy', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    const host = await loadHost(req, principal);
    const { hostCols, tenantCols } = await hostPolicyState(host);
    res.json({
      host_id: host.host_id,
      hostname: host.hostname,
      tenant_id: host.tenant_id,
      host: hostCols,
      tenant: tenantCols,
      effective: rules.effectiveColumns(hostCols, tenantCols),
      grants: rules.grantsOf(hostCols),
      version: rules.policyVersion(hostCols),
      dangerous: rules.dangerousEntries(null, rules.effectiveOf(hostCols, tenantCols))
    });
  }));

  // Full replace from grant lists (the CLI's set flags as keys).
  app.put('/api/v1/hosts/:hostId/channel-policy', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    const host = await loadHost(req, principal);
    const body = writeBody(req, principal);
    const dryRun = dryRunOf(req);
    rateGate();
    reasonOf(body);
    ifVersionOf(body);
    const next = ruled(() => rules.buildPolicy(body.grants, rules.apiLabel));
    await hostWrite(req, res, principal, host, body, next, 'channel_policy_set', { dryRun });
  }));

  for (const [verb, policy] of [['clear', rules.clearPolicy], ['inherit', rules.inheritPolicy]]) {
    app.post(`/api/v1/hosts/:hostId/channel-policy/${verb}`, wrap(async (req, res) => {
      noStore(res);
      const principal = await authenticate(req, fleet);
      const host = await loadHost(req, principal);
      const body = writeBody(req, principal);
      const dryRun = dryRunOf(req);
      rateGate();
      await hostWrite(req, res, principal, host, body, policy(), `channel_policy_${verb}`, { dryRun });
    }));
  }

  // Restores the six columns as they were before audit row audit_seq. Only
  // that host's own policy_schema 2 rows qualify; a dry run unless apply.
  app.post('/api/v1/hosts/:hostId/channel-policy/revert', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    const host = await loadHost(req, principal);
    const body = writeBody(req, principal);
    if (body.apply !== undefined && typeof body.apply !== 'boolean') throw http(400, 'bad_apply');
    if (!Number.isSafeInteger(body.audit_seq) || body.audit_seq < 1) throw http(400, 'bad_audit_seq');
    rateGate();
    reasonOf(body);
    ifVersionOf(body);
    const row = await fleet.registry.policyAuditRow(body.audit_seq);
    const own = row && typeof row.action === 'string' && row.action.startsWith('channel_policy_')
      && row.host_id === host.host_id && row.tenant_id === host.tenant_id;
    if (!own) {
      await safeSecurity(fleet, {
        kind: 'idor',
        tenant_id: null,
        actor_fingerprint: principal.keyId ? fingerprint(principal.keyId) : fingerprint(principal.userId),
        detail: { host_id: host.host_id, audit_seq: body.audit_seq }
      });
      throw http(404, 'not_found');
    }
    const payload = row.payload || {};
    const recorded = rules.COLUMNS.every((col) => Object.prototype.hasOwnProperty.call(payload, `previous_${col}`));
    if (payload.policy_schema !== rules.POLICY_SCHEMA || !recorded) throw http(409, 'revert_unsupported');
    const previous = {};
    for (const col of rules.COLUMNS) previous[col] = payload[`previous_${col}`];
    let next;
    try {
      next = rules.normalizeColumns(previous);
    } catch (err) {
      if (typeof err.rule !== 'string') throw err;
      const out = http(409, 'revert_unsupported');
      out.reason = err.rule;
      throw out;
    }
    await hostWrite(req, res, principal, host, body, next, 'channel_policy_revert', { dryRun: body.apply !== true, revertOf: body.audit_seq });
  }));

  // Tenant defaults. Every tenant write is dangerous (it widens every
  // inheriting host): tenant_write is always on its list.
  async function tenantWrite(req, res, principal, tenantId, cur, body, next, action, dryRun) {
    const reason = reasonOf(body);
    const ifVersion = ifVersionOf(body);
    const version = rules.policyVersion(cur);
    if (version !== ifVersion) {
      refuse(res, 409, { error: 'version_conflict', version });
      return;
    }
    const dangerous = [rules.TENANT_WRITE, ...rules.dangerousEntries(rules.effectiveOf(null, cur), rules.effectiveOf(null, next))].sort();
    const match = (hostId, hostTenant) => hostTenant === tenantId;
    if (dryRun) {
      res.json({
        dry_run: true,
        tenant: tenantId,
        action,
        version,
        next_version: rules.policyVersion(next),
        diff: rules.diffColumns(cur, next),
        dangerous,
        live_sessions: liveCount(match)
      });
      return;
    }
    if (!(await dangerousGate(req, res, principal, body, dangerous, tenantId))) return;
    let out;
    try {
      out = await fleet.registry.setTenantChannelPolicyAudited({
        tenantId,
        tcpPolicy: next.tcp_policy,
        filePolicy: next.file_policy,
        servicePolicy: next.service_policy,
        packagePolicy: next.package_policy,
        configPolicy: next.config_policy,
        tweakPolicy: next.tweak_policy,
        actor: String(principal.userId),
        action,
        reason,
        ifVersion,
        extra: { policy_schema: rules.POLICY_SCHEMA, ...actorFields(principal), dangerous }
      });
    } catch (err) {
      if (err.code === 'version_conflict') {
        refuse(res, 409, { error: 'version_conflict' });
        return;
      }
      throw err;
    }
    notifyDangerous(tenantId, null, dangerous, out.audit_seq, action);
    const counts = await renew(match);
    res.json({ tenant: tenantId, action, version: out.version, audit_seq: out.audit_seq, dangerous, renewed: counts.renewed, ended: counts.ended });
  }

  app.get('/api/v1/tenants/:tenant/channel-policy', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    const { tenantId, cols } = await loadTenant(req, principal);
    res.json({
      tenant: tenantId,
      policy: cols,
      grants: rules.grantsOf(cols),
      version: rules.policyVersion(cols),
      dangerous: rules.dangerousEntries(null, rules.effectiveOf(null, cols))
    });
  }));

  app.put('/api/v1/tenants/:tenant/channel-policy', wrap(async (req, res) => {
    noStore(res);
    const principal = await authenticate(req, fleet);
    const { tenantId, cols } = await loadTenant(req, principal);
    const body = writeBody(req, principal);
    const dryRun = dryRunOf(req);
    rateGate();
    reasonOf(body);
    ifVersionOf(body);
    const next = ruled(() => rules.buildPolicy(body.grants, rules.apiLabel));
    await tenantWrite(req, res, principal, tenantId, cols, body, next, 'channel_policy_tenant_set', dryRun);
  }));

  for (const [verb, policy] of [['clear', rules.clearPolicy], ['inherit', rules.inheritPolicy]]) {
    app.post(`/api/v1/tenants/:tenant/channel-policy/${verb}`, wrap(async (req, res) => {
      noStore(res);
      const principal = await authenticate(req, fleet);
      const { tenantId, cols } = await loadTenant(req, principal);
      const body = writeBody(req, principal);
      const dryRun = dryRunOf(req);
      rateGate();
      await tenantWrite(req, res, principal, tenantId, cols, body, policy(), `channel_policy_tenant_${verb}`, dryRun);
    }));
  }
}

module.exports = { mountPolicyRoutes, writeRate };
