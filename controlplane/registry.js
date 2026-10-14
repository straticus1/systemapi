// Threats: cross-tenant host reads, host theft by a second API key, a
// rewritten audit row, and a security event with no tenant shown to every
// audit reader. Queries are parameterized. A host id that belongs to another
// tenant is returned as not found. Webhook HMAC secrets are sealed before
// insert; this store does not log them. listSecurity returns only rows whose
// tenant_id is in the caller's set. Does NOT authenticate the caller.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { GENESIS, canonicalJSON, rowHash, verifyRows } = require('./chain');
const { scopesForKeyRows } = require('./authz');
const { escapeLike, efficiency: efficiencyOf } = require('./stats');
const { fingerprint } = require('./token');
const { assertPolicyShape } = require('./channels');

const METRICS = new Set(['cpu.usage_percent', 'memory.used_percent', 'disk.used_percent']);
const ROLES = new Set(['admin', 'operator', 'viewer']);
const SCHEMA_SQL = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
const TELEMETRY_CAP = 5000;

function http(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function publicHost(row) {
  if (!row) return null;
  return {
    host_id: row.host_id,
    tenant_id: row.tenant_id,
    hostname: row.hostname,
    os: row.os || '',
    platform: row.platform || '',
    ssh_pubkey: row.ssh_pubkey,
    status: row.status,
    last_seen_at: row.last_seen_at,
    tags: row.tags || [],
    created_at: row.created_at,
    cpu_percent: row.cpu_percent ?? null,
    sparkline: row.sparkline || []
  };
}

function publicWebhook(row) {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    url: row.url,
    secret_fingerprint: row.secret_fingerprint,
    created_at: row.created_at
  };
}

// Appends one chained audit row inside the caller's transaction.
async function auditInsert(client, entry) {
  const prevRes = await client.query('SELECT row_hash FROM cp_audit ORDER BY seq DESC LIMIT 1 FOR UPDATE');
  const prev = prevRes.rows[0] ? prevRes.rows[0].row_hash : GENESIS;
  const payload = JSON.parse(canonicalJSON(entry.payload || {}));
  const cols = {
    tenant_id: entry.tenant_id || null,
    host_id: entry.host_id || null,
    actor: entry.actor || null,
    action: entry.action,
    payload
  };
  const hash = rowHash(prev, cols);
  const ins = await client.query(
    `INSERT INTO cp_audit (prev_hash, row_hash, tenant_id, host_id, actor, action, payload)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
     RETURNING seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload, created_at`,
    [prev, hash, cols.tenant_id, cols.host_id, cols.actor, cols.action, JSON.stringify(payload)]
  );
  return ins.rows[0];
}

// The audit row for an SSO bind or unbind. The sub is recorded as a
// fingerprint, never in clear.
function ssoAuditEntry(tenantId, userId, sub, previous, actor) {
  return {
    tenant_id: tenantId,
    actor,
    action: sub === null ? 'sso_unbind' : 'sso_bind',
    payload: {
      user_id: userId,
      sso_sub_fp: sub === null ? null : fingerprint(sub),
      previous_fp: previous ? fingerprint(previous) : null
    }
  };
}

class MemoryRegistry {
  constructor(env = {}) {
    this.env = env;
    this.tenants = new Map();
    this.members = [];
    this.hosts = new Map();
    this.telemetry = [];
    this.metricInserts = 0;
    this.alerts = [];
    this.alertSeq = 1;
    this.audit = [];
    this.auditSeq = 1;
    this.auditChain = Promise.resolve();
    this.webhooks = [];
    this.schedules = [];
    this.comments = [];
    this.commentSeq = 1;
    this.securityEvents = [];
    this.securitySeq = 1;
    this.scopes = new Map();
        this.software = [];
    this.cves = [];
    // Channel policies live apart from host rows so publicHost never sees them.
    this.hostPolicies = new Map();
    this.tenantPolicies = new Map();
  }

  async enroll({ tenantId, userId, keyId, hostId, hostname, os, platform, sshPubkey }) {
    const existing = this.tenants.get(tenantId);
    const mine = this.members.filter((m) => m.user_id === userId);
    if (!existing) {
      if (mine.length > 0) throw http(403, 'tenant_create_denied');
      this.tenants.set(tenantId, {
        tenant_id: tenantId,
        display_name: tenantId,
        owner_user_id: userId,
        created_at: new Date().toISOString()
      });
      this.members.push({ tenant_id: tenantId, user_id: userId, email: null, role: 'admin' });
    } else if (!mine.some((m) => m.tenant_id === tenantId)) {
      throw http(403, 'not_a_member');
    }
    const prev = this.hosts.get(hostId);
    if (prev && (prev.tenant_id !== tenantId || prev.key_id !== keyId)) {
      throw http(403, 'host_steal');
    }
    const now = new Date().toISOString();
    this.hosts.set(hostId, {
      host_id: hostId,
      tenant_id: tenantId,
      key_id: keyId,
      hostname,
      os: os || '',
      platform: platform || '',
      ssh_pubkey: sshPubkey,
      status: 'online',
      last_seen_at: now,
      tags: prev ? prev.tags : [],
      created_at: prev ? prev.created_at : now
    });
    return this.getHost([tenantId], hostId);
  }

  tenantIdsOf(userId) {
    return this.members.filter((m) => m.user_id === userId).map((m) => m.tenant_id);
  }

  // Identity is the member id only; email is display data, never a match key.
  async membershipsForUser(userId) {
    return this.members
      .filter((m) => m.user_id === userId)
      .map((m) => ({ ...m }));
  }

  // Rows whose sso_sub is exactly this Authentik sub (byte-exact).
  async membershipsForSub(sub) {
    if (typeof sub !== 'string' || sub.length === 0) return [];
    return this.members.filter((m) => m.sso_sub === sub).map((m) => ({ ...m }));
  }

  // A member's identity is the same in every tenant: binding a row to a sub
  // that differs from another bound row of that member is refused
  // (sso_sub_conflict); changing it means unbinding every row first.
  // Sets (or clears, with sub null) one membership row's sso_sub and appends
  // the audit row; the row is put back if the audit write fails.
  async setSsoSub({ tenantId, userId, sub, actor }) {
    const row = this.members.find((m) => m.tenant_id === tenantId && m.user_id === userId);
    if (!row) throw http(404, 'not_found');
    if (sub !== null && this.members.some((m) => m.sso_sub === sub && m.user_id !== userId)) {
      throw http(409, 'sso_sub_taken');
    }
    if (sub !== null && this.members.some((m) => m.user_id === userId && m.tenant_id !== tenantId
      && m.sso_sub != null && m.sso_sub !== sub)) {
      throw http(409, 'sso_sub_conflict');
    }
    const previous = row.sso_sub || null;
    row.sso_sub = sub;
    try {
      await this.appendAudit(ssoAuditEntry(tenantId, userId, sub, previous, actor));
    } catch (err) {
      row.sso_sub = previous;
      throw err;
    }
    return { tenant_id: tenantId, user_id: userId, bound: sub !== null };
  }

  async addMember(tenantId, userId, role, email) {
    if (!ROLES.has(role)) throw http(400, 'bad_role');
    if (!this.tenants.has(tenantId)) throw http(404, 'not_found');
    const idx = this.members.findIndex((m) => m.tenant_id === tenantId && m.user_id === userId);
    const prev = idx >= 0 ? this.members[idx] : null;
    const row = { tenant_id: tenantId, user_id: userId, email: email || (prev ? prev.email : null), role, sso_sub: prev ? prev.sso_sub : null };
    if (idx >= 0) this.members[idx] = row;
    else this.members.push(row);
    return { tenant_id: row.tenant_id, user_id: row.user_id, email: row.email, role: row.role };
  }

  decorate(row) {
    const series = this.telemetry
      .filter((t) => t.host_id === row.host_id && t.metric === 'cpu.usage_percent')
      .slice(-20)
      .map((t) => t.value);
    return publicHost({ ...row, sparkline: series, cpu_percent: series.length ? series[series.length - 1] : null });
  }

  async listHosts(tenantIds, query) {
    const allow = new Set(tenantIds || []);
    let rows = [...this.hosts.values()].filter((h) => allow.has(h.tenant_id));
    if (query) {
      const needle = String(query).toLowerCase();
      rows = rows.filter((h) => h.hostname.toLowerCase().includes(needle));
    }
    rows.sort((a, b) => String(b.last_seen_at || '').localeCompare(String(a.last_seen_at || '')));
    return rows.map((row) => this.decorate(row));
  }

  async getHost(tenantIds, hostId) {
    const row = this.hosts.get(hostId);
    if (!row || !(tenantIds || []).includes(row.tenant_id)) return null;
    return this.decorate(row);
  }

  // Exact host_id, else exact case-insensitive hostname, inside tenantIds.
  async resolveHosts(tenantIds, name) {
    const allow = new Set(tenantIds || []);
    const byId = this.hosts.get(name);
    if (byId && allow.has(byId.tenant_id)) return [this.decorate(byId)];
    const needle = String(name).toLowerCase();
    return [...this.hosts.values()]
      .filter((h) => allow.has(h.tenant_id) && String(h.hostname).toLowerCase() === needle)
      .map((row) => this.decorate(row));
  }

  async touchHost(hostId, fields = {}) {
    const row = this.hosts.get(hostId);
    if (!row) return;
    row.last_seen_at = new Date().toISOString();
    row.status = 'online';
    if (fields.os) row.os = fields.os;
    if (fields.platform) row.platform = fields.platform;
  }

  // SAH channel policies, raw (unparsed) values. See controlplane/channels.js
  // effectivePolicies for the host -> tenant -> deny-all fallback.
  async channelPolicies(hostId) {
    const row = this.hosts.get(hostId);
    if (!row) return null;
    const h = this.hostPolicies.get(hostId) || {};
    const t = this.tenantPolicies.get(row.tenant_id) || {};
    return {
      host_tcp_policy: h.tcp_policy ?? null,
      host_file_policy: h.file_policy ?? null,
      tenant_tcp_policy: t.tcp_policy ?? null,
      tenant_file_policy: t.file_policy ?? null
    };
  }

  // Only keys present in `fields` change; null clears a column.
  async setHostChannelPolicy(hostId, fields) {
    if (!this.hosts.has(hostId)) throw http(404, 'not_found');
    const cur = { ...(this.hostPolicies.get(hostId) || {}) };
    for (const key of ['tcp_policy', 'file_policy']) {
      if (!(key in fields)) continue;
      assertPolicyShape(key === 'tcp_policy' ? 'tcp' : 'file', fields[key]);
      cur[key] = fields[key] === null ? null : JSON.parse(JSON.stringify(fields[key]));
    }
    this.hostPolicies.set(hostId, cur);
  }

  async setTenantChannelPolicy(tenantId, fields) {
    if (!this.tenants.has(tenantId)) throw http(404, 'not_found');
    const cur = { ...(this.tenantPolicies.get(tenantId) || {}) };
    for (const key of ['tcp_policy', 'file_policy']) {
      if (!(key in fields)) continue;
      assertPolicyShape(key === 'tcp_policy' ? 'tcp' : 'file', fields[key]);
      cur[key] = fields[key] === null ? null : JSON.parse(JSON.stringify(fields[key]));
    }
    this.tenantPolicies.set(tenantId, cur);
  }

  async setHostStatus(hostId, status) {
    const row = this.hosts.get(hostId);
    if (row) row.status = status;
  }

  async countHosts() {
    let online = 0;
    for (const host of this.hosts.values()) if (host.status === 'online') online += 1;
    return { total: this.hosts.size, online, offline: this.hosts.size - online };
  }

  async countOpenAlerts() {
    return this.alerts.filter((row) => row.status === 'open').length;
  }

  async recordMetric(hostId, metric, value, labels = {}) {
    if (!METRICS.has(metric) || typeof value !== 'number' || Number.isNaN(value)) return;
    this.telemetry.push({
      host_id: hostId,
      ts: new Date().toISOString(),
      metric,
      value,
      labels
    });
    if (this.telemetry.length > TELEMETRY_CAP) {
      this.telemetry.splice(0, this.telemetry.length - TELEMETRY_CAP);
    }
    this.metricInserts += 1;
    if (this.metricInserts % 100 === 0) {
      const days = retentionDays(this.env);
      const cutoff = Date.now() - days * 86400000;
      this.telemetry = this.telemetry.filter((t) => Date.parse(t.ts) >= cutoff);
    }
  }

  async metricSeries(hostId, metric, limit = 60) {
    if (!METRICS.has(metric)) return [];
    return this.telemetry
      .filter((t) => t.host_id === hostId && t.metric === metric)
      .slice(-limit)
      .map((t) => ({ ts: t.ts, value: t.value }));
  }

  async metricAggregate(hostId, metric, bucket, from, to) {
    if (!METRICS.has(metric)) return [];
    const rows = this.telemetry.filter((t) => {
      if (t.host_id !== hostId || t.metric !== metric) return false;
      const ms = Date.parse(t.ts);
      if (from && ms < from) return false;
      if (to && ms >= to) return false;
      return true;
    });
    const groups = new Map();
    for (const row of rows) {
      const key = bucketKey(row.ts, bucket);
      const cur = groups.get(key) || { bucket: key, sum: 0, n: 0 };
      cur.sum += row.value;
      cur.n += 1;
      groups.set(key, cur);
    }
    return [...groups.values()].map((g) => ({ bucket: g.bucket, value: g.sum / g.n }));
  }

  async appendAudit(entry) {
    const run = this.auditChain.then(() => {
      const prev = this.audit.length ? this.audit[this.audit.length - 1].row_hash : GENESIS;
      const payload = JSON.parse(canonicalJSON(entry.payload || {}));
      const row = {
        seq: this.auditSeq++,
        prev_hash: prev,
        tenant_id: entry.tenant_id || null,
        host_id: entry.host_id || null,
        actor: entry.actor || null,
        action: entry.action,
        payload,
        created_at: new Date().toISOString()
      };
      row.row_hash = rowHash(prev, row);
      this.audit.push(row);
      return row;
    });
    this.auditChain = run.then(() => {}, () => {});
    return run;
  }

  async verifyAudit() {
    return verifyRows(this.audit);
  }

  async listAudit(tenantIds, limit = 100) {
    const allow = new Set(tenantIds || []);
    return this.audit.filter((row) => row.tenant_id && allow.has(row.tenant_id)).slice(-limit).reverse();
  }

  async recordSecurity(event) {
    const row = {
      id: this.securitySeq++,
      tenant_id: event.tenant_id || null,
      kind: event.kind,
      actor_fingerprint: event.actor_fingerprint || null,
      detail: event.detail || {},
      created_at: new Date().toISOString()
    };
    this.securityEvents.push(row);
    return row;
  }

  async listSecurity(tenantIds, limit = 100) {
    const allow = new Set(tenantIds || []);
    return this.securityEvents
      .filter((row) => row.tenant_id && allow.has(row.tenant_id))
      .slice(-limit)
      .reverse();
  }

  async scopesForKey(keyId) {
    const rows = this.scopes.get(keyId) || [];
    return scopesForKeyRows(rows, this.env);
  }

  async setScopes(keyId, scopes) {
    this.scopes.set(keyId, [...scopes]);
  }

  async recentAlert(hostId, ruleName, withinMs, now = Date.now()) {
    return this.alerts.some((a) => a.host_id === hostId && a.rule_name === ruleName && now - Date.parse(a.created_at) < withinMs);
  }

  async openAlert(entry) {
    const row = {
      id: this.alertSeq++,
      tenant_id: entry.tenant_id,
      host_id: entry.host_id,
      rule_name: entry.rule_name,
      metric: entry.metric || null,
      value: entry.value,
      status: 'open',
      created_at: new Date().toISOString()
    };
    this.alerts.push(row);
    return row;
  }

  async listAlerts(tenantIds, status) {
    const allow = new Set(tenantIds || []);
    return this.alerts.filter((a) => allow.has(a.tenant_id) && (!status || a.status === status));
  }

  async setAlertStatus(tenantIds, id, status) {
    const allow = new Set(tenantIds || []);
    const row = this.alerts.find((a) => a.id === id && allow.has(a.tenant_id));
    if (!row) return null;
    row.status = status;
    return row;
  }

  async createWebhook(row) {
    this.webhooks.push(row);
    return publicWebhook(row);
  }

  async listWebhooks(tenantId) {
    return this.webhooks.filter((w) => w.tenant_id === tenantId).map(publicWebhook);
  }

  async deleteWebhook(tenantId, id) {
    const before = this.webhooks.length;
    this.webhooks = this.webhooks.filter((w) => !(w.tenant_id === tenantId && w.id === id));
    return this.webhooks.length < before;
  }

  async webhooksForTenant(tenantId) {
    return this.webhooks.filter((w) => w.tenant_id === tenantId).map((w) => ({ ...w }));
  }

  async createSchedule(row) {
    this.schedules.push(row);
    return publicSchedule(row);
  }

  async listSchedules(tenantId) {
    return this.schedules.filter((s) => s.tenant_id === tenantId).map(publicSchedule);
  }

  async deleteSchedule(tenantId, id) {
    const before = this.schedules.length;
    this.schedules = this.schedules.filter((s) => !(s.tenant_id === tenantId && s.id === id));
    return this.schedules.length < before;
  }

  async dueSchedules(date) {
    const { cronMatches } = require('./stats');
    return this.schedules.filter((s) => cronMatches(s.cron, date)).map((s) => ({ ...s }));
  }

  async markSchedule(id, minuteKey) {
    const row = this.schedules.find((s) => s.id === id);
    if (!row) return false;
    if (row.last_run_minute === minuteKey) return false;
    row.last_run_minute = minuteKey;
    return true;
  }

  async addComment(entry) {
    if (typeof entry.body !== 'string' || entry.body.length === 0 || entry.body.length > 2000) {
      throw http(400, 'bad_comment');
    }
    const row = {
      id: this.commentSeq++,
      tenant_id: entry.tenant_id,
      host_id: entry.host_id,
      author: entry.author,
      body: entry.body,
      created_at: new Date().toISOString()
    };
    this.comments.push(row);
    return row;
  }

  async listComments(tenantId, hostId) {
    return this.comments.filter((c) => c.tenant_id === tenantId && c.host_id === hostId);
  }

  async upsertSoftware(hostId, sw) {
    const name = sw.name || 'unknown';
    const version = sw.version || 'unknown';
    const found = this.software.find((s) => s.host_id === hostId && s.name === name && s.version === version);
    if (found) {
      found.last_detected_at = new Date().toISOString();
      return { inserted: false };
    }
    this.software.push({
      host_id: hostId,
      name,
      version,
      architecture: sw.architecture || '',
      last_detected_at: new Date().toISOString()
    });
    return { inserted: true };
  }

  async listSoftware(hostId) {
    return this.software.filter((s) => s.host_id === hostId);
  }

  async saveCVE(row) {
    const found = this.cves.find((c) => c.host_id === row.host_id && c.cve_id === row.cve_id && c.software_name === row.software_name);
    if (found) return found;
    const stored = { ...row, discovered_at: new Date().toISOString() };
    this.cves.push(stored);
    return stored;
  }

  async listCVEs(hostId) {
    return this.cves.filter((c) => c.host_id === hostId);
  }

  async efficiency(tenantIds) {
    const hosts = [];
    for (const host of await this.listHosts(tenantIds)) {
      const cpu = await this.metricSeries(host.host_id, 'cpu.usage_percent', 100);
      const mem = await this.metricSeries(host.host_id, 'memory.used_percent', 100);
      hosts.push({
        host_id: host.host_id,
        hostname: host.hostname,
        cpu_avg: avg(cpu.map((p) => p.value)),
        mem_avg: avg(mem.map((p) => p.value))
      });
    }
    return efficiencyOf(hosts);
  }
}

class PgRegistry {
  constructor(pool, env = {}) {
    this.pool = pool;
    this.env = env;
    this.metricInserts = 0;
  }

  async enroll({ tenantId, userId, keyId, hostId, hostname, os, platform, sshPubkey }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const mem = await client.query('SELECT tenant_id FROM cp_members WHERE user_id = $1', [userId]);
      const ins = await client.query(
        `INSERT INTO cp_tenants (tenant_id, display_name, owner_user_id)
         VALUES ($1, $1, $2)
         ON CONFLICT (tenant_id) DO NOTHING
         RETURNING tenant_id`,
        [tenantId, userId]
      );
      if (ins.rowCount > 0) {
        if (mem.rowCount > 0) throw http(403, 'tenant_create_denied');
        await client.query(
          `INSERT INTO cp_members (tenant_id, user_id, role) VALUES ($1, $2, 'admin')
           ON CONFLICT DO NOTHING`,
          [tenantId, userId]
        );
      } else {
        const member = await client.query(
          'SELECT role FROM cp_members WHERE tenant_id = $1 AND user_id = $2',
          [tenantId, userId]
        );
        if (member.rowCount === 0) throw http(403, 'not_a_member');
      }
      const host = await client.query(
        `INSERT INTO cp_hosts (host_id, tenant_id, key_id, hostname, os, platform, ssh_pubkey, status, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'online', now())
         ON CONFLICT (host_id) DO UPDATE SET
           hostname = EXCLUDED.hostname,
           os = EXCLUDED.os,
           platform = EXCLUDED.platform,
           ssh_pubkey = EXCLUDED.ssh_pubkey,
           status = 'online',
           last_seen_at = now()
         WHERE cp_hosts.tenant_id = EXCLUDED.tenant_id AND cp_hosts.key_id = EXCLUDED.key_id
         RETURNING host_id`,
        [hostId, tenantId, keyId, hostname, os || '', platform || '', sshPubkey]
      );
      if (host.rowCount === 0) {
        const cur = await client.query('SELECT tenant_id, key_id FROM cp_hosts WHERE host_id = $1', [hostId]);
        if (cur.rowCount > 0) throw http(403, 'host_steal');
        throw http(403, 'host_rejected');
      }
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
      throw err;
    } finally {
      client.release();
    }
    return this.getHost([tenantId], hostId);
  }

  // Identity is the member id only; email is display data, never a match key.
  async membershipsForUser(userId) {
    const res = await this.pool.query(
      'SELECT tenant_id, user_id, email, role, sso_sub FROM cp_members WHERE user_id = $1',
      [userId]
    );
    return res.rows;
  }

  async membershipsForSub(sub) {
    if (typeof sub !== 'string' || sub.length === 0) return [];
    const res = await this.pool.query(
      'SELECT tenant_id, user_id, email, role, sso_sub FROM cp_members WHERE sso_sub = $1',
      [sub]
    );
    return res.rows;
  }

  // One transaction: the binding and its audit-chain row land together or
  // not at all. The advisory lock serializes binds, so the "one sub, one
  // member id" check cannot race.
  async setSsoSub({ tenantId, userId, sub, actor }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('cp_members.sso_sub'))");
      const cur = await client.query(
        'SELECT sso_sub FROM cp_members WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE',
        [tenantId, userId]
      );
      if (!cur.rows[0]) throw http(404, 'not_found');
      if (sub !== null) {
        const taken = await client.query(
          'SELECT 1 FROM cp_members WHERE sso_sub = $1 AND user_id <> $2 LIMIT 1',
          [sub, userId]
        );
        if (taken.rowCount > 0) throw http(409, 'sso_sub_taken');
        const conflict = await client.query(
          `SELECT 1 FROM cp_members
           WHERE user_id = $1 AND tenant_id <> $2 AND sso_sub IS NOT NULL AND sso_sub <> $3 LIMIT 1`,
          [userId, tenantId, sub]
        );
        if (conflict.rowCount > 0) throw http(409, 'sso_sub_conflict');
      }
      await client.query(
        'UPDATE cp_members SET sso_sub = $3 WHERE tenant_id = $1 AND user_id = $2',
        [tenantId, userId, sub]
      );
      await auditInsert(client, ssoAuditEntry(tenantId, userId, sub, cur.rows[0].sso_sub || null, actor));
      await client.query('COMMIT');
      return { tenant_id: tenantId, user_id: userId, bound: sub !== null };
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
      if (err.code === '23505') throw http(409, 'sso_sub_taken');
      throw err;
    } finally {
      client.release();
    }
  }

  async addMember(tenantId, userId, role, email) {
    if (!ROLES.has(role)) throw http(400, 'bad_role');
    const res = await this.pool.query(
      `INSERT INTO cp_members (tenant_id, user_id, role, email)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role, email = COALESCE(EXCLUDED.email, cp_members.email)
       RETURNING tenant_id, user_id, email, role`,
      [tenantId, userId, role, email || null]
    );
    return res.rows[0];
  }

  async listHosts(tenantIds, query) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const like = query ? `%${escapeLike(query)}%` : null;
    const res = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, os, platform, ssh_pubkey, status, last_seen_at, tags, created_at
       FROM cp_hosts
       WHERE tenant_id = ANY($1::text[])
         AND ($2::text IS NULL OR hostname ILIKE $2 ESCAPE '\\')
       ORDER BY last_seen_at DESC NULLS LAST`,
      [tenantIds, like]
    );
    const ids = res.rows.map((r) => r.host_id);
    const sparks = await this.sparklines(ids);
    return res.rows.map((row) => {
      const series = sparks.get(row.host_id) || [];
      return publicHost({
        ...row,
        sparkline: series,
        cpu_percent: series.length ? series[series.length - 1] : null
      });
    });
  }

  async sparklines(hostIds) {
    const out = new Map();
    if (!hostIds.length) return out;
    const res = await this.pool.query(
      `SELECT host_id, value FROM (
         SELECT host_id, value, row_number() OVER (PARTITION BY host_id ORDER BY ts DESC) AS rn
         FROM cp_telemetry
         WHERE metric = 'cpu.usage_percent' AND host_id = ANY($1::text[])
       ) t WHERE rn <= 20`,
      [hostIds]
    );
    for (const row of res.rows) {
      if (!out.has(row.host_id)) out.set(row.host_id, []);
      out.get(row.host_id).push(Number(row.value));
    }
    for (const [id, values] of out) out.set(id, values.reverse());
    return out;
  }

  async getHost(tenantIds, hostId) {
    if (!tenantIds || tenantIds.length === 0) return null;
    const res = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, os, platform, ssh_pubkey, status, last_seen_at, tags, created_at
       FROM cp_hosts WHERE host_id = $1 AND tenant_id = ANY($2::text[])`,
      [hostId, tenantIds]
    );
    if (!res.rows[0]) return null;
    const sparks = await this.sparklines([hostId]);
    const series = sparks.get(hostId) || [];
    return publicHost({
      ...res.rows[0],
      sparkline: series,
      cpu_percent: series.length ? series[series.length - 1] : null
    });
  }

  // Exact host_id, else exact case-insensitive hostname, inside tenantIds.
  async resolveHosts(tenantIds, name) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const byId = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, status FROM cp_hosts
       WHERE host_id = $1 AND tenant_id = ANY($2::text[])`,
      [name, tenantIds]
    );
    if (byId.rows.length > 0) return byId.rows;
    const res = await this.pool.query(
      `SELECT host_id, tenant_id, hostname, status FROM cp_hosts
       WHERE lower(hostname) = lower($1) AND tenant_id = ANY($2::text[])
       ORDER BY host_id LIMIT 100`,
      [name, tenantIds]
    );
    return res.rows;
  }

  async touchHost(hostId, fields = {}) {
    await this.pool.query(
      `UPDATE cp_hosts SET last_seen_at = now(), status = 'online',
         os = COALESCE($2, os),
         platform = COALESCE($3, platform)
       WHERE host_id = $1`,
      [hostId, fields.os || null, fields.platform || null]
    );
  }

  async channelPolicies(hostId) {
    const res = await this.pool.query(
      `SELECT h.tcp_policy AS host_tcp_policy, h.file_policy AS host_file_policy,
              t.tcp_policy AS tenant_tcp_policy, t.file_policy AS tenant_file_policy
       FROM cp_hosts h JOIN cp_tenants t ON t.tenant_id = h.tenant_id
       WHERE h.host_id = $1`,
      [hostId]
    );
    return res.rows[0] || null;
  }

  async setHostChannelPolicy(hostId, fields) {
    await this.setChannelPolicy('cp_hosts', 'host_id', hostId, fields);
  }

  async setTenantChannelPolicy(tenantId, fields) {
    await this.setChannelPolicy('cp_tenants', 'tenant_id', tenantId, fields);
  }

  // table and key are fixed identifiers from the two callers above, never
  // caller input. Values are parameters.
  async setChannelPolicy(table, keyColumn, id, fields) {
    const sets = [];
    const values = [id];
    for (const key of ['tcp_policy', 'file_policy']) {
      if (!(key in fields)) continue;
      assertPolicyShape(key === 'tcp_policy' ? 'tcp' : 'file', fields[key]);
      values.push(fields[key] === null ? null : JSON.stringify(fields[key]));
      sets.push(`${key} = $${values.length}::jsonb`);
    }
    if (sets.length === 0) return;
    const res = await this.pool.query(`UPDATE ${table} SET ${sets.join(', ')} WHERE ${keyColumn} = $1`, values);
    if (res.rowCount === 0) throw http(404, 'not_found');
  }

  async setHostStatus(hostId, status) {
    await this.pool.query('UPDATE cp_hosts SET status = $2 WHERE host_id = $1', [hostId, status]);
  }

  async countHosts() {
    const res = await this.pool.query(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE status = 'online')::int AS online
       FROM cp_hosts`
    );
    const total = res.rows[0].total || 0;
    const online = res.rows[0].online || 0;
    return { total, online, offline: total - online };
  }

  async countOpenAlerts() {
    const res = await this.pool.query(
      `SELECT count(*)::int AS n FROM cp_alert_events WHERE status = 'open'`
    );
    return res.rows[0].n || 0;
  }

  async recordMetric(hostId, metric, value, labels = {}) {
    if (!METRICS.has(metric) || typeof value !== 'number' || Number.isNaN(value)) return;
    await this.pool.query(
      `INSERT INTO cp_telemetry (host_id, metric, value, labels) VALUES ($1, $2, $3, $4::jsonb)`,
      [hostId, metric, value, JSON.stringify(labels)]
    );
    this.metricInserts += 1;
    if (this.metricInserts % 100 === 0) await this.pruneTelemetry(retentionDays(this.env));
  }

  async pruneTelemetry(days) {
    const n = retentionDays({ SYSTEMAPI_METRICS_RETENTION_DAYS: String(days) });
    await this.pool.query('DELETE FROM cp_telemetry WHERE ts < now() - make_interval(days => $1::int)', [n]);
  }

  async metricSeries(hostId, metric, limit = 60) {
    if (!METRICS.has(metric)) return [];
    const res = await this.pool.query(
      `SELECT ts, value FROM cp_telemetry
       WHERE host_id = $1 AND metric = $2
       ORDER BY ts DESC LIMIT $3`,
      [hostId, metric, limit]
    );
    return res.rows.reverse().map((r) => ({ ts: r.ts, value: Number(r.value) }));
  }

  async metricAggregate(hostId, metric, bucket, from, to) {
    if (!METRICS.has(metric)) return [];
    const res = await this.pool.query(
      `SELECT date_trunc($1::text, ts) AS bucket, avg(value) AS value
       FROM cp_telemetry
       WHERE host_id = $2 AND metric = $3
         AND ($4::timestamptz IS NULL OR ts >= $4)
         AND ($5::timestamptz IS NULL OR ts < $5)
       GROUP BY 1 ORDER BY 1`,
      [bucket, hostId, metric, from ? new Date(from) : null, to ? new Date(to) : null]
    );
    return res.rows.map((r) => ({ bucket: r.bucket, value: Number(r.value) }));
  }

  async appendAudit(entry) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const row = await auditInsert(client, entry);
      await client.query('COMMIT');
      return row;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* already closed */ }
      throw err;
    } finally {
      client.release();
    }
  }

  async verifyAudit() {
    const res = await this.pool.query(
      'SELECT seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload FROM cp_audit ORDER BY seq ASC'
    );
    return verifyRows(res.rows.map((row) => ({ ...row, seq: Number(row.seq) })));
  }

  async listAudit(tenantIds, limit = 100) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload, created_at
       FROM cp_audit WHERE tenant_id = ANY($1::text[])
       ORDER BY seq DESC LIMIT $2`,
      [tenantIds, limit]
    );
    return res.rows;
  }

  async recordSecurity(event) {
    const res = await this.pool.query(
      `INSERT INTO cp_security_events (tenant_id, kind, actor_fingerprint, detail)
       VALUES ($1, $2, $3, $4::jsonb)
       RETURNING id, tenant_id, kind, actor_fingerprint, detail, created_at`,
      [event.tenant_id || null, event.kind, event.actor_fingerprint || null, JSON.stringify(event.detail || {})]
    );
    return res.rows[0];
  }

  async listSecurity(tenantIds, limit = 100) {
    const ids = Array.isArray(tenantIds) ? tenantIds : [];
    if (ids.length === 0) return [];
    const res = await this.pool.query(
      `SELECT id, tenant_id, kind, actor_fingerprint, detail, created_at
       FROM cp_security_events
       WHERE tenant_id = ANY($1::text[])
       ORDER BY id DESC LIMIT $2`,
      [ids, limit]
    );
    return res.rows;
  }

  async scopesForKey(keyId) {
    const res = await this.pool.query('SELECT scope FROM cp_api_scopes WHERE key_id = $1', [keyId]);
    return scopesForKeyRows(res.rows.map((r) => r.scope), this.env);
  }

  async setScopes(keyId, scopes) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM cp_api_scopes WHERE key_id = $1', [keyId]);
      for (const scope of scopes) {
        await client.query('INSERT INTO cp_api_scopes (key_id, scope) VALUES ($1, $2)', [keyId, scope]);
      }
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    } finally {
      client.release();
    }
  }

  async recentAlert(hostId, ruleName, withinMs) {
    const res = await this.pool.query(
      `SELECT 1 FROM cp_alert_events
       WHERE host_id = $1 AND rule_name = $2 AND created_at > now() - make_interval(secs => $3::int)
       LIMIT 1`,
      [hostId, ruleName, Math.ceil(withinMs / 1000)]
    );
    return res.rowCount > 0;
  }

  async openAlert(entry) {
    const res = await this.pool.query(
      `INSERT INTO cp_alert_events (tenant_id, host_id, rule_name, metric, value, status)
       VALUES ($1, $2, $3, $4, $5, 'open')
       RETURNING id, tenant_id, host_id, rule_name, metric, value, status, created_at`,
      [entry.tenant_id, entry.host_id, entry.rule_name, entry.metric || null, entry.value]
    );
    return res.rows[0];
  }

  async listAlerts(tenantIds, status) {
    if (!tenantIds || tenantIds.length === 0) return [];
    const res = await this.pool.query(
      `SELECT id, tenant_id, host_id, rule_name, metric, value, status, created_at
       FROM cp_alert_events
       WHERE tenant_id = ANY($1::text[]) AND ($2::text IS NULL OR status = $2)
       ORDER BY created_at DESC`,
      [tenantIds, status || null]
    );
    return res.rows;
  }

  async setAlertStatus(tenantIds, id, status) {
    if (!tenantIds || tenantIds.length === 0) return null;
    const res = await this.pool.query(
      `UPDATE cp_alert_events SET status = $3
       WHERE id = $1 AND tenant_id = ANY($2::text[])
       RETURNING id, tenant_id, host_id, rule_name, metric, value, status, created_at`,
      [id, tenantIds, status]
    );
    return res.rows[0] || null;
  }

  async createWebhook(row) {
    await this.pool.query(
      `INSERT INTO cp_webhooks (id, tenant_id, url, secret, secret_fingerprint)
       VALUES ($1, $2, $3, $4, $5)`,
      [row.id, row.tenant_id, row.url, row.secret, row.secret_fingerprint]
    );
    return publicWebhook(row);
  }

  async listWebhooks(tenantId) {
    const res = await this.pool.query(
      `SELECT id, tenant_id, url, secret_fingerprint, created_at FROM cp_webhooks WHERE tenant_id = $1`,
      [tenantId]
    );
    return res.rows.map(publicWebhook);
  }

  async deleteWebhook(tenantId, id) {
    const res = await this.pool.query('DELETE FROM cp_webhooks WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
    return res.rowCount > 0;
  }

  async webhooksForTenant(tenantId) {
    const res = await this.pool.query(
      'SELECT id, tenant_id, url, secret, secret_fingerprint FROM cp_webhooks WHERE tenant_id = $1',
      [tenantId]
    );
    return res.rows;
  }

  async createSchedule(row) {
    await this.pool.query(
      `INSERT INTO cp_schedules (id, tenant_id, host_id, cron, script) VALUES ($1, $2, $3, $4, $5)`,
      [row.id, row.tenant_id, row.host_id, row.cron, row.script]
    );
    return publicSchedule(row);
  }

  async listSchedules(tenantId) {
    const res = await this.pool.query(
      `SELECT id, tenant_id, host_id, cron, last_run_minute, created_at FROM cp_schedules WHERE tenant_id = $1`,
      [tenantId]
    );
    return res.rows.map(publicSchedule);
  }

  async deleteSchedule(tenantId, id) {
    const res = await this.pool.query('DELETE FROM cp_schedules WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
    return res.rowCount > 0;
  }

  async dueSchedules(date) {
    const { cronMatches } = require('./stats');
    const res = await this.pool.query('SELECT id, tenant_id, host_id, cron, script, last_run_minute FROM cp_schedules');
    return res.rows.filter((row) => cronMatches(row.cron, date));
  }

  async markSchedule(id, minuteKey) {
    const res = await this.pool.query(
      `UPDATE cp_schedules SET last_run_minute = $2
       WHERE id = $1 AND (last_run_minute IS DISTINCT FROM $2)`,
      [id, minuteKey]
    );
    return res.rowCount > 0;
  }

  async addComment(entry) {
    if (typeof entry.body !== 'string' || entry.body.length === 0 || entry.body.length > 2000) {
      throw http(400, 'bad_comment');
    }
    const res = await this.pool.query(
      `INSERT INTO cp_comments (tenant_id, host_id, author, body)
       VALUES ($1, $2, $3, $4)
       RETURNING id, tenant_id, host_id, author, body, created_at`,
      [entry.tenant_id, entry.host_id, entry.author, entry.body]
    );
    return res.rows[0];
  }

  async listComments(tenantId, hostId) {
    const res = await this.pool.query(
      `SELECT id, tenant_id, host_id, author, body, created_at
       FROM cp_comments WHERE tenant_id = $1 AND host_id = $2 ORDER BY id ASC`,
      [tenantId, hostId]
    );
    return res.rows;
  }

  async upsertSoftware(hostId, sw) {
    const res = await this.pool.query(
      `INSERT INTO cp_software (host_id, name, version, architecture)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (host_id, name, version) DO UPDATE SET last_detected_at = now()
       RETURNING (xmax = 0) AS inserted`,
      [hostId, sw.name || 'unknown', sw.version || 'unknown', sw.architecture || '']
    );
    return { inserted: Boolean(res.rows[0] && res.rows[0].inserted) };
  }

  async listSoftware(hostId) {
    const res = await this.pool.query(
      'SELECT host_id, name, version, architecture, last_detected_at FROM cp_software WHERE host_id = $1 ORDER BY name',
      [hostId]
    );
    return res.rows;
  }

  async saveCVE(row) {
    await this.pool.query(
      `INSERT INTO cp_cves (host_id, software_name, software_version, cve_id, severity, description)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT DO NOTHING`,
      [row.host_id, row.software_name, row.software_version, row.cve_id, row.severity || 'Unknown', row.description || '']
    );
  }

  async listCVEs(hostId) {
    const res = await this.pool.query(
      `SELECT host_id, software_name, software_version, cve_id, severity, description, discovered_at
       FROM cp_cves WHERE host_id = $1 ORDER BY discovered_at DESC`,
      [hostId]
    );
    return res.rows;
  }

  async efficiency(tenantIds) {
    if (!tenantIds || tenantIds.length === 0) return efficiencyOf([]);
    const res = await this.pool.query(
      `SELECT h.host_id, h.hostname,
              avg(t.value) FILTER (WHERE t.metric = 'cpu.usage_percent') AS cpu_avg,
              avg(t.value) FILTER (WHERE t.metric = 'memory.used_percent') AS mem_avg
       FROM cp_hosts h
       LEFT JOIN cp_telemetry t ON t.host_id = h.host_id
       WHERE h.tenant_id = ANY($1::text[])
       GROUP BY h.host_id, h.hostname`,
      [tenantIds]
    );
    return efficiencyOf(res.rows.map((r) => ({
      host_id: r.host_id,
      hostname: r.hostname,
      cpu_avg: r.cpu_avg == null ? null : Number(r.cpu_avg),
      mem_avg: r.mem_avg == null ? null : Number(r.mem_avg)
    })));
  }
}

function publicSchedule(row) {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    host_id: row.host_id,
    cron: row.cron,
    last_run_minute: row.last_run_minute || null,
    created_at: row.created_at || null
  };
}

function retentionDays(env) {
  const n = Number(env && env.SYSTEMAPI_METRICS_RETENTION_DAYS);
  if (!Number.isInteger(n) || n < 1 || n > 3650) return 30;
  return n;
}

function avg(values) {
  if (!values.length) return null;
  return values.reduce((sum, n) => sum + n, 0) / values.length;
}

function bucketKey(ts, bucket) {
  const d = new Date(ts);
  if (bucket === 'day') return d.toISOString().slice(0, 10);
  if (bucket === 'hour') return d.toISOString().slice(0, 13);
  return d.toISOString().slice(0, 16);
}

async function createRegistry({ pool, env, logger = console }) {
  if (env.NODE_ENV === 'production' && !pool) {
    throw http(503, 'registry_unavailable');
  }
  if (pool) {
    try {
      await pool.query(SCHEMA_SQL);
      logger.log('[control] cp schema ready');
      return new PgRegistry(pool, env);
    } catch (err) {
      if (env.NODE_ENV === 'production') throw err;
      logger.warn(`[control] schema unavailable (${err.message}); using memory registry`);
      return new MemoryRegistry(env);
    }
  }
  logger.warn('[control] no database pool; using memory registry');
  return new MemoryRegistry(env);
}

module.exports = {
  MemoryRegistry,
  createRegistry,
  fingerprint
};
