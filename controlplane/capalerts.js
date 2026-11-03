'use strict';

// Capability and host-offline alerts (plan sah-fleet-readiness P1b). The
// instance holding a host's agent socket evaluates its rules in the 30 s
// control tick and after each accepted capability_report; the database
// partial unique index cp_alert_events_active_capability_idx keeps at most one
// active alert per host and rule across replicas.
//
// Rules, N = the agent report cadence (SYSTEMAPI_CAPABILITY_INTERVAL_S,
// default 600):
//   capability:<name>  an expected capability (expectedCapabilities over the
//                      effective policy) out of the effective routing set for
//                      2 x N on this connection; a connection with no report
//                      yet (health unknown) never alerts.
//   capability:reports a connection that sent at least one report sends none
//                      for 3 x N.
//   Both resolve after 2 consecutive reports with the capability routable
//   (for capability:reports, any 2 reports); a capability no longer
//   expected resolves at the next evaluation with a report.
//   host:offline       5 min after the host's last socket closed (a reconnect
//                      inside that window opens nothing); resolved on
//                      reconnect.
//
// Threats: unbounded memory or timers from many hosts or flapping agents,
// duplicate alerts from replicas or retries, and paths or raw agent text in
// alerts, audits or webhooks. There is no per-host timer: one tick walks the
// hosts, single-flight. Memory holds one entry per connected host plus hosts
// closed less than 5 min ago; a host is dropped when its offline alert is
// tried, on retire, and an offline entry never outlives the window. Every
// alert field is a fixed rule name, a name from KNOWN_CAPABILITIES, a fixed
// state, or a reason code from the validator's fixed set. Inserts go through
// the partial unique index (ON CONFLICT DO NOTHING), resolves are idempotent
// UPDATEs, and each open or resolve writes its audit row in the same
// transaction. Health is self-reported: it detects breakage, NOT compromise
// (a compromised agent can report ok or withhold reports). Does NOT fire
// host:offline while the control plane is down, nor for a host that went
// offline before this process started (see the external /ready check).

const { KNOWN_CAPABILITIES, HEADER_ONLY, hostHealth } = require('./capabilities');

const DEFAULT_INTERVAL_S = 600;
const OFFLINE_AFTER_MS = 5 * 60_000;
// How long a host's expected set is reused before the policy is read again.
const EXPECTED_TTL_MS = 5 * 60_000;
const REPORTS_RULE = 'capability:reports';
const OFFLINE_RULE = 'host:offline';
const ACTOR = 'system:capability';
const TRACKED = KNOWN_CAPABILITIES.filter((name) => !HEADER_ONLY.has(name));

// SYSTEMAPI_CAPABILITY_INTERVAL_S: an integer from 60 to 86400, else the
// default.
function capabilityIntervalMs(env) {
  const raw = env && env.SYSTEMAPI_CAPABILITY_INTERVAL_S;
  const n = raw === undefined || raw === '' ? NaN : Number(raw);
  return (Number.isInteger(n) && n >= 60 && n <= 86400 ? n : DEFAULT_INTERVAL_S) * 1000;
}

const capabilityRule = (name) => `capability:${name}`;

function freshCaps() {
  const caps = new Map();
  for (const name of TRACKED) caps.set(name, { since: null, okStreak: 0, opened: false, resolveDone: false });
  return caps;
}

class CapabilityAlerts {
  // fleet: liveCapState(hostId), expectedCapabilities(hostId), registry,
  // deliverAlertWebhook(tenantId, rule, body).
  constructor(fleet) {
    this.fleet = fleet;
    this.hosts = new Map();
    // Overridable for tests.
    this.now = () => Date.now();
    this.intervalMs = null;
    this.offlineAfterMs = OFFLINE_AFTER_MS;
    this.ticking = false;
  }

  nMs() {
    return this.intervalMs || capabilityIntervalMs(this.fleet.env || process.env);
  }

  // A new connection for hostId: fresh per-connection state, and any open
  // host:offline alert resolved.
  async onConnect(hostId) {
    this.hosts.set(hostId, {
      disconnectedAt: null,
      caps: freshCaps(),
      reports: 0,
      lastReportAt: null,
      reportsOpened: false,
      reportsBase: 0,
      reportsResolveDone: false,
      expected: null,
      expectedAt: 0,
      health: null
    });
    await this.resolve(hostId, [{ rule: OFFLINE_RULE, capability: null, state: 'online', reason: 'reconnected' }], 'host_offline');
    await this.evaluate(hostId);
  }

  // hostId's last socket closed (a replaced one does not call this).
  onDisconnect(hostId) {
    const prev = this.hosts.get(hostId);
    this.hosts.set(hostId, { disconnectedAt: this.now(), health: prev ? prev.health : null });
  }

  dropHost(hostId) {
    this.hosts.delete(hostId);
  }

  // An accepted report on hostId's live connection: the streaks move.
  noteReport(hostId, conn) {
    const st = this.hosts.get(hostId);
    if (!st || !st.caps || !conn) return;
    st.reports += 1;
    st.lastReportAt = this.now();
    for (const [name, c] of st.caps) {
      if (conn.supports(name)) c.okStreak += 1;
      else c.okStreak = 0;
    }
  }

  async expected(hostId, st, refresh) {
    const now = this.now();
    if (refresh || !st.expected || now - st.expectedAt >= EXPECTED_TTL_MS) {
      st.expected = new Set(await this.fleet.expectedCapabilities(hostId));
      st.expectedAt = now;
    }
    return st.expected;
  }

  // One host's rules. refresh re-reads the expected set (after a report).
  async evaluate(hostId, { refresh = false } = {}) {
    const st = this.hosts.get(hostId);
    if (!st) return;
    const now = this.now();
    if (!st.caps) {
      if (now - st.disconnectedAt < this.offlineAfterMs) return;
      // One try: whatever its outcome the host leaves memory (a reconnect
      // resolves through the database, not this entry).
      this.hosts.delete(hostId);
      await this.open(hostId, { rule: OFFLINE_RULE, capability: null, state: 'offline', reason: 'no_socket' }, 'host_offline', 'critical');
      return;
    }
    const { connected, conn } = this.fleet.liveCapState(hostId);
    if (!connected) return;
    if (!conn || conn.reportCount === 0 || st.reports === 0) {
      await this.setHealth(hostId, st, hostHealth({ connected, conn, expected: [] }));
      return;
    }
    const expected = await this.expected(hostId, st, refresh);
    if (this.hosts.get(hostId) !== st) return;
    const n = this.nMs();
    const resolves = [];
    for (const [name, c] of st.caps) {
      const routable = conn.supports(name);
      if (expected.has(name) && !routable) {
        c.resolveDone = false;
        if (c.since === null) c.since = now;
        if (!c.opened && now - c.since >= 2 * n) {
          c.opened = true;
          const r = conn.reported.get(name);
          const state = r && r.state !== 'ok' ? r.state : 'degraded';
          const reason = conn.unsupportedReason(name) || (r && r.reason) || 'probe_error';
          await this.open(hostId, { rule: capabilityRule(name), capability: name, state, reason }, 'capability_alert', 'warning');
        }
        continue;
      }
      c.since = null;
      if (!c.resolveDone && (c.okStreak >= 2 || !expected.has(name))) {
        c.resolveDone = true;
        c.opened = false;
        resolves.push({ rule: capabilityRule(name), capability: name, state: routable ? 'ok' : 'not_expected', reason: '' });
      }
    }
    if (!st.reportsOpened && now - st.lastReportAt >= 3 * n) {
      st.reportsOpened = true;
      st.reportsBase = st.reports;
      st.reportsResolveDone = false;
      await this.open(hostId, { rule: REPORTS_RULE, capability: null, state: 'unknown', reason: 'report_missing' }, 'capability_alert', 'warning');
    } else if (!st.reportsResolveDone && st.reports - st.reportsBase >= 2) {
      st.reportsResolveDone = true;
      st.reportsOpened = false;
      resolves.push({ rule: REPORTS_RULE, capability: null, state: 'ok', reason: '' });
    }
    if (resolves.length > 0) await this.resolve(hostId, resolves, 'capability_alert');
    await this.setHealth(hostId, st, hostHealth({ connected, conn, expected: [...expected] }));
  }

  // The tick: every tracked host once, never two ticks at a time. A host's
  // failure is logged and the walk goes on.
  async tick() {
    if (this.ticking) return;
    this.ticking = true;
    try {
      for (const hostId of [...this.hosts.keys()]) {
        try {
          await this.evaluate(hostId);
        } catch (err) {
          console.error(`[alerts] capability evaluation failed host=${hostId} error=${codeOf(err)}`);
        }
      }
    } finally {
      this.ticking = false;
    }
  }

  async setHealth(hostId, st, health) {
    if (st.health === health) return;
    const reg = this.fleet.registry;
    if (!reg || typeof reg.setHostHealth !== 'function') return;
    await reg.setHostHealth(hostId, health);
    st.health = health;
  }

  async open(hostId, a, type, severity) {
    const reg = this.fleet.registry;
    if (!reg || typeof reg.openHostAlert !== 'function') return;
    const message = a.capability ? `${a.capability} ${a.state}${a.reason ? ` (${a.reason})` : ''}` : `${a.rule} ${a.reason}`;
    const row = await reg.openHostAlert({ host_id: hostId, rule_name: a.rule, severity, message, actor: ACTOR, audit: a });
    if (!row) return;
    await this.fleet.deliverAlertWebhook(row.tenant_id, a.rule, hostId, {
      type, status: 'open', alert_id: row.id, host_id: hostId, capability: a.capability, state: a.state, reason: a.reason
    }, true);
  }

  async resolve(hostId, list, type) {
    const reg = this.fleet.registry;
    if (!reg || typeof reg.resolveHostAlerts !== 'function') return;
    const rows = await reg.resolveHostAlerts(hostId, list, ACTOR);
    for (const row of rows) {
      const a = list.find((x) => x.rule === row.rule_name);
      await this.fleet.deliverAlertWebhook(row.tenant_id, a.rule, hostId, {
        type, status: 'resolved', alert_id: row.id, host_id: hostId, capability: a.capability, state: a.state, reason: a.reason
      }, false);
    }
  }
}

function codeOf(err) {
  return err && typeof err.code === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(err.code) ? err.code : 'internal';
}

// The audit row of an alert open or resolve: rule, capability, state and
// reason codes only.
function alertAuditEntry(row, a, actor, opened) {
  return {
    tenant_id: row.tenant_id,
    host_id: row.host_id,
    actor,
    action: opened ? 'capability_alert_open' : 'capability_alert_resolve',
    payload: { alert_id: Number(row.id), rule: a.rule, capability: a.capability, state: a.state, reason: a.reason }
  };
}

// Rule names the alert registry methods accept.
const ALERT_RULE_RE = /^(capability:[a-z][a-z0-9_]{0,15}|host:offline)$/;

module.exports = {
  CapabilityAlerts,
  capabilityIntervalMs,
  capabilityRule,
  alertAuditEntry,
  ALERT_RULE_RE,
  REPORTS_RULE,
  OFFLINE_RULE,
  OFFLINE_AFTER_MS,
  DEFAULT_INTERVAL_S
};
