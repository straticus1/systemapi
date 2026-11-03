'use strict';

// Capability and host-offline alerts (plan sah-fleet-readiness P1b). The
// instance holding a host's agent socket evaluates its rules in the 30 s
// control tick and after each accepted capability_report; the database
// partial unique index cp_alert_events_active_capability_idx keeps at most one
// active alert per host and rule across replicas.
//
// Rules, N = the report cadence: the larger of SYSTEMAPI_CAPABILITY_INTERVAL_S
// (default 600, at most 3600) and the interval_s the agent's latest report on
// this connection carried (its --capability-interval, 60..3600), so an agent
// set to report hourly never alerts on a 10 min control plane default:
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
//                      inside that window opens nothing, also to another
//                      replica: the open re-checks status and presence in
//                      SQL); resolved on reconnect.
//   A host opens at most OPENS_PER_HOUR_MAX alerts per rolling hour (a
//   flapping agent cannot flood alerts or webhooks); the held-back opens are
//   counted (cappedTotal, systemapi_capability_alert_capped_total) and tried
//   again once the hour allows. A resolve whose open webhook the cooldown
//   suppressed sends no webhook either. Retiring a host resolves its alerts
//   in the retire transaction (registry.retireHost).
//
// Threats: unbounded memory or timers from many hosts or flapping agents,
// duplicate alerts from replicas or retries, and paths or raw agent text in
// alerts, audits or webhooks. There is no per-host timer: one tick walks the
// hosts, single-flight. Memory holds one entry per connected host plus hosts
// closed less than 5 min ago (longer only while their offline alert keeps
// failing to write or is held back by the hourly cap); a host is dropped once
// its offline alert is written, and on retire. The retired, hourly-open and
// suppressed-webhook sets are per host and rule and pruned in the tick. State
// flags move only after the database call succeeded, so a failed write is
// tried again on the next tick. Every
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
const MIN_INTERVAL_S = 60;
const MAX_INTERVAL_S = 3600;
const OFFLINE_AFTER_MS = 5 * 60_000;
// Alert opens per host per rolling hour.
const OPENS_PER_HOUR_MAX = 6;
const OPEN_WINDOW_MS = 60 * 60_000;
// How long a host's expected set is reused before the policy is read again.
const EXPECTED_TTL_MS = 5 * 60_000;
const REPORTS_RULE = 'capability:reports';
const OFFLINE_RULE = 'host:offline';
const ACTOR = 'system:capability';
const TRACKED = KNOWN_CAPABILITIES.filter((name) => !HEADER_ONLY.has(name));

// SYSTEMAPI_CAPABILITY_INTERVAL_S: an integer from 60 to 3600 (the agent's
// own --capability-interval range), else the default.
function capabilityIntervalMs(env) {
  const raw = env && env.SYSTEMAPI_CAPABILITY_INTERVAL_S;
  const n = raw === undefined || raw === '' ? NaN : Number(raw);
  return (Number.isInteger(n) && n >= MIN_INTERVAL_S && n <= MAX_INTERVAL_S ? n : DEFAULT_INTERVAL_S) * 1000;
}

const capabilityRule = (name) => `capability:${name}`;
const alertKey = (hostId, rule) => `${hostId}\n${rule}`;

function freshCaps() {
  const caps = new Map();
  for (const name of TRACKED) caps.set(name, { since: null, okStreak: 0, opened: false, resolveDone: false });
  return caps;
}

class CapabilityAlerts {
  // fleet: liveCapState(hostId), expectedCapabilities(hostId), registry,
  // deliverAlertWebhook(tenantId, rule, hostId, body, isOpen) (false when
  // the cooldown suppressed it), instanceId(), noteAlertCapped(rule).
  constructor(fleet) {
    this.fleet = fleet;
    this.hosts = new Map();
    // hostId -> retire time: a close that lands after the retire is ignored.
    this.retired = new Map();
    // hostId -> open times in the last hour.
    this.opens = new Map();
    // alertKey of an active alert whose open webhook the cooldown suppressed.
    this.suppressedWebhooks = new Set();
    // alertKey of an open held back by the hourly cap (counted once).
    this.capped = new Set();
    this.cappedTotal = 0;
    // Overridable for tests.
    this.now = () => Date.now();
    this.intervalMs = null;
    this.offlineAfterMs = OFFLINE_AFTER_MS;
    this.opensPerHourMax = OPENS_PER_HOUR_MAX;
    this.ticking = false;
  }

  // N for one connection: the larger of the control plane's setting and the
  // interval_s the agent's latest report carried.
  nMs(conn) {
    const base = this.intervalMs || capabilityIntervalMs(this.fleet.env || process.env);
    const agent = conn && Number.isInteger(conn.intervalS) ? conn.intervalS * 1000 : 0;
    return Math.max(base, agent);
  }

  // The expected set the last evaluation read for a connected host, or null.
  cachedExpected(hostId) {
    const st = this.hosts.get(hostId);
    return st && st.caps && st.expected ? [...st.expected] : null;
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
    this.retired.delete(hostId);
    await this.resolve(hostId, [{ rule: OFFLINE_RULE, capability: null, state: 'online', reason: 'reconnected' }], 'host_offline');
    await this.evaluate(hostId);
  }

  // hostId's last socket closed (a replaced one does not call this). A host
  // retired in the last window is ignored: its socket closes after the
  // retire dropped it.
  onDisconnect(hostId) {
    if (this.retired.has(hostId)) return;
    this.hosts.set(hostId, { disconnectedAt: this.now() });
  }

  // A retired host leaves every alert structure.
  dropHost(hostId) {
    this.hosts.delete(hostId);
    this.retired.set(hostId, this.now());
    this.opens.delete(hostId);
    const prefix = alertKey(hostId, '');
    for (const set of [this.suppressedWebhooks, this.capped]) {
      for (const key of [...set]) if (key.startsWith(prefix)) set.delete(key);
    }
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
      // The host leaves memory once the open is written (the registry may
      // still find it online elsewhere and open nothing); a failed or capped
      // open is tried again next tick. A reconnect resolves through the
      // database, not this entry.
      const done = await this.open(hostId, { rule: OFFLINE_RULE, capability: null, state: 'offline', reason: 'no_socket' }, 'host_offline', 'critical');
      if (done && this.hosts.get(hostId) === st) this.hosts.delete(hostId);
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
    const n = this.nMs(conn);
    // Resolves are written together; their flags move only once written.
    const resolves = [];
    const resolved = [];
    for (const [name, c] of st.caps) {
      const routable = conn.supports(name);
      if (expected.has(name) && !routable) {
        c.resolveDone = false;
        if (c.since === null) c.since = now;
        if (!c.opened && now - c.since >= 2 * n) {
          const r = conn.reported.get(name);
          const state = r && r.state !== 'ok' ? r.state : 'degraded';
          const reason = conn.unsupportedReason(name) || (r && r.reason) || 'probe_error';
          if (await this.open(hostId, { rule: capabilityRule(name), capability: name, state, reason }, 'capability_alert', 'warning')) {
            c.opened = true;
          }
        }
        continue;
      }
      c.since = null;
      if (!c.resolveDone && (c.okStreak >= 2 || !expected.has(name))) {
        resolves.push({ rule: capabilityRule(name), capability: name, state: routable ? 'ok' : 'not_expected', reason: '' });
        resolved.push(() => { c.resolveDone = true; c.opened = false; });
      }
    }
    if (!st.reportsOpened && now - st.lastReportAt >= 3 * n) {
      if (await this.open(hostId, { rule: REPORTS_RULE, capability: null, state: 'unknown', reason: 'report_missing' }, 'capability_alert', 'warning')) {
        st.reportsOpened = true;
        st.reportsBase = st.reports;
        st.reportsResolveDone = false;
      }
    } else if (!st.reportsResolveDone && st.reports - st.reportsBase >= 2) {
      resolves.push({ rule: REPORTS_RULE, capability: null, state: 'ok', reason: '' });
      resolved.push(() => { st.reportsResolveDone = true; st.reportsOpened = false; });
    }
    if (resolves.length > 0) {
      await this.resolve(hostId, resolves, 'capability_alert');
      for (const done of resolved) done();
    }
    await this.setHealth(hostId, st, hostHealth({ connected, conn, expected: [...expected] }));
  }

  // The tick: every tracked host once, never two ticks at a time. A host's
  // failure is logged and the walk goes on.
  async tick() {
    if (this.ticking) return;
    this.ticking = true;
    try {
      this.prune();
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

  // Old retire marks and open times leave memory.
  prune() {
    const now = this.now();
    for (const [hostId, at] of this.retired) if (now - at >= 2 * this.offlineAfterMs) this.retired.delete(hostId);
    for (const [hostId, times] of this.opens) {
      const live = times.filter((t) => now - t < OPEN_WINDOW_MS);
      if (live.length === 0) this.opens.delete(hostId);
      else this.opens.set(hostId, live);
    }
  }

  // The health row is written only while this instance holds the host's
  // presence row; a refused write is tried again at the next evaluation.
  async setHealth(hostId, st, health) {
    if (st.health === health) return;
    const reg = this.fleet.registry;
    if (!reg || typeof reg.setHostHealth !== 'function') return;
    const instance = typeof this.fleet.instanceId === 'function' ? this.fleet.instanceId() : null;
    if (await reg.setHostHealth(hostId, health, instance)) st.health = health;
  }

  webhookBody(type, status, row, hostId, a) {
    return {
      type, status, rule: a.rule, alert_id: row.id, host_id: hostId,
      capability: a.capability, state: a.state, reason: a.reason, ts: new Date(this.now()).toISOString()
    };
  }

  // True once the open is settled in the database (a row written, or one
  // already active for this host and rule, or the host gone); false when
  // the hourly cap held it back. Throws when the write failed.
  async open(hostId, a, type, severity) {
    const reg = this.fleet.registry;
    if (!reg || typeof reg.openHostAlert !== 'function') return true;
    const key = alertKey(hostId, a.rule);
    const now = this.now();
    const times = (this.opens.get(hostId) || []).filter((t) => now - t < OPEN_WINDOW_MS);
    if (times.length >= this.opensPerHourMax) {
      if (!this.capped.has(key)) {
        this.capped.add(key);
        this.cappedTotal += 1;
        if (typeof this.fleet.noteAlertCapped === 'function') this.fleet.noteAlertCapped(a.rule);
        console.warn(`[alerts] capability alert held back host=${hostId} rule=${a.rule} (over ${this.opensPerHourMax} per hour)`);
      }
      return false;
    }
    const message = a.capability ? `${a.capability} ${a.state}${a.reason ? ` (${a.reason})` : ''}` : `${a.rule} ${a.reason}`;
    const row = await reg.openHostAlert({ host_id: hostId, rule_name: a.rule, severity, message, actor: ACTOR, audit: a });
    this.capped.delete(key);
    if (!row) return true;
    times.push(now);
    this.opens.set(hostId, times);
    const sent = await this.fleet.deliverAlertWebhook(row.tenant_id, a.rule, hostId, this.webhookBody(type, 'open', row, hostId, a), true);
    if (sent === false) this.suppressedWebhooks.add(key);
    else this.suppressedWebhooks.delete(key);
    return true;
  }

  async resolve(hostId, list, type) {
    const reg = this.fleet.registry;
    if (!reg || typeof reg.resolveHostAlerts !== 'function') return;
    const rows = await reg.resolveHostAlerts(hostId, list, ACTOR);
    for (const row of rows) {
      const a = list.find((x) => x.rule === row.rule_name);
      const key = alertKey(hostId, a.rule);
      this.capped.delete(key);
      // Its open went out without a webhook (cooldown): so does the resolve.
      if (this.suppressedWebhooks.delete(key)) continue;
      await this.fleet.deliverAlertWebhook(row.tenant_id, a.rule, hostId, this.webhookBody(type, 'resolved', row, hostId, a), false);
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
  OPENS_PER_HOUR_MAX,
  DEFAULT_INTERVAL_S,
  MIN_INTERVAL_S,
  MAX_INTERVAL_S
};
