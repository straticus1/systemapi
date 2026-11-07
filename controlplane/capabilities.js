'use strict';

// Agent capability health (plan sah-fleet-readiness P1b), the pure part: the
// capability_report frame validator, the per-connection routing state, the
// expected set derived from a host's channel policy, and the host health.
// playground/fleet.js owns the sockets, the rate limits and the storage.
//
// Wire contract (systemapi-agent): X-SystemAPI-Capabilities names what the
// binary supports; X-SystemAPI-Capabilities-Degraded names the supported ones
// whose probe failed at dial; the agent then sends
// {"type":"capability_report","v":1,"probed_at":RFC3339,"caps":[{name,state,reason}],
// "interval_s":<its --capability-interval in seconds, 60..3600>}
// after enroll, every cycle and on a capability_probe. interval_s is
// optional (older agents omit it); present, it must be an integer in range.
//
// Threats: an agent (or a stolen agent key) sending reports to make the
// control plane do unbounded work, store unbounded or arbitrary text, or
// widen what the server routes to it. A report is validated whole before any
// DB work: at most REPORT_MAX_BYTES and REPORT_MAX_ENTRIES, names from the
// fixed KNOWN_CAPABILITIES list (others dropped), states and reasons from
// fixed sets (anything else refuses the whole frame), so no path, unit body or
// raw error text is ever stored. A report can only withdraw a capability from
// routing, never add one the dial header did not advertise; sysscript_jobs and
// converge follow the header only. Health is self-reported: it detects
// breakage, NOT compromise (a compromised agent can report every capability
// ok, or withhold reports). It does NOT rate-limit (fleet.js does).

const REPORT_VERSION = 1;
const REPORT_MAX_BYTES = 8 * 1024;
const REPORT_MAX_ENTRIES = 16;
// The agent's --capability-interval range, in seconds.
const REPORT_INTERVAL_MIN_S = 60;
const REPORT_INTERVAL_MAX_S = 3600;

const KNOWN_CAPABILITIES = Object.freeze([
  'pty', 'file', 'tcp', 'xfer', 'service', 'config', 'package', 'tweak',
  'sysscript_jobs', 'converge', 'config_write', 'sysctl_write', 'override_write', 'intent_v1'
]);
const KNOWN = new Set(KNOWN_CAPABILITIES);
const CAPABILITY_STATES = new Set(['ok', 'degraded', 'absent']);
const CAPABILITY_REASONS = new Set([
  'enosys_openat2', 'binary_missing', 'helper_unit_missing', 'helper_trust_missing',
  'manager_unreachable', 'flag_off', 'unsupported_os', 'no_systemd', 'probe_error'
]);
// Job routing, the converge claim gate and the presence row read these from
// the dial header; a report or the degraded header never withdraws them.
// intent_v1 (the agent verifies systemapi-lease-v2) is a property of the
// binary, so it follows the header too.
const HEADER_ONLY = new Set(['sysscript_jobs', 'converge', 'intent_v1']);
// The sys write tokens (P1a). An agent that advertises none of them is an old
// agent: its writes gate on config/tweak as before.
const WRITE_CAPABILITIES = Object.freeze(['config_write', 'sysctl_write', 'override_write']);
// The reason a write token missing from a new agent's header answers with
// when no report names a better one.
const WRITE_MISSING_REASON = 'helper_unit_missing';
// The reason for a capability withdrawn by the degraded header before any
// report carried its real reason.
const DIAL_DEGRADED_REASON = 'probe_error';

const PROBED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

function refuse(error) {
  return { ok: false, error };
}

// validateCapabilityReport checks a parsed capability_report frame of
// `bytes` bytes. Returns { ok: true, report: { probedAt, caps, intervalS },
// dropped } (intervalS null when the frame has none)
// (dropped = entries with an unknown name, ignored) or { ok: false, error }
// with a fixed error code. Nothing from a refused frame is used.
function validateCapabilityReport(msg, bytes) {
  if (!Number.isInteger(bytes) || bytes > REPORT_MAX_BYTES) return refuse('too_large');
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return refuse('bad_frame');
  if (msg.v !== REPORT_VERSION) return refuse('bad_version');
  if (typeof msg.probed_at !== 'string' || !PROBED_AT_RE.test(msg.probed_at)) return refuse('bad_probed_at');
  const probedMs = Date.parse(msg.probed_at);
  if (!Number.isFinite(probedMs)) return refuse('bad_probed_at');
  let intervalS = null;
  if (msg.interval_s !== undefined) {
    const n = msg.interval_s;
    if (!Number.isInteger(n) || n < REPORT_INTERVAL_MIN_S || n > REPORT_INTERVAL_MAX_S) return refuse('bad_interval');
    intervalS = n;
  }
  if (!Array.isArray(msg.caps)) return refuse('bad_caps');
  if (msg.caps.length > REPORT_MAX_ENTRIES) return refuse('too_many');
  const caps = [];
  const seen = new Set();
  let dropped = 0;
  for (const c of msg.caps) {
    if (!c || typeof c !== 'object' || Array.isArray(c) || typeof c.name !== 'string') return refuse('bad_entry');
    if (!KNOWN.has(c.name)) {
      dropped += 1;
      continue;
    }
    if (seen.has(c.name)) return refuse('duplicate');
    seen.add(c.name);
    if (!CAPABILITY_STATES.has(c.state)) return refuse('bad_state');
    const reason = c.reason === undefined ? '' : c.reason;
    if (typeof reason !== 'string') return refuse('bad_reason');
    if (c.state === 'ok' && reason !== '') return refuse('bad_reason');
    if (reason !== '' && !CAPABILITY_REASONS.has(reason)) return refuse('bad_reason');
    caps.push({ name: c.name, state: c.state, reason });
  }
  return { ok: true, report: { probedAt: new Date(probedMs).toISOString(), caps, intervalS }, dropped };
}

// The capability state of one agent connection. supported is the dial
// header; the degraded header seeds the routing withdrawals; each accepted
// report updates them per name (a name missing from a report keeps its
// state). Reports are kept for every known name, in the header or not, for
// health.
class ConnectionCapabilities {
  constructor(supported, degraded) {
    this.supported = new Set(supported || []);
    // name -> reason ('' when the degraded header named it).
    this.withdrawn = new Map();
    for (const name of degraded || []) {
      if (this.supported.has(name) && !HEADER_ONLY.has(name)) this.withdrawn.set(name, '');
    }
    this.reported = new Map();
    this.reportCount = 0;
    this.lastReportAt = null;
    this.probedAt = null;
    // The agent's report interval from its latest report (null: none sent,
    // an older agent; the alert rules then use the control plane's N).
    this.intervalS = null;
  }

  applyReport(report, nowMs = Date.now()) {
    for (const c of report.caps) {
      this.reported.set(c.name, { state: c.state, reason: c.reason });
      if (!this.supported.has(c.name) || HEADER_ONLY.has(c.name)) continue;
      if (c.state === 'ok') this.withdrawn.delete(c.name);
      else this.withdrawn.set(c.name, c.reason);
    }
    this.reportCount += 1;
    this.lastReportAt = nowMs;
    this.probedAt = report.probedAt;
    this.intervalS = Number.isInteger(report.intervalS) ? report.intervalS : null;
  }

  // An agent that advertises any *_write token is a new agent.
  newAgent() {
    return WRITE_CAPABILITIES.some((name) => this.supported.has(name));
  }

  supports(name) {
    return this.supported.has(name) && !this.withdrawn.has(name);
  }

  effective() {
    return [...this.supported].filter((name) => this.supports(name)).sort();
  }

  // The reason code a refused capability answers with, or null when there is
  // none to give (a capability the agent never advertised, as before).
  unsupportedReason(name) {
    if (this.withdrawn.has(name)) {
      const reason = this.withdrawn.get(name);
      if (reason) return reason;
      // Withdrawn by the degraded header alone: a write token there means
      // its helper is missing (the agent probes the helper unit), not a
      // probe failure.
      return WRITE_CAPABILITIES.includes(name) ? WRITE_MISSING_REASON : DIAL_DEGRADED_REASON;
    }
    if (this.supported.has(name)) return null;
    if (WRITE_CAPABILITIES.includes(name) && this.newAgent()) {
      const r = this.reported.get(name);
      return r && r.state !== 'ok' && r.reason ? r.reason : WRITE_MISSING_REASON;
    }
    return null;
  }
}

// expectedCapabilities: the capabilities a host's effective channel policy
// (controlplane/channels.js effectivePolicies) needs to work. A malformed
// policy (null, deny-all) expects nothing.
function expectedCapabilities(policies) {
  const p = policies || {};
  const out = new Set();
  if (p.file && Array.isArray(p.file.roots) && p.file.roots.length > 0) {
    out.add('file');
    if (p.file.roots.some((r) => r && r.write === true)) out.add('xfer');
  }
  if (p.config && Array.isArray(p.config.paths) && p.config.paths.length > 0) {
    out.add('config');
    out.add('config_write');
  }
  // A config reload acts on a unit of the service allowlist.
  if (p.service && Array.isArray(p.service.units) && p.service.units.length > 0) out.add('service');
  if (p.tweak && Array.isArray(p.tweak.sysctls) && p.tweak.sysctls.length > 0) {
    out.add('tweak');
    out.add('sysctl_write');
  }
  if (p.tweak && Array.isArray(p.tweak.units) && p.tweak.units.length > 0) {
    out.add('tweak');
    out.add('override_write');
  }
  if (p.package && Array.isArray(p.package.names) && p.package.names.length > 0) out.add('package');
  if (p.tcp && Array.isArray(p.tcp.allow) && p.tcp.allow.length > 0) out.add('tcp');
  return [...out].sort();
}

// hostHealth: offline (no socket), unknown (connected, no report on this
// connection: old agents, reports switched off), degraded (an expected
// capability is not routable), else ok.
function hostHealth({ connected, conn, expected }) {
  if (!connected) return 'offline';
  if (!conn || conn.reportCount === 0) return 'unknown';
  return (expected || []).every((name) => conn.supports(name)) ? 'ok' : 'degraded';
}

module.exports = {
  REPORT_VERSION,
  REPORT_MAX_BYTES,
  REPORT_MAX_ENTRIES,
  REPORT_INTERVAL_MIN_S,
  REPORT_INTERVAL_MAX_S,
  KNOWN_CAPABILITIES,
  CAPABILITY_STATES,
  CAPABILITY_REASONS,
  HEADER_ONLY,
  WRITE_CAPABILITIES,
  WRITE_MISSING_REASON,
  DIAL_DEGRADED_REASON,
  validateCapabilityReport,
  ConnectionCapabilities,
  expectedCapabilities,
  hostHealth
};
