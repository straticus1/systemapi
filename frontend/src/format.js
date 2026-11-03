// Pure display helpers. Kept out of the .jsx views so node --test can cover them.

// CPU text for a host card. Only a real cpu.usage_percent sample is shown;
// a host with no sample says so instead of showing 0%.
export function cpuLabel(host) {
  const value = host && host.cpu_percent;
  if (typeof value === 'number' && Number.isFinite(value)) return `${Math.round(value * 10) / 10}%`;
  return host && host.status === 'online' ? 'No data yet' : '-';
}

// Outcome of POST /api/v1/fleet/:id/execute. The agent reports script errors
// inside a 200 response as result.error, so a 200 alone is not success.
export function scriptOutcome(res) {
  const result = (res && res.result) || {};
  if (result.error) return { success: false, data: result.error };
  return { success: true, data: result.output || 'No output returned.' };
}

const termSize = (n) => Math.min(1000, Math.max(1, Number.isFinite(n) ? Math.trunc(n) : 1));

// Terminal WebSocket URL; the initial size rides in the query so the shell
// starts at the viewport size.
export function terminalSocketURL(base, hostId, ticket, rows, cols) {
  return `${base}/api/v1/systems/terminal/${encodeURIComponent(hostId)}?ticket=${encodeURIComponent(ticket)}&rows=${termSize(rows)}&cols=${termSize(cols)}`;
}

// The resize frame to send for a pty_status, or null. "started" resends the
// size because the shell did not exist when "starting" arrived.
export function resizeFrameFor(status, rows, cols) {
  if (status !== 'starting' && status !== 'started') return null;
  return JSON.stringify({ type: 'pty_resize', rows: termSize(rows), cols: termSize(cols) });
}

// A sysscript job is still going in these states (GET /api/v1/jobs/:id).
export function jobActive(status) {
  return status === 'submitted' || status === 'accepted' || status === 'running';
}

// Outcome of a finished job. data is the output (and the error, if any);
// notice explains output the server did not return: hidden from this key
// (only the submitter or a tenant admin sees it), expired, or truncated.
export function jobOutcome(job) {
  const success = !!job && job.status === 'succeeded';
  const error = job && job.error ? job.error : '';
  if (job && job.output_visible === false) {
    return {
      success,
      data: error || (success ? '' : job.status),
      notice: 'Output hidden: only the submitter or an admin of this host\'s tenant can read it.'
    };
  }
  if (job && job.output_expired) {
    return { success, data: error, notice: 'Output expired: it is kept for a limited time after the job ends.' };
  }
  const output = job && typeof job.output === 'string' ? job.output : '';
  const data = [output, error].filter(Boolean).join(output.endsWith('\n') ? '' : '\n')
    || (success ? 'No output returned.' : (job && job.status) || 'failed');
  return { success, data, notice: job && job.output_truncated ? 'Output truncated by the agent.' : '' };
}

// "42s elapsed, 258s to deadline" while a job runs; the deadline part is
// left out when it is unknown, and shows 0s once passed.
export function jobClock(startedMs, deadlineUnix, nowMs) {
  const elapsed = Math.max(0, Math.floor((nowMs - startedMs) / 1000));
  if (typeof deadlineUnix !== 'number') return `${elapsed}s elapsed`;
  const left = Math.max(0, Math.ceil(deadlineUnix - nowMs / 1000));
  return `${elapsed}s elapsed, ${left}s to deadline`;
}

// The control plane's default job ceiling (SYSTEMAPI_SYSSCRIPT_JOB_MAX_S);
// an operator can set it lower or up to 3600.
export const JOB_TIMEOUT_MAX_S = 1800;

// The timeout field's text as whole seconds in 1..max, or null.
export function parseTimeout(text, max = JOB_TIMEOUT_MAX_S) {
  const t = String(text ?? '').trim();
  if (!/^[0-9]{1,6}$/.test(t)) return null;
  const n = Number(t);
  return n >= 1 && n <= max ? n : null;
}

// Readable text for a /jobs error code.
export function jobErrorText(code, max = JOB_TIMEOUT_MAX_S) {
  if (code === 'bad_timeout') {
    return `Timeout must be a whole number of seconds from 1 to ${max}. The control plane may be set to a lower limit.`;
  }
  return code;
}

// What a failed job poll means: 'stop' (it will not get better: signed
// out, no access, gone, or jobs switched off) or 'retry' (later, with
// back-off: network, 429, other 5xx).
export function pollFailure(status) {
  if (status === 401 || status === 403 || status === 404 || status === 503) return 'stop';
  return 'retry';
}

// Host capability health from /api/v1/fleet (plan P1b): ok, degraded,
// unknown (connected, no capability report yet) or offline. Anything else
// shows as unknown.
const HEALTH = {
  ok: { label: 'ok', color: 'var(--accent-green)', background: 'var(--accent-green-soft)' },
  degraded: { label: 'degraded', color: 'var(--accent-amber)', background: 'var(--accent-amber-soft)' },
  unknown: { label: 'unknown', color: 'var(--text-muted)', background: 'rgba(255, 255, 255, 0.05)' },
  offline: { label: 'offline', color: 'var(--text-muted)', background: 'rgba(255, 255, 255, 0.05)' }
};

export function healthBadge(health) {
  const key = Object.prototype.hasOwnProperty.call(HEALTH, health) ? health : 'unknown';
  return { state: key, ...HEALTH[key] };
}

// The expected capabilities that are not routable, with their reason codes,
// from GET /api/v1/hosts/:id/capabilities. One the agent never advertised
// shows as absent, not_supported.
export function degradedCapabilities(detail) {
  if (!detail || !Array.isArray(detail.expected)) return [];
  const effective = new Set(Array.isArray(detail.effective) ? detail.effective : []);
  const supported = new Set(Array.isArray(detail.supported) ? detail.supported : []);
  const caps = Array.isArray(detail.caps) ? detail.caps : [];
  return detail.expected.filter((name) => !effective.has(name)).map((name) => {
    const row = caps.find((c) => c && c.name === name);
    if (row && row.state !== 'ok') return { name, state: row.state, reason: row.reason || '' };
    return supported.has(name) ? { name, state: 'degraded', reason: '' } : { name, state: 'absent', reason: 'not_supported' };
  });
}

// The badge's hover text.
export function healthTitle(health, detail) {
  const { state } = healthBadge(health);
  if (state === 'unknown') return 'Health unknown: the agent has not sent a capability report on this connection.';
  if (state === 'offline') return 'Offline: no agent connection.';
  if (state === 'ok') return 'All expected capabilities ok.';
  const list = degradedCapabilities(detail);
  if (list.length === 0) return 'Degraded.';
  return `Degraded: ${list.map((c) => (c.reason ? `${c.name} (${c.reason})` : c.name)).join(', ')}`;
}
