'use strict';

// The software inventory an agent sends with its telemetry
// (systemapi-agent/telemetry.go): the full installed-package list on every
// 5 s tick, rescanned every 5 minutes. normalizeSoftwareInventory bounds it,
// dedupes it on the cp_software key (host_id, name, version) and returns a
// digest, so the fleet writes a list once when it changes (and once per
// SOFTWARE_REFRESH_MS to keep last_detected_at current), in one statement.
//
// Threats: an agent (or a stolen agent key) sending an oversized list or
// oversized fields to make the control plane do unbounded work or store
// unbounded rows: a list over SOFTWARE_MAX_ITEMS is refused whole (throws,
// nothing stored), an item with a field over SOFTWARE_FIELD_MAX is skipped
// and counted, and the fleet writes a host at most once per
// SOFTWARE_MIN_WRITE_GAP_MS however often its list changes (so the rows and
// CVE lookups one host can cause are bounded per hour, not per report).
// Text PostgreSQL cannot store (NUL) or that node-pg would fold into a
// duplicate key (lone UTF-16 surrogates) is cleaned first, so one odd package
// cannot fail the whole statement. Non-string fields take the
// defaults. Does NOT judge whether the packages are real: the host's own
// report is taken as is.

const crypto = require('node:crypto');

const SOFTWARE_MAX_ITEMS = 20000;
const SOFTWARE_FIELD_MAX = 256;
const SOFTWARE_REFRESH_MS = 60 * 60 * 1000;
// The least time between two writes for one host, even when its list
// changed; the agent rescans every 5 minutes, so an honest host loses nothing.
const SOFTWARE_MIN_WRITE_GAP_MS = 60 * 1000;
// After a failed write (or a refused list) a host waits this long.
const SOFTWARE_RETRY_MS = 5 * 60 * 1000;
// Inventory writes running at once across all hosts; a report over it waits
// for a later tick, so inventory never takes the pool from API traffic.
const SOFTWARE_MAX_CONCURRENT = 2;

// Returns the cleaned string, the fallback for a missing or non-string value,
// or undefined when it is over the length limit.
function field(v, fallback) {
  if (typeof v !== 'string') return fallback;
  const s = v.replace(/\u0000/g, '').toWellFormed();
  if (s === '') return fallback;
  return s.length > SOFTWARE_FIELD_MAX ? undefined : s;
}

// Returns { items: [{name, version, architecture}], digest, skipped } with one
// item per (name, version), the first one sent winning, sorted so the digest
// does not depend on the agent's order. Throws on a list over the item limit.
function normalizeSoftwareInventory(list) {
  if (!Array.isArray(list)) throw new Error('software inventory: not a list');
  if (list.length > SOFTWARE_MAX_ITEMS) throw new Error(`software inventory: ${list.length} items, over ${SOFTWARE_MAX_ITEMS}`);
  const byKey = new Map();
  let skipped = 0;
  for (const sw of list) {
    if (!sw || typeof sw !== 'object') continue;
    const name = field(sw.name, 'unknown');
    const version = field(sw.version, 'unknown');
    const architecture = field(sw.architecture, '');
    if (name === undefined || version === undefined || architecture === undefined) { skipped += 1; continue; }
    const key = JSON.stringify([name, version]);
    if (!byKey.has(key)) byKey.set(key, { name, version, architecture });
  }
  const items = [...byKey.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map((e) => e[1]);
  const digest = crypto.createHash('sha256').update(JSON.stringify(items)).digest('hex');
  return { items, digest, skipped };
}

module.exports = {
  normalizeSoftwareInventory,
  SOFTWARE_MAX_ITEMS,
  SOFTWARE_FIELD_MAX,
  SOFTWARE_REFRESH_MS,
  SOFTWARE_MIN_WRITE_GAP_MS,
  SOFTWARE_RETRY_MS,
  SOFTWARE_MAX_CONCURRENT
};
