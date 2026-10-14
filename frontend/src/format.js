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
