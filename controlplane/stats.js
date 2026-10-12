// Threats: none cryptographic. Statistical helpers only. Z-score is not a
// machine-learning model. Forecast is linear least squares. No invented prices.
'use strict';

function zscore(values) {
  if (!Array.isArray(values) || values.length < 9) {
    return { anomalous: false, z: 0, reason: 'insufficient' };
  }
  const current = values[values.length - 1];
  const base = values.slice(0, -1);
  if (base.length < 8) return { anomalous: false, z: 0, reason: 'insufficient' };
  const mean = base.reduce((sum, n) => sum + n, 0) / base.length;
  const variance = base.reduce((sum, n) => sum + (n - mean) ** 2, 0) / base.length;
  const stdev = Math.sqrt(variance);
  if (stdev === 0) return { anomalous: false, z: 0, reason: 'flat' };
  const z = (current - mean) / stdev;
  return { anomalous: Math.abs(z) >= 3, z, mean, stdev };
}

function linearForecast(values, ahead = 1) {
  if (!Array.isArray(values) || values.length < 2) return null;
  const n = values.length;
  let sumX = 0;
  let sumY = 0;
  let sumXY = 0;
  let sumXX = 0;
  for (let i = 0; i < n; i++) {
    sumX += i;
    sumY += values[i];
    sumXY += i * values[i];
    sumXX += i * i;
  }
  const denom = n * sumXX - sumX * sumX;
  if (denom === 0) return values[n - 1];
  const slope = (n * sumXY - sumX * sumY) / denom;
  const intercept = (sumY - slope * sumX) / n;
  return intercept + slope * (n - 1 + ahead);
}

function efficiency(hosts) {
  const idle = [];
  for (const host of hosts) {
    const cpu = host.cpu_avg;
    const mem = host.mem_avg;
    if (typeof cpu === 'number' && typeof mem === 'number' && cpu < 10 && mem < 20) {
      idle.push({ host_id: host.host_id, hostname: host.hostname, cpu_avg: cpu, mem_avg: mem });
    }
  }
  return { idle_hosts: idle, idle_count: idle.length, host_count: hosts.length };
}

function fieldMatch(field, value, min, max) {
  if (field === '*') return value >= min && value <= max;
  for (const part of field.split(',')) {
    const step = part.match(/^\*\/(\d+)$/);
    if (step) {
      const n = Number(step[1]);
      if (n > 0 && value % n === 0) return true;
      continue;
    }
    const range = part.match(/^(\d+)-(\d+)$/);
    if (range) {
      const a = Number(range[1]);
      const b = Number(range[2]);
      if (value >= a && value <= b) return true;
      continue;
    }
    if (/^\d+$/.test(part) && Number(part) === value) return true;
  }
  return false;
}

function fieldValid(field, min, max) {
  if (field === '*') return true;
  return field.split(',').every((part) => {
    const step = part.match(/^\*\/(\d+)$/);
    if (step) {
      const n = Number(step[1]);
      return n > 0 && n <= max;
    }
    const range = part.match(/^(\d+)-(\d+)$/);
    if (range) {
      const a = Number(range[1]);
      const b = Number(range[2]);
      return a >= min && b <= max && a <= b;
    }
    if (/^\d+$/.test(part)) {
      const n = Number(part);
      return n >= min && n <= max;
    }
    return false;
  });
}

function cronValid(expr) {
  if (typeof expr !== 'string') return false;
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const limits = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 6]];
  return parts.every((field, i) => fieldValid(field, limits[i][0], limits[i][1]));
}

function cronMatches(expr, date) {
  if (!cronValid(expr)) return false;
  const parts = expr.trim().split(/\s+/);
  const minute = date.getUTCMinutes();
  const hour = date.getUTCHours();
  const dom = date.getUTCDate();
  const month = date.getUTCMonth() + 1;
  const dow = date.getUTCDay();
  return fieldMatch(parts[0], minute, 0, 59)
    && fieldMatch(parts[1], hour, 0, 23)
    && fieldMatch(parts[2], dom, 1, 31)
    && fieldMatch(parts[3], month, 1, 12)
    && fieldMatch(parts[4], dow, 0, 6);
}

function csvCell(value) {
  let text = value == null ? '' : String(value);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  if (/[",\n]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

function toCSV(rows, columns) {
  const head = columns.map(csvCell).join(',');
  const body = rows.map((row) => columns.map((col) => csvCell(row[col])).join(','));
  return [head, ...body].join('\n');
}

function escapeLike(text) {
  return String(text).replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

const BUCKETS = Object.freeze({ minute: 'minute', hour: 'hour', day: 'day' });

function bucketName(name) {
  return BUCKETS[name] || null;
}

module.exports = {
  zscore,
  linearForecast,
  efficiency,
  fieldMatch,
  fieldValid,
  cronValid,
  cronMatches,
  csvCell,
  toCSV,
  escapeLike,
  bucketName
};
