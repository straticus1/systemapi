#!/usr/bin/env node
// Threats: API key theft via argv, query strings, redirects, or logs.
// The key is read from the environment and sent only as X-API-Key.
// Does NOT follow redirects, accept the key on argv, or run a shell.
// SYSTEMAPI_TENANT is optional and is neither sent nor printed.
// A missing URL or key exits 2 and does not echo the value.
// login is the exception: it does not read or send the API key. It writes
// the access token to an absolute SYSTEMAPI_TOKEN_FILE (mode 0600) and
// prints only the verification URI and the user code (typed in the browser
// after After Dark SSO), then "approved" and that path.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SCRIPT_MAX = 64 * 1024;
const BODY_MAX = 1024 * 1024;
const HOST_RE = /^[A-Za-z0-9._:-]{1,256}$/;

class Exit extends Error {
  constructor(code, message) {
    super(message);
    this.exitCode = code;
  }
}

function usage() {
  return [
    'usage: systemapi.js <command>',
    '  hosts',
    '  exec --host <id> --script-file <path>',
    '  metrics --host <id>',
    '  audit',
    '  breakglass-ticket --host <id>',
    '  host-json --host <id>',
    '  login <username>'
  ].join('\n');
}

function fail(code, message) {
  throw new Exit(code, message);
}

function controlUrl() {
  const rawUrl = process.env.SYSTEMAPI_URL;
  const urlText = typeof rawUrl === 'string' ? rawUrl.trim() : '';
  if (!urlText) fail(2, 'missing SYSTEMAPI_URL');
  let url;
  try {
    url = new URL(urlText.replace(/\/$/, ''));
  } catch {
    fail(2, 'invalid SYSTEMAPI_URL');
  }
  const queryKey = url.searchParams.has('api_key') || url.searchParams.has('api-key');
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password || queryKey) {
    fail(2, 'invalid SYSTEMAPI_URL');
  }
  url.search = '';
  url.hash = '';
  if (url.pathname.length > 1 && url.pathname.endsWith('/')) url.pathname = url.pathname.slice(0, -1);
  return url;
}

function loadConfig() {
  const rawUrl = process.env.SYSTEMAPI_URL;
  const key = process.env.SYSTEMAPI_API_KEY;
  const missing = [];
  const urlText = typeof rawUrl === 'string' ? rawUrl.trim() : '';
  if (!urlText) missing.push('SYSTEMAPI_URL');
  if (typeof key !== 'string' || key.trim() === '') missing.push('SYSTEMAPI_API_KEY');
  if (missing.length) fail(2, 'missing ' + missing.join(', '));
  return { url: controlUrl(), key };
}

function containsKey(text, key) {
  return Boolean(key && key.length >= 8 && typeof text === 'string' && text.includes(key));
}

function visible(text, key) {
  if (typeof text !== 'string' || containsKey(text, key)) fail(1, 'request_failed');
  return text;
}

function parseArgs(argv) {
  const opts = { host: '', scriptFile: '' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg !== '--host' && arg !== '--script-file') fail(2, usage());
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) fail(2, 'missing value for ' + arg);
    i += 1;
    if (arg === '--host') {
      if (opts.host) fail(2, usage());
      opts.host = value;
    } else {
      if (opts.scriptFile) fail(2, usage());
      opts.scriptFile = value;
    }
  }
  return opts;
}

function requireHost(id) {
  if (!HOST_RE.test(id) || id === '.' || id.includes('..')) fail(2, 'invalid --host');
  return id;
}

async function readLimited(res) {
  if (!res.body) return '';
  const chunks = [];
  let total = 0;
  for await (const chunk of res.body) {
    const buf = Buffer.from(chunk);
    total += buf.length;
    if (total > BODY_MAX) fail(1, 'response_too_large');
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function request(cfg, method, pathname, body) {
  const url = new URL(cfg.url.href);
  const prefix = url.pathname === '/' ? '' : url.pathname;
  url.pathname = prefix + pathname;
  url.search = '';
  url.hash = '';
  const headers = {
    Accept: 'application/json',
    'X-API-Key': cfg.key
  };
  const timeout = method === 'POST' && pathname.endsWith('/execute') ? 45000 : 20000;
  const init = {
    method,
    headers,
    redirect: 'error',
    cache: 'no-store',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(timeout)
  };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch {
    fail(1, 'request_failed');
  }
  const text = await readLimited(res);
  let parsed = null;
  if (text.trim()) {
    try {
      parsed = JSON.parse(text);
    } catch {
      fail(1, 'bad_response');
    }
  }
  return { status: res.status, parsed };
}

async function requestPublic(base, method, pathname, body) {
  const url = new URL(base.href);
  const prefix = url.pathname === '/' ? '' : url.pathname;
  url.pathname = prefix + pathname;
  url.search = '';
  url.hash = '';
  const headers = { Accept: 'application/json' };
  const init = {
    method,
    headers,
    redirect: 'error',
    cache: 'no-store',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(20000)
  };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch {
    fail(1, 'login_failed');
  }
  const text = await readLimited(res);
  let parsed = null;
  if (text.trim()) {
    try {
      parsed = JSON.parse(text);
    } catch {
      fail(1, 'login_failed');
    }
  }
  return { status: res.status, parsed };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function writeTokenFile(file, token) {
  if (typeof token !== 'string' || token.length < 16 || token.length > 512 || /[\r\n\0]/.test(token)) {
    fail(1, 'login_failed');
  }
  const flags = fs.constants.O_NOFOLLOW | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_WRONLY;
  let fd;
  try {
    fd = fs.openSync(file, flags, 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, token + '\n', { encoding: 'utf8' });
  } catch (err) {
    if (err instanceof Exit) throw err;
    fail(1, 'token_file_rejected');
  } finally {
    if (typeof fd === 'number') {
      try { fs.closeSync(fd); } catch { /* already closed */ }
    }
  }
}

async function login(argv) {
  if (argv.length !== 1) fail(2, usage());
  const username = argv[0];
  const base = controlUrl();
  const tokenFile = process.env.SYSTEMAPI_TOKEN_FILE;
  if (typeof tokenFile !== 'string' || !path.isAbsolute(tokenFile)) fail(2, 'token_file_rejected');
  const started = await requestPublic(base, 'POST', '/oauth/device', { username });
  if (started.status === 429) fail(1, 'slow_down');
  if (started.status !== 200) fail(1, started.status === 403 ? 'login_denied' : 'login_failed');
  const device = started.parsed && started.parsed.device_code;
  const verification = started.parsed && started.parsed.verification_uri;
  const userCode = started.parsed && started.parsed.user_code;
  const interval = started.parsed && started.parsed.interval;
  let verifyUrl;
  try {
    verifyUrl = new URL(verification);
  } catch {
    fail(1, 'login_failed');
  }
  if (verifyUrl.origin !== base.origin || verifyUrl.username || verifyUrl.password || verifyUrl.search || verifyUrl.hash) {
    fail(1, 'login_failed');
  }
  if (typeof userCode !== 'string' || !/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/.test(userCode)) fail(1, 'login_failed');
  if (typeof device !== 'string' || device.length < 16) fail(1, 'login_failed');
  await write(process.stdout, verifyUrl.href + '\n' + userCode + '\n');
  const pause = typeof interval === 'number' && interval > 0 ? Math.min(interval * 1000, 10000) : 100;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    await sleep(pause);
    const polled = await requestPublic(base, 'POST', '/oauth/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: device
    });
    const err = polled.parsed && polled.parsed.error;
    if (err === 'authorization_pending' || err === 'slow_down') continue;
    if (polled.status >= 400) fail(1, 'login_denied');
    const token = polled.parsed && polled.parsed.access_token;
    writeTokenFile(tokenFile, token);
    await write(process.stdout, 'approved\n' + tokenFile + '\n');
    return;
  }
  fail(1, 'login_denied');
}

function errorText(parsed, key) {
  const err = parsed && typeof parsed.error === 'string' && parsed.error ? parsed.error : 'request_failed';
  return visible(err, key);
}

function cell(value) {
  if (value == null) return '';
  return String(value).replace(/[\t\r\n]/g, ' ');
}

function asString(value) {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  fail(1, 'bad_response');
}

function hostsFrom(parsed) {
  if (!parsed || !Array.isArray(parsed.hosts)) fail(1, 'bad_response');
  return parsed.hosts;
}

function readScript(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
  } catch (err) {
    if (err && err.code === 'ENOENT') fail(1, 'script file missing');
    fail(1, 'script file unreadable');
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) fail(1, 'script file missing');
    if (stat.size > SCRIPT_MAX) fail(1, 'script file larger than 64 KiB');
    const buf = Buffer.alloc(SCRIPT_MAX + 1);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    if (n > SCRIPT_MAX) fail(1, 'script file larger than 64 KiB');
    return buf.subarray(0, n).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function execText(parsed, key) {
  const result = parsed && parsed.result;
  if (result && typeof result === 'object') {
    const output = typeof result.output === 'string' ? result.output : null;
    const error = typeof result.error === 'string' ? result.error : '';
    if (output != null && output.length > 0) return visible(output, key);
    if (error.length > 0) return visible(error, key);
    if (output != null) return visible(output, key);
  }
  if (parsed && typeof parsed.error === 'string' && parsed.error) return visible(parsed.error, key);
  return '';
}

function write(stream, text) {
  return new Promise((resolve, reject) => {
    stream.write(text, (err) => (err ? reject(err) : resolve()));
  });
}

async function emit(text, key) {
  if (containsKey(text, key)) fail(1, 'request_failed');
  await write(process.stdout, text);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const known = new Set(['hosts', 'exec', 'metrics', 'audit', 'breakglass-ticket', 'host-json', 'login']);
  if (!cmd || !known.has(cmd)) fail(2, usage());
  if (cmd === 'login') {
    await login(argv.slice(1));
    return;
  }
  const opts = parseArgs(argv.slice(1));
  if (cmd === 'exec') {
    if (!opts.host || !opts.scriptFile) fail(2, usage());
  } else if (cmd === 'metrics' || cmd === 'breakglass-ticket' || cmd === 'host-json') {
    if (!opts.host || opts.scriptFile) fail(2, usage());
  } else if (opts.host || opts.scriptFile) {
    fail(2, usage());
  }

  const cfg = loadConfig();
  if (cmd === 'hosts') {
    const { status, parsed } = await request(cfg, 'GET', '/api/v1/fleet');
    if (status >= 400) fail(1, errorText(parsed, cfg.key));
    const lines = hostsFrom(parsed).map((host) => {
      return [host.host_id, host.hostname, host.status, host.os].map(cell).join('\t');
    });
    await emit(lines.length ? lines.join('\n') + '\n' : '', cfg.key);
    return;
  }

  if (cmd === 'exec') {
    const host = requireHost(opts.host);
    const script = readScript(opts.scriptFile);
    const path = '/api/v1/fleet/' + encodeURIComponent(host) + '/execute';
    const { status, parsed } = await request(cfg, 'POST', path, {
      script,
      entitlements: { allow_exec: true }
    });
    if (status >= 400) {
      const msg = errorText(parsed, cfg.key);
      await emit(msg.endsWith('\n') ? msg : msg + '\n', cfg.key);
      process.exitCode = 1;
      return;
    }
    if (!parsed || typeof parsed !== 'object') fail(1, 'bad_response');
    await emit(execText(parsed, cfg.key), cfg.key);
    return;
  }

  if (cmd === 'metrics' || cmd === 'audit') {
    const path = cmd === 'audit'
      ? '/api/v1/audit'
      : '/api/v1/fleet/' + encodeURIComponent(requireHost(opts.host)) + '/metrics';
    const { status, parsed } = await request(cfg, 'GET', path);
    if (status >= 400) fail(1, errorText(parsed, cfg.key));
    if (!parsed || typeof parsed !== 'object') fail(1, 'bad_response');
    await emit(JSON.stringify(parsed) + '\n', cfg.key);
    return;
  }

  if (cmd === 'breakglass-ticket') {
    const host = requireHost(opts.host);
    const { status, parsed } = await request(cfg, 'POST', '/api/v1/ws-ticket', {
      host_id: host,
      purpose: 'breakglass:open'
    });
    if (status >= 400) fail(1, errorText(parsed, cfg.key));
    const ticket = parsed && parsed.ticket;
    const ticketOk = typeof ticket === 'string'
      && /^[A-Za-z0-9_-]{8,512}$/.test(ticket)
      && !containsKey(ticket, cfg.key);
    if (!ticketOk) fail(1, 'bad_ticket');
    await emit(ticket + '\n', cfg.key);
    return;
  }

  const host = requireHost(opts.host);
  const { status, parsed } = await request(cfg, 'GET', '/api/v1/fleet');
  if (status >= 400) fail(1, errorText(parsed, cfg.key));
  const found = hostsFrom(parsed).find((row) => row && row.host_id === host);
  if (!found) fail(1, 'host not found');
  const out = {
    host_id: asString(found.host_id),
    hostname: asString(found.hostname),
    status: asString(found.status)
  };
  await emit(JSON.stringify(out) + '\n', cfg.key);
}

main().catch(async (err) => {
  const code = err instanceof Exit ? err.exitCode : 1;
  const message = err instanceof Exit ? err.message : 'request_failed';
  const text = message.endsWith('\n') ? message : message + '\n';
  try {
    await write(process.stderr, text);
  } catch {
    process.exitCode = code;
    return;
  }
  process.exitCode = code;
});
