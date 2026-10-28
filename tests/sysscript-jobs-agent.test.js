'use strict';

// The real Go agent against the real control plane (server.js on
// PostgreSQL), driven only through the public HTTP API
// (.omc/plans/async-sysscript-jobs.md §10, §11). Run with npm run test:agent
// (scripts/test-agent.sh), which builds the agent for Linux, starts
// PostgreSQL and sets:
//   SYSTEMAPI_AGENT_BIN          the Linux agent binary
//   SYSTEMAPI_TEST_DATABASE_URL  the database server.js uses
//   SYSTEMAPI_E2E_RUN            label value on every container started here
//   SYSTEMAPI_E2E_IMAGE          the agent container image
//   SYSTEMAPI_E2E_PROXY_HOST     where the agent container can reach this host
//   SYSTEMAPI_E2E_NETWORK        the docker network the agent container joins
// It fails, not skips, without them. Not part of npm test. E2E_SLACK
// (default 1) multiplies every upper timing bound, for slow or loaded hosts.
//
// Enrollment follows production: scripts/bootstrap-admin.js mints the key,
// the agent reads it from a 0600 root file with --api-key-file, --state and
// --pty-user as in systemd/systemapi-agent.service, and pins the control key
// from its first enroll. The agent dials through a TCP proxy in this process
// that passes bytes unchanged, records each WebSocket message's type and job
// id, and can swallow the agent's bytes or cut the connection.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const WebSocket = require('ws');
const { Pool } = require('pg');

const REPO = path.join(__dirname, '..');
const AGENT_BIN = process.env.SYSTEMAPI_AGENT_BIN;
const DB_URL = process.env.SYSTEMAPI_TEST_DATABASE_URL;
const RUN = process.env.SYSTEMAPI_E2E_RUN;
const IMAGE = process.env.SYSTEMAPI_E2E_IMAGE || 'debian:bookworm-slim';
const PROXY_HOST = process.env.SYSTEMAPI_E2E_PROXY_HOST || '127.0.0.1';
const NETWORK = process.env.SYSTEMAPI_E2E_NETWORK;
const SLACK = Number(process.env.E2E_SLACK || 1);
// An upper timing bound in ms, stretched by E2E_SLACK.
const within = (ms) => ms * SLACK;
const TENANT = 'e2e';
const HOSTNAME = 'e2e-agent';
const ALLOW_EXEC = { allow_exec: true };

const st = {
  server: null,
  serverLog: [],
  port: 0,
  apiKey: null,
  proxy: null,
  container: null,
  hostId: null,
  pool: null,
  pty: null,
  pending: {}
};

// ---------------------------------------------------------------- helpers

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitUntil(what, fn, timeout = 15000, every = 50) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(every);
  }
}

// Runs a command; input goes to stdin. Never rejects: the caller checks code.
function run(cmd, args, { input, env, timeoutMs = 60000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env: env || process.env, stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() });
    });
    child.stdin.end(input === undefined ? '' : input);
  });
}

async function docker(args, opts) {
  const res = await run('docker', args, opts);
  if (res.code !== 0) throw new Error(`docker ${args[0]} failed (${res.code}): ${res.stderr.trim()}`);
  return res.stdout;
}

function exec(script, opts) {
  return docker(['exec', '-i', st.container, 'sh', '-c', script], opts);
}

async function api(method, route, body, { timeoutMs = 60000 } = {}) {
  const started = Date.now();
  const res = await fetch(`http://127.0.0.1:${st.port}${route}`, {
    method,
    headers: { authorization: `Bearer ${st.apiKey}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs)
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, body: json, text, ms: Date.now() - started };
}

function submit(script, extra = {}) {
  return api('POST', `/api/v1/fleet/${encodeURIComponent(st.hostId)}/jobs`,
    { script, entitlements: ALLOW_EXEC, timeout_s: 120, wait_s: 0, ...extra });
}

async function getJob(id) {
  const res = await api('GET', `/api/v1/jobs/${id}`);
  assert.equal(res.status, 200, res.text);
  return res.body.job;
}

async function waitStatus(id, statuses, timeout = 30000) {
  const want = new Set(statuses);
  return waitUntil(`job ${id} in ${statuses.join('|')}`, async () => {
    const job = await getJob(id);
    return want.has(job.status) ? job : null;
  }, timeout, 100);
}

// Processes in the agent container: pid, pgid and argv.
async function processes() {
  const out = await exec('for d in /proc/[0-9]*; do s=$(cat "$d/stat" 2>/dev/null) || continue; '
    + 'c=$(tr "\\000" " " < "$d/cmdline" 2>/dev/null); printf "%s\\t%s\\n" "$s" "$c"; done');
  const rows = [];
  for (const line of out.split('\n')) {
    if (!line) continue;
    const [stat, cmdline = ''] = line.split('\t');
    const tail = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    rows.push({ pid: Number(stat.split(' ')[0]), state: tail[0], pgid: Number(tail[2]), cmd: cmdline.trim() });
  }
  return rows;
}

function agentLog() {
  return exec('cat /var/log/systemapi-agent.log 2>/dev/null || true');
}

// ------------------------------------------------- WebSocket observing proxy

// Parses the WebSocket frames of one direction after the HTTP upgrade and
// calls onMessage({op, payload}) per message (continuations joined).
function wsParser(onMessage) {
  let buf = Buffer.alloc(0);
  let handshake = true;
  let frag = null;
  let fragOp = 0;
  return (chunk) => {
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    if (handshake) {
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return;
      buf = buf.subarray(i + 4);
      handshake = false;
    }
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const op = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        len = Number(buf.readBigUInt64BE(2));
        off = 10;
      }
      const maskAt = off;
      if (masked) off += 4;
      if (buf.length < off + len) return;
      const payload = Buffer.from(buf.subarray(off, off + len));
      if (masked) {
        for (let i = 0; i < payload.length; i++) payload[i] ^= buf[maskAt + (i & 3)];
      }
      buf = buf.subarray(off + len);
      if (op >= 8) {
        onMessage({ op, payload });
        continue;
      }
      if (op !== 0) {
        frag = [payload];
        fragOp = op;
      } else if (frag) {
        frag.push(payload);
      }
      if (fin && frag) {
        onMessage({ op: fragOp, payload: Buffer.concat(frag) });
        frag = null;
      }
    }
  };
}

function startProxy(targetPort) {
  const conns = [];
  const events = [];
  const server = net.createServer((client) => {
    const upstream = net.connect(targetPort, '127.0.0.1');
    const conn = { id: conns.length + 1, client, upstream, held: false, closed: false };
    conns.push(conn);
    const observe = (dir) => wsParser(({ op, payload }) => {
      const ev = { conn: conn.id, dir, op, size: payload.length, at: Date.now(), held: dir === 'up' && conn.held };
      if (op === 1) {
        try {
          const msg = JSON.parse(payload.toString('utf8'));
          ev.type = msg.type;
          ev.job_id = msg.job_id;
          if (msg.type === 'sysscript_job_sync') ev.sync = msg.payload;
          if (msg.type === 'sysscript_job_result') {
            ev.status = msg.payload && msg.payload.status;
            ev.nul = typeof (msg.payload && msg.payload.output) === 'string' && msg.payload.output.includes('\u0000');
          }
        } catch {
          ev.type = 'unparsed';
        }
      }
      if (op === 8) ev.closeCode = payload.length >= 2 ? payload.readUInt16BE(0) : null;
      events.push(ev);
    });
    const up = observe('up');
    const down = observe('down');
    client.on('data', (d) => {
      up(d);
      if (!conn.held) upstream.write(d);
    });
    upstream.on('data', (d) => {
      down(d);
      client.write(d);
    });
    const end = () => {
      conn.closed = true;
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end);
    upstream.on('close', end);
    client.on('error', () => {});
    upstream.on('error', () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, PROXY_HOST, () => resolve({
      port: server.address().port,
      conns,
      events,
      live() {
        return conns.filter((c) => !c.closed);
      },
      find(pred) {
        return events.find(pred);
      },
      close() {
        for (const c of conns) {
          c.client.destroy();
          c.upstream.destroy();
        }
        server.close();
      }
    }));
  });
}

// ------------------------------------------------------------- the pieces

async function freePort() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

async function startServer() {
  st.port = await freePort();
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    ENV_FILE: '/dev/null',
    NODE_ENV: 'development',
    HOST: '127.0.0.1',
    PORT: String(st.port),
    DATABASE_URL: DB_URL,
    SESSION_SECRET: crypto.randomBytes(32).toString('hex'),
    SYSTEMAPI_ED25519_SEED: crypto.randomBytes(32).toString('hex')
  };
  st.server = spawn(process.execPath, ['server.js'], { cwd: REPO, env, stdio: ['ignore', 'pipe', 'pipe'] });
  const keep = (d) => {
    st.serverLog.push(d.toString());
    if (st.serverLog.length > 2000) st.serverLog.splice(0, 1000);
  };
  st.server.stdout.on('data', keep);
  st.server.stderr.on('data', keep);
  await waitUntil('control plane schema', () => st.serverLog.join('').includes('[control] cp schema ready'), 30000);
}

async function mintKey() {
  const res = await run(process.execPath, [path.join(REPO, 'scripts/bootstrap-admin.js'),
    '--tenant', TENANT, '--member', 'e2e-admin', '--key-name', 'e2e-agent'], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ENV_FILE: '/dev/null', DATABASE_URL: DB_URL }
  });
  assert.equal(res.code, 0, `bootstrap-admin failed: ${res.stderr.trim()}`);
  const printed = JSON.parse(res.stdout.trim().split('\n').pop());
  // Never echo the key in an assertion message.
  assert.ok(typeof printed.api_key === 'string' && printed.api_key.startsWith('ak_live_'), 'bootstrap-admin printed no ak_live_ key');
  return printed.api_key;
}

async function startContainer() {
  const name = `systemapi-e2e-agent-${RUN}`;
  await docker(['run', '-d', '--init', '--name', name, '--label', `systemapi-e2e=${RUN}`,
    '--network', NETWORK, '--add-host', 'host.docker.internal:host-gateway', IMAGE, 'sleep', 'infinity']);
  st.container = name;
  await exec('useradd -m -s /bin/sh ops && mkdir -p /etc/systemapi-agent /var/lib/systemapi-agent');
  await exec('umask 077 && cat > /etc/systemapi-agent/api-key', { input: `${st.apiKey}\n` });
  await docker(['cp', AGENT_BIN, `${name}:/usr/local/bin/systemapi-agent`]);
}

// As systemd/systemapi-agent.service, plus --hostname and a log file.
async function startAgent() {
  const url = `ws://host.docker.internal:${st.proxy.port}/api/v1/systems/stream`;
  await docker(['exec', '-d', st.container, 'sh', '-c',
    'echo $$ > /run/systemapi-agent.pid; exec /usr/local/bin/systemapi-agent'
    + ` --server ${url} --tenant ${TENANT} --hostname ${HOSTNAME}`
    + ' --api-key-file /etc/systemapi-agent/api-key --state /var/lib/systemapi-agent/agent.json'
    + ' --pty-user ops >> /var/log/systemapi-agent.log 2>&1']);
}

// The newest proxy connection whose agent sent its sysscript_job_sync.
async function waitSynced(afterConn = 0, timeout = 20000) {
  return waitUntil('agent sync', () => st.proxy.find((e) => e.conn > afterConn && e.type === 'sysscript_job_sync'), timeout);
}

async function openTerminal() {
  const t = await api('POST', '/api/v1/ws-ticket', { purpose: 'terminal:open', host_id: st.hostId });
  assert.equal(t.status, 200, t.text);
  const ws = new WebSocket(`ws://127.0.0.1:${st.port}/api/v1/systems/terminal/${encodeURIComponent(st.hostId)}?ticket=${t.body.ticket}&purpose=terminal:open`);
  const term = { ws, text: '', statuses: [], closed: false };
  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      term.text += data.toString();
      return;
    }
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'pty_status') term.statuses.push(msg.payload);
    } catch {
      term.text += data.toString();
    }
  });
  ws.on('close', () => { term.closed = true; });
  ws.on('error', () => {});
  await waitUntil('terminal started', () => term.statuses.find((s) => s.status === 'started'), 15000);
  return term;
}

// Round trip of one shell command through the PTY, in ms. The marker is
// computed by the shell, so the echoed keystrokes never match it.
async function ptyRoundTrip(term) {
  const n = crypto.randomInt(1000, 9999);
  const marker = `E2E-${n * 2}`;
  const started = Date.now();
  term.ws.send(JSON.stringify({ type: 'pty_input', data: `echo E2E-$((${n}*2))\n` }));
  await waitUntil('pty echo', () => term.text.includes(marker), 10000, 5);
  return Date.now() - started;
}

// ------------------------------------------------------------------ tests

test.before(async () => {
  assert.ok(AGENT_BIN, 'SYSTEMAPI_AGENT_BIN is required (run npm run test:agent)');
  assert.ok(DB_URL, 'SYSTEMAPI_TEST_DATABASE_URL is required (run npm run test:agent)');
  assert.ok(RUN && /^[a-f0-9]{6,32}$/.test(RUN), 'SYSTEMAPI_E2E_RUN is required (run npm run test:agent)');
  assert.ok(NETWORK, 'SYSTEMAPI_E2E_NETWORK is required (run npm run test:agent)');
  assert.ok(Number.isFinite(SLACK) && SLACK >= 1, 'E2E_SLACK must be a number >= 1');
  st.pool = new Pool({ connectionString: DB_URL });
  await startServer();
  st.apiKey = await mintKey();
  st.proxy = await startProxy(st.port);
  await startContainer();
  await startAgent();
  await waitSynced();
  const row = await waitUntil('host presence', async () => {
    const res = await st.pool.query('SELECT host_id, agent_caps FROM cp_hosts WHERE hostname = $1 AND agent_caps IS NOT NULL', [HOSTNAME]);
    return res.rows[0];
  });
  st.hostId = row.host_id;
});

test.after(async () => {
  if (st.pty) st.pty.ws.close();
  if (st.proxy) st.proxy.close();
  if (st.container) await run('docker', ['rm', '-f', st.container]);
  if (st.server) {
    st.server.kill('SIGTERM');
    await sleep(200);
    if (st.server.exitCode === null) st.server.kill('SIGKILL');
  }
  if (st.pool) await st.pool.end();
});

process.on('exit', (code) => {
  if (code !== 0 && st.serverLog.length) {
    process.stderr.write(`--- server log (tail) ---\n${st.serverLog.join('').slice(-8000)}\n`);
  }
});

test('the agent enrolls with the bootstrap key and advertises sysscript_jobs', async () => {
  const log = await agentLog();
  assert.match(log, /advertised capabilities="[^"]*\bsysscript_jobs\b/);
  assert.match(log, /enrolled host_id=/);
  const { rows } = await st.pool.query('SELECT agent_caps FROM cp_hosts WHERE host_id = $1', [st.hostId]);
  assert.ok(rows[0].agent_caps.includes('sysscript_jobs'), JSON.stringify(rows[0]));
  const sync = st.proxy.find((e) => e.type === 'sysscript_job_sync');
  assert.ok(sync, 'the agent sent a sysscript_job_sync');
  assert.deepEqual(sync.sync, { active: [], unacked: [] });
});

// AC 1, 2, 11: the long job, the two legacy /execute calls and the PTY.
test('a long job returns its id at once and the agent stays live while it runs', async () => {
  st.pty = await openTerminal();
  const idle = await ptyRoundTrip(st.pty);

  const long = await submit('r = sys.exec.run("sleep", "40")\nprint("long done", r["error"])');
  assert.equal(long.status, 202, long.text);
  assert.match(long.body.job_id, /^sjb_[A-Za-z0-9_-]{22}$/);
  assert.ok(long.ms < within(1000), `202 took ${long.ms} ms`);
  st.pending.long = { id: long.body.job_id, at: Date.now() };

  // Legacy /execute on a capable agent: 40 s gives 504 + job_id at ~28 s,
  // 5 s gives today's 200 shape.
  // These settle later; a rejection becomes {error} so it is never unhandled
  // when an earlier assertion fails.
  const execute = (script) => api('POST', `/api/v1/fleet/${encodeURIComponent(st.hostId)}/execute`,
    { script, entitlements: ALLOW_EXEC }).catch((error) => ({ error }));
  st.pending.legacy40 = execute('sys.exec.run("sleep", "40")\nprint("legacy forty")');
  const legacy5 = execute('sys.exec.run("sleep", "5")\nprint("legacy five")');

  await waitStatus(st.pending.long.id, ['running'], 10000);
  // While a 40 s script runs: PTY round trips, and a second socket for the
  // host is refused because the busy agent still answers the server's ping.
  const busy = [];
  for (let i = 0; i < 5; i++) busy.push(await ptyRoundTrip(st.pty));
  const { rows } = await st.pool.query('SELECT ssh_pubkey FROM cp_hosts WHERE host_id = $1', [st.hostId]);
  const newcomerStarted = Date.now();
  const refused = await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${st.port}/api/v1/systems/stream`, {
      headers: {
        authorization: `Bearer ${st.apiKey}`,
        'x-systemapi-tenant': TENANT,
        'x-systemapi-host-id': st.hostId,
        'x-systemapi-hostname': HOSTNAME,
        'x-systemapi-ssh-pubkey': rows[0].ssh_pubkey
      }
    });
    const timer = setTimeout(() => reject(new Error('newcomer got no answer')), 15000);
    ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      clearTimeout(timer);
      ws.close();
      resolve(msg);
    });
    ws.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
  const newcomerMs = Date.now() - newcomerStarted;
  assert.deepEqual(refused, { type: 'enroll_error', error: 'host_connected' });
  assert.ok(newcomerMs < within(5000), `displacement probe took ${newcomerMs} ms`);
  assert.equal(st.proxy.live().length, 1, 'the real agent kept its one socket');
  console.log(`pty round trip idle=${idle} ms, during job=${busy.join(',')} ms; newcomer refused in ${newcomerMs} ms`);
  for (const ms of busy) assert.ok(ms < within(1000), `pty round trip ${ms} ms while a job runs`);

  const five = await legacy5;
  assert.ifError(five.error);
  assert.equal(five.status, 200, five.text);
  assert.equal(five.body.success, true);
  assert.equal(five.body.request_id, five.body.job_id);
  assert.equal(five.body.result.error, '');
  assert.match(five.body.result.output, /legacy five/);
  assert.ok(five.body.executed_by);
  console.log(`POST /jobs 202 in ${long.ms} ms; legacy /execute 5 s script: 200 in ${five.ms} ms`);
  const fiveJob = await getJob(five.body.job_id);
  assert.equal(fiveJob.source, 'execute');
  assert.equal(fiveJob.status, 'succeeded');
});

// AC 5: cancel kills the whole process group, including a child that ignores TERM.
test('cancel ends the job and kills its process group', async () => {
  const job = await submit('r = sys.exec.run("sh", "-c", "(trap \'\' TERM; exec sleep 617) & sleep 618 & wait")\nprint(r)');
  assert.equal(job.status, 202, job.text);
  const id = job.body.job_id;
  await waitStatus(id, ['running'], 10000);
  const procs = await waitUntil('job processes', async () => {
    const list = await processes();
    const mine = list.filter((p) => /^sleep 61[78]$/.test(p.cmd));
    return mine.length === 2 ? { list, mine } : null;
  }, 10000, 100);
  const pgid = procs.mine[0].pgid;
  assert.equal(procs.mine[1].pgid, pgid, 'both children share the job group');
  const agentPid = Number((await exec('cat /run/systemapi-agent.pid')).trim());
  const agent = procs.list.find((p) => p.pid === agentPid);
  assert.ok(agent, `agent pid ${agentPid} not found`);
  assert.notEqual(pgid, agent.pgid, 'the job has its own group');
  const leader = procs.list.find((p) => p.pid === pgid);
  assert.ok(leader && leader.cmd.startsWith('sh -c'), `group leader ${JSON.stringify(leader)}`);

  const started = Date.now();
  const cancel = await api('POST', `/api/v1/jobs/${id}/cancel`);
  assert.equal(cancel.status, 202, cancel.text);
  const done = await waitStatus(id, ['cancelled', 'failed', 'succeeded', 'timed_out'], 15000);
  const tookMs = Date.now() - started;
  assert.equal(done.status, 'cancelled', JSON.stringify(done));
  assert.ok(tookMs < within(12000), `cancelled after ${tookMs} ms`);
  const left = (await processes()).filter((p) => p.pgid === pgid || /^sleep 61[78]$/.test(p.cmd));
  assert.deepEqual(left, [], 'no process of the job group remains');
  console.log(`cancel: group ${pgid} gone, job cancelled after ${tookMs} ms`);
  const audit = await st.pool.query("SELECT action FROM cp_audit WHERE payload->>'job_id' = $1 ORDER BY seq", [id]);
  assert.deepEqual(audit.rows.map((r) => r.action), ['sysscript_job_submit', 'sysscript_job_cancel', 'sysscript_job_end']);
});

// AC 6.
test('timeout_s=2 ends a busy loop as timed_out', async () => {
  const spin = 'def spin():\n  for i in range(1 << 30):\n    for j in range(1 << 30):\n      pass\nspin()\n';
  const res = await submit(spin, { timeout_s: 2, wait_s: 10 });
  assert.equal(res.status, 200, res.text);
  assert.equal(res.body.job.status, 'timed_out');
  assert.ok(res.ms < within(3500), `timed_out after ${res.ms} ms`);
  console.log(`timeout_s=2 busy loop: timed_out in ${res.ms} ms`);
});

// AC 1, 3, 11 (the ends of the jobs started above).
test('the long job and the legacy 40 s script both end succeeded', async () => {
  assert.ok(st.pending.long && st.pending.legacy40, 'the jobs from the long-job test were started');
  const legacy = await st.pending.legacy40;
  assert.ifError(legacy.error);
  assert.equal(legacy.status, 504, legacy.text);
  assert.equal(legacy.body.error, 'agent_timeout');
  assert.match(legacy.body.job_id, /^sjb_/);
  assert.ok(legacy.ms >= 27000 && legacy.ms < within(31000), `504 after ${legacy.ms} ms`);

  const long = await waitStatus(st.pending.long.id, ['succeeded', 'failed', 'cancelled', 'timed_out'], 30000);
  assert.equal(long.status, 'succeeded', JSON.stringify(long));
  assert.ok(long.duration_ms >= 39000 && long.duration_ms < within(45000), `duration_ms ${long.duration_ms}`);
  assert.equal(long.output_visible, true);
  assert.match(long.output, /long done None/);
  console.log(`legacy /execute 40 s script: 504 agent_timeout in ${legacy.ms} ms; long job succeeded, duration_ms=${long.duration_ms}`);
  const legacyJob = await waitStatus(legacy.body.job_id, ['succeeded', 'failed', 'cancelled', 'timed_out'], 20000);
  assert.equal(legacyJob.status, 'succeeded');
  assert.equal(legacyJob.source, 'execute');
  assert.match(legacyJob.output, /legacy forty/);

  // Each result was acked to the agent, and audited once.
  for (const id of [long.job_id, legacyJob.job_id]) {
    await waitUntil(`ack ${id}`, () => st.proxy.find((e) => e.dir === 'down' && e.type === 'sysscript_job_ack' && e.job_id === id), 5000);
    const audit = await st.pool.query("SELECT action FROM cp_audit WHERE payload->>'job_id' = $1 ORDER BY seq", [id]);
    assert.deepEqual(audit.rows.map((r) => r.action), ['sysscript_job_submit', 'sysscript_job_end']);
  }
  const verify = await api('GET', '/api/v1/audit/verify');
  assert.equal(verify.status, 200, verify.text);
  assert.equal(verify.body.ok, true);
  const list = await api('GET', `/api/v1/jobs?host_id=${encodeURIComponent(st.hostId)}`);
  assert.equal(list.status, 200, list.text);
  assert.ok(list.body.jobs.some((j) => j.job_id === long.job_id));
  assert.ok(list.body.jobs.every((j) => !('output' in j)), 'the list never carries output');
});

// AC 13.
test('NUL bytes and 1 MiB of escaping output keep the socket up', async () => {
  const connsBefore = st.proxy.conns.length;
  const nul = await submit('print("a\\x00b")', { wait_s: 20 });
  assert.equal(nul.status, 200, nul.text);
  assert.equal(nul.body.job.status, 'succeeded');
  // The agent sends the NUL; the server stores U+FFFD (PostgreSQL TEXT).
  const nulFrame = st.proxy.find((e) => e.dir === 'up' && e.type === 'sysscript_job_result' && e.job_id === nul.body.job.job_id);
  assert.ok(nulFrame, 'NUL result frame seen on the wire');
  assert.equal(nulFrame.nul, true);
  assert.equal(nul.body.job.output, 'a�b\n');

  for (const [label, script] of [['<', 'print("<" * 1048576)'], ['\\x01', 'print("\\x01" * 1048576)']]) {
    const res = await submit(script, { wait_s: 20 });
    assert.equal(res.status, 200, `${label}: ${res.text}`);
    const job = res.body.job;
    assert.equal(job.status, 'succeeded', `${label}: ${job.error}`);
    assert.equal(job.output_truncated, true, label);
    assert.ok(job.output.length > 0, label);
    const frame = st.proxy.find((e) => e.dir === 'up' && e.type === 'sysscript_job_result' && e.job_id === job.job_id);
    assert.ok(frame, `${label}: result frame seen on the wire`);
    assert.ok(frame.size <= 1 << 20, `${label}: result frame ${frame.size} bytes`);
    console.log(`${label} x 1 MiB: frame ${frame.size} bytes, stored ${job.output.length} chars, truncated`);
  }
  assert.equal(st.proxy.conns.length, connsBefore, 'no reconnect');
  assert.equal(st.proxy.live().length, 1);
  assert.equal(st.proxy.find((e) => e.op === 8), undefined, 'no close frame either way');
  assert.ok(st.pty, 'the PTY session from the long-job test exists');
  assert.equal(st.pty.closed, false, 'the PTY session is still open');
  const ms = await ptyRoundTrip(st.pty);
  assert.ok(ms < within(1000), `pty round trip ${ms} ms after the big frames`);
  st.pty.ws.close();
  st.pty = null;
});

// AC 7: a result that never reached the server is re-sent after the sync on
// the next socket, stored once and acked; once acked it is not sent again.
test('a dropped socket hides a result; the agent re-sends it after sync and it is acked', async () => {
  const res = await submit('sys.exec.run("sleep", "3")\nprint("resent after drop")');
  assert.equal(res.status, 202, res.text);
  const id = res.body.job_id;
  await waitStatus(id, ['running'], 10000);
  const [conn] = st.proxy.live();
  assert.ok(conn, 'the agent is connected');
  conn.held = true;
  const swallowed = await waitUntil('swallowed result', () => st.proxy.find((e) => e.held && e.type === 'sysscript_job_result' && e.job_id === id), 15000);
  assert.equal(swallowed.status, 'succeeded');
  assert.equal((await getJob(id)).status, 'running', 'the server never saw the result');
  conn.client.destroy();
  conn.upstream.destroy();

  const sync = await waitSynced(conn.id);
  assert.deepEqual(sync.sync.active, []);
  assert.deepEqual(sync.sync.unacked, [{ job_id: id, status: 'succeeded' }]);
  const resent = await waitUntil('re-sent result', () => st.proxy.find((e) => e.conn === sync.conn && e.dir === 'up' && e.type === 'sysscript_job_result' && e.job_id === id));
  assert.ok(resent.at >= sync.at, 'the result follows the sync');
  await waitUntil('ack', () => st.proxy.find((e) => e.conn === sync.conn && e.dir === 'down' && e.type === 'sysscript_job_ack' && e.job_id === id));
  const job = await waitStatus(id, ['succeeded', 'failed'], 5000);
  assert.equal(job.status, 'succeeded');
  assert.match(job.output, /resent after drop/);
  const ends = await st.pool.query("SELECT count(*)::int AS n FROM cp_audit WHERE action = 'sysscript_job_end' AND payload->>'job_id' = $1", [id]);
  assert.equal(ends.rows[0].n, 1);

  // Drop again: the acked result is gone from the next sync.
  const [again] = st.proxy.live();
  assert.ok(again, 'the agent reconnected');
  again.client.destroy();
  again.upstream.destroy();
  const next = await waitSynced(again.id);
  assert.deepEqual(next.sync, { active: [], unacked: [] });
  assert.equal(st.proxy.events.filter((e) => e.dir === 'up' && e.type === 'sysscript_job_result' && e.job_id === id).length, 2);
});

// AC 7: the agent process dies mid-job; the new process's sync does not list
// the job, so the server ends it agent_lost_job.
test('killing the agent mid-job ends the job agent_lost_job after the restart', async () => {
  const res = await submit('sys.exec.run("sleep", "619")\nprint("never")');
  assert.equal(res.status, 202, res.text);
  const id = res.body.job_id;
  await waitStatus(id, ['running'], 10000);
  const before = st.proxy.conns.length;
  await exec('kill -KILL "$(cat /run/systemapi-agent.pid)"');
  await waitUntil('socket closed', () => st.proxy.live().length === 0, 10000);
  assert.equal((await getJob(id)).status, 'running', 'nothing ends the job before the agent is back');
  await startAgent();
  const sync = await waitSynced(before);
  assert.deepEqual(sync.sync, { active: [], unacked: [] });
  const job = await waitStatus(id, ['failed', 'succeeded', 'cancelled', 'timed_out'], 10000);
  assert.equal(job.status, 'failed');
  assert.equal(job.error, 'agent_lost_job');
  // The job's child got Pdeathsig when the agent died: none is left over.
  let orphans = [];
  await waitUntil('lost job children gone', async () => {
    orphans = (await processes()).filter((p) => p.cmd === 'sleep 619');
    return orphans.length === 0;
  }, within(2000), 100).catch(() => {}); // a timeout fails the assertion below, which lists them
  assert.deepEqual(orphans, [], 'orphaned children of the lost job');

  // The restarted agent runs jobs again.
  const after = await submit('print("back")', { wait_s: 20 });
  assert.equal(after.status, 200, after.text);
  assert.equal(after.body.job.status, 'succeeded');
  assert.equal(after.body.job.output, 'back\n');
});
