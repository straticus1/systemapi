'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'cli', 'systemapi.js');
const HELPER = path.join(ROOT, 'drivers', 'ansible', 'systemapi_exec.py');
const PLUGIN = path.join(ROOT, 'drivers', 'ansible', 'plugins', 'connection', 'systemapi.py');
const KEY = 'test-key-not-a-real-secret';
const TENANT = 'tenant-canary-value';

function run(args, env, input) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const out = [];
    const err = [];
    child.stdout.on('data', (chunk) => out.push(chunk));
    child.stderr.on('data', (chunk) => err.push(chunk));
    child.on('close', (status) => {
      resolve({
        status,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8')
      });
    });
    if (input) child.stdin.end(input);
    else child.stdin.end();
  });
}

function python(args, env, input) {
  return new Promise((resolve) => {
    const child = spawn('python3', args, {
      env: {
        PATH: process.env.PATH || '',
        PYTHONDONTWRITEBYTECODE: '1',
        ...env
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const out = [];
    const err = [];
    child.stdout.on('data', (chunk) => out.push(chunk));
    child.stderr.on('data', (chunk) => err.push(chunk));
    child.on('close', (status) => {
      resolve({
        status,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8')
      });
    });
    child.stdin.end(input || '');
  });
}

function readReq(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > 1024 * 1024) req.destroy();
      else chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function env(url, extra) {
  return {
    PATH: process.env.PATH || '',
    SYSTEMAPI_URL: url,
    SYSTEMAPI_API_KEY: KEY,
    SYSTEMAPI_TENANT: TENANT,
    ...extra
  };
}

function record(key) {
  const seen = [];
  const server = http.createServer(async (req, res) => {
    const body = await readReq(req);
    seen.push({
      method: req.method,
      url: req.url,
      authOk: req.headers['x-api-key'] === key,
      authorization: Object.prototype.hasOwnProperty.call(req.headers, 'authorization'),
      body
    });
    server.emit('request-done', req, res, body);
  });
  return { server, seen };
}

test('driver files do not embed an API key', () => {
  const files = [
    CLI,
    HELPER,
    PLUGIN,
    path.join(ROOT, 'drivers', 'ansible', 'README.md'),
    path.join(ROOT, 'drivers', 'terraform', 'main.tf'),
    path.join(ROOT, 'drivers', 'terraform', 'variables.tf'),
    path.join(ROOT, 'drivers', 'terraform', 'README.md')
  ];
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes('ak_live'), false, file);
    assert.equal(text.includes('api_key='), false, file);
    assert.equal(text.includes('rejectUnauthorized'), false, file);
  }
  const vars = fs.readFileSync(path.join(ROOT, 'drivers', 'terraform', 'variables.tf'), 'utf8');
  assert.match(vars, /variable\s+"host_id"/);
  assert.doesNotMatch(vars, /variable\s+"(?:api_key|SYSTEMAPI_API_KEY|token|password)"/);
  const main = fs.readFileSync(path.join(ROOT, 'drivers', 'terraform', 'main.tf'), 'utf8');
  assert.match(main, /\["node", "\$\{path\.module\}\/\.\.\/\.\.\/cli\/systemapi\.js", "host-json", "--host", var\.host_id\]/);
  assert.equal((fs.statSync(CLI).mode & 0o111) !== 0, true);
  const pluginText = fs.readFileSync(PLUGIN, 'utf8');
  const pluginLines = pluginText.endsWith('\n') ? pluginText.split('\n').length - 1 : pluginText.split('\n').length;
  assert.equal(pluginLines < 200, true, String(pluginLines));
  const doc = fs.readFileSync(PLUGIN, 'utf8').slice(0, 400);
  assert.match(doc, /Pipes, redirects, and ``&&`` are refused/);
});

test('missing env exits 2 without echoing values', async () => {
  const both = await run(['hosts'], { SYSTEMAPI_TENANT: TENANT });
  assert.equal(both.status, 2);
  assert.match(both.stderr, /SYSTEMAPI_URL/);
  assert.match(both.stderr, /SYSTEMAPI_API_KEY/);
  assert.equal(both.stderr.includes(TENANT), false);
  assert.equal(both.stdout, '');

  const keyOnly = await run(['hosts'], {
    SYSTEMAPI_URL: 'http://127.0.0.1:9/canary-path',
    SYSTEMAPI_TENANT: TENANT
  });
  assert.equal(keyOnly.status, 2);
  assert.match(keyOnly.stderr, /missing SYSTEMAPI_API_KEY/);
  assert.equal(keyOnly.stderr.includes('canary-path'), false);
  assert.equal(keyOnly.stderr.includes(TENANT), false);

  const query = await run(['hosts'], {
    SYSTEMAPI_URL: 'http://127.0.0.1:9/fleet?api_key=' + KEY,
    SYSTEMAPI_API_KEY: KEY
  });
  assert.equal(query.status, 2);
  assert.match(query.stderr, /invalid SYSTEMAPI_URL/);
  assert.equal(query.stderr.includes(KEY), false);
  assert.equal(query.stdout.includes(KEY), false);
});

test('login does not require an API key', async () => {
  const missing = await run(['login', 'user-1'], { PATH: process.env.PATH || '' });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /SYSTEMAPI_URL/);
  assert.equal(missing.stderr.includes('SYSTEMAPI_API_KEY'), false);
  assert.equal(missing.stdout, '');
});

test('unknown command and key-shaped argv exit 2 without echoing the value', async () => {
  const unknown = await run(['nope'], env('http://127.0.0.1:9'));
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /usage: systemapi\.js/);
  assert.equal(unknown.stderr.includes(KEY), false);

  const flag = await run(['exec', '--host', 'host-1', '--api-key', KEY], env('http://127.0.0.1:9'));
  assert.equal(flag.status, 2);
  assert.equal(flag.stdout.includes(KEY), false);
  assert.equal(flag.stderr.includes(KEY), false);
});

test('fleet commands use the header and never a query key', async (t) => {
  const { server, seen } = record(KEY);
  server.on('request-done', (req, res) => {
    if (req.method === 'GET' && req.url === '/api/v1/fleet') {
      res.end(JSON.stringify({
        hosts: [{
          host_id: 'host-1',
          hostname: 'box',
          status: 'online',
          os: 'linux',
          key_id: 'should-not-appear',
          tenant_id: TENANT
        }]
      }));
      return;
    }
    if (req.method === 'GET' && req.url === '/api/v1/fleet/host-1/metrics') {
      res.end(JSON.stringify({ host_id: 'host-1', metric: 'cpu.usage_percent', points: [] }));
      return;
    }
    if (req.method === 'GET' && req.url === '/api/v1/audit') {
      res.end(JSON.stringify({ events: [{ action: 'sysscript' }] }));
      return;
    }
    if (req.method === 'POST' && req.url === '/api/v1/ws-ticket') {
      res.end(JSON.stringify({
        ticket: 'stk_abc12345',
        expires_in: 60,
        host_id: 'host-1',
        purpose: 'breakglass:open',
        api_key: KEY
      }));
      return;
    }
    if (req.method === 'POST' && req.url === '/api/v1/fleet/host-1/execute') {
      const body = JSON.parse(seen[seen.length - 1].body);
      if (body.script === 'err-empty') {
        res.end(JSON.stringify({ success: true, result: { output: '', error: 'boom' }, executed_by: KEY }));
        return;
      }
      if (body.script === 'both') {
        res.end(JSON.stringify({ success: true, result: { output: 'out', error: 'err' } }));
        return;
      }
      if (body.script === 'http-error') {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad_script' }));
        return;
      }
      res.end(JSON.stringify({
        success: true,
        request_id: 'r1',
        result: { output: 'hello\n', error: '' },
        executed_by: 'user-1'
      }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });
  const port = await listen(server);
  t.after(() => close(server));
  const base = 'http://127.0.0.1:' + port + '/';

  const hosts = await run(['hosts'], env(base));
  assert.equal(hosts.status, 0);
  assert.equal(hosts.stdout, 'host-1\tbox\tonline\tlinux\n');
  assert.equal(hosts.stdout.includes('should-not-appear'), false);
  assert.equal(hosts.stdout.includes(TENANT), false);
  assert.equal(hosts.stdout.includes(KEY), false);
  assert.equal(seen[0].authOk, true);
  assert.equal(seen[0].authorization, false);
  assert.equal(seen[0].url.includes('api_key'), false);
  assert.equal(seen[0].body.includes(KEY), false);

  const metrics = await run(['metrics', '--host', 'host-1'], env(base));
  assert.equal(metrics.status, 0);
  assert.deepEqual(JSON.parse(metrics.stdout), { host_id: 'host-1', metric: 'cpu.usage_percent', points: [] });

  const audit = await run(['audit'], env(base));
  assert.equal(audit.status, 0);
  assert.deepEqual(JSON.parse(audit.stdout), { events: [{ action: 'sysscript' }] });

  const ticket = await run(['breakglass-ticket', '--host', 'host-1'], env(base));
  assert.equal(ticket.status, 0);
  assert.equal(ticket.stdout, 'stk_abc12345\n');
  assert.equal(ticket.stdout.includes('expires_in'), false);
  assert.equal(ticket.stdout.includes(KEY), false);
  const ticketBody = JSON.parse(seen.find((row) => row.url === '/api/v1/ws-ticket').body);
  assert.deepEqual(ticketBody, { host_id: 'host-1', purpose: 'breakglass:open' });

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'systemapi-exec-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const script = path.join(dir, 'ok.star');
  fs.writeFileSync(script, 'print(1)\n');
  const exec = await run(['exec', '--script-file', script, '--host', 'host-1'], env(base));
  assert.equal(exec.status, 0);
  assert.equal(exec.stdout, 'hello\n');
  assert.equal(exec.stdout.includes('executed_by'), false);
  assert.equal(exec.stdout.includes(KEY), false);
  const posted = JSON.parse(seen.find((row) => row.url.endsWith('/execute') && row.body.includes('print(1)')).body);
  assert.deepEqual(posted, { script: 'print(1)\n', entitlements: { allow_exec: true } });

  fs.writeFileSync(script, 'err-empty');
  const soft = await run(['exec', '--host', 'host-1', '--script-file', script], env(base));
  assert.equal(soft.status, 0);
  assert.equal(soft.stdout, 'boom');
  assert.equal(soft.stdout.includes(KEY), false);

  fs.writeFileSync(script, 'both');
  const both = await run(['exec', '--host', 'host-1', '--script-file', script], env(base));
  assert.equal(both.status, 0);
  assert.equal(both.stdout, 'out');

  fs.writeFileSync(script, 'http-error');
  const hard = await run(['exec', '--host', 'host-1', '--script-file', script], env(base));
  assert.equal(hard.status, 1);
  assert.equal(hard.stdout, 'bad_script\n');
  assert.equal(hard.stdout.includes(KEY), false);

  const json = await run(['host-json', '--host', 'host-1'], env(base));
  assert.equal(json.status, 0);
  assert.deepEqual(JSON.parse(json.stdout), { host_id: 'host-1', hostname: 'box', status: 'online' });
  assert.equal(json.stdout.includes('should-not-appear'), false);
  assert.equal(json.stdout.includes(KEY), false);

  const missing = await run(['host-json', '--host', 'missing-host'], env(base));
  assert.equal(missing.status, 1);
  assert.equal(missing.stdout, '');
  assert.match(missing.stderr, /host not found/);
  assert.equal(missing.stderr.includes(KEY), false);

  const dotdot = await run(['host-json', '--host', '..'], env(base));
  assert.equal(dotdot.status, 2);
  assert.match(dotdot.stderr, /invalid --host/);
  assert.equal(seen.some((row) => row.url.includes('..')), false);

  for (const row of seen) {
    assert.equal(row.authOk, true);
    assert.equal(row.url.includes('api_key'), false);
    assert.equal(row.url.includes(KEY), false);
    assert.equal(row.body.includes(KEY), false);
  }
});

test('exec rejects a missing or oversized script before any request', async (t) => {
  const { server, seen } = record(KEY);
  server.on('request-done', (req, res, body) => {
    let script = '';
    try {
      script = JSON.parse(body).script || '';
    } catch {
      script = '';
    }
    if (script.length === 64 * 1024) {
      res.end(JSON.stringify({ success: true, result: { output: 'ok', error: '' } }));
      return;
    }
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'unexpected' }));
  });
  const port = await listen(server);
  t.after(() => close(server));
  const base = 'http://127.0.0.1:' + port;
  const missing = await run(['exec', '--host', 'host-1', '--script-file', path.join(os.tmpdir(), 'systemapi-no-such-script')], env(base));
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /script file missing/);
  assert.equal(missing.stderr.includes(KEY), false);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'systemapi-big-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const big = path.join(dir, 'big.star');
  fs.writeFileSync(big, Buffer.alloc(64 * 1024 + 1, 0x61));
  const tooBig = await run(['exec', '--host', 'host-1', '--script-file', big], env(base));
  assert.equal(tooBig.status, 1);
  assert.match(tooBig.stderr, /larger than 64 KiB/);
  assert.equal(seen.length, 0);

  const exact = path.join(dir, 'exact.star');
  fs.writeFileSync(exact, Buffer.alloc(64 * 1024, 0x62));
  const ok = await run(['exec', '--host', 'host-1', '--script-file', exact], env(base));
  assert.equal(ok.status, 0);
  assert.equal(ok.stdout, 'ok');
  const body = JSON.parse(seen[0].body);
  assert.equal(body.script.length, 64 * 1024);
  assert.equal(seen[0].url, '/api/v1/fleet/host-1/execute');
});

const JOB_DONE = 'sjb_' + 'd'.repeat(22);
const JOB_SLOW = 'sjb_' + 's'.repeat(22);
const JOB_FAIL = 'sjb_' + 'f'.repeat(22);
const JOB_STUCK = 'sjb_' + 'r'.repeat(22);
const JOB_HIDDEN = 'sjb_' + 'h'.repeat(22);
const JOB_OVER = 'sjb_' + 'o'.repeat(22);

function jobRow(id, status, extra) {
  return {
    job_id: id,
    host_id: 'host-1',
    source: 'api',
    status,
    error: null,
    deadline_unix: Math.floor(Date.now() / 1000) + 300,
    output_truncated: false,
    output_expired: false,
    created_at: '2026-10-28T00:00:00.000Z',
    duration_ms: null,
    output_visible: true,
    output: null,
    ...extra
  };
}

function jobServer() {
  const { server, seen } = record(KEY);
  const gets = new Map();
  server.on('request-done', (req, res, body) => {
    const reply = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };
    if (req.method === 'POST' && req.url === '/api/v1/fleet/host-1/jobs') {
      const sent = JSON.parse(body);
      if (sent.script === 'done' && sent.wait_s > 0) {
        reply(200, { job: jobRow(JOB_DONE, 'succeeded', { output: 'hi\n', duration_ms: 5 }) });
        return;
      }
      const id = { slow: JOB_SLOW, fail: JOB_FAIL, stuck: JOB_STUCK }[sent.script] || JOB_DONE;
      reply(202, { job_id: id, status: 'submitted', deadline_unix: Math.floor(Date.now() / 1000) + 300 });
      return;
    }
    const get = /^\/api\/v1\/jobs\/(sjb_[A-Za-z0-9_-]{22})$/.exec(req.url);
    if (req.method === 'GET' && get) {
      const id = get[1];
      const n = (gets.get(id) || 0) + 1;
      gets.set(id, n);
      if (id === JOB_SLOW) {
        reply(200, { job: n < 2 ? jobRow(id, 'running') : jobRow(id, 'succeeded', { output: 'slow done\n', duration_ms: 2100 }) });
        return;
      }
      if (id === JOB_FAIL) {
        reply(200, { job: jobRow(id, 'timed_out', { error: 'timed_out', output: 'partial\n' }) });
        return;
      }
      if (id === JOB_HIDDEN) {
        reply(200, { job: jobRow(id, 'succeeded', { output_visible: false, output: null }) });
        return;
      }
      if (id === JOB_STUCK) {
        reply(200, { job: jobRow(id, 'running', { deadline_unix: Math.floor(Date.now() / 1000) - 120 }) });
        return;
      }
      reply(404, { error: 'not_found' });
      return;
    }
    if (req.method === 'POST' && req.url === '/api/v1/jobs/' + JOB_STUCK + '/cancel') {
      reply(202, { job: jobRow(JOB_STUCK, 'running', { cancel_requested_at: '2026-10-28T00:00:01.000Z' }) });
      return;
    }
    if (req.method === 'POST' && req.url === '/api/v1/jobs/' + JOB_OVER + '/cancel') {
      reply(409, { error: 'job_finished' });
      return;
    }
    if (req.method === 'GET' && (req.url === '/api/v1/jobs' || req.url.startsWith('/api/v1/jobs?'))) {
      reply(200, {
        jobs: [
          jobRow(JOB_DONE, 'succeeded', { duration_ms: 5 }),
          jobRow(JOB_FAIL, 'timed_out', { source: 'sched\tule' })
        ]
      });
      return;
    }
    reply(404, { error: 'not_found' });
  });
  return { server, seen };
}

test('jobs submit: async prints the id; --wait polls to the end; exit 0, 1 and 3', async (t) => {
  const { server, seen } = jobServer();
  const port = await listen(server);
  t.after(() => close(server));
  const base = 'http://127.0.0.1:' + port;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'systemapi-jobs-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const script = path.join(dir, 'job.star');

  fs.writeFileSync(script, 'done');
  const async = await run(['jobs', 'submit', 'host-1', script], env(base));
  assert.equal(async.status, 0, async.stderr);
  assert.equal(async.stdout, JOB_DONE + '\n');
  assert.deepEqual(JSON.parse(seen[0].body), { script: 'done', entitlements: { allow_exec: true }, wait_s: 0 });

  const quick = await run(['jobs', 'submit', 'host-1', script, '--timeout', '600', '--wait', '45'], env(base));
  assert.equal(quick.status, 0, quick.stderr);
  assert.equal(quick.stdout, 'hi\n');
  assert.equal(quick.stderr, '');
  assert.deepEqual(JSON.parse(seen[1].body), { script: 'done', entitlements: { allow_exec: true }, wait_s: 20, timeout_s: 600 });
  assert.equal(seen.length, 2);

  fs.writeFileSync(script, 'slow');
  const slow = await run(['jobs', 'submit', 'host-1', script, '--wait', '5'], env(base));
  assert.equal(slow.status, 0, slow.stderr);
  assert.equal(slow.stdout, 'slow done\n');
  assert.equal(JSON.parse(seen[2].body).wait_s, 5);
  assert.deepEqual(seen.slice(3).map((row) => row.method + ' ' + row.url), [
    'GET /api/v1/jobs/' + JOB_SLOW,
    'GET /api/v1/jobs/' + JOB_SLOW
  ]);

  fs.writeFileSync(script, 'fail');
  const failed = await run(['jobs', 'submit', 'host-1', script, '--wait', '3'], env(base));
  assert.equal(failed.status, 1);
  assert.equal(failed.stdout, 'partial\n');
  assert.match(failed.stderr, /^timed_out timed_out\n$/);

  fs.writeFileSync(script, 'stuck');
  const stuck = await run(['jobs', 'submit', 'host-1', script, '--wait', '1'], env(base));
  assert.equal(stuck.status, 3);
  assert.equal(stuck.stdout, JOB_STUCK + '\n');
  assert.match(stuck.stderr, /still running/);

  const hidden = await run(['jobs', 'wait', JOB_HIDDEN], env(base));
  assert.equal(hidden.status, 0);
  assert.equal(hidden.stdout, '');
  assert.match(hidden.stderr, /output hidden/);

  // No --wait: a job past its deadline + 90 s is not waited on.
  const past = await run(['jobs', 'wait', JOB_STUCK], env(base));
  assert.equal(past.status, 3);
  assert.equal(past.stdout, JOB_STUCK + '\n');

  for (const row of seen) {
    assert.equal(row.authOk, true);
    assert.equal(row.authorization, false);
    assert.equal(row.url.includes(KEY), false);
    assert.equal(row.body.includes(KEY), false);
  }
  for (const out of [async, quick, slow, failed, stuck, hidden, past]) {
    assert.equal(out.stdout.includes(KEY), false);
    assert.equal(out.stderr.includes(KEY), false);
  }
});

test('jobs status, cancel and list', async (t) => {
  const { server, seen } = jobServer();
  const port = await listen(server);
  t.after(() => close(server));
  const base = 'http://127.0.0.1:' + port;

  const done = await run(['jobs', 'status', JOB_SLOW], env(base));
  assert.equal(done.status, 3);
  assert.equal(JSON.parse(done.stdout).status, 'running');
  const failed = await run(['jobs', 'status', JOB_FAIL], env(base));
  assert.equal(failed.status, 1);
  assert.equal(JSON.parse(failed.stdout).status, 'timed_out');
  const missing = await run(['jobs', 'status', 'sjb_' + 'x'.repeat(22)], env(base));
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /not_found/);

  const cancel = await run(['jobs', 'cancel', JOB_STUCK], env(base));
  assert.equal(cancel.status, 0, cancel.stderr);
  assert.equal(cancel.stdout, JOB_STUCK + '\trunning\n');
  const over = await run(['jobs', 'cancel', JOB_OVER], env(base));
  assert.equal(over.status, 1);
  assert.match(over.stderr, /job_finished/);

  const list = await run(['jobs', 'list', '--host', 'host-1', '--status', 'timed_out'], env(base));
  assert.equal(list.status, 0, list.stderr);
  assert.equal(list.stdout, [
    [JOB_DONE, 'host-1', 'succeeded', 'api', '2026-10-28T00:00:00.000Z', '5'].join('\t'),
    [JOB_FAIL, 'host-1', 'timed_out', 'sched ule', '2026-10-28T00:00:00.000Z', ''].join('\t')
  ].join('\n') + '\n');
  assert.equal(seen[seen.length - 1].url, '/api/v1/jobs?host_id=host-1&status=timed_out');
  const all = await run(['jobs', 'list'], env(base));
  assert.equal(all.status, 0);
  assert.equal(seen[seen.length - 1].url, '/api/v1/jobs');
});

test('jobs rejects bad arguments before any request', async (t) => {
  const { server, seen } = jobServer();
  const port = await listen(server);
  t.after(() => close(server));
  const base = 'http://127.0.0.1:' + port;
  const cases = [
    ['jobs'],
    ['jobs', 'nope'],
    ['jobs', 'status'],
    ['jobs', 'status', 'not-a-job-id'],
    ['jobs', 'status', JOB_DONE, '--wait', '1'],
    ['jobs', 'cancel', '../' + JOB_DONE],
    ['jobs', 'wait', JOB_DONE, '--wait', '-1'],
    ['jobs', 'submit', 'host-1'],
    ['jobs', 'submit', '..', '/dev/null'],
    ['jobs', 'submit', 'host-1', '/dev/null', '--timeout', '0'],
    ['jobs', 'submit', 'host-1', '/dev/null', '--timeout', '1.5'],
    ['jobs', 'submit', 'host-1', '/dev/null', '--wait', '1', '--wait', '2'],
    ['jobs', 'list', '--status', 'bogus'],
    ['jobs', 'list', '--host', '..'],
    ['jobs', 'list', 'extra']
  ];
  for (const args of cases) {
    const out = await run(args, env(base));
    assert.equal(out.status, 2, args.join(' '));
    assert.equal(out.stdout, '');
  }
  assert.equal(seen.length, 0);
});

test('redirects are not followed and do not echo the key', async (t) => {
  const hits = [];
  const trap = http.createServer((req, res) => {
    hits.push(req.url);
    res.writeHead(500);
    res.end('trap');
  });
  const trapPort = await listen(trap);
  const main = http.createServer((req, res) => {
    res.writeHead(302, { Location: 'http://127.0.0.1:' + trapPort + '/redirect-canary' });
    res.end();
  });
  const port = await listen(main);
  t.after(() => Promise.all([close(main), close(trap)]));
  const result = await run(['hosts'], env('http://127.0.0.1:' + port));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /request_failed/);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes(KEY), false);
  assert.equal(result.stderr.includes('redirect-canary'), false);
  assert.deepEqual(hits, []);
});

test('starlark helper quotes argv and refuses shell syntax', async () => {
  const probe = await python(['-c', `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("systemapi_exec", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
prog = mod.starlark_exec(["echo", 'a"b', "a&b"])
assert "shell" not in prog
assert prog.startswith("r = sys.exec.run(")
sys.stdout.write(prog)
for bad in (["a", "b|c"], ["a", "b&&c"], ["a", "x;y"], ["a", "b>c"], ["a", "b<c"], ["a", "b\`c"], ["&&"]):
    try:
        mod.starlark_exec(bad)
    except ValueError as exc:
        assert "refusing shell metacharacter" in str(exc)
    else:
        raise SystemExit("accepted")
try:
    mod.starlark_exec([])
except ValueError as exc:
    assert "empty argv" in str(exc)
else:
    raise SystemExit("empty accepted")
`, HELPER]);
  assert.equal(probe.status, 0, probe.stderr);
  assert.equal(probe.stdout, 'r = sys.exec.run("echo", "a\\"b", "a&b")\nprint(r["output"])\n');
});

test('starlark main reads one JSON list from stdin', async () => {
  const ok = await python([HELPER], {}, '["uname","-a"]');
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout, 'r = sys.exec.run("uname", "-a")\nprint(r["output"])\n');

  const obj = await python([HELPER], {}, '{"a":1}');
  assert.equal(obj.status, 1);
  assert.match(obj.stderr, /expected a JSON list/);

  const empty = await python([HELPER], {}, '[]');
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /empty argv/);

  const meta = await python([HELPER], {}, '["a","b&&c"]');
  assert.equal(meta.status, 1);
  assert.match(meta.stderr, /refusing shell metacharacter/);

  const huge = await python([HELPER], {}, JSON.stringify(['a'.repeat(70 * 1024)]));
  assert.equal(huge.status, 1);
  assert.match(huge.stderr, /larger than 64 KiB/);
  assert.equal(huge.stdout, '');
});

test('ansible connection posts starlark and refuses a shell', async (t) => {
  const { server, seen } = record(KEY);
  server.on('request-done', (req, res, body) => {
    let script = '';
    try {
      script = JSON.parse(body).script || '';
    } catch {
      script = '';
    }
    if (script.includes('uname')) {
      res.end(JSON.stringify({ success: true, result: { output: 'Linux\n', error: '' } }));
      return;
    }
    if (script.includes('false')) {
      res.end(JSON.stringify({ success: true, result: { output: 'partial', error: 'exit status 1' } }));
      return;
    }
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'scope_denied' }));
  });
  const port = await listen(server);
  t.after(() => close(server));
  const code = `
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("systemapi_conn", os.environ["PLUGIN"])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PC:
    def __init__(self, host):
        self.remote_addr = host

mode = sys.argv[1]
if mode == "option":
    conn = mod.Connection(PC("host-1"))
    conn.get_option = lambda name: "host-9" if name == "host" else None
    rc, out, err = conn.exec_command("uname -a")
elif mode == "play":
    conn = mod.Connection(PC("host-1"))
    rc, out, err = conn.exec_command("uname -a")
elif mode == "shell":
    conn = mod.Connection(PC("host-1"))
    rc, out, err = conn.exec_command("ls | wc")
elif mode == "stdin":
    conn = mod.Connection(PC("host-1"))
    rc, out, err = conn.exec_command("uname", b"data")
elif mode == "dotdot":
    conn = mod.Connection(PC(".."))
    rc, out, err = conn.exec_command("uname")
elif mode == "http":
    conn = mod.Connection(PC("host-1"))
    rc, out, err = conn.exec_command("id")
elif mode == "result":
    conn = mod.Connection(PC("host-1"))
    rc, out, err = conn.exec_command("false")
else:
    raise SystemExit("bad mode")
sys.stdout.write(json.dumps({"rc": rc, "out": out.decode(), "err": err.decode()}))
`;
  const pyEnv = {
    SYSTEMAPI_URL: 'http://127.0.0.1:' + port + '/',
    SYSTEMAPI_API_KEY: KEY,
    SYSTEMAPI_TENANT: TENANT,
    PLUGIN
  };
  async function call(mode) {
    const result = await python(['-c', code, mode], pyEnv);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr.includes(KEY), false);
    assert.equal(result.stdout.includes(KEY), false);
    return JSON.parse(result.stdout);
  }

  const option = await call('option');
  assert.equal(option.rc, 0);
  assert.equal(option.out, 'Linux\n');
  assert.equal(option.err, '');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, '/api/v1/fleet/host-9/execute');
  assert.equal(seen[0].authOk, true);
  assert.equal(seen[0].authorization, false);
  assert.equal(seen[0].url.includes('api_key'), false);
  const posted = JSON.parse(seen[0].body);
  assert.equal(posted.script, 'r = sys.exec.run("uname", "-a")\nprint(r["output"])\n');
  assert.deepEqual(posted.entitlements, { allow_exec: true });
  assert.equal(posted.script.includes('shell'), false);

  const play = await call('play');
  assert.equal(play.rc, 0);
  assert.equal(play.out, 'Linux\n');
  assert.equal(seen[1].url, '/api/v1/fleet/host-1/execute');

  const before = seen.length;
  const shell = await call('shell');
  assert.equal(shell.rc, 1);
  assert.match(shell.err, /refusing shell metacharacter/);
  assert.equal(shell.out, '');
  const stdin = await call('stdin');
  assert.equal(stdin.rc, 1);
  assert.match(stdin.err, /stdin is not supported/);
  const dotdot = await call('dotdot');
  assert.equal(dotdot.rc, 1);
  assert.match(dotdot.err, /invalid host id/);
  assert.equal(seen.length, before);

  const denied = await call('http');
  assert.equal(denied.rc, 1);
  assert.equal(denied.err, 'scope_denied\n');
  assert.equal(denied.out, '');
  const failed = await call('result');
  assert.equal(failed.rc, 1);
  assert.equal(failed.out, 'partial');
  assert.equal(failed.err, 'exit status 1\n');
  for (const row of seen) {
    assert.equal(row.body.includes(KEY), false);
    assert.equal(row.url.includes(KEY), false);
  }
});

test('ansible connection does not follow redirects', async (t) => {
  const hits = [];
  const trap = http.createServer((req, res) => {
    hits.push(req.url);
    res.writeHead(500);
    res.end('trap');
  });
  const trapPort = await listen(trap);
  const main = http.createServer(async (req, res) => {
    await readReq(req);
    res.writeHead(302, { Location: 'http://127.0.0.1:' + trapPort + '/redirect-canary' });
    res.end();
  });
  const port = await listen(main);
  t.after(() => Promise.all([close(main), close(trap)]));
  const code = `
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("systemapi_conn_redir", os.environ["PLUGIN"])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PC:
    remote_addr = "host-1"

conn = mod.Connection(PC())
rc, out, err = conn.exec_command("uname")
sys.stdout.write(json.dumps({"rc": rc, "out": out.decode(), "err": err.decode()}))
`;
  const result = await python(['-c', code], {
    SYSTEMAPI_URL: 'http://127.0.0.1:' + port,
    SYSTEMAPI_API_KEY: KEY,
    SYSTEMAPI_TENANT: TENANT,
    PLUGIN
  });
  assert.equal(result.status, 0, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.rc, 1);
  assert.equal(body.out, '');
  assert.match(body.err, /redirect_rejected/);
  assert.equal(body.err.includes(KEY), false);
  assert.equal(body.err.includes('redirect-canary'), false);
  assert.equal(result.stderr.includes(KEY), false);
  assert.deepEqual(hits, []);
});
