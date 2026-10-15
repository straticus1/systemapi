'use strict';

// scripts/channel-policy.js against MemoryRegistry: the narrow host policy
// it writes, the decisions the ticket route then makes with it, the audit row,
// and every refusal (bad input, wrong tenant, ambiguous name, audit failure).

const test = require('node:test');
const assert = require('node:assert/strict');

const { MemoryRegistry, PgRegistry } = require('../controlplane/registry');
const { policyDecision } = require('../controlplane/channels');
const { run, parseArgs, ACTOR, MAX_ENTRIES, SYSTEM_ROOTS } = require('../scripts/channel-policy');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const HOST_B = '22222222-2222-4222-8222-222222222222';
const HOST_C = '33333333-3333-4333-8333-333333333333';
const PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

async function fixture() {
  const reg = new MemoryRegistry({});
  await reg.enroll({ tenantId: 'afterdark', userId: 'ryan', keyId: 'k1', hostId: HOST_A, hostname: 'miniapps1', sshPubkey: PUB });
  await reg.enroll({ tenantId: 'other', userId: 'mallory', keyId: 'k2', hostId: HOST_B, hostname: 'theirs', sshPubkey: PUB });
  return reg;
}

const SET = ['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42',
  '--tcp-local', '3003', '--file-write', '/var/tmp/sah-filetest'];

test('set writes a local-only TCP policy and one read-write root', async () => {
  const reg = await fixture();
  const out = await run(SET, { registry: reg });
  assert.equal(out.host_id, HOST_A);
  assert.deepEqual(out.host_tcp_policy, { allow: [{ local: true, ports: [3003] }] });
  assert.deepEqual(out.host_file_policy, { roots: [{ path: '/var/tmp/sah-filetest', read: true, write: true }] });
});

test('the ticket route then allows exactly that and nothing near it', async () => {
  const reg = await fixture();
  await run(SET, { registry: reg });
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: 'local', port: 3003 } }), null);
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: 'local', port: 3004 } }), 'target_denied');
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: '127.0.0.1', port: 3003 } }), 'bad_target');
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: '10.0.0.1', port: 3003 } }), 'target_denied');
  assert.equal(await policyDecision(reg, HOST_A, 'file:write', { root: '/var/tmp/sah-filetest' }), null);
  assert.equal(await policyDecision(reg, HOST_A, 'file:read', { root: '/var/tmp/sah-filetest/sub' }), null);
  assert.equal(await policyDecision(reg, HOST_A, 'file:write', { root: '/var/tmp' }), 'root_denied');
  assert.equal(await policyDecision(reg, HOST_A, 'file:write', { root: '/var/tmp/sah-filetest-evil' }), 'root_denied');
  assert.equal(await policyDecision(reg, HOST_A, 'file:root', { root: '/var/tmp/sah-filetest' }), 'root_denied');
  // The other tenant's host is untouched: still deny by default.
  assert.equal(await policyDecision(reg, HOST_B, 'tcp:open', { target: { host: 'local', port: 3003 } }), 'target_denied');
});

test('file-read gives read only; a dir named for both read and write is read-write', async () => {
  const reg = await fixture();
  const out = await run(['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42',
    '--file-read', '/srv/logs', '--file-read', '/srv/data', '--file-write', '/srv/data'], { registry: reg });
  assert.deepEqual(out.host_file_policy.roots, [
    { path: '/srv/data', read: true, write: true },
    { path: '/srv/logs', read: true, write: false }
  ]);
  assert.deepEqual(out.host_tcp_policy, { allow: [] });
  assert.equal(await policyDecision(reg, HOST_A, 'file:read', { root: '/srv/logs' }), null);
  assert.equal(await policyDecision(reg, HOST_A, 'file:write', { root: '/srv/logs' }), 'root_denied');
});

test('set replaces both columns; nothing from the earlier policy lingers', async () => {
  const reg = await fixture();
  await run(SET, { registry: reg });
  const out = await run(['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42', '--tcp-local', '8080'], { registry: reg });
  assert.deepEqual(out.host_tcp_policy, { allow: [{ local: true, ports: [8080] }] });
  assert.deepEqual(out.host_file_policy, { roots: [] });
  assert.equal(await policyDecision(reg, HOST_A, 'file:write', { root: '/var/tmp/sah-filetest' }), 'root_denied');
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: 'local', port: 3003 } }), 'target_denied');
});

test('every set, clear and inherit appends one audit row with the old and new policy', async () => {
  const reg = await fixture();
  await run(SET, { registry: reg });
  await run(['clear', '--tenant', 'afterdark', '--host', HOST_A, '--reason', 'ticket 42'], { registry: reg });
  await run(['inherit', '--tenant', 'afterdark', '--host', HOST_A, '--reason', 'ticket 42'], { registry: reg });
  const rows = reg.audit.filter((r) => r.actor === ACTOR);
  assert.equal(rows.length, 3);
  assert.equal(rows[0].action, 'channel_policy_set');
  assert.equal(rows[0].tenant_id, 'afterdark');
  assert.equal(rows[0].host_id, HOST_A);
  assert.deepEqual(rows[0].payload.tcp_policy, { allow: [{ local: true, ports: [3003] }] });
  assert.equal(rows[0].payload.previous_tcp_policy, null);
  assert.equal(rows[1].action, 'channel_policy_clear');
  assert.deepEqual(rows[1].payload.tcp_policy, { allow: [] });
  assert.deepEqual(rows[1].payload.file_policy, { roots: [] });
  assert.deepEqual(rows[1].payload.previous_file_policy, { roots: [{ path: '/var/tmp/sah-filetest', read: true, write: true }] });
  assert.equal(rows[2].action, 'channel_policy_inherit');
  assert.equal(rows[2].payload.tcp_policy, null);
  assert.equal(rows[2].payload.file_policy, null);
  assert.deepEqual(rows[2].payload.previous_tcp_policy, { allow: [] });
});

test('clear denies on the host even when a tenant default allows', async () => {
  const reg = await fixture();
  await reg.setTenantChannelPolicy('afterdark', {
    tcp_policy: { allow: [{ local: true, ports: [3003] }] },
    file_policy: { roots: [{ path: '/var/tmp/sah-filetest', read: true, write: true }] }
  });
  await run(SET, { registry: reg });
  const out = await run(['clear', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42'], { registry: reg });
  assert.deepEqual(out.host_tcp_policy, { allow: [] });
  assert.deepEqual(out.host_file_policy, { roots: [] });
  assert.deepEqual(out.effective_tcp_policy, { allow: [] });
  assert.deepEqual(out.effective_file_policy, { roots: [] });
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: 'local', port: 3003 } }), 'target_denied');
  assert.equal(await policyDecision(reg, HOST_A, 'file:read', { root: '/var/tmp/sah-filetest' }), 'root_denied');
});

test('inherit falls back to the tenant default, else deny', async () => {
  const reg = await fixture();
  await run(SET, { registry: reg });
  const out = await run(['inherit', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42'], { registry: reg });
  assert.equal(out.host_tcp_policy, null);
  assert.equal(out.host_file_policy, null);
  assert.deepEqual(out.effective_tcp_policy, { allow: [] });
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: 'local', port: 3003 } }), 'target_denied');
  await reg.setTenantChannelPolicy('afterdark', { tcp_policy: { allow: [{ local: true, ports: [3003] }] } });
  assert.equal(await policyDecision(reg, HOST_A, 'tcp:open', { target: { host: 'local', port: 3003 } }), null);
});

test('set, clear and inherit need --reason; it lands in the audit row with the actor', async () => {
  for (const command of ['set', 'clear', 'inherit']) {
    const argv = [command, '--tenant', 'afterdark', '--host', 'miniapps1', ...(command === 'set' ? ['--tcp-local', '3003'] : [])];
    assert.throws(() => parseArgs(argv), (err) => err.code === 'usage', `${command} without --reason`);
    for (const bad of ['', '   ', 'a\nb', 'tab\there', 'x'.repeat(257)]) {
      assert.throws(() => parseArgs([...argv, '--reason', bad]), (err) => err.code === 'usage', `${command} --reason ${JSON.stringify(bad)}`);
    }
    assert.throws(() => parseArgs([...argv, '--reason', 'a', '--reason', 'b']), (err) => err.code === 'usage');
  }
  assert.throws(() => parseArgs(['show', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'x']), (err) => err.code === 'usage');
  const reg = await fixture();
  await run([...SET.slice(0, 5), '--reason', '  CHG-1234 open the file test dir  ', ...SET.slice(7)], { registry: reg });
  const row = reg.audit.filter((r) => r.actor === ACTOR).pop();
  assert.equal(row.actor, 'cli:channel-policy');
  assert.equal(row.payload.reason, 'CHG-1234 open the file test dir');
});

test('show changes nothing and writes no audit row', async () => {
  const reg = await fixture();
  const auditBefore = reg.audit.length;
  const out = await run(['show', '--tenant', 'afterdark', '--host', 'miniapps1'], { registry: reg });
  assert.equal(out.host_tcp_policy, null);
  assert.deepEqual(out.effective_file_policy, { roots: [] });
  assert.equal(reg.audit.length, auditBefore);
});

test('a host of another tenant is not found and is left alone', async () => {
  const reg = await fixture();
  for (const host of ['theirs', HOST_B]) {
    await assert.rejects(run(['set', '--tenant', 'afterdark', '--host', host, '--reason', 'ticket 42', '--tcp-local', '22'], { registry: reg }),
      (err) => err.code === 'not_found');
  }
  const raw = await reg.channelPolicies(HOST_B);
  assert.equal(raw.host_tcp_policy, null);
  assert.equal(reg.audit.filter((r) => r.actor === ACTOR).length, 0);
});

test('a hostname shared by two hosts is ambiguous; the host id still works', async () => {
  const reg = await fixture();
  await reg.enroll({ tenantId: 'afterdark', userId: 'ryan', keyId: 'k1', hostId: HOST_C, hostname: 'MINIAPPS1', sshPubkey: PUB });
  await assert.rejects(run(SET, { registry: reg }), (err) => err.code === 'ambiguous');
  const out = await run(['set', '--tenant', 'afterdark', '--host', HOST_C, '--reason', 'ticket 42', '--tcp-local', '3003'], { registry: reg });
  assert.equal(out.host_id, HOST_C);
  assert.equal((await reg.channelPolicies(HOST_A)).host_tcp_policy, null);
});

test('an audit write that fails leaves the previous policy and fails', async () => {
  const reg = await fixture();
  await run(SET, { registry: reg });
  reg.appendAudit = async () => { throw new Error('disk full'); };
  await assert.rejects(run(['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42', '--tcp-local', '22'], { registry: reg }),
    (err) => err.code === 'write_failed');
  const raw = await reg.channelPolicies(HOST_A);
  assert.deepEqual(raw.host_tcp_policy, { allow: [{ local: true, ports: [3003] }] });
  assert.deepEqual(raw.host_file_policy, { roots: [{ path: '/var/tmp/sah-filetest', read: true, write: true }] });
});

// A pg client double that records every statement and can fail one.
function fakePool(failOn) {
  const log = [];
  let clients = 0;
  const pool = {
    log,
    get clients() { return clients; },
    async query() { throw new Error('the pool itself must not be queried'); },
    async connect() {
      clients += 1;
      const id = clients;
      return {
        async query(sql, params = []) {
          const q = sql.replace(/\s+/g, ' ').trim();
          log.push({ client: id, q, params });
          if (failOn && q.startsWith(failOn)) throw new Error('boom');
          if (q.startsWith('SELECT tcp_policy, file_policy FROM cp_hosts')) {
            return { rowCount: 1, rows: [{ tcp_policy: { allow: [{ local: true, ports: [3003] }] }, file_policy: null }] };
          }
          if (q.startsWith('SELECT row_hash FROM cp_audit')) return { rowCount: 0, rows: [] };
          return { rowCount: 1, rows: [{}] };
        },
        release() { log.push({ client: id, q: 'RELEASE' }); }
      };
    }
  };
  return pool;
}

test('PgRegistry writes the policy and its audit row in one transaction on one client', async () => {
  const pool = fakePool(null);
  const pg = new PgRegistry(pool, { NODE_ENV: 'production' });
  await pg.setHostChannelPolicyAudited({
    tenantId: 'afterdark', hostId: HOST_A, tcpPolicy: { allow: [] }, filePolicy: { roots: [] }, actor: ACTOR, action: 'channel_policy_clear', reason: 'why'
  });
  assert.equal(pool.clients, 1);
  const qs = pool.log.map((e) => e.q);
  assert.equal(qs[0], 'BEGIN');
  assert.match(qs[1], /^SELECT tcp_policy, file_policy FROM cp_hosts WHERE host_id = \$1 AND tenant_id = \$2 FOR UPDATE$/);
  assert.deepEqual(pool.log[1].params, [HOST_A, 'afterdark']);
  assert.match(qs[2], /^UPDATE cp_hosts SET tcp_policy = \$2::jsonb, file_policy = \$3::jsonb WHERE host_id = \$1$/);
  assert.match(qs[3], /^SELECT row_hash FROM cp_audit .*FOR UPDATE$/);
  assert.match(qs[4], /^INSERT INTO cp_audit/);
  const audit = JSON.parse(pool.log[4].params[6]);
  assert.deepEqual(audit.previous_tcp_policy, { allow: [{ local: true, ports: [3003] }] });
  assert.deepEqual(audit.tcp_policy, { allow: [] });
  assert.equal(audit.reason, 'why');
  assert.equal(pool.log[4].params[4], ACTOR);
  assert.deepEqual(qs.slice(5), ['COMMIT', 'RELEASE']);
});

test('PgRegistry rolls the policy back when its audit row fails', async () => {
  const pool = fakePool('INSERT INTO cp_audit');
  const pg = new PgRegistry(pool, { NODE_ENV: 'production' });
  await assert.rejects(pg.setHostChannelPolicyAudited({
    tenantId: 'afterdark', hostId: HOST_A, tcpPolicy: { allow: [] }, filePolicy: { roots: [] }, actor: ACTOR, action: 'channel_policy_clear'
  }), /boom/);
  const qs = pool.log.map((e) => e.q);
  assert.equal(pool.clients, 1);
  assert.equal(qs.includes('COMMIT'), false);
  assert.deepEqual(qs.slice(-2), ['ROLLBACK', 'RELEASE']);
});

test('a registry without the policy methods is refused', async () => {
  await assert.rejects(run(SET, { registry: {} }), (err) => err.code === 'registry_unavailable');
  await assert.rejects(run(SET, { registry: null }), (err) => err.code === 'registry_unavailable');
});

test('parseArgs refuses anything wider or malformed', () => {
  const base = ['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42'];
  const bad = [
    [],
    ['delete', '--tenant', 'afterdark', '--host', 'miniapps1'],
    ['set', '--tenant', 'afterdark'],
    ['set', '--host', 'miniapps1', '--tcp-local', '3003'],
    [...base],
    [...base, '--tcp-local'],
    [...base, '--tcp-local', '0'],
    [...base, '--tcp-local', '65536'],
    [...base, '--tcp-local', '03003'],
    [...base, '--tcp-local', '3003x'],
    [...base, '--tcp-local', '-1'],
    [...base, '--tcp-local', '1-100'],
    [...base, '--tcp-cidr', '10.0.0.0/8:22'],
    [...base, '--file-root', '/srv'],
    [...base, '--file-write', '/'],
    [...base, '--file-write', '~'],
    [...base, '--file-read', '~'],
    [...base, '--file-write', 'var/tmp/x'],
    [...base, '--file-write', '/var/tmp/../etc'],
    [...base, '--file-write', '/var/tmp/./x'],
    [...base, '--file-write', '/var//tmp'],
    [...base, '--file-write', '/var/tmp/'],
    [...base, '--file-write', '/var/tmp/a\nb'],
    [...base, '--file-write', '/var/tmp/\u0000x'],
    ['set', '--tenant', 'Afterdark', '--host', 'miniapps1', '--reason', 'ticket 42', '--tcp-local', '3003'],
    ['set', '--tenant', 'afterdark', '--tenant', 'other', '--host', 'miniapps1', '--tcp-local', '3003'],
    ['set', '--tenant', 'afterdark', '--host', 'mini apps1', '--reason', 'ticket 42', '--tcp-local', '3003'],
    ['set', '--tenant', 'afterdark', '--host', 'a/../b', '--reason', 'ticket 42', '--tcp-local', '3003'],
    ['show', '--tenant', 'afterdark', '--host', 'miniapps1', '--tcp-local', '3003'],
    ['clear', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42', '--file-write', '/srv'],
    ['inherit', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42', '--tcp-local', '22']
  ];
  for (const argv of bad) {
    assert.throws(() => parseArgs(argv), (err) => err.code === 'usage', JSON.stringify(argv));
  }
  const many = [...base];
  for (let p = 1; p <= MAX_ENTRIES + 1; p += 1) many.push('--tcp-local', String(p));
  assert.throws(() => parseArgs(many), (err) => err.code === 'usage');
  const dirs = [...base];
  for (let d = 0; d <= MAX_ENTRIES; d += 1) dirs.push('--file-read', `/srv/d${d}`);
  assert.throws(() => parseArgs(dirs), (err) => err.code === 'usage');
});

test('parseArgs refuses system roots, their contents, their parents and one-level directories', () => {
  const base = ['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42'];
  const refused = [
    ...SYSTEM_ROOTS,
    '/proc/1', '/sys/kernel', '/dev/shm', '/boot/efi', '/etc/ssh', '/root/.ssh',
    '/var/lib/systemapi-agent/state', '/etc/systemapi-agent/keys', '/var/lib/postgresql/16', '/etc/sahcore/env',
    '/var/lib', '/var', '/srv', '/home', '/opt', '/tmp'
  ];
  for (const dir of refused) {
    for (const flag of ['--file-read', '--file-write']) {
      assert.throws(() => parseArgs([...base, flag, dir]), (err) => err.code === 'usage', `${flag} ${dir}`);
    }
  }
  for (const dir of ['/srv/data', '/var/tmp/sah-filetest', '/var/lib/app', '/home/ops', '/etcetera/x', '/var/lib/postgresql-backup']) {
    assert.deepEqual(parseArgs([...base, '--file-read', dir]).filePolicy.roots, [{ path: dir, read: true, write: false }], dir);
  }
});

test('parseArgs de-duplicates and sorts ports', () => {
  const out = parseArgs(['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--reason', 'ticket 42',
    '--tcp-local', '8080', '--tcp-local', '3003', '--tcp-local', '8080']);
  assert.deepEqual(out.tcpPolicy, { allow: [{ local: true, ports: [3003, 8080] }] });
  assert.deepEqual(out.filePolicy, { roots: [] });
});

// main() in-process: env handling and what reaches stdout and stderr. A
// secret planted in the env must never be printed.
const { main } = require('../scripts/channel-policy');
const ENV_KEYS = ['ENV_FILE', 'DATABASE_URL', 'DB_PASSWORD', 'DB_HOST', 'DB_PORT', 'DB_SSL', 'DB_SSL_CA'];
const SECRET = 'hunter2-not-a-real-password';

async function runMain(argv, env) {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, env);
  const out = [];
  const err = [];
  const realError = console.error;
  console.error = (...args) => err.push(args.join(' '));
  const prevExit = process.exitCode;
  process.exitCode = undefined;
  try {
    await main(argv, { write(chunk) { out.push(String(chunk)); return true; } });
    return { out: out.join(''), err: err.join('\n'), exitCode: process.exitCode };
  } finally {
    process.exitCode = prevExit;
    console.error = realError;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('main: env and argument errors exit 2 with a short message and print no secret', async () => {
  const empty = await runMain(SET, { ENV_FILE: '  ', DB_PASSWORD: SECRET });
  assert.equal(empty.exitCode, 2);
  assert.match(empty.err, /ENV_FILE is set but empty/);

  const bad = await runMain(['set', '--tenant', 'afterdark', '--host', 'miniapps1', '--tcp-local', '3003'], { ENV_FILE: '/dev/null', DB_PASSWORD: SECRET });
  assert.equal(bad.exitCode, 2);
  assert.match(bad.err, /needs --reason/);

  const nodb = await runMain(SET, { ENV_FILE: '/dev/null' });
  assert.equal(nodb.exitCode, 2);
  assert.match(nodb.err, /no database configured/);

  for (const r of [empty, bad, nodb]) {
    assert.equal(r.out, '');
    assert.equal(r.err.includes(SECRET), false);
  }
});

test('main: a database that cannot be reached or configured fails with a code, never the credentials', async () => {
  const cases = [
    { ENV_FILE: '/dev/null', DATABASE_URL: `postgres://ops:${SECRET}@127.0.0.1:1/systemapi` },
    { ENV_FILE: '/dev/null', DB_PASSWORD: SECRET, DB_HOST: '127.0.0.1', DB_PORT: '1', DB_SSL: 'disable' },
    { ENV_FILE: '/dev/null', DB_PASSWORD: SECRET, DB_HOST: '127.0.0.1', DB_PORT: '1', DB_SSL_CA: '/nonexistent/ca.pem' }
  ];
  for (const env of cases) {
    const r = await runMain(SET, env);
    assert.equal(r.exitCode, 1, JSON.stringify(r));
    assert.match(r.err, /^channel-policy failed: [A-Za-z0-9_]+$/);
    assert.equal(r.err.includes(SECRET), false);
    assert.equal(r.out, '');
  }
});
