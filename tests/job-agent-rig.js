'use strict';

// Shared by tests/sysscript-jobs.test.js and tests/registry-pg.test.js: an
// HTTP + WebSocket rig around a FleetManager, and a fake agent that
// advertises sysscript_jobs, answers enrolled with a sysscript_job_sync,
// and checks every sysscript_job frame it receives the way the Go agent
// does: the sysscript_job lease against the control key, with the payload
// rebuilt from the frame (job id, deadline, timeout, script hash and the
// canonical entitlements hash of the entitlements in the frame).

const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const WebSocket = require('ws');

const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { verifyLease, sysscriptJobPayload, convergeJobPayload, sha256Hex } = require('../controlplane/lease');
const { entitlementsSha256 } = require('../controlplane/entitlements');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');

function opensshEd25519(raw32) {
  const name = Buffer.from('ssh-ed25519');
  const buf = Buffer.alloc(4 + name.length + 4 + 32);
  buf.writeUInt32BE(name.length, 0);
  name.copy(buf, 4);
  buf.writeUInt32BE(32, 4 + name.length);
  raw32.copy(buf, 4 + name.length + 4);
  return `ssh-ed25519 ${buf.toString('base64')} test@systemapi`;
}

async function waitUntil(what, fn, timeout = 4000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

function signer() {
  const key = privateKeyFromSeed(TEST_SEED);
  return buildSigner(key, rawPublicKey(key));
}

// keys: { presented key: { key_id, user_id } }.
async function rig({ registry, keys, env = {} }) {
  const app = express();
  app.use(express.json({ limit: '2mb' }));
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test', ...env };
  fm.signer = signer();
  fm.tickets = new Map();
  fm.agentPingMs = 50;
  fm.registry = registry;
  fm.verifyApiKey = async (k) => keys[k] || null;
  mount(app, fm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const sockets = [];
  return {
    fm,
    url: `http://127.0.0.1:${port}`,
    ws: `ws://127.0.0.1:${port}`,
    track(ws) { sockets.push(ws); return ws; },
    async api(method, path, key, body) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`, {
        method,
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
        body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body))
      });
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { json = { raw: text }; }
      return { status: res.status, body: json };
    },
    async close() {
      fm.jobs.stop();
      for (const ws of sockets) ws.terminate();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}

// A fake agent. sync is what it lists on enrolled ({active, unacked}),
// resend the result frames it sends again right after the sync, as the Go
// agent does for unacked results.
async function connectAgent(r, hostId, opts = {}) {
  const {
    tenant = 'acme', key = 'agent-key', caps = 'sysscript_jobs', sync = { active: [], unacked: [] }, resend = [],
    onOpen = null, waitEnrolled = true
  } = opts;
  const headers = {
    authorization: `Bearer ${key}`,
    'x-systemapi-tenant': tenant,
    'x-systemapi-host-id': hostId,
    'x-systemapi-hostname': `${hostId.slice(0, 4)}.example`,
    'x-systemapi-ssh-pubkey': opensshEd25519(r.fm.signer.publicKeyRaw)
  };
  if (caps) headers['x-systemapi-capabilities'] = caps;
  const ws = r.track(new WebSocket(`${r.ws}/api/v1/systems/stream`, { headers }));
  const pub = crypto.createPublicKey(r.fm.signer.privateKey);
  const agent = {
    ws,
    hostId,
    frames: [],
    jobs: new Map(),
    send(obj) { ws.send(typeof obj === 'string' ? obj : JSON.stringify(obj)); },
    status(jobId, payload) { this.send({ type: 'sysscript_job_status', job_id: jobId, payload }); },
    result(jobId, payload) {
      this.send({ type: 'sysscript_job_result', job_id: jobId, payload: { error: '', output: '', output_truncated: false, duration_ms: 5, ...payload } });
    },
    alert(jobId, payload) { this.send({ type: 'sysscript_alert', job_id: jobId, payload }); },
    of(type, jobId) { return this.frames.filter((f) => f.type === type && (jobId === undefined || f.job_id === jobId)); },
    async waitFor(type, jobId, timeout) {
      return waitUntil(`${type} ${jobId || ''}`, () => this.of(type, jobId)[0], timeout);
    },
    async waitJob(jobId, timeout) {
      return waitUntil(`sysscript_job ${jobId || ''}`, () => {
        if (jobId) return this.jobs.get(jobId);
        return [...this.jobs.values()][0];
      }, timeout);
    }
  };
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    const f = JSON.parse(data.toString());
    agent.frames.push(f);
    if (f.type === 'enrolled') {
      agent.send({ type: 'sysscript_job_sync', payload: sync });
      for (const frame of resend) agent.send(frame);
    }
    if (f.type === 'sysscript_job') {
      let check;
      // A converge frame (kind converge) is checked as the Go agent does:
      // a converge_job lease over the bundle, mode and plan hash.
      const converge = f.kind === 'converge';
      try {
        const fields = {
          jobId: f.job_id,
          deadlineUnix: f.deadline_unix,
          timeoutS: f.timeout_s,
          entitlementsSha256: entitlementsSha256(f.entitlements)
        };
        const payload = converge
          ? convergeJobPayload({ ...fields, bundleSha256: sha256Hex(Buffer.from(f.bundle_json, 'utf8')), mode: f.mode, expectPlanSha256: f.expect_plan_sha256 })
          : sysscriptJobPayload({ ...fields, scriptSha256: sha256Hex(Buffer.from(f.script, 'utf8')) });
        check = verifyLease(pub, f.lease, payload);
        const action = converge ? 'converge_job' : 'sysscript_job';
        if (check.ok && (f.lease.host_id !== hostId || f.lease.action !== action)) check = { ok: false, error: 'bad_host' };
      } catch (err) {
        check = { ok: false, error: err.message };
      }
      agent.jobs.set(f.job_id, { frame: f, lease: check });
    }
  });
  ws.on('error', () => {});
  if (onOpen) ws.on('open', () => onOpen(agent));
  if (waitEnrolled) await waitUntil('enrolled', () => agent.frames.find((f) => f.type === 'enrolled' || f.type === 'enroll_error'));
  return agent;
}

module.exports = { rig, connectAgent, waitUntil, opensshEd25519 };
