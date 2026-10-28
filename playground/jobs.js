/**
 * Async sysscript jobs, server engine (.omc/plans/async-sysscript-jobs.md
 * §6): submit, dispatch and cancel delivery, the agent's job frames, sync
 * reconciliation and the sweepers. The routes are in controlplane/router.js;
 * the rows, transitions and job events are in controlplane/registry.js.
 *
 * Threats: a job frame from one host settling another host's job (host_id
 * comes from the enrolled connection and is in every registry WHERE; a
 * frame for a job of another host, or an unknown job, changes nothing, is
 * not acked and writes a security event), a frame before enroll (dropped by
 * the caller), a rejection ending a job the agent already accepted (a
 * rejected result only moves a job out of submitted), a terminal row
 * rewritten (registry transitions only leave non-terminal statuses), a
 * result lost between the agent and the database (ack only after the row
 * is written, or when it is already terminal; the agent keeps the result
 * until then and re-sends it after every sync), job frames reordered (one
 * ordered chain per host, separate from terminal frames, capped like the
 * terminal queue: an agent that floods it is disconnected), entitlements
 * changed between signing and sending (the frame carries the dispatch
 * payload exactly as hashed into the lease), and a job sent twice by two
 * replicas (markDispatched claims the payload once). Dispatch and cancel
 * reach the agent from whichever instance holds its socket, through the
 * registry's job events (Postgres LISTEN/NOTIFY) with a pendingForHosts
 * scan every tick as the fallback.
 * Does NOT decide who may submit, read or cancel (router.js does), and does
 * NOT keep the script after dispatch (only its hash stays on the row).
 */
'use strict';

const WebSocket = require('ws');
const { issueLease, sysscriptJobPayload, sha256Hex, SYSSCRIPT_JOB_RE } = require('../controlplane/lease');
const { entitlementsSha256 } = require('../controlplane/entitlements');
const { jobRetentionDays, jobOutputRetentionHours, noNul, truncateUtf8 } = require('../controlplane/registry');
const { randomToken } = require('../controlplane/token');

const JOB_CAPABILITY = 'sysscript_jobs';
const ACTIVE = ['submitted', 'accepted', 'running'];
const TERMINAL = new Set(['succeeded', 'failed', 'cancelled', 'timed_out']);
const RESULT_STATUSES = new Set([...TERMINAL, 'rejected']);
const ALERT_SEVERITIES = new Set(['info', 'warning', 'critical']);
const ALERT_MESSAGE_MAX_BYTES = 4096;
const ALERTS_PER_JOB_MAX = 20;
const SYNC_IDS_MAX = 1024;
const ERROR_CODE_RE = /^[a-z_]{1,64}$/;
const JOB_LEASE_TTL_S = 60;
// Security events from job frames, per host: at most this many a minute;
// the next event that gets through carries the suppressed count.
const JOB_SECURITY_PER_MIN = 10;
// Never rate limited: a frame for another host's job.
const JOB_SECURITY_UNLIMITED = new Set(['job_frame_host_mismatch']);
// A host whose job chain has been busy this long no longer holds off the
// ack-timeout sweep.
const JOB_CHAIN_BUSY_GRACE_MS = 15000;
const SYNC_EVENT_IDS_MAX = 16;
// The agent's scriptMaxBytes (systemapi-agent/pty.go).
const SCRIPT_MAX_BYTES = 64 * 1024;

// SYSTEMAPI_SYSSCRIPT_JOBS: on unless it is "0". Off, the /jobs routes
// answer 503 jobs_disabled and every legacy caller stays on pushSysscript.
function jobsEnabled(env) {
    const raw = env && env.SYSTEMAPI_SYSSCRIPT_JOBS;
    return String(raw === undefined || raw === null || raw === '' ? '1' : raw).trim() !== '0';
}

function http(status, code) {
    const err = new Error(code);
    err.status = status;
    err.code = code;
    return err;
}

function sendJSON(ws, obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify(obj));
    return true;
}

function isJobId(id) {
    return typeof id === 'string' && SYSSCRIPT_JOB_RE.test(id);
}

function payloadOf(msg) {
    return msg && msg.payload && typeof msg.payload === 'object' && !Array.isArray(msg.payload) ? msg.payload : {};
}

function unixOf(value) {
    if (value == null) return null;
    const ms = new Date(value).getTime();
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

function isoOf(value) {
    if (value == null) return null;
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

// The API shape of a job row. Without output the key is left out (lists);
// with output not visible to this principal it is null and output_visible
// is false. The agent's error text can carry script output, so it is shown
// in full only alongside visible output; otherwise only a code-shaped error
// (or agent_error). conn_id, the lease nonce and the send stamps stay
// internal.
function jobView(row, { output = true, visible = true } = {}) {
    const full = output && visible;
    let error = row.error == null ? null : row.error;
    if (error !== null && !full && !ERROR_CODE_RE.test(error)) error = 'agent_error';
    const out = {
        job_id: row.job_id,
        tenant_id: row.tenant_id,
        host_id: row.host_id,
        actor: row.actor,
        source: row.source,
        status: row.status,
        error,
        timeout_s: row.timeout_s,
        deadline_unix: unixOf(row.deadline_at),
        script_sha256: row.script_sha256,
        entitlements_sha256: row.entitlements_sha256,
        alert_count: row.alert_count || 0,
        output_truncated: row.output_truncated === true,
        output_expired: row.output_expired === true,
        cancel_requested_at: isoOf(row.cancel_requested_at),
        created_at: isoOf(row.created_at),
        accepted_at: isoOf(row.accepted_at),
        started_at: isoOf(row.started_at),
        finished_at: isoOf(row.finished_at),
        duration_ms: row.duration_ms == null ? null : row.duration_ms
    };
    if (output) {
        out.output_visible = visible;
        out.output = visible && row.output != null ? row.output : null;
    }
    return out;
}

class SysscriptJobs {
    constructor(fleet) {
        this.fleet = fleet;
        // Written on the row (agent_instance) and into every conn_id.
        this.instanceId = randomToken(16);
        // Per accepted agent socket: "<instance>:<token>", and when it
        // enrolled (cp_hosts.agent_enrolled_at).
        this.connIds = new WeakMap();
        this.enrolledAt = new WeakMap();
        // Per host, per kind: the security event rate window.
        this.securityRate = new Map();
        // Per host: the ordered chain of job frames and job deliveries.
        this.chains = new Map();
        // Per job id: the wait_s waiters woken by state events.
        this.waiters = new Map();
        // The registry whose job events this instance listens to.
        this.listening = null;
        this.unlisten = null;
        // False disables the job event listener (tests of the fallback scan).
        this.events = true;
    }

    // Subscribes to the registry's job events once per registry. Returns
    // the listener's ready promise, or null when there is nothing to listen to.
    listen() {
        const reg = this.fleet.registry;
        if (!this.events || !reg || typeof reg.onJobEvent !== 'function') return null;
        if (this.listening === reg) return this.unlisten.ready;
        if (this.unlisten) this.unlisten();
        this.listening = reg;
        this.unlisten = reg.onJobEvent((evt) => this.onEvent(evt));
        return this.unlisten.ready;
    }

    stop() {
        if (this.unlisten) this.unlisten();
        this.unlisten = null;
        this.listening = null;
    }

    metric(name, labels) {
        const m = this.fleet.metrics && this.fleet.metrics[name];
        if (m && typeof m.inc === 'function') m.inc(labels);
    }

    rejected(hostId, reason) {
        console.error(`[Fleet] job frame rejected host=${hostId} reason=${reason}`);
        this.metric('jobFrameRejectedTotal', { reason });
    }

    // Null when hostId is over JOB_SECURITY_PER_MIN of kind this minute
    // (counted as suppressed), else the count suppressed since the last
    // event of that kind written.
    securityAllowed(hostId, kind) {
        if (JOB_SECURITY_UNLIMITED.has(kind)) return 0;
        const now = Date.now();
        let kinds = this.securityRate.get(hostId);
        if (!kinds) {
            kinds = new Map();
            this.securityRate.set(hostId, kinds);
        }
        let s = kinds.get(kind);
        if (!s || now - s.start >= 60000) {
            s = { start: now, n: 0, suppressed: s ? s.suppressed : 0 };
            kinds.set(kind, s);
        }
        if (s.n >= JOB_SECURITY_PER_MIN) {
            s.suppressed += 1;
            return null;
        }
        s.n += 1;
        const suppressed = s.suppressed;
        s.suppressed = 0;
        return suppressed;
    }

    async security(hostId, kind, detail) {
        if (!this.fleet.registry) return;
        const suppressed = this.securityAllowed(hostId, kind);
        if (suppressed === null) return;
        try {
            await this.fleet.registry.recordSecurity({
                kind,
                tenant_id: this.fleet.hostTenants.get(hostId) || null,
                actor_fingerprint: null,
                detail: { host_id: hostId, ...detail, ...(suppressed > 0 ? { suppressed } : {}) }
            });
        } catch (err) {
            console.error('[Fleet] security event failed:', err.message);
        }
    }

    localSocket(hostId) {
        const ws = this.fleet.connectedAgents.get(hostId);
        return ws && ws.readyState === WebSocket.OPEN ? ws : null;
    }

    // True when this instance holds hostId's socket and its agent
    // advertised sysscript_jobs.
    capable(hostId) {
        return !!this.localSocket(hostId) && this.fleet.agentSupports(hostId, JOB_CAPABILITY);
    }

    // The conn_ids of sockets held here, except a host whose job chain has
    // been busy for less than JOB_CHAIN_BUSY_GRACE_MS: its queued frames may
    // hold the ack the sweep would time out. A chain busy longer than that
    // no longer holds the sweep off.
    localConnIds(now = Date.now()) {
        const out = [];
        for (const [hostId, ws] of this.fleet.connectedAgents) {
            const id = this.connIds.get(ws);
            const c = this.chains.get(hostId);
            const busy = c && c.queued > 0 && now - c.busySince < JOB_CHAIN_BUSY_GRACE_MS;
            if (id && ws.readyState === WebSocket.OPEN && !busy) out.push(id);
        }
        return out;
    }

    async assertPresence(hostId, ws) {
        const reg = this.fleet.registry;
        const connId = this.connIds.get(ws);
        if (!reg || typeof reg.setAgentPresence !== 'function' || !connId) return false;
        return reg.setAgentPresence(hostId, {
            caps: [...(this.fleet.agentCaps.get(ws) || [])],
            instance: this.instanceId,
            connId,
            enrolledAt: this.enrolledAt.get(ws)
        });
    }

    // Runs fn on hostId's chain. A frame from the agent (ws set) counts
    // against the same item and byte caps as the terminal queue; over them
    // the agent is disconnected. Work the server starts is never refused.
    enqueue(hostId, fn, bytes = 0, ws = null) {
        let c = this.chains.get(hostId);
        if (!c) {
            c = { chain: Promise.resolve(), queued: 0, bytes: 0, busySince: 0 };
            this.chains.set(hostId, c);
        }
        if (ws && (c.queued >= this.fleet.agentQueueMaxItems || c.bytes + bytes > this.fleet.agentQueueMaxBytes)) {
            this.rejected(hostId, 'flood');
            console.error('[Fleet] agent job queue over its cap; disconnecting the agent');
            ws.terminate();
            return;
        }
        if (c.queued === 0) c.busySince = Date.now();
        c.queued += 1;
        c.bytes += bytes;
        c.chain = c.chain.then(fn).catch((err) => console.error('[Fleet] job frame error:', err.message)).finally(() => {
            c.queued -= 1;
            c.bytes -= bytes;
            if (c.queued === 0 && !this.fleet.connectedAgents.has(hostId) && this.chains.get(hostId) === c) {
                this.chains.delete(hostId);
            }
        });
    }

    // An accepted agent socket: its conn_id, the host's agent_caps and
    // agent_instance, then any dispatch or cancel waiting for it.
    onEnroll(ws, hostId) {
        this.connIds.set(ws, `${this.instanceId}:${randomToken(16)}`);
        this.enrolledAt.set(ws, new Date());
        this.listen();
        this.enqueue(hostId, async () => {
            await this.assertPresence(hostId, ws);
            await this.pump(hostId);
        });
    }

    // The host's current socket closed on this instance: its presence row is
    // cleared if it is still this socket's.
    onClose(ws, hostId) {
        this.securityRate.delete(hostId);
        const reg = this.fleet.registry;
        const connId = this.connIds.get(ws);
        if (!reg || typeof reg.clearAgentPresence !== 'function' || !connId) return;
        this.enqueue(hostId, () => reg.clearAgentPresence(hostId, connId));
    }

    onEvent(evt) {
        if (evt.k === 'state') {
            this.wake(evt.job_id);
            return;
        }
        const hostId = evt.host_id;
        if (!this.capable(hostId)) return;
        if (evt.k === 'dispatch') this.enqueue(hostId, () => this.deliverDispatch(hostId, evt.job_id));
        else if (evt.k === 'cancel') this.enqueue(hostId, () => this.deliverCancel(hostId, evt.job_id));
    }

    // Sends the job to the host's agent if this instance can claim its
    // dispatch payload. The frame carries the payload exactly as stored at
    // submit, the entitlements object the lease hashed included. True when
    // sent.
    // Only the socket named in cp_hosts (the newest enroll) is sent jobs, so
    // a duplicate agent on another instance never takes one.
    async deliverDispatch(hostId, jobId) {
        if (!this.capable(hostId)) return false;
        const ws = this.localSocket(hostId);
        const connId = this.connIds.get(ws);
        if (!connId) return false;
        const reg = this.fleet.registry;
        if (typeof reg.hostAgent === 'function') {
            const agent = await reg.hostAgent(hostId);
            if (!agent || agent.conn_id !== connId) return false;
        }
        const claimed = await this.fleet.registry.markDispatched(jobId, hostId, connId);
        if (!claimed || !claimed.dispatch) return false;
        const d = claimed.dispatch;
        const sent = sendJSON(ws, {
            type: 'sysscript_job',
            job_id: jobId,
            script: d.script,
            entitlements: d.entitlements,
            deadline_unix: d.deadline_unix,
            timeout_s: d.timeout_s,
            lease: d.lease
        });
        // A socket that closed after the claim: the row carries its conn_id,
        // so the next sync ends it agent_lost_job (or the deadline sweep does).
        if (!sent) console.error(`[Fleet] sysscript job ${jobId} lost its socket at dispatch`);
        return sent;
    }

    async deliverCancel(hostId, jobId, reason = 'user') {
        const ws = this.localSocket(hostId);
        if (!ws || !sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason })) return false;
        await this.fleet.registry.markCancelSent(jobId, hostId);
        return true;
    }

    // The dispatches and cancels waiting for hostId, delivered here.
    // Returns how many frames were sent.
    async pump(hostId) {
        if (!this.capable(hostId)) return 0;
        const rows = await this.fleet.registry.pendingForHosts([hostId]);
        let sent = 0;
        for (const row of rows) {
            if (row.dispatch_pending && await this.deliverDispatch(hostId, row.job_id)) sent += 1;
            if (row.cancel_pending && await this.deliverCancel(hostId, row.job_id)) sent += 1;
        }
        return sent;
    }

    onAgentFrame(ws, hostId, msg, bytes) {
        this.enqueue(hostId, () => this.handleFrame(ws, hostId, msg), bytes, ws);
    }

    async handleFrame(ws, hostId, msg) {
        if (!this.fleet.registry) return;
        if (msg.type === 'sysscript_job_status') await this.onStatus(ws, hostId, msg);
        else if (msg.type === 'sysscript_job_result') await this.onResult(ws, hostId, msg);
        else if (msg.type === 'sysscript_job_sync') await this.onSync(ws, hostId, msg);
        else if (msg.type === 'sysscript_alert') await this.onAlert(hostId, msg);
    }

    // The row of jobId if it is this host's. An unknown id, or one of
    // another host, is null with a security event.
    async ownRow(hostId, jobId) {
        const tenantId = this.fleet.hostTenants.get(hostId);
        const row = tenantId ? await this.fleet.registry.getJob([tenantId], jobId) : null;
        if (!row) {
            await this.security(hostId, 'job_frame_unknown', { job_id: jobId });
            return null;
        }
        if (row.host_id !== hostId) {
            await this.security(hostId, 'job_frame_host_mismatch', { job_id: jobId });
            return null;
        }
        return row;
    }

    async onStatus(ws, hostId, msg) {
        const jobId = msg.job_id;
        if (!isJobId(jobId)) return this.rejected(hostId, 'bad_job_id');
        const status = payloadOf(msg).status;
        let from;
        if (status === 'accepted') from = ['submitted'];
        else if (status === 'running') from = ['submitted', 'accepted'];
        else return this.rejected(hostId, 'bad_status');
        const row = await this.fleet.registry.transitionJob(jobId, hostId, from, { status });
        if (row) return undefined;
        const cur = await this.ownRow(hostId, jobId);
        // The server already ended this job (a sweep): stop the agent's copy.
        if (cur && TERMINAL.has(cur.status)) sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason: 'terminal' });
        return undefined;
    }

    // A result is acked once its row is written, or when the row is already
    // terminal (a re-send). A rejection only ends a job still submitted.
    async onResult(ws, hostId, msg) {
        const jobId = msg.job_id;
        if (!isJobId(jobId)) return this.rejected(hostId, 'bad_job_id');
        const p = payloadOf(msg);
        if (!RESULT_STATUSES.has(p.status)) return this.rejected(hostId, 'bad_status');
        const reg = this.fleet.registry;
        if (p.status === 'rejected') {
            const code = typeof p.error === 'string' && ERROR_CODE_RE.test(p.error) ? p.error : 'agent_rejected';
            const row = await reg.transitionJob(jobId, hostId, ['submitted'], { status: 'failed', error: code },
                { audit: { actor: 'agent' }, notify: true });
            if (row) {
                this.ended(row);
                return undefined;
            }
            const cur = await this.ownRow(hostId, jobId);
            if (cur) this.rejected(hostId, `late_reject_${cur.status}`);
            return undefined;
        }
        const row = await reg.transitionJob(jobId, hostId, ACTIVE, {
            status: p.status,
            error: typeof p.error === 'string' && p.error !== '' ? p.error : null,
            output: typeof p.output === 'string' ? p.output : null,
            output_truncated: p.output_truncated === true,
            duration_ms: Number.isInteger(p.duration_ms) ? p.duration_ms : null
        }, { audit: { actor: 'agent' }, notify: true });
        if (row) {
            sendJSON(ws, { type: 'sysscript_job_ack', job_id: jobId });
            this.ended(row);
            return undefined;
        }
        const cur = await this.ownRow(hostId, jobId);
        if (cur && TERMINAL.has(cur.status)) sendJSON(ws, { type: 'sysscript_job_ack', job_id: jobId });
        return undefined;
    }

    // sys.alerts.push from a job: at most ALERTS_PER_JOB_MAX per job,
    // counted in the row (bumpJobAlert), only while it is accepted or
    // running on this host.
    async onAlert(hostId, msg) {
        const jobId = msg.job_id;
        if (!isJobId(jobId)) return this.rejected(hostId, 'bad_job_id');
        const { severity } = payloadOf(msg);
        const raw = payloadOf(msg).message;
        if (!ALERT_SEVERITIES.has(severity)) return this.rejected(hostId, 'bad_severity');
        if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > ALERT_MESSAGE_MAX_BYTES) {
            return this.rejected(hostId, 'bad_message');
        }
        const message = truncateUtf8(noNul(raw), ALERT_MESSAGE_MAX_BYTES);
        const reg = this.fleet.registry;
        const bump = await reg.bumpJobAlert(jobId, hostId, ALERTS_PER_JOB_MAX);
        if (!bump.ok) return this.rejected(hostId, bump.reason);
        const tenantId = this.fleet.hostTenants.get(hostId);
        if (!tenantId || tenantId !== bump.tenant_id) return this.rejected(hostId, 'no_tenant');
        const alert = await reg.openAlert({
            tenant_id: tenantId,
            host_id: hostId,
            rule_name: 'sysscript',
            metric: null,
            value: null,
            severity,
            message
        });
        await reg.appendAudit({
            tenant_id: tenantId,
            host_id: hostId,
            actor: 'agent',
            action: 'sysscript_alert',
            payload: { alert_id: alert.id, job_id: jobId, severity }
        });
        console.log(`[Fleet] sysscript alert host=${hostId} severity=${severity} alert_id=${alert.id} job=${jobId}`);
        return undefined;
    }

    // sysscript_job_sync (§6.1): for each listed id, cancel it when unknown
    // (security event) or terminal-but-active, ack it when terminal and
    // unacked, re-send a requested cancel; then end this host's rows sent on
    // another connection that the agent no longer lists, and deliver what
    // is pending.
    async onSync(ws, hostId, msg) {
        const p = payloadOf(msg);
        if (!Array.isArray(p.active) || !Array.isArray(p.unacked) || p.active.length + p.unacked.length > SYNC_IDS_MAX) {
            return this.rejected(hostId, 'bad_sync');
        }
        const connId = this.connIds.get(ws);
        if (!connId) return this.rejected(hostId, 'no_conn');
        const active = new Set(p.active.filter(isJobId));
        const unacked = new Set(p.unacked.map((e) => e && e.job_id).filter(isJobId));
        const listed = new Set([...active, ...unacked]);
        const reg = this.fleet.registry;
        const tenantId = this.fleet.hostTenants.get(hostId);
        const unknown = [];
        for (const jobId of listed) {
            const row = tenantId ? await reg.getJob([tenantId], jobId) : null;
            if (!row || row.host_id !== hostId) {
                sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason: 'unknown' });
                unknown.push(jobId);
            } else if (TERMINAL.has(row.status)) {
                if (unacked.has(jobId)) sendJSON(ws, { type: 'sysscript_job_ack', job_id: jobId });
                if (active.has(jobId)) sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason: 'terminal' });
            } else if (row.cancel_requested_at) {
                if (sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason: 'user' })) {
                    await reg.markCancelSent(jobId, hostId);
                }
            }
        }
        // One event per sync, however many ids it names.
        if (unknown.length > 0) {
            await this.security(hostId, 'job_unknown_on_sync', { count: unknown.length, job_ids: unknown.slice(0, SYNC_EVENT_IDS_MAX) });
        }
        const ended = await reg.reconcileHostJobs(hostId, connId, [...listed]);
        for (const row of ended) this.ended(row);
        await this.pump(hostId);
        return undefined;
    }

    // A job reached a terminal status through this instance.
    ended(row) {
        console.log(`[Fleet] sysscript job ${row.job_id} ended status=${row.status} host=${row.host_id}`);
        this.metric('sysscriptJobsTotal', { status: row.status, source: row.source });
        if (typeof this.fleet.putDarkStorageAudit === 'function') {
            this.fleet.putDarkStorageAudit(row.host_id, row.script_sha256).catch((err) => {
                console.error('[DarkStorage] audit write failed:', err.message);
            });
        }
    }

    wake(jobId) {
        const set = this.waiters.get(jobId);
        if (!set) return;
        for (const fn of [...set]) fn();
    }

    // Resolves with the row once it is terminal, or with the latest row
    // (null if not found) after ms. Woken by state events; reads the row
    // once more at the end in case an event was missed.
    waitFor(tenantIds, jobId, ms) {
        this.listen();
        const reg = this.fleet.registry;
        return new Promise((resolve) => {
            let settled = false;
            let timer = null;
            const finish = (row) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                const set = this.waiters.get(jobId);
                if (set) {
                    set.delete(check);
                    if (set.size === 0) this.waiters.delete(jobId);
                }
                resolve(row);
            };
            function check() {
                reg.getJob(tenantIds, jobId).then((row) => {
                    if (row && TERMINAL.has(row.status)) finish(row);
                }, (err) => console.error('[Fleet] job wait read failed:', err.message));
            }
            if (!this.waiters.has(jobId)) this.waiters.set(jobId, new Set());
            this.waiters.get(jobId).add(check);
            timer = setTimeout(() => {
                reg.getJob(tenantIds, jobId).then(finish, (err) => {
                    console.error('[Fleet] job wait read failed:', err.message);
                    finish(null);
                });
            }, ms);
            check();
        });
    }

    // 409 agent_offline or 501 agent_unsupported unless hostId's agent is
    // connected (here, or on the instance named in cp_hosts) and advertised
    // sysscript_jobs.
    async requireAgent(hostId) {
        if (this.localSocket(hostId)) {
            if (typeof this.fleet.agentSupports === 'function' && this.fleet.agentSupports(hostId, JOB_CAPABILITY)) return;
            throw http(501, 'agent_unsupported');
        }
        const reg = this.fleet.registry;
        const agent = reg && typeof reg.hostAgent === 'function' ? await reg.hostAgent(hostId) : null;
        if (!agent) throw http(409, 'agent_offline');
        if (!agent.caps.includes(JOB_CAPABILITY)) throw http(501, 'agent_unsupported');
    }

    // The legacy callers (/execute, /fleet/execute, playbooks, the scheduler
    // and rule playbooks) submit a job only when this is true: the kill
    // switch is on and hostId's agent advertised sysscript_jobs, on the
    // socket held here or, for a socket on another instance, in cp_hosts.
    // Anything else, an old agent or an offline one, stays on pushSysscript.
    async useJobs(hostId) {
        if (!jobsEnabled(this.fleet.env)) return false;
        if (this.localSocket(hostId)) {
            return typeof this.fleet.agentSupports === 'function' && this.fleet.agentSupports(hostId, JOB_CAPABILITY);
        }
        const reg = this.fleet.registry;
        const agent = reg && typeof reg.hostAgent === 'function' ? await reg.hostAgent(hostId) : null;
        return !!agent && agent.caps.includes(JOB_CAPABILITY);
    }

    // Creates the job row (with its submit audit row and dispatch event) and
    // sends it here when this instance holds the socket. entitlements must
    // already be clamped for the principal; the same object is hashed into
    // the lease, stored and sent. Returns {job, deadlineUnix}.
    async submit({ host, actor, source, script, entitlements, timeoutS }) {
        // U+0000 cannot be stored in the dispatch JSONB.
        if (typeof script !== 'string' || script.length === 0 || !script.isWellFormed() || script.includes('\u0000')
            || Buffer.byteLength(script, 'utf8') > SCRIPT_MAX_BYTES) {
            throw http(400, 'bad_script');
        }
        const signer = this.fleet.signer;
        if (!signer) throw http(503, 'signer_unavailable');
        const ents = entitlements || {};
        const entSha = entitlementsSha256(ents);
        const scriptSha = sha256Hex(Buffer.from(script, 'utf8'));
        const jobId = `sjb_${randomToken(16)}`;
        const deadlineUnix = Math.floor(Date.now() / 1000) + timeoutS;
        const lease = issueLease(signer, {
            hostId: host.host_id,
            action: 'sysscript_job',
            payload: sysscriptJobPayload({ jobId, deadlineUnix, timeoutS, scriptSha256: scriptSha, entitlementsSha256: entSha }),
            ttl: JOB_LEASE_TTL_S
        });
        this.listen();
        const job = await this.fleet.registry.createJob({
            job_id: jobId,
            tenant_id: host.tenant_id,
            host_id: host.host_id,
            actor: String(actor),
            source,
            script_sha256: scriptSha,
            entitlements_sha256: entSha,
            entitlements: ents,
            timeout_s: timeoutS,
            deadline_at: new Date(deadlineUnix * 1000),
            lease_nonce: lease.nonce_hex,
            dispatch: { script, entitlements: ents, lease, deadline_unix: deadlineUnix, timeout_s: timeoutS }
        });
        if (this.capable(host.host_id)) this.enqueue(host.host_id, () => this.deliverDispatch(host.host_id, jobId));
        return { job, deadlineUnix };
    }

    // After a cancel request: delivered here at once when this instance
    // holds the socket (the cancel event covers the others).
    // A job never dispatched ended right there (cancelled_before_dispatch).
    cancelRequested(row) {
        if (!row) return;
        if (TERMINAL.has(row.status)) {
            this.ended(row);
            return;
        }
        if (!row.conn_id || !this.capable(row.host_id)) return;
        this.enqueue(row.host_id, () => this.deliverCancel(row.host_id, row.job_id));
    }

    // Every instance, every tick: end overdue rows (ack timeout only for
    // sockets held here), expire output, prune old rows, then the fallback
    // scan for this instance's hosts. now only moves MemoryRegistry's
    // cutoffs (tests); PgRegistry uses the database clock.
    async tick(now = Date.now()) {
        const reg = this.fleet.registry;
        if (!reg || typeof reg.sweepJobs !== 'function') return;
        this.listen();
        const ended = await reg.sweepJobs(now, { connectedConnIds: this.localConnIds(Date.now()) });
        // Re-assert presence for the sockets held here (heals a row a lost
        // write left stale); an older enroll than the stored one is refused.
        // After the sweep, so this queued work does not hold off its ack check.
        for (const [hostId, ws] of this.fleet.connectedAgents) {
            if (ws.readyState === WebSocket.OPEN && this.connIds.has(ws)) {
                this.enqueue(hostId, () => this.assertPresence(hostId, ws));
            }
        }
        for (const row of ended) this.ended(row);
        const env = this.fleet.env || {};
        await reg.expireOutput(jobOutputRetentionHours(env));
        await reg.pruneJobs(jobRetentionDays(env));
        const hosts = [...this.fleet.connectedAgents.keys()].filter((hostId) => this.capable(hostId));
        if (hosts.length === 0) return;
        const byHost = new Set((await reg.pendingForHosts(hosts)).map((row) => row.host_id));
        for (const hostId of byHost) {
            this.enqueue(hostId, async () => {
                const sent = await this.pump(hostId);
                if (sent > 0) this.metric('jobNotifyFallbackTotal');
            });
        }
    }
}

module.exports = { SysscriptJobs, jobView, jobsEnabled, JOB_CAPABILITY, TERMINAL_JOB_STATUSES: TERMINAL };
