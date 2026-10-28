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
const { jobRetentionDays, jobOutputRetentionHours } = require('../controlplane/registry');
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
// is false. conn_id, the lease nonce and the send stamps stay internal.
function jobView(row, { output = true, visible = true } = {}) {
    const out = {
        job_id: row.job_id,
        tenant_id: row.tenant_id,
        host_id: row.host_id,
        actor: row.actor,
        source: row.source,
        status: row.status,
        error: row.error == null ? null : row.error,
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
        // Per accepted agent socket: "<instance>:<token>".
        this.connIds = new WeakMap();
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

    async security(hostId, kind, detail) {
        if (!this.fleet.registry) return;
        try {
            await this.fleet.registry.recordSecurity({
                kind,
                tenant_id: this.fleet.hostTenants.get(hostId) || null,
                actor_fingerprint: null,
                detail: { host_id: hostId, ...detail }
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

    localConnIds() {
        const out = [];
        for (const ws of this.fleet.connectedAgents.values()) {
            const id = this.connIds.get(ws);
            if (id && ws.readyState === WebSocket.OPEN) out.push(id);
        }
        return out;
    }

    // Runs fn on hostId's chain. A frame from the agent (ws set) counts
    // against the same item and byte caps as the terminal queue; over them
    // the agent is disconnected. Work the server starts is never refused.
    enqueue(hostId, fn, bytes = 0, ws = null) {
        let c = this.chains.get(hostId);
        if (!c) {
            c = { chain: Promise.resolve(), queued: 0, bytes: 0 };
            this.chains.set(hostId, c);
        }
        if (ws && (c.queued >= this.fleet.agentQueueMaxItems || c.bytes + bytes > this.fleet.agentQueueMaxBytes)) {
            this.rejected(hostId, 'flood');
            console.error('[Fleet] agent job queue over its cap; disconnecting the agent');
            ws.terminate();
            return;
        }
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
    onEnroll(ws, hostId, caps) {
        this.connIds.set(ws, `${this.instanceId}:${randomToken(16)}`);
        this.listen();
        const reg = this.fleet.registry;
        this.enqueue(hostId, async () => {
            if (reg && typeof reg.setAgentPresence === 'function') {
                await reg.setAgentPresence(hostId, [...(caps || [])], this.instanceId);
            }
            await this.pump(hostId);
        });
    }

    // The host's current socket closed on this instance.
    onClose(hostId) {
        const reg = this.fleet.registry;
        if (!reg || typeof reg.clearAgentPresence !== 'function') return;
        this.enqueue(hostId, () => reg.clearAgentPresence(hostId, this.instanceId));
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
    async deliverDispatch(hostId, jobId) {
        if (!this.capable(hostId)) return false;
        const ws = this.localSocket(hostId);
        const connId = this.connIds.get(ws);
        if (!connId) return false;
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
        const { severity, message } = payloadOf(msg);
        if (!ALERT_SEVERITIES.has(severity)) return this.rejected(hostId, 'bad_severity');
        if (typeof message !== 'string' || Buffer.byteLength(message, 'utf8') > ALERT_MESSAGE_MAX_BYTES) {
            return this.rejected(hostId, 'bad_message');
        }
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
        for (const jobId of listed) {
            const row = tenantId ? await reg.getJob([tenantId], jobId) : null;
            if (!row || row.host_id !== hostId) {
                sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason: 'unknown' });
                await this.security(hostId, 'job_unknown_on_sync', { job_id: jobId });
            } else if (TERMINAL.has(row.status)) {
                if (unacked.has(jobId)) sendJSON(ws, { type: 'sysscript_job_ack', job_id: jobId });
                if (active.has(jobId)) sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason: 'terminal' });
            } else if (row.cancel_requested_at) {
                if (sendJSON(ws, { type: 'sysscript_job_cancel', job_id: jobId, reason: 'user' })) {
                    await reg.markCancelSent(jobId, hostId);
                }
            }
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

    // Creates the job row (with its submit audit row and dispatch event) and
    // sends it here when this instance holds the socket. entitlements must
    // already be clamped for the principal; the same object is hashed into
    // the lease, stored and sent. Returns {job, deadlineUnix}.
    async submit({ host, actor, source, script, entitlements, timeoutS }) {
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
    cancelRequested(row) {
        if (!row || TERMINAL.has(row.status) || !row.conn_id || !this.capable(row.host_id)) return;
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
        const ended = await reg.sweepJobs(now, { connectedConnIds: this.localConnIds() });
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

module.exports = { SysscriptJobs, jobView, JOB_CAPABILITY, TERMINAL_JOB_STATUSES: TERMINAL };
