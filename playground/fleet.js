/**
 * SystemAPI.io fleet gateway.
 * Agents dial out. The control plane never opens an inbound SSH port.
 * Threats: query-string API keys, unsigned exec, and a demo key in production.
 * A missing lease is a refusal. This file does not store the API key.
 * Terminal sessions: one server-generated session id per socket; agent
 * output is routed only to the session that the same agent connection owns;
 * client frames over 64 KiB close with 1009; the server enforces
 * SYSTEMAPI_PTY_MAX_SECONDS and renews the lease every 30 s, so a dead server
 * lets the agent end the shell when the last lease lapses. Does NOT persist
 * tickets or sessions across restarts or between server nodes.
 */

const WebSocket = require('ws');
const axios = require('axios');
const crypto = require('node:crypto');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { demoKeyAllowed, agentAuthFromRequest, ticketFromRequest } = require('../controlplane/httpauth');
const { validateTenant, validateHostId, validateHostname, validateSSHPublicKey } = require('../controlplane/sshkey');
const { consumeTicket } = require('../controlplane/tickets');
const { issueLease, terminalPayload } = require('../controlplane/lease');
const { fingerprint, randomToken } = require('../controlplane/token');
const { zscore } = require('../controlplane/stats');
const { readPlaybook } = require('../controlplane/playbooks');
const { deliverWebhooks, COOLDOWN_MS } = require('../controlplane/router');

const PTY_FRAME_MAX = 64 * 1024;
const PTY_PENDING_MAX = 1024 * 1024;
const PTY_RENEW_MS = 30_000;
const PTY_LEASE_TTL_S = 60;
const PTY_MAX_SECONDS_DEFAULT = 28800;
const PTY_MAX_SECONDS_CAP = 7 * 86400;
const PURPOSE_ACTIONS = new Map([
    ['terminal:open', 'pty'],
    ['terminal:root', 'pty_root'],
    ['breakglass:open', 'breakglass']
]);
const PTY_ERRORS = new Set([
    'ticket_invalid', 'scope_denied', 'agent_offline', 'lease_required',
    'pty_user_unset', 'recording_unavailable', 'pty_start_failed', 'internal'
]);
const PTY_EXIT_REASONS = new Set(['exited', 'max_duration', 'stopped']);
const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function ptyMaxSeconds(env) {
    const raw = env && env.SYSTEMAPI_PTY_MAX_SECONDS;
    if (raw === undefined || raw === null || raw === '') return PTY_MAX_SECONDS_DEFAULT;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > PTY_MAX_SECONDS_CAP) {
        console.error('[Fleet] SYSTEMAPI_PTY_MAX_SECONDS is invalid; using the default');
        return PTY_MAX_SECONDS_DEFAULT;
    }
    return n;
}

// Returns the size, the fallback when absent, or null when invalid.
function sizeParam(params, name, fallback) {
    if (!params.has(name)) return fallback;
    const raw = params.get(name);
    if (!/^[0-9]{1,4}$/.test(raw)) return null;
    const n = Number(raw);
    return n >= 1 && n <= 1000 ? n : null;
}

function validSize(n) {
    return Number.isInteger(n) && n >= 1 && n <= 1000;
}

function sendJSON(ws, obj) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

class FleetManager {
    constructor(server, db, apiSite = 'systemapi', prometheusMetrics = null) {
        this.wss = new WebSocket.Server({ noServer: true });
        this.db = db;
        this.apiSite = apiSite;
        this.metrics = prometheusMetrics;
        this.connectedAgents = new Map();
        this.terminalSessions = new Map();
        this.terminalWss = new WebSocket.Server({ noServer: true, maxPayload: PTY_FRAME_MAX });
        this.ptyRenewMs = PTY_RENEW_MS;
        this.hostTenants = new Map();
        this.alertCooldown = new Map();
        this.pendingExecutions = new Map();
        this.signer = null;
        this.tickets = null;
        this.registry = null;
        this.env = process.env;

        const accessKey = process.env.DARKSTORAGE_ACCESS_KEY;
        const secretKey = process.env.DARKSTORAGE_SECRET_KEY;
        if (accessKey && secretKey) {
            this.darkStorage = new S3Client({
                region: 'us-east-1',
                endpoint: process.env.DARKSTORAGE_URL || 'http://127.0.0.1:9000',
                credentials: { accessKeyId: accessKey, secretAccessKey: secretKey },
                forcePathStyle: true
            });
        } else {
            this.darkStorage = null;
        }

        server.on('upgrade', (request, socket, head) => {
            this.handleUpgrade(request, socket, head).catch((err) => {
                console.error('[Fleet] upgrade failed:', err.message);
                if (!socket.destroyed) {
                    socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
                    socket.destroy();
                }
            });
        });

        this.wss.on('connection', this.handleConnection.bind(this));
    }

    rejectUpgrade(socket, status, reason) {
        socket.write(`HTTP/1.1 ${status} ${reason}\r\n\r\n`);
        socket.destroy();
    }

    async handleUpgrade(request, socket, head) {
        const parsed = new URL(request.url, 'http://127.0.0.1');
        if (parsed.pathname === '/api/v1/systems/stream') {
            await this.upgradeAgent(request, socket, head, parsed);
            return;
        }
        if (parsed.pathname.startsWith('/api/v1/systems/terminal/')) {
            await this.upgradeTerminal(request, socket, head, parsed);
            return;
        }
        this.rejectUpgrade(socket, 404, 'Not Found');
    }

    async upgradeAgent(request, socket, head, parsed) {
        const auth = agentAuthFromRequest(parsed, request.headers);
        if (!auth.ok) {
            this.rejectUpgrade(socket, auth.status, 'Unauthorized');
            return;
        }
        if (!this.registry) {
            this.rejectUpgrade(socket, 503, 'Unavailable');
            return;
        }
        const keyData = await this.verifyApiKey(auth.token);
        if (!keyData) {
            await this.noteSecurity('auth_fail', fingerprint(auth.token), { where: 'agent_upgrade' });
            this.rejectUpgrade(socket, 403, 'Forbidden');
            return;
        }
        let enroll;
        try {
            enroll = {
                tenant: validateTenant(request.headers['x-systemapi-tenant']),
                hostId: validateHostId(request.headers['x-systemapi-host-id']),
                hostname: validateHostname(request.headers['x-systemapi-hostname']),
                sshPubkey: validateSSHPublicKey(request.headers['x-systemapi-ssh-pubkey'])
            };
        } catch (err) {
            this.rejectUpgrade(socket, 401, 'Unauthorized');
            return;
        }
        request.systemapiEnroll = enroll;
        request.systemapiKey = keyData;
        this.wss.handleUpgrade(request, socket, head, (ws) => {
            this.wss.emit('connection', ws, request, keyData);
        });
    }

    async upgradeTerminal(request, socket, head, parsed) {
        if (parsed.searchParams.has('api_key')) {
            this.rejectUpgrade(socket, 401, 'Unauthorized');
            return;
        }
        const rows = sizeParam(parsed.searchParams, 'rows', 24);
        const cols = sizeParam(parsed.searchParams, 'cols', 80);
        if (rows === null || cols === null) {
            this.rejectUpgrade(socket, 400, 'Bad Request');
            return;
        }
        let hostId;
        try {
            hostId = decodeURIComponent(parsed.pathname.split('/').pop() || '');
        } catch {
            this.rejectUpgrade(socket, 400, 'Bad Request');
            return;
        }
        this.terminalWss.handleUpgrade(request, socket, head, (ws) => {
            try {
                this.openTerminal(ws, parsed, hostId, rows, cols);
            } catch (err) {
                console.error('[Fleet] terminal open failed:', err.message);
                this.failTerminalSocket(ws, 'internal');
            }
        });
    }

    failTerminalSocket(ws, code) {
        sendJSON(ws, { type: 'pty_status', payload: { error: code } });
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close(1011);
    }

    openTerminal(ws, parsed, hostId, rows, cols) {
        ws.on('error', (err) => console.error('[Fleet] terminal socket error:', err.message));
        const ticketRes = ticketFromRequest(parsed);
        const purpose = parsed.searchParams.get('purpose') || 'terminal:open';
        const action = PURPOSE_ACTIONS.get(purpose);
        if (!this.tickets) {
            this.failTerminalSocket(ws, 'internal');
            return;
        }
        if (!ticketRes.ok || !action) {
            this.failTerminalSocket(ws, 'ticket_invalid');
            return;
        }
        const row = consumeTicket(this.tickets, ticketRes.ticket, hostId, purpose);
        if (!row) {
            this.failTerminalSocket(ws, 'ticket_invalid');
            return;
        }
        if (!this.signer) {
            this.failTerminalSocket(ws, 'lease_required');
            return;
        }
        const agentWs = this.connectedAgents.get(hostId);
        if (!agentWs || agentWs.readyState !== WebSocket.OPEN) {
            this.failTerminalSocket(ws, 'agent_offline');
            return;
        }
        const sessionId = `pts_${randomToken(16)}`;
        const maxSeconds = ptyMaxSeconds(this.env);
        const startedMs = Date.now();
        const deadlineUnix = Math.floor(startedMs / 1000) + maxSeconds;
        const payload = terminalPayload(sessionId, deadlineUnix);
        let lease;
        try {
            lease = issueLease(this.signer, { hostId, action, payload, ttl: PTY_LEASE_TTL_S });
        } catch (err) {
            this.failTerminalSocket(ws, 'lease_required');
            return;
        }
        const session = {
            id: sessionId,
            hostId,
            tenantId: row.tenantId,
            actor: row.actor || null,
            purpose,
            action,
            payload,
            deadlineUnix,
            startedMs,
            client: ws,
            agent: agentWs,
            started: false,
            ended: false,
            announced: false,
            pending: [],
            pendingBytes: 0,
            ptyUser: null,
            recording: null,
            renewTimer: null,
            maxTimer: null
        };
        this.terminalSessions.set(sessionId, session);
        ws.on('message', (buf, isBinary) => this.onTerminalClientMessage(session, buf, isBinary));
        ws.on('close', () => this.endTerminal(session, 'client_closed', -1, { notifyAgent: true }));
        sendJSON(ws, { type: 'pty_status', payload: { status: 'starting' } });
        sendJSON(agentWs, {
            type: 'pty_start',
            session_id: sessionId,
            request_id: sessionId,
            action,
            rows,
            cols,
            deadline_unix: deadlineUnix,
            lease
        });
        session.renewTimer = setInterval(() => this.renewTerminal(session), this.ptyRenewMs);
        if (typeof session.renewTimer.unref === 'function') session.renewTimer.unref();
        session.maxTimer = setTimeout(() => {
            this.endTerminal(session, 'max_duration', -1, { notifyAgent: true, notifyClient: true });
        }, maxSeconds * 1000);
        if (typeof session.maxTimer.unref === 'function') session.maxTimer.unref();
    }

    renewTerminal(session) {
        if (session.ended || !this.signer) return;
        try {
            const lease = issueLease(this.signer, {
                hostId: session.hostId,
                action: session.action,
                payload: session.payload,
                ttl: PTY_LEASE_TTL_S
            });
            sendJSON(session.agent, { type: 'pty_renew', session_id: session.id, lease });
        } catch (err) {
            console.error('[Fleet] lease renewal failed:', err.message);
        }
    }

    onTerminalClientMessage(session, buf, isBinary) {
        if (session.ended || isBinary) return;
        const text = buf.toString();
        let cmd;
        try {
            cmd = JSON.parse(text);
        } catch {
            // Legacy browser clients sent raw text as input.
            sendJSON(session.agent, {
                type: 'pty_input',
                session_id: session.id,
                data_b64: Buffer.from(text, 'utf8').toString('base64')
            });
            return;
        }
        const type = cmd && typeof cmd === 'object' ? cmd.type : undefined;
        if (type === 'pty_input') {
            let b64 = null;
            if (typeof cmd.data_b64 === 'string') {
                if (B64_RE.test(cmd.data_b64)) b64 = cmd.data_b64;
            } else if (typeof cmd.data === 'string') {
                b64 = Buffer.from(cmd.data, 'utf8').toString('base64');
            }
            if (b64 === null) {
                console.warn(`[Fleet] terminal ${session.id}: malformed pty_input ignored`);
                return;
            }
            sendJSON(session.agent, { type: 'pty_input', session_id: session.id, data_b64: b64 });
        } else if (type === 'pty_resize') {
            if (!validSize(cmd.rows) || !validSize(cmd.cols)) {
                console.warn(`[Fleet] terminal ${session.id}: bad pty_resize ignored`);
                return;
            }
            sendJSON(session.agent, { type: 'pty_resize', session_id: session.id, rows: cmd.rows, cols: cmd.cols });
        } else if (type === 'pty_eof') {
            sendJSON(session.agent, { type: 'pty_eof', session_id: session.id });
        } else {
            const label = typeof type === 'string' ? type.replace(/[^A-Za-z0-9_:-]/g, '').slice(0, 32) : typeof type;
            console.warn(`[Fleet] terminal ${session.id}: unknown frame type ${label} ignored`);
        }
    }

    // Ends a session once. opts.error sends a pty_status error and closes 1011;
    // opts.notifyClient sends pty_exit and closes 1000.
    endTerminal(session, reason, code, opts = {}) {
        if (session.ended) return;
        session.ended = true;
        clearInterval(session.renewTimer);
        clearTimeout(session.maxTimer);
        this.terminalSessions.delete(session.id);
        if (opts.notifyAgent) sendJSON(session.agent, { type: 'pty_stop', session_id: session.id });
        if (opts.error) {
            this.failTerminalSocket(session.client, opts.error);
        } else if (opts.notifyClient && session.client.readyState === WebSocket.OPEN) {
            sendJSON(session.client, { type: 'pty_exit', payload: { session_id: session.id, code, reason } });
            session.client.close(1000);
        }
        this.auditTerminal(session, 'terminal_end', {
            session_id: session.id,
            purpose: session.purpose,
            reason,
            exit_code: code,
            started: session.started,
            duration_s: Math.round((Date.now() - session.startedMs) / 1000)
        }).catch((err) => console.error('[Fleet] terminal end audit failed:', err.message));
    }

    async auditTerminal(session, action, payload) {
        if (!this.registry) throw new Error('registry_unavailable');
        return this.registry.appendAudit({
            tenant_id: session.tenantId,
            host_id: session.hostId,
            actor: session.actor,
            action,
            payload
        });
    }

    // Returns the session only when this agent connection owns it.
    agentSession(ws, hostId, sessionId) {
        if (typeof sessionId !== 'string') return null;
        const session = this.terminalSessions.get(sessionId);
        if (!session || session.ended || session.agent !== ws || session.hostId !== hostId) return null;
        return session;
    }

    onAgentOutput(ws, hostId, buf) {
        if (!Buffer.isBuffer(buf) || buf.length < 1) return;
        const n = buf[0];
        if (buf.length < 1 + n) return;
        const session = this.agentSession(ws, hostId, buf.toString('latin1', 1, 1 + n));
        if (!session) return;
        const data = buf.subarray(1 + n);
        if (!session.announced) {
            // Output can arrive while the start audit row is being written.
            // Hold it so the client sees "started" first.
            session.pendingBytes += data.length;
            if (session.pendingBytes > PTY_PENDING_MAX) {
                this.endTerminal(session, 'internal', -1, { error: 'internal', notifyAgent: true });
                return;
            }
            session.pending.push(Buffer.from(data));
            return;
        }
        this.sendOutput(session, data);
    }

    // Output goes out in slices of at most 64 KiB; clients cap frames at 1 MiB.
    sendOutput(session, data) {
        for (let off = 0; off < data.length; off += PTY_FRAME_MAX) {
            if (session.client.readyState !== WebSocket.OPEN) return;
            session.client.send(data.subarray(off, off + PTY_FRAME_MAX));
        }
    }

    async onAgentPtyStatus(ws, hostId, msg) {
        const session = this.agentSession(ws, hostId, msg.session_id);
        if (!session) return;
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        if (payload.error) {
            const code = PTY_ERRORS.has(payload.error) ? payload.error : 'internal';
            this.endTerminal(session, code, -1, { error: code });
            return;
        }
        if (payload.status !== 'started' || session.started) return;
        session.started = true;
        session.ptyUser = typeof payload.pty_user === 'string' ? payload.pty_user.slice(0, 64) : null;
        session.recording = payload.recording === true;
        try {
            await this.auditTerminal(session, 'terminal_start', {
                session_id: session.id,
                purpose: session.purpose,
                pty_user: session.ptyUser,
                recording: session.recording
            });
        } catch (err) {
            console.error('[Fleet] terminal start audit failed:', err.message);
            this.endTerminal(session, 'internal', -1, { error: 'internal', notifyAgent: true });
            return;
        }
        if (session.ended) return;
        sendJSON(session.client, { type: 'pty_status', payload: { status: 'started', session_id: session.id } });
        session.announced = true;
        for (const chunk of session.pending) this.sendOutput(session, chunk);
        session.pending = [];
        session.pendingBytes = 0;
    }

    onAgentPtyExit(ws, hostId, msg) {
        const session = this.agentSession(ws, hostId, msg.session_id);
        if (!session) return;
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        const code = Number.isInteger(payload.code) ? payload.code : -1;
        const reason = PTY_EXIT_REASONS.has(payload.reason) ? payload.reason : 'exited';
        this.endTerminal(session, reason, code, { notifyClient: true });
    }

    async verifyApiKey(secretProvided) {
        if (typeof secretProvided !== 'string' || secretProvided.length === 0 || secretProvided.length > 512) {
            return null;
        }
        if (secretProvided === 'ak_live_1234.demo') {
            if (!demoKeyAllowed(this.env || process.env)) return null;
            return { key_id: 'ak_live_1234', user_id: 'demo_user' };
        }
        if (!this.db) return null;
        try {
            const parts = secretProvided.split('.');
            if (parts.length !== 2) return null;
            const keyId = parts[0];
            const res = await this.db.query(
                `SELECT key_id, user_id, key_hash FROM playground_api_keys
                 WHERE key_id = $1 AND api_site = $2 AND is_active = true AND is_locked = false`,
                [keyId, this.apiSite]
            );
            if (res.rows.length === 0) return null;
            const bcrypt = require('bcryptjs');
            const isValid = await bcrypt.compare(secretProvided, res.rows[0].key_hash);
            if (!isValid) return null;
            await this.db.query('UPDATE playground_api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_id = $1', [keyId]);
            return { key_id: res.rows[0].key_id, user_id: res.rows[0].user_id };
        } catch (err) {
            console.error('[Fleet] API key verification failed:', err.message);
            return null;
        }
    }

    async noteSecurity(kind, actorFingerprint, detail) {
        if (!this.registry) return;
        try {
            await this.registry.recordSecurity({ kind, actor_fingerprint: actorFingerprint, detail });
        } catch (err) {
            console.error('[Fleet] security event failed:', err.message);
        }
    }

    async handleConnection(ws, request, keyData) {
        const enroll = request.systemapiEnroll;
        const userId = keyData.user_id;
        const keyId = keyData.key_id;
        let hostId = null;
        // Terminal frames are handled in arrival order, even while a start
        // audit row is being written.
        let ptyChain = Promise.resolve();
        const inOrder = (fn) => {
            ptyChain = ptyChain.then(fn).catch((err) => console.error('[Fleet] terminal frame error:', err.message));
        };
        console.log(`[Fleet] Agent connected key fingerprint sha256:${fingerprint(keyId)}`);

        ws.on('message', async (messageBuffer, isBinary) => {
            try {
                if (isBinary) {
                    if (hostId) {
                        const id = hostId;
                        inOrder(() => this.onAgentOutput(ws, id, messageBuffer));
                    }
                    return;
                }
                const msg = JSON.parse(messageBuffer.toString());
                if (msg.type === 'telemetry') {
                    hostId = await this.handleTelemetry(keyId, userId, ws, msg.payload, hostId);
                } else if (msg.type === 'command_result') {
                    if (this.pendingExecutions && msg.request_id && this.pendingExecutions.has(msg.request_id)) {
                        const executionContext = this.pendingExecutions.get(msg.request_id);
                        this.logExecutionToDarkStorage(hostId, executionContext.script, msg.payload).catch((err) => {
                            console.error('[DarkStorage] audit write failed:', err.message);
                        });
                        executionContext.resolve(msg.payload);
                        this.pendingExecutions.delete(msg.request_id);
                    }
                } else if (msg.type === 'pty_status') {
                    const id = hostId;
                    if (id) inOrder(() => this.onAgentPtyStatus(ws, id, msg));
                } else if (msg.type === 'pty_exit') {
                    const id = hostId;
                    if (id) inOrder(() => this.onAgentPtyExit(ws, id, msg));
                } else if (msg.type === 'pty_renew_rejected') {
                    const raw = msg.payload && msg.payload.error;
                    const err = typeof raw === 'string' ? raw.replace(/[^a-z_]/g, '').slice(0, 64) : 'unknown';
                    console.warn(`[Fleet] agent rejected a lease renewal: ${err}`);
                }
            } catch (err) {
                console.error('[Fleet] message error:', err.message);
            }
        });

        ws.on('close', async () => {
            if (!hostId) return;
            if (this.connectedAgents.get(hostId) === ws) this.connectedAgents.delete(hostId);
            inOrder(() => {
                for (const session of [...this.terminalSessions.values()]) {
                    if (session.agent === ws) this.endTerminal(session, 'agent_disconnected', -1, { notifyClient: true });
                }
            });
            if (this.registry) {
                try { await this.registry.setHostStatus(hostId, 'offline'); } catch (err) {
                    console.error('[Fleet] status update failed:', err.message);
                }
            }
            if (this.db) {
                try {
                    await this.db.query(`UPDATE playground_hosts SET status = 'offline' WHERE host_id = $1`, [hostId]);
                } catch (err) {
                    console.error('[Fleet] legacy status update failed:', err.message);
                }
            }
        });

        const interval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) ws.ping();
            else clearInterval(interval);
        }, 30000);

        if (!this.signer) {
            ws.send(JSON.stringify({ type: 'enroll_error', error: 'signer_unavailable' }));
            ws.close();
            return;
        }
        if (!enroll || !this.registry) {
            ws.send(JSON.stringify({ type: 'enroll_error', error: 'enroll_required' }));
            ws.close();
            return;
        }
        try {
            const host = await this.registry.enroll({
                tenantId: enroll.tenant,
                userId,
                keyId,
                hostId: enroll.hostId,
                hostname: enroll.hostname,
                os: '',
                platform: '',
                sshPubkey: enroll.sshPubkey
            });
            hostId = host.host_id;
            this.hostTenants.set(hostId, host.tenant_id);
            this.connectedAgents.set(hostId, ws);
            ws.send(JSON.stringify({
                type: 'enrolled',
                host_id: hostId,
                control_pubkey: this.signer.publicKeyB64
            }));
        } catch (err) {
            await this.noteSecurity('enroll_rejected', fingerprint(keyId), { error: err.code || 'enroll_failed' });
            ws.send(JSON.stringify({ type: 'enroll_error', error: err.code || 'enroll_failed' }));
            ws.close();
        }
    }

    async handleTelemetry(keyId, userId, ws, payload, hostId) {
        if (!hostId || !this.registry) return hostId;
        const hostInfo = (payload && payload.host) || {};
        try {
            await this.registry.touchHost(hostId, {
                hostname: hostInfo.hostname,
                os: hostInfo.os,
                platform: hostInfo.platform
            });
        } catch (err) {
            console.error('[Fleet] touch failed:', err.message);
        }
        this.exportTelemetryToPrometheus(hostId, payload);
        await this.recordTelemetry(hostId, payload);
        await this.analyzeForAnomalies(hostId, payload);
        await this.evaluateRules(userId, hostId, payload);
        if (payload && Array.isArray(payload.software) && payload.software.length > 0) {
            this.processSoftwareInventory(hostId, payload.software).catch((err) => {
                console.error('[Software Inventory]', err.message);
            });
        }
        if (this.redis) {
            this.redis.publish('systemapi:telemetry', JSON.stringify({ host_id: hostId })).catch((err) => {
                console.error('[control] redis publish failed:', err.message);
            });
        }
        return hostId;
    }

    async recordTelemetry(hostId, telemetry) {
        if (!this.registry || !telemetry) return;
        if (telemetry.cpu && typeof telemetry.cpu.usage_percent === 'number') {
            await this.registry.recordMetric(hostId, 'cpu.usage_percent', telemetry.cpu.usage_percent);
        }
        if (telemetry.memory && typeof telemetry.memory.used_percent === 'number') {
            await this.registry.recordMetric(hostId, 'memory.used_percent', telemetry.memory.used_percent);
        }
        if (Array.isArray(telemetry.disk)) {
            for (const disk of telemetry.disk) {
                if (typeof disk.used_percent === 'number') {
                    await this.registry.recordMetric(hostId, 'disk.used_percent', disk.used_percent, { path: String(disk.path || '') });
                }
            }
        }
    }

    exportTelemetryToPrometheus(hostId, telemetry) {
        if (!this.metrics || !telemetry) return;
        const hostname = telemetry.host && telemetry.host.hostname ? telemetry.host.hostname : 'unknown';
        try {
            if (telemetry.cpu && typeof telemetry.cpu.usage_percent === 'number') {
                this.metrics.cpuUsageGauge.labels(hostId, hostname).set(telemetry.cpu.usage_percent);
            }
            if (telemetry.memory && typeof telemetry.memory.used_percent === 'number') {
                this.metrics.memoryUsageGauge.labels(hostId, hostname).set(telemetry.memory.used_percent);
            }
            if (Array.isArray(telemetry.disk)) {
                telemetry.disk.forEach((disk) => {
                    if (typeof disk.used_percent === 'number') {
                        this.metrics.diskUsageGauge.labels(hostId, hostname, disk.path || '/').set(disk.used_percent);
                    }
                });
            }
        } catch (err) {
            console.error('[Prometheus]', err.message);
        }
    }

    cooled(hostId, rule) {
        const key = `${rule}:${hostId}`;
        const prev = this.alertCooldown.get(key) || 0;
        if (Date.now() - prev < COOLDOWN_MS) return true;
        this.alertCooldown.set(key, Date.now());
        return false;
    }

    async analyzeForAnomalies(hostId, telemetry) {
        if (!this.registry || !telemetry) return;
        const checks = [
            ['cpu.usage_percent', telemetry.cpu && telemetry.cpu.usage_percent],
            ['memory.used_percent', telemetry.memory && telemetry.memory.used_percent]
        ];
        for (const [metric, value] of checks) {
            if (typeof value !== 'number') continue;
            const series = await this.registry.metricSeries(hostId, metric, 60);
            const score = zscore(series.map((point) => point.value));
            if (!score.anomalous) continue;
            const rule = `zscore:${metric}`;
            if (this.cooled(hostId, rule)) continue;
            if (await this.registry.recentAlert(hostId, rule, COOLDOWN_MS)) continue;
            const tenantId = this.hostTenants.get(hostId);
            if (!tenantId) continue;
            const alert = await this.registry.openAlert({
                tenant_id: tenantId,
                host_id: hostId,
                rule_name: rule,
                metric,
                value
            });
            await deliverWebhooks(this, tenantId, { type: 'anomaly', alert_id: alert.id, host_id: hostId, metric, value });
        }
    }

    async evaluateRules(userId, hostId, telemetry) {
        if (!this.db || !telemetry) return;
        try {
            const res = await this.db.query(
                `SELECT alert_id, metric, operator, threshold_value, action_type, action_target, name
                 FROM playground_alerts
                 WHERE user_id = $1 AND api_site = $2 AND is_active = true`,
                [userId, this.apiSite]
            );
            for (const rule of res.rows) this.checkRule(userId, hostId, telemetry, rule);
        } catch (err) {
            console.error('[Fleet] rule lookup failed:', err.message);
        }
    }

    checkRule(userId, hostId, telemetry, rule) {
        let valueToTest = null;
        if (rule.metric === 'cpu.usage_percent') valueToTest = telemetry.cpu && telemetry.cpu.usage_percent;
        if (rule.metric === 'memory.used_percent') valueToTest = telemetry.memory && telemetry.memory.used_percent;
        if (typeof valueToTest !== 'number') return;
        const threshold = parseFloat(rule.threshold_value);
        let triggered = false;
        if (rule.operator === '>') triggered = valueToTest > threshold;
        if (rule.operator === '<') triggered = valueToTest < threshold;
        if (rule.operator === '=') triggered = valueToTest === threshold;
        if (triggered) {
            const hostname = telemetry.host && telemetry.host.hostname;
            this.triggerIncident(rule, valueToTest, hostId, hostname);
        }
    }

    async triggerIncident(rule, actualValue, hostId, hostname) {
        const ruleName = rule.name || rule.metric;
        if (this.cooled(hostId, `rule:${ruleName}`)) return;
        const message = `[SystemAPI.io Incident] Alert '${ruleName}' triggered on ${hostname || hostId}. Metric was ${Number(actualValue).toFixed(2)}.`;
        console.log(`[ALERT] ${ruleName} on ${hostId}`);
        if (rule.action_type === 'sms') await this.sendAdstelcoSMS(rule.action_target, message);
        else if (rule.action_type === 'voice') await this.sendAdstelcoVoice(rule.action_target, message);
        else if (rule.action_type === 'playbook') await this.dispatchPlaybook(rule.action_target, hostId);
    }

    async dispatchPlaybook(playbookId, hostId) {
        let script;
        try {
            script = readPlaybook(playbookId);
        } catch (err) {
            console.error('[PLAYBOOK] refused:', err.message);
            return;
        }
        if (!this.signer) {
            console.error('[PLAYBOOK] signer unavailable');
            return;
        }
        const lease = issueLease(this.signer, { hostId, action: 'sysscript', payload: script, ttl: 60 });
        await this.pushSysscript(hostId, script, {
            allow_exec: true,
            allow_fs_write: false,
            allow_fs_read: false,
            allow_net_outbound: false,
            allow_config_write: false,
            allow_service_reload: false,
            allow_containers: false,
            allow_k3s: false
        }, randomToken(16), lease);
    }

    async sendAdstelcoSMS(toPhone, body) {
        if (!process.env.ADSTELCO_KEY) return;
        try {
            await axios.post(
                'http://127.0.0.1:3000/api/v1/sms/send',
                { to: toPhone, body },
                { headers: { Authorization: `Bearer ${process.env.ADSTELCO_KEY}` }, timeout: 5000, maxRedirects: 0 }
            );
        } catch (err) {
            console.error('[adstelco] SMS send failed:', err.message);
        }
    }

    async sendAdstelcoVoice(toPhone, message) {
        if (!process.env.ADSTELCO_KEY) return;
        try {
            await axios.post(
                'http://127.0.0.1:3000/api/v1/voice/call',
                { to: toPhone, tts_message: message },
                { headers: { Authorization: `Bearer ${process.env.ADSTELCO_KEY}` }, timeout: 5000, maxRedirects: 0 }
            );
        } catch (err) {
            console.error('[adstelco] voice call failed:', err.message);
        }
    }

    async logExecutionToDarkStorage(hostId, script, resultPayload) {
        const hash = crypto.createHash('sha256').update(String(script)).digest('hex');
        if (this.registry && hostId) {
            await this.registry.appendAudit({
                tenant_id: this.hostTenants.get(hostId) || null,
                host_id: hostId,
                actor: 'agent',
                action: 'command_result',
                payload: { script_sha256: hash }
            });
        }
        if (!this.darkStorage || !hostId) return;
        const timestamp = new Date().toISOString();
        const command = new PutObjectCommand({
            Bucket: 'systemapi-audits',
            Key: `sysscript-audits/${hostId}/${timestamp}-${hash.substring(0, 8)}.json`,
            Body: JSON.stringify({ host_id: hostId, timestamp, script_sha256: hash }),
            ContentType: 'application/json'
        });
        await this.darkStorage.send(command);
    }

    async processSoftwareInventory(hostId, softwareList) {
        if (!this.registry) return;
        for (const sw of softwareList) {
            if (!sw || typeof sw !== 'object') continue;
            const saved = await this.registry.upsertSoftware(hostId, sw);
            if (saved.inserted) await this.checkDarkAPIForCVEs(hostId, sw.name || 'unknown', sw.version || 'unknown');
        }
    }

    async checkDarkAPIForCVEs(hostId, name, version) {
        if (!process.env.DARKAPI_KEY) return;
        const darkUrl = process.env.DARKAPI_URL || 'https://api.darkapi.io';
        try {
            const response = await axios.get(
                `${darkUrl}/v1/cve/software/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
                { headers: { 'X-API-Key': process.env.DARKAPI_KEY }, timeout: 5000, maxRedirects: 0 }
            );
            const vulnerabilities = (response.data && response.data.cves) || [];
            for (const vuln of vulnerabilities) {
                if (!vuln || typeof vuln.id !== 'string') continue;
                await this.registry.saveCVE({
                    host_id: hostId,
                    software_name: name,
                    software_version: version,
                    cve_id: vuln.id,
                    severity: vuln.severity,
                    description: vuln.description
                });
            }
        } catch (err) {
            console.error('[DarkAPI] CVE lookup failed:', err.message);
        }
    }

    pushSysscript(hostId, script, entitlements, requestId, lease) {
        return new Promise((resolve, reject) => {
            if (!lease || typeof lease.signature !== 'string') {
                reject(Object.assign(new Error('lease_required'), { status: 503, code: 'lease_required' }));
                return;
            }
            const ws = this.connectedAgents.get(hostId);
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                reject(Object.assign(new Error('agent_offline'), { status: 409, code: 'agent_offline' }));
                return;
            }
            this.pendingExecutions.set(requestId, { resolve, reject, script });
            setTimeout(() => {
                if (this.pendingExecutions.has(requestId)) {
                    this.pendingExecutions.get(requestId).reject(Object.assign(new Error('agent_timeout'), { status: 504, code: 'agent_timeout' }));
                    this.pendingExecutions.delete(requestId);
                }
            }, 30000);
            ws.send(JSON.stringify({
                type: 'sysscript',
                script,
                entitlements: entitlements || {},
                request_id: requestId,
                lease
            }));
        });
    }
}

module.exports = FleetManager;
