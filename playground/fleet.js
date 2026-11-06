/**
 * SystemAPI.io fleet gateway.
 * Agents dial out. The control plane never opens an inbound SSH port.
 * Threats: query-string API keys, unsigned exec, and a demo key in production.
 * A missing lease is a refusal. This file does not store the API key.
 * A sash login grant is signed with SASH_GRANT_ED25519_SEED when that seed is
 * set; the seed is never logged, a malformed seed refuses the session, and an
 * unset seed omits the grant.
 * Terminal sessions: one server-generated session id per socket; agent
 * output is routed only to the session that the same agent connection owns;
 * client frames over 64 KiB close with 1009; a client whose send buffer
 * passes SYSTEMAPI_PTY_CLIENT_BUFFER_MAX (8 MiB) is ended, and an agent that
 * floods its terminal queue is disconnected; SYSTEMAPI_PTY_MAX_PER_ACTOR (8)
 * caps live sessions per actor; the server enforces SYSTEMAPI_PTY_MAX_SECONDS,
 * gives a start 30 s, and renews the lease every 30 s, so a dead server lets
 * the agent end the shell when the last lease lapses. A root shell must
 * report agent recording. Does NOT persist tickets or sessions across
 * restarts or between server nodes. TCP-forward and file channel sessions
 * live in playground/tcp.js and playground/file.js (with their own Threats
 * notes); this file routes their
 * upgrade path, agent frames and binary data, and ends them when the agent
 * connection drops. Session watching (§7.2) lives in playground/watch.js;
 * this file routes watch tickets on the terminal path, watch_consent frames
 * and the session's output to its watchers. Async sysscript jobs live in
 * playground/jobs.js (with its own Threats note); this file routes their
 * agent frames (only after enroll) to it and tells it about enroll and close.
 * One live agent per host: a second connection for a host whose agent is
 * connected (it already passed enroll, so it holds the same key and SSH public
 * key) wins only when the live socket fails a ping probe
 * (SYSTEMAPI_AGENT_PROBE_MS, 5 s); while the live agent answers, the newcomer
 * gets enroll_error host_connected (today's agent treats that as fatal and
 * exits; systemd's Restart=on-failure retries in 30 s). An agent reconnecting
 * after a network drop gets in once the server's half-open socket stops
 * answering. Does NOT prove
 * the newcomer holds the SSH private key: with the real agent offline, a
 * stolen API key plus the (public) host key still enrolls.
 * A key whose playground_api_keys.tenant_id is set enrolls only into that
 * tenant (enroll_error key_tenant_mismatch otherwise).
 * A revoked key loses its live agents: the /playground/api-keys delete and
 * lock routes call closeAgentsForKey, and every ping (30 s) re-checks
 * registry.keyActive for the socket's key, so a key expired, locked or
 * deleted by any other path is caught within one ping; a check that errors
 * twice in a row also closes. Each close is code 4403 with an audit row.
 * A retired host (POST /api/v1/hosts/:host_id/retire with force) loses its
 * live agent the same way: close 4403 "host_retired" (retireAgent), and the
 * registry refuses that host_id's re-enroll as host_retired.
 * Capability health (controlplane/capabilities.js, with its own Threats
 * note): capability_report frames count only after enroll, one write at a
 * time per socket (writes for one host queue behind each other, across
 * sockets) and at least 60 s apart; refused or dropped ones are counted (a
 * report dropped because our own write is still running is never a
 * violation), and 10
 * within 10 min close the socket 1008. Routing uses the dial header minus the
 * degraded header minus what reports on this connection withdraw; a report
 * never adds a capability. Health is self-reported: it detects breakage, NOT
 * compromise.
 */

const WebSocket = require('ws');
const axios = require('axios');
const crypto = require('node:crypto');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { demoKeyAllowed, agentAuthFromRequest, ticketFromRequest, originAllowed } = require('../controlplane/httpauth');
const { validateTenant, validateHostId, validateHostname, validateSSHPublicKey } = require('../controlplane/sshkey');
const { consumeTicket } = require('../controlplane/tickets');
const { errName: anchorErrName } = require('../controlplane/anchor');
const { issueLease, terminalPayload } = require('../controlplane/lease');
const { fingerprint, randomToken } = require('../controlplane/token');
const { zscore } = require('../controlplane/stats');
const { readPlaybook } = require('../controlplane/playbooks');
const { parseCapabilities, effectivePolicies } = require('../controlplane/channels');
const { buildSashTerminalGrant } = require('../controlplane/sashgrant');
const {
    validateCapabilityReport, ConnectionCapabilities, expectedCapabilities, hostHealth, KNOWN_CAPABILITIES, CAPABILITY_STATES
} = require('../controlplane/capabilities');
const { CapabilityAlerts } = require('../controlplane/capalerts');
const {
    normalizeSoftwareInventory, SOFTWARE_REFRESH_MS, SOFTWARE_MIN_WRITE_GAP_MS, SOFTWARE_RETRY_MS, SOFTWARE_MAX_CONCURRENT
} = require('../controlplane/software');
const { CreditLedger } = require('../controlplane/credit');
const { deliverWebhooks, COOLDOWN_MS } = require('../controlplane/router');
const { TcpChannels } = require('./tcp');
const { MeshChannels } = require('./mesh');
const { FileChannels } = require('./file');
const { SysChannels } = require('./sys');
const { XferGrants } = require('./xfer');
const { TerminalWatches } = require('./watch');
const { SysscriptJobs } = require('./jobs');
// What a background failure logs: the error's code, never its message
// (which may carry agent text).
function errorCode(err) {
    return err && typeof err.code === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(err.code) ? err.code : 'internal';
}
// The whole-script deadline of a rule playbook sent as a job.
const RULE_JOB_TIMEOUT_S = 300;
const { noNul, truncateUtf8 } = require('../controlplane/registry');
const { rejectUpgrade } = require('./channel');

const PTY_FRAME_MAX = 64 * 1024;
const PTY_PENDING_MAX = 1024 * 1024;
const PTY_HELD_INPUT_MAX = 256 * 1024;
const PTY_CLIENT_BUFFER_DEFAULT = 8 * 1024 * 1024;
const PTY_PER_ACTOR_DEFAULT = 8;
const PTY_START_TIMEOUT_MS = 30_000;
const PTY_FINAL_WAIT_MS = 5_000;
const AGENT_FRAME_MAX = 4 * 1024 * 1024;
const AGENT_QUEUE_MAX_ITEMS = 4096;
const AGENT_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const RECORDING_MODES = new Set(['agent', 'user_owned', 'off']);
const PTY_RENEW_MS = 30_000;
const PTY_LEASE_TTL_S = 60;
const PTY_MAX_SECONDS_DEFAULT = 28800;
const PTY_MAX_SECONDS_CAP = 7 * 86400;
const AGENT_PROBE_MS_DEFAULT = 5000;
const AGENT_PING_MS = 30_000;
const AGENT_REVOKED_CLOSE = 4403;
const AGENT_CLOSE_GRACE_MS = 2000;
// capability_report frames (controlplane/capabilities.js): per host, one in
// flight and at least CAP_REPORT_GAP_MS apart; CAP_VIOLATION_MAX refused or
// dropped frames within CAP_VIOLATION_WINDOW_MS close the socket 1008.
const CAP_REPORT_GAP_MS = 60_000;
// Slack on the gap (5 s at the 60 s gap, a twelfth of shorter test gaps):
// the agent measures from its own last write, so a report delayed in
// transit can arrive a little early.
const CAP_REPORT_GAP_SLACK_MS = 5_000;
const CAP_VIOLATION_WINDOW_MS = 10 * 60_000;
const CAP_VIOLATION_MAX = 10;
const AGENT_POLICY_CLOSE = 1008;
const KNOWN_CAPABILITY_SET = new Set(KNOWN_CAPABILITIES);
// sys.alerts.push frames (sysscript_alert). The agent enforces the same
// limits; these hold against an agent that does not.
const ALERT_SEVERITIES = new Set(['info', 'warning', 'critical']);
const ALERT_MESSAGE_MAX_BYTES = 4096;
const ALERTS_PER_RUN_MAX = 20;
const PURPOSE_ACTIONS = new Map([
    ['terminal:open', 'pty'],
    ['terminal:root', 'pty_root'],
    ['breakglass:open', 'breakglass']
]);
const PTY_ERRORS = new Set([
    'ticket_invalid', 'scope_denied', 'agent_offline', 'lease_required',
    'pty_user_unset', 'account_unmapped', 'recording_unavailable', 'root_unavailable', 'pty_start_failed', 'internal',
    'grant_missing', 'grant_bad_shape', 'grant_star', 'grant_bad_sig', 'grant_expired',
    'grant_purpose', 'grant_binding', 'sash_missing'
]);
const PTY_EXIT_REASONS = new Set(['exited', 'max_duration', 'stopped']);
const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Integer setting from env, or the default when unset or invalid.
function envInt(env, name, fallback, min, max) {
    const raw = env && env[name];
    if (raw === undefined || raw === null || raw === '') return fallback;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || n > max) {
        console.error(`[Fleet] ${name} is invalid; using the default`);
        return fallback;
    }
    return n;
}

function unref(timer) {
    if (timer && typeof timer.unref === 'function') timer.unref();
    return timer;
}

// Recording summary from an agent pty_exit, sanitized for the audit row.
function agentExitSummary(payload) {
    const out = {
        code: Number.isInteger(payload.code) ? payload.code : -1,
        reason: typeof payload.reason === 'string' ? payload.reason.replace(/[^a-z_]/g, '').slice(0, 32) : null,
        record: null,
        record_error: typeof payload.record_error === 'string' ? payload.record_error.replace(/[^a-z_]/g, '').slice(0, 64) : null
    };
    const rec = payload.record;
    if (rec && typeof rec === 'object') {
        out.record = {
            path: typeof rec.path === 'string' ? rec.path.slice(0, 512) : null,
            digest: typeof rec.digest === 'string' && /^[0-9a-f]{64}$/.test(rec.digest) ? rec.digest : null,
            bytes_in: Number.isSafeInteger(rec.bytes_in) && rec.bytes_in >= 0 ? rec.bytes_in : null,
            bytes_out: Number.isSafeInteger(rec.bytes_out) && rec.bytes_out >= 0 ? rec.bytes_out : null
        };
    }
    return out;
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
        this.wss = new WebSocket.Server({ noServer: true, maxPayload: AGENT_FRAME_MAX });
        this.db = db;
        this.apiSite = apiSite;
        this.metrics = prometheusMetrics;
        this.connectedAgents = new Map();
        // Per live agent socket: the capabilities it advertised on dial
        // (X-SystemAPI-Capabilities) and the credit state of its channel
        // streams. Keyed by socket, so a reconnect starts fresh.
        this.agentCaps = new WeakMap();
        this.agentLedgers = new WeakMap();
        // The API key id each accepted agent socket enrolled with.
        this.agentKeys = new WeakMap();
        // Per live agent socket: its capability routing and report state
        // (ConnectionCapabilities). agentCaps stays the dial header, which
        // job routing, the converge gate and the presence row read.
        this.agentCapState = new WeakMap();
        // Per host: the capability_report rate state. Per live agent socket:
        // its write slot (one capability write in flight) and the rows it
        // last wrote (so a report writes only what changed); keyed by socket,
        // so an old socket's late write never touches the new one's state.
        // Per host: the tail of its capability writes, so writes for one
        // host never overlap, across sockets too.
        this.capReportLimits = new Map();
        this.capWrites = new WeakMap();
        this.capWriteChains = new Map();
        // Refused or dropped capability_report frames by reason code.
        this.capReportDrops = new Map();
        this.capReportGapMs = CAP_REPORT_GAP_MS;
        this.capViolationWindowMs = CAP_VIOLATION_WINDOW_MS;
        this.capViolationMax = CAP_VIOLATION_MAX;
        // capability:<name>, capability:reports and host:offline alerts
        // (controlplane/capalerts.js), evaluated in the control tick.
        this.capAlerts = new CapabilityAlerts(this);
        this.agentPingMs = AGENT_PING_MS;
        this.terminalSessions = new Map();
        this.terminalWss = new WebSocket.Server({ noServer: true, maxPayload: PTY_FRAME_MAX });
        this.stoppingSessions = new Map();
        this.ptyRenewMs = PTY_RENEW_MS;
        this.ptyStartTimeoutMs = PTY_START_TIMEOUT_MS;
        this.ptyFinalWaitMs = PTY_FINAL_WAIT_MS;
        this.auditRetryDelaysMs = [200, 1000];
        this.terminalAuditFailures = 0;
        this.agentQueueMaxItems = AGENT_QUEUE_MAX_ITEMS;
        this.agentQueueMaxBytes = AGENT_QUEUE_MAX_BYTES;
        this.hostTenants = new Map();
        this.alertCooldown = new Map();
        this.pendingExecutions = new Map();
        // Hosts whose live agent is being ping-probed for a newcomer.
        this.agentProbes = new Set();
        // Software inventory per host: the digest and time of the last list
        // written, and the hosts with a write running (one at a time each).
        this.softwareSeen = new Map();
        this.softwareInFlight = new Set();
        this.signer = null;
        this.tickets = null;
        this.registry = null;
        this.env = process.env;
        // TCP-forward channel sessions (playground/tcp.js).
        this.tcp = new TcpChannels(this);
        // Mesh channel sessions (playground/mesh.js): multiplexed TCP streams.
        this.mesh = new MeshChannels(this);
        // File channel sessions (playground/file.js).
        this.file = new FileChannels(this);
        // Service-management channel sessions (playground/sys.js).
        this.sys = new SysChannels(this);
        // sahxfer grants (playground/xfer.js).
        this.xfer = new XferGrants(this);
        // Terminal session watches (playground/watch.js).
        this.watch = new TerminalWatches(this);
        // Async sysscript jobs (playground/jobs.js).
        this.jobs = new SysscriptJobs(this);

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
                this.rejectUpgrade(socket, 500, 'Internal Server Error');
            });
        });

        this.wss.on('connection', this.handleConnection.bind(this));
    }

    rejectUpgrade(socket, status, reason) {
        rejectUpgrade(socket, status, reason);
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
        if (parsed.pathname.startsWith('/api/v1/systems/tcp/')) {
            this.tcp.upgrade(request, socket, head, parsed);
            return;
        }
        if (parsed.pathname.startsWith('/api/v1/systems/mesh/')) {
            this.mesh.upgrade(request, socket, head, parsed);
            return;
        }
        if (parsed.pathname.startsWith('/api/v1/systems/file/')) {
            this.file.upgrade(request, socket, head, parsed);
            return;
        }
        if (parsed.pathname.startsWith('/api/v1/systems/sys/')) {
            this.sys.upgrade(request, socket, head, parsed);
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
        request.systemapiCapabilities = parseCapabilities(request.headers['x-systemapi-capabilities']);
        request.systemapiCapabilitiesDegraded = parseCapabilities(request.headers['x-systemapi-capabilities-degraded']);
        this.wss.handleUpgrade(request, socket, head, (ws) => {
            this.wss.emit('connection', ws, request, keyData);
        });
    }

    async upgradeTerminal(request, socket, head, parsed) {
        if (parsed.searchParams.has('api_key')) {
            this.rejectUpgrade(socket, 401, 'Unauthorized');
            return;
        }
        if (!originAllowed(request.headers.origin, this.env || {})) {
            console.warn('[Fleet] terminal upgrade refused: origin not allowed');
            this.rejectUpgrade(socket, 403, 'Forbidden');
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

    liveSessionsFor(actor) {
        let n = 0;
        for (const s of this.terminalSessions.values()) if (s.actor === actor) n++;
        return n;
    }

    openTerminal(ws, parsed, hostId, rows, cols) {
        ws.on('error', (err) => console.error('[Fleet] terminal socket error:', err.message));
        const purpose = parsed.searchParams.get('purpose') || 'terminal:open';
        if (TerminalWatches.purposeMode(purpose)) {
            this.watch.attach(ws, parsed, hostId, purpose).catch((err) => {
                console.error('[Fleet] watch open failed:', err.message);
                this.failTerminalSocket(ws, 'internal');
            });
            return;
        }
        const ticketRes = ticketFromRequest(parsed);
        const action = PURPOSE_ACTIONS.get(purpose);
        if (!this.tickets) {
            this.failTerminalSocket(ws, 'internal');
            return;
        }
        if (!ticketRes.ok) {
            this.failTerminalSocket(ws, 'ticket_invalid');
            return;
        }
        // Consumed on first upgrade, even when host or purpose do not match
        // (a tcp:open or file ticket presented here is spent too).
        const row = consumeTicket(this.tickets, ticketRes.ticket, hostId, purpose);
        if (!row || !action) {
            this.failTerminalSocket(ws, 'ticket_invalid');
            return;
        }
        if (!this.signer) {
            this.failTerminalSocket(ws, 'lease_required');
            return;
        }
        const actor = row.actor || null;
        if (this.liveSessionsFor(actor) >= envInt(this.env, 'SYSTEMAPI_PTY_MAX_PER_ACTOR', PTY_PER_ACTOR_DEFAULT, 1, 1000)) {
            console.warn('[Fleet] terminal refused: per-actor session cap reached');
            this.failTerminalSocket(ws, 'pty_start_failed');
            return;
        }
        const agentWs = this.connectedAgents.get(hostId);
        if (!agentWs || agentWs.readyState !== WebSocket.OPEN) {
            this.failTerminalSocket(ws, 'agent_offline');
            return;
        }
        const sessionId = `pts_${randomToken(16)}`;
        const maxSeconds = envInt(this.env, 'SYSTEMAPI_PTY_MAX_SECONDS', PTY_MAX_SECONDS_DEFAULT, 1, PTY_MAX_SECONDS_CAP);
        const startedMs = Date.now();
        const deadlineUnix = Math.floor(startedMs / 1000) + maxSeconds;
        let lease;
        try {
            lease = issueLease(this.signer, {
                hostId,
                action,
                payload: terminalPayload(sessionId, deadlineUnix, 'start'),
                ttl: PTY_LEASE_TTL_S
            });
        } catch (err) {
            this.failTerminalSocket(ws, 'lease_required');
            return;
        }
        const session = {
            id: sessionId,
            hostId,
            tenantId: row.tenantId,
            actor,
            purpose,
            action,
            deadlineUnix,
            startedMs,
            client: ws,
            agent: agentWs,
            started: false,
            announced: false,
            ended: false,
            finalized: false,
            pending: [],
            pendingBytes: 0,
            heldInput: [],
            heldInputBytes: 0,
            ptyUser: null,
            recording: 'off',
            privilegedGroups: [],
            renewTimer: null,
            maxTimer: null,
            startTimer: null,
            finalTimer: null,
            endReason: null,
            endCode: -1,
            ptyStartSent: false
        };
        this.terminalSessions.set(sessionId, session);
        ws.on('message', (buf, isBinary) => this.onTerminalClientMessage(session, buf, isBinary));
        ws.on('close', () => this.endTerminal(session, 'client_closed', -1, { notifyAgent: true }));
        sendJSON(ws, { type: 'pty_status', payload: { status: 'starting' } });
        const sendStart = (extra = {}) => {
            if (session.ended) return;
            session.ptyStartSent = true;
            sendJSON(agentWs, {
                type: 'pty_start',
                session_id: sessionId,
                request_id: sessionId,
                action,
                rows,
                cols,
                deadline_unix: deadlineUnix,
                // The agent picks the Unix account from this identity when it
                // has a --pty-user-map (one account per identity).
                actor: actor === null ? '' : String(actor),
                lease,
                ...extra
            });
        };
        const arm = () => {
            session.renewTimer = unref(setInterval(() => this.renewTerminal(session), this.ptyRenewMs));
            session.maxTimer = unref(setTimeout(() => {
                this.endTerminal(session, 'max_duration', -1, { notifyAgent: true, notifyClient: true });
            }, maxSeconds * 1000));
            session.startTimer = unref(setTimeout(() => {
                if (!session.started) {
                    this.endTerminal(session, 'start_timeout', -1, { error: 'internal', notifyAgent: session.ptyStartSent === true });
                }
            }, this.ptyStartTimeoutMs));
        };
        // Unset seed stays synchronous and omits the grant. A set seed signs
        // after the timers are armed; a bad seed or a policy failure refuses
        // the session and does not send pty_start.
        let sashRaw = null;
        if (action !== 'breakglass' && actor) sashRaw = this.env && this.env.SASH_GRANT_ED25519_SEED;
        if (!sashRaw) { sendStart(); arm(); return; }
        if (!/^[0-9a-fA-F]{64}$/.test(sashRaw)) {
            this.endTerminal(session, 'internal', -1, { error: 'internal', notifyAgent: false });
            return;
        }
        arm();
        effectivePolicies(this.registry, hostId).then((policies) => {
            if (session.ended) return;
            let built;
            try {
                built = buildSashTerminalGrant(sashRaw, {
                    actor: String(actor),
                    host: hostId,
                    purpose: action === 'pty_root' ? 'terminal:root' : 'terminal:open',
                    exp: deadlineUnix,
                    lease_id: lease.nonce_hex,
                    policies
                });
            } catch {
                if (session.ended) return;
                console.error('[Fleet] sash grant refused');
                this.endTerminal(session, 'internal', -1, { error: 'internal', notifyAgent: false });
                return;
            }
            sendStart({ grant: built.grant, sash_targets: built.targets });
        }).catch(() => {
            if (session.ended) return;
            console.error('[Fleet] sash grant refused');
            this.endTerminal(session, 'internal', -1, { error: 'internal', notifyAgent: false });
        });
    }

    renewTerminal(session) {
        if (session.ended || !this.signer) return;
        try {
            const lease = issueLease(this.signer, {
                hostId: session.hostId,
                action: session.action,
                payload: terminalPayload(session.id, session.deadlineUnix, 'renew'),
                ttl: PTY_LEASE_TTL_S
            });
            sendJSON(session.agent, { type: 'pty_renew', session_id: session.id, lease });
        } catch (err) {
            console.error('[Fleet] lease renewal failed:', err.message);
        }
    }

    // Client frames wait until the shell is announced, which is after the
    // start audit row is written and the recording check passed. Nothing
    // reaches the agent's PTY before then.
    onTerminalClientMessage(session, buf, isBinary) {
        if (session.ended || isBinary) return;
        if (!session.announced) {
            session.heldInputBytes += buf.length;
            if (session.heldInputBytes > PTY_HELD_INPUT_MAX) {
                this.endTerminal(session, 'internal', -1, { error: 'internal', notifyAgent: true });
                return;
            }
            session.heldInput.push(Buffer.from(buf));
            return;
        }
        this.forwardClientFrame(session, buf);
    }

    forwardClientFrame(session, buf) {
        if (session.ended) return;
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
    // opts.notifyClient sends pty_exit and closes 1000. When the agent is told
    // to stop, the end audit row waits briefly for the agent's pty_exit so it
    // can carry the recording digest.
    endTerminal(session, reason, code, opts = {}) {
        if (session.ended) return;
        session.ended = true;
        session.endReason = reason;
        session.endCode = code;
        clearInterval(session.renewTimer);
        clearTimeout(session.maxTimer);
        clearTimeout(session.startTimer);
        this.terminalSessions.delete(session.id);
        session.pending = [];
        session.heldInput = [];
        this.watch.onSessionEnd(session, reason, code);
        if (opts.error) {
            this.failTerminalSocket(session.client, opts.error);
        } else if (opts.notifyClient && session.client.readyState === WebSocket.OPEN) {
            sendJSON(session.client, { type: 'pty_exit', payload: { session_id: session.id, code, reason } });
            session.client.close(1000);
        }
        if (opts.notifyAgent && session.agent.readyState === WebSocket.OPEN) {
            sendJSON(session.agent, { type: 'pty_stop', session_id: session.id });
            this.stoppingSessions.set(session.id, session);
            session.finalTimer = unref(setTimeout(() => this.finalizeTerminal(session, null), this.ptyFinalWaitMs));
            return;
        }
        this.finalizeTerminal(session, opts.agentExit || null);
    }

    // Writes the terminal_end row once, retrying; a final failure is counted
    // and recorded as a security event.
    finalizeTerminal(session, agentExit) {
        if (session.finalized) return;
        session.finalized = true;
        clearTimeout(session.finalTimer);
        this.stoppingSessions.delete(session.id);
        const payload = {
            session_id: session.id,
            purpose: session.purpose,
            reason: session.endReason,
            exit_code: session.endCode,
            started: session.started,
            recording: session.recording,
            duration_s: Math.round((Date.now() - session.startedMs) / 1000),
            agent_exit: agentExit
        };
        const attempt = async () => {
            let lastErr = null;
            for (const delay of [0, ...this.auditRetryDelaysMs]) {
                if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
                try {
                    await this.auditTerminal(session, 'terminal_end', payload);
                    return;
                } catch (err) {
                    lastErr = err;
                }
            }
            this.terminalAuditFailures += 1;
            if (this.metrics && this.metrics.terminalAuditFailures) this.metrics.terminalAuditFailures.inc();
            console.error('[Fleet] terminal end audit failed:', lastErr && lastErr.message);
            await this.noteSecurity('audit_write_failed', fingerprint(String(session.actor)), {
                session_id: session.id,
                action: 'terminal_end'
            });
        };
        attempt().catch((err) => console.error('[Fleet] terminal end audit failed:', err.message));
    }

    // A break-glass start is anchored right away (controlplane/anchor.js).
    async auditTerminal(session, action, payload) {
        if (!this.registry) throw new Error('registry_unavailable');
        const row = await this.registry.appendAudit({
            tenant_id: session.tenantId,
            host_id: session.hostId,
            actor: session.actor,
            action,
            payload
        });
        // The row is written; an anchor failure must not end the session.
        try {
            if (this.anchor) this.anchor.noteAudit(row);
        } catch (err) {
            console.error(`[anchor] trigger failed: ${anchorErrName(err)}`);
        }
        return row;
    }

    // Returns the live session only when this agent connection owns it.
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
        const sid = buf.toString('latin1', 1, 1 + n);
        if (TcpChannels.owns(sid)) {
            this.tcp.onAgentData(ws, hostId, sid, buf.subarray(1 + n));
            return;
        }
        if (FileChannels.owns(sid)) {
            this.file.onAgentData(ws, hostId, sid, buf.subarray(1 + n));
            return;
        }
        const session = this.agentSession(ws, hostId, sid);
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
        if (!session.ended) this.watch.relay(session, data);
    }

    // Output goes out in slices of at most 64 KiB; clients cap frames at 1 MiB.
    // A client that cannot keep up (bufferedAmount over the cap) ends the
    // session instead of growing server memory.
    sendOutput(session, data) {
        const cap = envInt(this.env, 'SYSTEMAPI_PTY_CLIENT_BUFFER_MAX', PTY_CLIENT_BUFFER_DEFAULT, PTY_FRAME_MAX, 1 << 30);
        for (let off = 0; off < data.length; off += PTY_FRAME_MAX) {
            if (session.ended || session.client.readyState !== WebSocket.OPEN) return;
            if (session.client.bufferedAmount > cap) {
                console.warn(`[Fleet] terminal ${session.id}: client too slow; ending session`);
                this.endTerminal(session, 'client_too_slow', -1, { error: 'internal', notifyAgent: true });
                return;
            }
            session.client.send(data.subarray(off, off + PTY_FRAME_MAX));
        }
    }

    async onAgentPtyStatus(ws, hostId, msg) {
        // Older agents tag frames with request_id only; the server sets
        // request_id to the session id.
        const sid = typeof msg.session_id === 'string' ? msg.session_id : msg.request_id;
        const session = this.agentSession(ws, hostId, sid);
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        if (!session) {
            if (payload.error) console.warn('[Fleet] agent pty error without a known session');
            return;
        }
        if (payload.error) {
            const code = PTY_ERRORS.has(payload.error) ? payload.error : 'internal';
            this.endTerminal(session, code, -1, { error: code });
            return;
        }
        if (payload.status !== 'started' || session.started) return;
        session.started = true;
        clearTimeout(session.startTimer);
        session.ptyUser = typeof payload.pty_user === 'string' ? payload.pty_user.slice(0, 64) : null;
        session.recording = RECORDING_MODES.has(payload.recording) ? payload.recording : 'off';
        session.privilegedGroups = Array.isArray(payload.pty_user_privileged_groups)
            ? payload.pty_user_privileged_groups.filter((g) => typeof g === 'string').map((g) => g.slice(0, 32)).slice(0, 16)
            : [];
        try {
            await this.auditTerminal(session, 'terminal_start', {
                session_id: session.id,
                purpose: session.purpose,
                pty_user: session.ptyUser,
                recording: session.recording,
                pty_user_privileged_groups: session.privilegedGroups
            });
        } catch (err) {
            console.error('[Fleet] terminal start audit failed:', err.message);
            this.endTerminal(session, 'internal', -1, { error: 'internal', notifyAgent: true });
            return;
        }
        if (session.ended) return;
        // Until phase 2 policy exists, a root shell must be agent-recorded.
        if (session.purpose === 'terminal:root' && session.recording !== 'agent') {
            this.endTerminal(session, 'root_unavailable', -1, { error: 'root_unavailable', notifyAgent: true });
            return;
        }
        sendJSON(session.client, { type: 'pty_status', payload: { status: 'started', session_id: session.id } });
        session.announced = true;
        const held = session.pending;
        session.pending = [];
        session.pendingBytes = 0;
        for (const chunk of held) this.sendOutput(session, chunk);
        const input = session.heldInput;
        session.heldInput = [];
        session.heldInputBytes = 0;
        for (const frame of input) this.forwardClientFrame(session, frame);
    }

    onAgentPtyExit(ws, hostId, msg) {
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        const agentExit = agentExitSummary(payload);
        const stopping = typeof msg.session_id === 'string' ? this.stoppingSessions.get(msg.session_id) : null;
        if (stopping && stopping.agent === ws && stopping.hostId === hostId) {
            this.finalizeTerminal(stopping, agentExit);
            return;
        }
        const session = this.agentSession(ws, hostId, msg.session_id);
        if (!session) return;
        const code = Number.isInteger(payload.code) ? payload.code : -1;
        const reason = PTY_EXIT_REASONS.has(payload.reason) ? payload.reason : 'exited';
        this.endTerminal(session, reason, code, { notifyClient: true, agentExit });
    }

    onAgentRenewRejected(ws, hostId, msg) {
        const raw = msg.payload && msg.payload.error;
        const err = typeof raw === 'string' ? raw.replace(/[^a-z_]/g, '').slice(0, 64) : 'unknown';
        console.warn(`[Fleet] agent rejected a lease renewal: ${err}`);
        if (err !== 'unknown_session' && err !== 'session_ended') return;
        const session = this.agentSession(ws, hostId, msg.session_id);
        if (session) this.endTerminal(session, 'stopped', -1, { notifyClient: true });
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
                `SELECT key_id, user_id, key_hash, tenant_id FROM playground_api_keys
                 WHERE key_id = $1 AND api_site = $2 AND is_active = true AND is_locked = false
                   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
                [keyId, this.apiSite]
            );
            if (res.rows.length === 0) return null;
            const bcrypt = require('bcryptjs');
            const isValid = await bcrypt.compare(secretProvided, res.rows[0].key_hash);
            if (!isValid) return null;
            await this.db.query('UPDATE playground_api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_id = $1', [keyId]);
            return { key_id: res.rows[0].key_id, user_id: res.rows[0].user_id, tenant_id: res.rows[0].tenant_id ?? null };
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
        // The queue is capped: an agent that floods it while an audit write
        // is pending is disconnected.
        let ptyChain = Promise.resolve();
        let queued = 0;
        let queuedBytes = 0;
        let flooded = false;
        const inOrder = (fn, bytes = 0, force = false) => {
            if (!force) {
                if (flooded) return;
                if (queued >= this.agentQueueMaxItems || queuedBytes + bytes > this.agentQueueMaxBytes) {
                    flooded = true;
                    console.error('[Fleet] agent terminal queue over its cap; disconnecting the agent');
                    ws.terminate();
                    return;
                }
            }
            queued += 1;
            queuedBytes += bytes;
            ptyChain = ptyChain.then(fn).catch((err) => console.error('[Fleet] terminal frame error:', err.message)).finally(() => {
                queued -= 1;
                queuedBytes -= bytes;
            });
        };
        console.log(`[Fleet] Agent connected key fingerprint sha256:${fingerprint(keyId)}`);
        // ws emits oversize frames (maxPayload, close 1009) and protocol errors here.
        ws.on('error', (err) => console.error('[Fleet] agent socket error:', err.message));

        ws.on('message', async (messageBuffer, isBinary) => {
            try {
                if (isBinary) {
                    if (hostId) {
                        const id = hostId;
                        inOrder(() => this.onAgentOutput(ws, id, messageBuffer), messageBuffer.length);
                    }
                    return;
                }
                const msg = JSON.parse(messageBuffer.toString());
                if (msg.type === 'telemetry') {
                    hostId = await this.handleTelemetry(keyId, userId, ws, msg.payload, hostId);
                } else if (msg.type === 'command_result') {
                    const executionContext = this.pendingExecutions && typeof msg.request_id === 'string'
                        ? this.pendingExecutions.get(msg.request_id) : null;
                    // Only the host the script was sent to may settle it,
                    // as in onAgentAlert.
                    if (executionContext && (!hostId || executionContext.hostId !== hostId)) {
                        console.error(`[Fleet] command_result rejected host=${hostId} error=unknown_execution`);
                    } else if (executionContext) {
                        this.logExecutionToDarkStorage(hostId, executionContext.script, msg.payload).catch((err) => {
                            console.error('[DarkStorage] audit write failed:', err.message);
                        });
                        executionContext.resolve(msg.payload);
                        this.pendingExecutions.delete(msg.request_id);
                    }
                } else if (msg.type === 'sysscript_alert') {
                    // An alert from an async job carries job_id and goes on
                    // the host's job chain; request_id alerts are legacy.
                    if (hostId && typeof msg.job_id === 'string' && msg.job_id !== '') {
                        this.jobs.onAgentFrame(ws, hostId, msg, messageBuffer.length);
                    } else if (hostId) {
                        await this.onAgentAlert(hostId, msg);
                    }
                } else if (msg.type === 'sysscript_job_status' || msg.type === 'sysscript_job_result' || msg.type === 'sysscript_job_sync') {
                    // Dropped before enroll, as every other agent frame.
                    if (hostId) this.jobs.onAgentFrame(ws, hostId, msg, messageBuffer.length);
                } else if (msg.type === 'pty_status') {
                    const id = hostId;
                    if (id) inOrder(() => this.onAgentPtyStatus(ws, id, msg));
                } else if (msg.type === 'pty_exit') {
                    const id = hostId;
                    if (id) inOrder(() => this.onAgentPtyExit(ws, id, msg));
                } else if (msg.type === 'watch_consent') {
                    const id = hostId;
                    if (id) inOrder(() => this.watch.onAgentConsent(ws, id, msg));
                } else if (msg.type === 'pty_renew_rejected') {
                    const id = hostId;
                    if (id) inOrder(() => this.onAgentRenewRejected(ws, id, msg));
                } else if (msg.type === 'tcp_status' || msg.type === 'tcp_eof' || msg.type === 'tcp_credit' || msg.type === 'tcp_closed') {
                    const id = hostId;
                    if (id) inOrder(() => this.tcp.onAgentFrame(ws, id, msg));
                } else if (msg.type === 'file_status' || msg.type === 'file_result' || msg.type === 'file_write_ack' || msg.type === 'file_credit' || msg.type === 'file_closed') {
                    const id = hostId;
                    const raw = messageBuffer;
                    if (id) inOrder(() => this.file.onAgentFrame(ws, id, msg, raw));
                } else if (msg.type === 'xfer_status' || msg.type === 'xfer_result') {
                    const id = hostId;
                    if (id) inOrder(() => this.xfer.onAgentFrame(ws, id, msg));
                } else if (msg.type === 'sys_result' || msg.type === 'sys_status') {
                    const id = hostId;
                    if (id) inOrder(() => this.sys.onAgentFrame(ws, id, msg));
                } else if (msg.type === 'capability_report') {
                    if (hostId) await this.onCapabilityReport(ws, hostId, keyId, msg, messageBuffer.length);
                    else this.noteCapabilityDrop('pre_enroll');
                }
            } catch (err) {
                console.error('[Fleet] message error:', err.message);
            }
        });

        ws.on('close', async () => {
            if (!hostId) return;
            inOrder(() => {
                for (const session of [...this.terminalSessions.values()]) {
                    if (session.agent === ws) this.endTerminal(session, 'agent_disconnected', -1, { notifyClient: true });
                }
                for (const session of [...this.stoppingSessions.values()]) {
                    if (session.agent === ws) this.finalizeTerminal(session, null);
                }
                this.tcp.onAgentGone(ws);
                this.mesh.onAgentGone(ws);
                this.file.onAgentGone(ws);
                this.xfer.onAgentGone(ws);
                this.sys.onAgentGone(ws);
            }, 0, true);
            // A connection that a newer one for the same host already
            // replaced does not mark the host offline.
            if (this.connectedAgents.get(hostId) !== ws) return;
            this.connectedAgents.delete(hostId);
            this.jobs.onClose(ws, hostId);
            this.capAlerts.onDisconnect(hostId);
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

        // Each ping also re-checks the key, once the socket is accepted.
        let keyCheckFailures = 0;
        const interval = setInterval(() => {
            if (ws.readyState !== WebSocket.OPEN) {
                clearInterval(interval);
                return;
            }
            ws.ping();
            if (!hostId || !this.registry || typeof this.registry.keyActive !== 'function') return;
            const id = hostId;
            this.registry.keyActive(keyId).then((active) => {
                keyCheckFailures = 0;
                if (active !== true) return this.closeRevokedAgent(id, ws, keyId, 'key_inactive', 'system:key_check');
                return undefined;
            }, (err) => {
                keyCheckFailures += 1;
                console.error('[Fleet] agent key check failed:', err.message);
                if (keyCheckFailures >= 2) return this.closeRevokedAgent(id, ws, keyId, 'key_check_failed', 'system:key_check');
                return undefined;
            }).catch((err) => console.error('[Fleet] agent key close failed:', err.message));
        }, this.agentPingMs);

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
        // A key bound to a tenant enrolls only into that tenant.
        if (keyData.tenant_id != null && keyData.tenant_id !== enroll.tenant) {
            await this.noteSecurity('enroll_rejected', fingerprint(keyId), { error: 'key_tenant_mismatch' });
            ws.send(JSON.stringify({ type: 'enroll_error', error: 'key_tenant_mismatch' }));
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
            const live = this.connectedAgents.get(host.host_id);
            if (live && live !== ws && !(await this.displaceStaleAgent(host.host_id, live))) {
                await this.noteSecurity('agent_displace_refused', fingerprint(keyId), { host_id: host.host_id });
                ws.send(JSON.stringify({ type: 'enroll_error', error: 'host_connected' }));
                ws.close(1008);
                return;
            }
            hostId = host.host_id;
            this.hostTenants.set(hostId, host.tenant_id);
            this.agentCaps.set(ws, request.systemapiCapabilities || new Set());
            // A fresh connection starts from what it reports, not from what
            // this instance last wrote (another instance may have written
            // since: the write cache is per socket), and holds no probe
            // credit from an earlier socket.
            if (this.capReportLimits.has(hostId)) this.capReportLimits.get(hostId).probeCredit = false;
            this.agentCapState.set(ws, new ConnectionCapabilities(
                request.systemapiCapabilities || new Set(),
                request.systemapiCapabilitiesDegraded || new Set()
            ));
            this.agentKeys.set(ws, keyId);
            this.connectedAgents.set(hostId, ws);
            this.jobs.onEnroll(ws, hostId);
            const enrolledId = hostId;
            this.capAlerts.onConnect(enrolledId).catch((err) => {
                console.error(`[Fleet] capability alerts on connect failed host=${enrolledId} error=${errorCode(err)}`);
            });
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

    // A newcomer for hostId may replace the live agent socket only when that
    // socket does not answer a ping within the probe window. True when live
    // is gone or was dropped (and unregistered, so its close does not mark
    // the host offline); false while it answers, while another probe for the
    // host runs, or when a third socket took the host meanwhile.
    async displaceStaleAgent(hostId, live) {
        if (this.agentProbes.has(hostId)) return false;
        this.agentProbes.add(hostId);
        try {
            const answered = live.readyState !== WebSocket.OPEN ? false : await new Promise((resolve) => {
                let timer = null;
                const done = (value) => {
                    clearTimeout(timer);
                    live.off('pong', onPong);
                    live.off('close', onClose);
                    resolve(value);
                };
                const onPong = () => done(true);
                const onClose = () => done(false);
                live.on('pong', onPong);
                live.on('close', onClose);
                timer = setTimeout(() => done(false), envInt(this.env, 'SYSTEMAPI_AGENT_PROBE_MS', AGENT_PROBE_MS_DEFAULT, 10, 60000));
                try { live.ping(); } catch { done(false); }
            });
            if (answered) return false;
            const current = this.connectedAgents.get(hostId);
            if (current && current !== live) return false;
            this.connectedAgents.delete(hostId);
            live.terminate();
            return true;
        } finally {
            this.agentProbes.delete(hostId);
        }
    }

    // Closes every live agent socket enrolled with keyId. Called by the key
    // delete and lock routes. Returns how many were closed.
    async closeAgentsForKey(keyId, reason, actor) {
        let closed = 0;
        for (const [hostId, ws] of [...this.connectedAgents]) {
            if (this.agentKeys.get(ws) !== keyId) continue;
            await this.closeRevokedAgent(hostId, ws, keyId, reason, actor);
            closed += 1;
        }
        return closed;
    }

    // Close 4403 at once (nothing new is routed to a socket that is not
    // OPEN), terminate if the agent has not finished the close within the
    // grace period, then the audit row.
    async closeRevokedAgent(hostId, ws, keyId, reason, actor) {
        if (ws.readyState !== WebSocket.OPEN) return;
        ws.close(AGENT_REVOKED_CLOSE, 'key_revoked');
        unref(setTimeout(() => {
            if (ws.readyState !== WebSocket.CLOSED) ws.terminate();
        }, AGENT_CLOSE_GRACE_MS));
        console.warn(`[Fleet] agent closed: key sha256:${fingerprint(keyId)} ${reason}`);
        if (!this.registry) return;
        try {
            await this.registry.appendAudit({
                tenant_id: this.hostTenants.get(hostId) || null,
                host_id: hostId,
                actor,
                action: 'agent_key_revoked',
                payload: { key_fp: fingerprint(keyId), reason, close_code: AGENT_REVOKED_CLOSE }
            });
        } catch (err) {
            console.error('[Fleet] agent revoke audit failed:', err.message);
            await this.noteSecurity('audit_write_failed', fingerprint(keyId), { action: 'agent_key_revoked' });
        }
    }

    // Ends a retired host's live agent: close 4403 "host_retired" (terminate
    // after the grace period). The socket's close handler ends its terminal,
    // TCP, file and xfer sessions and marks the row offline; its re-enroll
    // is then refused host_retired. False when no agent is connected.
    retireAgent(hostId) {
        const ws = this.connectedAgents.get(hostId);
        if (!ws) return false;
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
            ws.close(AGENT_REVOKED_CLOSE, 'host_retired');
        }
        unref(setTimeout(() => {
            if (ws.readyState !== WebSocket.CLOSED) ws.terminate();
        }, AGENT_CLOSE_GRACE_MS));
        return true;
    }

    // Channel-policy writes (plan P2d): the live sessions on this replica
    // whose host matches match(hostId, tenantId): tcp (each mesh stream is a
    // tcp session too), file, xfer, and the mesh sessions themselves.
    policySessions(match) {
        const out = [];
        for (const s of this.tcp.sessions.values()) if (!s.ended && match(s.hostId, s.tenantId)) out.push(['tcp', s]);
        for (const s of this.file.sessions.values()) if (!s.ended && match(s.hostId, s.tenantId)) out.push(['file', s]);
        for (const g of this.xfer.grants.values()) if (g.state === 'live' && match(g.hostId, g.tenantId)) out.push(['xfer', g]);
        for (const m of this.mesh.sessions.values()) if (!m.ended && match(m.hostId, m.tenantId)) out.push(['mesh', m]);
        return out;
    }

    // Renews each matching session now instead of at its next 30 s tick.
    // Renewal re-checks the grant against the stored policy and ends one it
    // no longer allows with stopped; that session's own end row (tcp_end,
    // file_end, xfer_result, mesh_end) audits the stop. A mesh session
    // re-checks its scope; its streams re-check the tcp policy as tcp
    // sessions. This replica only: a cross-replica fan-out (LISTEN/NOTIFY,
    // as jobs) waits for a second replica. Returns how many were renewed.
    renewPolicySessions(match) {
        const list = this.policySessions(match);
        for (const [kind, s] of list) {
            const run = kind === 'tcp' ? this.tcp.renew(s)
                : kind === 'file' ? this.file.renew(s)
                    : kind === 'xfer' ? this.xfer.renew(s)
                        : this.mesh.recheck(s);
            run.catch((err) => console.error(`[Fleet] ${kind} policy renewal failed:`, err.message));
        }
        return list.length;
    }

    // True when capability is in the live agent's effective set: advertised
    // on dial, minus the degraded header, minus what the latest report on
    // this connection marks degraded or absent (sysscript_jobs and converge
    // follow the header only). Channel handlers answer agent_unsupported
    // when this is false (an old agent advertises nothing).
    agentSupports(hostId, capability) {
        const ws = this.connectedAgents.get(hostId);
        if (!ws) return false;
        const state = this.agentCapState.get(ws);
        if (state) return state.supports(capability);
        const caps = this.agentCaps.get(ws);
        return !!caps && caps.has(capability);
    }

    // The dial header of hostId's live agent (what the binary supports).
    agentSupportedCaps(hostId) {
        const ws = this.connectedAgents.get(hostId);
        return (ws && this.agentCaps.get(ws)) || new Set();
    }

    // Counts systemapi_agent_unsupported_total{capability}: called wherever
    // routing answers agent_unsupported (the channels and the job routes).
    noteUnsupported(capability) {
        if (this.metrics && this.metrics.agentUnsupportedTotal) {
            this.metrics.agentUnsupportedTotal.inc({ capability: KNOWN_CAPABILITY_SET.has(capability) ? capability : 'other' });
        }
    }

    // The reason code an agent_unsupported for capability carries, or null.
    agentUnsupportedReason(hostId, capability) {
        const ws = this.connectedAgents.get(hostId);
        const state = ws && this.agentCapState.get(ws);
        return state ? state.unsupportedReason(capability) : null;
    }

    // reason is a fixed code (the validator's errors and the rate-limit
    // ones), so the counter's label set is bounded.
    noteCapabilityDrop(reason) {
        this.capReportDrops.set(reason, (this.capReportDrops.get(reason) || 0) + 1);
        if (this.metrics && this.metrics.capabilityReportDroppedTotal) this.metrics.capabilityReportDroppedTotal.inc({ reason });
    }

    capReportLimit(hostId) {
        let limit = this.capReportLimits.get(hostId);
        if (!limit) {
            limit = { inFlight: false, lastAt: 0, probeCredit: false, violations: [], closing: null };
            this.capReportLimits.set(hostId, limit);
        }
        return limit;
    }

    // A refused or dropped capability_report: counted; capViolationMax of
    // them within the window close the socket 1008 (the credit-ledger
    // pattern: a security event, then the socket ends).
    capabilityViolation(ws, hostId, keyId, limit, reason, nowMs) {
        this.noteCapabilityDrop(reason);
        if (limit.closing === ws) return;
        limit.violations = limit.violations.filter((t) => nowMs - t < this.capViolationWindowMs);
        limit.violations.push(nowMs);
        if (limit.violations.length < this.capViolationMax) return;
        limit.closing = ws;
        console.error(`[Fleet] agent capability_report flood host=${hostId} (${reason}); disconnecting the agent`);
        this.noteSecurity('agent_capability_flood', fingerprint(keyId), { host_id: hostId, reason })
            .catch((err) => console.error('[Fleet] security event failed:', err.message));
        if (ws.readyState === WebSocket.OPEN) ws.close(AGENT_POLICY_CLOSE, 'capability_report_flood');
        unref(setTimeout(() => {
            if (ws.readyState !== WebSocket.CLOSED) ws.terminate();
        }, AGENT_CLOSE_GRACE_MS));
    }

    // A capability_report from hostId's enrolled agent: rate-checked and
    // validated before any DB work, applied to this connection's routing at
    // once, then the changed rows written in one statement.
    async onCapabilityReport(ws, hostId, keyId, msg, bytes) {
        const now = Date.now();
        const state = this.agentCapState.get(ws);
        if (!state || this.connectedAgents.get(hostId) !== ws) {
            this.noteCapabilityDrop('stale_socket');
            return;
        }
        const limit = this.capReportLimit(hostId);
        const slot = this.capWriteState(ws);
        // This socket's write still running is our side being slow, not the
        // agent misbehaving: drop and count it, never a violation.
        if (slot.inFlight) {
            this.noteCapabilityDrop('in_flight');
            return;
        }
        // The first report on a connection and the answer to a server probe
        // are not held to the gap.
        if (state.reportCount > 0 && !limit.probeCredit && now - limit.lastAt < this.capReportGapMs - Math.min(CAP_REPORT_GAP_SLACK_MS, this.capReportGapMs / 12)) {
            this.capabilityViolation(ws, hostId, keyId, limit, 'too_soon', now);
            return;
        }
        const checked = validateCapabilityReport(msg, bytes);
        if (!checked.ok) {
            this.capabilityViolation(ws, hostId, keyId, limit, checked.error, now);
            return;
        }
        if (checked.dropped > 0) this.noteCapabilityDrop('unknown_name');
        limit.lastAt = now;
        limit.probeCredit = false;
        state.applyReport(checked.report, now);
        this.capAlerts.noteReport(hostId, state);
        // The slot is held until the write itself settles (no timeout frees
        // it early), so this socket never has two writes running.
        slot.inFlight = true;
        let changed = false;
        try {
            changed = await this.storeCapabilities(ws, hostId, checked.report.caps);
        } finally {
            slot.inFlight = false;
        }
        // A change already evaluated the alerts (onCapabilityChange); an old
        // socket's late write evaluates nothing.
        if (!changed && this.connectedAgents.get(hostId) === ws) await this.evaluateCapabilityAlerts(hostId);
    }

    // The capability write state of one agent socket.
    capWriteState(ws) {
        let slot = this.capWrites.get(ws);
        if (!slot) {
            slot = { inFlight: false, stored: null };
            this.capWrites.set(ws, slot);
        }
        return slot;
    }

    async evaluateCapabilityAlerts(hostId) {
        try {
            await this.capAlerts.evaluate(hostId, { refresh: true });
        } catch (err) {
            console.error(`[Fleet] capability alert evaluation failed host=${hostId} error=${errorCode(err)}`);
        }
    }

    // The control tick's alert pass (controlplane/index.js).
    tickCapabilityAlerts() {
        return this.capAlerts.tick();
    }

    // A capability or host-offline alert webhook (signed by deliverWebhooks).
    // Opens keep the anomaly cooldown: at most one open webhook per host and
    // rule per COOLDOWN_MS; resolves are always sent. The alert row and its
    // audit row are never suppressed.
    // False when the cooldown suppressed it.
    async deliverAlertWebhook(tenantId, rule, hostId, body, isOpen) {
        if (!tenantId) return true;
        if (isOpen && this.cooled(hostId, rule)) return false;
        await deliverWebhooks(this, tenantId, body);
        return true;
    }

    // An alert open held back by the hourly per-host cap (capalerts.js).
    noteAlertCapped(rule) {
        const m = this.metrics && this.metrics.capabilityAlertCappedTotal;
        if (m) m.inc({ rule: /^(capability:[a-z_]{1,16}|host:offline)$/.test(rule) ? rule : 'other' });
    }

    // This process's id on presence rows (cp_hosts.agent_instance).
    instanceId() {
        return this.jobs ? this.jobs.instanceId : null;
    }

    // A retired host leaves the alert state, the cooldowns and its
    // capability gauge series at once (refreshGauges also leaves it out).
    onHostRetired(hostId) {
        this.capAlerts.dropHost(hostId);
        this.capReportLimits.delete(hostId);
        for (const key of [...this.alertCooldown.keys()]) {
            if (key.endsWith(`:${hostId}`)) this.alertCooldown.delete(key);
        }
        const gauge = this.metrics && this.metrics.capabilityStateGauge;
        if (gauge) {
            for (const capability of KNOWN_CAPABILITIES) {
                for (const state of CAPABILITY_STATES) gauge.remove({ host_id: hostId, capability, state });
            }
        }
    }

    // Queues ws's report rows behind any capability write still running for
    // hostId (from this or an older socket), so writes for one host never
    // overlap and land in order. Resolves as writeCapabilities does.
    storeCapabilities(ws, hostId, caps) {
        const prior = this.capWriteChains.get(hostId) || Promise.resolve();
        const run = prior.then(() => this.writeCapabilities(ws, hostId, caps));
        const tail = run.then(() => {}, () => {});
        this.capWriteChains.set(hostId, tail);
        tail.then(() => {
            if (this.capWriteChains.get(hostId) === tail) this.capWriteChains.delete(hostId);
        });
        return run;
    }

    // Writes the report's rows that differ from what ws last wrote (all of
    // them when nothing is cached), in one statement. A failed write is
    // logged and forgets ws's cache, so its next report writes every row
    // again; routing already took the report. A write that completes after
    // ws stopped being hostId's socket updates no cache and evaluates
    // nothing. True when a state changed (onCapabilityChange ran).
    async writeCapabilities(ws, hostId, caps) {
        if (!this.registry || typeof this.registry.setHostCapabilities !== 'function') return false;
        const slot = this.capWriteState(ws);
        const stored = slot.stored;
        const rows = stored
            ? caps.filter((c) => {
                const prev = stored.get(c.name);
                return !prev || prev.state !== c.state || prev.reason !== c.reason;
            })
            : caps;
        if (rows.length === 0) return false;
        let changed;
        try {
            changed = await this.registry.setHostCapabilities(hostId, rows);
        } catch (err) {
            slot.stored = null;
            console.error(`[Fleet] capability write failed host=${hostId} error=${errorCode(err)}`);
            return false;
        }
        if (this.connectedAgents.get(hostId) !== ws) return false;
        const next = stored || new Map();
        for (const c of rows) next.set(c.name, { state: c.state, reason: c.reason });
        slot.stored = next;
        const changes = changed.filter((c) => c.previous_state !== c.state);
        if (changes.length === 0) return false;
        await this.onCapabilityChange(hostId, changes);
        return true;
    }

    // The single hook for capability state changes: logs them and evaluates
    // the host's alerts. changes is [{name, state, reason, since,
    // last_report_at, previous_state}] for the rows whose state changed;
    // previous_state is null on a name's first row.
    async onCapabilityChange(hostId, changes) {
        const summary = changes.map((c) => `${c.name}:${c.previous_state || 'none'}->${c.state}`).join(',');
        console.log(`[Fleet] capability change host=${hostId} ${summary}`);
        await this.evaluateCapabilityAlerts(hostId);
    }

    // Sends capability_probe to hostId's live agent (old agents ignore it);
    // its answer is not held to the report gap. False when no agent is
    // connected here.
    requestCapabilityProbe(hostId) {
        const ws = this.connectedAgents.get(hostId);
        if (!ws || ws.readyState !== WebSocket.OPEN) return false;
        this.capReportLimit(hostId).probeCredit = true;
        sendJSON(ws, { type: 'capability_probe' });
        return true;
    }

    // The expected capabilities of hostId under its effective channel policy.
    async expectedCapabilities(hostId) {
        return expectedCapabilities(await effectivePolicies(this.registry, hostId));
    }

    liveCapState(hostId) {
        const ws = this.connectedAgents.get(hostId);
        const connected = !!ws && ws.readyState === WebSocket.OPEN;
        return { connected, conn: connected ? this.agentCapState.get(ws) || null : null };
    }

    // hostId's health. Its socket held here: computed from this connection,
    // with the expected set the alert pass last read (the policy is read
    // only when none is cached). Not held here: from row (a cp_hosts row,
    // written by the instance that holds it), offline without one.
    async hostHealth(hostId, row = null) {
        const { connected, conn } = this.liveCapState(hostId);
        if (!connected) {
            if (!row) return 'offline';
            return row.status === 'online' ? (row.capability_health || 'unknown') : 'offline';
        }
        if (!conn || conn.reportCount === 0) return hostHealth({ connected, conn, expected: [] });
        const expected = this.capAlerts.cachedExpected(hostId) || await this.expectedCapabilities(hostId);
        return hostHealth({ connected, conn, expected });
    }

    // The GET /api/v1/hosts/:id/capabilities body for an authorized host.
    async hostCapabilities(hostId) {
        const { connected, conn } = this.liveCapState(hostId);
        const expected = await this.expectedCapabilities(hostId);
        const caps = this.registry && typeof this.registry.listHostCapabilities === 'function'
            ? await this.registry.listHostCapabilities(hostId) : [];
        return {
            host_id: hostId,
            health: hostHealth({ connected, conn, expected }),
            supported: conn ? [...conn.supported].sort() : [],
            effective: conn ? conn.effective() : [],
            expected,
            caps
        };
    }

    // The credit ledger of one agent socket (controlplane/credit.js). An
    // agent that overruns a stream's window, or returns more credit than it
    // could owe, is disconnected (TCP §6, FILE §6).
    agentCreditLedger(ws) {
        let ledger = this.agentLedgers.get(ws);
        if (!ledger) {
            ledger = new CreditLedger({
                onViolation: (sessionId, reason) => {
                    console.error(`[Fleet] agent credit violation (${reason}); disconnecting the agent`);
                    this.noteSecurity('agent_credit_violation', null, { reason }).catch(() => {});
                    ws.terminate();
                }
            });
            this.agentLedgers.set(ws, ledger);
        }
        return ledger;
    }

    async handleTelemetry(keyId, userId, ws, payload, hostId) {
        if (!hostId || !this.registry) return hostId;
        const hostInfo = (payload && payload.host) || {};
        try {
            // The enrolled hostname is the resolvable name; telemetry never
            // renames a host.
            await this.registry.touchHost(hostId, {
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
            // Not awaited (telemetry goes on); a failure is logged, never
            // left as an unhandled rejection, which would end the process.
            this.triggerIncident(rule, valueToTest, hostId, hostname).catch((err) => {
                console.error(`[ALERT] incident action failed host=${hostId} error=${errorCode(err)}`);
            });
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
        const entitlements = {
            allow_exec: true,
            allow_fs_write: false,
            allow_fs_read: false,
            allow_net_outbound: false,
            allow_config_write: false,
            allow_service_reload: false,
            allow_containers: false,
            allow_k3s: false
        };
        // A sysscript_jobs agent gets a job (no waiting on the agent);
        // otherwise, or with the kill switch off, the legacy push. Either
        // can fail (too_many_jobs, agent_timeout, a registry error): logged
        // by code only, never the script or its output.
        const tenantId = this.hostTenants.get(hostId);
        try {
            if (tenantId && await this.jobs.useJobs(hostId)) {
                await this.jobs.submit({
                    host: { host_id: hostId, tenant_id: tenantId },
                    actor: 'system:rule',
                    source: 'rule',
                    script,
                    entitlements,
                    timeoutS: RULE_JOB_TIMEOUT_S
                });
                return;
            }
            const lease = issueLease(this.signer, { hostId, action: 'sysscript', payload: script, ttl: 60 });
            await this.pushSysscript(hostId, script, entitlements, randomToken(16), lease);
        } catch (err) {
            console.error(`[PLAYBOOK] run failed playbook=${playbookId} host=${hostId} error=${errorCode(err)}`);
        }
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

    // A sysscript_alert frame from sys.alerts.push. Host and tenant come from
    // the enrolled connection, never the frame. request_id must name a script
    // this server sent to this host that is still waiting for its result;
    // each such run stores at most ALERTS_PER_RUN_MAX alerts. The execution is
    // looked up before any await, so a command_result right behind the alert
    // does not drop it. Returns { alert } or { error }.
    async onAgentAlert(hostId, msg) {
        const requestId = typeof msg.request_id === 'string' ? msg.request_id : '';
        const ctx = requestId ? this.pendingExecutions.get(requestId) : null;
        const reject = (error) => {
            console.error(`[Fleet] sysscript_alert rejected host=${hostId} error=${error}`);
            return { error };
        };
        if (!ctx || ctx.hostId !== hostId) return reject('unknown_execution');
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        const { severity } = payload;
        if (!ALERT_SEVERITIES.has(severity)) return reject('bad_severity');
        if (typeof payload.message !== 'string' || Buffer.byteLength(payload.message, 'utf8') > ALERT_MESSAGE_MAX_BYTES) return reject('bad_message');
        // Postgres TEXT cannot hold U+0000.
        const message = truncateUtf8(noNul(payload.message), ALERT_MESSAGE_MAX_BYTES);
        ctx.alerts = (ctx.alerts || 0) + 1;
        if (ctx.alerts > ALERTS_PER_RUN_MAX) return reject('rate_limited');
        const tenantId = this.hostTenants.get(hostId);
        if (!tenantId || !this.registry) return reject('no_tenant');
        const alert = await this.registry.openAlert({
            tenant_id: tenantId,
            host_id: hostId,
            rule_name: 'sysscript',
            metric: null,
            value: null,
            severity,
            message
        });
        await this.registry.appendAudit({
            tenant_id: tenantId,
            host_id: hostId,
            actor: 'agent',
            action: 'sysscript_alert',
            payload: { alert_id: alert.id, request_id: requestId, severity }
        });
        console.log(`[Fleet] sysscript alert host=${hostId} severity=${severity} alert_id=${alert.id}`);
        return { alert };
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
        await this.putDarkStorageAudit(hostId, hash);
    }

    // The DarkStorage copy of an execution record: host, time and script
    // hash. Async jobs call it on end with the hash stored on the row.
    async putDarkStorageAudit(hostId, hash) {
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

    // The agent resends its whole list every telemetry tick. Write it only
    // when it changed or about SOFTWARE_REFRESH_MS has passed, in one
    // statement, never twice at once for a host and at most
    // SOFTWARE_MAX_CONCURRENT at once overall, and at most once per
    // SOFTWARE_MIN_WRITE_GAP_MS for a host: unawaited per-row writes piled
    // up and held the pool. A report that cannot run now is dropped; the next
    // tick carries the same list. A failed write or a refused list makes the
    // host wait SOFTWARE_RETRY_MS, so a list that always fails is not retried
    // every tick.
    async processSoftwareInventory(hostId, softwareList) {
        if (!this.registry || this.softwareInFlight.has(hostId)) return;
        if (this.softwareInFlight.size >= SOFTWARE_MAX_CONCURRENT) return;
        const now = Date.now();
        const last = this.softwareSeen.get(hostId);
        if (last && last.retryAt && now < last.retryAt) return;
        if (last && last.writtenAt && now - last.writtenAt < SOFTWARE_MIN_WRITE_GAP_MS) return;
        let added;
        this.softwareInFlight.add(hostId);
        try {
            const { items, digest, skipped } = normalizeSoftwareInventory(softwareList);
            if (last && !last.retryAt && last.digest === digest && now < last.refreshAt) return;
            if (skipped > 0 && (!last || last.digest !== digest)) {
                console.warn(`[Software Inventory] host ${hostId}: skipped ${skipped} item(s) with a field over the length limit`);
            }
            added = await this.registry.upsertSoftwareBatch(hostId, items);
            // Spread the hourly refresh so hosts that connected together do
            // not all rewrite in the same tick.
            const jitter = crypto.randomInt(0, Math.floor(SOFTWARE_REFRESH_MS / 4));
            this.softwareSeen.set(hostId, { digest, writtenAt: now, refreshAt: now + SOFTWARE_REFRESH_MS - jitter });
        } catch (err) {
            this.softwareSeen.set(hostId, { retryAt: now + SOFTWARE_RETRY_MS });
            throw new Error(`host ${hostId}: ${err.message}`, { cause: err });
        } finally {
            this.softwareInFlight.delete(hostId);
        }
        for (const sw of added) await this.checkDarkAPIForCVEs(hostId, sw.name, sw.version);
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
            this.pendingExecutions.set(requestId, { resolve, reject, script, hostId });
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
