/**
 * File channel, server side (docs/sah-file-protocol.md).
 *
 * One WebSocket is one session of strictly sequential request/response
 * operations under one ticket, one root and one identity, run on the host by
 * the agent's dropped-privilege file-helper.
 * Threats: a write through a read ticket (file:write needs both scopes at
 * issue and at the upgrade, the lease signs the mode, the server answers
 * read_only before forwarding, and the agent checks again), a root file
 * operation by an operator (file:root needs the admin-only scope, the policy
 * entry's root flag and a file_root lease), a ticket replayed or moved to
 * another host, purpose or root (consumed on first upgrade, bound to all
 * three, the root re-validated and the policy and scopes re-checked at the
 * upgrade), traversal (every path is checked against §5.1 here and again by
 * the agent, which resolves only beneath the held root fd), a client
 * confusing the audit order (one request at a time; a pipelined request or a
 * reused request_id is a protocol_error that ends the session), memory
 * growth (text frames 64 KiB, binary frames chunk_max, 1009 past either; an
 * 8 MiB credit window per session to the agent, the client paused while
 * there is no credit; agent data held only inside its window and credited
 * back only while the client's bufferedAmount is under 8 MiB; at most
 * write_window unacknowledged chunks; never drop bytes), sessions without
 * end (idle timeout, max duration, session byte cap, op cap, per-actor and
 * per-agent caps with 2 of the 16 agent slots kept for file:root, a signed 60 s lease renewed every 30 s only while the
 * actor's scope, membership, key and the root policy still allow it), and
 * changes without an audit trail (file_session_start is written before ready; an
 * intent row is written before every write_commit, mkdir and remove is
 * forwarded and a failure refuses the op with internal; result rows,
 * write_open and write_abort rows, coalesced file_read rows and
 * file_session_end follow, retried). Ticket values and file content are
 * never logged or audited.
 * Does NOT inspect content (FILE §9), does NOT defend against what the
 * pty_user may legitimately read inside the root or hard links (§5.6), and
 * does NOT persist sessions across a server restart.
 */
'use strict';

const WebSocket = require('ws');
const { ticketFromRequest } = require('../controlplane/httpauth');
const { consumeTicket } = require('../controlplane/tickets');
const { issueLease, filePayload } = require('../controlplane/lease');
const { FILE_PURPOSES, validateFileRoot } = require('../controlplane/channels');
const { FILE_WINDOW, creditFrame, creditBytes, encodeData } = require('../controlplane/credit');
const { randomToken } = require('../controlplane/token');
const {
    envInt, unref, sendJSON, channelUpgradeHost, recheckChannelTicket, appendAuditRetrying, ClientSink, AgentSource
} = require('./channel');

const SESSION_PREFIX = 'fls_';
const TEXT_FRAME_MAX = 64 * 1024;
const CHUNK_MAX = 1024 * 1024;
const READ_MAX = 8 * 1024 * 1024;
const LIST_MAX = 1000;
const WRITE_WINDOW = 8;
const CLIENT_BUFFER_MAX = 8 * 1024 * 1024;
const FILE_LEASE_TTL_S = 60;
const FILE_RENEW_MS = 30_000;
const FILE_START_TIMEOUT_MS = 30_000;
const FILE_FINAL_WAIT_MS = 5_000;
const FILE_MAX_SECONDS_DEFAULT = 28800;
const FILE_SECONDS_CAP = 7 * 86400;
const FILE_IDLE_SECONDS_DEFAULT = 900;
const FILE_MAX_BYTES_DEFAULT = 16 * 1024 ** 3;
const FILE_SESSION_BYTES_DEFAULT = 64 * 1024 ** 3;
const FILE_BYTES_CAP = 2 ** 50;
const FILE_MAX_OPS_DEFAULT = 100000;
const FILE_PER_ACTOR_DEFAULT = 4;
const FILE_PER_AGENT = 16;
// Of the per-agent slots, this many are only for file:root sessions, so an
// admin can always reach a host that operators have filled.
const FILE_ROOT_RESERVED = 2;
const PATH_MAX = 4096;
const COMPONENT_MAX = 255;
const CURSOR_MAX = 1024;

const REQUEST_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const MODE_RE = /^0[67][0-7]{2}$/;
const UPLOAD_ID_RE = /^upl_[A-Za-z0-9_-]{16,64}$/;
const OPS = new Set(['stat', 'list', 'read', 'hash', 'write_open', 'write_chunk', 'write_commit', 'write_abort', 'mkdir', 'remove']);
const MUTATING = new Set(['write_open', 'write_chunk', 'write_commit', 'write_abort', 'mkdir', 'remove']);
const INTENT_OPS = new Set(['write_commit', 'mkdir', 'remove']);
const SESSION_ERRORS = new Set([
    'ticket_invalid', 'scope_denied', 'agent_offline', 'agent_unsupported', 'lease_required', 'cap_reached',
    'root_denied', 'root_invalid', 'pty_user_unset', 'root_unavailable', 'protocol_error', 'internal'
]);
const OP_ERRORS = new Set([
    'bad_request', 'bad_path', 'reserved_name', 'not_found', 'not_a_file', 'not_a_dir', 'exists', 'not_empty',
    'symlink_refused', 'permission_denied', 'read_only', 'too_large', 'no_space', 'changed', 'sha256_mismatch',
    'offset_mismatch', 'upload_not_found', 'io_error'
]);
const CLOSE_REASONS = new Set(['idle_timeout', 'max_duration', 'byte_cap', 'op_cap', 'agent_disconnected', 'stopped']);

// --- exact JSON integers ---------------------------------------------------
// mtime_ns (nanoseconds since the epoch) does not fit a double. Integer
// literals of 16 or more digits are parsed as BigInt and written back as the
// same digits, so if_match and stat results survive the relay exactly.
const BIG_TAG = '\u0000sahbig:';

function tagBigIntegers(text) {
    let out = '';
    let last = 0;
    let inString = false;
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (inString) {
            if (c === '\\') i += 1;
            else if (c === '"') inString = false;
            continue;
        }
        if (c === '"') {
            inString = true;
            continue;
        }
        if (c === '-' || (c >= '0' && c <= '9')) {
            let j = i + 1;
            while (j < text.length && /[0-9.eE+-]/.test(text[j])) j += 1;
            const tok = text.slice(i, j);
            if (/^-?[0-9]{16,}$/.test(tok)) {
                out += `${text.slice(last, i)}"\\u0000sahbig:${tok}"`;
                last = j;
            }
            i = j - 1;
        }
    }
    return last === 0 ? text : out + text.slice(last);
}

function parseExact(text) {
    return JSON.parse(tagBigIntegers(text), (key, value) => (
        typeof value === 'string' && value.startsWith(BIG_TAG) ? BigInt(value.slice(BIG_TAG.length)) : value
    ));
}

function stringifyExact(obj) {
    return JSON.stringify(obj, (key, value) => (typeof value === 'bigint' ? JSON.rawJSON(value.toString()) : value));
}

function sendExact(ws, obj) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(stringifyExact(obj));
}

// --- request checks ----------------------------------------------------------

// FILE §5.1/§5.2. Returns null, 'bad_path' or 'reserved_name'.
function checkPath(p) {
    if (typeof p !== 'string' || !p.isWellFormed()) return 'bad_path';
    const bytes = Buffer.byteLength(p, 'utf8');
    if (bytes < 1 || bytes > PATH_MAX) return 'bad_path';
    if (p === '.') return null;
    if (p.startsWith('/')) return 'bad_path';
    if (/[\u0000-\u001f\u007f\\]/.test(p)) return 'bad_path';
    let reserved = false;
    for (const c of p.split('/')) {
        if (c === '' || c === '.' || c === '..' || Buffer.byteLength(c, 'utf8') > COMPONENT_MAX) return 'bad_path';
        if (c.length >= '.sahsync-.part'.length && c.startsWith('.sahsync-') && c.endsWith('.part')) reserved = true;
    }
    return reserved ? 'reserved_name' : null;
}

const isCount = (v) => Number.isSafeInteger(v) && v >= 0;
// mtime_ns is a signed 64-bit integer on the agent: -2^63 <= v < 2^63.
const NS_MIN = -(2n ** 63n);
const NS_LIMIT = 2n ** 63n;
const isNs = (v) => (typeof v === 'bigint' && v >= NS_MIN && v < NS_LIMIT) || Number.isSafeInteger(v);

function checkIfMatch(m) {
    if (m === undefined || m === null) return { ok: true, value: undefined };
    if (typeof m !== 'object' || Array.isArray(m) || !isCount(m.size) || !isNs(m.mtime_ns)) return { ok: false };
    return { ok: true, value: { size: m.size, mtime_ns: m.mtime_ns } };
}

// Builds the request forwarded to the agent from known fields only, or
// returns { error } for an operation error answered by the server.
function shapeRequest(op, cmd, limits) {
    const out = { request_id: cmd.request_id, op };
    const pathErr = checkPath(cmd.path);
    if (typeof cmd.path !== 'string') return { error: 'bad_request' };
    out.path = cmd.path;
    switch (op) {
        case 'stat':
        case 'remove':
            break;
        case 'list': {
            const cursor = cmd.cursor === undefined ? null : cmd.cursor;
            if (cursor !== null && (typeof cursor !== 'string' || cursor.length === 0 || cursor.length > CURSOR_MAX)) return { error: 'bad_request' };
            const limit = cmd.limit === undefined || cmd.limit === null ? 500 : cmd.limit;
            if (!Number.isInteger(limit) || limit < 1 || limit > LIST_MAX) return { error: 'bad_request' };
            out.cursor = cursor;
            out.limit = limit;
            break;
        }
        case 'read': {
            if (!isCount(cmd.offset) || !Number.isInteger(cmd.length) || cmd.length < 1 || cmd.length > READ_MAX) return { error: 'bad_request' };
            const m = checkIfMatch(cmd.if_match);
            if (!m.ok) return { error: 'bad_request' };
            if (cmd.offset + cmd.length > limits.fileMax) return { error: pathErr || 'too_large' };
            out.offset = cmd.offset;
            out.length = cmd.length;
            if (m.value) out.if_match = m.value;
            break;
        }
        case 'hash': {
            const m = checkIfMatch(cmd.if_match);
            if (!m.ok) return { error: 'bad_request' };
            if (m.value) out.if_match = m.value;
            break;
        }
        case 'write_open': {
            if (!isCount(cmd.size) || typeof cmd.sha256 !== 'string' || !SHA256_RE.test(cmd.sha256) || typeof cmd.overwrite !== 'boolean') return { error: 'bad_request' };
            if (cmd.mode !== undefined && (typeof cmd.mode !== 'string' || !MODE_RE.test(cmd.mode))) return { error: 'bad_request' };
            if (cmd.resume !== undefined && typeof cmd.resume !== 'boolean') return { error: 'bad_request' };
            if (pathErr) return { error: pathErr };
            if (cmd.size > limits.fileMax) return { error: 'too_large' };
            Object.assign(out, { size: cmd.size, sha256: cmd.sha256, overwrite: cmd.overwrite, resume: cmd.resume === true });
            if (cmd.mode !== undefined) out.mode = cmd.mode;
            break;
        }
        case 'mkdir':
            if (cmd.parents !== undefined && typeof cmd.parents !== 'boolean') return { error: 'bad_request' };
            if (cmd.mode !== undefined && (typeof cmd.mode !== 'string' || !MODE_RE.test(cmd.mode))) return { error: 'bad_request' };
            out.parents = cmd.parents === true;
            if (cmd.mode !== undefined) out.mode = cmd.mode;
            break;
        default:
            return { error: 'bad_request' };
    }
    if (pathErr) return { error: pathErr };
    return { req: out };
}

function count(v) {
    return Number.isSafeInteger(v) && v >= 0 ? v : null;
}

class FileChannels {
    constructor(fm) {
        this.fm = fm;
        this.sessions = new Map();
        this.stopping = new Map();
        this.wss = new WebSocket.Server({ noServer: true, maxPayload: CHUNK_MAX });
        this.renewMs = FILE_RENEW_MS;
        this.startTimeoutMs = FILE_START_TIMEOUT_MS;
        this.finalWaitMs = FILE_FINAL_WAIT_MS;
        this.pollMs = 20;
        this.clientBufferMax = CLIENT_BUFFER_MAX;
        this.auditFailures = 0;
    }

    get env() {
        return this.fm.env || {};
    }

    static owns(sessionId) {
        return typeof sessionId === 'string' && sessionId.startsWith(SESSION_PREFIX);
    }

    upgrade(request, socket, head, parsed) {
        const hostId = channelUpgradeHost(this.env, request, socket, parsed, 'file');
        if (hostId === null) return;
        this.wss.handleUpgrade(request, socket, head, (ws) => {
            this.open(ws, parsed, hostId).catch((err) => {
                console.error('[Fleet] file open failed:', err.message);
                this.failSocket(ws, 'internal');
            });
        });
    }

    failSocket(ws, code) {
        sendJSON(ws, { type: 'file_status', payload: { error: code } });
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close(1011);
    }

    liveFor(predicate) {
        let n = 0;
        for (const s of this.sessions.values()) if (predicate(s)) n += 1;
        return n;
    }

    async open(ws, parsed, hostId) {
        const fm = this.fm;
        let session = null;
        const early = { closed: false, failed: false };
        ws.on('error', (err) => {
            if (err && err.code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH' && session) session.clientError = 'frame_too_large';
            else if (!(err && err.code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH')) console.error('[Fleet] file socket error:', err && err.message);
        });
        ws.on('message', (buf, isBinary) => {
            if (session) {
                this.onClientMessage(session, buf, isBinary);
                return;
            }
            // A request before ready is a protocol_error (FILE §3).
            if (early.failed) return;
            early.failed = true;
            this.failSocket(ws, 'protocol_error');
        });
        ws.on('close', () => {
            if (session) this.onClientClose(session);
            else early.closed = true;
        });

        if (!fm.tickets) {
            this.failSocket(ws, 'internal');
            return;
        }
        const ticketRes = ticketFromRequest(parsed);
        if (!ticketRes.ok) {
            this.failSocket(ws, 'ticket_invalid');
            return;
        }
        // Consumed on first upgrade, even when host, purpose or root do not
        // match.
        const purpose = parsed.searchParams.get('purpose') || '';
        const row = consumeTicket(fm.tickets, ticketRes.ticket, hostId, purpose);
        if (!row || !FILE_PURPOSES.has(purpose)) {
            this.failSocket(ws, 'ticket_invalid');
            return;
        }
        const checked = validateFileRoot(row.root, purpose);
        if (!checked.ok) {
            this.failSocket(ws, 'ticket_invalid');
            return;
        }
        if (!fm.signer) {
            this.failSocket(ws, 'lease_required');
            return;
        }
        const denied = await recheckChannelTicket(fm.registry, row, purpose, { root: checked.root });
        if (early.closed || early.failed) return;
        if (denied) {
            this.failSocket(ws, denied);
            return;
        }
        const agentWs = fm.connectedAgents.get(hostId);
        if (!agentWs || agentWs.readyState !== WebSocket.OPEN) {
            this.failSocket(ws, 'agent_offline');
            return;
        }
        if (!fm.agentSupports(hostId, 'file')) {
            this.failSocket(ws, 'agent_unsupported');
            return;
        }
        const actor = row.actor || null;
        const perActor = envInt(this.env, 'SYSTEMAPI_FILE_MAX_PER_ACTOR', FILE_PER_ACTOR_DEFAULT, 1, 100000);
        const agentCap = purpose === 'file:root' ? FILE_PER_AGENT : FILE_PER_AGENT - FILE_ROOT_RESERVED;
        if (this.liveFor((s) => s.actor === actor) >= perActor || this.liveFor((s) => s.agent === agentWs) >= agentCap) {
            console.warn('[Fleet] file refused: session cap reached');
            this.failSocket(ws, 'cap_reached');
            return;
        }

        const sessionId = `${SESSION_PREFIX}${randomToken(16)}`;
        const maxSeconds = envInt(this.env, 'SYSTEMAPI_FILE_MAX_SECONDS', FILE_MAX_SECONDS_DEFAULT, 1, FILE_SECONDS_CAP);
        const idleSeconds = envInt(this.env, 'SYSTEMAPI_FILE_IDLE_SECONDS', FILE_IDLE_SECONDS_DEFAULT, 1, FILE_SECONDS_CAP);
        const fileMax = envInt(this.env, 'SYSTEMAPI_FILE_MAX_BYTES', FILE_MAX_BYTES_DEFAULT, 1, FILE_BYTES_CAP);
        const sessionBytes = envInt(this.env, 'SYSTEMAPI_FILE_SESSION_BYTES', FILE_SESSION_BYTES_DEFAULT, 1, FILE_BYTES_CAP);
        const maxOps = envInt(this.env, 'SYSTEMAPI_FILE_MAX_OPS', FILE_MAX_OPS_DEFAULT, 1, 1e9);
        const startedMs = Date.now();
        const deadlineUnix = Math.floor(startedMs / 1000) + maxSeconds;
        const action = purpose === 'file:root' ? 'file_root' : 'file';
        const mode = purpose === 'file:read' ? 'read' : 'write';
        let lease;
        try {
            lease = issueLease(fm.signer, {
                hostId,
                action,
                payload: filePayload(sessionId, deadlineUnix, 'start', mode, checked.root),
                ttl: FILE_LEASE_TTL_S
            });
        } catch (err) {
            this.failSocket(ws, 'lease_required');
            return;
        }
        let stream;
        try {
            stream = fm.agentCreditLedger(agentWs).open(sessionId, { window: FILE_WINDOW });
        } catch (err) {
            this.failSocket(ws, 'internal');
            return;
        }
        const s = {
            id: sessionId,
            hostId,
            tenantId: row.tenantId,
            actor,
            auth: row.auth || null,
            purpose,
            action,
            mode,
            root: checked.root,
            canonRoot: null,
            client: ws,
            agent: agentWs,
            stream,
            sink: null,
            source: null,
            ready: false,
            ended: false,
            finalized: false,
            clientError: null,
            limits: { fileMax, sessionBytes, maxOps },
            seen: new Set(),
            inflight: null, // { rid, op, req }
            write: null, // { rid, uploadId, path, size, sha256, next, unacked, closing }
            lastWriteRid: null,
            discardRids: new Map(), // closed write rid -> chunks still accepted and dropped
            expectBinary: null, // { length, forward }
            read: null, // { rid, path, offset, received, held: [], heldLen }
            reads: new Map(),
            ops: 0,
            statCount: 0,
            listCount: 0,
            bytesRead: 0,
            bytesWritten: 0,
            lastActivityMs: startedMs,
            idleMs: idleSeconds * 1000,
            deadlineUnix,
            startedMs,
            renewTimer: null,
            renewing: false,
            maxTimer: null,
            startTimer: null,
            idleTimer: null,
            finalTimer: null,
            agentCounts: null,
            endReason: null
        };
        s.sink = new ClientSink({
            client: ws,
            stream,
            pollMs: this.pollMs,
            maxBuffered: this.clientBufferMax,
            frameMax: CHUNK_MAX,
            onCredit: (n) => sendJSON(s.agent, creditFrame('file', s.id, n))
        });
        s.source = new AgentSource({
            client: ws,
            stream,
            maxQueued: FILE_WINDOW + CHUNK_MAX,
            send: (chunk) => {
                if (s.agent.readyState === WebSocket.OPEN) s.agent.send(encodeData(s.id, chunk));
            }
        });
        this.sessions.set(sessionId, s);
        session = s;
        sendJSON(ws, { type: 'file_status', payload: { status: 'starting' } });
        sendJSON(agentWs, {
            type: 'file_open',
            session_id: sessionId,
            action,
            mode,
            root: checked.root,
            deadline_unix: deadlineUnix,
            idle_s: idleSeconds,
            file_max: fileMax,
            actor: actor === null ? '' : String(actor),
            lease
        });
        s.renewTimer = unref(setInterval(() => { this.renew(s); }, this.renewMs));
        s.maxTimer = unref(setTimeout(() => this.end(s, 'max_duration', { notifyClient: true, notifyAgent: true }), maxSeconds * 1000));
        s.startTimer = unref(setTimeout(() => {
            if (!s.ready) this.end(s, 'start_timeout', { error: 'internal', notifyAgent: true });
        }, this.startTimeoutMs));
    }

    // Each renewal re-checks the ticket's grant first: an actor who lost the
    // scope or the membership, a revoked key, or a root the policy stopped
    // allowing ends the session with stopped and gets no new lease. A failed
    // lookup only skips this renewal: the agent ends the session when the
    // last lease lapses.
    async renew(s) {
        if (s.ended || !this.fm.signer || s.renewing) return;
        s.renewing = true;
        let denied;
        try {
            denied = await recheckChannelTicket(this.fm.registry,
                { actor: s.actor, tenantId: s.tenantId, auth: s.auth, hostId: s.hostId }, s.purpose, { root: s.root });
        } finally {
            s.renewing = false;
        }
        if (s.ended) return;
        if (denied === 'internal') {
            console.error('[Fleet] file lease renewal skipped: re-check unavailable');
            return;
        }
        if (denied) {
            console.warn(`[Fleet] file ${s.id}: grant withdrawn (${denied}); ending session`);
            this.end(s, 'stopped', { notifyClient: true, notifyAgent: true });
            return;
        }
        try {
            const lease = issueLease(this.fm.signer, {
                hostId: s.hostId,
                action: s.action,
                payload: filePayload(s.id, s.deadlineUnix, 'renew', s.mode, s.root),
                ttl: FILE_LEASE_TTL_S
            });
            sendJSON(s.agent, { type: 'file_renew', session_id: s.id, lease });
        } catch (err) {
            console.error('[Fleet] file lease renewal failed:', err.message);
        }
    }

    touch(s) {
        s.lastActivityMs = Date.now();
    }

    scheduleIdle(s) {
        clearTimeout(s.idleTimer);
        const wait = Math.max(10, s.lastActivityMs + s.idleMs - Date.now());
        s.idleTimer = unref(setTimeout(() => {
            if (s.ended) return;
            if (Date.now() - s.lastActivityMs >= s.idleMs) {
                this.end(s, 'idle_timeout', { notifyClient: true, notifyAgent: true });
                return;
            }
            this.scheduleIdle(s);
        }, wait));
    }

    protocolError(s) {
        this.end(s, 'protocol_error', { error: 'protocol_error', notifyAgent: true });
    }

    audit(s, action, payload) {
        return this.fm.registry.appendAudit({ tenant_id: s.tenantId, host_id: s.hostId, actor: s.actor, action, payload });
    }

    auditRetrying(s, action, payload) {
        const fm = this.fm;
        return appendAuditRetrying(fm.registry, { tenant_id: s.tenantId, host_id: s.hostId, actor: s.actor, action, payload },
            fm.auditRetryDelaysMs, (err) => {
                this.auditFailures += 1;
                if (fm.metrics && fm.metrics.terminalAuditFailures) fm.metrics.terminalAuditFailures.inc();
                console.error(`[Fleet] file ${action} audit failed:`, err && err.message);
            }, (kind, fp, detail) => fm.noteSecurity(kind, fp, detail)).catch((err) => {
            console.error(`[Fleet] file ${action} audit failed:`, err.message);
            return false;
        });
    }

    // Every frame to the client goes through the sink, after any read data
    // queued before it.
    toClient(s, obj) {
        s.sink.after(() => sendExact(s.client, obj));
    }

    clientResult(s, rid, op, error, fields = {}) {
        const out = { type: 'file_result', request_id: rid, op, status: error ? 'error' : 'ok', error: error || null };
        if (!error) {
            for (const [k, v] of Object.entries(fields)) {
                if (!(k in out)) out[k] = v;
            }
        }
        this.toClient(s, out);
    }

    toAgent(s, req) {
        s.source.after(() => {
            if (s.agent.readyState === WebSocket.OPEN) s.agent.send(stringifyExact({ type: 'file_req', session_id: s.id, request: req }));
        });
    }

    onClientMessage(s, buf, isBinary) {
        if (s.ended) return;
        this.touch(s);
        if (isBinary) {
            this.onClientBinary(s, buf);
            return;
        }
        if (buf.length > TEXT_FRAME_MAX) {
            this.end(s, 'frame_too_large', { notifyAgent: true, closeCode: 1009 });
            return;
        }
        if (!s.ready || s.expectBinary) {
            this.protocolError(s);
            return;
        }
        let cmd;
        try {
            cmd = parseExact(buf.toString('utf8'));
        } catch {
            this.protocolError(s);
            return;
        }
        if (!cmd || typeof cmd !== 'object' || Array.isArray(cmd) || typeof cmd.type !== 'string' || typeof cmd.request_id !== 'string' || !REQUEST_ID_RE.test(cmd.request_id)) {
            this.protocolError(s);
            return;
        }
        // A request names its op in `op` (type "file_request"); the §6 chunk
        // header names it in `type`. Either spelling is accepted.
        let op = typeof cmd.op === 'string' ? cmd.op : null;
        if (op === null && OPS.has(cmd.type)) op = cmd.type;
        if (op !== null && cmd.type !== 'file_request' && cmd.type !== op) {
            this.protocolError(s);
            return;
        }
        if (op === 'write_chunk') {
            this.onWriteChunk(s, cmd);
            return;
        }
        if ((op === 'write_commit' || op === 'write_abort') && s.write && cmd.request_id === s.write.rid) {
            this.onWriteEnd(s, op, cmd);
            return;
        }
        // Strictly sequential: nothing while a result is pending or a write
        // is open (only that write's chunk, commit and abort).
        if (s.inflight || s.write || s.seen.has(cmd.request_id)) {
            this.protocolError(s);
            return;
        }
        s.seen.add(cmd.request_id);
        if (!this.countOp(s)) return;
        if (op === null || !OPS.has(op)) {
            this.clientResult(s, cmd.request_id, typeof op === 'string' ? op.slice(0, 64) : null, 'bad_request');
            return;
        }
        if (MUTATING.has(op) && s.mode !== 'write') {
            this.clientResult(s, cmd.request_id, op, 'read_only');
            return;
        }
        if (op === 'write_commit' || op === 'write_abort') {
            this.clientResult(s, cmd.request_id, op, 'upload_not_found');
            return;
        }
        const shaped = shapeRequest(op, cmd, s.limits);
        if (shaped.error) {
            this.clientResult(s, cmd.request_id, op, shaped.error);
            return;
        }
        const req = shaped.req;
        if (op === 'read' && s.bytesRead + s.bytesWritten + req.length > s.limits.sessionBytes) {
            this.end(s, 'byte_cap', { notifyClient: true, notifyAgent: true });
            return;
        }
        s.inflight = { rid: cmd.request_id, op, req };
        if (op === 'read') s.read = { rid: cmd.request_id, path: req.path, offset: req.offset, received: 0, held: [], heldLen: 0 };
        if (INTENT_OPS.has(op)) {
            this.forwardWithIntent(s, req, { op, path: req.path });
            return;
        }
        this.toAgent(s, req);
    }

    countOp(s) {
        if (s.ops + 1 > s.limits.maxOps) {
            this.end(s, 'op_cap', { notifyClient: true, notifyAgent: true });
            return false;
        }
        s.ops += 1;
        return true;
    }

    // The intent row is written before the op is forwarded; a failure
    // refuses it with internal (FILE §9).
    forwardWithIntent(s, req, intent) {
        this.audit(s, 'file_intent', { session_id: s.id, ...intent }).then(() => {
            if (s.ended) return;
            this.toAgent(s, req);
        }, (err) => {
            console.error('[Fleet] file intent audit failed:', err.message);
            if (s.ended) return;
            s.inflight = null;
            if (req.op === 'write_commit' && s.write) s.write.closing = false;
            this.clientResult(s, req.request_id, req.op, 'internal');
        });
    }

    onWriteChunk(s, cmd) {
        const rid = cmd.request_id;
        const length = cmd.length;
        if (!Number.isInteger(length) || length < 1 || length > CHUNK_MAX || !isCount(cmd.offset)) {
            this.protocolError(s);
            return;
        }
        const w = s.write;
        if (!w || w.rid !== rid || w.closing) {
            // Chunks already in flight when their write ended are dropped:
            // at most write_window of them (all a client may have
            // unacknowledged); one more is a protocol_error, so a closed
            // write is never a way around the byte and op caps.
            const left = s.discardRids.get(rid);
            if (left !== undefined) {
                if (left <= 0) {
                    this.protocolError(s);
                    return;
                }
                s.discardRids.set(rid, left - 1);
                s.expectBinary = { length, forward: false };
                return;
            }
            this.protocolError(s);
            return;
        }
        if (w.unacked >= WRITE_WINDOW) {
            this.protocolError(s);
            return;
        }
        let error = null;
        if (cmd.offset !== w.next) error = 'offset_mismatch';
        else if (cmd.offset + length > w.size) error = 'too_large';
        if (error) {
            this.failWrite(s, error, 'write_chunk');
            s.expectBinary = { length, forward: false };
            return;
        }
        if (s.bytesRead + s.bytesWritten + length > s.limits.sessionBytes) {
            this.end(s, 'byte_cap', { notifyClient: true, notifyAgent: true });
            return;
        }
        s.expectBinary = { length, forward: true, offset: cmd.offset, rid };
    }

    // Ends the open write after a chunk failure: the client gets the error,
    // the agent keeps the temp file for resume, and chunks still in flight
    // are dropped.
    failWrite(s, error, op) {
        const w = s.write;
        if (!w) return;
        s.write = null;
        s.discardRids.set(w.rid, WRITE_WINDOW);
        this.clientResult(s, w.rid, op, error);
        this.toAgent(s, { request_id: w.rid, op: 'write_release' });
    }

    onClientBinary(s, buf) {
        const exp = s.expectBinary;
        if (!s.ready || !exp || buf.length !== exp.length) {
            this.protocolError(s);
            return;
        }
        s.expectBinary = null;
        if (!exp.forward) return;
        const w = s.write;
        if (!w || w.rid !== exp.rid) return;
        const header = { type: 'file_chunk', session_id: s.id, request_id: exp.rid, offset: exp.offset, length: buf.length };
        s.source.after(() => sendJSON(s.agent, header));
        w.next += buf.length;
        w.unacked += 1;
        s.bytesWritten += buf.length;
        if (!s.source.push(buf)) {
            console.warn(`[Fleet] file ${s.id}: client queue over its cap; ending session`);
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
        }
    }

    onWriteEnd(s, op, cmd) {
        const w = s.write;
        if (s.inflight || w.closing || s.expectBinary) {
            this.protocolError(s);
            return;
        }
        if (!this.countOp(s)) return;
        w.closing = true;
        const req = { request_id: w.rid, op };
        s.inflight = { rid: w.rid, op, req };
        if (op === 'write_commit') {
            this.forwardWithIntent(s, req, { op, path: w.path, size: w.size, sha256: w.sha256, upload_id: w.uploadId });
            return;
        }
        this.toAgent(s, req);
    }

    onClientClose(s) {
        if (s.ended) return;
        this.end(s, s.clientError || 'client_closed', { notifyAgent: true });
    }

    agentSession(ws, hostId, sessionId) {
        if (typeof sessionId !== 'string') return null;
        const s = this.sessions.get(sessionId);
        if (!s || s.ended || s.agent !== ws || s.hostId !== hostId) return null;
        return s;
    }

    onAgentData(ws, hostId, sessionId, data) {
        const ledger = this.fm.agentCreditLedger(ws);
        if (!ledger.receive(sessionId, data.length)) return;
        const s = this.agentSession(ws, hostId, sessionId);
        if (!s || data.length === 0) return;
        const r = s.read;
        if (!r || r.received + data.length > s.inflight.req.length) {
            console.warn(`[Fleet] file ${s.id}: agent data outside a read; ending session`);
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            return;
        }
        this.touch(s);
        r.received += data.length;
        r.held.push(Buffer.from(data));
        r.heldLen += data.length;
        while (r.heldLen >= CHUNK_MAX) this.emitReadChunk(s, CHUNK_MAX);
    }

    // Sends one read_chunk text frame and exactly one binary frame (FILE §6).
    emitReadChunk(s, n) {
        const r = s.read;
        const all = Buffer.concat(r.held, r.heldLen);
        const chunk = all.subarray(0, n);
        const rest = all.subarray(n);
        r.held = rest.length ? [rest] : [];
        r.heldLen = rest.length;
        const header = { type: 'read_chunk', request_id: r.rid, offset: r.offset, length: n };
        r.offset += n;
        s.bytesRead += n;
        s.sink.after(() => sendJSON(s.client, header));
        s.sink.push(chunk);
    }

    async onAgentFrame(ws, hostId, msg, raw) {
        const sid = msg.session_id;
        if (msg.type === 'file_credit') {
            const n = creditBytes(msg);
            const ledger = this.fm.agentCreditLedger(ws);
            if (n === null) {
                if (this.agentSession(ws, hostId, sid)) ledger.violation(sid, 'credit_malformed');
                return;
            }
            if (!ledger.grant(sid, n)) return;
            const s = this.agentSession(ws, hostId, sid);
            if (s) s.source.pump();
            return;
        }
        if (msg.type === 'file_closed') {
            this.onAgentClosed(ws, hostId, msg);
            return;
        }
        const s = this.agentSession(ws, hostId, sid);
        if (!s) return;
        if (msg.type === 'file_status') {
            await this.onAgentStatus(s, msg);
            return;
        }
        if (!s.ready) return;
        if (msg.type === 'file_write_ack') {
            this.onAgentAck(s, msg);
            return;
        }
        if (msg.type === 'file_result') {
            let exact;
            try {
                exact = parseExact(raw.toString('utf8'));
            } catch {
                exact = msg;
            }
            await this.onAgentResult(s, exact);
        }
    }

    async onAgentStatus(s, msg) {
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        if (payload.error) {
            const code = !s.ready && SESSION_ERRORS.has(payload.error) ? payload.error : 'internal';
            this.end(s, code, { error: code });
            return;
        }
        if (payload.status !== 'ready' || s.ready) return;
        const root = payload.root;
        const user = payload.user;
        const uid = payload.uid;
        if (typeof root !== 'string' || !validateFileRoot(root, 'file:read').ok || root === '~' || (s.root !== '~' && root !== s.root)
            || typeof user !== 'string' || user.length === 0 || user.length > 64 || !Number.isSafeInteger(uid) || uid < 0) {
            console.warn(`[Fleet] file ${s.id}: agent reported an unexpected root or user; ending session`);
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            return;
        }
        if (s.purpose === 'file:root' && uid !== 0) {
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            return;
        }
        clearTimeout(s.startTimer);
        s.canonRoot = root;
        try {
            await this.audit(s, 'file_session_start', { session_id: s.id, purpose: s.purpose, root, user, uid });
        } catch (err) {
            console.error('[Fleet] file start audit failed:', err.message);
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            return;
        }
        if (s.ended) return;
        s.ready = true;
        sendJSON(s.client, {
            type: 'file_status',
            payload: {
                status: 'ready',
                session_id: s.id,
                root,
                user,
                limits: { chunk_max: CHUNK_MAX, read_max: READ_MAX, write_window: WRITE_WINDOW, file_max: s.limits.fileMax, list_max: LIST_MAX }
            }
        });
        this.touch(s);
        this.scheduleIdle(s);
        s.sink.open();
    }

    onAgentAck(s, msg) {
        const off = msg.offset;
        if (typeof msg.request_id !== 'string' || !isCount(off)) return;
        const w = s.write;
        if (w && w.rid === msg.request_id) {
            w.unacked = Math.max(0, w.unacked - 1);
        } else if (msg.request_id !== s.lastWriteRid) {
            return;
        }
        this.touch(s);
        this.toClient(s, { type: 'write_ack', request_id: msg.request_id, offset: off });
    }

    readRow(s, path) {
        let row = s.reads.get(path);
        if (!row) {
            row = { bytes: 0, ranges: 0, sha256: null };
            s.reads.set(path, row);
        }
        return row;
    }

    async onAgentResult(s, msg) {
        const rid = msg.request_id;
        const op = msg.op;
        const status = msg.status;
        const error = status === 'ok' ? null : (OP_ERRORS.has(msg.error) ? msg.error : 'io_error');
        const fields = {};
        for (const [k, v] of Object.entries(msg)) {
            if (!['type', 'session_id', 'request_id', 'op', 'status', 'error'].includes(k)) fields[k] = v;
        }
        // A chunk the agent could not write ends the open write.
        if (op === 'write_chunk' && s.write && rid === s.write.rid && !s.write.closing) {
            const w = s.write;
            s.write = null;
            s.discardRids.set(w.rid, WRITE_WINDOW);
            this.clientResult(s, rid, 'write_chunk', error || 'io_error');
            return;
        }
        const inf = s.inflight;
        if (!inf || inf.rid !== rid || inf.op !== op) {
            console.warn(`[Fleet] file ${s.id}: unexpected result from agent ignored`);
            return;
        }
        this.touch(s);
        switch (op) {
            case 'stat':
                s.statCount += 1;
                break;
            case 'list':
                s.listCount += 1;
                break;
            case 'read': {
                const r = s.read;
                s.read = null;
                if (error && r.heldLen > 0) {
                    // Bytes of a failed read are never sent; their credit
                    // still goes back so the window does not shrink.
                    const credit = s.stream.drain(r.heldLen);
                    if (credit > 0) sendJSON(s.agent, creditFrame('file', s.id, credit));
                }
                if (!error) {
                    if (r.heldLen > 0) {
                        s.read = r;
                        this.emitReadChunk(s, r.heldLen);
                        s.read = null;
                    }
                    if (fields.bytes !== r.received) {
                        console.warn(`[Fleet] file ${s.id}: read byte count mismatch; ending session`);
                        this.end(s, 'internal', { error: 'internal', notifyAgent: true });
                        return;
                    }
                    const row = this.readRow(s, r.path);
                    row.bytes += r.received;
                    row.ranges += 1;
                }
                break;
            }
            case 'hash':
                if (!error && typeof fields.sha256 === 'string' && SHA256_RE.test(fields.sha256)) this.readRow(s, inf.req.path).sha256 = fields.sha256;
                break;
            case 'write_open': {
                const req = inf.req;
                const uploadId = typeof fields.upload_id === 'string' && UPLOAD_ID_RE.test(fields.upload_id) ? fields.upload_id : null;
                const offset = fields.offset;
                const okOpen = !error && uploadId && isCount(offset) && offset <= req.size;
                const logged = await this.auditRetrying(s, 'file_op', {
                    session_id: s.id, op, path: req.path, size: req.size, sha256: req.sha256, overwrite: req.overwrite,
                    upload_id: uploadId, offset: okOpen ? offset : null, result: error || (okOpen ? 'ok' : 'internal')
                });
                if (s.ended) return;
                s.inflight = null;
                if (!error && (!okOpen || !logged)) {
                    this.toAgent(s, { request_id: rid, op: 'write_release' });
                    this.clientResult(s, rid, op, 'internal');
                    return;
                }
                if (okOpen) {
                    s.write = { rid, uploadId, path: req.path, size: req.size, sha256: req.sha256, next: offset, unacked: 0, closing: false };
                    s.lastWriteRid = rid;
                }
                this.clientResult(s, rid, op, error, fields);
                return;
            }
            case 'write_commit':
            case 'write_abort': {
                const w = s.write;
                s.write = null;
                if (w) s.discardRids.set(w.rid, WRITE_WINDOW);
                const payload = { session_id: s.id, op, path: w ? w.path : null, size: w ? w.size : null, upload_id: w ? w.uploadId : null, result: error || 'ok' };
                if (op === 'write_commit') payload.sha256 = !error && typeof fields.sha256 === 'string' ? fields.sha256 : (w ? w.sha256 : null);
                await this.auditRetrying(s, 'file_op', payload);
                if (s.ended) return;
                break;
            }
            case 'mkdir':
            case 'remove':
                await this.auditRetrying(s, 'file_op', { session_id: s.id, op, path: inf.req.path, result: error || 'ok' });
                if (s.ended) return;
                break;
            default:
                break;
        }
        s.inflight = null;
        this.clientResult(s, rid, op, error, fields);
    }

    onAgentClosed(ws, hostId, msg) {
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        const agentCounts = {
            reason: typeof payload.reason === 'string' ? payload.reason.replace(/[^a-z_]/g, '').slice(0, 32) : null,
            ops: count(payload.ops), bytes_read: count(payload.bytes_read), bytes_written: count(payload.bytes_written)
        };
        const stopping = typeof msg.session_id === 'string' ? this.stopping.get(msg.session_id) : null;
        if (stopping && stopping.agent === ws && stopping.hostId === hostId) {
            this.finalize(stopping, agentCounts);
            return;
        }
        const s = this.agentSession(ws, hostId, msg.session_id);
        if (!s) return;
        if (CLOSE_REASONS.has(agentCounts.reason)) {
            this.end(s, agentCounts.reason, { notifyClient: true, agentCounts });
            return;
        }
        this.end(s, 'internal', { error: 'internal', agentCounts });
    }

    onAgentGone(ws) {
        for (const s of [...this.sessions.values()]) {
            if (s.agent === ws) this.end(s, 'agent_disconnected', { notifyClient: true });
        }
        for (const s of [...this.stopping.values()]) {
            if (s.agent === ws) this.finalize(s, null);
        }
    }

    // Ends a session once. opts.error: file_status error, close 1011.
    // opts.notifyClient: file_close, close 1000. opts.closeCode: close with
    // that code and no frame (1009). opts.notifyAgent: file_stop, then wait
    // briefly for the agent's file_closed (its counts).
    end(s, reason, opts = {}) {
        if (s.ended) return;
        s.ended = true;
        s.endReason = reason;
        clearInterval(s.renewTimer);
        clearTimeout(s.maxTimer);
        clearTimeout(s.startTimer);
        clearTimeout(s.idleTimer);
        this.sessions.delete(s.id);
        s.sink.stop();
        s.source.stop();
        this.fm.agentCreditLedger(s.agent).close(s.id);
        const ws = s.client;
        if (opts.error) {
            this.failSocket(ws, opts.error);
        } else if (opts.closeCode) {
            if (ws.readyState === WebSocket.OPEN) ws.close(opts.closeCode);
        } else if (opts.notifyClient && ws.readyState === WebSocket.OPEN) {
            sendJSON(ws, { type: 'file_close', payload: { session_id: s.id, reason, ops: s.ops, bytes_read: s.bytesRead, bytes_written: s.bytesWritten } });
            ws.close(1000);
        }
        if (ws.isPaused && ws.readyState === WebSocket.OPEN) ws.resume();
        if (opts.agentCounts) {
            this.finalize(s, opts.agentCounts);
            return;
        }
        const agentOpen = s.agent.readyState === WebSocket.OPEN;
        if ((opts.notifyAgent || opts.notifyClient) && agentOpen && reason !== 'agent_disconnected') {
            sendJSON(s.agent, { type: 'file_stop', session_id: s.id });
            this.stopping.set(s.id, s);
            s.finalTimer = unref(setTimeout(() => this.finalize(s, null), this.finalWaitMs));
            return;
        }
        this.finalize(s, null);
    }

    // Writes the coalesced file_read rows, then file_session_end, once.
    finalize(s, agentCounts) {
        if (s.finalized) return;
        s.finalized = true;
        clearTimeout(s.finalTimer);
        this.stopping.delete(s.id);
        s.agentCounts = agentCounts;
        const rows = [...s.reads.entries()];
        const end = {
            session_id: s.id,
            reason: s.endReason,
            ops: s.ops,
            bytes_read: s.bytesRead,
            bytes_written: s.bytesWritten,
            stat_count: s.statCount,
            list_count: s.listCount,
            duration_s: Math.round((Date.now() - s.startedMs) / 1000)
        };
        (async () => {
            if (!s.ready) {
                // No session_start row was written: nothing to close.
                return;
            }
            for (const [path, row] of rows) {
                await this.auditRetrying(s, 'file_read', { session_id: s.id, path, bytes: row.bytes, ranges: row.ranges, sha256: row.sha256 });
            }
            await this.auditRetrying(s, 'file_session_end', end);
        })().catch((err) => console.error('[Fleet] file end audit failed:', err.message));
    }
}

module.exports = {
    FileChannels,
    checkPath,
    parseExact,
    stringifyExact,
    CHUNK_MAX,
    READ_MAX,
    WRITE_WINDOW,
    LIST_MAX,
    FILE_PER_AGENT,
    FILE_ROOT_RESERVED,
    CLOSE_REASONS,
    SESSION_ERRORS
};
