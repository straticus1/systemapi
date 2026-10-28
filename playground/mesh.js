/**
 * Mesh channel, server side (docs/sah-mesh-protocol.md).
 *
 * One WebSocket from sahmesh carries many TCP streams to one host. Each
 * stream is a TcpChannels session (playground/tcp.js startSession) behind
 * a per-stream view of this socket, so a stream has the same target
 * validation, policy, signed tcp lease, renewal, idle, byte cap, caps and
 * tcp_start / tcp_end rows as a tcp:open channel. The agent is unchanged.
 *
 * Threats: an SSRF pivot through a binding-less ticket (every mesh_open is
 * validated, checked against the refused classes and the server policy, and
 * re-checked at every lease renewal; the lease signs the exact target), a
 * mesh ticket used for a single TCP channel or the reverse (purposes do not
 * cross; mesh:open is its own scope, re-checked at the upgrade, every 30 s
 * for the session and at every stream renewal; a loss ends everything with
 * stopped), a replayed or swapped ticket (consumed on first upgrade), one
 * stream starving the others or growing server memory (per-stream credit
 * windows toward the client in both directions, the 1 MiB bufferedAmount
 * gate, the agent-side windows; a client past its window or returning credit
 * it is not owed is disconnected), stream ids replayed to confuse accounting
 * (strictly increasing, never reused), one actor or agent taking every
 * stream (the TCP per-actor and per-agent caps are shared with tcp:open;
 * SYSTEMAPI_MESH_MAX_PER_ACTOR sessions per actor), a session that never
 * ends (SYSTEMAPI_MESH_MAX_SECONDS, SYSTEMAPI_MESH_IDLE_SECONDS with no live
 * stream), a session without a trail (mesh_start before mesh_ready, mesh_end
 * retried, each stream's rows carry the mesh id). Ticket values are never
 * logged. Does NOT inspect or record content (TCP §9), does NOT open a
 * listener on a host (MESH §10) and does NOT persist sessions across a
 * restart.
 */
'use strict';

const WebSocket = require('ws');
const { ticketFromRequest } = require('../controlplane/httpauth');
const { consumeTicket } = require('../controlplane/tickets');
const { validateTcpTarget, policyDecision } = require('../controlplane/channels');
const { TCP_WINDOW, CreditStream, creditBytes } = require('../controlplane/credit');
const { randomToken } = require('../controlplane/token');
const {
    CHANNEL_FRAME_MAX, envInt, unref, sendJSON, channelUpgradeHost, recheckChannelTicket, appendAuditRetrying
} = require('./channel');
const { TCP_PER_AGENT } = require('./tcp');

const MESH_PURPOSE = 'mesh:open';
const TCP_PURPOSE = 'tcp:open';
const SESSION_PREFIX = 'msh_';
const STREAM_HEADER = 4;
const STREAM_ID_MAX = 2 ** 32 - 1;
const MESH_RECHECK_MS = 30_000;
const MESH_MAX_SECONDS_DEFAULT = 28800;
const MESH_MAX_SECONDS_CAP = 7 * 86400;
const MESH_IDLE_SECONDS_DEFAULT = 3600;
const MESH_PER_ACTOR_DEFAULT = 16;
const MESH_PER_ACTOR_CAP = 256;
const FRAME_TYPES = Object.freeze({ tcp_status: 'mesh_status', tcp_eof: 'mesh_eof', tcp_close: 'mesh_close' });

function labelOf(type) {
    return typeof type === 'string' ? type.replace(/[^A-Za-z0-9_:-]/g, '').slice(0, 32) : typeof type;
}

class MeshChannels {
    constructor(fm) {
        this.fm = fm;
        this.sessions = new Map();
        // A binary frame is a 4-byte stream id plus at most 64 KiB (MESH §3.1).
        this.wss = new WebSocket.Server({ noServer: true, maxPayload: CHANNEL_FRAME_MAX + STREAM_HEADER });
        this.recheckMs = MESH_RECHECK_MS;
        this.auditFailures = 0;
    }

    get env() {
        return this.fm.env || {};
    }

    upgrade(request, socket, head, parsed) {
        const hostId = channelUpgradeHost(this.env, request, socket, parsed, 'mesh');
        if (hostId === null) return;
        this.wss.handleUpgrade(request, socket, head, (ws) => {
            this.open(ws, parsed, hostId).catch((err) => {
                console.error('[Fleet] mesh open failed:', err.message);
                this.failSocket(ws, 'internal');
            });
        });
    }

    // A session-level error: mesh_status without a stream, then 1011.
    failSocket(ws, code) {
        sendJSON(ws, { type: 'mesh_status', payload: { error: code } });
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close(1011);
    }

    liveFor(predicate) {
        let n = 0;
        for (const m of this.sessions.values()) if (predicate(m)) n += 1;
        return n;
    }

    async open(ws, parsed, hostId) {
        const fm = this.fm;
        let session = null;
        const early = { closed: false, failed: false };
        ws.on('error', (err) => {
            if (err && err.code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH' && session) session.clientError = 'frame_too_large';
            else console.error('[Fleet] mesh socket error:', err && err.message);
        });
        ws.on('message', (buf, isBinary) => {
            if (session) {
                this.onClientMessage(session, buf, isBinary);
                return;
            }
            // Nothing may arrive before mesh_ready (MESH §3).
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
        // Consumed on first upgrade, even when host or purpose do not match.
        const purpose = parsed.searchParams.get('purpose') || MESH_PURPOSE;
        const row = consumeTicket(fm.tickets, ticketRes.ticket, hostId, purpose);
        if (!row || purpose !== MESH_PURPOSE) {
            this.failSocket(ws, 'ticket_invalid');
            return;
        }
        if (!fm.signer) {
            this.failSocket(ws, 'lease_required');
            return;
        }
        const denied = await recheckChannelTicket(fm.registry, row, MESH_PURPOSE, null);
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
        if (!fm.agentSupports(hostId, 'tcp')) {
            this.failSocket(ws, 'agent_unsupported');
            return;
        }
        const actor = row.actor || null;
        const perActor = envInt(this.env, 'SYSTEMAPI_MESH_MAX_PER_ACTOR', MESH_PER_ACTOR_DEFAULT, 1, MESH_PER_ACTOR_CAP);
        const maxSeconds = envInt(this.env, 'SYSTEMAPI_MESH_MAX_SECONDS', MESH_MAX_SECONDS_DEFAULT, 1, MESH_MAX_SECONDS_CAP);
        const idleSeconds = envInt(this.env, 'SYSTEMAPI_MESH_IDLE_SECONDS', MESH_IDLE_SECONDS_DEFAULT, 1, MESH_MAX_SECONDS_CAP);
        const startedMs = Date.now();
        const m = {
            id: `${SESSION_PREFIX}${randomToken(16)}`,
            hostId,
            tenantId: row.tenantId,
            actor,
            auth: row.auth || null,
            client: ws,
            agent: agentWs,
            streams: new Map(),
            accepted: new Set(),
            lastId: 0,
            opened: 0,
            startedMs,
            idleMs: idleSeconds * 1000,
            ended: false,
            finalized: false,
            endReason: null,
            clientError: null,
            rechecking: false,
            recheckTimer: null,
            maxTimer: null,
            idleTimer: null
        };
        // Reserve the session slot synchronously (no await between the cap
        // check and the set) so N parallel upgrades cannot bypass
        // SYSTEMAPI_MESH_MAX_PER_ACTOR (MESH §5).
        if (this.liveFor((x) => x.actor === actor) >= perActor) {
            console.warn('[Fleet] mesh refused: session cap reached');
            this.failSocket(ws, 'cap_reached');
            return;
        }
        this.sessions.set(m.id, m);
        // mesh_start before mesh_ready (MESH §9).
        try {
            await fm.registry.appendAudit({
                tenant_id: m.tenantId,
                host_id: hostId,
                actor,
                action: 'mesh_start',
                payload: { session_id: m.id }
            });
        } catch (err) {
            console.error('[Fleet] mesh start audit failed:', err.message);
            this.sessions.delete(m.id);
            this.failSocket(ws, 'internal');
            return;
        }
        // The agent dropped during the await (onAgentGone already ended the
        // reserved session and wrote mesh_end).
        if (m.ended) return;
        // The client closed or broke framing while mesh_start was in flight:
        // the session still gets a mesh_end row (MESH §9).
        if (early.closed || early.failed) {
            m.ended = true;
            m.endReason = early.failed ? 'protocol_error' : 'client_closed';
            this.sessions.delete(m.id);
            this.finalize(m);
            return;
        }
        session = m;
        sendJSON(ws, { type: 'mesh_ready', payload: { session_id: m.id, window: TCP_WINDOW } });
        m.recheckTimer = unref(setInterval(() => {
            this.recheck(m).catch((err) => console.error('[Fleet] mesh re-check failed:', err.message));
        }, this.recheckMs));
        m.maxTimer = unref(setTimeout(() => { this.endSession(m, 'max_duration'); }, maxSeconds * 1000));
        this.armIdle(m);
    }

    // The idle timer runs only while the session has no stream (MESH §5).
    armIdle(m) {
        clearTimeout(m.idleTimer);
        m.idleTimer = null;
        if (m.ended || m.streams.size > 0) return;
        m.idleTimer = unref(setTimeout(() => {
            if (m.ended || m.streams.size > 0) return;
            this.endSession(m, 'idle_timeout');
        }, m.idleMs));
    }

    // Every 30 s the session's grant is re-checked (membership, key state,
    // mesh:open). A denial ends every stream and the session with stopped; a
    // failed lookup only skips this check.
    async recheck(m) {
        if (m.ended || m.rechecking) return;
        m.rechecking = true;
        let denied;
        try {
            denied = await recheckChannelTicket(this.fm.registry,
                { actor: m.actor, tenantId: m.tenantId, auth: m.auth, hostId: m.hostId }, MESH_PURPOSE, null);
        } finally {
            m.rechecking = false;
        }
        if (m.ended) return;
        if (denied === 'internal') {
            console.error('[Fleet] mesh re-check skipped: unavailable');
            return;
        }
        if (denied) {
            console.warn(`[Fleet] mesh ${m.id}: grant withdrawn (${denied}); ending session`);
            this.endSession(m, 'stopped');
        }
    }

    protocolError(m) {
        this.endSession(m, 'protocol_error', { error: 'protocol_error' });
    }

    // A stream that failed before or instead of starting: one mesh_status
    // error for it, nothing else (MESH §3.1).
    streamError(m, id, code) {
        const entry = m.streams.get(id);
        if (entry) this.finishStream(m, entry);
        sendJSON(m.client, { type: 'mesh_status', stream: id, payload: { error: code } });
    }

    finishStream(m, entry) {
        if (!m.streams.has(entry.id) || m.streams.get(entry.id) !== entry) return;
        m.streams.delete(entry.id);
        if (m.streams.size === 0) this.armIdle(m);
    }

    // The per-stream client the TcpChannels session talks to. Binary frames
    // arrive already prefixed by the sink's encode; text frames are the tcp_*
    // frames of TCP §3, rewritten with the stream id. close() ends only this
    // stream; the socket stays open for the others.
    makeView(m, entry) {
        const ws = m.client;
        const self = this;
        return {
            get readyState() { return ws.readyState; },
            get bufferedAmount() { return ws.bufferedAmount; },
            isPaused: false,
            pause() {},
            resume() {},
            send(data) {
                if (ws.readyState !== WebSocket.OPEN) return;
                if (Buffer.isBuffer(data)) {
                    ws.send(data);
                    return;
                }
                let frame;
                try {
                    frame = JSON.parse(String(data));
                } catch {
                    return;
                }
                const type = frame && FRAME_TYPES[frame.type];
                if (!type) return;
                const out = { type, stream: entry.id };
                if (frame.payload !== undefined) out.payload = frame.payload;
                ws.send(JSON.stringify(out));
                if (type === 'mesh_status' && frame.payload && frame.payload.status === 'connected') entry.connected = true;
                if (type === 'mesh_close' || (type === 'mesh_status' && frame.payload && frame.payload.error)) self.finishStream(m, entry);
            },
            close() {
                self.finishStream(m, entry);
            }
        };
    }

    onClientMessage(m, buf, isBinary) {
        if (m.ended) return;
        // §3.1: a text frame is at most 64 KiB (binary may be 65,540: a
        // 4-byte id plus 64 KiB, bounded by the server's maxPayload).
        if (!isBinary && buf.length > CHANNEL_FRAME_MAX) {
            if (m.client.readyState === WebSocket.OPEN) m.client.close(1009);
            this.endSession(m, 'frame_too_large');
            return;
        }
        if (isBinary) {
            if (buf.length < STREAM_HEADER) {
                this.protocolError(m);
                return;
            }
            const id = buf.readUInt32BE(0);
            // §3.2: a frame of any kind for an id the session never accepted
            // (above lastId, or a skipped id) is a protocol error; an id that
            // was opened and has since closed is ignored.
            if (id === 0 || !m.accepted.has(id)) {
                this.protocolError(m);
                return;
            }
            const entry = m.streams.get(id);
            if (!entry) return;
            if (!entry.connected || entry.clientEof || !entry.session) {
                this.protocolError(m);
                return;
            }
            const data = buf.subarray(STREAM_HEADER);
            if (data.length === 0) return;
            if (!entry.fromClient.receive(data.length)) {
                console.warn(`[Fleet] mesh ${m.id}: stream ${id} past its credit window; ending session`);
                this.protocolError(m);
                return;
            }
            this.fm.tcp.onClientMessage(entry.session, data, true);
            return;
        }
        let cmd;
        try {
            cmd = JSON.parse(buf.toString());
        } catch {
            this.protocolError(m);
            return;
        }
        if (!cmd || typeof cmd !== 'object' || Array.isArray(cmd)) {
            this.protocolError(m);
            return;
        }
        switch (cmd.type) {
        case 'mesh_open':
            this.onOpen(m, cmd);
            return;
        case 'mesh_eof':
            this.onEof(m, cmd);
            return;
        case 'mesh_close':
            this.onClose(m, cmd);
            return;
        case 'mesh_credit':
            this.onCredit(m, cmd);
            return;
        default:
            console.warn(`[Fleet] mesh ${m.id}: unknown frame type ${labelOf(cmd.type)} ignored`);
        }
    }

    onOpen(m, cmd) {
        const id = cmd.stream;
        if (!Number.isInteger(id) || id < 1 || id > STREAM_ID_MAX || id <= m.lastId) {
            this.protocolError(m);
            return;
        }
        m.lastId = id;
        m.opened += 1;
        m.accepted.add(id);
        const checked = validateTcpTarget(cmd.target);
        if (!checked.ok) {
            this.streamError(m, id, checked.error);
            return;
        }
        // §5: bound in-flight opens. Live TCP sessions plus pending mesh
        // opens for this actor/agent may not exceed the shared caps, so a
        // burst of mesh_open frames cannot pass the per-actor or per-agent
        // limit while their policy checks are still in flight.
        const tcp = this.fm.tcp;
        const actorFull = tcp.liveFor((s) => s.actor === m.actor) + this.pendingFor((x) => x.actor === m.actor) >= tcp.perActor();
        const agentFull = tcp.liveFor((s) => s.agent === m.agent) + this.pendingFor((x) => x.agent === m.agent) >= TCP_PER_AGENT;
        if (actorFull || agentFull) {
            console.warn('[Fleet] mesh stream refused: session cap reached (in-flight)');
            this.streamError(m, id, 'cap_reached');
            return;
        }
        const idBE = Buffer.alloc(STREAM_HEADER);
        idBE.writeUInt32BE(id, 0);
        const entry = {
            id,
            idBE,
            session: null,
            pending: true,
            abandoned: false,
            connected: false,
            clientEof: false,
            toClient: new CreditStream({ window: TCP_WINDOW }),
            fromClient: new CreditStream({ window: TCP_WINDOW }),
            view: null
        };
        entry.view = this.makeView(m, entry);
        m.streams.set(id, entry);
        clearTimeout(m.idleTimer);
        m.idleTimer = null;
        this.startStream(m, entry, checked.target).catch((err) => {
            console.error('[Fleet] mesh stream open failed:', err.message);
            if (!m.ended) this.streamError(m, id, 'internal');
        });
    }

    async startStream(m, entry, target) {
        // §5: re-check scope AND policy per stream, so a revoked key or lost
        // membership cannot open new streams before the 30 s session
        // re-check. policyDecision for mesh:open with a target runs the TCP
        // target check, and ticketScopesHeld re-checks mesh:open.
        let denied;
        try {
            denied = await recheckChannelTicket(this.fm.registry,
                { actor: m.actor, tenantId: m.tenantId, auth: m.auth, hostId: m.hostId }, MESH_PURPOSE, { target });
        } catch (err) {
            console.error('[Fleet] mesh stream re-check failed:', err.message);
            denied = 'internal';
        }
        if (m.ended) return;
        if (entry.abandoned) {
            this.finishStream(m, entry);
            return;
        }
        // recheckChannelTicket maps a bad binding to ticket_invalid, but the
        // target was validated at mesh_open, so that cannot happen here.
        if (denied) {
            this.streamError(m, entry.id, denied === 'ticket_invalid' ? 'internal' : denied);
            return;
        }
        const tcp = this.fm.tcp;
        if (m.agent.readyState !== WebSocket.OPEN) {
            this.streamError(m, entry.id, 'agent_offline');
            return;
        }
        if (tcp.liveFor((s) => s.actor === m.actor) >= tcp.perActor() || tcp.liveFor((s) => s.agent === m.agent) >= TCP_PER_AGENT) {
            console.warn('[Fleet] mesh stream refused: session cap reached');
            this.streamError(m, entry.id, 'cap_reached');
            return;
        }
        const ws = m.client;
        let s;
        try {
            s = tcp.startSession(entry.view, {
            hostId: m.hostId,
            tenantId: m.tenantId,
            actor: m.actor,
            auth: m.auth,
            target,
            agent: m.agent,
            clientEof: entry.clientEof,
            purpose: MESH_PURPOSE,
            mesh: m.id,
            stream: entry.id,
            encode: (chunk) => Buffer.concat([entry.idBE, chunk]),
            clientCredit: entry.toClient,
            onSent: (n) => {
                const credit = entry.fromClient.drain(n);
                if (credit > 0) sendJSON(ws, { type: 'mesh_credit', stream: entry.id, bytes: credit });
            }
            });
        } catch (err) {
            // startSession cleans up its own half-built session (tcp.js), so
            // only this stream needs to fail here.
            console.error('[Fleet] mesh startSession threw:', err && err.message);
            entry.pending = false;
            this.streamError(m, entry.id, 'internal');
            return;
        }
        entry.pending = false;
        if (!s) {
            this.finishStream(m, entry);
            return;
        }
        entry.session = s;
    }

    // Pending mesh opens (no TCP session yet) that match the predicate,
    // across every session on this manager.
    pendingFor(predicate) {
        let n = 0;
        for (const m of this.sessions.values()) {
            if (!predicate(m)) continue;
            for (const e of m.streams.values()) if (e.pending) n += 1;
        }
        return n;
    }

    onEof(m, cmd) {
        const id = cmd.stream;
        if (!Number.isInteger(id) || id < 1 || !m.accepted.has(id)) {
            this.protocolError(m);
            return;
        }
        const entry = m.streams.get(id);
        if (!entry || entry.clientEof) return;
        entry.clientEof = true;
        if (entry.session) this.fm.tcp.onClientMessage(entry.session, Buffer.from('{"type":"tcp_eof"}'), false);
    }

    // The client abandoned the stream: audited client_closed, no frame.
    onClose(m, cmd) {
        const id = cmd.stream;
        if (!Number.isInteger(id) || id < 1 || !m.accepted.has(id)) {
            this.protocolError(m);
            return;
        }
        const entry = m.streams.get(id);
        if (!entry) return;
        if (entry.pending) {
            entry.abandoned = true;
            return;
        }
        this.finishStream(m, entry);
        if (entry.session && !entry.session.ended) this.fm.tcp.end(entry.session, 'client_closed', { notifyAgent: true });
    }

    onCredit(m, cmd) {
        const id = cmd.stream;
        if (!Number.isInteger(id) || id < 1 || !m.accepted.has(id)) {
            this.protocolError(m);
            return;
        }
        const entry = m.streams.get(id);
        if (!entry) return;
        const n = creditBytes(cmd);
        if (n === null || !entry.toClient.grant(n)) {
            console.warn(`[Fleet] mesh ${m.id}: bad credit on stream ${entry.id}; ending session`);
            this.protocolError(m);
            return;
        }
        if (entry.session && entry.session.sink) entry.session.sink.pump();
    }

    onClientClose(m) {
        if (m.ended) return;
        this.endSession(m, m.clientError || 'client_closed');
    }

    onAgentGone(ws) {
        for (const m of [...this.sessions.values()]) {
            if (m.agent === ws) this.endSession(m, 'agent_disconnected');
        }
    }

    // Ends the session once: every live stream first (mesh_close with the
    // same reason, tcp_stop to the agent), then the session frame. opts.error
    // sends mesh_status error and 1011; otherwise mesh_end and 1000. A client
    // that already closed gets no frame.
    endSession(m, reason, opts = {}) {
        if (m.ended) return;
        m.ended = true;
        m.endReason = reason;
        clearInterval(m.recheckTimer);
        clearTimeout(m.maxTimer);
        clearTimeout(m.idleTimer);
        this.sessions.delete(m.id);
        const tcp = this.fm.tcp;
        const clientOpen = m.client.readyState === WebSocket.OPEN;
        // A pending stream (no TCP session yet) gets a stream error before
        // mesh_end (MESH §5): the session error code when there is one, else
        // the reason mapped to a code.
        const pendingCode = opts.error
            || (reason === 'protocol_error' ? 'protocol_error' : reason === 'agent_disconnected' ? 'agent_disconnected' : 'internal');
        for (const entry of [...m.streams.values()]) {
            const hadSession = !!entry.session;
            const wasAbandoned = entry.abandoned;
            entry.abandoned = true;
            if (hadSession && !entry.session.ended) {
                tcp.end(entry.session, reason, { notifyClient: clientOpen, notifyAgent: true });
            } else if (!hadSession && !wasAbandoned && clientOpen) {
                sendJSON(m.client, { type: 'mesh_status', stream: entry.id, payload: { error: pendingCode } });
            }
            this.finishStream(m, entry);
        }
        if (opts.error) {
            this.failSocket(m.client, opts.error);
        } else if (clientOpen) {
            sendJSON(m.client, { type: 'mesh_end', payload: { session_id: m.id, reason, streams: m.opened } });
            m.client.close(1000);
        }
        this.finalize(m);
    }

    finalize(m) {
        if (m.finalized) return;
        m.finalized = true;
        const fm = this.fm;
        appendAuditRetrying(fm.registry, {
            tenant_id: m.tenantId,
            host_id: m.hostId,
            actor: m.actor,
            action: 'mesh_end',
            payload: {
                session_id: m.id,
                reason: m.endReason,
                streams: m.opened,
                duration_s: Math.round((Date.now() - m.startedMs) / 1000)
            }
        }, fm.auditRetryDelaysMs, (err) => {
            this.auditFailures += 1;
            if (fm.metrics && fm.metrics.terminalAuditFailures) fm.metrics.terminalAuditFailures.inc();
            console.error('[Fleet] mesh end audit failed:', err && err.message);
        }, (kind, fp, detail) => fm.noteSecurity(kind, fp, detail)).catch((err) => {
            console.error('[Fleet] mesh end audit failed:', err.message);
        });
    }
}

module.exports = { MeshChannels, MESH_PURPOSE, STREAM_HEADER };
