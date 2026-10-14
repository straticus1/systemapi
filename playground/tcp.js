/**
 * TCP-forward channel, server side (docs/sah-tcp-protocol.md).
 *
 * One WebSocket carries one TCP connection that the host's agent dials.
 * Threats: an SSRF pivot into the host's network (the ticket's bound target
 * is re-validated, the refused classes and the server policy re-checked and
 * the actor's scope re-checked at the upgrade; the lease signs the exact
 * target; the agent applies its own allowlist), a replayed or swapped ticket
 * (consumed on first upgrade, bound to host, purpose and target), a stream
 * outliving its lease (signed 60 s lease renewed every 30 s, deadline
 * SYSTEMAPI_TCP_MAX_SECONDS), a stream that never ends (idle timeout
 * SYSTEMAPI_TCP_IDLE_SECONDS, byte cap SYSTEMAPI_TCP_MAX_BYTES, start timeout
 * 30 s), a client or agent growing server memory (credit windows of 256 KiB
 * per direction, client bufferedAmount gate of 1 MiB, never drop bytes; an
 * agent past its window is disconnected), one actor or one agent taking every
 * stream (SYSTEMAPI_TCP_MAX_PER_ACTOR, default 32; 64 streams per agent,
 * separate from PTY slots), and a session without an audit trail (tcp_start
 * is written before "connected" and before any byte flows; tcp_end is
 * retried). Ticket values are never logged.
 * Does NOT inspect or record content (owner-accepted, TCP §9), does NOT
 * protect against an allowed target that is itself a proxy, and does NOT
 * persist sessions across a server restart.
 */
'use strict';

const WebSocket = require('ws');
const { ticketFromRequest } = require('../controlplane/httpauth');
const { consumeTicket } = require('../controlplane/tickets');
const { issueLease, tcpPayload } = require('../controlplane/lease');
const { validateTcpTarget } = require('../controlplane/channels');
const { TCP_WINDOW, creditFrame, creditBytes, encodeData } = require('../controlplane/credit');
const { randomToken } = require('../controlplane/token');
const {
    CHANNEL_FRAME_MAX, envInt, unref, sendJSON, channelUpgradeHost, recheckChannelTicket,
    appendAuditRetrying, ClientSink, AgentSource
} = require('./channel');

const TCP_PURPOSE = 'tcp:open';
const TCP_LEASE_TTL_S = 60;
const TCP_RENEW_MS = 30_000;
const TCP_START_TIMEOUT_MS = 30_000;
const TCP_FINAL_WAIT_MS = 5_000;
const TCP_MAX_SECONDS_DEFAULT = 28800;
const TCP_MAX_SECONDS_CAP = 7 * 86400;
const TCP_IDLE_SECONDS_DEFAULT = 900;
const TCP_MAX_BYTES_DEFAULT = 10 * 1024 * 1024 * 1024;
const TCP_MAX_BYTES_CAP = 2 ** 50;
const TCP_PER_ACTOR_DEFAULT = 32;
const TCP_PER_AGENT = 64;
const TCP_ERRORS = new Set([
    'ticket_invalid', 'scope_denied', 'agent_offline', 'agent_unsupported', 'lease_required', 'cap_reached',
    'target_denied', 'target_denied_agent', 'target_forbidden', 'connect_refused', 'connect_timeout',
    'host_unreachable', 'protocol_error', 'internal'
]);
const TCP_CLOSE_REASONS = new Set(['closed', 'reset', 'idle_timeout', 'byte_cap', 'max_duration', 'agent_disconnected', 'stopped']);
const SESSION_PREFIX = 'tcs_';

// The peer the agent must report: the address it dials for this target.
function expectedPeer(target) {
    if (target.host === 'local') return `127.0.0.1:${target.port}`;
    if (target.host.includes(':')) return `[${target.host}]:${target.port}`;
    return `${target.host}:${target.port}`;
}

function count(v) {
    return Number.isSafeInteger(v) && v >= 0 ? v : null;
}

class TcpChannels {
    constructor(fm) {
        this.fm = fm;
        this.sessions = new Map();
        this.stopping = new Map();
        this.wss = new WebSocket.Server({ noServer: true, maxPayload: CHANNEL_FRAME_MAX });
        this.renewMs = TCP_RENEW_MS;
        this.startTimeoutMs = TCP_START_TIMEOUT_MS;
        this.finalWaitMs = TCP_FINAL_WAIT_MS;
        this.pollMs = 20;
        this.auditFailures = 0;
    }

    get env() {
        return this.fm.env || {};
    }

    upgrade(request, socket, head, parsed) {
        const hostId = channelUpgradeHost(this.env, request, socket, parsed, 'tcp');
        if (hostId === null) return;
        this.wss.handleUpgrade(request, socket, head, (ws) => {
            this.open(ws, parsed, hostId).catch((err) => {
                console.error('[Fleet] tcp open failed:', err.message);
                this.failSocket(ws, 'internal');
            });
        });
    }

    failSocket(ws, code) {
        sendJSON(ws, { type: 'tcp_status', payload: { error: code } });
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
        const early = { closed: false, eof: false, failed: false };
        ws.on('error', (err) => {
            if (err && err.code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH' && session) session.clientError = 'frame_too_large';
            else console.error('[Fleet] tcp socket error:', err && err.message);
        });
        ws.on('message', (buf, isBinary) => {
            if (session) {
                this.onClientMessage(session, buf, isBinary);
                return;
            }
            if (early.failed) return;
            // Before the session exists nothing may flow (TCP §3).
            if (isBinary) {
                early.failed = true;
                this.failSocket(ws, 'protocol_error');
                return;
            }
            let cmd;
            try {
                cmd = JSON.parse(buf.toString());
            } catch {
                early.failed = true;
                this.failSocket(ws, 'protocol_error');
                return;
            }
            if (cmd && cmd.type === 'tcp_eof') early.eof = true;
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
        // Consumed on first upgrade, even when host, purpose or target do not
        // match (TCP §3).
        const purpose = parsed.searchParams.get('purpose') || TCP_PURPOSE;
        const row = consumeTicket(fm.tickets, ticketRes.ticket, hostId, purpose);
        if (!row || purpose !== TCP_PURPOSE) {
            this.failSocket(ws, 'ticket_invalid');
            return;
        }
        const checked = validateTcpTarget(row.target);
        if (!checked.ok) {
            this.failSocket(ws, checked.error === 'target_forbidden' ? 'target_forbidden' : 'ticket_invalid');
            return;
        }
        if (!fm.signer) {
            this.failSocket(ws, 'lease_required');
            return;
        }
        const denied = await recheckChannelTicket(fm.registry, row, TCP_PURPOSE, { target: checked.target });
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
        const perActor = envInt(this.env, 'SYSTEMAPI_TCP_MAX_PER_ACTOR', TCP_PER_ACTOR_DEFAULT, 1, 100000);
        if (this.liveFor((s) => s.actor === actor) >= perActor || this.liveFor((s) => s.agent === agentWs) >= TCP_PER_AGENT) {
            console.warn('[Fleet] tcp refused: session cap reached');
            this.failSocket(ws, 'cap_reached');
            return;
        }

        const sessionId = `${SESSION_PREFIX}${randomToken(16)}`;
        const maxSeconds = envInt(this.env, 'SYSTEMAPI_TCP_MAX_SECONDS', TCP_MAX_SECONDS_DEFAULT, 1, TCP_MAX_SECONDS_CAP);
        const idleSeconds = envInt(this.env, 'SYSTEMAPI_TCP_IDLE_SECONDS', TCP_IDLE_SECONDS_DEFAULT, 1, TCP_MAX_SECONDS_CAP);
        const maxBytes = envInt(this.env, 'SYSTEMAPI_TCP_MAX_BYTES', TCP_MAX_BYTES_DEFAULT, 1, TCP_MAX_BYTES_CAP);
        const startedMs = Date.now();
        const deadlineUnix = Math.floor(startedMs / 1000) + maxSeconds;
        const target = checked.target;
        let lease;
        try {
            lease = issueLease(fm.signer, {
                hostId,
                action: 'tcp',
                payload: tcpPayload(sessionId, deadlineUnix, 'start', target.host, target.port),
                ttl: TCP_LEASE_TTL_S
            });
        } catch (err) {
            this.failSocket(ws, 'lease_required');
            return;
        }
        let stream;
        try {
            stream = fm.agentCreditLedger(agentWs).open(sessionId, { window: TCP_WINDOW });
        } catch (err) {
            this.failSocket(ws, 'internal');
            return;
        }
        const s = {
            id: sessionId,
            hostId,
            tenantId: row.tenantId,
            actor,
            target,
            peer: null,
            expectedPeer: expectedPeer(target),
            via: target.host !== 'local',
            client: ws,
            agent: agentWs,
            stream,
            sink: null,
            source: null,
            agentConnected: false,
            connected: false,
            ended: false,
            finalized: false,
            clientEof: early.eof,
            clientEofSent: false,
            targetEof: false,
            targetEofDelivered: false,
            clientError: null,
            bytesIn: 0,
            bytesOut: 0,
            lastActivityMs: startedMs,
            idleMs: idleSeconds * 1000,
            maxBytes,
            deadlineUnix,
            startedMs,
            renewTimer: null,
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
            onCredit: (n) => sendJSON(s.agent, creditFrame('tcp', s.id, n))
        });
        s.source = new AgentSource({
            client: ws,
            stream,
            send: (chunk) => {
                if (s.agent.readyState === WebSocket.OPEN) s.agent.send(encodeData(s.id, chunk));
            }
        });
        this.sessions.set(sessionId, s);
        session = s;
        sendJSON(ws, { type: 'tcp_status', payload: { status: 'connecting' } });
        sendJSON(agentWs, {
            type: 'tcp_open',
            session_id: sessionId,
            target: { host: target.host, port: target.port },
            deadline_unix: deadlineUnix,
            idle_s: idleSeconds,
            max_bytes: maxBytes,
            lease
        });
        s.renewTimer = unref(setInterval(() => this.renew(s), this.renewMs));
        s.maxTimer = unref(setTimeout(() => {
            this.end(s, 'max_duration', { notifyClient: true, notifyAgent: true });
        }, maxSeconds * 1000));
        s.startTimer = unref(setTimeout(() => {
            if (!s.connected) this.end(s, 'start_timeout', { error: 'internal', notifyAgent: true });
        }, this.startTimeoutMs));
    }

    renew(s) {
        if (s.ended || !this.fm.signer) return;
        try {
            const lease = issueLease(this.fm.signer, {
                hostId: s.hostId,
                action: 'tcp',
                payload: tcpPayload(s.id, s.deadlineUnix, 'renew', s.target.host, s.target.port),
                ttl: TCP_LEASE_TTL_S
            });
            sendJSON(s.agent, { type: 'tcp_renew', session_id: s.id, lease });
        } catch (err) {
            console.error('[Fleet] tcp lease renewal failed:', err.message);
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

    // True when n more bytes stay within the byte cap; else ends the stream.
    withinCap(s, n) {
        if (s.bytesIn + s.bytesOut + n <= s.maxBytes) return true;
        this.end(s, 'byte_cap', { notifyClient: true, notifyAgent: true });
        return false;
    }

    protocolError(s) {
        this.end(s, 'protocol_error', { error: 'protocol_error', notifyAgent: true });
    }

    onClientMessage(s, buf, isBinary) {
        if (s.ended) return;
        if (isBinary) {
            if (!s.connected || s.clientEof) {
                this.protocolError(s);
                return;
            }
            const n = buf.length;
            if (n === 0) return;
            if (!this.withinCap(s, n)) return;
            s.bytesOut += n;
            this.touch(s);
            if (!s.source.push(buf)) {
                console.warn(`[Fleet] tcp ${s.id}: client queue over its cap; ending stream`);
                this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            }
            return;
        }
        let cmd;
        try {
            cmd = JSON.parse(buf.toString());
        } catch {
            this.protocolError(s);
            return;
        }
        const type = cmd && typeof cmd === 'object' ? cmd.type : undefined;
        if (type === 'tcp_eof') {
            if (s.clientEof) return;
            s.clientEof = true;
            if (s.connected) s.source.after(() => this.sendEofToAgent(s));
            return;
        }
        const label = typeof type === 'string' ? type.replace(/[^A-Za-z0-9_:-]/g, '').slice(0, 32) : typeof type;
        console.warn(`[Fleet] tcp ${s.id}: unknown frame type ${label} ignored`);
    }

    sendEofToAgent(s) {
        if (s.ended) return;
        sendJSON(s.agent, { type: 'tcp_eof', session_id: s.id });
        s.clientEofSent = true;
        this.maybeClosed(s);
    }

    // FIN seen both ways: the server sends tcp_close "closed" (TCP §8). The
    // agent reports its own tcp_closed with its byte counts.
    maybeClosed(s) {
        if (s.ended || !s.clientEofSent || !s.targetEofDelivered) return;
        this.end(s, 'closed', { notifyClient: true, awaitAgent: true });
    }

    onClientClose(s) {
        if (s.ended) return;
        // A client close is audited as client_closed and sends no frame
        // (TCP §7); an oversized frame (1009, by ws) is audited as such.
        this.end(s, s.clientError || 'client_closed', { notifyAgent: true });
    }

    // Returns the live session only when this agent connection owns it.
    agentSession(ws, hostId, sessionId) {
        if (typeof sessionId !== 'string') return null;
        const s = this.sessions.get(sessionId);
        if (!s || s.ended || s.agent !== ws || s.hostId !== hostId) return null;
        return s;
    }

    static owns(sessionId) {
        return typeof sessionId === 'string' && sessionId.startsWith(SESSION_PREFIX);
    }

    onAgentData(ws, hostId, sessionId, data) {
        const ledger = this.fm.agentCreditLedger(ws);
        // Accounting first: data for a live stream past its window is a
        // violation even when the session is ending.
        if (!ledger.receive(sessionId, data.length)) return;
        const s = this.agentSession(ws, hostId, sessionId);
        if (!s || data.length === 0) return;
        if (!s.agentConnected || s.targetEof) {
            console.warn(`[Fleet] tcp ${s.id}: agent data outside the stream; ending it`);
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            return;
        }
        if (!this.withinCap(s, data.length)) return;
        s.bytesIn += data.length;
        this.touch(s);
        s.sink.push(data);
    }

    async onAgentFrame(ws, hostId, msg) {
        const sid = msg.session_id;
        if (msg.type === 'tcp_credit') {
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
        if (msg.type === 'tcp_closed') {
            this.onAgentClosed(ws, hostId, msg);
            return;
        }
        const s = this.agentSession(ws, hostId, sid);
        if (!s) return;
        if (msg.type === 'tcp_eof') {
            if (!s.agentConnected || s.targetEof) return;
            s.targetEof = true;
            s.sink.after(() => {
                sendJSON(s.client, { type: 'tcp_eof' });
                s.targetEofDelivered = true;
                this.maybeClosed(s);
            });
            return;
        }
        if (msg.type === 'tcp_status') await this.onAgentStatus(s, msg);
    }

    async onAgentStatus(s, msg) {
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        if (payload.error) {
            const code = TCP_ERRORS.has(payload.error) ? payload.error : 'internal';
            this.end(s, code, { error: code });
            return;
        }
        if (payload.status !== 'connected' || s.agentConnected) return;
        if (payload.peer !== s.expectedPeer) {
            console.warn(`[Fleet] tcp ${s.id}: agent reported an unexpected peer; ending stream`);
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            return;
        }
        s.agentConnected = true;
        s.peer = s.expectedPeer;
        clearTimeout(s.startTimer);
        try {
            await this.fm.registry.appendAudit({
                tenant_id: s.tenantId,
                host_id: s.hostId,
                actor: s.actor,
                action: 'tcp_start',
                payload: { session_id: s.id, target: { host: s.target.host, port: s.target.port }, peer: s.peer, via: s.via }
            });
        } catch (err) {
            console.error('[Fleet] tcp start audit failed:', err.message);
            this.end(s, 'internal', { error: 'internal', notifyAgent: true });
            return;
        }
        if (s.ended) return;
        sendJSON(s.client, { type: 'tcp_status', payload: { status: 'connected', session_id: s.id, peer: s.peer } });
        s.connected = true;
        this.touch(s);
        this.scheduleIdle(s);
        s.sink.open();
        if (s.clientEof) s.source.after(() => this.sendEofToAgent(s));
    }

    onAgentClosed(ws, hostId, msg) {
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        const agentCounts = { reason: typeof payload.reason === 'string' ? payload.reason.replace(/[^a-z_]/g, '').slice(0, 32) : null,
            bytes_in: count(payload.bytes_in), bytes_out: count(payload.bytes_out) };
        const stopping = typeof msg.session_id === 'string' ? this.stopping.get(msg.session_id) : null;
        if (stopping && stopping.agent === ws && stopping.hostId === hostId) {
            this.finalize(stopping, agentCounts);
            return;
        }
        const s = this.agentSession(ws, hostId, msg.session_id);
        if (!s) return;
        const reason = TCP_CLOSE_REASONS.has(agentCounts.reason) ? agentCounts.reason : 'reset';
        if (reason === 'closed') {
            // Every byte and the tcp_eof the agent sent first still reach the
            // client; the counts are kept for whichever path ends the stream.
            s.agentCounts = agentCounts;
            s.sink.after(() => this.end(s, 'closed', { notifyClient: true, agentCounts }));
            return;
        }
        this.end(s, reason, { notifyClient: true, agentCounts });
    }

    onAgentGone(ws) {
        for (const s of [...this.sessions.values()]) {
            if (s.agent === ws) this.end(s, 'agent_disconnected', { notifyClient: true });
        }
        for (const s of [...this.stopping.values()]) {
            if (s.agent === ws) this.finalize(s, null);
        }
    }

    // Ends a stream once. opts.error: tcp_status error, close 1011.
    // opts.notifyClient: tcp_close, close 1000. opts.notifyAgent: tcp_stop,
    // then wait briefly for the agent's tcp_closed (its byte counts).
    // opts.awaitAgent: wait for tcp_closed without a stop (both FINs seen).
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
        } else if (opts.notifyClient && ws.readyState === WebSocket.OPEN) {
            sendJSON(ws, { type: 'tcp_close', payload: { session_id: s.id, reason, bytes_in: s.bytesIn, bytes_out: s.bytesOut } });
            ws.close(1000);
        }
        if (ws.isPaused && ws.readyState === WebSocket.OPEN) ws.resume();
        const counts = opts.agentCounts || s.agentCounts;
        if (counts) {
            this.finalize(s, counts);
            return;
        }
        const agentOpen = s.agent.readyState === WebSocket.OPEN;
        if ((opts.notifyAgent || opts.awaitAgent) && agentOpen) {
            if (opts.notifyAgent) sendJSON(s.agent, { type: 'tcp_stop', session_id: s.id });
            this.stopping.set(s.id, s);
            s.finalTimer = unref(setTimeout(() => {
                if (opts.awaitAgent) sendJSON(s.agent, { type: 'tcp_stop', session_id: s.id });
                this.finalize(s, null);
            }, this.finalWaitMs));
            return;
        }
        this.finalize(s, null);
    }

    // Writes the tcp_end row once, retried like terminal_end.
    finalize(s, agentCounts) {
        if (s.finalized) return;
        s.finalized = true;
        clearTimeout(s.finalTimer);
        this.stopping.delete(s.id);
        const payload = {
            session_id: s.id,
            reason: s.endReason,
            target: { host: s.target.host, port: s.target.port },
            peer: s.peer,
            connected: s.connected,
            bytes_in: s.bytesIn,
            bytes_out: s.bytesOut,
            agent_bytes_in: agentCounts ? agentCounts.bytes_in : null,
            agent_bytes_out: agentCounts ? agentCounts.bytes_out : null,
            duration_s: Math.round((Date.now() - s.startedMs) / 1000)
        };
        const fm = this.fm;
        appendAuditRetrying(fm.registry, {
            tenant_id: s.tenantId,
            host_id: s.hostId,
            actor: s.actor,
            action: 'tcp_end',
            payload
        }, fm.auditRetryDelaysMs, (err) => {
            this.auditFailures += 1;
            if (fm.metrics && fm.metrics.terminalAuditFailures) fm.metrics.terminalAuditFailures.inc();
            console.error('[Fleet] tcp end audit failed:', err && err.message);
        }, (kind, fp, detail) => fm.noteSecurity(kind, fp, detail)).catch((err) => {
            console.error('[Fleet] tcp end audit failed:', err.message);
        });
    }
}

module.exports = { TcpChannels, TCP_ERRORS, TCP_CLOSE_REASONS, TCP_PER_AGENT, expectedPeer };
