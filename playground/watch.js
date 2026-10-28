/**
 * Terminal session watching, server half (docs/sahconnect-terminal-protocol.md
 * §7.2). A support or admin actor asks, with POST /api/v1/ws-ticket purpose
 * terminal:watch (view only) or terminal:watch_rw (read-write), to watch a
 * live terminal session; the server signs a watch lease, sends watch_request
 * to the session's agent, waits for watch_consent and only on a grant returns
 * a ticket. The watcher opens the terminal WebSocket with that ticket and
 * receives the session's output; a read-write watcher's input is forwarded as
 * pty_input with its watch_id.
 *
 * Threats: watching without consent (only an admin may set override, only
 * for view only, only with a reason; read-write is always sent with override
 * false, and a grant the agent reports without consent that the server did
 * not ask to override is refused and stopped), watching another tenant's
 * session (the session's host must be visible to the actor, else 404, and
 * the scope is checked in the session's tenant), output relayed before the
 * watch_started row exists (the row is written before the ticket is issued,
 * and a failed write stops the watch and issues nothing), a view-only
 * watcher typing into the shell (its input is dropped here; the agent drops
 * it again), a grant nobody uses (a ticket not opened within its 60 s is
 * stopped and the agent told), a prompt that waits forever (35 s, then the
 * request is withdrawn with watch_stop), and a watcher that cannot keep up
 * (closed, the session itself is not ended). The user is told on the
 * terminal by the agent, not here. Does NOT persist watches across a server
 * restart (the agent's watch ends with the session or the next watch_stop),
 * and does NOT replay output sent before the watcher connected.
 */
'use strict';

const WebSocket = require('ws');
const { issueLease, watchPayload } = require('../controlplane/lease');
const { consumeTicket, TTL_MS: TICKET_TTL_MS } = require('../controlplane/tickets');
const { ticketFromRequest } = require('../controlplane/httpauth');
const { ticketScopesHeld } = require('../controlplane/authz');
const { randomToken } = require('../controlplane/token');
const { envInt, unref, sendJSON, appendAuditRetrying } = require('./channel');

const WATCH_PURPOSES = new Map([['terminal:watch', 'ro'], ['terminal:watch_rw', 'rw']]);
const CONSENT_TIMEOUT_MS = 35_000;
const LEASE_TTL_S = 60;
const FRAME_MAX = 64 * 1024;
const WATCHER_BUFFER_DEFAULT = 8 * 1024 * 1024;
const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const REFUSAL_RESULTS = new Set(['denied', 'timeout', 'cancelled']);
// Agent refusal codes (§7.2) and the HTTP answer for each.
const AGENT_ERRORS = new Map([
    ['unknown_session', [404, 'unknown_session']],
    ['session_ended', [404, 'unknown_session']],
    ['busy', [409, 'busy']],
    ['reason_required', [400, 'reason_required']],
    ['bad_request', [400, 'bad_request']],
    ['lease_required', [502, 'lease_required']]
]);

function httpError(status, code) {
    const err = new Error(code);
    err.status = status;
    err.code = code;
    return err;
}

// The scopes a watch needs: an override or read-write watch is admin only;
// a view-only watch with consent needs terminal:watch (admin implies it).
function watchScopes(mode, override) {
    return mode === 'rw' || override ? ['admin'] : ['terminal:watch'];
}

class TerminalWatches {
    constructor(fm) {
        this.fm = fm;
        // Requests waiting for watch_consent, by watch id.
        this.pending = new Map();
        // Granted watches, by watch id, until stopped.
        this.watches = new Map();
        this.consentTimeoutMs = CONSENT_TIMEOUT_MS;
        this.ticketTtlMs = TICKET_TTL_MS;
    }

    static purposeMode(purpose) {
        return WATCH_PURPOSES.get(purpose) || null;
    }

    audit(session, actor, action, payload) {
        return this.fm.registry.appendAudit({ tenant_id: session.tenantId, host_id: session.hostId, actor, action, payload });
    }

    auditLater(session, actor, action, payload) {
        return appendAuditRetrying(this.fm.registry, {
            tenant_id: session.tenantId, host_id: session.hostId, actor, action, payload
        }, this.fm.auditRetryDelaysMs || [200, 1000], (err) => {
            console.error(`[Fleet] ${action} audit failed:`, err && err.message);
        }, this.fm.noteSecurity ? this.fm.noteSecurity.bind(this.fm) : null);
    }

    // Asks the session's agent for a watch and waits for its answer. Resolves
    // with the granted watch after watch_started is on record; throws an
    // HTTP error otherwise (watch_refused is on record for every answer).
    // client is { gone, onGone } from the route, as in xfer.js.
    async request({ actor, session, mode, override, reason, client = { gone: false, onGone: null } }) {
        const fm = this.fm;
        if (!session || session.ended || !session.announced) throw httpError(404, 'unknown_session');
        // Read-write never claims an override: the user is always asked.
        const sentOverride = override === true && mode === 'ro';
        if (!sentOverride) {
            for (const p of this.pending.values()) {
                if (p.session === session && !p.override) throw httpError(409, 'busy');
            }
        }
        if (!fm.signer) throw httpError(503, 'lease_required');
        const watchId = `wch_${randomToken(16)}`;
        let lease;
        try {
            lease = issueLease(fm.signer, {
                hostId: session.hostId,
                action: session.action,
                payload: watchPayload(session.id, session.deadlineUnix, watchId, mode, sentOverride, reason),
                ttl: LEASE_TTL_S
            });
        } catch (err) {
            throw httpError(err.status === 400 ? 400 : 500, err.status === 400 ? 'bad_request' : 'internal');
        }
        const p = { watchId, session, actor, mode, override: sentOverride, reason, resolve: null, timer: null };
        const answer = new Promise((resolve) => { p.resolve = resolve; });
        p.timer = unref(setTimeout(() => p.resolve({ local: 'timeout' }), this.consentTimeoutMs));
        this.pending.set(watchId, p);
        client.onGone = () => p.resolve({ local: 'client_gone' });
        sendJSON(session.agent, {
            type: 'watch_request',
            session_id: session.id,
            watch_id: watchId,
            mode,
            actor: String(actor),
            reason,
            override: sentOverride,
            lease
        });
        const reply = client.gone ? { local: 'client_gone' } : await answer;
        clearTimeout(p.timer);
        this.pending.delete(watchId);
        client.onGone = null;

        const refused = { session_id: session.id, watch_id: watchId, mode, actor: String(actor), reason };
        if (reply.local) {
            // Withdraw the open prompt; the agent answers "cancelled", which
            // nobody waits for any more.
            if (reply.local !== 'session_ended') this.tellAgent(session, watchId);
            const result = reply.local === 'client_gone' ? 'cancelled' : reply.local;
            await this.auditLater(session, actor, 'watch_refused', { ...refused, result });
            if (reply.local === 'session_ended') throw httpError(404, 'unknown_session');
            if (reply.local === 'client_gone') throw httpError(499, 'client_gone');
            throw httpError(403, 'watch_denied');
        }
        const payload = reply.payload;
        if (typeof payload.error === 'string') {
            const code = AGENT_ERRORS.has(payload.error) ? payload.error : 'bad_request';
            await this.auditLater(session, actor, 'watch_refused', { ...refused, result: code });
            const [status, out] = AGENT_ERRORS.get(code);
            throw httpError(status, out);
        }
        if (payload.granted !== true) {
            const result = REFUSAL_RESULTS.has(payload.result) || payload.result === 'session_ended' ? payload.result : 'denied';
            await this.auditLater(session, actor, 'watch_refused', { ...refused, result });
            if (result === 'session_ended') throw httpError(404, 'unknown_session');
            throw httpError(403, 'watch_denied');
        }
        // A grant must be the user's yes, or the override the server itself
        // signed (view only). Anything else is stopped, never relayed.
        const consent = payload.consent === true && payload.result === 'granted';
        const overridden = sentOverride && payload.consent === false && payload.result === 'override';
        if ((!consent && !overridden) || payload.mode !== mode || session.ended) {
            this.tellAgent(session, watchId);
            const result = session.ended ? 'session_ended' : 'invalid_grant';
            await this.auditLater(session, actor, 'watch_refused', { ...refused, result });
            if (session.ended) throw httpError(404, 'unknown_session');
            throw httpError(502, 'agent_error');
        }
        const w = {
            id: watchId,
            session,
            actor,
            mode,
            reason,
            consent,
            ws: null,
            bytes: 0,
            dropped: 0,
            startedMs: Date.now(),
            ticketTimer: null,
            stopped: false
        };
        try {
            await this.audit(session, actor, 'watch_started', {
                session_id: session.id,
                host_id: session.hostId,
                watch_id: watchId,
                mode,
                actor: String(actor),
                reason,
                consent
            });
        } catch (err) {
            console.error('[Fleet] watch_started audit failed:', err.message);
            this.tellAgent(session, watchId);
            throw httpError(500, 'internal');
        }
        if (session.ended) {
            await this.stop(w, 'session_ended', { notifyAgent: false });
            throw httpError(404, 'unknown_session');
        }
        if (!session.watchers) session.watchers = new Map();
        session.watchers.set(watchId, w);
        this.watches.set(watchId, w);
        // A ticket that is never opened ends the watch.
        w.ticketTimer = unref(setTimeout(() => { if (!w.ws) this.stopLogged(w, 'ticket_unused'); }, this.ticketTtlMs + 1000));
        return w;
    }

    tellAgent(session, watchId) {
        if (session.agent && session.agent.readyState === WebSocket.OPEN) {
            sendJSON(session.agent, { type: 'watch_stop', session_id: session.id, watch_id: watchId });
        }
    }

    // watch_consent from an agent: only the agent socket that owns the
    // session can answer, and only a request that is still waiting.
    onAgentConsent(ws, hostId, msg) {
        const session = this.fm.agentSession(ws, hostId, msg.session_id);
        const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : null;
        if (!session || !payload || typeof payload.watch_id !== 'string') return;
        const p = this.pending.get(payload.watch_id);
        if (!p || p.session !== session) return;
        p.resolve({ payload });
    }

    // Opens a watcher socket for a consumed watch ticket.
    async attach(ws, parsed, hostId, purpose) {
        const fm = this.fm;
        const ticketRes = ticketFromRequest(parsed);
        if (!fm.tickets || !ticketRes.ok) {
            fm.failTerminalSocket(ws, fm.tickets ? 'ticket_invalid' : 'internal');
            return;
        }
        const row = consumeTicket(fm.tickets, ticketRes.ticket, hostId, purpose);
        const w = row && row.watch ? this.watches.get(row.watch.watchId) : null;
        if (!w || w.stopped || w.ws || w.session.id !== row.watch.sessionId || w.mode !== row.watch.mode || w.actor !== row.actor) {
            fm.failTerminalSocket(ws, 'ticket_invalid');
            return;
        }
        w.ws = ws;
        clearTimeout(w.ticketTimer);
        ws.on('close', () => this.stopLogged(w, 'watcher_closed'));
        // The actor must still hold the scope the watch needed.
        if (!(await ticketScopesHeld(fm.registry, row, watchScopes(w.mode, !w.consent)))) {
            fm.failTerminalSocket(ws, 'scope_denied');
            await this.stop(w, 'scope_denied');
            return;
        }
        if (w.stopped || w.session.ended) {
            fm.failTerminalSocket(ws, 'agent_offline');
            await this.stop(w, 'session_ended', { notifyAgent: false });
            return;
        }
        ws.on('message', (buf, isBinary) => this.onWatcherMessage(w, buf, isBinary));
        sendJSON(ws, {
            type: 'pty_status',
            payload: { status: 'started', session_id: w.session.id, watch_id: w.id, mode: w.mode }
        });
    }

    // A view-only watcher's input is dropped here; a read-write watcher's
    // pty_input goes to the agent tagged with its watch id. Resize and EOF
    // belong to the session's own user and are dropped.
    onWatcherMessage(w, buf, isBinary) {
        if (w.stopped || isBinary) return;
        let cmd = null;
        try { cmd = JSON.parse(buf.toString()); } catch { /* not a frame */ }
        if (!cmd || cmd.type !== 'pty_input') return;
        if (w.mode !== 'rw') {
            w.dropped += 1;
            if (w.dropped === 1) console.warn(`[Fleet] watch ${w.id}: input from a view-only watcher dropped`);
            return;
        }
        let b64 = null;
        if (typeof cmd.data_b64 === 'string') {
            if (B64_RE.test(cmd.data_b64)) b64 = cmd.data_b64;
        } else if (typeof cmd.data === 'string') {
            b64 = Buffer.from(cmd.data, 'utf8').toString('base64');
        }
        if (b64 === null) return;
        sendJSON(w.session.agent, { type: 'pty_input', session_id: w.session.id, watch_id: w.id, data_b64: b64 });
    }

    // Session output to every connected watcher. A watcher that cannot keep
    // up is closed; the session goes on.
    relay(session, data) {
        if (!session.watchers || session.watchers.size === 0) return;
        const cap = envInt(this.fm.env, 'SYSTEMAPI_PTY_CLIENT_BUFFER_MAX', WATCHER_BUFFER_DEFAULT, FRAME_MAX, 1 << 30);
        for (const w of [...session.watchers.values()]) {
            if (w.stopped || !w.ws || w.ws.readyState !== WebSocket.OPEN) continue;
            if (w.ws.bufferedAmount > cap) {
                console.warn(`[Fleet] watch ${w.id}: watcher too slow; closing it`);
                this.stopLogged(w, 'watcher_too_slow');
                continue;
            }
            for (let off = 0; off < data.length; off += FRAME_MAX) w.ws.send(data.subarray(off, off + FRAME_MAX));
            w.bytes += data.length;
        }
    }

    // The session ended: waiting requests are answered session_ended, and
    // every watcher gets pty_exit and is closed.
    onSessionEnd(session, reason, code) {
        for (const p of this.pending.values()) {
            if (p.session === session) p.resolve({ local: 'session_ended' });
        }
        if (!session.watchers) return;
        for (const w of [...session.watchers.values()]) {
            if (w.ws && w.ws.readyState === WebSocket.OPEN) {
                sendJSON(w.ws, { type: 'pty_exit', payload: { session_id: session.id, code, reason } });
            }
            this.stopLogged(w, 'session_ended', { notifyAgent: false });
        }
    }

    // stop() from a timer or a socket event, where nothing awaits it.
    stopLogged(w, reason, opts) {
        this.stop(w, reason, opts).catch((err) => console.error('[Fleet] watch stop failed:', err.message));
    }

    // Ends one watch once: tells the agent (unless the session is gone),
    // closes the watcher and writes watch_stopped.
    async stop(w, reason, { notifyAgent = true } = {}) {
        if (w.stopped) return;
        w.stopped = true;
        clearTimeout(w.ticketTimer);
        if (w.session.watchers) w.session.watchers.delete(w.id);
        this.watches.delete(w.id);
        if (notifyAgent && !w.session.ended) this.tellAgent(w.session, w.id);
        if (w.ws && (w.ws.readyState === WebSocket.OPEN || w.ws.readyState === WebSocket.CONNECTING)) w.ws.close(1000);
        await this.auditLater(w.session, w.actor, 'watch_stopped', {
            session_id: w.session.id,
            watch_id: w.id,
            actor: String(w.actor),
            mode: w.mode,
            reason,
            duration: Math.round((Date.now() - w.startedMs) / 1000),
            bytes_relayed: w.bytes
        });
    }
}

module.exports = { TerminalWatches, WATCH_PURPOSES, watchScopes };
