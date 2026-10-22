/**
 * Service-management channel, server side (docs/sah-os-management-design.md
 * Phase 1), modelled on playground/tcp.js. One WebSocket carries one service
 * operation: Phase 1 is `service restart`, with the agent's status read as the
 * confirm. It is request/response, not a byte stream, so there is no credit
 * mux: the client opens the socket, the server mints a signed sys_service
 * lease and forwards one frame to the agent, and the agent answers one
 * sys_result.
 *
 * Threats: a service restart is root-equivalent. The ticket's bound { unit,
 * action } is re-validated and the actor's scope and the host's service
 * allowlist are re-checked at the upgrade (recheckChannelTicket); the lease
 * signs the exact unit and action so the agent acts only on what was signed; a
 * host that does not advertise the `service` capability is refused
 * agent_unsupported; the ticket is single-use (consumed on first upgrade) so
 * it cannot be replayed; and every operation leaves an intent row before the
 * request is forwarded and a result row after (both auditable, the result row
 * retried like tcp_end). A request without a result in time ends with timeout
 * and still writes its result row. Caps bound how many operations one actor or
 * one agent can have in flight. Does NOT stream or record any content, and
 * does NOT persist a request across a server restart.
 */
'use strict';

const WebSocket = require('ws');
const { ticketFromRequest } = require('../controlplane/httpauth');
const { consumeTicket } = require('../controlplane/tickets');
const { issueLease, sysServicePayload } = require('../controlplane/lease');
const { validateServiceBinding } = require('../controlplane/channels');
const { randomToken } = require('../controlplane/token');
const { envInt, unref, sendJSON, channelUpgradeHost, recheckChannelTicket, appendAuditRetrying } = require('./channel');

const SYS_PURPOSE = 'sys:service';
const SYS_LEASE_TTL_S = 60;
const SYS_RESULT_TIMEOUT_MS = 30_000;
const SYS_PER_ACTOR_DEFAULT = 16;
const SYS_PER_AGENT = 64;
const SYS_ERRORS = new Set([
    'ticket_invalid', 'scope_denied', 'agent_offline', 'agent_unsupported', 'lease_required', 'unit_denied',
    'cap_reached', 'protocol_error', 'timeout', 'agent_disconnected', 'internal'
]);

class SysChannels {
    constructor(fm) {
        this.fm = fm;
        this.sessions = new Map();
        this.wss = new WebSocket.Server({ noServer: true, maxPayload: 64 * 1024 });
        this.resultWaitMs = SYS_RESULT_TIMEOUT_MS;
    }

    get env() {
        return this.fm.env || {};
    }

    upgrade(request, socket, head, parsed) {
        const hostId = channelUpgradeHost(this.env, request, socket, parsed, 'sys');
        if (hostId === null) return;
        this.wss.handleUpgrade(request, socket, head, (ws) => {
            this.open(ws, parsed, hostId).catch((err) => {
                console.error('[Fleet] sys open failed:', err.message);
                this.failSocket(ws, 'internal');
            });
        });
    }

    failSocket(ws, code) {
        sendJSON(ws, { type: 'sys_result', payload: { ok: false, error: code } });
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
            if (!session) console.error('[Fleet] sys socket error:', err && err.message);
        });
        // The client sends nothing on this channel; any frame is a protocol
        // error (SYS is request/response, the request rides the lease).
        ws.on('message', () => {
            if (session || early.failed) return;
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
        const purpose = parsed.searchParams.get('purpose') || SYS_PURPOSE;
        const row = consumeTicket(fm.tickets, ticketRes.ticket, hostId, purpose);
        if (!row || purpose !== SYS_PURPOSE) {
            this.failSocket(ws, 'ticket_invalid');
            return;
        }
        const checked = validateServiceBinding(row.sys);
        if (!checked.ok) {
            this.failSocket(ws, 'ticket_invalid');
            return;
        }
        if (!fm.signer) {
            this.failSocket(ws, 'lease_required');
            return;
        }
        const denied = await recheckChannelTicket(fm.registry, row, SYS_PURPOSE, { sys: checked.service });
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
        if (!fm.agentSupports(hostId, 'service')) {
            this.failSocket(ws, 'agent_unsupported');
            return;
        }
        const actor = row.actor || null;
        const perActor = envInt(this.env, 'SYSTEMAPI_SYS_MAX_PER_ACTOR', SYS_PER_ACTOR_DEFAULT, 1, SYS_PER_AGENT - 1);
        if (this.liveFor((s) => s.actor === actor) >= perActor || this.liveFor((s) => s.agent === agentWs) >= SYS_PER_AGENT) {
            console.warn('[Fleet] sys refused: in-flight cap reached');
            this.failSocket(ws, 'cap_reached');
            return;
        }

        const requestId = `sys_${randomToken(16)}`;
        const service = checked.service;
        let lease;
        try {
            lease = issueLease(fm.signer, {
                hostId,
                action: 'sys_service',
                payload: sysServicePayload(service.unit, service.action),
                ttl: SYS_LEASE_TTL_S
            });
        } catch (err) {
            this.failSocket(ws, 'lease_required');
            return;
        }
        const s = {
            id: requestId,
            hostId,
            tenantId: row.tenantId,
            actor,
            auth: row.auth || null,
            service,
            client: ws,
            agent: agentWs,
            ended: false,
            finalized: false,
            startedMs: Date.now(),
            resultTimer: null,
            endReason: null,
            result: null
        };
        this.sessions.set(requestId, s);
        session = s;

        // The intent row is written before the request is forwarded; if it
        // cannot be written, nothing is forwarded (fail closed).
        try {
            await fm.registry.appendAudit({
                tenant_id: s.tenantId,
                host_id: s.hostId,
                actor: s.actor,
                action: 'sys_service_intent',
                payload: { request_id: s.id, unit: service.unit, action: service.action }
            });
        } catch (err) {
            console.error('[Fleet] sys intent audit failed:', err.message);
            this.end(s, 'internal', { error: 'internal' });
            return;
        }
        if (s.ended) return;
        sendJSON(ws, { type: 'sys_status', payload: { status: 'forwarded', request_id: s.id } });
        sendJSON(agentWs, { type: 'sys_service', request_id: s.id, unit: service.unit, action: service.action, lease });
        s.resultTimer = unref(setTimeout(() => this.end(s, 'timeout', { error: 'timeout' }), this.resultWaitMs));
    }

    onClientClose(s) {
        if (s.ended) return;
        this.end(s, 'client_closed', {});
    }

    // Returns the live session only when this agent connection owns it.
    agentSession(ws, hostId, requestId) {
        if (typeof requestId !== 'string') return null;
        const s = this.sessions.get(requestId);
        if (!s || s.ended || s.agent !== ws || s.hostId !== hostId) return null;
        return s;
    }

    static owns(requestId) {
        return typeof requestId === 'string' && requestId.startsWith('sys_');
    }

    onAgentFrame(ws, hostId, msg) {
        if (msg.type !== 'sys_result') return;
        const s = this.agentSession(ws, hostId, msg.request_id);
        if (!s) return;
        const payload = msg.payload && typeof msg.payload === 'object' && !Array.isArray(msg.payload) ? msg.payload : {};
        this.end(s, 'result', { result: payload });
    }

    onAgentGone(ws) {
        for (const s of [...this.sessions.values()]) {
            if (s.agent === ws) this.end(s, 'agent_disconnected', { error: 'agent_disconnected' });
        }
    }

    // Ends a request once: relays the agent's result (or an error) to the
    // client, then writes the result audit row. opts.result is the agent's
    // sys_result payload; opts.error is a contract error (1011).
    end(s, reason, opts = {}) {
        if (s.ended) return;
        s.ended = true;
        s.endReason = reason;
        s.result = opts.result || null;
        clearTimeout(s.resultTimer);
        this.sessions.delete(s.id);
        const ws = s.client;
        if (reason === 'result' && opts.result) {
            sendJSON(ws, { type: 'sys_result', request_id: s.id, payload: opts.result });
            if (ws.readyState === WebSocket.OPEN) ws.close(1000);
        } else if (opts.error) {
            this.failSocket(ws, SYS_ERRORS.has(opts.error) ? opts.error : 'internal');
        } else if (ws.readyState === WebSocket.OPEN) {
            ws.close(1000);
        }
        this.finalize(s);
    }

    // Writes the sys_service_result row once, retried like tcp_end.
    finalize(s) {
        if (s.finalized) return;
        s.finalized = true;
        const r = s.result || {};
        const payload = {
            request_id: s.id,
            unit: s.service.unit,
            action: s.service.action,
            reason: s.endReason,
            ok: r.ok === true,
            result_state: typeof r.state === 'string' ? r.state : null,
            result_active: typeof r.active === 'boolean' ? r.active : null,
            error: typeof r.error === 'string' ? r.error : null,
            duration_s: Math.round((Date.now() - s.startedMs) / 1000)
        };
        const fm = this.fm;
        appendAuditRetrying(fm.registry, {
            tenant_id: s.tenantId,
            host_id: s.hostId,
            actor: s.actor,
            action: 'sys_service_result',
            payload
        }, fm.auditRetryDelaysMs, (err) => {
            console.error('[Fleet] sys result audit failed:', err && err.message);
        }, (kind, fp, detail) => fm.noteSecurity(kind, fp, detail)).catch((err) => {
            console.error('[Fleet] sys result audit failed:', err.message);
        });
    }
}

module.exports = { SysChannels, SYS_ERRORS, SYS_PER_AGENT };
