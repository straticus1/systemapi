/**
 * Shared server scaffolding for SAH channel sessions (TCP forward now, file
 * channel next): the PTY §3 upgrade rules, the upgrade-time re-check of a
 * consumed ticket, the two backpressure pumps of docs/sah-tcp-protocol.md §6
 * and a retrying audit append.
 *
 * Threats: an API key in a channel URL (HTTP 401), a browser page on another
 * site opening a channel (Origin allowlist, HTTP 403), a ticket whose actor
 * lost the scope or whose target/root the policy stopped allowing between
 * issue and upgrade (re-check at the upgrade, fail closed), and one stream
 * growing server memory: agent->client bytes are held only up to the
 * stream's credit window and are sent while the client's bufferedAmount is
 * under 1 MiB, with credit returned to the agent only below that line;
 * client->agent bytes leave only inside the agent's credit, and the client
 * socket is paused while there is none. Nothing is ever dropped: a pump that
 * cannot send keeps the bytes and stalls only its own stream. Does NOT
 * bound how long a stalled stream lives (the caller's idle timeout and byte
 * cap do), and does NOT check the ticket itself (tickets.consumeTicket).
 */
'use strict';

const WebSocket = require('ws');
const { originAllowed } = require('../controlplane/httpauth');
const { PURPOSE_SCOPES, policyDecision } = require('../controlplane/channels');
const { ticketScopesHeld } = require('../controlplane/authz');
const { MAX_TURN } = require('../controlplane/credit');
const { fingerprint } = require('../controlplane/token');

const CHANNEL_FRAME_MAX = 64 * 1024;
const CLIENT_BUFFER_MAX = 1024 * 1024;
const PUMP_POLL_MS = 20;

// Integer setting from env, or the default when unset or invalid.
function envInt(env, name, fallback, min, max) {
    const raw = env && env[name];
    if (raw === undefined || raw === null || raw === '') return fallback;
    const n = Number(raw);
    if (!Number.isSafeInteger(n) || n < min || n > max) {
        console.error(`[Fleet] ${name} is invalid; using the default`);
        return fallback;
    }
    return n;
}

function unref(timer) {
    if (timer && typeof timer.unref === 'function') timer.unref();
    return timer;
}

function sendJSON(ws, obj) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function rejectUpgrade(socket, status, reason) {
    socket.write(`HTTP/1.1 ${status} ${reason}\r\n\r\n`);
    socket.destroy();
}

// PTY §3 upgrade rules for a channel path ".../<host_id>": api_key in the
// query is 401, a present Origin outside the allowlist is 403 (no Origin, a
// CLI, is fine). Returns the host id, or null after rejecting.
function channelUpgradeHost(env, request, socket, parsed, label) {
    if (parsed.searchParams.has('api_key')) {
        rejectUpgrade(socket, 401, 'Unauthorized');
        return null;
    }
    if (!originAllowed(request.headers.origin, env || {})) {
        console.warn(`[Fleet] ${label} upgrade refused: origin not allowed`);
        rejectUpgrade(socket, 403, 'Forbidden');
        return null;
    }
    try {
        return decodeURIComponent(parsed.pathname.split('/').pop() || '');
    } catch {
        rejectUpgrade(socket, 400, 'Bad Request');
        return null;
    }
}

// Re-checks a consumed channel ticket at the upgrade (TCP §4.2, §13): the
// actor still holds the purpose's scopes, and the bound target/root still
// passes validation, the refused classes and the server policy. Returns null
// or a contract error code. Any lookup failure is 'internal' (fail closed).
async function recheckChannelTicket(registry, row, purpose, binding) {
    try {
        if (!(await ticketScopesHeld(registry, row, PURPOSE_SCOPES[purpose] || [purpose]))) return 'scope_denied';
        const denied = await policyDecision(registry, row.hostId, purpose, binding);
        if (denied === 'bad_target' || denied === 'bad_root') return 'ticket_invalid';
        return denied || null;
    } catch (err) {
        console.error('[Fleet] channel re-check failed:', err.message);
        return 'internal';
    }
}

// Appends an audit row, retrying after each delay in delaysMs; a final
// failure calls onFail(err) and records audit_write_failed. Resolves either
// way (end rows must not throw into socket handlers).
async function appendAuditRetrying(registry, entry, delaysMs, onFail, noteSecurity) {
    let lastErr = null;
    for (const delay of [0, ...delaysMs]) {
        if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
        try {
            if (!registry) throw new Error('registry_unavailable');
            await registry.appendAudit(entry);
            return true;
        } catch (err) {
            lastErr = err;
        }
    }
    if (onFail) onFail(lastErr);
    if (noteSecurity) {
        await noteSecurity('audit_write_failed', fingerprint(String(entry.actor)), {
            session_id: entry.payload && entry.payload.session_id,
            action: entry.action
        });
    }
    return false;
}

// Agent -> client bytes of one stream (TCP §6 "client <-> server").
// push(data) queues bytes the agent sent inside its window; after(fn) queues
// a callback that runs once every byte queued before it was handed to the
// client (tcp_eof and tcp_close ordering). Bytes go out only while
// client.bufferedAmount < maxBuffered; credit for them goes back to the
// agent (onCredit(n), batched by the CreditStream) only while it is under
// that line too. Held bytes are bounded by the stream's window.
class ClientSink {
    constructor({ client, stream, onCredit, maxBuffered = CLIENT_BUFFER_MAX, pollMs = PUMP_POLL_MS }) {
        this.client = client;
        this.stream = stream;
        this.onCredit = onCredit;
        this.maxBuffered = maxBuffered;
        this.pollMs = pollMs;
        this.items = [];
        this.queuedBytes = 0;
        this.uncredited = 0;
        this.opened = false;
        this.stopped = false;
        this.timer = null;
    }

    // Data is held until open() (the start audit row and "connected").
    open() {
        this.opened = true;
        this.pump();
    }

    push(data) {
        if (this.stopped || data.length === 0) return;
        this.items.push(Buffer.from(data));
        this.queuedBytes += data.length;
        this.pump();
    }

    after(fn) {
        if (this.stopped) return;
        this.items.push(fn);
        this.pump();
    }

    get empty() {
        return this.items.length === 0;
    }

    pump() {
        if (this.stopped || !this.opened) return;
        const ws = this.client;
        while (this.items.length > 0) {
            if (ws.readyState !== WebSocket.OPEN) return;
            if (ws.bufferedAmount >= this.maxBuffered) break;
            const item = this.items[0];
            if (typeof item === 'function') {
                this.items.shift();
                item();
                if (this.stopped) return;
                continue;
            }
            const take = Math.min(item.length, CHANNEL_FRAME_MAX);
            ws.send(item.subarray(0, take));
            this.queuedBytes -= take;
            this.uncredited += take;
            if (take === item.length) this.items.shift();
            else this.items[0] = item.subarray(take);
        }
        if (this.uncredited > 0 && ws.readyState === WebSocket.OPEN && ws.bufferedAmount < this.maxBuffered) {
            const credit = this.stream.drain(this.uncredited);
            this.uncredited = 0;
            if (credit > 0) this.onCredit(credit);
        }
        const blocked = this.items.length > 0 || this.uncredited > 0;
        if (blocked && !this.timer && !this.stopped) {
            this.timer = unref(setTimeout(() => {
                this.timer = null;
                this.pump();
            }, this.pollMs));
        }
    }

    stop() {
        this.stopped = true;
        this.items = [];
        this.queuedBytes = 0;
        clearTimeout(this.timer);
        this.timer = null;
    }
}

// Client -> agent bytes of one stream. push(data) queues; bytes leave
// (send(chunk), at most 64 KiB) only inside the agent's credit; the client
// socket is paused while bytes wait for credit or no credit is left, and
// resumed once the queue is empty and credit is back. after(fn) runs fn once everything queued before it was sent
// (tcp_eof ordering). push returns false past maxQueued (bytes a paused
// socket had already parsed); the caller ends the stream.
class AgentSource {
    constructor({ client, stream, send, maxQueued = CLIENT_BUFFER_MAX }) {
        this.client = client;
        this.stream = stream;
        this.send = send;
        this.maxQueued = maxQueued;
        this.items = [];
        this.queuedBytes = 0;
        this.paused = false;
        this.stopped = false;
    }

    push(data) {
        if (this.stopped) return true;
        if (this.queuedBytes + data.length > this.maxQueued) return false;
        this.items.push(Buffer.from(data));
        this.queuedBytes += data.length;
        this.pump();
        return true;
    }

    after(fn) {
        if (this.stopped) return;
        this.items.push(fn);
        this.pump();
    }

    pump() {
        if (this.stopped) return;
        while (this.items.length > 0) {
            const item = this.items[0];
            if (typeof item === 'function') {
                this.items.shift();
                item();
                if (this.stopped) return;
                continue;
            }
            const take = Math.min(item.length, this.stream.sendable(MAX_TURN));
            if (take <= 0) break;
            this.stream.take(take);
            this.send(item.subarray(0, take));
            this.queuedBytes -= take;
            if (take === item.length) this.items.shift();
            else this.items[0] = item.subarray(take);
        }
        // Paused while bytes wait or the agent has granted no credit at all.
        this.setPaused(this.items.length > 0 || this.stream.sendable(1) === 0);
    }

    setPaused(want) {
        if (want === this.paused) return;
        const ws = this.client;
        if (ws.readyState !== WebSocket.OPEN) return;
        this.paused = want;
        if (want) ws.pause();
        else ws.resume();
    }

    stop() {
        this.stopped = true;
        this.items = [];
        this.queuedBytes = 0;
    }
}

module.exports = {
    CHANNEL_FRAME_MAX,
    CLIENT_BUFFER_MAX,
    envInt,
    unref,
    sendJSON,
    rejectUpgrade,
    channelUpgradeHost,
    recheckChannelTicket,
    appendAuditRetrying,
    ClientSink,
    AgentSource
};
