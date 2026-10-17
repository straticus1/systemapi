/**
 * sahxfer grants, server half (POST /api/v1/xfer/grant; sahxfer
 * docs/design.md §3). SystemAPI authorizes one file in one direction and
 * pushes the grant to the host agent on its existing WebSocket. File bytes
 * never touch this process: they move on UDP between the client and the
 * address in peer.udp.
 *
 * Threats: a write through read-only authority (xfer:put needs file:read and
 * file:write in the host's tenant and a policy root with read and write;
 * xfer:root needs the admin-only file:root and a root-flagged policy entry,
 * the same rules as the file channel), a grant for a path outside the root
 * (FILE §5.1 shapes refused here, the agent's openat2 helper refuses again),
 * a grant for host A used on host B (the lease is signed for one host id and
 * one grant id), a put lease used for a get (the signed payload names the
 * direction), a grant with no audit trail (the xfer_intent row is written
 * before the agent sees the key; a failed write issues nothing; no result
 * row is written for a grant that was never pushed past its intent row), a
 * grant that outlives the operator's authority (renewal every 30 s re-checks
 * scopes, membership, key and policy; a refusal cancels the grant and the
 * agent's last lease lapses in 60 s), a grant nobody uses (no "active"
 * progress within 60 s of ready, or none for idle_seconds after it, cancels
 * it; a client that hangs up before the response cancels it), unbounded
 * grants (two live per actor, counting grants still in their tombstone
 * window, and a hard max of SYSTEMAPI_XFER_MAX_SECONDS), a result recorded
 * wrongly (a grant the server cancels, or whose agent socket drops, is kept
 * as a tombstone for the agent's remaining lease window; a late xfer_result
 * from any authenticated socket of the same host is recorded, and with none
 * the row says "unknown", never "aborted", because the agent may have
 * committed) and a leaked key or route token (both come from the OS CSPRNG,
 * are sent only in the no-store response and the xfer_grant frame, and are
 * never logged or audited; JavaScript strings holding them are not wiped).
 * Does NOT carry or inspect file bytes, does NOT run the relay that
 * peer.udp names (SYSTEMAPI_XFER_PEER_UDP must point at one; unset is
 * agent_unsupported), does NOT issue get grants yet (design §15: put ships
 * first; the agent hash step has no wire frame), does NOT persist grants
 * across a server restart (a restart loses the result row), and does NOT
 * sign overwrite, peer_udp, max_s, idle_s, byte_cap or transfer_id: the
 * design §3.4 lease payload covers only grant id, deadline, phase, dir,
 * root, path, size and sha256 (docs/sah-suite.md, Partially wired).
 *
 * Agent frames (no agent implements them yet; an agent that does advertises
 * the "xfer" capability):
 *   server -> agent  xfer_grant  {grant_id, transfer_id, action, purpose, dir,
 *                    root, path, size, sha256, overwrite, profile, transport,
 *                    peer_udp, aead, key, route_token, expires_unix,
 *                    deadline_unix, idle_s, max_s, byte_cap, actor, lease}
 *   agent -> server  xfer_status {grant_id, payload:{status:"ready"} | {error}}
 *                    then {status:"active", bytes} as progress; an {error}
 *                    after ready ends the grant
 *   server -> agent  xfer_renew  {grant_id, deadline_unix, lease}
 *   server -> agent  xfer_cancel {grant_id, reason}
 *   agent -> server  xfer_result {grant_id, payload:{status, bytes, sha256}},
 *                    accepted from any socket of the same host until the
 *                    tombstone window closes
 */
'use strict';

const crypto = require('node:crypto');
const WebSocket = require('ws');
const { issueLease, xferPayload } = require('../controlplane/lease');
const { validateFileRoot } = require('../controlplane/channels');
const { randomToken } = require('../controlplane/token');
const { checkPath } = require('./file');
const { envInt, unref, sendJSON, recheckChannelTicket, appendAuditRetrying } = require('./channel');

const PURPOSES = Object.freeze({ 'xfer:put': 'file:write', 'xfer:get': 'file:read', 'xfer:root': 'file:root' });
const TRANSPORTS = new Set(['udp', 'quic-datagram', 'quic-stream', 'quic-bridge']);
const SHA256_RE = /^[0-9a-f]{64}$/;
const AEAD = 'ChaCha20-Poly1305';
const LEASE_TTL_S = 60;
const RENEW_MS = 30_000;
const READY_TIMEOUT_MS = 10_000;
const FIRST_PACKET_S = 60;
// How long a cancelled or orphaned grant waits for a late xfer_result: the
// agent's last lease (60 s) plus the lease clock skew allowance (30 s).
const TOMBSTONE_MS = (LEASE_TTL_S + 30) * 1000;
const MAX_SECONDS_DEFAULT = 3600;
const IDLE_SECONDS_DEFAULT = 30;
const PER_ACTOR_DEFAULT = 2;
const MAX_BYTES_DEFAULT = 256 * 1024 ** 3;
const RESULT_STATUSES = new Set(['ok', 'hash_mismatch', 'aborted', 'expired', 'io_error']);
// Agent refusals passed through to the client, with their HTTP status.
const AGENT_ERRORS = Object.freeze({
    bad_root: 400, bad_path: 400, reserved_name: 400, symlink_refused: 403, not_a_file: 409, root_denied: 403,
    not_found: 404, exists: 409, too_large: 413, agent_unsupported: 501, cap_reached: 429, changed: 409, internal: 500
});

function httpError(status, code) {
    const err = new Error(code);
    err.status = status;
    err.code = code;
    return err;
}

// design §3.2: FILE §5.1 path rules, plus "." (not a file) and the
// .sahxfer-*.part temp name refused.
function checkXferPath(p) {
    if (p === '.') return 'bad_path';
    const err = checkPath(p);
    if (err) return err;
    for (const c of p.split('/')) {
        if (c.length >= '.sahxfer-.part'.length && c.startsWith('.sahxfer-') && c.endsWith('.part')) return 'reserved_name';
    }
    return null;
}

// Shape checks of the request body, before any lookup. Returns
// { ok:true, request } or { ok:false, status, error }.
function parseGrantRequest(body, env = {}) {
    const bad = (error, status = 400) => ({ ok: false, status, error });
    if (!body || typeof body !== 'object' || Array.isArray(body)) return bad('bad_request');
    const { host_id: hostId, purpose, dir, root, path, size, sha256 } = body;
    if (typeof purpose !== 'string' || !Object.prototype.hasOwnProperty.call(PURPOSES, purpose)) return bad('bad_purpose');
    if (dir !== 'put' && dir !== 'get') return bad('bad_purpose');
    if ((purpose === 'xfer:put' && dir !== 'put') || (purpose === 'xfer:get' && dir !== 'get')) return bad('bad_purpose');
    if (typeof hostId !== 'string' || !/^[A-Za-z0-9._-]{1,253}$/.test(hostId)) return bad('bad_request');
    const rootChecked = validateFileRoot(root, 'file:root');
    if (!rootChecked.ok) return bad('bad_root');
    const pathErr = checkXferPath(path);
    if (pathErr) return bad(pathErr);
    if (typeof size !== 'number' || !Number.isInteger(size) || size < 0) return bad('bad_request');
    const cap = envInt(env, 'SYSTEMAPI_XFER_MAX_BYTES', MAX_BYTES_DEFAULT, 1, Number.MAX_SAFE_INTEGER);
    if (!Number.isSafeInteger(size) || size > cap) return bad('too_large', 413);
    if (dir === 'put' && (typeof sha256 !== 'string' || !SHA256_RE.test(sha256))) return bad('bad_request');
    if (dir === 'get' && sha256 !== undefined && (typeof sha256 !== 'string' || !SHA256_RE.test(sha256))) return bad('bad_request');
    if (body.overwrite !== undefined && typeof body.overwrite !== 'boolean') return bad('bad_request');
    const transport = body.transport === undefined ? 'udp' : body.transport;
    if (!TRANSPORTS.has(transport)) return bad('bad_request');
    return {
        ok: true,
        request: {
            host_id: hostId, purpose, dir, root: rootChecked.root, path, size,
            sha256: sha256 === undefined ? null : sha256, overwrite: body.overwrite === true, transport
        }
    };
}

// host:port with a numeric port 1..65535; the host is an IP literal or a DNS
// name (IPv6 in brackets). Returns the string or null.
function peerAddress(raw) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 256 || /[\s\u0000-\u001f\u007f]/.test(raw)) return null;
    const m = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,4})$/.exec(raw);
    if (!m || Number(m[2]) > 65535) return null;
    return raw;
}

class XferGrants {
    constructor(fm) {
        this.fm = fm;
        // Live and tombstoned grants by grant id. state is 'live' or
        // 'tombstone'; a finished grant is removed.
        this.grants = new Map();
        this.renewMs = RENEW_MS;
        this.readyTimeoutMs = READY_TIMEOUT_MS;
        this.firstPacketMs = FIRST_PACKET_S * 1000;
        this.tombstoneMs = TOMBSTONE_MS;
    }

    get env() {
        return this.fm.env || {};
    }

    liveFor(actor) {
        let n = 0;
        for (const g of this.grants.values()) if (g.actor === actor) n += 1;
        return n;
    }

    newTransferId() {
        for (;;) {
            const id = crypto.randomBytes(8).toString('hex');
            if (id === '0000000000000000') continue;
            let used = false;
            for (const g of this.grants.values()) if (g.transferId === id) used = true;
            if (!used) return id;
        }
    }

    lease(g, phase, nowMs) {
        const deadlineUnix = Math.floor(nowMs / 1000) + LEASE_TTL_S;
        const lease = issueLease(this.fm.signer, {
            hostId: g.hostId,
            action: g.action,
            payload: xferPayload(g.id, deadlineUnix, phase, g.dir, g.root, g.path, g.size, g.sha256),
            ttl: LEASE_TTL_S,
            now: nowMs
        });
        return { lease, deadlineUnix };
    }

    // Called by the route after authentication, scope, host and policy
    // checks. Resolves the response body or throws an HTTP error. client is
    // { gone, onGone }: the route sets gone and calls onGone when the HTTP
    // client hangs up before the response is written.
    async grant({ principal, host, request, client = { gone: false, onGone: null } }) {
        const fm = this.fm;
        const env = this.env;
        if (request.dir !== 'put') throw httpError(501, 'agent_unsupported');
        if (request.transport !== 'udp') throw httpError(501, 'agent_unsupported');
        const peerUdp = peerAddress(env.SYSTEMAPI_XFER_PEER_UDP);
        if (!peerUdp) throw httpError(501, 'agent_unsupported');
        const agentWs = fm.connectedAgents && fm.connectedAgents.get(host.host_id);
        if (!agentWs || agentWs.readyState !== WebSocket.OPEN) throw httpError(503, 'agent_offline');
        if (!fm.agentSupports(host.host_id, 'xfer')) throw httpError(501, 'agent_unsupported');
        if (!fm.signer) throw httpError(503, 'internal');
        const actor = principal.userId;
        const perActor = envInt(env, 'SYSTEMAPI_XFER_MAX_PER_ACTOR', PER_ACTOR_DEFAULT, 1, 1000);
        if (this.liveFor(actor) >= perActor) throw httpError(429, 'cap_reached');

        const maxSeconds = envInt(env, 'SYSTEMAPI_XFER_MAX_SECONDS', MAX_SECONDS_DEFAULT, 1, 3600);
        const idleSeconds = Math.min(envInt(env, 'SYSTEMAPI_XFER_IDLE_SECONDS', IDLE_SECONDS_DEFAULT, 1, 3600), maxSeconds);
        const nowMs = Date.now();
        const g = {
            id: `xfr_${randomToken(16)}`,
            transferId: this.newTransferId(),
            hostId: host.host_id,
            tenantId: host.tenant_id,
            actor,
            auth: { kind: principal.kind, keyId: principal.keyId || null, groupRole: principal.groupRole || null },
            purpose: request.purpose,
            filePurpose: PURPOSES[request.purpose],
            action: request.purpose === 'xfer:root' ? 'xfer_root' : 'xfer',
            dir: request.dir,
            root: request.root,
            path: request.path,
            size: request.size,
            sha256: request.sha256,
            overwrite: request.overwrite,
            agent: agentWs,
            startedMs: nowMs,
            idleMs: idleSeconds * 1000,
            state: 'live',
            pushed: false,
            ready: null,
            active: false,
            bytes: null,
            renewing: false,
            renewTimer: null,
            maxTimer: null,
            idleTimer: null,
            tombTimer: null,
            retireReason: null
        };
        // The slot is held before the first await so two concurrent requests
        // cannot both pass the per-actor cap.
        this.grants.set(g.id, g);
        let first;
        try {
            first = this.lease(g, 'start', nowMs);
        } catch (err) {
            this.grants.delete(g.id);
            throw httpError(500, 'internal');
        }
        try {
            if (!fm.registry) throw new Error('registry_unavailable');
            await fm.registry.appendAudit({
                tenant_id: g.tenantId,
                host_id: g.hostId,
                actor,
                action: 'xfer_intent',
                payload: {
                    grant_id: g.id, transfer_id: g.transferId, purpose: g.purpose, dir: g.dir, root: g.root,
                    path: g.path, size: g.size, sha256: g.sha256, overwrite: g.overwrite, transport: 'udp',
                    lease_nonce: first.lease.nonce_hex
                }
            });
        } catch (err) {
            this.grants.delete(g.id);
            console.error('[Fleet] xfer intent audit failed:', err.message);
            throw httpError(500, 'internal');
        }
        // Nothing was pushed: the agent never saw the key, so aborted is exact.
        if (agentWs.readyState !== WebSocket.OPEN || client.gone) {
            const code = client.gone ? 'client_gone' : 'agent_offline';
            await this.end(g, 'aborted', { error: code });
            throw httpError(code === 'client_gone' ? 499 : 503, code);
        }

        const key = crypto.randomBytes(32).toString('base64');
        const routeToken = crypto.randomBytes(16).toString('base64');
        const expiresMs = nowMs + FIRST_PACKET_S * 1000;
        const doc = {
            grant_id: g.id,
            host_id: g.hostId,
            transfer_id: g.transferId,
            expires_at: new Date(expiresMs).toISOString(),
            expires_in: FIRST_PACKET_S,
            idle_seconds: idleSeconds,
            max_seconds: maxSeconds,
            byte_cap: g.size,
            purpose: g.purpose,
            root: g.root,
            path: g.path,
            size: g.size,
            sha256: g.sha256,
            overwrite: g.overwrite,
            profile: 'internet',
            transport: 'udp',
            peer: { udp: peerUdp, quic: null },
            aead: AEAD,
            key,
            route_token: routeToken
        };
        const readyP = new Promise((resolve, reject) => {
            g.ready = { resolve, reject, timer: null };
            g.ready.timer = unref(setTimeout(() => reject(httpError(503, 'agent_offline')), this.readyTimeoutMs));
        });
        readyP.catch(() => {});
        client.onGone = () => {
            if (g.ready) g.ready.reject(httpError(499, 'client_gone'));
            else this.cancel(g, 'client_gone');
        };
        try {
            g.pushed = true;
            sendJSON(agentWs, {
                type: 'xfer_grant',
                grant_id: g.id,
                transfer_id: g.transferId,
                action: g.action,
                purpose: g.purpose,
                dir: g.dir,
                root: g.root,
                path: g.path,
                size: g.size,
                sha256: g.sha256,
                overwrite: g.overwrite,
                profile: doc.profile,
                transport: doc.transport,
                peer_udp: peerUdp,
                aead: AEAD,
                key,
                route_token: routeToken,
                expires_unix: Math.floor(expiresMs / 1000),
                deadline_unix: first.deadlineUnix,
                idle_s: idleSeconds,
                max_s: maxSeconds,
                byte_cap: doc.byte_cap,
                actor: actor === null || actor === undefined ? '' : String(actor),
                lease: first.lease
            });
            await readyP;
        } catch (err) {
            const code = err.code || 'internal';
            if (g.state === 'live') {
                if (code === 'agent_offline' || code === 'client_gone' || !err.status) {
                    // The agent may have accepted the frame: wait for a result.
                    this.cancel(g, code === 'agent_offline' && agentWs.readyState === WebSocket.OPEN ? 'start_timeout' : code);
                } else {
                    // The agent refused before ready: nothing was started.
                    await this.end(g, 'aborted', { error: code });
                }
            }
            throw httpError(err.status || 500, code);
        } finally {
            if (g.ready) clearTimeout(g.ready.timer);
            g.ready = null;
        }
        if (g.state !== 'live') throw httpError(503, 'agent_offline');
        g.renewTimer = unref(setInterval(() => { this.renew(g); }, this.renewMs));
        g.maxTimer = unref(setTimeout(() => this.cancel(g, 'max_duration'), maxSeconds * 1000));
        this.armIdle(g, this.firstPacketMs, 'first_packet_timeout');
        return doc;
    }

    // Before the first "active" frame the window is firstPacketMs; after
    // each one it is idle_seconds.
    armIdle(g, ms, reason) {
        clearTimeout(g.idleTimer);
        g.idleTimer = unref(setTimeout(() => this.cancel(g, reason), ms));
    }

    // Server-side stop of a pushed grant: tell the agent, then wait for its
    // result as a tombstone.
    cancel(g, reason) {
        if (g.state !== 'live') return;
        sendJSON(g.agent, { type: 'xfer_cancel', grant_id: g.id, reason });
        this.retire(g, reason);
    }

    // The grant stops renewing but stays in the map (and in the actor's
    // count) until the agent's lease window has closed. A late xfer_result
    // ends it with the agent's status; none ends it as "unknown".
    retire(g, reason) {
        if (g.state !== 'live') return;
        g.state = 'tombstone';
        g.retireReason = reason;
        clearInterval(g.renewTimer);
        clearTimeout(g.maxTimer);
        clearTimeout(g.idleTimer);
        g.tombTimer = unref(setTimeout(() => { this.end(g, 'unknown', { error: reason }); }, this.tombstoneMs));
    }

    // Re-checks the actor's authority, then sends a fresh 60 s lease. A
    // withdrawn grant is cancelled; a failed lookup skips one renewal (the
    // agent's lease lapses if the next one fails too).
    async renew(g) {
        if (g.state !== 'live' || g.renewing || !this.fm.signer) return;
        g.renewing = true;
        let denied;
        try {
            denied = await recheckChannelTicket(this.fm.registry,
                { actor: g.actor, tenantId: g.tenantId, auth: g.auth, hostId: g.hostId }, g.filePurpose, { root: g.root });
        } finally {
            g.renewing = false;
        }
        if (g.state !== 'live') return;
        if (denied === 'internal') {
            console.error('[Fleet] xfer lease renewal skipped: re-check unavailable');
            return;
        }
        if (denied) {
            console.warn(`[Fleet] xfer ${g.id}: grant withdrawn (${denied}); cancelling`);
            this.cancel(g, 'stopped');
            return;
        }
        try {
            const { lease, deadlineUnix } = this.lease(g, 'renew', Date.now());
            sendJSON(g.agent, { type: 'xfer_renew', grant_id: g.id, deadline_unix: deadlineUnix, lease });
        } catch (err) {
            console.error('[Fleet] xfer lease renewal failed:', err.message);
        }
    }

    // hostId is the host the sending socket enrolled as. xfer_status is
    // accepted only from the socket the grant was pushed on; xfer_result
    // from any socket of the same host, so a result sent after a reconnect
    // is still recorded.
    onAgentFrame(ws, hostId, msg) {
        const g = typeof msg.grant_id === 'string' ? this.grants.get(msg.grant_id) : null;
        if (!g || g.hostId !== hostId || !g.pushed) return;
        const p = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};
        if (msg.type === 'xfer_status') {
            if (g.agent !== ws || g.state !== 'live') return;
            if (g.ready) {
                if (p.status === 'ready') {
                    g.ready.resolve();
                    return;
                }
                const code = Object.prototype.hasOwnProperty.call(AGENT_ERRORS, p.error) ? p.error : 'internal';
                g.ready.reject(httpError(AGENT_ERRORS[code], code));
                return;
            }
            if (p.status === 'active') {
                g.active = true;
                if (Number.isSafeInteger(p.bytes) && p.bytes >= 0) g.bytes = p.bytes;
                this.armIdle(g, g.idleMs, 'idle_timeout');
                return;
            }
            if (p.error !== undefined) {
                // A failure after ready is terminal: the agent says it stopped.
                const code = Object.prototype.hasOwnProperty.call(AGENT_ERRORS, p.error) ? p.error : 'internal';
                this.end(g, 'aborted', { error: code, bytes: g.bytes });
            }
            return;
        }
        if (msg.type === 'xfer_result') {
            // A result before ready is a refusal the agent spelled wrong.
            if (g.ready) {
                if (g.agent === ws) g.ready.reject(httpError(500, 'internal'));
                return;
            }
            const status = RESULT_STATUSES.has(p.status) ? p.status : 'aborted';
            const bytes = Number.isSafeInteger(p.bytes) && p.bytes >= 0 ? p.bytes : null;
            const sha256 = typeof p.sha256 === 'string' && SHA256_RE.test(p.sha256) ? p.sha256 : null;
            this.end(g, status, { bytes, sha256, error: g.retireReason });
        }
    }

    // Grants not pushed yet are left to grant(), which sees the closed
    // socket after its intent row and ends them itself.
    onAgentGone(ws) {
        for (const g of [...this.grants.values()]) {
            if (g.agent !== ws || !g.pushed || g.state !== 'live') continue;
            if (g.ready) g.ready.reject(httpError(503, 'agent_offline'));
            else this.retire(g, 'agent_disconnected');
        }
    }

    // Removes the grant and writes the xfer_result row (design §3.5). The
    // agent's bytes and hash are recorded as reported; status ok with a
    // different hash is recorded as hash_mismatch. "unknown" means the
    // server stopped hearing about a grant the agent may still have
    // committed.
    async end(g, status, { error = null, bytes = null, sha256 = null } = {}) {
        if (g.state === 'done') return;
        g.state = 'done';
        clearInterval(g.renewTimer);
        clearTimeout(g.maxTimer);
        clearTimeout(g.idleTimer);
        clearTimeout(g.tombTimer);
        this.grants.delete(g.id);
        let final = status;
        if (final === 'ok' && (sha256 !== g.sha256 || bytes !== g.size)) final = 'hash_mismatch';
        const payload = {
            grant_id: g.id, size: g.size, sha256: g.sha256, bytes, result_sha256: sha256,
            status: final, duration_ms: Date.now() - g.startedMs
        };
        if (error) payload.error = error;
        await appendAuditRetrying(this.fm.registry, {
            tenant_id: g.tenantId, host_id: g.hostId, actor: g.actor, action: 'xfer_result', payload
        }, this.fm.auditRetryDelaysMs || [200, 1000], (err) => {
            console.error('[Fleet] xfer result audit failed:', err && err.message);
        }, this.fm.noteSecurity ? this.fm.noteSecurity.bind(this.fm) : null);
    }
}

module.exports = { XferGrants, PURPOSES, parseGrantRequest, checkXferPath, peerAddress };
