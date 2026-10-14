// Threats: a long-lived API key in a browser WebSocket URL. Tickets are
// single-use, 60s, and bound to a host and purpose. Consume deletes the
// ticket even when the host or purpose does not match. Channel tickets
// (tcp:open, file:*) are also bound to their target or root: the binding is
// stored on the ticket, a channel ticket without one is refused at consume,
// and a caller that passes an expected binding must match it exactly. Tickets
// live in this process's memory: they do not survive a restart and are not
// shared between server nodes (known residual until phase 4).
'use strict';

const { randomToken } = require('./token');

const TTL_MS = 60_000;

function frozenTarget(target) {
  if (!target) return null;
  return Object.freeze({ host: target.host, port: target.port });
}

// auth ({ kind, keyId, groupRole }) is what the upgrade needs to re-check the
// actor's scopes (authz.ticketScopesHeld); it is never sent anywhere.
function issueTicket(store, { hostId, purpose, tenantId, actor = null, auth = null, target = null, root = null }) {
  const ticket = `stk_${randomToken(32)}`;
  store.set(ticket, {
    hostId,
    purpose,
    tenantId,
    actor,
    auth: auth ? Object.freeze({ kind: auth.kind, keyId: auth.keyId || null, groupRole: auth.groupRole || null }) : null,
    target: frozenTarget(target),
    root: typeof root === 'string' ? root : null,
    exp: Date.now() + TTL_MS
  });
  return ticket;
}

function bindingOk(row, expect) {
  if (row.purpose === 'tcp:open') {
    if (!row.target || typeof row.target.host !== 'string' || !Number.isInteger(row.target.port)) return false;
    if (expect && expect.target !== undefined) {
      const t = expect.target;
      if (!t || t.host !== row.target.host || t.port !== row.target.port) return false;
    }
    return true;
  }
  if (row.purpose === 'file:read' || row.purpose === 'file:write' || row.purpose === 'file:root') {
    if (typeof row.root !== 'string' || row.root.length === 0) return false;
    if (expect && expect.root !== undefined && expect.root !== row.root) return false;
    return true;
  }
  return true;
}

// expect, when given, is { target } or { root } and must equal the binding.
function consumeTicket(store, token, hostId, purpose, now = Date.now(), expect = undefined) {
  if (typeof token !== 'string' || !token.startsWith('stk_')) return null;
  const row = store.get(token);
  if (!row) return null;
  store.delete(token);
  if (row.exp < now) return null;
  if (row.hostId !== hostId || row.purpose !== purpose) return null;
  if (!bindingOk(row, expect)) return null;
  return row;
}

module.exports = { TTL_MS, issueTicket, consumeTicket };
