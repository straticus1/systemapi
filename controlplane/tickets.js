// Threats: a long-lived API key in a browser WebSocket URL. Tickets are
// single-use, 60s, and bound to a host and purpose. Consume deletes the
// ticket even when the host or purpose does not match.
'use strict';

const { randomToken } = require('./token');

const TTL_MS = 60_000;

function issueTicket(store, { hostId, purpose, tenantId }) {
  const ticket = `stk_${randomToken(32)}`;
  store.set(ticket, { hostId, purpose, tenantId, exp: Date.now() + TTL_MS });
  return ticket;
}

function consumeTicket(store, token, hostId, purpose, now = Date.now()) {
  if (typeof token !== 'string' || !token.startsWith('stk_')) return null;
  const row = store.get(token);
  if (!row) return null;
  store.delete(token);
  if (row.exp < now) return null;
  if (row.hostId !== hostId || row.purpose !== purpose) return null;
  return row;
}

module.exports = { TTL_MS, issueTicket, consumeTicket };
