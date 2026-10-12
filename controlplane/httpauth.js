// Threats: demo credentials accepted in production, and long-lived API keys
// placed in WebSocket query strings (logs, proxies, Referer). Does NOT
// authenticate the key itself; callers still verify the bearer against the store.
'use strict';

function demoKeyAllowed(env) {
  return env.SYSTEMAPI_ALLOW_DEMO === '1' && env.NODE_ENV !== 'production';
}

function agentAuthFromRequest(url, headers) {
  const params = url.searchParams;
  if (params.has('api_key')) {
    return { ok: false, status: 401, error: 'query_key_rejected' };
  }
  const auth = headers.authorization || headers.Authorization || '';
  if (!auth.startsWith('Bearer ')) {
    return { ok: false, status: 401, error: 'bearer_required' };
  }
  const token = auth.slice('Bearer '.length);
  if (!token || token !== token.trim() || /\s/.test(token)) {
    return { ok: false, status: 401, error: 'bearer_required' };
  }
  return { ok: true, token };
}

function ticketFromRequest(url) {
  const params = url.searchParams;
  if (params.has('api_key')) {
    return { ok: false, status: 401, error: 'query_key_rejected' };
  }
  const ticket = params.get('ticket');
  if (typeof ticket !== 'string' || !ticket.startsWith('stk_')) {
    return { ok: false, status: 401, error: 'ticket_required' };
  }
  return { ok: true, ticket };
}

module.exports = { demoKeyAllowed, agentAuthFromRequest, ticketFromRequest };
