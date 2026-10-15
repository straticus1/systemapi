// Threats: a viewer invoking exec, an unscored API key inheriting operator,
// and an OAuth session with no tenant listing every host. An API key with no
// scope rows has no scopes. SYSTEMAPI_REQUIRE_SCOPES=0 is the migration
// escape and grants operator, which includes exec:run and excludes
// breakglass:open, terminal:root, file:root and admin. Does NOT bind a
// session to a tenant by itself. admin implies every scope. terminal:root (a
// root shell) and file:root (file operations as root) are granted to admin
// only. tcp:open, file:read and file:write are operator scopes; the
// file:write purpose needs both file:read and file:write (channels.js).
// ticketScopesHeld re-checks a channel ticket's scopes at the WebSocket
// upgrade against the actor's CURRENT membership (and, for an API key, its
// current key scopes), so a role or key downgraded in the ticket's 60 s
// lifetime cannot open the channel; an API key must also still be active
// (not revoked, locked or expired). It does NOT re-read SSO groups: a group
// boost seen at ticket issue is kept for that one ticket.
'use strict';

const ALL = Object.freeze([
  'hosts:read',
  'hosts:write',
  'metrics:read',
  'exec:run',
  'terminal:open',
  'terminal:root',
  'breakglass:open',
  'tcp:open',
  'file:read',
  'file:write',
  'file:root',
  'alerts:write',
  'audit:read',
  'admin'
]);

const VIEWER = Object.freeze(['hosts:read', 'metrics:read', 'audit:read']);
const OPERATOR = Object.freeze([
  ...VIEWER,
  'exec:run',
  'terminal:open',
  'tcp:open',
  'file:read',
  'file:write',
  'alerts:write',
  'hosts:write'
]);

function scopesForRole(role) {
  if (role === 'admin') return new Set(ALL);
  if (role === 'operator') return new Set(OPERATOR);
  return new Set(VIEWER);
}

function hasScope(scopes, need) {
  if (!scopes) return false;
  if (scopes.has('admin')) return true;
  return scopes.has(need);
}

function roleFromGroups(groups) {
  if (!Array.isArray(groups) || groups.length === 0) return null;
  if (groups.includes('systemapi-admins')) return 'admin';
  if (groups.includes('systemapi-operators')) return 'operator';
  return 'viewer';
}

function scopesForKeyRows(rows, env) {
  if (!rows || rows.length === 0) {
    if (env && env.SYSTEMAPI_REQUIRE_SCOPES === '0') return scopesForRole('operator');
    return new Set();
  }
  return new Set(rows);
}

// The scopes an API key principal holds in a tenant: the key's scopes
// intersected with the member's role.
function intersectScopes(keyScopes, role) {
  const roleScopes = scopesForRole(role);
  if (keyScopes.has('admin') && roleScopes.has('admin')) return new Set(ALL);
  const left = keyScopes.has('admin') ? new Set(ALL) : keyScopes;
  const right = roleScopes.has('admin') ? new Set(ALL) : roleScopes;
  const out = new Set();
  for (const scope of left) if (right.has(scope)) out.add(scope);
  return out;
}

// row is a consumed ws-ticket row: { actor, tenantId, auth }, where auth is
// { kind: 'key'|'session', keyId, groupRole } captured at issue (absent on
// rows made outside the route, which are checked as sessions). Fails closed
// on any lookup error.
async function ticketScopesHeld(registry, row, needed) {
  if (!registry || !row || typeof row.actor !== 'string' || !Array.isArray(needed)) return false;
  try {
    const memberships = await registry.membershipsForUser(row.actor);
    const member = (memberships || []).find((m) => m.tenant_id === row.tenantId);
    if (!member) return false;
    const auth = row.auth || {};
    let scopes;
    if (auth.kind === 'key') {
      if (typeof auth.keyId !== 'string') return false;
      // A key revoked, locked or expired since the ticket was issued no
      // longer opens anything; a registry that cannot say is a refusal.
      if (typeof registry.keyActive !== 'function' || (await registry.keyActive(auth.keyId)) !== true) return false;
      scopes = intersectScopes(await registry.scopesForKey(auth.keyId), member.role);
    } else {
      scopes = scopesForRole(auth.groupRole || member.role);
    }
    return needed.every((scope) => hasScope(scopes, scope));
  } catch {
    return false;
  }
}

module.exports = {
  ALL,
  OPERATOR,
  scopesForRole,
  hasScope,
  roleFromGroups,
  scopesForKeyRows,
  intersectScopes,
  ticketScopesHeld
};
