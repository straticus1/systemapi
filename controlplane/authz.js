// Threats: a viewer invoking exec, an unscored API key inheriting operator,
// and an OAuth session with no tenant listing every host. An API key with no
// scope rows has no scopes. SYSTEMAPI_REQUIRE_SCOPES=0 is the migration
// escape and grants operator, which includes exec:run and excludes
// breakglass:open and admin. Does NOT bind a session to a tenant by itself.
// admin implies every scope.
'use strict';

const ALL = Object.freeze([
  'hosts:read',
  'hosts:write',
  'metrics:read',
  'exec:run',
  'terminal:open',
  'breakglass:open',
  'alerts:write',
  'audit:read',
  'admin'
]);

const VIEWER = Object.freeze(['hosts:read', 'metrics:read', 'audit:read']);
const OPERATOR = Object.freeze([...VIEWER, 'exec:run', 'terminal:open', 'alerts:write', 'hosts:write']);

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

module.exports = {
  ALL,
  VIEWER,
  OPERATOR,
  scopesForRole,
  hasScope,
  roleFromGroups,
  scopesForKeyRows
};
