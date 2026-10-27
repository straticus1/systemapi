# SAH TAP — temporary access process, design

Status: proposal 2026-10-23, for review (Christian Schreiber). Not implemented.
Author: Claude. Reviewer: Codex (first pass), then Christian.

Threats: standing over-grants (access that outlives its need); a grant that
survives loss of the control plane; a replayed or forged grant; a grant that
fails open at expiry. Does NOT cover the per-session lease/ticket layer (already
time-bound) or identity/authn (device login + API keys, unchanged).

## Where we are

Time-bound already: leases are Ed25519-signed with a TTL (default 60s, hard cap
`MAX_TTL_S` = 300s), renewed every 30s, 30s skew. Tickets are single-use, 60s,
bound to one host and purpose. So a live *session* is inherently short.

NOT time-bound: channel *policies* (`cp_hosts.tcp_policy`/`file_policy` and the
tenant defaults) are standing JSONB. A grant from `channel-policy.js` /
`sahpolicy.py` persists until someone runs `clear`. No `valid_until`, no
auto-revoke. That is standing privilege — the gap TAP closes.

Precedent in-house: the vpscfgfarm door policies already expire and disarm on a
date. That is TAP at the fleet-door layer; SAH should mirror it at the platform
layer.

## What TAP adds

Time-boxed, auto-expiring policy grants (just-in-time access): "host H may
<grant> until T," after which the grant is gone with no human action.
Deny-by-default is unchanged; TAP only narrows the window of an allow.

## Two shapes (Christian's question: the root service governs it, or a separate
## sah-tap-service)

### Option A — a TTL on the grant, enforced by the control plane
- Add `expires_at` (plus `granted_by`, `reason`) per grant: either per-entry
  metadata in the policy JSONB, or a new `cp_grants` table keyed by
  host + channel + resource.
- `channel-policy.js` / `sahpolicy.py` gain `--until DURATION|TIMESTAMP`. A grant
  with no `--until` is allowed but flagged (see open questions).
- The control plane refuses to issue a ticket or lease for a grant whose
  `expires_at` has passed — checked at `ws-ticket` issue, the choke point that
  already exists (`tickets.js`/`authz.js`). A periodic sweep removes expired
  grants; every expiry is an audit-chain row.
- Pro: least new surface; reuses the policy path and the one enforcement point.
  Con: enforcement is control-plane-side. With the control plane down no new
  grant is issued (fail-closed holds). The 5-min lease cap only BOUNDS
  residual access; it does not enforce closure at the grant's expiry. See
  Revisions for how the deadline is clamped and enforced host-side.

### Option B — a separate sah-tap-service (dedicated daemon on the host)
- Mirrors the `sah-service` recovery-daemon pattern (`sah-os-management`): own
  systemd unit, own key, own scopes (`tap:*`), deny-by-default, strictly less
  capable than a shell.
- Holds grants locally and enforces expiry with a LOCAL timer that fails safe to
  closed even when the control plane is unreachable — the same mechanism the
  specced sshd break-glass already uses (enable, start timer, auto-disable at
  expiry regardless).
- Pro: expiry survives a control-plane outage; stronger isolation. Con: a second
  privileged surface and its own key provisioning; more to build and secure.

### Recommendation
- Build Option A first. Most "temporary access" is an operator grant checked at
  `ws-ticket` issue, and the control plane is its natural owner. Add
  `expires_at` + `--until` + sweep + audit, fail-closed at expiry.
- Fold the one case that MUST survive a control-plane outage — host-local
  break-glass, re-enabling sshd — into `sah-service` (Option B's local-timer
  pattern), which the design already specs. So the answer to "root service or a
  separate service" is: the control plane owns operator TAP (A); `sah-service`
  owns the outage-surviving host-local break-glass TAP (the recovery daemon).
  Not a third `sah-tap-service` — one fewer privileged surface.

## Security (SECURITY-RULES.md)
- No new secret: the signed artifact stays the Ed25519 `systemapi-lease-v1`
  lease; TAP only gates whether a lease is issued (rule 4).
- `expires_at` is a timestamp, not a secret; token/key compares stay
  constant-time (rule 2).
- Fail closed at expiry (rule 8): an expired or malformed `expires_at` denies;
  `sah-service`'s local timer closes the window even if nothing signals it.
- Every grant, use, and expiry is an audit-chain row; never log the actor key,
  only a SHA-256 fingerprint (rule 6).
- Negative tests (required, rule in "security-domain assets"): grant past
  expiry -> denied; clock-skew at the boundary; a host-A grant unusable on host
  B; a tampered `expires_at`; control-plane-down -> no new grant and the local
  timer still closes the window.

## Open for review
- Expiry granularity: whole policy vs per-resource grant.
- Default when `--until` is omitted: allow-with-flag now, deny later?
- A maximum TAP window (`MAX_GRANT_TTL`, analogous to `MAX_TTL_S`).


## Revisions after Codex review (2026-10-23)

Codex confirmed the shape (A owns authorization, sah-service owns host-local
break-glass, no third daemon) and found the expiry guarantee under-specified.
Folded in:

1. **Expiry is a clamped, host-enforced deadline, not the 300s cap.** The control
   plane clamps every issued AND renewed lease, and the signed session deadline,
   to `min(lease TTL, grant.expires_at)`; the agent enforces that hard deadline
   locally and ends the session at it. The 300s cap only bounds residual access.
   Timer behavior and clock-error tolerance are specified separately from the
   verifier's 30s skew.
2. **Re-check at every decision point, not just ws-ticket issue:** ticket
   consume/upgrade, initial lease issue, every lease renewal (TCP and file
   renewals already re-check policy -- extend that path), every mesh stream open,
   and the separate xfer HTTP grant route. Negative tests: a ticket issued before
   expiry but consumed after; authorization that lapses mid-async-lookup.
3. **Grant semantics pinned to prevent accidental widening.** A host policy of
   `null` inherits the tenant default; an empty policy denies. So an expired grant
   is NOT swept back to `null` (that could reveal a broader tenant allow) -- it
   resets to explicit-deny for that resource, or grants live in a `cp_grants`
   table that never mutates the base policy. Every temporary grant REQUIRES an
   expiry (the "omit and flag" option is dropped). Precedence, overlapping grants,
   revocation, tenant boundary, and principal-bound vs scope-bound are defined
   before build.
4. **The local timer is made durable and fail-safe.** sah-service arms the
   deadline BEFORE enabling the capability (arm-then-open, never the reverse),
   persists it, and on restart/reboot closes anything past deadline. Clock
   rollback handled (monotonic + wall, close on the earlier). Expiry terminates
   live sessions, not only new logins.
5. **Audit/transaction rules.** Keep the CLI's atomic policy-write-plus-audit.
   Grants carry id + version; concurrent revoke/renew defined; expiry audit
   idempotent; enforcement works with sweeper AND audit DB down, recording overdue
   expiry after recovery marked overdue, never backdated.

**Outage honesty (Codex's sharpest point).** Completing an already-authorized
break-glass window during an outage is NOT the same as INITIATING break-glass
during an outage. sah-service receives its grants THROUGH the control plane, so
it cannot start a new break-glass while the control plane is unreachable. That
needs a separately-designed offline authorization path (a pre-provisioned offline
grant token, or the provider console) -- a host daemon alone does not provide it.
This design no longer claims otherwise.
