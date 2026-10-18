# First-admin bootstrap

On a fresh database there is no credential that can create one. Members
appear only when an agent enrolls with an API key, and an API key can be
created only by a caller who is already authenticated.
`scripts/bootstrap-admin.js` breaks that loop once, on the server.

## Before the first boot

The app applies its whole schema at boot (`createRegistry`): first
`controlplane/schema.sql`, then `playground/playground_schema.sql` (the API key
tables), then `playground/playground_fleet_schema.sql`. All three are
idempotent. A failure is fatal in production. There is no manual `psql` step.

Applying the schema needs ownership. `CREATE INDEX IF NOT EXISTS`,
`CREATE OR REPLACE FUNCTION` and `DROP TRIGGER IF EXISTS` all need the
connecting role to own the object, even when it already exists. If an earlier
deploy created the playground tables as another role (for example `postgres`),
boot stops with `[control] boot failed: must be owner of table ...`. Check
before you deploy:

```sql
SELECT tablename, tableowner FROM pg_tables
 WHERE schemaname = 'public'
   AND (tablename LIKE 'playground_%' OR tablename IN ('anonymous_rate_limits', 'saved_requests'));
SELECT proname, pg_get_userbyid(proowner) FROM pg_proc
 WHERE proname IN ('playground_set_updated_at', 'reset_playground_credits', 'cleanup_old_playground_usage');
```

Every owner must be `DB_USER`. If one is not, have a superuser run
`ALTER TABLE <t> OWNER TO <DB_USER>;` (and `ALTER FUNCTION <f>() OWNER TO
<DB_USER>;`). The trigger function is `playground_set_updated_at()`.
Earlier versions created the generic `update_updated_at_column()`; the boot
now re-points both triggers to the namespaced function and leaves the old one
in place, because another application may own it. Drop it by hand only once
you know nothing else uses it.

## Lease signing key

Set `SYSTEMAPI_ED25519_SEED` in the production env file before the first boot:
64 hex characters, generated once and never changed.

```bash
openssl rand -hex 32   # paste into /etc/sahcore/sahcore.env as SYSTEMAPI_ED25519_SEED=
```

With `NODE_ENV=production` the server refuses to start (exit 1, before it
listens) when the seed is unset or not 64 hex characters:
`[control] SYSTEMAPI_ED25519_SEED is not set; production refuses an ephemeral
signing key ...; refusing to start`. An ephemeral key would change at every
restart, and every enrolled agent pins the first key it sees and exits with
`control_pubkey_changed` when it changes. A PEM key in
`SYSTEMAPI_SIGNING_KEY` is also accepted. Outside production the server keeps
an ephemeral key and logs `ephemeral signing key; set SYSTEMAPI_ED25519_SEED
to persist`. Treat the seed as a secret: it signs every lease. On miniapps1
it lives in `/etc/sahcore/sahcore.env` with the other secrets.

## Run it once

Run it on the server, as the sahcore service user, with the production env
file. It uses the same database settings as `server.js` and
`scripts/sso-bind.js`. The paths below are the miniapps1 layout
(`deploy/miniapps1` branch).

```bash
sudo -u sahcore env ENV_FILE=/etc/sahcore/sahcore.env \
  /opt/sahcore/node/bin/node /opt/sahcore/current/scripts/bootstrap-admin.js \
    --tenant <tenant> --member <member_user_id> \
    [--email <email>] [--sso-sub <authentik_sub>]
```

Without `ENV_FILE`, the script reads `.env.production` beside `server.js`.

Run it in an interactive terminal on the host, not through `vpsexec`. The
door's secret masker replaces the `api_key` value with `<masked>` before it
shows or journals output, so the key would be lost and you would need
`--force-additional` to mint another. The door's step files under `/run` on
the host would also hold the unmasked output until they are cleaned up.
`sso-bind.js` prints no secret, so it can still go through the door.

- `--tenant`: lowercase letters, digits and `-`, at most 63 characters. This
  is the rule an agent's `--tenant` must also meet. The tenant is created if
  it is missing.
- `--member`: the member id that owns the key and gets the `admin` role.
- `--sso-sub`: optional. The Authentik `sub` claim (provider `sub_mode` set to
  `hashed_user_id`). It is bound to the member in the same transaction, using
  the same registry code as `scripts/sso-bind.js`. With it, the admin can also
  use the dashboard and device login through SSO.
- `--key-name`: optional; the default is `bootstrap-admin`.
- `--force-additional`: see below.

On success it prints one JSON line to stdout:

```json
{"tenant_id":"acme","user_id":"ryan","key_id":"ak_live_…","sso_bound":true,"forced":false,"api_key":"ak_live_….…"}
```

`api_key` is shown once. It is not logged, not written to any file, and the
database stores only its bcrypt hash. Store it in the secret store now. Do not
redirect stdout to a file on the server.

One transaction writes all of the following. If any part fails, none of it is
written:

| Row | Value |
|---|---|
| `cp_tenants` | the tenant (if it is new), owner = the member |
| `cp_members` | `(tenant, member, role 'admin')` |
| `playground_api_keys` | the key, through `AuthManager.insertAPIKey` (the same generator, prefix and bcrypt cost as `POST /playground/api-keys`), `api_site 'systemapi'` |
| `cp_api_scopes` | `(key_id, 'admin')` |
| `cp_audit` | actor `bootstrap:admin`, action `bootstrap_admin`, the key as a SHA-256 fingerprint, `forced` |
| `cp_audit` | with `--sso-sub`: action `sso_bind`, the sub as a fingerprint |

The router expects exactly this state. An API key principal's scopes are the
key's scopes intersected with the member's role, and `admin` with `admin`
grants everything. So the key passes `requireScope(..., 'admin')` on
`POST /api/v1/tenants/:tenant/members`, `PUT /api/v1/tenants/:tenant/members/:user/sso`,
`POST /api/v1/keys/:keyId/scopes` and the webhook routes. It also passes the
playground key routes (`/playground/api-keys`), and an agent can enroll into
the tenant with it.

## Refusal and `--force-additional`

The script refuses (`bootstrap-admin failed: admin_exists`, exit 1, nothing
written, nothing printed on stdout) while any `admin` member or any
`admin`-scoped key exists. An advisory lock serializes two runs against an
empty database. `--force-additional` mints another admin key anyway. Its audit
row records `forced: true` and how many admin members and keys already
existed. Use it only for recovery. The normal way to add an admin is through
the API, with an admin credential.

## Afterwards

1. Add named admins (`POST /api/v1/tenants/:tenant/members`) and bind their
   SSO subs (`PUT /api/v1/tenants/:tenant/members/:user/sso`).
2. Create agent keys (`POST /playground/api-keys`) and give each one only the
   scopes it needs (`POST /api/v1/keys/:keyId/scopes`).
3. Revoke the bootstrap key (`DELETE /playground/api-keys/:keyId`, called with
   that key). It does not expire on its own.

## Agent flags: accounts, notice and watching

Set these on each host's `systemapi-agent` once the first admin exists.

- `--pty-user-map <file>`: one Unix account per identity for `terminal:open`,
  `file:read`/`file:write` and `xfer:put`/`xfer:get`. Each line is
  `identity = unixuser`, where the identity is the actor the server sends
  (the member's user id); `#` starts a comment. The file must be a regular
  file, mode `0600` or stricter, owned by root or by the agent user. The
  agent refuses to start when a line uses `*`, repeats an identity, maps to
  `root`, or maps two identities to one account. With a map, an identity
  that has no line is refused with `account_unmapped`, and `--pty-user` is
  ignored. Create the accounts first (`useradd --create-home sah_alice`); a
  mapped account that does not exist refuses that session.

  ```
  # /etc/systemapi/pty-users  (root:root 0600)
  17 = sah_alice
  23 = sah_bob
  ```

- `--pty-user <name>`: the old single account. Without a map it still works
  for every identity, and the agent logs at startup that it maps all
  identities to one account: people sharing it can signal, ptrace (with
  `kernel.yama.ptrace_scope` 0) and plant profile files for each other.
- `--pty-notice <file>`: the monitoring notice every terminal session shows
  before the shell accepts input. The default is "This session is recorded
  and may be viewed by an administrator."; the agent always appends
  `Tenant: <--tenant>`. The file must be owned by root or the agent user and
  not group or other writable. An empty file is refused at startup: the
  notice can be reworded, never turned off.

See `docs/sahconnect-terminal-protocol.md` §6 and §7.

## Tests

`npm test` runs `tests/bootstrap.test.js` (the registry transaction on a
recording client) and `tests/schema.test.js`. The end-to-end test runs against
a real PostgreSQL and needs a role that may `CREATE DATABASE`:

```bash
SYSTEMAPI_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres \
  node --test tests/bootstrap-pg.test.js
```
