-- Control-plane tables. CREATE IF NOT EXISTS only. No drops, except the guarded
-- swap of the cp_sysscript_jobs source CHECK at the end of the file.
-- Threats: tenant isolation and audit integrity live in the application
-- queries (parameterized, tenant predicate). This file does not grant roles.

-- This file is sent as one simple query, which Postgres runs as one implicit
-- transaction. Two of them at once would each take a share lock (CREATE INDEX
-- IF NOT EXISTS) and then need an exclusive one (ALTER TABLE) on one table,
-- and deadlock. createRegistry runs it under the session-level boot lock
-- (two-int form: namespace 'SAPI' = 1396789321, key 2); this transaction
-- lock on the same key covers any other caller of the file.
SELECT pg_advisory_xact_lock(1396789321, 2);

CREATE TABLE IF NOT EXISTS cp_tenants (
  tenant_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_members (
  tenant_id TEXT NOT NULL REFERENCES cp_tenants(tenant_id),
  user_id TEXT NOT NULL,
  email TEXT,
  role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS cp_members_user_idx ON cp_members (user_id);

-- SSO identity is the Authentik sub only (provider sub_mode hashed_user_id:
-- stable, opaque, not reassigned on an email or username change). NULL means
-- the membership cannot be used through SSO until an admin binds it. The
-- binding is per membership row, so a tenant admin can only bind rows of that
-- tenant; a device login needs every row of the member bound to the same sub.
-- Unique per tenant here; the application also refuses one sub on two member
-- ids anywhere and two different subs on one member id (bind holds an
-- advisory lock; changing a member's sub means unbinding every row first),
-- and the reader fails closed if it ever finds one sub on two member ids.
ALTER TABLE cp_members ADD COLUMN IF NOT EXISTS sso_sub TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS cp_members_tenant_sso_sub_idx ON cp_members (tenant_id, sso_sub) WHERE sso_sub IS NOT NULL;
CREATE INDEX IF NOT EXISTS cp_members_sso_sub_idx ON cp_members (sso_sub) WHERE sso_sub IS NOT NULL;

CREATE TABLE IF NOT EXISTS cp_hosts (
  host_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES cp_tenants(tenant_id),
  key_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  os TEXT,
  platform TEXT,
  ssh_pubkey TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'offline',
  last_seen_at TIMESTAMPTZ,
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cp_hosts_tenant_idx ON cp_hosts (tenant_id);
CREATE INDEX IF NOT EXISTS cp_hosts_tenant_hostname_idx ON cp_hosts (tenant_id, lower(hostname));

-- SAH channel policies (docs/sah-tcp-protocol.md §4, docs/sah-file-protocol.md
-- §2). NULL on the host means "use the tenant default"; NULL on the tenant
-- means deny-all ({"allow":[]} / {"roots":[]}). A host value replaces the
-- tenant value, it is never merged. The application validates the shape on
-- write and treats a malformed stored value as deny-all.
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS tcp_policy JSONB;
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS file_policy JSONB;
ALTER TABLE cp_tenants ADD COLUMN IF NOT EXISTS tcp_policy JSONB;
ALTER TABLE cp_tenants ADD COLUMN IF NOT EXISTS file_policy JSONB;

-- Host retirement (POST /api/v1/hosts/:host_id/retire). A retired row is
-- kept for audit but never resolves, is left out of the fleet listing by
-- default and of channel policy lookups, and its host_id cannot re-enroll.
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS cp_telemetry (
  id BIGSERIAL PRIMARY KEY,
  host_id TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  metric TEXT NOT NULL,
  value DOUBLE PRECISION NOT NULL,
  labels JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS cp_telemetry_host_metric_ts ON cp_telemetry (host_id, metric, ts DESC);

CREATE TABLE IF NOT EXISTS cp_audit (
  seq BIGSERIAL PRIMARY KEY,
  prev_hash TEXT NOT NULL,
  row_hash TEXT NOT NULL,
  tenant_id TEXT,
  host_id TEXT,
  actor TEXT,
  action TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_api_scopes (
  key_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  PRIMARY KEY (key_id, scope)
);

CREATE TABLE IF NOT EXISTS cp_alert_events (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  metric TEXT,
  value DOUBLE PRECISION,
  status TEXT NOT NULL CHECK (status IN ('open', 'ack', 'resolved')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cp_alert_events_host_idx ON cp_alert_events (host_id, rule_name, created_at DESC);
-- sys.alerts.push from a script run (rule_name 'sysscript'): severity is
-- info, warning or critical; message is at most 4096 bytes (playground/fleet.js).
ALTER TABLE cp_alert_events ADD COLUMN IF NOT EXISTS severity TEXT;
ALTER TABLE cp_alert_events ADD COLUMN IF NOT EXISTS message TEXT;

CREATE TABLE IF NOT EXISTS cp_webhooks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  secret_fingerprint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_schedules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  cron TEXT NOT NULL,
  script TEXT NOT NULL,
  last_run_minute TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_security_events (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT,
  kind TEXT NOT NULL,
  actor_fingerprint TEXT,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_comments (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  author TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_software (
  host_id TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  architecture TEXT,
  last_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, name, version)
);

CREATE TABLE IF NOT EXISTS cp_cves (
  host_id TEXT NOT NULL,
  software_name TEXT NOT NULL,
  software_version TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  severity TEXT,
  description TEXT,
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, software_name, software_version, cve_id)
);

CREATE TABLE IF NOT EXISTS cp_oauth_devices (
  device_hash TEXT PRIMARY KEY,
  user_code_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
  expires_at TIMESTAMPTZ NOT NULL,
  poll_after TIMESTAMPTZ NOT NULL,
  provider TEXT,
  state_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE cp_oauth_devices ADD COLUMN IF NOT EXISTS requester_ip TEXT;
ALTER TABLE cp_oauth_devices ADD COLUMN IF NOT EXISTS requester_ua TEXT;
CREATE INDEX IF NOT EXISTS cp_oauth_devices_user_idx ON cp_oauth_devices (user_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS cp_oauth_devices_state_idx ON cp_oauth_devices (state_hash) WHERE state_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS cp_oauth_access (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_oauth_links (
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('google', 'github')),
  subject TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, provider)
);

-- Async sysscript jobs (playground/fleet.js, controlplane/router.js
-- /api/v1/jobs). The script is held in dispatch only until it is sent, then
-- only its hash remains. Output is nulled after
-- SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS; terminal rows are deleted after
-- SYSTEMAPI_JOB_RETENTION_DAYS. Reads always carry a tenant predicate; agent
-- frames are matched on host_id (and conn_id where it applies) in the WHERE.
-- Writes NOTIFY cp_sysscript_jobs inside their transaction.
CREATE TABLE IF NOT EXISTS cp_sysscript_jobs (
  job_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('api', 'execute', 'fleet_execute', 'playbook', 'schedule', 'rule')),
  script_sha256 TEXT NOT NULL,
  entitlements_sha256 TEXT NOT NULL,
  entitlements JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL CHECK (status IN ('submitted', 'accepted', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out')),
  error TEXT,
  output TEXT,
  output_truncated BOOLEAN NOT NULL DEFAULT false,
  output_expired BOOLEAN NOT NULL DEFAULT false,
  timeout_s INTEGER NOT NULL CHECK (timeout_s BETWEEN 1 AND 3600),
  deadline_at TIMESTAMPTZ NOT NULL,
  lease_nonce TEXT NOT NULL,
  dispatch JSONB,
  conn_id TEXT,
  sent_at TIMESTAMPTZ,
  alert_count INTEGER NOT NULL DEFAULT 0,
  cancel_requested_at TIMESTAMPTZ,
  cancel_sent_at TIMESTAMPTZ,
  cancel_actor TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  accepted_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS cp_sysscript_jobs_tenant_created_idx ON cp_sysscript_jobs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS cp_sysscript_jobs_host_active_idx ON cp_sysscript_jobs (host_id)
  WHERE status IN ('submitted', 'accepted', 'running');
CREATE INDEX IF NOT EXISTS cp_sysscript_jobs_output_idx ON cp_sysscript_jobs (finished_at)
  WHERE output IS NOT NULL;

-- Which instance holds a host's agent socket and the capabilities that agent
-- advertised (written on enroll, cleared on close). Used for the online and
-- capability check at job submit across replicas; a crashed instance can
-- leave a stale value, overwritten on the next enroll.
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS agent_caps TEXT[];
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS agent_instance TEXT;
-- The live agent socket's conn_id and enroll time: a presence write from an
-- older enroll never overwrites a newer one, and a close clears only its own.
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS agent_conn_id TEXT;
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS agent_enrolled_at TIMESTAMPTZ;
-- When the instance holding the socket last wrote its presence (enroll and
-- every 30 s tick). Older than 90 s, a remote presence is treated as stale:
-- the legacy callers do not send a job to it.
ALTER TABLE cp_hosts ADD COLUMN IF NOT EXISTS agent_seen_at TIMESTAMPTZ;

-- Declarative convergence and drift (.omc/plans/convergence-drift.md §8.1).
-- Versions are immutable: the registry has no UPDATE path for them. Every
-- read and user write carries a tenant predicate; cp_host_state is
-- server-authoritative and written only in the transaction of the event that
-- changes it (assignment and tag changes, enroll, retire, a job's terminal
-- transition), conditional on check_job_id / last_apply_run_id so a late
-- result never overwrites a newer run. facts holds {key: {status, digest}},
-- never content. Desired file content in cp_state_versions.files is stored
-- in plaintext (a user risk acceptance, plan §3.1).
CREATE TABLE IF NOT EXISTS cp_states (
  state_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES cp_tenants(tenant_id),
  name TEXT NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
  description TEXT,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  archived_at TIMESTAMPTZ,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS cp_state_versions (
  version_id TEXT PRIMARY KEY,
  state_id TEXT NOT NULL REFERENCES cp_states(state_id),
  tenant_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  files JSONB NOT NULL,
  files_sha256 TEXT NOT NULL,
  entitlements JSONB NOT NULL,
  entitlements_sha256 TEXT NOT NULL,
  published_by TEXT NOT NULL,
  notes TEXT,
  published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (state_id, version)
);

-- Tag and tenant targets always require approval; auto_remediate only on a
-- host target without require_approval (plan §6.2). The registry refuses
-- both first (400 auto_remediate_host_only); the CHECKs are the backstop.
CREATE TABLE IF NOT EXISTS cp_state_assignments (
  assignment_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  state_id TEXT NOT NULL REFERENCES cp_states(state_id),
  version_id TEXT NOT NULL REFERENCES cp_state_versions(version_id),
  target_kind TEXT NOT NULL CHECK (target_kind IN ('host', 'tag', 'tenant')),
  target_value TEXT NOT NULL,
  vars JSONB NOT NULL DEFAULT '{}'::jsonb,
  check_interval_s INTEGER NOT NULL DEFAULT 3600 CHECK (check_interval_s = 0 OR check_interval_s BETWEEN 300 AND 86400),
  drift_threshold INTEGER NOT NULL DEFAULT 1 CHECK (drift_threshold BETWEEN 1 AND 10),
  auto_remediate BOOLEAN NOT NULL DEFAULT false,
  require_approval BOOLEAN NOT NULL DEFAULT false,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT cp_state_assignments_approval_check CHECK (target_kind = 'host' OR require_approval),
  CONSTRAINT cp_state_assignments_auto_check CHECK (NOT auto_remediate OR (target_kind = 'host' AND NOT require_approval)),
  UNIQUE (tenant_id, state_id, target_kind, target_value)
);

CREATE TABLE IF NOT EXISTS cp_host_state (
  host_id TEXT NOT NULL,
  state_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  assignment_id TEXT,
  version_id TEXT,
  status TEXT NOT NULL DEFAULT 'unknown'
    CHECK (status IN ('unknown', 'compliant', 'drifted', 'failed', 'partial', 'conflict', 'stale')),
  facts JSONB NOT NULL DEFAULT '{}'::jsonb,
  consecutive_drift INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  last_check_run_id TEXT,
  last_check_at TIMESTAMPTZ,
  last_apply_run_id TEXT,
  last_applied_version_id TEXT,
  last_applied_at TIMESTAMPTZ,
  manual_apply_assignment_id TEXT,
  manual_apply_version_id TEXT,
  auto_apply_failures INTEGER NOT NULL DEFAULT 0,
  last_report_sha256 TEXT,
  next_check_at TIMESTAMPTZ,
  check_claimed_at TIMESTAMPTZ,
  check_job_id TEXT,
  PRIMARY KEY (host_id, state_id)
);
CREATE INDEX IF NOT EXISTS cp_host_state_due_idx ON cp_host_state (next_check_at) WHERE next_check_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS cp_host_state_tenant_idx ON cp_host_state (tenant_id, status);

-- One row per converge job (run_id = cp_sysscript_jobs.job_id). Check runs
-- are deleted with their job row; plan and apply runs are kept
-- SYSTEMAPI_APPLY_RUN_RETENTION_DAYS (365) with report nulled after the
-- output retention (report_expired). bundle_json is kept on a plan run only
-- until it is consumed or older than the plan max age.
CREATE TABLE IF NOT EXISTS cp_converge_runs (
  run_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  state_id TEXT NOT NULL,
  assignment_id TEXT NOT NULL,
  version_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('check', 'plan', 'apply')),
  actor TEXT NOT NULL,
  plan_run_id TEXT,
  parent_job_id TEXT,
  bundle_json TEXT,
  plan_sha256 TEXT,
  plan_truncated BOOLEAN NOT NULL DEFAULT false,
  report_sha256 TEXT,
  summary JSONB,
  report JSONB,
  report_expired BOOLEAN NOT NULL DEFAULT false,
  approved_by TEXT,
  approved_at TIMESTAMPTZ,
  consumed_by_run_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS cp_converge_runs_host_idx ON cp_converge_runs (tenant_id, host_id, created_at DESC);

-- At most one active (open or ack) drift alert per host and state, across
-- replicas: the ingest inserts with ON CONFLICT ... DO NOTHING on this index.
CREATE UNIQUE INDEX IF NOT EXISTS cp_alert_events_active_drift_idx ON cp_alert_events (host_id, rule_name)
  WHERE status IN ('open', 'ack') AND rule_name LIKE 'drift:%';

-- The job source CHECK gains the converge sources. Every replica runs this
-- file at boot under the boot lock (taken again here, a no-op for the same
-- session), and the swap runs only while the v2 constraint is absent. NOT
-- VALID then VALIDATE in one transaction is no cheaper than a plain ADD
-- CONSTRAINT: the ALTER's ACCESS EXCLUSIVE lock is held to the end of the
-- transaction while VALIDATE scans the existing rows once. That scan is
-- bounded by the job retention, and it runs once per database.
DO $$ BEGIN
  PERFORM pg_advisory_xact_lock(1396789321, 2);
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'cp_sysscript_jobs_source_check_v2') THEN
    ALTER TABLE cp_sysscript_jobs DROP CONSTRAINT IF EXISTS cp_sysscript_jobs_source_check;
    ALTER TABLE cp_sysscript_jobs ADD CONSTRAINT cp_sysscript_jobs_source_check_v2
      CHECK (source IN ('api', 'execute', 'fleet_execute', 'playbook', 'schedule', 'rule',
                        'converge_check', 'converge_plan', 'converge_apply')) NOT VALID;
    ALTER TABLE cp_sysscript_jobs VALIDATE CONSTRAINT cp_sysscript_jobs_source_check_v2;
  END IF;
END $$;
