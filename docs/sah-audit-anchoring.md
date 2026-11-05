# Audit chain anchoring (option 2A)

The control plane signs the head of the audit chain at a fixed interval and
writes it to one or two write-once S3-compatible buckets. A verifier that runs
on another host compares those signed heads with the rows. Code:
`controlplane/anchor.js`, `scripts/audit-anchor-verify.js`,
`scripts/audit-checkpoint-pubkey.js`. Background:
`.omc/research/sah-next-gen.md`, Direction 2.

## Threat

`cp_audit` is a hash chain (`controlplane/chain.js`). It catches one edited
row. It does not catch someone with database write access (a stolen
`DB_PASSWORD`, SQL injection, a bad backup restore) who rewrites every row
from seq k on, or deletes the tail, and then recomputes the hashes. After that,
`/api/v1/audit/verify` still returns `ok`. Anchoring keeps a copy of the head
where a database attacker cannot change it, and has a second host check it.

## What runs

- **Key.** `SYSTEMAPI_AUDIT_CHECKPOINT_SEED` is a 64-hex Ed25519 seed.
  Generate it once with `openssl rand -hex 32` and keep it in the env file. It
  is separate from the lease key, so leaking one does not give you the other.
  Root on the control-plane host can read it, the same as the lease seed and
  `DB_PASSWORD`.
  Anchoring refuses to start (`anchor_seed_reuses_lease_key`) when this key
  matches the lease key, whether that key is set as `SYSTEMAPI_ED25519_SEED`,
  as `SYSTEMAPI_SIGNING_KEY`, or is the running signer.
- **When.** The existing 30 s control tick writes a checkpoint once the last
  one is `SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S` old (default 3600, allowed
  300 to 86400). A break-glass terminal start (`terminal_start` with purpose
  `breakglass:open`) gets a checkpoint right away. There is no `recovery_sshd`
  action yet. When one exists, add it to `isTrigger`. Replicas that share the
  database write one checkpoint per interval between them, because the "due?"
  check and the insert happen under the chain lock. A forced checkpoint is
  always written, one second after the last if it falls in the same second.
  If the last checkpoint's time is more than 600 s ahead of the clock (a
  clock that was wrong), the log says `[anchor] last_checkpoint_in_future`
  and a checkpoint is written now. Its time is one second past the newest
  sane note, so every object key stays unique. The verifier will flag the
  future note (`anchor_time_mismatch`, and possibly `anchor_seq_regression`);
  ack it after review.
- **What.** Under the chain-wide advisory lock, the control plane reads
  `max(seq)` and its `row_hash` (seq 0 and the genesis hash if the chain is
  empty) and signs a C2SP signed note:

  ```
  systemapi.io/audit/<deployment>
  <max_seq>
  <base64 of the 32 row_hash bytes>
  chain sha256-linear-v2
  time <unix seconds>

  — systemapi.io/audit/<deployment> <base64(key hash || signature)>
  ```

  The `chain sha256-linear-v2` line tells a human reader that the hash is the
  head of a linear chain, not a Merkle root. C2SP allows extension lines, so
  a tlog tool may still parse the note as a checkpoint. What keeps it apart
  is the dedicated key and origin. A later public log or Merkle log (options
  2B and 2C) must use a different origin and a different key.
  `SYSTEMAPI_AUDIT_DEPLOYMENT` is 1 to 63 characters from `a-z`,
  `0-9` and `-`, and does not start or end with `-`.
- **Where.** The note goes into `cp_audit_checkpoints` with its seq, head,
  time and per-sink status. Then, after COMMIT and outside the lock, it is
  PUT to every configured sink at
  `checkpoints/<deployment>/<seq, 19 digits>-<unix time>.note`. Each sink is
  written on its own. A failed sink is recorded as `put_failed` and logged as
  `[anchor] sinkN put failed: <error name>`. It does not block the other sink
  or the chain. On the following ticks the stored note is PUT again under the
  same key to each sink whose put failed (or, after 60 s, never recorded an
  outcome). Retries stop 540 s after the note time, inside the verifier's
  600 s LastModified skew, so a late put never looks backdated. A put still
  missing after that is one missed checkpoint for that sink. The verifier's
  gap rule (2x the cadence plus 300 s) allows for one missed checkpoint, and
  `anchor_sink_mismatch` reports it.
- **Off unless configured.** With no anchoring variables set, the log says
  `[anchor] off`. If any of them is set, all of them must be valid. Otherwise
  anchoring stays off and boot logs exactly one line,
  `[anchor] off: <code>`. Under `NODE_ENV=production` the same code is thrown
  instead and boot stops, failing closed as `keys.js` does for an ephemeral
  lease key. The codes are `anchor_seed_missing`,
  `anchor_seed_invalid`, `anchor_deployment_invalid`,
  `anchor_interval_invalid`, `anchor_sink_invalid`, `anchor_sink_missing` and
  `anchor_seed_reuses_lease_key` (plus `registry_unavailable`). Outside
  production, boot continues. While anchoring is off, no new anchors appear, and the verifier reports that as
  `anchor_gap`. The seed and the sink secrets are never logged. The "on" line
  logs only the SHA-256 fingerprint of the public key.

### Cadence decision: a checkpoint every interval, head changed or not

A checkpoint is written every interval even when the head has not moved. The
two notes then share a seq but have different times, and each gets its own
object key. Reasons:

- The verifier's suppression rule stays simple. Consecutive anchors in a sink
  must be at most 2x the cadence plus 300 s apart, and the newest must be no
  older than that. The 300 s covers the 30 s tick, which writes once
  `now - last >= cadence`, so one missed checkpoint leaves notes slightly
  more than 2x the cadence apart. A quiet chain and stopped anchoring do not look the same.
- Because notes do not depend on activity, a reader of the bucket cannot tell
  quiet hours from busy ones. The only timing leak left is the extra
  checkpoint at each break-glass start, which is accepted.
- Cost: 24 small objects a day per sink.

## Sinks

Each sink takes five variables: `SYSTEMAPI_ANCHOR_SINK1_ENDPOINT`, `_BUCKET`,
`_REGION`, `_ACCESS_KEY_ID` and `_SECRET_ACCESS_KEY`. `SINK2_*` takes the same
five. Set all five for a sink or none of them. Sink 2 requires sink 1. The two
sinks cannot be the same endpoint and bucket. The endpoint must be `https://`.
Plain `http://` is accepted only for 127.0.0.1, localhost and [::1]. The
plan is DarkStorage (the `systemapi-audits` provider) as sink 1, and
Cloudflare R2 as sink 2, the mirror.

The client uses plain `PutObject`, `ListObjectsV2` and `GetObject`, with
path-style URLs. It does not send Object Lock or retention headers on
requests. Retention must be the bucket default, and R2 does not accept those
headers. It sends `Content-MD5` because S3 refuses uploads to a bucket with
default retention when no integrity header is present. Checksums are added
only when an operation requires one.

What must be true of the bucket before you rely on it:

- **Object Lock in compliance mode** with a default retention period (years),
  and versioning on. The control plane's credential may have `s3:PutObject`
  on `checkpoints/<deployment>/*` only. It must not have delete, version
  delete, `s3:BypassGovernanceRetention`, retention or lock-configuration
  rights, or bucket-policy rights. The verifier gets a separate credential
  with `ListBucket` and `GetObject` only.
- **DarkStorage:** nothing in this repo says whether it supports Object Lock.
  The existing writer in `playground/fleet.js` uses a MinIO-style endpoint.
  MinIO supports compliance mode only on buckets created with locking
  enabled. Before you rely on DarkStorage, check on the actual bucket that
  locking is on in COMPLIANCE mode and that the credential cannot delete an
  object version. Until that is confirmed, treat sink 1 as unverified.
- **R2:** bucket lock rules can be removed by anyone holding the Cloudflare
  account token, and the docs describe no compliance mode. R2 is a mirror,
  not the root of trust.

## The verifier

Run it from cron on a host that is not the control plane, for example a CI
job or another fleet host. It needs no write access anywhere.

Run `scripts/audit-checkpoint-pubkey.js` once on the control plane and pin the
vkey line it prints in the verifier's own config, for example a CI secret or
a file under change review. Do not fetch it from the control plane on each
run, because a compromised host could hand over a new key.

```bash
node scripts/audit-checkpoint-pubkey.js        # on the control plane: prints the vkey line only
SYSTEMAPI_ANCHOR_VKEY='<vkey line>' \
SYSTEMAPI_ANCHOR_SINK1_...=<read-only creds> SYSTEMAPI_ANCHOR_SINK2_...=<read-only creds> \
SYSTEMAPI_ANCHOR_VERIFY_DATABASE_URL='postgres://audit_ro@...?sslmode=verify-full' \
  node scripts/audit-anchor-verify.js [--sink sink1|sink2|all] [--cadence-s 3600] \
    [--since <unix>] [--ack reviewed-acks.json]
```

The database connection gives up after 15 s, and the query after 120 s.

Rows come from one of two sources:

- **A read-only database role** (`SYSTEMAPI_ANCHOR_VERIFY_DATABASE_URL`, read
  from the environment so it never appears on argv). The connection also sets
  `default_transaction_read_only`. Grant the role `SELECT` on `cp_audit`
  only. This is the default for a live check.
- **A JSON export** (`--export file.json`, plus `--now <export time>`), for a
  verifier that holds no database credential at all, or for checking a
  restored backup before it takes traffic. Produce it with:

  ```bash
  psql "$URL" -Atc "SELECT coalesce(json_agg(a ORDER BY seq), '[]') FROM
    (SELECT seq, prev_hash, row_hash, tenant_id, host_id, actor, action, payload FROM cp_audit) a" > audit.json
  ```

  The export's rows do not need to be trusted, because a forged or stale
  export still has to match every anchored head. The run is only as honest as
  the `--now` the operator passes. Notes after `--now` are not judged, so a
  `--now` that is too early hides the newest anchors.

The verifier lists and checks the notes first and reads the rows second. That
way a checkpoint written during the run can never name a row the read missed.
It recomputes the chain with `verifyRows`, applying `KNOWN_FORKS` and
`SYSTEMAPI_AUDIT_LEGACY_MAX_SEQ`, and gets the head at every anchored seq in
the same pass (`heads_at`).

Exit codes: 0 means clean. 1 means one or more of the codes below; it prints
one JSON line `{ok, max_seq, anchors, reasons, acked, acked_reasons}`. 2
means a usage or operational failure (`usage`, `vkey_invalid`,
`sink_config_invalid`, `sink_unavailable`, `sink_list_too_large` (more than
200,000 objects listed), `db_unavailable`, `export_invalid`, `ack_invalid`),
printed to stderr as the code alone. **Exit 2 must page just like exit 1.** A
verifier that cannot read the sinks or the rows checks nothing, and an
attacker can cause exactly that.

**Acks and cut-offs.** WORM objects cannot be deleted, so a bad note from a
past incident would raise the same alarm on every run and bury new ones.
`--ack FILE` takes a reviewed JSON list that is kept off-box, for example in
the verifier's repo:

```json
[{ "code": "anchor_time_mismatch", "sink": "sink1", "seq": 1042, "why": "clock step 2026-11-05, INC-12" }]
```

Each entry names a code, the sink (or `null` for `chain_broken` and seq
mismatches), exactly one of `seq` or `key`, and a non-empty `why`. A matching
reason is still listed under `acked_reasons` but does not fail the run.
`--since <unix>` skips fetching and judging notes signed before the cut-off,
and the gap rule then starts from it. Use it to drop history once an
incident is closed, or to keep the per-run GET count bounded.

| Code | Meaning |
| --- | --- |
| `chain_broken` | The rows do not verify on their own. |
| `anchor_rewrite` | The head at an anchored seq differs, or that row is gone (rewrite). At or after a `chain_broken` seq, the anchored head is compared with the stored `row_hash`. |
| `anchor_truncation` | An anchored seq is greater than the current `max(seq)`. |
| `anchor_gap` | A sink has no anchor for more than 2x the cadence plus 300 s, its newest anchor is older than that, or it has none at all (suppression). |
| `anchor_seq_regression` | A later anchor names a lower seq than an earlier one. |
| `anchor_bad_signature` | A note is not signed by this key (tampered, or signed by another key). |
| `anchor_note_invalid` | A note is unparseable, garbage, over 4 KiB, or listed without a `LastModified`, or its object key does not match its seq and time. |
| `anchor_time_mismatch` | A note's signed time is more than 600 s from the sink's `LastModified` (a backdated backfill). |
| `anchor_sink_mismatch` | Two sinks, or two notes, hold different heads for the same seq. Or, with both sinks read, a key more than 600 s old is in one sink and missing from the other. |

`--cadence-s` must match the control plane's interval, so the gap rule the
verifier applies is the same one the writer follows.

## What it does NOT do

- **It does not prevent anything.** It detects a rewrite, truncation or
  stopped anchoring the next time the verifier runs, and only if someone acts
  on a non-zero exit.
- **`created_at` is not in the v2 row hash.** Anchoring proves a row existed by
  the time of the next anchor. It does not stop someone editing a row's own
  timestamp. A v3 row hash that covers `created_at` would fix that.
- **Rows after the newest anchor** are checked only as a chain until the next
  checkpoint covers them.
- **Timing leak.** Notes sit at a fixed cadence, but every break-glass start
  adds one, so a bucket reader can see when break-glass was used. Each note
  also shows the total event count (`max(seq)`).
- **Seed theft plus bucket rights.** Someone with the checkpoint seed can sign
  any note. They can add notes, but existing objects in a compliance-mode
  bucket stay, so old heads still expose a rewrite, and a backdated note
  shows up as `anchor_time_mismatch`. If that attacker also has delete or
  retention-bypass rights on every sink, the anchors give no protection.
- **No public log or witness.** That is option 2B (Sigsum) or 2C (Tessera).
- **Without `--since`, the verifier reads every note on every run.** That is
  about 9k GETs per sink per year at hourly cadence.
