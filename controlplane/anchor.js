// Threats: a database writer who rewrites the audit chain from some seq on, or
// truncates its tail, and re-chains it so /api/v1/audit/verify says ok. Every
// interval (and right after a break-glass terminal start) the control plane
// signs the chain head, max(seq) and its row_hash read under the chain lock,
// as a C2SP signed note with its own Ed25519 key
// (SYSTEMAPI_AUDIT_CHECKPOINT_SEED, refused when it is the lease key), and
// PUTs it to one or two S3-compatible sinks that must be WORM (Object Lock in
// compliance mode, a PutObject-only credential). An off-box verifier
// (scripts/audit-anchor-verify.js) holding only the public key compares the
// anchors with the rows. The extension line "chain sha256-linear-v2" tells a
// human reader the hash is a linear chain head, not a Merkle root; C2SP
// allows extension lines, so a tlog tool may still parse the note. What keeps
// it apart from any tlog checkpoint is the dedicated key and origin (a later
// Sigsum or Tessera log, 2B/2C, must use another origin and another key).
// Anchoring is off unless seed, deployment and a sink are all set and valid;
// a bad value turns it off with a fixed reason code (in production it stops
// boot) and never prints the seed or a credential. A failed sink write is
// recorded per sink, retried under the same key for RETRY_WINDOW_S, and never
// blocks the other sink or the chain. Does NOT prevent a
// rewrite (it detects one at the next verifier run, if someone reads the
// alarm); does NOT protect created_at (not in the v2 row hash); does NOT hide
// activity timing (each break-glass start adds a checkpoint); does NOT survive
// theft of the checkpoint seed together with sink delete rights.
'use strict';

const crypto = require('node:crypto');
const { privateKeyFromSeed, rawPublicKey } = require('./keys');

const ORIGIN_PREFIX = 'systemapi.io/audit/';
const CHAIN_EXT = 'chain sha256-linear-v2';
const DEPLOYMENT_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SEED_RE = /^[0-9a-fA-F]{64}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const REGION_RE = /^[a-z0-9-]{1,32}$/;
const NOTE_MAX_BYTES = 4096;
const SIG_LINES_MAX = 8;
const INTERVAL_DEFAULT_S = 3600;
const INTERVAL_MIN_S = 300;
const INTERVAL_MAX_S = 86400;
const SINK_IDS = ['sink1', 'sink2'];
const SINK_FIELDS = ['ENDPOINT', 'BUCKET', 'REGION', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY'];
const SINK_TIMEOUT_MS = 15000;
// A checkpoint with no recorded outcome for a sink is retried only after
// this long (its first put may still be in flight on another replica).
const RETRY_UNRECORDED_S = 60;
// Retries stop this far inside TIME_SKEW_S, so a put that takes up to
// SINK_TIMEOUT_MS still lands within the verifier's skew.
const RETRY_WINDOW_S = 540;
const LIST_MAX_OBJECTS = 200000;
// How far a note's signed time may be from the sink's LastModified before
// the verifier calls it backdated; also the window for retrying a failed put
// and the limit on a checkpoint time ahead of the clock.
const TIME_SKEW_S = 600;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ALG_ED25519 = 0x01;

function anchorError(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

// An error's name or code, reduced to a safe token for a log line.
function errName(err) {
  const raw = String((err && (err.code || err.name)) || 'error');
  return raw.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 64) || 'error';
}

function originOf(deployment) {
  return `${ORIGIN_PREFIX}${deployment}`;
}

// C2SP signed-note key hash: SHA-256(name || "\n" || 0x01 || key)[:4].
function keyHash(name, raw) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from(`${name}\n`, 'utf8'), Buffer.from([ALG_ED25519]), raw]))
    .digest()
    .subarray(0, 4);
}

// The verifier key line: <name>+<hex key hash>+<base64(0x01 || key)>.
function vkeyOf(name, raw) {
  return `${name}+${keyHash(name, raw).toString('hex')}+${Buffer.concat([Buffer.from([ALG_ED25519]), raw]).toString('base64')}`;
}

function parseVkey(text) {
  if (typeof text !== 'string' || text.length > 512) throw anchorError('vkey_invalid');
  // The name has no '+'; the base64 key may.
  const t = text.trim();
  const i = t.indexOf('+');
  const j = i < 0 ? -1 : t.indexOf('+', i + 1);
  if (j < 0) throw anchorError('vkey_invalid');
  const name = t.slice(0, i);
  const hashHex = t.slice(i + 1, j);
  const b64 = t.slice(j + 1);
  const deployment = name.startsWith(ORIGIN_PREFIX) ? name.slice(ORIGIN_PREFIX.length) : '';
  if (!DEPLOYMENT_RE.test(deployment) || !/^[0-9a-f]{8}$/.test(hashHex)) throw anchorError('vkey_invalid');
  const key = Buffer.from(b64, 'base64');
  if (key.length !== 33 || key[0] !== ALG_ED25519 || key.toString('base64') !== b64) throw anchorError('vkey_invalid');
  const raw = key.subarray(1);
  const hash = keyHash(name, raw);
  if (hash.toString('hex') !== hashHex) throw anchorError('vkey_invalid');
  const publicKey = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
  return { name, deployment, raw, hash, publicKey };
}

// The note body: origin, seq, base64 head, the chain extension, the time.
function noteBody({ deployment, seq, head, time }) {
  if (!DEPLOYMENT_RE.test(deployment) || !Number.isSafeInteger(seq) || seq < 0 ||
    !HEX64_RE.test(head) || !Number.isSafeInteger(time) || time < 0) {
    throw anchorError('checkpoint_invalid');
  }
  return `${originOf(deployment)}\n${seq}\n${Buffer.from(head, 'hex').toString('base64')}\n${CHAIN_EXT}\ntime ${time}\n`;
}

function signNote(signer, fields) {
  const body = noteBody(fields);
  const name = originOf(fields.deployment);
  const sig = crypto.sign(null, Buffer.from(body, 'utf8'), signer.privateKey);
  const blob = Buffer.concat([keyHash(name, signer.publicKeyRaw), sig]).toString('base64');
  return `${body}\n— ${name} ${blob}\n`;
}

// Parses and verifies one note against the verifier key. Throws
// anchor_note_invalid (size, encoding, layout, values) or
// anchor_bad_signature (no valid signature by this key). Lines from other
// signers are allowed and ignored, as the signed-note format says.
function parseNote(buf, vkey) {
  if (!Buffer.isBuffer(buf) || buf.length === 0 || buf.length > NOTE_MAX_BYTES) throw anchorError('anchor_note_invalid');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    throw anchorError('anchor_note_invalid');
  }
  if (/[\u0000-\u0009\u000b-\u001f\u007f]/.test(text) || !text.endsWith('\n')) throw anchorError('anchor_note_invalid');
  const split = text.indexOf('\n\n');
  if (split < 0) throw anchorError('anchor_note_invalid');
  const body = text.slice(0, split + 1);
  const lines = body.slice(0, -1).split('\n');
  const sigLines = text.slice(split + 2, -1).split('\n');
  if (lines.length !== 5 || sigLines.length === 0 || sigLines.length > SIG_LINES_MAX) throw anchorError('anchor_note_invalid');
  const [origin, seqText, headB64, ext, timeLine] = lines;
  if (origin !== vkey.name || ext !== CHAIN_EXT) throw anchorError('anchor_note_invalid');
  if (!/^(0|[1-9][0-9]{0,15})$/.test(seqText)) throw anchorError('anchor_note_invalid');
  const time = /^time (0|[1-9][0-9]{0,11})$/.exec(timeLine);
  const head = Buffer.from(headB64, 'base64');
  if (!time || head.length !== 32 || head.toString('base64') !== headB64) throw anchorError('anchor_note_invalid');
  let signed = false;
  for (const line of sigLines) {
    const m = /^— (\S+) ([A-Za-z0-9+/]+={0,2})$/.exec(line);
    if (!m) throw anchorError('anchor_note_invalid');
    const blob = Buffer.from(m[2], 'base64');
    if (m[1] !== vkey.name || blob.length < 4 || !crypto.timingSafeEqual(blob.subarray(0, 4), vkey.hash)) continue;
    if (blob.length !== 68 || !crypto.verify(null, Buffer.from(body, 'utf8'), vkey.publicKey, blob.subarray(4))) {
      throw anchorError('anchor_bad_signature');
    }
    signed = true;
  }
  if (!signed) throw anchorError('anchor_bad_signature');
  if (!Number.isSafeInteger(Number(seqText))) throw anchorError('anchor_note_invalid');
  return { seq: Number(seqText), head: head.toString('hex'), time: Number(time[1]) };
}

// checkpoints/<deployment>/<seq, 19 digits>-<unix time>.note: listing order
// is seq order, and every checkpoint has its own key (WORM buckets refuse,
// or version, an overwrite).
function objectKey(deployment, seq, time) {
  return `${prefixOf(deployment)}${String(seq).padStart(19, '0')}-${time}.note`;
}

function prefixOf(deployment) {
  return `checkpoints/${deployment}/`;
}

function parseObjectKey(deployment, key) {
  const prefix = prefixOf(deployment);
  if (typeof key !== 'string' || !key.startsWith(prefix)) return null;
  const m = /^([0-9]{19})-(0|[1-9][0-9]{0,11})\.note$/.exec(key.slice(prefix.length));
  if (!m) return null;
  const seq = Number(m[1]);
  return Number.isSafeInteger(seq) ? { seq, time: Number(m[2]) } : null;
}

// SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S: 300..86400, default 3600. Anything
// else is null (the caller refuses it).
function intervalOf(env) {
  const raw = env && env.SYSTEMAPI_AUDIT_CHECKPOINT_INTERVAL_S;
  if (raw === undefined || raw === '') return INTERVAL_DEFAULT_S;
  if (!/^[0-9]{1,6}$/.test(String(raw))) return null;
  const n = Number(raw);
  return n >= INTERVAL_MIN_S && n <= INTERVAL_MAX_S ? n : null;
}

function validEndpoint(text) {
  let u;
  try {
    u = new URL(text);
  } catch {
    return false;
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) return false;
  return u.protocol === 'https:' || (u.protocol === 'http:' && LOOPBACK.has(u.hostname));
}

// The configured sinks, SYSTEMAPI_ANCHOR_SINK1_* then SINK2_*. A sink is all
// five fields or none; SINK2 needs SINK1. Throws anchor_sink_invalid.
function sinkConfigs(env) {
  const out = [];
  for (const id of SINK_IDS) {
    const prefix = `SYSTEMAPI_ANCHOR_${id.toUpperCase()}_`;
    const vals = SINK_FIELDS.map((f) => env[prefix + f]);
    const set = vals.filter((v) => v !== undefined && v !== '');
    if (set.length === 0) continue;
    const [endpoint, bucket, region, accessKeyId, secretAccessKey] = vals;
    if (set.length !== SINK_FIELDS.length || !validEndpoint(endpoint) || !BUCKET_RE.test(bucket) ||
      !REGION_RE.test(region) || accessKeyId.length > 256 || secretAccessKey.length > 256) {
      throw anchorError('anchor_sink_invalid');
    }
    out.push({ id, endpoint, bucket, region, accessKeyId, secretAccessKey });
  }
  if (out.length > 0 && out[0].id !== 'sink1') throw anchorError('anchor_sink_invalid');
  if (out.length === 2 && out[0].endpoint === out[1].endpoint && out[0].bucket === out[1].bucket) {
    throw anchorError('anchor_sink_invalid');
  }
  return out;
}

// The lease key's public half from the env (seed or PEM), or null.
function leasePublicKeyOf(env) {
  if (env.SYSTEMAPI_ED25519_SEED && SEED_RE.test(env.SYSTEMAPI_ED25519_SEED)) {
    return rawPublicKey(privateKeyFromSeed(Buffer.from(env.SYSTEMAPI_ED25519_SEED, 'hex')));
  }
  if (env.SYSTEMAPI_SIGNING_KEY) {
    try {
      const key = crypto.createPrivateKey(env.SYSTEMAPI_SIGNING_KEY);
      return key.asymmetricKeyType === 'ed25519' ? rawPublicKey(key) : null;
    } catch {
      return null;
    }
  }
  return null;
}

function anchorSigner(seedHex) {
  const privateKey = privateKeyFromSeed(Buffer.from(seedHex, 'hex'));
  const publicKeyRaw = rawPublicKey(privateKey);
  return { privateKey, publicKeyRaw };
}

// Reads the anchoring config. { enabled: false, reason } when off: reason
// anchor_off when nothing is set, else a fixed misconfiguration code.
// leasePublicKey: the running lease signer's key (an ephemeral one is not in
// the env). Never puts the seed or a credential in the result's reason.
function loadAnchorConfig(env, { leasePublicKey = null } = {}) {
  const intended = Object.keys(env).some((k) => (k.startsWith('SYSTEMAPI_AUDIT_CHECKPOINT_') ||
    k.startsWith('SYSTEMAPI_ANCHOR_SINK') || k === 'SYSTEMAPI_AUDIT_DEPLOYMENT') && env[k] !== undefined && env[k] !== '');
  if (!intended) return { enabled: false, reason: 'anchor_off' };
  const seed = env.SYSTEMAPI_AUDIT_CHECKPOINT_SEED;
  if (!seed) return { enabled: false, reason: 'anchor_seed_missing' };
  if (!SEED_RE.test(seed)) return { enabled: false, reason: 'anchor_seed_invalid' };
  const deployment = env.SYSTEMAPI_AUDIT_DEPLOYMENT;
  if (!deployment || !DEPLOYMENT_RE.test(deployment)) return { enabled: false, reason: 'anchor_deployment_invalid' };
  const intervalS = intervalOf(env);
  if (intervalS === null) return { enabled: false, reason: 'anchor_interval_invalid' };
  let sinks;
  try {
    sinks = sinkConfigs(env);
  } catch (err) {
    return { enabled: false, reason: err.code };
  }
  if (sinks.length === 0) return { enabled: false, reason: 'anchor_sink_missing' };
  const signer = anchorSigner(seed);
  const leaseSeed = env.SYSTEMAPI_ED25519_SEED && SEED_RE.test(env.SYSTEMAPI_ED25519_SEED)
    ? Buffer.from(env.SYSTEMAPI_ED25519_SEED, 'hex') : null;
  const sameSeed = leaseSeed && crypto.timingSafeEqual(leaseSeed, Buffer.from(seed, 'hex'));
  const leaseKeys = [leasePublicKey, leasePublicKeyOf(env)].filter((k) => Buffer.isBuffer(k) && k.length === 32);
  if (sameSeed || leaseKeys.some((k) => crypto.timingSafeEqual(k, signer.publicKeyRaw))) {
    return { enabled: false, reason: 'anchor_seed_reuses_lease_key' };
  }
  return { enabled: true, deployment, intervalS, sinks, signer, vkey: vkeyOf(originOf(deployment), signer.publicKeyRaw) };
}

// An S3-compatible sink: plain PutObject, ListObjectsV2 and GetObject only.
// No Object Lock headers per request (retention is the bucket default; R2
// does not take them). Content-MD5 is sent because S3 refuses an upload to a
// bucket with default retention without an integrity header; it is not a
// security control. Path-style, and checksums only when an operation needs
// one (some S3-compatible stores refuse the newer checksum headers).
function s3Sink(cfg, { client = null } = {}) {
  const s3 = require('@aws-sdk/client-s3');
  const c = client || new s3.S3Client({
    region: cfg.region,
    endpoint: cfg.endpoint,
    credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
    forcePathStyle: true,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED'
  });
  const send = (cmd) => c.send(cmd, { abortSignal: AbortSignal.timeout(SINK_TIMEOUT_MS) });
  return {
    id: cfg.id,
    async put(key, body) {
      const buf = Buffer.from(body, 'utf8');
      await send(new s3.PutObjectCommand({
        Bucket: cfg.bucket,
        Key: key,
        Body: buf,
        ContentType: 'text/plain; charset=utf-8',
        ContentMD5: crypto.createHash('md5').update(buf).digest('base64')
      }));
    },
    async list(prefix) {
      const out = [];
      let token;
      do {
        const res = await send(new s3.ListObjectsV2Command({ Bucket: cfg.bucket, Prefix: prefix, ContinuationToken: token }));
        for (const o of res.Contents || []) {
          out.push({ key: o.Key, size: Number(o.Size), lastModified: o.LastModified ? new Date(o.LastModified) : null });
        }
        if (out.length > LIST_MAX_OBJECTS) throw anchorError('sink_list_too_large');
        token = res.IsTruncated ? res.NextContinuationToken : undefined;
      } while (token);
      return out;
    },
    async get(key) {
      const res = await send(new s3.GetObjectCommand({ Bucket: cfg.bucket, Key: key, Range: `bytes=0-${NOTE_MAX_BYTES}` }));
      return Buffer.from(await res.Body.transformToByteArray());
    }
  };
}

// The breakglass terminal start: anchored right away, not at the next
// interval. (There is no recovery_sshd action in this codebase yet.)
function isTrigger(row) {
  return Boolean(row && row.action === 'terminal_start' && row.payload && row.payload.purpose === 'breakglass:open');
}

class AuditAnchor {
  constructor({ config, registry, sinks, logger = console, now = () => Date.now() }) {
    this.config = config;
    this.registry = registry;
    this.sinks = sinks;
    this.logger = logger;
    this.now = now;
    this.running = null;
    this.forcePending = false;
  }

  // Called from the 30 s control tick: retries failed sink puts, then writes
  // a checkpoint when the last one is an interval old. One run at a time; a
  // forced request during a run runs right after it.
  tick() {
    if (this.running) return this.running;
    this.running = (async () => {
      try {
        await this.retryFailed();
        do {
          const force = this.forcePending;
          this.forcePending = false;
          await this.checkpoint(force);
        } while (this.forcePending);
      } finally {
        this.running = null;
      }
    })();
    return this.running;
  }

  // Re-puts the stored note under the SAME key to each sink whose put failed
  // (or never recorded, after RETRY_UNRECORDED_S: a crash between insert and
  // put), while the note time is within RETRY_WINDOW_S of now (inside
  // TIME_SKEW_S), so a late put never trips the verifier's
  // anchor_time_mismatch.
  async retryFailed() {
    if (typeof this.registry.recentAuditCheckpoints !== 'function') return;
    const nowS = Math.floor(this.now() / 1000);
    let rows;
    try {
      rows = await this.registry.recentAuditCheckpoints(this.config.deployment, nowS - RETRY_WINDOW_S, nowS + RETRY_WINDOW_S);
    } catch (err) {
      this.logger.error(`[anchor] retry scan failed: db_error ${errName(err)}`);
      return;
    }
    for (const cp of rows) {
      const status = cp.sink_status || {};
      for (const sink of this.sinks) {
        const st = status[sink.id];
        if (st === 'ok' || (st === undefined && nowS - cp.note_time < RETRY_UNRECORDED_S)) continue;
        let result = 'put_failed';
        try {
          await sink.put(objectKey(cp.deployment, cp.seq, cp.note_time), cp.note);
          result = 'ok';
          this.logger.log(`[anchor] ${sink.id} put retried: ok`);
        } catch (err) {
          this.logger.error(`[anchor] ${sink.id} put retry failed: ${errName(err)}`);
        }
        try {
          await this.registry.setAuditCheckpointSink(cp.id, sink.id, result);
        } catch (err) {
          this.logger.error(`[anchor] sink status write failed: ${errName(err)}`);
        }
      }
    }
  }

  // An appended audit row; a trigger row asks for a checkpoint now.
  noteAudit(row) {
    if (!isTrigger(row)) return;
    this.forcePending = true;
    this.tick().catch((err) => this.logger.error(`[anchor] checkpoint failed: ${errName(err)}`));
  }

  async checkpoint(force) {
    const { deployment, intervalS, signer } = this.config;
    let cp;
    try {
      cp = await this.registry.createAuditCheckpoint({
        deployment,
        nowS: Math.floor(this.now() / 1000),
        minGapS: force ? 0 : intervalS,
        sign: ({ seq, head, time }) => signNote(signer, { deployment, seq, head, time })
      });
    } catch (err) {
      this.logger.error(`[anchor] checkpoint failed: db_error ${errName(err)}`);
      return null;
    }
    if (!cp) return null;
    if (cp.clock_warning) this.logger.error(`[anchor] ${cp.clock_warning}`);
    const key = objectKey(deployment, cp.seq, cp.note_time);
    // Each sink on its own: one failing never holds the other.
    const results = await Promise.all(this.sinks.map(async (sink) => {
      try {
        await sink.put(key, cp.note);
        return [sink.id, 'ok'];
      } catch (err) {
        this.logger.error(`[anchor] ${sink.id} put failed: ${errName(err)}`);
        return [sink.id, 'put_failed'];
      }
    }));
    const status = Object.fromEntries(results);
    try {
      await this.registry.setAuditCheckpointSinks(cp.id, status);
    } catch (err) {
      this.logger.error(`[anchor] sink status write failed: ${errName(err)}`);
    }
    return { ...cp, key, sink_status: status };
  }
}

// The anchor for this process, or null (logged with its reason code). Under
// NODE_ENV=production a set but invalid config throws its reason code (boot
// stops), as keys.js does for an ephemeral lease key.
function createAnchor({ env, registry, leasePublicKey = null, logger = console, sinkFactory = s3Sink }) {
  const config = loadAnchorConfig(env, { leasePublicKey });
  const off = (reason) => {
    // Production fails closed: anchoring was asked for and cannot run.
    if (env.NODE_ENV === 'production') throw anchorError(reason);
    logger.error(`[anchor] off: ${reason}`);
    return null;
  };
  if (!config.enabled) {
    if (config.reason === 'anchor_off') {
      logger.log('[anchor] off');
      return null;
    }
    return off(config.reason);
  }
  if (!registry || typeof registry.createAuditCheckpoint !== 'function') return off('registry_unavailable');
  const sinks = config.sinks.map((s) => sinkFactory(s));
  const fp = crypto.createHash('sha256').update(config.signer.publicKeyRaw).digest('hex');
  logger.log(`[anchor] on: deployment=${config.deployment} interval_s=${config.intervalS} sinks=${sinks.map((s) => s.id).join(',')} key sha256:${fp}`);
  return new AuditAnchor({ config, registry, sinks, logger });
}

module.exports = {
  CHAIN_EXT,
  NOTE_MAX_BYTES,
  TIME_SKEW_S,
  INTERVAL_MIN_S,
  INTERVAL_MAX_S,
  AuditAnchor,
  anchorError,
  anchorSigner,
  createAnchor,
  errName,
  intervalOf,
  isTrigger,
  loadAnchorConfig,
  noteBody,
  objectKey,
  originOf,
  parseNote,
  parseObjectKey,
  parseVkey,
  prefixOf,
  s3Sink,
  signNote,
  sinkConfigs,
  vkeyOf
};
