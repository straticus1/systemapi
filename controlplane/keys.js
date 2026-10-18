// Threats: a missing or attacker-supplied signing key. Ed25519 only (Node
// stdlib). Does NOT log key material. An ephemeral key is process-local and
// dies on restart; set SYSTEMAPI_ED25519_SEED (64 hex chars) to persist.
// NODE_ENV=production refuses the ephemeral key (assertSignerConfig): a
// restart would rotate it and every enrolled agent would stop with
// control_pubkey_changed. Development keeps it with a warning.
// TEST_SEED below is a fixture, not a production key.
'use strict';

const crypto = require('node:crypto');

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const TEST_SEED = Buffer.alloc(32, 0x11);

function privateKeyFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new Error('ed25519 seed must be 32 bytes');
  }
  const der = Buffer.concat([PKCS8_PREFIX, seed]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

function rawPublicKey(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - 32);
}

function fingerprintOf(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function signMessage(privateKey, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('base64');
}

const SEED_RE = /^[0-9a-fA-F]{64}$/;

// Throws when the signing key config is malformed, or absent under
// NODE_ENV=production. Never prints the value.
function assertSignerConfig(env) {
  if (env.SYSTEMAPI_ED25519_SEED) {
    if (!SEED_RE.test(env.SYSTEMAPI_ED25519_SEED)) {
      throw new Error('SYSTEMAPI_ED25519_SEED must be 64 hex characters');
    }
    return;
  }
  if (env.SYSTEMAPI_SIGNING_KEY) return;
  if (env.NODE_ENV === 'production') {
    throw new Error('SYSTEMAPI_ED25519_SEED is not set; production refuses an ephemeral signing key '
      + '(a restart would rotate it and every enrolled agent would stop with control_pubkey_changed). '
      + 'Generate one once with `openssl rand -hex 32`, keep it in the env file, and never change it');
  }
}

function loadSigner(env, logger = console) {
  assertSignerConfig(env);
  let seed;
  let ephemeral = false;
  if (env.SYSTEMAPI_ED25519_SEED) {
    seed = Buffer.from(env.SYSTEMAPI_ED25519_SEED, 'hex');
  } else if (env.SYSTEMAPI_SIGNING_KEY) {
    const privateKey = crypto.createPrivateKey(env.SYSTEMAPI_SIGNING_KEY);
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('SYSTEMAPI_SIGNING_KEY must be ed25519');
    }
    const raw = rawPublicKey(privateKey);
    logger.log(`[control] ed25519 public fingerprint sha256:${fingerprintOf(raw)}`);
    return buildSigner(privateKey, raw);
  } else {
    seed = crypto.randomBytes(32);
    ephemeral = true;
  }
  const privateKey = privateKeyFromSeed(seed);
  const raw = rawPublicKey(privateKey);
  logger.log(`[control] ed25519 public fingerprint sha256:${fingerprintOf(raw)}`);
  if (ephemeral) {
    logger.log('[control] ephemeral signing key; set SYSTEMAPI_ED25519_SEED to persist');
  }
  return buildSigner(privateKey, raw);
}

function buildSigner(privateKey, raw) {
  return {
    privateKey,
    publicKeyRaw: raw,
    publicKeyB64: raw.toString('base64'),
    fingerprint: fingerprintOf(raw),
    sign(message) {
      return signMessage(privateKey, message);
    }
  };
}

module.exports = {
  TEST_SEED,
  privateKeyFromSeed,
  rawPublicKey,
  loadSigner,
  assertSignerConfig,
  buildSigner
};
