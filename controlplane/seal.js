// Threats: a database reader replaying a webhook HMAC secret, a ciphertext
// opened under the wrong key, and a swapped or truncated nonce. AES-256-GCM
// with a fresh 12-byte nonce. The key is SYSTEMAPI_WEBHOOK_KEY, 64 hex
// characters, supplied by the operator. Does NOT rotate keys, does NOT call
// a remote vault, and does NOT hide the secret from the process that signs
// the delivery. A missing or wrong-length key fails closed.
'use strict';

const { createCipheriv, createDecipheriv, randomBytes } = require('node:crypto');

const PREFIX = 'v1.';
const NONCE_LEN = 12;
const TAG_LEN = 16;

function fail(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function webhookKey(env) {
  const hex = env && env.SYSTEMAPI_WEBHOOK_KEY;
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw fail(503, 'webhook_key_unavailable');
  }
  return Buffer.from(hex, 'hex');
}

function sealSecret(plain, env) {
  if (typeof plain !== 'string' || plain.length === 0 || plain.length > 256) {
    throw fail(500, 'webhook_secret_rejected');
  }
  const key = webhookKey(env);
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([nonce, body, tag]).toString('base64url');
}

function openSecret(sealed, env) {
  const key = webhookKey(env);
  try {
    if (typeof sealed !== 'string' || !sealed.startsWith(PREFIX) || sealed.length > 512) {
      throw new Error('shape');
    }
    const raw = Buffer.from(sealed.slice(PREFIX.length), 'base64url');
    if (raw.length < NONCE_LEN + TAG_LEN + 1 || raw.length > 256) throw new Error('shape');
    const nonce = raw.subarray(0, NONCE_LEN);
    const tag = raw.subarray(raw.length - TAG_LEN);
    const body = raw.subarray(NONCE_LEN, raw.length - TAG_LEN);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  } catch (err) {
    if (err && err.code === 'webhook_key_unavailable') throw err;
    throw fail(500, 'webhook_secret_rejected');
  }
}

module.exports = { sealSecret, openSecret };
