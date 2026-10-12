// Threats: predictable tokens (Math.random) and timing comparison, including
// unequal-length probes. Does NOT handle storage, expiry, rotation, or claims.
// CommonJS port of ads-fable-utils assets/node/auth/token (that file is ESM and
// cannot be require()'d by this process). Limits: Node crypto only.
'use strict';

const { randomBytes, createHash, timingSafeEqual } = require('node:crypto');

const MIN_BYTES = 16;

function randomToken(nBytes = 32) {
  if (!Number.isInteger(nBytes) || nBytes < MIN_BYTES) {
    throw new RangeError(`randomToken: ${nBytes} bytes is below the ${MIN_BYTES}-byte minimum`);
  }
  return randomBytes(nBytes).toString('base64url');
}

function tokenEqual(known, presented) {
  if (typeof known !== 'string' || typeof presented !== 'string') return false;
  const a = createHash('sha256').update(known).digest();
  const b = createHash('sha256').update(presented).digest();
  return timingSafeEqual(a, b) && known.length === presented.length;
}

function fingerprint(value) {
  if (typeof value !== 'string') return null;
  return createHash('sha256').update(value).digest('hex');
}

module.exports = { MIN_BYTES, randomToken, tokenEqual, fingerprint };
