'use strict';

// systemapi-intent-v1 and systemapi-lease-v2 (.omc/plans/sah-signed-intent-
// contract.md 1.1-1.5, 4.4), the control-plane half. The shared vectors in
// controlplane/testdata/intent-lease-vectors.json are also checked by
// systemapi-agent/intent_test.go, so Node and Go agree byte for byte.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const L = require('../controlplane/lease');
const I = require('../controlplane/intent');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require('../controlplane/keys');

const key = privateKeyFromSeed(TEST_SEED);
const signer = buildSigner(key, rawPublicKey(key));
const pub = crypto.createPublicKey(key);
const vec = require('../controlplane/testdata/intent-lease-vectors.json');

function code(fn) {
  try {
    fn();
  } catch (err) {
    return err.message;
  }
  return 'no_error';
}

test('intent vectors: canonical text, hash and v2 leases agree with the stored bytes', () => {
  assert.equal(vec.public_raw_b64, rawPublicKey(key).toString('base64'));
  for (const v of vec.vectors) {
    assert.equal(I.buildIntent(v.fields), v.intent, v.name);
    assert.deepEqual(I.parseIntent(v.intent), v.fields, v.name);
    assert.equal(I.intentSha256(v.intent), v.intent_sha256, v.name);
    assert.equal(v.intent.split('\n').length, 14, `${v.name}: 13 LF-terminated lines`);
    if (!v.start) continue;
    assert.equal(L.payloadHash(v.action, v.payload), v.fields.payload_sha256, v.name);
    for (const [phase, l] of [['start', v.start], ['renew', v.renew]]) {
      if (!l) continue;
      const payload = phase === 'start' ? v.payload : v.renew.payload;
      const msg = L.canonicalLeaseV2({
        hostId: l.lease.host_id, action: l.lease.action, expiresUnix: l.lease.expires_unix,
        nonceHex: l.lease.nonce_hex, payloadSha256: l.lease.payload_sha256, intentSha256: l.lease.intent_sha256
      });
      assert.equal(msg, l.message, `${v.name} ${phase}`);
      assert.ok(msg.startsWith('systemapi-lease-v2\n') && msg.endsWith(`\n${v.intent_sha256}\n`));
      assert.equal(signer.sign(msg), l.lease.signature, `${v.name} ${phase}`);
      const ok = L.verifyLeaseV2(pub, l.lease, payload, vec.now_ms);
      assert.equal(ok.ok, true, `${v.name} ${phase}`);
      assert.equal(ok.intentSha256, v.intent_sha256);
    }
  }
});

test('intent parse refuses every invalid shared vector (injection, reorder, prefix, numbers)', () => {
  assert.ok(vec.invalid.length >= 30);
  for (const v of vec.invalid) {
    assert.equal(code(() => I.parseIntent(v.intent)), 'intent_malformed', v.name);
  }
});

test('intent builder refuses, never escapes', () => {
  const f = vec.vectors[0].fields;
  for (const [name, over] of [
    ['newline', { requester: 'member:a\nb' }],
    ['space', { tenant_id: 'ac me' }],
    ['nul', { request_id: 'apr_AAAAAAAAAAAAAAAAAAAAA\0' }],
    ['float', { threshold_k: 1.5 }],
    ['string number', { not_before_unix: '1699999940' }],
    ['negative', { not_before_unix: -1 }],
    ['unknown action', { action: 'pty' }],
    ['missing field', { reason_sha256: undefined }]
  ]) {
    assert.equal(code(() => I.buildIntent({ ...f, ...over })), 'intent_malformed', name);
  }
});

test('lease v2 and v1 never verify as each other', () => {
  const v = vec.vectors[0];
  const l2 = v.start.lease;
  // A v2 lease handed to the v1 verifier (an old CP-side check): malformed.
  assert.equal(L.verifyLease(pub, l2, v.payload, vec.now_ms).error, 'malformed');
  // The same fields relabelled v1 without the intent line: the signature
  // was made over the v2 text, so it fails.
  const { intent_sha256: _drop, ...rest } = l2;
  assert.equal(L.verifyLease(pub, { ...rest, v: 1 }, v.payload, vec.now_ms).error, 'bad_signature');
  // A v1 lease relabelled v2 with some intent hash: bad signature.
  const l1 = L.issueLease(signer, { hostId: vec.host_id, action: v.action, payload: v.payload, now: vec.now_ms });
  assert.equal(L.verifyLease(pub, l1, v.payload, vec.now_ms).ok, true);
  assert.equal(L.verifyLeaseV2(pub, { ...l1, v: 2, intent_sha256: v.intent_sha256 }, v.payload, vec.now_ms).error, 'bad_signature');
  assert.equal(L.verifyLeaseV2(pub, l1, v.payload, vec.now_ms).error, 'malformed');
  // A tampered intent hash on a v2 lease fails the signature.
  const other = 'f'.repeat(64);
  assert.equal(L.verifyLeaseV2(pub, { ...l2, intent_sha256: other }, v.payload, vec.now_ms).error, 'bad_signature');
  assert.equal(L.verifyLeaseV2(pub, { ...l2, intent_sha256: 'F'.repeat(64) }, v.payload, vec.now_ms).error, 'malformed');
});

test('mintIntentStartLease binds the intent, refuses a mismatched payload and a start after use_by', () => {
  const v = vec.vectors[0];
  const now = vec.now_ms;
  const l = I.mintIntentStartLease(signer, { intentText: v.intent, action: v.action, payload: v.payload, now });
  assert.equal(l.v, 2);
  assert.equal(l.host_id, vec.host_id);
  assert.equal(l.intent_sha256, v.intent_sha256);
  assert.equal(L.verifyLeaseV2(pub, l, v.payload, now).ok, true);
  // Payload hash does not match the intent (another session id).
  const wrong = L.terminalPayload('pts_ZZZZZZZZZZZZZZZZZZZZZZ', v.fields.max_session_deadline_unix, 'start');
  assert.equal(code(() => I.mintIntentStartLease(signer, { intentText: v.intent, action: v.action, payload: wrong, now })), 'intent_mismatch');
  // A renew payload can never be minted as the start.
  assert.equal(code(() => I.mintIntentStartLease(signer, { intentText: v.intent, action: v.action, payload: v.renew.payload, now })), 'intent_mismatch');
  // Another action than the intent names.
  assert.equal(code(() => I.mintIntentStartLease(signer, { intentText: v.intent, action: 'pty_root', payload: v.payload, now })), 'intent_mismatch');
  // N24: minted at or after use_by.
  const late = v.fields.use_by_unix * 1000;
  assert.equal(code(() => I.mintIntentStartLease(signer, { intentText: v.intent, action: v.action, payload: v.payload, now: late })), 'intent_window');
  const early = (v.fields.not_before_unix - 31) * 1000;
  assert.equal(code(() => I.mintIntentStartLease(signer, { intentText: v.intent, action: v.action, payload: v.payload, now: early })), 'intent_window');
  // An approval-only intent carries no lease.
  const pg = vec.vectors.find((x) => x.name === 'policy_grant_no_lease');
  assert.equal(code(() => I.mintIntentStartLease(signer, { intentText: pg.intent, action: 'policy_grant', payload: 'x', now })), 'intent_mismatch');
  // A malformed intent never signs.
  assert.equal(code(() => I.mintIntentStartLease(signer, { intentText: vec.invalid[0].intent, action: v.action, payload: v.payload, now })), 'intent_malformed');
  assert.equal(code(() => I.mintIntentStartLease(null, { intentText: v.intent, action: v.action, payload: v.payload, now })), 'signer_unavailable');
});

test('mintIntentRenewLease signs only renew payloads of the stored intent, no use_by, never past its deadline', () => {
  const v = vec.vectors[0];
  const host = vec.host_id;
  // N20 (CP side): a renew after use_by is still minted.
  const now = (v.fields.use_by_unix + 600) * 1000;
  const l = I.mintIntentRenewLease(signer, { hostId: host, action: v.action, payload: v.renew.payload, intentText: v.intent, now });
  assert.equal(l.v, 2);
  assert.equal(l.intent_sha256, v.intent_sha256);
  assert.equal(L.verifyLeaseV2(pub, l, v.renew.payload, now).ok, true);
  assert.equal(code(() => I.mintIntentRenewLease(signer, { hostId: host, action: v.action, payload: v.payload, intentText: v.intent, now })), 'bad_phase');
  assert.equal(code(() => I.mintIntentRenewLease(signer, { hostId: host, action: v.action, payload: v.renew.payload, intentText: '', now })), 'intent_required');
  assert.equal(code(() => I.mintIntentRenewLease(signer, { hostId: host, action: 'sys_config', payload: v.renew.payload, intentText: v.intent, now })), 'bad_action');
  assert.equal(code(() => I.mintIntentRenewLease(signer, { hostId: host, action: 'pty_root', payload: v.renew.payload, intentText: v.intent, now })), 'intent_mismatch');
  assert.equal(code(() => I.mintIntentRenewLease(signer, { hostId: '44444444-4444-4444-8444-444444444444', action: v.action, payload: v.renew.payload, intentText: v.intent, now })), 'intent_mismatch');
  // A renew payload whose deadline passes max_session_deadline is refused.
  const msd = v.fields.max_session_deadline_unix;
  const past = L.terminalPayload('pts_AAAAAAAAAAAAAAAAAAAAAA', msd + 30, 'renew');
  assert.equal(code(() => I.mintIntentRenewLease(signer, { hostId: host, action: v.action, payload: past, intentText: v.intent, now })), 'intent_deadline');
  const f = vec.vectors.find((x) => x.name === 'file_root_start');
  const fl = I.mintIntentRenewLease(signer, { hostId: host, action: 'file_root', payload: f.renew.payload, intentText: f.intent, now });
  assert.equal(L.verifyLeaseV2(pub, fl, f.renew.payload, now).ok, true);
});

test('mintIntentRenewLease refuses an xfer_root renew past the intent deadline', () => {
  const sha = (s) => L.sha256Hex(Buffer.from(s, 'utf8'));
  const base = Math.floor(vec.now_ms / 1000);
  const msd = base + 900;
  const xp = (deadline, phase) => L.xferPayload({
    grantId: 'xfr_AAAAAAAAAAAA', deadlineUnix: deadline, phase, dir: 'put', root: '/', path: 'a', size: 1,
    sha256: 'a'.repeat(64), overwrite: false, transferId: '0123456789abcdef', expiresUnix: base + 60,
    idleS: 10, maxS: 60, byteCap: 1, profile: 'internet', transport: 'udp', peer: 'listen', material: 'b'.repeat(64)
  });
  const intentText = I.buildIntent({
    ...vec.vectors[0].fields, action: 'xfer_root', payload_sha256: L.payloadHash('xfer_root', xp(msd, 'start')),
    max_session_deadline_unix: msd, reason_sha256: sha('x')
  });
  const args = (deadline) => ({ hostId: vec.host_id, action: 'xfer_root', payload: xp(deadline, 'renew'), intentText, now: vec.now_ms });
  assert.equal(I.mintIntentRenewLease(signer, args(msd)).v, 2);
  assert.equal(code(() => I.mintIntentRenewLease(signer, args(msd + 30))), 'intent_deadline');
});
