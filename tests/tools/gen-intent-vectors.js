// Regenerates controlplane/testdata/intent-lease-vectors.json, the vectors
// shared by tests/intent.test.js and systemapi-agent/intent_test.go.
//
//   node tests/tools/gen-intent-vectors.js
//
// Everything is deterministic (keys.js TEST_SEED, Ed25519, fixed nonces and
// times), so a rerun with unchanged builders writes the same bytes; a diff
// means a canonical form changed and both sides must be reviewed. It refuses
// to write if any invalid vector parses.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const root = path.join(__dirname, '..', '..');
const L = require(path.join(root, 'controlplane/lease'));
const I = require(path.join(root, 'controlplane/intent'));
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require(path.join(root, 'controlplane/keys'));
const key = privateKeyFromSeed(TEST_SEED);
const signer = buildSigner(key, rawPublicKey(key));
const sha = (s) => L.sha256Hex(Buffer.from(s, 'utf8'));
const HOST = '11111111-1111-4111-8111-111111111111';
const NOW = 1700000000; // seconds
const base = {
  request_id: 'apr_AAAAAAAAAAAAAAAAAAAAAA',
  tenant_id: 'acme',
  host_id: HOST,
  requester: 'member:alice@example.com',
  not_before_unix: NOW - 60,
  use_by_unix: NOW + 840,
  reason_sha256: sha('rotate the nginx cert'),
  approver_set_version: 3,
  threshold_k: 1
};
const sid = 'pts_AAAAAAAAAAAAAAAAAAAAAA';
const fid = 'fls_BBBBBBBBBBBBBBBBBBBBBB';
const bgDeadline = NOW + 7200;
const rootDeadline = NOW + 28800;
const cfgPayload = L.sysConfigPayload('write', '/etc/nginx/nginx.conf', sha('worker_processes 2;\n'));
const cases = [
  { name: 'breakglass_start', action: 'breakglass', payload: L.terminalPayload(sid, bgDeadline, 'start'), msd: bgDeadline, renew: L.terminalPayload(sid, bgDeadline, 'renew') },
  { name: 'pty_root_start', action: 'pty_root', payload: L.terminalPayload(sid, rootDeadline, 'start'), msd: rootDeadline, renew: L.terminalPayload(sid, rootDeadline, 'renew') },
  { name: 'file_root_start', action: 'file_root', payload: L.filePayload(fid, rootDeadline, 'start', 'write', '/'), msd: rootDeadline, renew: L.filePayload(fid, rootDeadline, 'renew', 'write', '/') },
  { name: 'sys_config_write', action: 'sys_config', payload: cfgPayload, msd: 0 },
  { name: 'sys_package_install', action: 'sys_package', payload: L.sysPackagePayload('nginx', 'install'), msd: 0 }
];
const nonces = ['abababababababababababababababab', 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'];
const sign = (hostId, action, payload, intentHash, nonceHex) => {
  const payloadSha256 = L.payloadHash(action, payload);
  const expiresUnix = NOW + 60;
  const message = L.canonicalLeaseV2({ hostId, action, expiresUnix, nonceHex, payloadSha256, intentSha256: intentHash });
  return { message, lease: { v: 2, host_id: hostId, action, expires_unix: expiresUnix, nonce_hex: nonceHex, payload_sha256: payloadSha256, intent_sha256: intentHash, signature: signer.sign(message) } };
};
const vectors = cases.map((c) => {
  const fields = { ...base, action: c.action, payload_sha256: L.payloadHash(c.action, c.payload), max_session_deadline_unix: c.msd };
  const text = I.buildIntent(fields);
  const h = I.intentSha256(text);
  const out = { name: c.name, fields, intent: text, intent_sha256: h, action: c.action, payload: c.payload, start: sign(HOST, c.action, c.payload, h, nonces[0]) };
  if (c.renew) out.renew = { payload: c.renew, ...sign(HOST, c.action, c.renew, h, nonces[1]) };
  return out;
});
// An approval-only action (no lease) still has a canonical intent.
const pg = { ...base, action: 'policy_grant', payload_sha256: sha('change-record'), max_session_deadline_unix: 0 };
vectors.push({ name: 'policy_grant_no_lease', fields: pg, intent: I.buildIntent(pg), intent_sha256: I.intentSha256(I.buildIntent(pg)), action: 'policy_grant' });

const good = vectors[0].intent;
const lines = good.slice(0, -1).split('\n');
const withLine = (i, v) => `${lines.map((l, j) => (j === i ? v : l)).join('\n')}\n`;
const sysLines = vectors[3].intent.slice(0, -1).split('\n');
const withSysLine = (i, v) => `${sysLines.map((l, j) => (j === i ? v : l)).join('\n')}\n`;
const swap = (i, j) => { const x = [...lines]; [x[i], x[j]] = [x[j], x[i]]; return `${x.join('\n')}\n`; };
const invalid = [
  ['newline_injection_in_requester', withLine(4, 'member:alice\nmember:bob')],
  ['space_in_field', withLine(4, 'member:alice bob')],
  ['tab_in_field', withLine(1, 'apr_AAAAAAAAAAAA\tAAAAAAAAA')],
  ['control_byte_in_field', withLine(2, 'acme\x01')],
  ['del_byte_in_field', withLine(2, 'acme\x7f')],
  ['non_ascii_in_field', withLine(2, 'acmé')],
  ['crlf_line_ends', good.replace(/\n/g, '\r\n')],
  ['missing_trailing_lf', good.slice(0, -1)],
  ['extra_trailing_lf', `${good}\n`],
  ['empty_field', withLine(10, '')],
  ['wrong_domain_prefix', withLine(0, 'systemapi-intent-v2')],
  ['lease_prefix_as_intent', withLine(0, 'systemapi-lease-v2')],
  ['fields_reordered_tenant_host', swap(2, 3)],
  ['fields_reordered_times', swap(7, 8)],
  ['leading_zero_number', withLine(12, '01')],
  ['signed_number', withLine(11, '+3')],
  ['number_above_safe_integer', withLine(11, '9007199254740993')],
  ['uppercase_hex', withLine(6, lines[6].toUpperCase())],
  ['unknown_action', withLine(5, 'pty')],
  ['requester_without_member_prefix', withLine(4, 'alice@example.com')],
  ['requester_empty_user', withLine(4, 'member:')],
  ['requester_key_principal', withLine(4, 'key:abc')],
  ['request_id_bad_shape', withLine(1, 'apr_short')],
  ['host_id_uppercase', withLine(3, 'AAAAAAAA-1111-4111-8111-111111111111')],
  ['threshold_zero', withLine(12, '0')],
  ['threshold_ten', withLine(12, '10')],
  ['approver_set_version_zero', withLine(11, '0')],
  ['use_by_before_not_before', withLine(8, String(NOW - 61))],
  ['window_over_3600', withLine(8, String(NOW - 60 + 3601))],
  ['breakglass_session_over_cap', withLine(9, String(NOW - 60 + 14401))],
  ['session_deadline_before_use_by', withLine(9, String(NOW + 839))],
  ['one_shot_with_session_deadline', withSysLine(9, String(NOW + 900))],
  ['thirteen_lines_plus_one', `${good}extra\n`],
  ['twelve_lines', `${lines.slice(0, 12).join('\n')}\n`]
].map(([name, text]) => ({ name, intent: text }));
for (const v of invalid) {
  let refused = false;
  try { I.parseIntent(v.intent); } catch { refused = true; }
  if (!refused) throw new Error(`generator: ${v.name} parsed`);
}
const out = {
  comment: 'Shared by tests/intent.test.js and systemapi-agent/intent_test.go (.omc/plans/sah-signed-intent-contract.md 1.1-1.5): the systemapi-intent-v1 canonical text and hash, and systemapi-lease-v2 start and renew leases over it, must agree byte for byte in Node and Go; every invalid intent must be refused by both parsers. Signed with keys.js TEST_SEED.',
  public_raw_b64: rawPublicKey(key).toString('base64'),
  host_id: HOST,
  now_ms: NOW * 1000,
  vectors,
  invalid
};
fs.writeFileSync(path.join(root, 'controlplane/testdata/intent-lease-vectors.json'), `${JSON.stringify(out, null, 2)}\n`);
console.log('ok', vectors.length, invalid.length);
