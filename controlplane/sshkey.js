// Threats: an agent enrolling with a private key, a non-ed25519 key, or a
// truncated blob. Accepts an OpenSSH ssh-ed25519 public key only. Wire form
// is 4+11+4+32 = 51 bytes. Does NOT prove the agent holds the private key
// (possession is the API key plus a later challenge if one is added).
'use strict';

const TENANT_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const HOST_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

function reject(error) {
  const err = new Error(error);
  err.status = 400;
  return err;
}

function validateTenant(tenant) {
  if (typeof tenant !== 'string' || !TENANT_RE.test(tenant)) throw reject('bad_tenant');
  return tenant;
}

function validateHostId(hostId) {
  if (typeof hostId !== 'string' || !HOST_ID_RE.test(hostId)) throw reject('bad_host_id');
  return hostId.toLowerCase();
}

function validateHostname(hostname) {
  if (typeof hostname !== 'string' || hostname.length > 253 || !HOSTNAME_RE.test(hostname)) {
    throw reject('bad_hostname');
  }
  return hostname;
}

function validateSSHPublicKey(line) {
  if (typeof line !== 'string' || line.length === 0 || line.length > 16384) throw reject('bad_ssh_pubkey');
  if (/PRIVATE KEY|OPENSSH PRIVATE/i.test(line)) throw reject('private_key_rejected');
  const parts = line.trim().split(/\s+/);
  if (parts[0] !== 'ssh-ed25519') throw reject('bad_ssh_pubkey');
  let raw;
  try {
    raw = Buffer.from(parts[1], 'base64');
  } catch {
    throw reject('bad_ssh_pubkey');
  }
  if (raw.length !== 51) throw reject('bad_ssh_pubkey');
  const nameLen = raw.readUInt32BE(0);
  const name = raw.subarray(4, 4 + nameLen).toString('utf8');
  if (name !== 'ssh-ed25519' || nameLen !== 11) throw reject('bad_ssh_pubkey');
  const keyLen = raw.readUInt32BE(4 + nameLen);
  if (keyLen !== 32 || raw.length !== 4 + nameLen + 4 + keyLen) throw reject('bad_ssh_pubkey');
  return line.trim();
}

// The key itself (type and base64 blob) without the comment, so a re-enroll
// is matched on the key, not on the text after it.
function sshKeyMaterial(line) {
  if (typeof line !== 'string') return '';
  return line.trim().split(/\s+/).slice(0, 2).join(' ');
}

module.exports = {
  validateTenant,
  validateHostId,
  validateHostname,
  validateSSHPublicKey,
  sshKeyMaterial
};
