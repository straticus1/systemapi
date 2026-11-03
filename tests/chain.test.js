'use strict';

// controlplane/chain.js verifyRows with pinned known forks: only an exact
// (seq, prev_hash, row_hash) match that links to an earlier row is accepted,
// the row's own hash is still checked, and every other break still fails.

const test = require('node:test');
const assert = require('node:assert/strict');

const { GENESIS, KNOWN_FORKS, rowHash, verifyRows } = require('../controlplane/chain');

function row(seq, prev, action) {
  const r = { seq, prev_hash: prev, tenant_id: 'afterdark', host_id: null, actor: 'k-admin', action, payload: { n: seq } };
  return { ...r, row_hash: rowHash(prev, r) };
}

// 1 <- 2 <- 3, then 4 and 5 both chain from 3 (the race), 6 chains from 5.
function forked() {
  const r1 = row(1, GENESIS, 'a');
  const r2 = row(2, r1.row_hash, 'b');
  const r3 = row(3, r2.row_hash, 'c');
  const r4 = row(4, r3.row_hash, 'tcp_end');
  const r5 = row(5, r3.row_hash, 'ticket_issued');
  const r6 = row(6, r5.row_hash, 'd');
  return [r1, r2, r3, r4, r5, r6];
}
// The pin for rows[4] (the fork) with rows[3] as its sibling.
const pinOf = (rows) => ({
  seq: rows[4].seq, prev_hash: rows[4].prev_hash, row_hash: rows[4].row_hash,
  sibling_seq: rows[3].seq, sibling_row_hash: rows[3].row_hash
});

test('a linear chain verifies and reports no known forks', () => {
  const rows = forked().slice(0, 4);
  const out = verifyRows(rows, []);
  assert.deepEqual(out, { ok: true, head: rows[3].row_hash });
});

test('an unlisted fork fails at the forked row', () => {
  assert.deepEqual(verifyRows(forked(), []), { ok: false, broken_at: 5 });
});

test('a pinned fork verifies and is reported', () => {
  const rows = forked();
  assert.deepEqual(verifyRows(rows, [pinOf(rows)]), { ok: true, head: rows[5].row_hash, known_forks: [5] });
});

test('a pinned fork row whose content was edited fails', () => {
  const rows = forked();
  const forks = [pinOf(rows)];
  rows[4] = { ...rows[4], actor: 'someone-else' };
  assert.deepEqual(verifyRows(rows, forks), { ok: false, broken_at: 5 });
});

test('a pin with the right seq but another row hash, or another seq, does not excuse the fork', () => {
  const rows = forked();
  assert.deepEqual(verifyRows(rows, [{ ...pinOf(rows), row_hash: 'f'.repeat(64) }]), { ok: false, broken_at: 5 });
  assert.deepEqual(verifyRows(rows, [{ ...pinOf(rows), seq: 4 }]), { ok: false, broken_at: 5 });
});

test('a pinned row that links to a hash no earlier row has fails', () => {
  const rows = forked();
  const r5 = row(5, 'e'.repeat(64), 'ticket_issued');
  rows[4] = r5;
  rows[5] = row(6, r5.row_hash, 'd');
  assert.deepEqual(verifyRows(rows, [pinOf(rows)]), { ok: false, broken_at: 5 });
});

test('a second, unlisted break after a pinned fork still fails', () => {
  const rows = forked();
  rows.push(row(7, rows[3].row_hash, 'late'));
  assert.deepEqual(verifyRows(rows, [pinOf(rows)]), { ok: false, broken_at: 7 });
});

test('the sibling (dead branch) row edited and re-hashed fails at the fork', () => {
  const rows = forked();
  const forks = [pinOf(rows)];
  const r4 = { ...rows[3], actor: 'someone-else' };
  rows[3] = { ...r4, row_hash: rowHash(r4.prev_hash, r4) };
  assert.deepEqual(verifyRows(rows, forks), { ok: false, broken_at: 5 });
});

test('the sibling row deleted fails at the pinned row', () => {
  const rows = forked();
  const forks = [pinOf(rows)];
  rows.splice(3, 1);
  assert.deepEqual(verifyRows(rows, forks), { ok: false, broken_at: 5 });
});

test('rows inserted between the sibling and the fork (prefix renumbered) fail at the fork', () => {
  const rows = forked();
  const forks = [pinOf(rows)];
  const fake = row(5, rows[3].row_hash, 'fabricated');
  const tampered = [...rows.slice(0, 4), fake, rows[4], rows[5]];
  assert.deepEqual(verifyRows(tampered, forks), { ok: false, broken_at: 5 });
  const renumbered = [...rows.slice(0, 3).map((r) => ({ ...r, seq: r.seq - 1 })), { ...fake, seq: 3, prev_hash: rows[2].row_hash, row_hash: rowHash(rows[2].row_hash, { ...fake, prev_hash: rows[2].row_hash }) }, rows[3], rows[4], rows[5]];
  assert.equal(verifyRows(renumbered, forks).ok, false);
});

test('a duplicated pinned row fails at the second copy', () => {
  const rows = forked();
  const forks = [pinOf(rows)];
  const dup = [...rows.slice(0, 5), rows[3], rows[4], rows[5]];
  assert.equal(verifyRows(dup, forks).ok, false);
});

test('a pinned row on the legacy payload-only hash is refused', () => {
  const { chainHash } = require('../controlplane/chain');
  const rows = forked();
  const r5 = { ...rows[4] };
  r5.row_hash = chainHash(r5.prev_hash, r5.payload);
  rows[4] = r5;
  rows[5] = row(6, r5.row_hash, 'd');
  assert.deepEqual(verifyRows(rows, [pinOf(rows)]), { ok: false, broken_at: 5 });
});

test('the production pin list is frozen and pins full sha256 hashes', () => {
  assert.ok(Object.isFrozen(KNOWN_FORKS));
  for (const f of KNOWN_FORKS) {
    assert.ok(Object.isFrozen(f));
    assert.match(f.prev_hash, /^[0-9a-f]{64}$/);
    assert.match(f.row_hash, /^[0-9a-f]{64}$/);
    assert.match(f.sibling_row_hash, /^[0-9a-f]{64}$/);
    assert.equal(f.sibling_seq, f.seq - 1);
    assert.ok(Number.isInteger(f.seq) && f.seq > 0);
  }
});
