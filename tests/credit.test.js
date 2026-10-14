'use strict';

// Credit-window flow control for SAH channels (TCP §6, FILE §6). Not PTY.

const test = require('node:test');
const assert = require('node:assert/strict');
const credit = require('../controlplane/credit');

test('window sizes match the contracts', () => {
  assert.equal(credit.TCP_WINDOW, 256 * 1024);
  assert.equal(credit.FILE_WINDOW, 8 * 1024 * 1024);
  assert.equal(credit.MAX_TURN, 64 * 1024);
  assert.throws(() => new credit.CreditStream({ window: 0 }), /bad_window/);
});

test('send credit: take, exhaust, grant back, never past the window', () => {
  const s = new credit.CreditStream({ window: credit.TCP_WINDOW });
  assert.equal(s.sendable(), 64 * 1024, 'one turn at most');
  for (let i = 0; i < 4; i++) assert.equal(s.take(64 * 1024), true);
  assert.equal(s.sendable(), 0);
  assert.equal(s.take(1), false);
  assert.equal(s.grant(1000), true);
  assert.equal(s.sendable(), 1000);
  // Returning more than could be owed is a violation.
  assert.equal(s.grant(credit.TCP_WINDOW), false);
  for (const bad of [0, -1, 1.5, '10', NaN]) assert.equal(s.grant(bad), false, String(bad));
});

test('receive: overrun past the window is detected; drain returns batched credit', () => {
  const s = new credit.CreditStream({ window: 1000, returnAt: 400 });
  assert.equal(s.receive(600), true);
  assert.equal(s.receive(400), true);
  assert.equal(s.receive(1), false, 'overrun');
  assert.equal(s.drain(300), 0, 'batching');
  assert.equal(s.drain(200), 500);
  assert.equal(s.receive(500), true, 'the returned credit may be used again');
  assert.equal(s.receive(1), false);
  assert.equal(s.drain(5000), 1000, 'never returns more than received');
  assert.equal(s.flush(), 0);
});

test('a parameterized file window behaves the same', () => {
  const s = new credit.CreditStream({ window: credit.FILE_WINDOW });
  assert.equal(s.receive(credit.FILE_WINDOW), true);
  assert.equal(s.receive(1), false);
  assert.equal(s.drain(credit.FILE_WINDOW / 4), credit.FILE_WINDOW / 4);
});

test('ledger: an agent that overruns its credit is reported once', () => {
  const seen = [];
  const ledger = new credit.CreditLedger({ onViolation: (id, reason) => seen.push([id, reason]) });
  ledger.open('tcs_aaaaaaaaaaaaaaaa', { window: 1024 });
  ledger.open('tcs_bbbbbbbbbbbbbbbb', { window: 1024 });
  assert.throws(() => ledger.open('tcs_aaaaaaaaaaaaaaaa', { window: 1024 }), /stream_exists/);
  assert.equal(ledger.receive('tcs_aaaaaaaaaaaaaaaa', 1024), true);
  assert.equal(ledger.receive('unknown', 1 << 30), true, 'unknown stream ignored');
  assert.equal(ledger.receive('tcs_aaaaaaaaaaaaaaaa', 1), false);
  assert.equal(ledger.grant('tcs_bbbbbbbbbbbbbbbb', 1), false);
  assert.deepEqual(seen, [['tcs_aaaaaaaaaaaaaaaa', 'credit_overrun']]);

  const seen2 = [];
  const l2 = new credit.CreditLedger({ onViolation: (id, reason) => seen2.push(reason) });
  l2.open('fls_aaaaaaaaaaaaaaaa', { window: 1024 });
  assert.equal(l2.grant('fls_aaaaaaaaaaaaaaaa', 1), false, 'credit beyond the window');
  assert.deepEqual(seen2, ['credit_overflow']);
  l2.close('fls_aaaaaaaaaaaaaaaa');
  assert.equal(l2.get('fls_aaaaaaaaaaaaaaaa'), null);
});

test('frames: credit and binary data', () => {
  assert.deepEqual(credit.creditFrame('tcp', 'tcs_x', 4096), { type: 'tcp_credit', session_id: 'tcs_x', bytes: 4096 });
  assert.deepEqual(credit.creditFrame('file', 'fls_x', 1), { type: 'file_credit', session_id: 'fls_x', bytes: 1 });
  assert.equal(credit.creditBytes({ bytes: 10 }), 10);
  for (const bad of [{ bytes: 0 }, { bytes: -5 }, { bytes: 1.5 }, { bytes: '10' }, {}, null, { bytes: 2 ** 60 }]) {
    assert.equal(credit.creditBytes(bad), null, JSON.stringify(bad));
  }
  const buf = credit.encodeData('tcs_abc', Buffer.from('hello'));
  assert.equal(buf[0], 7);
  const d = credit.decodeData(buf);
  assert.equal(d.sessionId, 'tcs_abc');
  assert.equal(d.data.toString(), 'hello');
  assert.equal(credit.decodeData(Buffer.from([5, 1])), null);
  assert.equal(credit.decodeData(Buffer.from([0, 1])), null);
  assert.throws(() => credit.encodeData('', Buffer.alloc(0)), /bad_session_id/);
});
