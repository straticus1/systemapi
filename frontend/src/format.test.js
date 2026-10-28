import test from 'node:test';
import assert from 'node:assert/strict';
import { cpuLabel, scriptOutcome, terminalSocketURL, resizeFrameFor, jobActive, jobOutcome, jobClock } from './format.js';

test('cpuLabel shows a real sample', () => {
  assert.equal(cpuLabel({ status: 'online', cpu_percent: 42.345 }), '42.3%');
  assert.equal(cpuLabel({ status: 'online', cpu_percent: 0 }), '0%');
});

test('cpuLabel never invents 0% for a host with no sample', () => {
  assert.equal(cpuLabel({ status: 'online', cpu_percent: null }), 'No data yet');
  assert.equal(cpuLabel({ status: 'online' }), 'No data yet');
  assert.equal(cpuLabel({ status: 'online', cpu_percent: NaN }), 'No data yet');
  assert.equal(cpuLabel({ status: 'offline', cpu_percent: null }), '-');
});

test('scriptOutcome treats an agent error inside a 200 as failure', () => {
  assert.deepEqual(scriptOutcome({ result: { error: 'boom', output: '' } }), { success: false, data: 'boom' });
});

test('scriptOutcome passes real output through', () => {
  assert.deepEqual(scriptOutcome({ result: { error: '', output: 'hi\n' } }), { success: true, data: 'hi\n' });
  assert.deepEqual(scriptOutcome({ result: { error: '', output: '' } }), { success: true, data: 'No output returned.' });
  assert.deepEqual(scriptOutcome({}), { success: true, data: 'No output returned.' });
});

test('terminalSocketURL carries the initial size and encodes the ticket', () => {
  assert.equal(
    terminalSocketURL('wss://x', 'h/1', 'stk_a+b', 40, 120),
    'wss://x/api/v1/systems/terminal/h%2F1?ticket=stk_a%2Bb&rows=40&cols=120'
  );
  assert.match(terminalSocketURL('wss://x', 'h', 't', 0, 5000), /rows=1&cols=1000$/);
});

test('resizeFrameFor resends the size when the shell has started', () => {
  assert.deepEqual(JSON.parse(resizeFrameFor('started', 30, 100)), { type: 'pty_resize', rows: 30, cols: 100 });
  assert.deepEqual(JSON.parse(resizeFrameFor('starting', 30, 100)), { type: 'pty_resize', rows: 30, cols: 100 });
  assert.equal(resizeFrameFor('exited', 30, 100), null);
});

test('jobActive is true only before the job ends', () => {
  for (const s of ['submitted', 'accepted', 'running']) assert.equal(jobActive(s), true);
  for (const s of ['succeeded', 'failed', 'cancelled', 'timed_out', undefined]) assert.equal(jobActive(s), false);
});

test('jobOutcome shows output, and the error when the job did not succeed', () => {
  assert.deepEqual(jobOutcome({ status: 'succeeded', output: 'hi\n', error: null, output_visible: true }),
    { success: true, data: 'hi\n', notice: '' });
  assert.deepEqual(jobOutcome({ status: 'succeeded', output: '', output_visible: true }),
    { success: true, data: 'No output returned.', notice: '' });
  assert.deepEqual(jobOutcome({ status: 'failed', output: 'partial', error: 'boom', output_visible: true }),
    { success: false, data: 'partial\nboom', notice: '' });
  assert.deepEqual(jobOutcome({ status: 'timed_out', output: null, error: null, output_visible: true }),
    { success: false, data: 'timed_out', notice: '' });
  assert.match(jobOutcome({ status: 'succeeded', output: 'x', output_visible: true, output_truncated: true }).notice, /truncated/);
});

test('jobOutcome explains hidden and expired output instead of showing nothing', () => {
  const hidden = jobOutcome({ status: 'succeeded', output: null, error: null, output_visible: false });
  assert.equal(hidden.success, true);
  assert.equal(hidden.data, '');
  assert.match(hidden.notice, /hidden/);
  const hiddenFail = jobOutcome({ status: 'failed', output: null, error: 'agent_error', output_visible: false });
  assert.equal(hiddenFail.data, 'agent_error');
  const expired = jobOutcome({ status: 'succeeded', output: null, output_visible: true, output_expired: true });
  assert.equal(expired.data, '');
  assert.match(expired.notice, /expired/);
});

test('jobClock counts up and down to the deadline', () => {
  assert.equal(jobClock(1000, 400, 43500), '42s elapsed, 357s to deadline');
  assert.equal(jobClock(1000, 10, 43500), '42s elapsed, 0s to deadline');
  assert.equal(jobClock(1000, undefined, 3000), '2s elapsed');
});
