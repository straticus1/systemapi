import test from 'node:test';
import assert from 'node:assert/strict';
import { cpuLabel, scriptOutcome, terminalSocketURL, resizeFrameFor } from './format.js';

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
