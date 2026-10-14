import test from 'node:test';
import assert from 'node:assert/strict';
import { cpuLabel, scriptOutcome } from './format.js';

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
