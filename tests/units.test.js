'use strict';

// Every unit in systemd/ that runs the agent binary runs the same path, the
// one the deploy kit installs (deploy/miniapps1/agent/install-agent.sh,
// LIB=/usr/local/lib/systemapi-agent). The helper units once pointed at
// /usr/local/bin, so every helper start would have failed on a kit install.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const AGENT_INSTALL_PATH = '/usr/local/lib/systemapi-agent/systemapi-agent';
const DIR = path.join(__dirname, '..', 'systemd');

test('every agent and helper unit runs the installed agent binary', () => {
  const units = fs.readdirSync(DIR).filter((f) => f === 'systemapi-agent.service' || /^sah-.*-helper@\.service$/.test(f));
  assert.equal(units.length, 4, `found ${units.join(', ')}`);
  for (const unit of units) {
    const lines = fs.readFileSync(path.join(DIR, unit), 'utf8').split('\n').filter((l) => l.startsWith('ExecStart='));
    assert.equal(lines.length, 1, unit);
    assert.equal(lines[0].slice('ExecStart='.length).split(/\s+/)[0], AGENT_INSTALL_PATH, unit);
  }
});
