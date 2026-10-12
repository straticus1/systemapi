// Threats: a playbook id used as a path. Ids are a safe charset, and the
// resolved file must stay inside this directory. Scripts report; they do not
// delete files. Does NOT decide who may run them.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DIR = path.join(__dirname, 'playbooks');
const ID_RE = /^[a-z0-9_-]+$/;

function http(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function listPlaybooks() {
  if (!fs.existsSync(DIR)) return [];
  return fs.readdirSync(DIR)
    .filter((name) => name.endsWith('.star') && ID_RE.test(name.slice(0, -5)))
    .map((name) => name.slice(0, -5))
    .sort();
}

function readPlaybook(id) {
  if (typeof id !== 'string' || !ID_RE.test(id)) throw http(400, 'bad_playbook');
  const file = path.resolve(DIR, `${id}.star`);
  const rel = path.relative(DIR, file);
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw http(400, 'bad_playbook');
  if (!fs.existsSync(file)) throw http(404, 'playbook_not_found');
  return fs.readFileSync(file, 'utf8');
}

module.exports = { DIR, listPlaybooks, readPlaybook };
