// General SAH sys-channel client. Node 22 built-ins only (fetch + WebSocket).
//
//   node /tmp/sah_sys.mjs <purpose> '<json-binding>'
//
// Examples:
//   node /tmp/sah_sys.mjs sys:tweak   '{"verb":"sysctl-get","key":"net.ipv4.ip_forward"}'
//   node /tmp/sah_sys.mjs sys:tweak   '{"verb":"sysctl-set","key":"net.ipv4.ip_forward","value":"0"}'
//   node /tmp/sah_sys.mjs sys:package '{"name":"cowsay","action":"query"}'
//   node /tmp/sah_sys.mjs sys:config  '{"action":"read","target":"/etc/hostname"}'
//   node /tmp/sah_sys.mjs sys:service '{"unit":"cron.service","action":"restart"}'
//
// The binding object must match the host's policy allowlist (deny by default)
// or the server answers *_denied.
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';

const API = process.env.SAHCORE_API || 'https://api.systemapi.io';
const NAME = 'miniapps1';
const PURPOSE = process.argv[2];
const BIND = process.argv[3];
const FIELD = { 'sys:service': 'service', 'sys:package': 'package', 'sys:config': 'config', 'sys:tweak': 'tweak' }[PURPOSE];
if (!FIELD || !BIND) { console.error('usage: node sah_sys.mjs <sys:service|sys:package|sys:config|sys:tweak> \'<json>\''); process.exit(2); }
let binding;
try { binding = JSON.parse(BIND); } catch (e) { console.error('bad JSON binding:', e.message); process.exit(2); }

const keyFile = process.env.SAHCORE_ADMIN_KEY_FILE || `${homedir()}/.config/sahcore/admin-api-key`;
const KEY = readFileSync(keyFile, 'utf8').trim();
const H = { 'x-api-key': KEY, 'content-type': 'application/json' };
const die = (m) => { console.error('FAIL:', m); process.exit(1); };

const r = await fetch(`${API}/api/v1/hosts/resolve?name=${NAME}`, { headers: H });
if (!r.ok) die(`resolve ${NAME}: HTTP ${r.status} ${await r.text()}`);
const host = await r.json();
if (host.status !== 'online') die(`${NAME} is ${host.status}, not online`);
const hostId = host.host_id;
console.log(`host    : ${NAME} -> ${hostId}`);
console.log(`purpose : ${PURPOSE}`);
console.log(`binding : ${JSON.stringify(binding)}`);

const tr = await fetch(`${API}/api/v1/ws-ticket`, {
  method: 'POST', headers: H,
  body: JSON.stringify({ purpose: PURPOSE, host_id: hostId, [FIELD]: binding }),
});
if (!tr.ok) die(`ws-ticket: HTTP ${tr.status} ${await tr.text()}`);
const ticket = (await tr.json()).ticket;
if (!ticket) die('ws-ticket: no ticket in response');
console.log('ticket  : issued');

const wsURL = `${API.replace(/^http/, 'ws')}/api/v1/systems/sys/${hostId}?ticket=${encodeURIComponent(ticket)}&purpose=${encodeURIComponent(PURPOSE)}`;
const ws = new WebSocket(wsURL);
const timer = setTimeout(() => die('timed out waiting for sys_result (30s)'), 30000);
ws.addEventListener('message', (ev) => {
  clearTimeout(timer);
  let msg; try { msg = JSON.parse(ev.data); } catch { die(`non-JSON frame: ${ev.data}`); }
  if (msg.type !== 'sys_result') { console.log('frame:', ev.data); return; }
  const p = msg.payload || {};
  console.log('result  :', JSON.stringify(p));
  try { ws.close(); } catch {}
  if (p.ok) { console.log('\nOK'); process.exit(0); }
  die(`refused: ${p.error || 'unknown'}`);
});
ws.addEventListener('error', (e) => { clearTimeout(timer); die(`websocket error: ${e.message || e}`); });
ws.addEventListener('close', (e) => { if (e.code !== 1000) console.error(`ws closed ${e.code} ${e.reason || ''}`); });
