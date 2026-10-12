// Threats: guessing a device or user code, approving by GET (prefetch, link
// scanners), open signup through Google or GitHub, linking an IdP subject
// that is not on the whitelist, replaying a consumed grant, open redirects,
// and logging the verification URL or access token. A 200 versus 403 tells a
// caller whether the username is already a member. A stolen user code inside
// its 10-minute TTL is consent. A stolen access token inside its hour is a
// session. Does NOT create members, store IdP access tokens, keep a PKCE
// verifier, or replace the Authentik client in routes/oauth.js. Does NOT stop
// a caller who already knows a member id from holding the three pending slots
// until they expire.
'use strict';

const { randomToken, tokenEqual, fingerprint } = require('./token');
const { hostIPv4 } = require('./webhook');

const DEVICE_TTL_MS = 10 * 60 * 1000;
const ACCESS_TTL_MS = 60 * 60 * 1000;
const PENDING_CAP = 3;
const USER_RE = /^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,128}$/;
const SUBJECT_RE = /^[A-Za-z0-9._:-]{1,255}$/;
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const RESPONSE_CAP = 8192;
const PROVIDERS = {
  google: {
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    userinfo: 'https://openidconnect.googleapis.com/v1/userinfo',
    scope: 'openid'
  },
  github: {
    authorize: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token',
    userinfo: 'https://api.github.com/user',
    scope: 'read:user'
  }
};

function http(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function atMs(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value;
  const n = Date.parse(value);
  return Number.isFinite(n) ? n : NaN;
}

function pollSeconds(env) {
  return env && env.NODE_ENV === 'test' ? 0 : 5;
}

function publicBase(env) {
  const raw = env && env.SYSTEMAPI_PUBLIC_URL;
  if (typeof raw !== 'string' || raw.length < 8 || raw.length > 200) throw http(503, 'oauth_unavailable');
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw http(503, 'oauth_unavailable');
  }
  if (url.username || url.password || url.search || url.hash) throw http(503, 'oauth_unavailable');
  if (url.pathname !== '/' && url.pathname !== '') throw http(503, 'oauth_unavailable');
  const prod = env.NODE_ENV === 'production';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && !prod)) throw http(503, 'oauth_unavailable');
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || host === 'metadata.google.internal' || host.endsWith('.internal') || host.endsWith('.localhost')) {
    throw http(503, 'oauth_unavailable');
  }
  const v4 = hostIPv4(host);
  if (v4 != null) {
    const linkLocal = (v4 >>> 16) === 0xa9fe;
    const loop = (v4 >>> 24) === 0x7f;
    if (linkLocal || (prod && loop)) throw http(503, 'oauth_unavailable');
  }
  if (prod && (host === 'localhost' || host === '::1')) throw http(503, 'oauth_unavailable');
  if (host.startsWith('fe80:') || host.startsWith('fe80%')) throw http(503, 'oauth_unavailable');
  return url.origin;
}

function configuredProvider(env, name) {
  const spec = PROVIDERS[name];
  if (!spec) return null;
  const id = env && env[`SYSTEMAPI_${name.toUpperCase()}_CLIENT_ID`];
  const secret = env && env[`SYSTEMAPI_${name.toUpperCase()}_CLIENT_SECRET`];
  if (typeof id !== 'string' || typeof secret !== 'string') return null;
  const clientId = id.trim();
  const clientSecret = secret.trim();
  if (!clientId || !clientSecret || clientId.length > 256 || clientSecret.length > 256) return null;
  return { name, id: clientId, secret: clientSecret, ...spec };
}

function configuredNames(env) {
  return ['google', 'github'].filter((name) => configuredProvider(env, name));
}

function ensure(registry) {
  if (!registry.oauthDevices) {
    registry.oauthDevices = new Map();
    registry.oauthByUserCode = new Map();
    registry.oauthByState = new Map();
    registry.oauthAccess = new Map();
    registry.oauthLinks = new Map();
  }
}

function linkKey(userId, provider) {
  return userId + '\0' + provider;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]));
}

function page(body) {
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="referrer" content="no-referrer">'
    + '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; form-action \'self\'; base-uri \'none\'; frame-ancestors \'none\'">'
    + '<title>Sign in</title></head><body>' + body + '</body></html>';
}

function denialPage() {
  return page('<p>Login denied.</p>');
}

function donePage() {
  return page('<p>Signed in. Return to the client.</p>');
}

function validCode(value) {
  return typeof value === 'string' && value.length >= 16 && value.length <= 256;
}

async function memberUser(registry, username) {
  if (typeof username !== 'string' || !USER_RE.test(username)) return null;
  const rows = await registry.membershipsForUser(username);
  if (!rows || rows.length === 0) return null;
  return username;
}

function countPendingSync(registry, userId, now) {
  ensure(registry);
  let n = 0;
  for (const row of registry.oauthDevices.values()) {
    if (row.user_id === userId && row.status === 'pending' && atMs(row.expires_at) > now) n += 1;
  }
  return n;
}

async function insertDevice(registry, row, now) {
  if (!registry.pool) {
    ensure(registry);
    if (countPendingSync(registry, row.user_id, now) >= PENDING_CAP) throw http(429, 'slow_down');
    const stored = {
      device_hash: row.device_hash,
      user_code_hash: row.user_code_hash,
      user_id: row.user_id,
      status: 'pending',
      expires_at: row.expires_at,
      poll_after: row.poll_after,
      provider: null,
      state_hash: null
    };
    registry.oauthDevices.set(stored.device_hash, stored);
    registry.oauthByUserCode.set(stored.user_code_hash, stored);
    return;
  }
  const client = await registry.pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['oauth-device:' + row.user_id]);
    const count = await client.query(
      `SELECT count(*)::int AS n FROM cp_oauth_devices
       WHERE user_id = $1 AND status = 'pending' AND expires_at > $2`,
      [row.user_id, new Date(now).toISOString()]
    );
    if (count.rows[0].n >= PENDING_CAP) {
      await client.query('ROLLBACK');
      throw http(429, 'slow_down');
    }
    await client.query(
      `INSERT INTO cp_oauth_devices
        (device_hash, user_code_hash, user_id, status, expires_at, poll_after)
       VALUES ($1, $2, $3, 'pending', $4, $5)`,
      [row.device_hash, row.user_code_hash, row.user_id, row.expires_at, row.poll_after]
    );
    await client.query('COMMIT');
  } catch (err) {
    if (!err.status) {
      try { await client.query('ROLLBACK'); } catch { /* already closed */ }
      console.error('[control] oauth store failed:', err.code || 'oauth_store_failed');
      throw http(503, 'oauth_unavailable');
    }
    throw err;
  } finally {
    client.release();
  }
}

async function startDevice(registry, username, env, now = Date.now()) {
  const base = publicBase(env);
  const user = await memberUser(registry, username);
  if (!user) throw http(403, 'login_denied');
  const deviceCode = randomToken(32);
  const userCode = randomToken(32);
  await insertDevice(registry, {
    device_hash: fingerprint(deviceCode),
    user_code_hash: fingerprint(userCode),
    user_id: user,
    expires_at: new Date(now + DEVICE_TTL_MS).toISOString(),
    poll_after: new Date(now).toISOString()
  }, now);
  return {
    device_code: deviceCode,
    verification_url: base + '/oauth/device/verify?code=' + encodeURIComponent(userCode),
    expires_in: 600,
    interval: pollSeconds(env)
  };
}

async function deviceByHash(registry, hash) {
  if (!registry.pool) {
    ensure(registry);
    return registry.oauthDevices.get(hash) || null;
  }
  const res = await registry.pool.query(
    `SELECT device_hash, user_id, status, expires_at, poll_after, provider, state_hash
     FROM cp_oauth_devices WHERE device_hash = $1`,
    [hash]
  );
  return res.rows[0] || null;
}

async function deviceByUserCode(registry, code) {
  if (!validCode(code)) return null;
  const hash = fingerprint(code);
  if (!registry.pool) {
    ensure(registry);
    return registry.oauthByUserCode.get(hash) || null;
  }
  const res = await registry.pool.query(
    `SELECT device_hash, user_id, status, expires_at, poll_after, provider, state_hash
     FROM cp_oauth_devices WHERE user_code_hash = $1`,
    [hash]
  );
  return res.rows[0] || null;
}

async function deviceByState(registry, state) {
  if (!validCode(state)) return null;
  const hash = fingerprint(state);
  if (!registry.pool) {
    ensure(registry);
    return registry.oauthByState.get(hash) || null;
  }
  const res = await registry.pool.query(
    `SELECT device_hash, user_id, status, expires_at, poll_after, provider, state_hash
     FROM cp_oauth_devices WHERE state_hash = $1`,
    [hash]
  );
  return res.rows[0] || null;
}

async function linksFor(registry, userId) {
  if (!registry.pool) {
    ensure(registry);
    const out = [];
    for (const name of ['google', 'github']) {
      if (registry.oauthLinks.has(linkKey(userId, name))) out.push(name);
    }
    return out;
  }
  const res = await registry.pool.query(
    'SELECT provider FROM cp_oauth_links WHERE user_id = $1',
    [userId]
  );
  return res.rows.map((row) => row.provider).filter((name) => PROVIDERS[name]);
}

async function verifyPage(registry, code, env, now = Date.now()) {
  const row = await deviceByUserCode(registry, typeof code === 'string' ? code : '');
  if (!row || row.status !== 'pending' || atMs(row.expires_at) <= now) return denialPage();
  const names = [];
  const allowed = await linksFor(registry, row.user_id);
  for (const name of configuredNames(env)) {
    if (allowed.includes(name)) names.push(name);
  }
  const safeUser = escapeHtml(row.user_id);
  const safeCode = escapeHtml(code);
  let body = '<p>Sign in as <strong>' + safeUser + '</strong></p>'
    + '<form method="post" action="/oauth/device/verify">'
    + '<input type="hidden" name="code" value="' + safeCode + '">'
    + '<button type="submit">Yes</button></form>';
  for (const name of names) {
    const label = name === 'google' ? 'Google' : 'GitHub';
    body += '<form method="post" action="/oauth/device/verify">'
      + '<input type="hidden" name="code" value="' + safeCode + '">'
      + '<input type="hidden" name="provider" value="' + name + '">'
      + '<button type="submit">Continue with ' + label + '</button></form>';
  }
  return page(body);
}

async function markApproved(registry, deviceHash, now) {
  if (!registry.pool) {
    ensure(registry);
    const row = registry.oauthDevices.get(deviceHash);
    if (!row || row.status !== 'pending' || atMs(row.expires_at) <= now) return false;
    row.status = 'approved';
    return true;
  }
  const res = await registry.pool.query(
    `UPDATE cp_oauth_devices SET status = 'approved'
     WHERE device_hash = $1 AND status = 'pending' AND expires_at > $2`,
    [deviceHash, new Date(now).toISOString()]
  );
  return res.rowCount === 1;
}

async function approveUserCode(registry, code, now = Date.now()) {
  const row = await deviceByUserCode(registry, code);
  if (!row || row.status !== 'pending' || atMs(row.expires_at) <= now) throw http(403, 'login_denied');
  const ok = await markApproved(registry, row.device_hash, now);
  if (!ok) throw http(403, 'login_denied');
}

function authorizeUrl(cfg, redirectUri, state) {
  const url = new URL(cfg.authorize);
  url.searchParams.set('client_id', cfg.id);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', cfg.scope);
  url.searchParams.set('state', state);
  if (cfg.name === 'github') url.searchParams.set('allow_signup', 'false');
  const out = url.toString();
  if (!out.startsWith(cfg.authorize + '?') || out.includes(cfg.secret)) throw http(503, 'oauth_unavailable');
  return out;
}

async function beginExternal(registry, code, provider, env, now = Date.now()) {
  const cfg = configuredProvider(env, provider);
  if (!cfg) throw http(403, 'link_denied');
  const row = await deviceByUserCode(registry, code);
  if (!row || row.status !== 'pending' || atMs(row.expires_at) <= now) throw http(403, 'login_denied');
  const allowed = await linksFor(registry, row.user_id);
  if (!allowed.includes(provider)) throw http(403, 'link_denied');
  const base = publicBase(env);
  const state = randomToken(32);
  const stateHash = fingerprint(state);
  if (!registry.pool) {
    ensure(registry);
    const current = registry.oauthDevices.get(row.device_hash);
    if (!current || current.status !== 'pending' || atMs(current.expires_at) <= now) throw http(403, 'login_denied');
    if (current.state_hash) registry.oauthByState.delete(current.state_hash);
    current.provider = provider;
    current.state_hash = stateHash;
    registry.oauthByState.set(stateHash, current);
  } else {
    const res = await registry.pool.query(
      `UPDATE cp_oauth_devices SET provider = $2, state_hash = $3
       WHERE device_hash = $1 AND status = 'pending' AND expires_at > $4`,
      [row.device_hash, provider, stateHash, new Date(now).toISOString()]
    );
    if (res.rowCount !== 1) throw http(403, 'login_denied');
  }
  return authorizeUrl(cfg, base + '/oauth/' + provider + '/callback', state);
}

function subjectTakenSync(registry, provider, subject, exceptUser) {
  for (const other of registry.oauthLinks.values()) {
    if (other.provider !== provider || other.user_id === exceptUser) continue;
    if (typeof other.subject === 'string' && other.subject.length > 0 && tokenEqual(other.subject, subject)) {
      return true;
    }
  }
  return false;
}

function finishMemory(registry, input, now) {
  ensure(registry);
  const row = deviceByStateSync(registry, input.state);
  if (!row || row.status !== 'pending' || atMs(row.expires_at) <= now || row.provider !== input.provider) {
    throw http(403, 'link_denied');
  }
  const link = registry.oauthLinks.get(linkKey(row.user_id, input.provider));
  if (!link) throw http(403, 'link_denied');
  if (typeof link.subject === 'string' && link.subject.length > 0) {
    if (!tokenEqual(link.subject, input.subject)) throw http(403, 'link_denied');
  } else if (subjectTakenSync(registry, input.provider, input.subject, row.user_id)) {
    throw http(403, 'link_denied');
  } else {
    link.subject = input.subject;
  }
  if (row.status !== 'pending' || atMs(row.expires_at) <= now) throw http(403, 'link_denied');
  row.status = 'approved';
  return { user_id: row.user_id };
}

function deviceByStateSync(registry, state) {
  if (!validCode(state)) return null;
  return registry.oauthByState.get(fingerprint(state)) || null;
}

async function finishPg(registry, input, now) {
  const client = await registry.pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['oauth-subject:' + input.provider + ':' + fingerprint(input.subject)]);
    const found = await client.query(
      `SELECT device_hash, user_id, status, expires_at, provider
       FROM cp_oauth_devices WHERE state_hash = $1 FOR UPDATE`,
      [fingerprint(input.state)]
    );
    const row = found.rows[0];
    if (!row || row.status !== 'pending' || atMs(row.expires_at) <= now || row.provider !== input.provider) {
      await client.query('ROLLBACK');
      throw http(403, 'link_denied');
    }
    const link = await client.query(
      'SELECT subject FROM cp_oauth_links WHERE user_id = $1 AND provider = $2 FOR UPDATE',
      [row.user_id, input.provider]
    );
    if (link.rowCount !== 1) {
      await client.query('ROLLBACK');
      throw http(403, 'link_denied');
    }
    const current = link.rows[0].subject;
    if (typeof current === 'string' && current.length > 0) {
      if (!tokenEqual(current, input.subject)) {
        await client.query('ROLLBACK');
        throw http(403, 'link_denied');
      }
    } else {
      const others = await client.query(
        `SELECT subject FROM cp_oauth_links
         WHERE provider = $1 AND user_id <> $2 AND subject IS NOT NULL`,
        [input.provider, row.user_id]
      );
      const taken = others.rows.some((other) => typeof other.subject === 'string' && tokenEqual(other.subject, input.subject));
      if (taken) {
        await client.query('ROLLBACK');
        throw http(403, 'link_denied');
      }
      await client.query(
        `UPDATE cp_oauth_links SET subject = $3
         WHERE user_id = $1 AND provider = $2 AND subject IS NULL`,
        [row.user_id, input.provider, input.subject]
      );
    }
    const approved = await client.query(
      `UPDATE cp_oauth_devices SET status = 'approved'
       WHERE device_hash = $1 AND status = 'pending' AND expires_at > $2`,
      [row.device_hash, new Date(now).toISOString()]
    );
    if (approved.rowCount !== 1) {
      await client.query('ROLLBACK');
      throw http(403, 'link_denied');
    }
    await client.query('COMMIT');
    return { user_id: row.user_id };
  } catch (err) {
    if (!err.status) {
      try { await client.query('ROLLBACK'); } catch { /* already closed */ }
      console.error('[control] oauth store failed:', err.code || 'oauth_store_failed');
      throw http(503, 'oauth_unavailable');
    }
    throw err;
  } finally {
    client.release();
  }
}

async function completeExternal(registry, input, now = Date.now()) {
  const provider = input && input.provider;
  const subject = input && input.subject;
  const state = input && input.state;
  if (!PROVIDERS[provider] || typeof subject !== 'string' || !SUBJECT_RE.test(subject) || !validCode(state)) {
    throw http(403, 'link_denied');
  }
  if (!registry.pool) return finishMemory(registry, { provider, subject, state }, now);
  return finishPg(registry, { provider, subject, state }, now);
}

async function readCap(res) {
  if (!res || res.status >= 400) throw http(403, 'link_denied');
  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const step = await reader.read();
        if (step.done) break;
        const buf = Buffer.from(step.value);
        total += buf.length;
        if (total > RESPONSE_CAP) {
          await reader.cancel();
          throw http(403, 'link_denied');
        }
        chunks.push(buf);
      }
    } catch (err) {
      if (err.status) throw err;
      throw http(403, 'link_denied');
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  if (typeof res.text !== 'function') throw http(403, 'link_denied');
  const text = await res.text();
  if (typeof text !== 'string' || text.length > RESPONSE_CAP) throw http(403, 'link_denied');
  return text;
}

function externalSubject(provider, user) {
  if (provider === 'google') {
    const sub = user && user.sub;
    return typeof sub === 'string' && SUBJECT_RE.test(sub) ? sub : null;
  }
  const id = user && user.id;
  if (typeof id === 'number' && Number.isSafeInteger(id) && id > 0) return String(id);
  if (typeof id === 'string' && /^[0-9]{1,32}$/.test(id)) return id;
  return null;
}

async function exchangeExternal(fleet, input, now = Date.now()) {
  const provider = input && input.provider;
  const cfg = configuredProvider(fleet.env || {}, provider);
  if (!cfg || typeof fleet.oauthFetch !== 'function') throw http(403, 'link_denied');
  const code = input && input.code;
  if (typeof code !== 'string' || code.length < 1 || code.length > 2048) throw http(403, 'link_denied');
  const base = publicBase(fleet.env || {});
  const body = new URLSearchParams({
    client_id: cfg.id,
    client_secret: cfg.secret,
    code,
    redirect_uri: base + '/oauth/' + provider + '/callback',
    grant_type: 'authorization_code'
  });
  let tokenRes;
  try {
    tokenRes = await fleet.oauthFetch(cfg.token, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'systemapi-oauth'
      },
      body: body.toString(),
      redirect: 'error',
      signal: AbortSignal.timeout(5000)
    });
  } catch (err) {
    if (err.status) throw err;
    throw http(403, 'link_denied');
  }
  let tokenJson;
  try {
    tokenJson = JSON.parse(await readCap(tokenRes));
  } catch (err) {
    if (err.status) throw err;
    throw http(403, 'link_denied');
  }
  const access = tokenJson && tokenJson.access_token;
  if (typeof access !== 'string' || access.length < 1 || access.length > 4096) throw http(403, 'link_denied');
  let infoRes;
  try {
    infoRes = await fleet.oauthFetch(cfg.userinfo, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer ' + access,
        'User-Agent': 'systemapi-oauth'
      },
      redirect: 'error',
      signal: AbortSignal.timeout(5000)
    });
  } catch (err) {
    if (err.status) throw err;
    throw http(403, 'link_denied');
  }
  let info;
  try {
    info = JSON.parse(await readCap(infoRes));
  } catch (err) {
    if (err.status) throw err;
    throw http(403, 'link_denied');
  }
  const subject = externalSubject(provider, info);
  if (!subject) throw http(403, 'link_denied');
  return completeExternal(fleet.registry, { state: input.state, provider, subject }, now);
}

async function touchPoll(registry, deviceHash, when) {
  if (!registry.pool) {
    ensure(registry);
    const row = registry.oauthDevices.get(deviceHash);
    if (row) row.poll_after = when;
    return;
  }
  await registry.pool.query(
    'UPDATE cp_oauth_devices SET poll_after = $2 WHERE device_hash = $1',
    [deviceHash, when]
  );
}

async function consumeDevice(registry, deviceHash, tokenHash, expiresAt, now) {
  if (!registry.pool) {
    ensure(registry);
    const row = registry.oauthDevices.get(deviceHash);
    if (!row || row.status !== 'approved' || atMs(row.expires_at) <= now) return null;
    row.status = 'consumed';
    registry.oauthAccess.set(tokenHash, {
      token_hash: tokenHash,
      user_id: row.user_id,
      expires_at: expiresAt
    });
    return row.user_id;
  }
  const client = await registry.pool.connect();
  try {
    await client.query('BEGIN');
    const updated = await client.query(
      `UPDATE cp_oauth_devices SET status = 'consumed'
       WHERE device_hash = $1 AND status = 'approved' AND expires_at > $2
       RETURNING user_id`,
      [deviceHash, new Date(now).toISOString()]
    );
    if (updated.rowCount !== 1) {
      await client.query('ROLLBACK');
      return null;
    }
    await client.query(
      'INSERT INTO cp_oauth_access (token_hash, user_id, expires_at) VALUES ($1, $2, $3)',
      [tokenHash, updated.rows[0].user_id, expiresAt]
    );
    await client.query('COMMIT');
    return updated.rows[0].user_id;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* already closed */ }
    console.error('[control] oauth store failed:', err.code || 'oauth_store_failed');
    throw http(503, 'oauth_unavailable');
  } finally {
    client.release();
  }
}

async function pollToken(registry, deviceCode, env, now = Date.now()) {
  if (!validCode(deviceCode)) throw http(400, 'invalid_grant');
  const row = await deviceByHash(registry, fingerprint(deviceCode));
  if (!row) throw http(400, 'invalid_grant');
  if (atMs(row.expires_at) <= now) throw http(400, 'expired_token');
  const interval = pollSeconds(env);
  if (interval > 0 && now < atMs(row.poll_after)) {
    await touchPoll(registry, row.device_hash, new Date(now + interval * 1000).toISOString());
    throw http(400, 'slow_down');
  }
  if (interval > 0) await touchPoll(registry, row.device_hash, new Date(now + interval * 1000).toISOString());
  if (row.status === 'pending') throw http(400, 'authorization_pending');
  if (row.status === 'denied') throw http(400, 'access_denied');
  if (row.status !== 'approved') throw http(400, 'invalid_grant');
  const access = randomToken(32);
  const expiresAt = new Date(now + ACCESS_TTL_MS).toISOString();
  const userId = await consumeDevice(registry, row.device_hash, fingerprint(access), expiresAt, now);
  if (!userId) throw http(400, 'invalid_grant');
  return { access_token: access, token_type: 'Bearer', expires_in: 3600 };
}

async function userForAccessToken(registry, presented, now = Date.now()) {
  if (!registry || typeof presented !== 'string' || presented.length < 16 || presented.length > 512) return null;
  const hash = fingerprint(presented);
  if (!registry.pool) {
    ensure(registry);
    const row = registry.oauthAccess.get(hash);
    if (!row || atMs(row.expires_at) <= now) return null;
    return { user_id: row.user_id };
  }
  const res = await registry.pool.query(
    'SELECT user_id, expires_at FROM cp_oauth_access WHERE token_hash = $1',
    [hash]
  );
  const row = res.rows[0];
  if (!row || atMs(row.expires_at) <= now) return null;
  return { user_id: row.user_id };
}

async function createLink(registry, userId, provider) {
  if (provider !== 'google' && provider !== 'github') throw http(400, 'bad_provider');
  if (!registry.pool) {
    ensure(registry);
    const key = linkKey(userId, provider);
    if (!registry.oauthLinks.has(key)) {
      registry.oauthLinks.set(key, { user_id: userId, provider, subject: null });
    }
    const row = registry.oauthLinks.get(key);
    return { user_id: userId, provider, linked: typeof row.subject === 'string' && row.subject.length > 0 };
  }
  await registry.pool.query(
    `INSERT INTO cp_oauth_links (user_id, provider) VALUES ($1, $2)
     ON CONFLICT (user_id, provider) DO NOTHING`,
    [userId, provider]
  );
  const res = await registry.pool.query(
    `SELECT user_id, provider, (subject IS NOT NULL AND subject <> '') AS linked
     FROM cp_oauth_links WHERE user_id = $1 AND provider = $2`,
    [userId, provider]
  );
  return res.rows[0];
}

async function removeLink(registry, userId, provider) {
  if (provider !== 'google' && provider !== 'github') throw http(400, 'bad_provider');
  if (!registry.pool) {
    ensure(registry);
    return registry.oauthLinks.delete(linkKey(userId, provider));
  }
  const res = await registry.pool.query(
    'DELETE FROM cp_oauth_links WHERE user_id = $1 AND provider = $2',
    [userId, provider]
  );
  return res.rowCount === 1;
}

async function memberIds(registry, tenantIds) {
  if (!tenantIds || tenantIds.length === 0) return [];
  if (!registry.pool) {
    const allow = new Set(tenantIds);
    const ids = new Set();
    for (const member of registry.members || []) {
      if (allow.has(member.tenant_id)) ids.add(member.user_id);
    }
    return [...ids];
  }
  const res = await registry.pool.query(
    'SELECT DISTINCT user_id FROM cp_members WHERE tenant_id = ANY($1::text[])',
    [tenantIds]
  );
  return res.rows.map((row) => row.user_id);
}

async function listLinks(registry, userIds) {
  if (!userIds || userIds.length === 0) return [];
  if (!registry.pool) {
    ensure(registry);
    const allow = new Set(userIds);
    const out = [];
    for (const row of registry.oauthLinks.values()) {
      if (!allow.has(row.user_id)) continue;
      out.push({
        user_id: row.user_id,
        provider: row.provider,
        linked: typeof row.subject === 'string' && row.subject.length > 0
      });
    }
    out.sort((a, b) => (a.user_id + a.provider).localeCompare(b.user_id + b.provider));
    return out;
  }
  const res = await registry.pool.query(
    `SELECT user_id, provider, (subject IS NOT NULL AND subject <> '') AS linked
     FROM cp_oauth_links WHERE user_id = ANY($1::text[])
     ORDER BY user_id, provider`,
    [userIds]
  );
  return res.rows;
}

module.exports = {
  DEVICE_GRANT,
  publicBase,
  startDevice,
  verifyPage,
  approveUserCode,
  beginExternal,
  completeExternal,
  exchangeExternal,
  pollToken,
  userForAccessToken,
  createLink,
  removeLink,
  memberIds,
  listLinks,
  denialPage,
  donePage
};
