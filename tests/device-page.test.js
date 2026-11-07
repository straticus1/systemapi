'use strict';

// The device-login pages approve logins: they must stay inert. A strict
// CSP (one inline style by hash, fonts from 'self', no script), no external
// URL anywhere, escaped interpolation, and only allowlisted font files.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const express = require('express');

const oauth = require('../controlplane/oauth');
const devicePage = require('../controlplane/devicepage');
const FleetManager = require('../playground/fleet');
const { mount } = require('../controlplane/router');
const { MemoryRegistry } = require('../controlplane/registry');

const CSRF = 'c'.repeat(43);
const USER = { id: 'sub-1', email: 'person@example.test' };
const ROW = {
  user_id: 'user-1',
  requester_ip: '203.0.113.9',
  requester_ua: 'cli-test/2.0',
  created_at: new Date('2026-11-07T15:04:05Z').toISOString(),
  fresh: false
};
const ENV = {
  SYSTEMAPI_GOOGLE_CLIENT_ID: 'g', SYSTEMAPI_GOOGLE_CLIENT_SECRET: 'g',
  SYSTEMAPI_GITHUB_CLIENT_ID: 'h', SYSTEMAPI_GITHUB_CLIENT_SECRET: 'h'
};

function linkedRegistry() {
  return {
    oauthDevices: new Map(), oauthByUserCode: new Map(), oauthByState: new Map(), oauthAccess: new Map(),
    oauthLinks: new Map([['user-1\0google', {}], ['user-1\0github', {}]])
  };
}

async function allPages() {
  return {
    sso: oauth.ssoPage(),
    entry: oauth.entryPage(USER, 'user-1', CSRF),
    entryNotice: oauth.entryPage(USER, 'user-1', CSRF, 'That code was not accepted (login_denied).'),
    confirm: await oauth.confirmPage(linkedRegistry(), ROW, 'BCDFGHJK', CSRF, ENV),
    confirmFresh: await oauth.confirmPage(linkedRegistry(), { ...ROW, fresh: true }, 'BCDFGHJK', CSRF, ENV),
    done: oauth.donePage(),
    denied: oauth.denialPage(),
    unbound: oauth.unboundPage(USER, CSRF)
  };
}

function directives(csp) {
  const out = new Map();
  for (const part of csp.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) out.set(name, values);
  }
  return out;
}

function assertStrict(csp) {
  const d = directives(csp);
  assert.deepEqual([...d.keys()].sort(), ['base-uri', 'default-src', 'font-src', 'form-action', 'frame-ancestors', 'style-src']);
  assert.deepEqual(d.get('default-src'), ["'none'"]);
  assert.deepEqual(d.get('form-action'), ["'self'"]);
  assert.deepEqual(d.get('base-uri'), ["'none'"]);
  assert.deepEqual(d.get('frame-ancestors'), ["'none'"]);
  assert.deepEqual(d.get('font-src'), ["'self'"]);
  assert.equal(d.get('style-src').length, 1);
  assert.match(d.get('style-src')[0], /^'sha256-[A-Za-z0-9+/]{43}='$/);
  assert.doesNotMatch(csp, /unsafe-|script-src|img-src|connect-src|\*|https?:|data:/);
}

test('the CSP is strict and allows exactly the one inline style by hash', () => {
  assertStrict(devicePage.CSP);
  const expected = 'sha256-' + crypto.createHash('sha256').update(devicePage.CSS, 'utf8').digest('base64');
  assert.equal(devicePage.STYLE_HASH, expected);
  assert.ok(devicePage.CSP.includes("'" + expected + "'"));
});

test('every device-login page carries the strict CSP, a matching style hash, and no script or external URL', async () => {
  for (const [name, html] of Object.entries(await allPages())) {
    assert.match(html, /^<!DOCTYPE html><html lang="en">/, name);
    assert.ok(html.includes('<meta name="referrer" content="no-referrer">'), name);
    const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
    assert.ok(meta, name);
    assert.equal(meta[1], devicePage.CSP, name);
    assertStrict(meta[1]);

    // Exactly one <style>, and the hash of what the browser sees matches.
    const styles = [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)];
    assert.equal(styles.length, 1, name);
    assert.equal((html.match(/<style/g) || []).length, 1, name);
    const seen = 'sha256-' + crypto.createHash('sha256').update(styles[0][1], 'utf8').digest('base64');
    assert.equal(seen, devicePage.STYLE_HASH, name);

    assert.equal(/<script/i.test(html), false, name);
    assert.equal(/\son[a-z]+\s*=/i.test(html), false, name);
    assert.equal(/style="/i.test(html), false, name);
    assert.equal(/<(img|iframe|object|embed|link|base)\b/i.test(html), false, name);
    // No absolute or protocol-relative URL anywhere, in markup or CSS.
    assert.equal(/https?:|\/\/[a-z0-9]|javascript:|data:/i.test(html), false, name);
    for (const m of html.matchAll(/\s(?:href|src|action)="([^"]*)"/g)) assert.match(m[1], /^\/(?!\/)/, name + ' ' + m[1]);
    for (const m of html.matchAll(/url\('([^']*)'\)/g)) assert.ok(m[1].startsWith(devicePage.ASSET_PREFIX), name + ' ' + m[1]);
  }
});

test('the security copy is still on the pages', async () => {
  const p = await allPages();
  assert.match(p.confirm, /A command-line client asked to sign in as <strong>user-1<\/strong>/);
  assert.match(p.confirm, /From IP: <strong>203\.0\.113\.9<\/strong>/);
  assert.match(p.confirm, /Client: <strong>cli-test\/2\.0<\/strong>/);
  assert.match(p.confirm, /Started: <strong>2026-11-07T15:04:05/);
  assert.match(p.confirm, /Only continue if you started this login yourself\./);
  assert.match(p.confirm, /Continue with Google/);
  assert.equal(p.confirm.includes('dangerous channel-policy changes'), false);
  assert.match(p.confirmFresh, /This code asks for a token that can make dangerous channel-policy changes \(root-equivalent grants, tenant-wide policy\)\.<\/strong> Approve it only for a change you are making now\./);
  assert.equal(p.confirmFresh.includes('Continue with Google'), false);
  assert.match(p.entry, /Type the code your command-line client shows\./);
  assert.match(p.entry, /Never type a code someone sent you\./);
  assert.match(p.entryNotice, /role="alert"[^]*That code was not accepted \(login_denied\)\./);
  assert.match(p.unbound, /Login denied \(login_denied\)\.[^]*is not bound to a SystemAPI member\. Ask an admin to bind it\./);
  assert.match(p.denied, /Login denied\./);
  assert.match(p.done, /Signed in\. Return to the client\./);
  assert.equal(p.sso.includes('<form'), false);
});

test('the code field is a labelled code input with autofill off (one-time-code would surface attacker-sent codes from SMS or mail) and the forms are unchanged', async () => {
  const p = await allPages();
  const input = /<label>Code <input ([^>]+)><\/label>/.exec(p.entry);
  assert.ok(input);
  for (const attr of ['name="user_code"', 'autocomplete="off"', 'autocapitalize="characters"', 'spellcheck="false"', 'inputmode="text"', 'maxlength="16"', 'required', 'aria-describedby="code-hint"']) {
    assert.ok(input[1].includes(attr), attr);
  }
  assert.ok(p.entry.includes('id="code-hint"'));
  for (const html of [p.entry, p.confirm, p.unbound]) {
    for (const m of html.matchAll(/<form ([^>]+)>/g)) assert.match(m[1], /^method="post" action="\/oauth\/(device\/verify|logout)"$/);
  }
  assert.equal((p.confirm.match(/name="confirm" value="yes"/g) || []).length, 1);
  assert.equal((p.confirm.match(/name="provider" value="(google|github)"/g) || []).length, 2);
});

test('every interpolated value is escaped', async () => {
  const evil = '<script>x()</script>"\'&';
  const escaped = '&lt;script&gt;x()&lt;/script&gt;&quot;&#39;&amp;';
  const row = { ...ROW, user_id: evil, requester_ip: evil, requester_ua: evil };
  const pages = [
    await oauth.confirmPage({}, row, 'BCDFGHJK', evil, {}),
    oauth.entryPage({ id: 's', email: evil }, evil, evil, evil),
    oauth.unboundPage({ id: 's', email: evil }, evil)
  ];
  for (const html of pages) {
    assert.equal(html.includes('<script>'), false);
    assert.equal(html.includes('"\'&'), false);
    assert.ok(html.includes(escaped));
  }
});

test('the control plane sends the same strict CSP header and serves only the allowlisted fonts', async (t) => {
  const app = express();
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test' };
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  mount(app, fm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const url = 'http://127.0.0.1:' + server.address().port;

  const pageRes = await fetch(url + '/oauth/device/verify');
  assert.equal(pageRes.status, 200);
  assert.equal(pageRes.headers.get('content-security-policy'), devicePage.CSP);
  assert.equal(pageRes.headers.get('cache-control'), 'no-store');
  assert.equal(pageRes.headers.get('referrer-policy'), 'no-referrer');
  assert.ok((await pageRes.text()).includes(devicePage.STYLE_HASH));

  for (const name of ['atkinson-400.woff2', 'atkinson-700.woff2', 'fraunces-italic.woff2']) {
    const res = await fetch(url + devicePage.ASSET_PREFIX + name);
    assert.equal(res.status, 200, name);
    assert.equal(res.headers.get('content-type'), 'font/woff2', name);
    assert.equal(res.headers.get('cache-control'), 'public, max-age=31536000, immutable', name);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff', name);
    const body = Buffer.from(await res.arrayBuffer());
    assert.ok(body.equals(fs.readFileSync(path.join(__dirname, '..', 'controlplane', 'assets', name))), name);
    assert.equal(body.subarray(0, 4).toString('latin1'), 'wOF2', name);
  }
  const license = await fetch(url + devicePage.ASSET_PREFIX + 'OFL-atkinson.txt');
  assert.equal(license.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.match(await license.text(), /SIL Open Font License/);

  for (const bad of ['site.css', '..%2Frouter.js', '%2E%2E%2Foauth.js', 'constructor', '__proto__', 'atkinson-400.woff2%00']) {
    const res = await fetch(url + devicePage.ASSET_PREFIX + bad);
    assert.equal(res.status, 404, bad);
    assert.equal(res.headers.get('cache-control'), 'no-store', bad);
  }
});
