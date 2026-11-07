'use strict';

// Shell for the device-login pages (/oauth/device/verify and the provider
// callbacks), in the SAH brand: sah.sh's "system" theme tokens, Atkinson +
// Fraunces italic, square marks, hairline rules, mono eyebrows.
//
// Threats: these pages approve logins, so the page stays inert. No script
// at all, no external request (fonts are vendored and served from
// /oauth/device/assets/), and the CSP allows exactly one inline <style>
// by its sha256, fonts from 'self', nothing else. Every interpolated value
// is escaped by the caller (controlplane/oauth.js escapeHtml); the heading
// and eyebrow passed to layout() are fixed strings, never user input.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ASSET_PREFIX = '/oauth/device/assets/';

const CSS = [
  "@font-face{font-family:Atkinson;src:url('" + ASSET_PREFIX + "atkinson-400.woff2') format('woff2');font-weight:400;font-display:swap}",
  "@font-face{font-family:Atkinson;src:url('" + ASSET_PREFIX + "atkinson-700.woff2') format('woff2');font-weight:700;font-display:swap}",
  "@font-face{font-family:Fraunces;src:url('" + ASSET_PREFIX + "fraunces-italic.woff2') format('woff2');font-style:italic;font-weight:100 900;font-display:swap}",
  ':root{--paper:#f3f1e9;--ink:#202b27;--muted:#56635b;--line:#cbd0c4;--accent:#b9e7dc;--accent-ink:#123e35;--panel:#e1eae6;--dark:#172f2d;--white:#fffef8;--danger:#9c3a1b;--danger-bg:#f6e4dc;--focus:#bd4b25;--bar-ink:#cbd5c9;'
    + "--mono:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;--sans:Atkinson,'Atkinson Hyperlegible',-apple-system,'Segoe UI',sans-serif;color-scheme:light}",
  '@media(prefers-color-scheme:dark){:root{--paper:#182820;--ink:#f0f1df;--muted:#b7c5b7;--line:#405246;--panel:#23392c;--dark:#0e1c15;--white:#21372a;--danger:#f2a184;--danger-bg:#2e2a1f;--focus:#e8825b;color-scheme:dark}}',
  '*{box-sizing:border-box}',
  'html{-webkit-text-size-adjust:100%}',
  'body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--paper);color:var(--ink);font:18px/1.55 var(--sans)}',
  'a{color:inherit;text-underline-offset:4px}a:hover{text-decoration-thickness:2px}',
  'button,input{font:inherit;color:inherit;border-radius:0}button{cursor:pointer}',
  'a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid var(--focus);outline-offset:4px}',
  '::selection{background:var(--accent);color:var(--accent-ink)}',
  '.wrap{width:min(1120px,calc(100% - 48px));margin:0 auto}',
  '.network{background:var(--dark);color:var(--bar-ink);font:11px/1.5 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:10px 0}',
  '.network .wrap{display:flex;justify-content:space-between;gap:20px;overflow-wrap:anywhere}',
  '.header{border-bottom:1px solid var(--line)}',
  '.nav{min-height:80px;display:flex;align-items:center;justify-content:space-between;gap:20px}',
  '.brand{font-size:25px;font-weight:700;letter-spacing:-1px;display:inline-flex;align-items:center;gap:12px;white-space:nowrap}',
  '.brand-mark{display:inline-grid;place-items:center;width:31px;height:31px;background:#172f2d;color:#b9e7dc;box-shadow:0 0 0 1px var(--line)}',
  '.brand-mark svg{width:23px;height:23px;display:block}',
  '.tag{font:11px/1.3 var(--mono);letter-spacing:.06em;text-transform:uppercase;padding:6px 9px;border:1px solid var(--line);background:var(--panel);white-space:nowrap}',
  'main{flex:1;padding:56px 0 80px}',
  '.column{width:min(660px,calc(100% - 48px));margin:0 auto;animation:arrive .5s both}',
  '@keyframes arrive{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}',
  '.steps{list-style:none;display:flex;margin:0 0 44px;padding:0;border:1px solid var(--line);font:11px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase}',
  '.steps li{flex:1;padding:11px 12px;color:var(--muted);border-right:1px solid var(--line);min-width:0}',
  '.steps li:last-child{border-right:0}',
  '.steps b{display:block;font-weight:400;margin-bottom:2px}',
  '.steps [aria-current=step]{background:var(--accent);color:var(--accent-ink)}',
  '.steps .past{color:var(--ink)}',
  '.eyebrow{font:11px/1.5 var(--mono);letter-spacing:.13em;text-transform:uppercase;display:flex;gap:10px;align-items:center;margin:0 0 18px}',
  ".eyebrow:before{content:'';width:7px;height:7px;background:currentColor;flex:none}",
  '.tone-danger .eyebrow{color:var(--danger)}',
  'h1{font-size:clamp(36px,6vw,54px);line-height:1.04;letter-spacing:-.045em;font-weight:700;margin:0 0 30px}',
  'h1 em{font-family:Fraunces,Georgia,serif;font-weight:420;letter-spacing:-.03em}',
  '.card{background:var(--white);border:1px solid var(--line);padding:28px}',
  '.card>:first-child{margin-top:0}.card>:last-child{margin-bottom:0}',
  '.card p{margin:0 0 18px}',
  '.lede{color:var(--muted)}',
  'code{font:.88em var(--mono);background:var(--panel);padding:1px 5px;border:1px solid var(--line)}',
  '.whoami{font-size:16px;padding:14px 16px;background:var(--panel);border:1px solid var(--line);margin:0 0 22px}',
  '.facts{list-style:none;margin:0 0 22px;padding:0;border-top:1px solid var(--line)}',
  '.facts li{display:grid;grid-template-columns:96px minmax(0,1fr);gap:14px;padding:12px 0;border-bottom:1px solid var(--line);font:12px/1.6 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}',
  '.facts strong{font:15px/1.5 var(--mono);letter-spacing:0;text-transform:none;color:var(--ink);overflow-wrap:anywhere}',
  '.notice{background:var(--panel);border-left:3px solid var(--ink);padding:16px 20px;margin:0 0 18px;font-size:16px}',
  '.card .notice p{margin:0}',
  '.notice.danger{background:var(--danger-bg);border-left-color:var(--danger)}',
  '.notice.danger strong{color:var(--danger)}',
  'label{display:block;font:11px/1.5 var(--mono);letter-spacing:.13em;text-transform:uppercase;margin:0 0 10px}',
  '.code{display:block;width:100%;margin:10px 0 0;padding:14px 16px;background:var(--paper);border:1px solid var(--ink);font:600 clamp(26px,8vw,36px)/1.2 var(--mono);letter-spacing:.16em;text-transform:uppercase;text-align:center}',
  '.code:focus{background:var(--white)}',
  '.hint{font:12px/1.6 var(--mono);color:var(--muted);margin:10px 0 22px}',
  '.actions{display:flex;flex-direction:column;align-items:stretch;gap:10px;margin-top:22px}',
  '.actions form{margin:0}',
  '.button{display:flex;width:100%;align-items:center;justify-content:space-between;gap:24px;background:var(--ink);color:var(--paper);padding:14px 20px;text-decoration:none;border:1px solid var(--ink);font-size:16px;font-weight:700;line-height:1.3;text-align:left;transition:transform .15s}',
  ".button:after{content:'\\2192';font-size:19px}",
  '.button:hover{transform:translateY(-2px)}',
  '.button.secondary{background:transparent;color:var(--ink)}',
  '.signout{margin-top:26px;padding-top:18px;border-top:1px solid var(--line)}',
  '.signout form{margin:0}',
  '.signout button{background:none;border:0;padding:0;font:12px/1.5 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);text-decoration:underline;text-underline-offset:4px}',
  '.small{font:12px/1.6 var(--mono);color:var(--muted);margin:22px 0 0}',
  '.footer{border-top:1px solid var(--line);padding:20px 0 24px}',
  '.footer .wrap{display:flex;justify-content:space-between;gap:12px 20px;flex-wrap:wrap;font:11px/1.5 var(--mono);color:var(--muted)}',
  '@media(max-width:600px){body{font-size:17px}.wrap,.column{width:calc(100% - 32px)}.network .wrap>span:last-child{display:none}.nav{min-height:68px}.brand{font-size:22px}main{padding:32px 0 56px}.steps{margin-bottom:32px}.steps li{padding:9px 8px;font-size:10px}.card{padding:20px}.facts li{grid-template-columns:1fr;gap:2px}}',
  '@media(max-width:360px){.tag{display:none}}',
  '@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}'
].join('');

const STYLE_HASH = 'sha256-' + crypto.createHash('sha256').update(CSS, 'utf8').digest('base64');

// One policy for the meta tag and the header (controlplane/router.js noStore).
// Browsers ignore frame-ancestors in <meta>; the header carries it.
const CSP = "default-src 'none'; style-src '" + STYLE_HASH + "'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

const MARK = '<span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 64 64" focusable="false">'
  + '<path d="m15 19 13 13-13 13m20 0h15" fill="none" stroke="currentColor" stroke-width="5"/></svg></span>';

const STEPS = ['Sign in', 'Enter code', 'Confirm'];

function stepsHtml(step) {
  if (!step) return '';
  let out = '<ol class="steps" aria-label="Login steps">';
  STEPS.forEach((name, i) => {
    const n = i + 1;
    const attr = n === step ? ' aria-current="step"' : (n < step ? ' class="past"' : '');
    out += '<li' + attr + '><b>0' + n + '</b>' + name + '</li>';
  });
  return out + '</ol>';
}

// opts: { title, eyebrow, heading, step (1-3), tone ('danger') }. title,
// eyebrow and heading are fixed strings from controlplane/oauth.js.
function layout(body, opts = {}) {
  const title = opts.title || 'Sign in';
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta name="referrer" content="no-referrer">'
    + '<meta http-equiv="Content-Security-Policy" content="' + CSP + '">'
    + '<meta name="robots" content="noindex,nofollow">'
    + '<title>' + title + ' | SystemAPI</title>'
    + '<style>' + CSS + '</style></head><body>'
    + '<div class="network"><div class="wrap"><span>After Dark Systems / Service Automation Hub</span><span>Command-line login</span></div></div>'
    + '<header class="header"><div class="nav wrap"><span class="brand">' + MARK + 'SystemAPI</span>'
    + '<span class="tag">systemapi login</span></div></header>'
    + '<main id="main"><div class="column' + (opts.tone === 'danger' ? ' tone-danger' : '') + '">'
    + stepsHtml(opts.step)
    + (opts.eyebrow ? '<p class="eyebrow">' + opts.eyebrow + '</p>' : '')
    + (opts.heading ? '<h1>' + opts.heading + '</h1>' : '')
    + '<div class="card">' + body + '</div></div></main>'
    + '<footer class="footer"><div class="wrap"><span>&copy; 2026 After Dark Systems</span><span>Observe. Decide. Execute. Verify.</span></div></footer>'
    + '</body></html>';
}

// Only these files are served; the name is a key, never a path.
const ASSET_TYPES = {
  'atkinson-400.woff2': 'font/woff2',
  'atkinson-700.woff2': 'font/woff2',
  'fraunces-italic.woff2': 'font/woff2',
  'OFL-atkinson.txt': 'text/plain; charset=utf-8',
  'OFL-fraunces.txt': 'text/plain; charset=utf-8'
};
const ASSETS = new Map(Object.entries(ASSET_TYPES).map(([name, type]) => [
  name, { type, body: fs.readFileSync(path.join(__dirname, 'assets', name)) }
]));

function mountAssets(app) {
  app.get(ASSET_PREFIX + ':name', (req, res) => {
    const asset = ASSETS.get(req.params.name);
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.set('Cross-Origin-Resource-Policy', 'same-origin');
    if (!asset) {
      res.set('Cache-Control', 'no-store');
      res.status(404).json({ error: 'not_found' });
      return;
    }
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.type(asset.type).send(asset.body);
  });
}

module.exports = { CSS, STYLE_HASH, CSP, ASSET_PREFIX, layout, mountAssets };
