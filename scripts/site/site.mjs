import { createServer } from 'node:http';
import { readFile, stat, readdir } from 'node:fs/promises';
import { resolve, extname, relative, sep } from 'node:path';

const root = resolve(process.argv[3] || 'site');
const mode = process.argv[2] || 'check';
const mime = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2','.txt':'text/plain; charset=utf-8','.xml':'application/xml'};
async function files(dir) {
  const result = [];
  for (const entry of await readdir(dir, {withFileTypes:true})) {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) result.push(...await files(path)); else result.push(path);
  }
  return result;
}
function localFile(pathname) {
  const target = resolve(root, '.' + pathname);
  if (relative(root, target).split(sep).includes('..')) throw new Error('Path outside site');
  return target;
}
if (mode === 'serve') {
  const port = Number(process.env.PORT || 4173);
  createServer(async (req, res) => {
    if (!['GET','HEAD'].includes(req.method)) { res.writeHead(405, {Allow:'GET, HEAD'}); return res.end(); }
    try {
      const url = new URL(req.url, 'http://localhost');
      const decoded = decodeURIComponent(url.pathname);
      if (decoded.split('/').some(part => part.startsWith('.') || part.includes('\\'))) { res.writeHead(404); return res.end(); }
      let target = localFile(decoded.endsWith('/') ? decoded + 'index.html' : decoded);
      try { await stat(target); } catch { if (!extname(target)) target += '.html'; }
      const data = await readFile(target);
      res.writeHead(200, {'Content-Type':mime[extname(target)] || 'application/octet-stream','X-Content-Type-Options':'nosniff','Cache-Control':'no-store'});
      res.end(req.method === 'HEAD' ? undefined : data);
    } catch {
      res.writeHead(404, {'Content-Type':'text/html; charset=utf-8'});
      res.end(req.method === 'HEAD' ? undefined : await readFile(resolve(root,'404.html')));
    }
  }).listen(port, '127.0.0.1', () => console.log(`Preview: http://127.0.0.1:${port} (${root})`));
} else if (mode === 'check') {
  const all = await files(root); let count = 0; const failures = [];
  for (const path of all.filter(path => path.endsWith('.html'))) {
    const body = await readFile(path,'utf8'); count++;
    const label = relative(root,path);
    const ids = [...body.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
    if (new Set(ids).size !== ids.length) failures.push(`${label}: duplicate ID`);
    if ((body.match(/<h1\b/g)||[]).length !== 1) failures.push(`${label}: expected one h1`);
    if (!body.includes('<html lang="en">') || !body.includes('name="description"')) failures.push(`${label}: missing page metadata`);
    const origin = body.match(/rel="canonical" href="([^\"]+)"/)?.[1];
    for (const match of body.matchAll(/\b(?:href|src)="([^"]+)"/g)) {
      const href = match[1];
      if (/^(mailto:|tel:|data:)/.test(href)) continue;
      const url = new URL(href, origin);
      if (url.origin !== new URL(origin).origin) continue;
      let target = localFile(url.pathname.endsWith('/') ? url.pathname+'index.html' : url.pathname);
      try {
        await stat(target);
        if (url.hash && target.endsWith('.html')) {
          const targetBody = await readFile(target,'utf8');
          if (!targetBody.includes(`id="${url.hash.slice(1)}"`) && !targetBody.includes(`id=${url.hash.slice(1)}`)) failures.push(`${label}: missing anchor ${href}`);
        }
      } catch { failures.push(`${label}: missing asset or page ${href}`); }
    }
  }
  if (failures.length) { console.error(failures.join('\n')); process.exitCode = 1; }
  else console.log(`Checked ${count} pages: local links, assets, anchors, titles, and IDs passed.`);
} else { console.error('Usage: node tools/site.mjs check|serve [site-directory]'); process.exitCode = 2; }
