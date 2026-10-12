const CACHE = 'systemapi-shell';
const SHELL = ['/', '/index.html', '/favicon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)));
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.url.includes('/api')) {
    event.respondWith(fetch(request));
    return;
  }
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => caches.match('/index.html').then((hit) => hit || caches.match('/')).then((hit) => hit || new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' } }))));
    return;
  }
  const path = new URL(request.url).pathname;
  if (SHELL.includes(path)) {
    event.respondWith(fetch(request).catch(() => caches.match(path).then((hit) => hit || new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' } }))));
  }
});
