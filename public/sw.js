const CACHE = 'fityanul-islam-app-v1';
const APP_SHELL = ['/', '/manifest.webmanifest', '/style.css', '/badge.jpg'];
self.addEventListener('install', event => { event.waitUntil(caches.open(CACHE).then(c => c.addAll(APP_SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', event => { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  event.respondWith(fetch(event.request).then(response => {
    const copy = response.clone();
    caches.open(CACHE).then(c => c.put(event.request, copy)).catch(() => {});
    return response;
  }).catch(() => caches.match(event.request).then(r => r || caches.match('/'))));
});
