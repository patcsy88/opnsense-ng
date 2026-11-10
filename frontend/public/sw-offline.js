// Imported by the generated service worker. When a page navigation cannot reach the
// network, show the static offline page. It contains no firewall data, and /api is
// never cached or intercepted here.
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.mode !== "navigate") return;
  event.respondWith(
    fetch(req).catch(async () => {
      const cached = await caches.match("/offline.html", { ignoreSearch: true });
      return cached ?? Response.error();
    }),
  );
});
