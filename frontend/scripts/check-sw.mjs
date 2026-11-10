// Post-build guard: the generated service worker must not cache anything under /api.
import { readFileSync, readdirSync } from "node:fs";

const dist = "dist";
const sw = readFileSync(`${dist}/sw.js`, "utf8");
const errors = [];

// Precache manifest: static assets only, never /api.
const urls = [...sw.matchAll(/url:\s*"([^"]+)"/g)].map((m) => m[1]);
if (urls.length === 0) errors.push("no precache entries found");
for (const u of urls) {
  if (u.includes("api/") || u.startsWith("/api")) errors.push(`precache entry touches api: ${u}`);
}

// Runtime caching: the only allowed route for /api is NetworkOnly; no cache-backed strategies at all.
for (const strat of ["CacheFirst", "StaleWhileRevalidate", "NetworkFirst"]) {
  if (new RegExp(`\\b${strat}\\b`).test(sw)) errors.push(`service worker uses ${strat}`);
}
if (!/NetworkOnly/.test(sw)) errors.push("explicit NetworkOnly route for /api missing");
if (!/denylist/.test(sw)) errors.push("navigation fallback denylist for /api missing");
if (!sw.includes("sw-offline.js")) errors.push("offline handler not imported");

const offline = readFileSync(`${dist}/sw-offline.js`, "utf8");
if (/\/api/.test(offline.replace(/\/\/.*$/gm, ""))) errors.push("offline handler references /api");
if (!readdirSync(dist).includes("offline.html")) errors.push("offline.html missing from dist");
if (!urls.includes("offline.html")) errors.push("offline.html is not precached");

if (errors.length) {
  console.error("Service worker check FAILED:\n- " + errors.join("\n- "));
  process.exit(1);
}
console.log(`Service worker check passed (${urls.length} precached static assets, no /api caching).`);
