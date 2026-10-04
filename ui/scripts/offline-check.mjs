#!/usr/bin/env node
/**
 * Offline check (R5): scan dist/ for anything that could make the browser touch the network.
 *
 *   node scripts/offline-check.mjs [--strict] [dist-dir]
 *
 * FAIL (exit 1):
 *   - any absolute http(s)/ws(s)/protocol-relative URL in index.html or CSS (src/href/url()/@import)
 *   - any CDN / font-host URL anywhere in JS (jsdelivr, unpkg, cdnjs, googleapis, gstatic, cloudflare, …)
 *   - dev-mock code or the mock header leaking into the production bundle
 * --strict additionally FAILs on every JS URL whose host is not on the "inert reference" list
 *   (W3C namespaces, docs links embedded as text by React/Monaco/ECharts — never fetched).
 * Always prints a host summary so a human can review.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

const args = process.argv.slice(2);
const strict = args.includes("--strict");
const root = resolve(args.find((a) => !a.startsWith("--")) ?? "dist");

const INERT = [
  "www.w3.org", "w3.org", "react.dev", "reactjs.org", "fb.me", "github.com", "developer.mozilla.org", "mozilla.org",
  "microsoft.com", "aka.ms", "code.visualstudio.com", "echarts.apache.org", "apache.org", "localhost", "127.0.0.1",
  "example.com", "json-schema.org", "schemas.microsoft.com", "unicode.org", "tc39.es", "whatwg.org", "ecma-international.org",
  "mathiasbynens.be", "stackoverflow.com", "npmjs.com", "gist.github.com", "bugs.chromium.org", "crbug.com", "webkit.org",
  "datatracker.ietf.org", "tools.ietf.org", "wikipedia.org", "en.wikipedia.org", "w3schools.com", "dojotoolkit.org"
];
const CDN = /(^|\.)(jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|cloudflare\.com|googleapis\.com|gstatic\.com|googletagmanager\.com|google-analytics\.com|bootstrapcdn\.com|fontawesome\.com|typekit\.net|jquery\.com|azureedge\.net|cloudfront\.net|fastly\.net|akamaized\.net|sentry\.io|segment\.io|hotjar\.com)$/i;
const LEAK = [/ULPF dev-mock/i, /x-ulpf-mock["'`]?\s*[,:)]\s*["'`]?1/i, /dev-mock\//];

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

let files;
try { files = walk(root); } catch { console.error(`✗ ${root} not found — run \`pnpm build\` first.`); process.exit(2); }

const URL_RE = /(?:https?|wss?):\/\/[^\s"'`)<>\\,;]+|(?<=["'(=\s])\/\/[a-z0-9.-]+\.[a-z]{2,}\/[^\s"'`)<>\\]*/gi;
const failures = [];
const hosts = new Map();
const hostOf = (u) => { try { return new URL(u.startsWith("//") ? "https:" + u : u).hostname; } catch { return null; } };
const inert = (h) => INERT.some((i) => h === i || h.endsWith("." + i));

for (const f of files) {
  const ext = extname(f).toLowerCase();
  if (![".html", ".css", ".js", ".mjs", ".json", ".svg", ".map", ".webmanifest"].includes(ext)) continue;
  const text = readFileSync(f, "utf8");
  const rel = relative(root, f);
  const markup = ext === ".html" || ext === ".css";
  for (const m of text.matchAll(URL_RE)) {
    const u = m[0];
    const h = hostOf(u);
    if (!h) continue;
    hosts.set(h, (hosts.get(h) ?? 0) + 1);
    const ctx = text.slice(Math.max(0, m.index - 40), m.index + Math.min(u.length, 80)).replace(/\s+/g, " ");
    if (markup && !/^(www\.)?w3\.org$/.test(h) && !(ext === ".svg")) failures.push({ rel, why: "external URL in " + ext.slice(1), u, ctx });
    else if (CDN.test(h)) failures.push({ rel, why: "CDN / third-party host", u, ctx });
    else if (strict && !inert(h)) failures.push({ rel, why: "non-inert host (strict)", u, ctx });
  }
  if (ext === ".js" || ext === ".mjs") for (const re of LEAK) if (re.test(text)) failures.push({ rel, why: `mock leak (${re})`, u: "", ctx: "" });
  if (ext === ".html" && /<script[^>]+src=["']https?:/i.test(text)) failures.push({ rel, why: "external <script>", u: "", ctx: "" });
}

const size = files.reduce((a, f) => a + statSync(f).size, 0);
console.log(`ULPF offline check · ${files.length} files · ${(size / 1048576).toFixed(1)} MiB in ${root}`);
if (hosts.size) {
  console.log("\nURL hosts found in bundle (text only unless listed under FAIL):");
  for (const [h, n] of [...hosts].sort((a, b) => b[1] - a[1])) console.log(`  ${inert(h) ? "·" : "?"} ${h}  ×${n}`);
}
if (failures.length) {
  console.error(`\n✗ ${failures.length} problem(s):`);
  const seen = new Set();
  for (const f of failures) {
    const k = f.rel + f.why + f.u;
    if (seen.has(k)) continue;
    seen.add(k);
    console.error(`  - ${f.rel}: ${f.why}${f.u ? `\n      ${f.u}\n      …${f.ctx}…` : ""}`);
  }
  process.exit(1);
}
console.log("\n✓ no external fetch targets in dist/ — safe for air-gapped delivery");
