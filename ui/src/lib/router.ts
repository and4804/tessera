import { useSyncExternalStore } from "react";

/** Tiny hash router: `#/explorer?q=src_ip%3A1.2.3.4`, `#/event/<id>`. No dependency, works from any static host. */
export interface Route {
  path: string;
  segments: string[];
  params: URLSearchParams;
}

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#/, "") || "/live";
  const [path, query = ""] = raw.split("?");
  return { path, segments: path.split("/").filter(Boolean).map(decodeURIComponent), params: new URLSearchParams(query) };
}

let cached: { hash: string; route: Route } | null = null;
function snapshot(): Route {
  const h = location.hash;
  if (!cached || cached.hash !== h) cached = { hash: h, route: parseHash(h) };
  return cached.route;
}
function subscribe(cb: () => void) {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
}
export const useRoute = (): Route => useSyncExternalStore(subscribe, snapshot, () => parseHash("#/live"));

export function href(path: string, params?: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  if (params) for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  const q = p.toString();
  return `#${path}${q ? `?${q}` : ""}`;
}
export function navigate(path: string, params?: Record<string, string | undefined>) {
  location.hash = href(path, params).slice(1);
}
export const eventHref = (id: string) => href(`/event/${encodeURIComponent(id)}`);
