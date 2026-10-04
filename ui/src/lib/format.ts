export const nf = new Intl.NumberFormat("en-US");
export const fmtInt = (n: number | null | undefined) => (n == null ? "—" : nf.format(Math.round(n)));

export function fmtCompact(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "—";
  const a = Math.abs(n);
  if (a >= 1e12) return (n / 1e12).toFixed(2) + "T";
  if (a >= 1e9) return (n / 1e9).toFixed(2) + "B";
  if (a >= 1e6) return (n / 1e6).toFixed(2) + "M";
  if (a >= 1e4) return (n / 1e3).toFixed(1) + "k";
  if (a >= 100) return String(Math.round(n));
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${i === 0 ? v : v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
}

export const pct = (x: number | null | undefined, digits = 1) =>
  x == null || !Number.isFinite(x) ? "—" : `${(x * 100).toFixed(digits)}%`;

const p2 = (n: number) => String(n).padStart(2, "0");
/** SOC convention: everything in UTC. */
export function fmtClock(ms: number, withMs = true): string {
  const d = new Date(ms);
  const base = `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`;
  return withMs ? `${base}.${String(d.getUTCMilliseconds()).padStart(3, "0")}` : base;
}
export function fmtDate(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}`;
}
export const fmtDateTime = (ms: number) => `${fmtDate(ms)} ${fmtClock(ms, false)}Z`;

export function fmtAgo(ms: number | null | undefined, now = Date.now()): string {
  if (ms == null) return "never";
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

/** OCSF class names from the §6.2 table. Unknown uids render as "class N". */
export const CLASS_NAMES: Record<number, string> = {
  0: "Base Event",
  2004: "Detection Finding",
  3002: "Authentication",
  4001: "Network Activity",
  4002: "HTTP Activity",
  4003: "DNS Activity"
};
export const className = (uid: number) => CLASS_NAMES[uid] ?? `class ${uid}`;

export const SEVERITY_NAMES = ["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal"];
export const severityName = (id: number | null | undefined) => (id == null ? "—" : (SEVERITY_NAMES[id] ?? `sev ${id}`));
export const ACTION_NAMES: Record<number, string> = { 0: "Unknown", 1: "Allowed", 2: "Denied" };
export const actionName = (id: number | null | undefined) => (id == null ? "—" : (ACTION_NAMES[id] ?? `action ${id}`));

export function endpoint(ip: string | null, port: number | null): string {
  if (!ip) return "—";
  const v6 = ip.includes(":");
  return port != null ? (v6 ? `[${ip}]:${port}` : `${ip}:${port}`) : ip;
}

export const cx = (...a: (string | false | null | undefined)[]) => a.filter(Boolean).join(" ");
