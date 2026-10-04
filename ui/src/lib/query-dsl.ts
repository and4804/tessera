/**
 * Client-side parser for the ULPF field-query DSL (IMPLEMENTATION_GUIDE §7.13):
 *
 *   src_ip:10.1.1.15 action:denied dst_port:22 -status:parsed bytes_out:>=1000 "free text"
 *
 * The SERVER is authoritative (it compiles to parameterized SQL over a field whitelist).
 * This parser exists to give instant feedback: token highlighting, validation and
 * autocomplete. It never builds SQL.
 *
 * Grammar (whitespace separated terms, implicit AND):
 *   term    := ['-'] ( field ':' [op] value | text )
 *   op      := '>=' | '<=' | '>' | '<'          (numeric / time fields only)
 *   value   := quoted | bare ; bare may be a comma list  22,2222   or a range  1000..5000
 *   text    := quoted | bare                    (free-text match against the raw message)
 */
import type { QueryField } from "@/api/types";

export type Op = "=" | ">" | ">=" | "<" | "<=";
export interface QIssue {
  start: number;
  end: number;
  level: "error" | "warning";
  message: string;
}
export interface QTerm {
  kind: "field" | "text";
  start: number;
  end: number;
  negated: boolean;
  field?: string;
  fieldEnd?: number; // index of the ':' (exclusive end of field name)
  op: Op;
  value: string;
  valueStart: number;
  quoted: boolean;
}
export interface ParseResult {
  terms: QTerm[];
  issues: QIssue[];
}

const FIELD_START = /[A-Za-z_]/;
const FIELD_CHAR = /[A-Za-z0-9_.]/;

export function isIPv4(s: string): boolean {
  const p = s.split(".");
  if (p.length !== 4) return false;
  return p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255);
}
export function isIPv6(s: string): boolean {
  if (!/^[0-9A-Fa-f:.]+$/.test(s) || !s.includes(":")) return false;
  if (s.split("::").length > 2) return false;
  if ((s.startsWith(":") && !s.startsWith("::")) || (s.endsWith(":") && !s.endsWith("::"))) return false;
  const groups = s.split(":").filter((g) => g !== "");
  if (!groups.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g) || isIPv4(g))) return false;
  const count = groups.length + groups.filter((g) => g.includes(".")).length;
  return s.includes("::") ? count <= 7 : count === 8;
}
/** IPv4/IPv6, optional /prefix, optional trailing-wildcard octets (10.1.*). */
export function isIpish(s: string): boolean {
  const [addr, prefix, ...rest] = s.split("/");
  if (rest.length) return false;
  if (prefix !== undefined) {
    if (!/^\d{1,3}$/.test(prefix)) return false;
    const n = Number(prefix);
    if (n > (addr.includes(":") ? 128 : 32)) return false;
  }
  if (addr.includes("*")) return /^(\d{1,3}\.){1,3}\*$/.test(addr);
  return isIPv4(addr) || isIPv6(addr);
}

function lev(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)] as number[]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}
export function didYouMean(name: string, fields: QueryField[]): string | null {
  let best: string | null = null;
  let bd = 3;
  for (const f of fields) {
    const d = lev(name.toLowerCase(), f.name);
    if (d < bd) { bd = d; best = f.name; }
  }
  return best;
}

export function tokenize(input: string): { terms: QTerm[]; issues: QIssue[] } {
  const terms: QTerm[] = [];
  const issues: QIssue[] = [];
  const n = input.length;
  let i = 0;

  const readQuoted = (from: number): { value: string; end: number; closed: boolean } => {
    let j = from + 1;
    let out = "";
    while (j < n) {
      const ch = input[j];
      if (ch === "\\" && j + 1 < n) { out += input[j + 1]; j += 2; continue; }
      if (ch === '"') return { value: out, end: j + 1, closed: true };
      out += ch;
      j++;
    }
    return { value: out, end: n, closed: false };
  };

  while (i < n) {
    if (/\s/.test(input[i])) { i++; continue; }
    const start = i;
    let negated = false;
    if (input[i] === "-" && i + 1 < n && !/\s/.test(input[i + 1])) { negated = true; i++; }

    // field:value ?
    let k = i;
    if (k < n && FIELD_START.test(input[k])) {
      while (k < n && FIELD_CHAR.test(input[k])) k++;
    }
    if (k > i && input[k] === ":") {
      const field = input.slice(i, k);
      let p = k + 1;
      let op: Op = "=";
      const two = input.slice(p, p + 2);
      if (two === ">=" || two === "<=") { op = two; p += 2; }
      else if (input[p] === ">" || input[p] === "<") { op = input[p] as Op; p += 1; }
      let value = "";
      let quoted = false;
      let end = p;
      if (input[p] === '"') {
        const q = readQuoted(p);
        value = q.value; quoted = true; end = q.end;
        if (!q.closed) issues.push({ start: p, end, level: "error", message: "Unterminated quote" });
      } else {
        while (end < n && !/\s/.test(input[end])) end++;
        value = input.slice(p, end);
      }
      terms.push({ kind: "field", start, end, negated, field, fieldEnd: k, op, value, valueStart: p, quoted });
      i = end;
      continue;
    }

    // free text
    let value = "";
    let quoted = false;
    let end = i;
    if (input[i] === '"') {
      const q = readQuoted(i);
      value = q.value; quoted = true; end = q.end;
      if (!q.closed) issues.push({ start: i, end, level: "error", message: "Unterminated quote" });
    } else {
      while (end < n && !/\s/.test(input[end])) end++;
      value = input.slice(i, end);
    }
    terms.push({ kind: "text", start, end, negated, op: "=", value, valueStart: i, quoted });
    i = end;
  }
  return { terms, issues };
}

function checkScalar(t: QTerm, f: QueryField, v: string, at: number, issues: QIssue[]) {
  const bad = (message: string, level: QIssue["level"] = "error") =>
    issues.push({ start: at, end: at + Math.max(v.length, 1), level, message });
  switch (f.type) {
    case "ip":
      if (!isIpish(v)) bad(`"${v}" is not an IP address or CIDR`);
      break;
    case "int":
      if (!/^-?\d+$/.test(v)) bad(`"${v}" is not an integer`);
      else if ((f.name.endsWith("_port") || f.name === "src_port" || f.name === "dst_port") && (Number(v) < 0 || Number(v) > 65535))
        bad(`Port ${v} out of range 0–65535`);
      break;
    case "float":
      if (!/^-?\d+(\.\d+)?$/.test(v)) bad(`"${v}" is not a number`);
      break;
    case "time":
      if (!/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?Z?$/.test(v) && !/^\d{10,13}$/.test(v)) bad(`"${v}" is not a time (ISO-8601 or epoch)`);
      break;
    case "enum":
      if (f.enum && !f.enum.includes(v.toLowerCase())) bad(`"${v}" is not a known value (${f.enum.join(", ")})`, "warning");
      break;
    default:
      void t;
  }
}

export function parseQuery(input: string, fields: QueryField[]): ParseResult {
  const { terms, issues } = tokenize(input);
  const byName = new Map(fields.map((f) => [f.name, f]));
  for (const t of terms) {
    if (t.kind === "text") {
      if (!t.value) issues.push({ start: t.start, end: t.end, level: "error", message: "Empty term" });
      continue;
    }
    const f = byName.get(t.field!);
    if (!f) {
      const dym = didYouMean(t.field!, fields);
      issues.push({
        start: t.start + (t.negated ? 1 : 0), end: t.fieldEnd!, level: "error",
        message: `Unknown field "${t.field}"${dym ? ` — did you mean ${dym}?` : ""}`
      });
      continue;
    }
    if (t.value === "") {
      issues.push({ start: t.start, end: t.end, level: "error", message: `Missing value for ${f.name}` });
      continue;
    }
    const numeric = f.type === "int" || f.type === "float" || f.type === "time";
    if (t.op !== "=" && !numeric)
      issues.push({ start: t.valueStart, end: t.valueStart + t.op.length, level: "error", message: `${t.op} only applies to numeric/time fields` });
    if (t.quoted) continue;
    // comma lists and a..b ranges
    if (numeric && t.op === "=" && /^-?\d+(\.\d+)?\.\.-?\d+(\.\d+)?$/.test(t.value)) continue;
    let offset = t.valueStart + (t.op === "=" ? 0 : t.op.length);
    for (const part of t.value.split(",")) {
      if (part === "") issues.push({ start: offset, end: offset + 1, level: "error", message: "Empty list item" });
      else checkScalar(t, f, part, offset, issues);
      offset += part.length + 1;
    }
  }
  return { terms, issues };
}

export interface Completion {
  label: string;
  insert: string;
  detail?: string;
  kind: "field" | "value";
}
export interface CompletionContext {
  kind: "field" | "value" | "none";
  field?: string;
  prefix: string;
  start: number; // replace range in the input
  end: number;
}

/** Work out what the caret is completing. */
export function contextAt(input: string, caret: number): CompletionContext {
  let s = caret;
  while (s > 0 && !/\s/.test(input[s - 1])) s--;
  let e = caret;
  while (e < input.length && !/\s/.test(input[e])) e++;
  let word = input.slice(s, caret);
  let ws = s;
  if (word.startsWith("-")) { word = word.slice(1); ws += 1; }
  // inside an open quote => nothing to complete
  const quotes = (input.slice(0, caret).match(/(?<!\\)"/g) ?? []).length;
  if (quotes % 2 === 1) return { kind: "none", prefix: "", start: caret, end: caret };
  const colon = word.indexOf(":");
  if (colon >= 0) {
    let vp = word.slice(colon + 1);
    let vs = ws + colon + 1;
    const op = /^(>=|<=|>|<)/.exec(vp);
    if (op) { vp = vp.slice(op[0].length); vs += op[0].length; }
    const comma = vp.lastIndexOf(",");
    if (comma >= 0) { vs += comma + 1; vp = vp.slice(comma + 1); }
    return { kind: "value", field: word.slice(0, colon), prefix: vp, start: vs, end: Math.max(e, caret) };
  }
  if (word === "" && s !== caret) return { kind: "none", prefix: "", start: caret, end: caret };
  return { kind: "field", prefix: word, start: ws, end: Math.max(e, caret) };
}

export function suggest(
  input: string,
  caret: number,
  fields: QueryField[],
  dynamicValues: string[] = []
): { ctx: CompletionContext; items: Completion[] } {
  const ctx = contextAt(input, caret);
  if (ctx.kind === "field") {
    const p = ctx.prefix.toLowerCase();
    const items = fields
      .filter((f) => f.name.includes(p))
      .sort((a, b) => Number(b.name.startsWith(p)) - Number(a.name.startsWith(p)) || a.name.localeCompare(b.name))
      .slice(0, 10)
      .map<Completion>((f) => ({ label: f.name, insert: f.name + ":", detail: f.description ?? f.type, kind: "field" }));
    return { ctx, items };
  }
  if (ctx.kind === "value") {
    const f = fields.find((x) => x.name === ctx.field);
    const p = ctx.prefix.toLowerCase();
    const pool = [...(f?.enum ?? []), ...dynamicValues];
    const seen = new Set<string>();
    const items: Completion[] = [];
    for (const v of pool) {
      if (seen.has(v) || !v.toLowerCase().startsWith(p) || v === ctx.prefix) continue;
      seen.add(v);
      items.push({ label: v, insert: /\s/.test(v) ? `"${v}"` : v, kind: "value", detail: f?.type });
      if (items.length >= 10) break;
    }
    return { ctx, items };
  }
  return { ctx, items: [] };
}

export function applyCompletion(input: string, ctx: CompletionContext, c: Completion): { text: string; caret: number } {
  const text = input.slice(0, ctx.start) + c.insert + input.slice(ctx.end);
  return { text, caret: ctx.start + c.insert.length };
}
