import { useEffect, useRef, useState, type ReactNode } from "react";
import type { ExplainField, OcsfEvent } from "@/api/types";
import { cx, fmtDateTime } from "@/lib/format";
import { Icon } from "./ui/Icon";
import type { HlMeta } from "./RawView";

interface Ctx {
  explainByPath: Map<string, { id: string; f: ExplainField }>;
  meta: Map<string, HlMeta>;
  activeId: string | null;
  hoverId: string | null;
  onHover: (id: string | null) => void;
  onSelect: (id: string) => void;
  register: (id: string, el: HTMLElement | null) => void;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const TIME_KEYS = new Set(["time", "recv_time", "start_time", "end_time"]);

function Leaf({ k, path, v, ctx, depth }: { k: string; path: string; v: unknown; ctx: Ctx; depth: number }) {
  const hit = ctx.explainByPath.get(path);
  const m = hit ? ctx.meta.get(hit.id) : undefined;
  const hot = hit && (ctx.hoverId === hit.id || ctx.activeId === hit.id);
  const val =
    typeof v === "string" ? <span className="text-ink">{v}</span>
    : typeof v === "number" ? <span className="text-info num">{v}</span>
    : typeof v === "boolean" ? <span className="text-partial">{String(v)}</span>
    : v == null ? <span className="text-ink-3">null</span>
    : <span className="text-ink">{JSON.stringify(v)}</span>;
  return (
    <div ref={(el) => hit && ctx.register(hit.id, el)}
      onMouseEnter={() => hit && ctx.onHover(hit.id)} onMouseLeave={() => hit && ctx.onHover(null)} onClick={() => hit && ctx.onSelect(hit.id)}
      className={cx("group flex items-baseline gap-2 h-[24px] pr-2 rounded-[3px] mono text-[12px]", hit && "cursor-pointer", !hot && hit && "hover:bg-raised")}
      style={{ paddingLeft: 10 + depth * 14, background: hot && m ? m.color.tint : undefined, boxShadow: m ? `inset 2px 0 0 ${m.color.solid}` : "inset 2px 0 0 transparent" }}>
      <span className="text-ink-2 shrink-0">{k}</span>
      <span className="text-ink-3">:</span>
      <span className="truncate min-w-0">{val}</span>
      {typeof v === "number" && TIME_KEYS.has(k) && <span className="text-ink-3 text-[10.5px] shrink-0">{fmtDateTime(v)}</span>}
      {hit && hit.f.source_fields.length > 0 && <span className="ml-auto chip chip-neutral !h-[16px] !text-[9.5px] shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">{hit.f.source_fields.join(", ")}</span>}
    </div>
  );
}

function Node({ k, path, v, ctx, depth }: { k: string; path: string; v: unknown; ctx: Ctx; depth: number }) {
  const [open, setOpen] = useState(depth < 2);
  if (!isObj(v) && !Array.isArray(v)) return <Leaf k={k} path={path} v={v} ctx={ctx} depth={depth} />;
  const entries: [string, unknown][] = Array.isArray(v) ? v.map((x, i) => [String(i), x]) : Object.entries(v);
  return (
    <div>
      <button className="flex items-center gap-1.5 h-[24px] w-full text-left mono text-[12px] text-ink hover:bg-raised/70 rounded-[3px]" style={{ paddingLeft: 10 + depth * 14 - 2 }}
        onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <Icon name={open ? "chevD" : "chevR"} size={11} className="text-ink-3" />
        <span>{k}</span>
        <span className="text-ink-3 text-[10.5px]">{Array.isArray(v) ? `[${entries.length}]` : `{${entries.length}}`}</span>
      </button>
      {open && entries.map(([ck, cv]) => <Node key={ck} k={ck} path={`${path}.${ck}`} v={cv} ctx={ctx} depth={depth + 1} />)}
    </div>
  );
}

function Section({ title, count, children, tone }: { title: string; count: number; children: ReactNode; tone?: "warn" }) {
  return (
    <div className="border-b border-line last:border-0 py-2">
      <div className="px-3 pb-1 flex items-center gap-2">
        <span className="kicker">{title}</span>
        <span className={cx("chip !h-[16px]", tone === "warn" ? "chip-partial" : "chip-neutral")}>{count}</span>
      </div>
      {children}
    </div>
  );
}

export function OcsfTree({ doc, mapped, meta, activeId, hoverId, onHover, onSelect }: {
  doc: OcsfEvent;
  mapped: ExplainField[] | null;
  meta: Map<string, HlMeta>;
  activeId: string | null;
  hoverId: string | null;
  onHover: (id: string | null) => void;
  onSelect: (id: string) => void;
}) {
  const els = useRef(new Map<string, HTMLElement>());
  const explainByPath = new Map<string, { id: string; f: ExplainField }>();
  mapped?.forEach((f, i) => explainByPath.set(f.ocsf_path, { id: `f:${i}`, f }));
  const register = (id: string, el: HTMLElement | null) => { if (el) els.current.set(id, el); else els.current.delete(id); };
  const ctx: Ctx = { explainByPath, meta, activeId, hoverId, onHover, onSelect, register };

  // bring the pinned field into view when it was picked from the raw bytes
  useEffect(() => {
    if (activeId) els.current.get(activeId)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [activeId]);

  const { unmapped: um, ulpf: _ulpf, ...rest } = doc;
  void _ulpf;
  const mappedEntries = Object.entries(rest);
  const umEntries = Object.entries(um ?? {});

  return (
    <div>
      <Section title="Mapped · OCSF" count={mappedEntries.length}>
        {mappedEntries.map(([k, v]) => <Node key={k} k={k} path={k} v={v} ctx={ctx} depth={0} />)}
      </Section>
      <Section title="Unmapped · preserved" count={umEntries.length} tone={umEntries.length ? "warn" : undefined}>
        {umEntries.length === 0 && <div className="px-3 py-1.5 text-ink-3 text-[12px]">Every extracted field was mapped.</div>}
        {umEntries.map(([k, v]) => {
          const id = `u:${k}`;
          const m = meta.get(id);
          const hot = m && (hoverId === id || activeId === id);
          return (
            <div key={k} ref={(el) => register(id, el)} onMouseEnter={() => m && onHover(id)} onMouseLeave={() => m && onHover(null)} onClick={() => m && onSelect(id)}
              className={cx("flex items-baseline gap-2 h-[24px] px-3 mono text-[12px] rounded-[3px]", m && "cursor-pointer hover:bg-raised")}
              style={{ background: hot && m ? m.color.tint : undefined, boxShadow: m ? `inset 2px 0 0 ${m.color.solid}` : "inset 2px 0 0 transparent" }}>
              <span className="text-partial shrink-0">{k}</span><span className="text-ink-3">:</span>
              <span className="text-ink truncate">{typeof v === "string" ? v : JSON.stringify(v)}</span>
            </div>
          );
        })}
      </Section>
    </div>
  );
}
