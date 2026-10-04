import { memo, useMemo } from "react";
import { buildSegments, clampSpans, type HighlightItem } from "@/lib/spans";
import { cx } from "@/lib/format";

export interface HlMeta { id: string; label: string; color: { solid: string; tint: string; strong: string } }

interface Props {
  bytes: Uint8Array;
  items: HighlightItem[];
  meta: Map<string, HlMeta>;
  activeId: string | null; // pinned
  hoverId: string | null;
  onHover: (id: string | null) => void;
  onSelect: (id: string) => void;
  mode: "text" | "hex";
}

export const RawView = memo(function RawView({ bytes, items, meta, activeId, hoverId, onHover, onSelect, mode }: Props) {
  const segs = useMemo(() => buildSegments(bytes, items), [bytes, items]);
  const hot = hoverId ?? activeId;

  if (mode === "hex") return <HexView bytes={bytes} items={items} meta={meta} hot={hot} activeId={activeId} onHover={onHover} onSelect={onSelect} />;

  return (
    <pre className="mono text-[12.5px] leading-[1.9] whitespace-pre-wrap break-all text-ink-2 p-4 select-text m-0" aria-label="Raw event bytes">
      {segs.map((s) => {
        if (!s.ids.length) return <span key={s.start} className={s.escaped ? "raw-esc" : undefined}>{s.text}</span>;
        const m = meta.get(s.ids[0])!;
        const isHot = s.ids.includes(hot ?? "\0");
        const overlap = s.ids.length > 1;
        return (
          <span key={s.start} className={cx("raw-seg cursor-pointer text-ink", s.escaped && "raw-esc")}
            title={s.ids.map((i) => meta.get(i)?.label).join(" · ")}
            onMouseEnter={() => onHover(s.ids[0])} onMouseLeave={() => onHover(null)} onClick={() => onSelect(s.ids[0])}
            style={{
              background: isHot ? m.color.strong : m.color.tint,
              boxShadow: `inset 0 -2px 0 ${m.color.solid}${overlap ? `, inset 0 -5px 0 ${meta.get(s.ids[1])!.color.solid}` : ""}`,
              outline: s.ids[0] === activeId ? `1px solid ${m.color.solid}` : undefined
            }}>{s.text}</span>
        );
      })}
    </pre>
  );
});

const HEX_LIMIT = 4096;
function HexView({ bytes, items, meta, hot, activeId, onHover, onSelect }: {
  bytes: Uint8Array; items: HighlightItem[]; meta: Map<string, HlMeta>; hot: string | null; activeId: string | null;
  onHover: (id: string | null) => void; onSelect: (id: string) => void;
}) {
  const cover = useMemo(() => {
    const c: (string | null)[] = new Array(Math.min(bytes.length, HEX_LIMIT)).fill(null);
    for (const it of items) for (const s of clampSpans(it.spans, c.length)) for (let i = s.start; i < s.end; i++) if (c[i] == null) c[i] = it.id;
    return c;
  }, [bytes, items]);
  const n = Math.min(bytes.length, HEX_LIMIT);
  const rows = Math.ceil(n / 16);
  return (
    <div className="mono text-[11.5px] leading-[1.75] p-4 overflow-x-auto">
      {Array.from({ length: rows }, (_, r) => {
        const base = r * 16;
        return (
          <div key={r} className="flex gap-4 whitespace-pre">
            <span className="text-ink-3 w-[56px] shrink-0">{base.toString(16).padStart(8, "0")}</span>
            <span className="flex">
              {Array.from({ length: 16 }, (_, i) => {
                const o = base + i;
                if (o >= n) return <span key={i} className="w-[22px]" />;
                const id = cover[o];
                const m = id ? meta.get(id) : null;
                return (
                  <span key={i} className="w-[22px] text-center rounded-[2px] cursor-default"
                    onMouseEnter={() => id && onHover(id)} onMouseLeave={() => onHover(null)} onClick={() => id && onSelect(id)}
                    style={m ? { background: id === hot ? m.color.strong : m.color.tint, color: "rgb(var(--ink))", outline: id === activeId ? `1px solid ${m.color.solid}` : undefined } : { color: "rgb(var(--ink-3))" }}>
                    {bytes[o].toString(16).padStart(2, "0")}
                  </span>
                );
              })}
            </span>
            <span className="text-ink-3">
              {Array.from({ length: Math.min(16, n - base) }, (_, i) => {
                const b = bytes[base + i];
                return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·";
              })}
            </span>
          </div>
        );
      })}
      {bytes.length > HEX_LIMIT && <div className="mt-2 text-ink-3">… {bytes.length - HEX_LIMIT} more bytes (hex view shows first {HEX_LIMIT})</div>}
    </div>
  );
}
