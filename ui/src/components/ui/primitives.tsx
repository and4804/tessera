import { useId, useState, type CSSProperties, type ReactNode } from "react";
import { ApiError } from "@/api/client";
import type { EventStatus, SeriesPoint } from "@/api/types";
import { sourceColor } from "@/lib/color";
import { cx } from "@/lib/format";
import { Icon, type IconName } from "./Icon";

/* ── status + source ─────────────────────────────────────────────── */
const STATUS_ICON: Record<EventStatus, IconName> = { parsed: "check", partial: "drift", unparsed: "x" };
export function StatusChip({ status, compact }: { status: EventStatus; compact?: boolean }) {
  return (
    <span className={cx("chip", `chip-${status}`)} title={`status: ${status}`}>
      <Icon name={STATUS_ICON[status]} size={10} strokeWidth={2.4} />
      {!compact && status}
    </span>
  );
}

export function SourceBadge({ id }: { id: string }) {
  const short = id.includes(".") ? id.split(".").slice(1).join(".") : id;
  const vendor = id.includes(".") ? id.split(".")[0] : "";
  return (
    <span className="inline-flex items-center gap-1.5 min-w-0" title={id}>
      <span className="h-2 w-2 rounded-[2px] shrink-0" style={{ background: sourceColor(id) }} />
      <span className="truncate mono text-ink">{short}</span>
      {vendor && <span className="mono text-ink-3 hidden xl:inline">{vendor}</span>}
    </span>
  );
}

/* ── loading / empty / error ─────────────────────────────────────── */
export function Skeleton({ className, style }: { className?: string; style?: CSSProperties }) {
  return <div className={cx("skeleton", className)} style={style} aria-hidden="true" />;
}

export function EmptyState({
  icon, title, children, action, tone = "neutral", className
}: { icon: IconName; title: string; children?: ReactNode; action?: ReactNode; tone?: "neutral" | "warn"; className?: string }) {
  return (
    <div className={cx("flex flex-col items-center justify-center text-center px-6 py-14 gap-3 animate-rise", className)}>
      <div className="relative grid place-items-center h-14 w-14">
        <span className="absolute inset-0 rounded-full border border-dashed border-line-strong animate-[spin_40s_linear_infinite]" />
        <span className={cx("grid place-items-center h-9 w-9 rounded-full border", tone === "warn" ? "border-partial/40 text-partial bg-partial/10" : "border-line-strong text-ink-2 bg-raised")}>
          <Icon name={icon} size={17} />
        </span>
      </div>
      <h3 className="font-display text-[19px] leading-tight text-ink">{title}</h3>
      {children && <p className="text-ink-2 max-w-md text-[13px]">{children}</p>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, className, what }: { error: unknown; onRetry?: () => void; className?: string; what?: string }) {
  const e = error instanceof ApiError ? error : null;
  const down = e?.isNetwork;
  const notFound = e?.status === 404;
  return (
    <EmptyState
      className={className}
      icon={down ? "plug" : "alert"}
      tone="warn"
      title={down ? "Can't reach the ULPF API" : notFound ? `${what ?? "Resource"} not found` : "Request failed"}
      action={onRetry && <button className="btn" onClick={onRetry}><Icon name="refresh" size={13} />Retry</button>}
    >
      {down ? (
        <>The UI only shows live data from the node, so there is nothing to display until it answers. Start it with <code className="mono text-ink">ulpf run</code> and this page will recover on its own.</>
      ) : (
        <>
          <span className="mono text-ink">{e ? `${e.status} ${e.code}` : "error"}</span>
          <br />
          {e?.message ?? (error instanceof Error ? error.message : "Unknown error")}
        </>
      )}
    </EmptyState>
  );
}

/* ── layout ──────────────────────────────────────────────────────── */
export function PageHeader({ index, title, accent, sub, right }: { index: string; title: string; accent?: string; sub?: ReactNode; right?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-3 md:gap-6 px-4 md:px-8 pt-4 md:pt-7 pb-4 md:pb-5 animate-rise">
      <div className="min-w-0">
        <div className="kicker flex items-center gap-2"><span className="text-signal">§{index}</span><span className="h-px w-8 bg-line-strong" />ULPF / Rosetta</div>
        <h1 className="text-[26px] md:text-[34px] leading-[1.05] mt-1.5">
          {title}{accent && <> <em className="italic text-signal/95 font-light">{accent}</em></>}
        </h1>
        {sub && <p className="text-ink-2 mt-1.5 max-w-2xl">{sub}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">{right}</div>
    </header>
  );
}

export function Panel({ title, kicker, right, children, className, bodyClass, ticks = true }: {
  title?: ReactNode; kicker?: string; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; ticks?: boolean;
}) {
  return (
    <section className={cx("panel", ticks && "ticks", "flex flex-col min-h-0", className)}>
      {(title || right) && (
        <div className="panel-head">
          <div className="min-w-0 flex items-baseline gap-2.5">
            {kicker && <span className="kicker">{kicker}</span>}
            {title && <h2 className="text-[15px] text-ink truncate">{title}</h2>}
          </div>
          <div className="ml-auto flex items-center gap-2">{right}</div>
        </div>
      )}
      <div className={cx("min-h-0 flex-1", bodyClass)}>{children}</div>
    </section>
  );
}

/* ── metrics ─────────────────────────────────────────────────────── */
export function Stat({ label, value, unit, sub, tone, big }: { label: string; value: ReactNode; unit?: string; sub?: ReactNode; tone?: "ok" | "warn" | "bad"; big?: boolean }) {
  const color = tone === "ok" ? "text-parsed" : tone === "warn" ? "text-partial" : tone === "bad" ? "text-unparsed" : "text-ink";
  return (
    <div className="min-w-0">
      <div className="kicker">{label}</div>
      <div className={cx("font-display num leading-none mt-1.5 flex items-baseline gap-1.5", big ? "text-[44px]" : "text-[26px]", color)}>
        {value}{unit && <span className="text-ink-2 text-[13px] font-sans">{unit}</span>}
      </div>
      {sub && <div className="text-ink-3 text-[12px] mt-1">{sub}</div>}
    </div>
  );
}

/** Horizontal coverage meter with threshold ticks. value in 0..1 */
export function Meter({ value, goal, height = 6, className }: { value: number; goal?: number; height?: number; className?: string }) {
  const v = Math.max(0, Math.min(1, value));
  const tone = goal == null ? "bg-signal" : v >= goal ? "bg-parsed" : v >= goal * 0.6 ? "bg-partial" : "bg-unparsed";
  return (
    <div className={cx("relative w-full rounded-full bg-well border border-line overflow-hidden", className)} style={{ height }} role="meter" aria-valuenow={Math.round(v * 100)} aria-valuemin={0} aria-valuemax={100}>
      <div className={cx("absolute inset-y-0 left-0 rounded-full transition-[width] duration-500", tone)} style={{ width: `${v * 100}%` }} />
      {goal != null && <div className="absolute inset-y-0 w-px bg-ink/60" style={{ left: `${goal * 100}%` }} title={`target ${(goal * 100).toFixed(0)}%`} />}
    </div>
  );
}

/** Dense SVG sparkline with a hover readout. */
export function Sparkline({ data, width = 220, height = 44, tone = "signal", fmt = (n: number) => String(Math.round(n)), unit = "", className }: {
  data: (number | SeriesPoint)[]; width?: number; height?: number; tone?: string; fmt?: (n: number) => string; unit?: string; className?: string;
}) {
  const id = useId();
  const [hover, setHover] = useState<number | null>(null);
  const vals = data.map((d) => (typeof d === "number" ? d : d.v));
  if (vals.length < 2) return <div className={cx("text-ink-3 mono text-[11px]", className)} style={{ height }}>no series yet</div>;
  const max = Math.max(...vals, 1e-9);
  const pad = 3;
  const x = (i: number) => pad + (i / (vals.length - 1)) * (width - pad * 2);
  const y = (v: number) => height - pad - (v / max) * (height - pad * 2 - 6);
  const line = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = `${line}L${x(vals.length - 1)},${height}L${x(0)},${height}Z`;
  const hi = hover ?? vals.length - 1;
  const stroke = `rgb(var(--${tone}))`;
  return (
    <div className={cx("relative", className)} style={{ width: "100%", maxWidth: width }}>
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none"
        onMouseMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          setHover(Math.max(0, Math.min(vals.length - 1, Math.round(((e.clientX - r.left) / r.width) * (vals.length - 1)))));
        }}
        onMouseLeave={() => setHover(null)} role="img" aria-label={`series, latest ${fmt(vals[vals.length - 1])}${unit}`}>
        <defs>
          <linearGradient id={id} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" style={{ stopColor: stroke }} stopOpacity=".32" />
            <stop offset="1" style={{ stopColor: stroke }} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={area} style={{ fill: `url(#${id})` }} />
        <path d={line} fill="none" style={{ stroke }} strokeWidth="1.6" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
        {hover != null && <line x1={x(hover)} x2={x(hover)} y1={0} y2={height} style={{ stroke: "rgb(var(--ink-3))" }} strokeDasharray="2 3" vectorEffect="non-scaling-stroke" />}
        <circle cx={x(hi)} cy={y(vals[hi])} r="2.6" style={{ fill: stroke, stroke: "rgb(var(--panel))" }} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="absolute right-0 top-0 mono text-[10.5px] text-ink-2 num pointer-events-none">{fmt(vals[hi])}{unit}</div>
    </div>
  );
}

/* ── controls ────────────────────────────────────────────────────── */
export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: ReactNode }[]; label?: string }) {
  return (
    <div role="group" aria-label={label} className="inline-flex rounded-[6px] border border-line-strong bg-well p-0.5 gap-0.5">
      {options.map((o) => (
        <button key={o.value} aria-pressed={o.value === value} onClick={() => onChange(o.value)}
          className={cx("h-6 px-2.5 rounded-[4px] text-[12px] mono transition-colors", o.value === value ? "bg-signal text-[#10140a] font-semibold" : "text-ink-2 hover:text-ink hover:bg-raised")}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn btn-ghost btn-sm" onClick={async () => {
      try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1400); } catch { /* clipboard unavailable */ }
    }}>
      <Icon name={done ? "check" : "copy"} size={12} />{done ? "Copied" : label}
    </button>
  );
}
