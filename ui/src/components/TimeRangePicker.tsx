import { useEffect, useState } from "react";
import { cx, fmtDateTime } from "@/lib/format";
import { RANGE_PRESETS, resolveRange, useUi, type TimeRange } from "@/store/ui";
import { Icon } from "./ui/Icon";

/** Resolved {from,to}. Relative ranges re-resolve every `tickMs` so data refreshes without thrashing query keys. */
export function useResolvedRange(range: TimeRange, tickMs = 15_000) {
  const [tick, setTick] = useState(() => Date.now());
  useEffect(() => {
    if (range.kind !== "rel") return;
    const id = setInterval(() => setTick(Date.now()), tickMs);
    return () => clearInterval(id);
  }, [range, tickMs]);
  const now = range.kind === "rel" ? Math.floor(tick / tickMs) * tickMs : 0;
  const r = resolveRange(range, now || undefined);
  // `now` is quantised so query keys stay stable; extend `to` to the end of the current tick so events ingested since the
  // quantisation point (up to tickMs ago) are not cut off.
  return range.kind === "rel" ? { from: r.from, to: r.to + tickMs } : r;
}

const toLocalInput = (ms: number) => new Date(ms - new Date(ms).getTimezoneOffset() * 60000).toISOString().slice(0, 16);

export function TimeRangePicker() {
  const range = useUi((s) => s.range);
  const setRange = useUi((s) => s.setRange);
  const [open, setOpen] = useState(false);
  const r = resolveRange(range);
  const [from, setFrom] = useState(toLocalInput(r.from));
  const [to, setTo] = useState(toLocalInput(r.to));
  const bad = !from || !to || new Date(from) >= new Date(to);

  return (
    <div className="relative flex items-center gap-2">
      <Icon name="clock" size={14} className="text-ink-3" />
      <div role="group" aria-label="Time range" className="inline-flex rounded-[6px] border border-line-strong bg-well p-0.5 gap-0.5">
        {RANGE_PRESETS.map((p) => {
          const on = range.kind === "rel" && range.ms === p.ms;
          return (
            <button key={p.label} aria-pressed={on} onClick={() => setRange({ kind: "rel", ms: p.ms, label: p.label })}
              className={cx("h-6 px-2.5 rounded-[4px] text-[12px] mono transition-colors", on ? "bg-signal text-[#10140a] font-semibold" : "text-ink-2 hover:text-ink hover:bg-raised")}>
              {p.label}
            </button>
          );
        })}
        <button aria-pressed={range.kind === "abs"} onClick={() => setOpen((o) => !o)}
          className={cx("h-6 px-2.5 rounded-[4px] text-[12px] mono", range.kind === "abs" ? "bg-signal text-[#10140a] font-semibold" : "text-ink-2 hover:text-ink hover:bg-raised")}>
          {range.kind === "abs" ? `${fmtDateTime(range.from).slice(5, 16)} → ${fmtDateTime(range.to).slice(5, 16)}` : "custom"}
        </button>
      </div>
      {open && (
        <div className="absolute right-0 top-9 z-30 panel !bg-raised p-3 w-[300px] space-y-2 animate-rise shadow-[0_24px_60px_-12px_rgba(0,0,0,.8)]">
          <label className="block"><span className="kicker">from (local)</span><input type="datetime-local" className="input mt-1 mono" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
          <label className="block"><span className="kicker">to (local)</span><input type="datetime-local" className="input mt-1 mono" value={to} onChange={(e) => setTo(e.target.value)} /></label>
          {bad && <div className="text-unparsed text-[12px]">“from” must be before “to”.</div>}
          <div className="flex justify-end gap-2 pt-1">
            <button className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>Cancel</button>
            <button className="btn btn-primary btn-sm" disabled={bad} onClick={() => { setRange({ kind: "abs", from: new Date(from).getTime(), to: new Date(to).getTime() }); setOpen(false); }}>Apply</button>
          </div>
        </div>
      )}
    </div>
  );
}
