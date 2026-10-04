import { useEffect, useMemo, useState } from "react";
import { useDetections } from "@/api/hooks";
import type { Detection } from "@/api/types";
import { EventTable } from "@/components/EventTable";
import { Icon } from "@/components/ui/Icon";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { cx, fmtCompact, fmtDateTime, fmtInt, severityName } from "@/lib/format";
import { eventHref, href } from "@/lib/router";

const sevClass = (id: number) => (id >= 5 ? "chip-unparsed" : id === 4 ? "chip-unparsed" : id === 3 ? "chip-partial" : "chip-info");

function ScoreBar({ v }: { v: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 rounded-full bg-well border border-line overflow-hidden"><div className={cx("h-full", v >= 0.8 ? "bg-unparsed" : v >= 0.6 ? "bg-partial" : "bg-info")} style={{ width: `${Math.min(1, v) * 100}%` }} /></div>
      <span className="mono num text-[11px] text-ink-2">{v.toFixed(2)}</span>
    </div>
  );
}

function Detail({ d }: { d: Detection }) {
  const maxZ = Math.max(3, ...d.features.map((f) => Math.abs(f.z)));
  return (
    <div className="flex flex-col h-full min-h-0 animate-rise" key={d.finding_id}>
      <div className="p-5 border-b border-line">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={cx("chip", sevClass(d.severity_id))}>{severityName(d.severity_id)}</span>
          <span className="chip chip-neutral">{d.entity.kind}</span>
          <span className="mono text-signal text-[13px]">{d.entity.value}</span>
          <span className="ml-auto mono text-[11px] text-ink-3">{fmtDateTime(d.window.start)} → {fmtDateTime(d.window.end).slice(11)}</span>
        </div>
        <h2 className="text-[24px] leading-tight mt-2">{d.title}</h2>
        <p className="text-ink-2 mt-1.5 max-w-3xl">{d.summary}</p>
        <div className="mt-3 flex items-center gap-2">
          <a className="btn btn-sm" href={eventHref(d.event_id)}><Icon name="doc" size={12} />Finding event</a>
          <a className="btn btn-sm" href={href("/explorer", { q: `${d.entity.kind}:${d.entity.value}` })}><Icon name="search" size={12} />All events for {d.entity.value}</a>
        </div>
      </div>

      <div className="p-5 border-b border-line">
        <div className="kicker mb-2.5">why it was flagged · feature z-scores vs baseline</div>
        {d.features.length === 0 ? <span className="text-ink-3 text-[12.5px]">No feature breakdown supplied.</span> : (
          <div className="grid grid-cols-[100px_1fr_90px] md:grid-cols-[150px_1fr_130px] gap-x-4 gap-y-1.5 items-center mono text-[12px]">
            {[...d.features].sort((a, b) => Math.abs(b.z) - Math.abs(a.z)).map((f) => (
              <div key={f.name} className="contents">
                <span className="text-ink-2 truncate">{f.name}</span>
                <div className="relative h-2 rounded-full bg-well border border-line overflow-hidden">
                  <div className={cx("absolute inset-y-0 left-0", Math.abs(f.z) >= 3 ? "bg-unparsed" : Math.abs(f.z) >= 2 ? "bg-partial" : "bg-info")} style={{ width: `${(Math.abs(f.z) / maxZ) * 100}%` }} />
                </div>
                <span className="text-right num text-ink-2">{fmtCompact(f.value)} <span className="text-ink-3">vs {fmtCompact(f.baseline)}</span> <b className="text-ink">z{f.z.toFixed(1)}</b></span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="px-5 pt-4 pb-1 flex items-baseline gap-3">
        <span className="kicker">evidence</span>
        <span className="mono text-[11.5px] text-ink-3 num">showing {fmtInt(d.evidence.length)} of {fmtInt(d.evidence_total)} contributing events</span>
        <span className="ml-auto flex gap-1">{d.sources.map((s) => <span key={s} className="chip chip-neutral !normal-case">{s}</span>)}</span>
      </div>
      <EventTable rows={d.evidence} className="flex-1 min-h-[220px]" onOpen={(r) => { location.hash = eventHref(r.event_id).slice(1); }}
        empty={<EmptyState icon="doc" title="No evidence rows attached" className="!py-8">The finding was emitted without contributing events.</EmptyState>} />
    </div>
  );
}

export function DetectionsPage() {
  const q = useDetections();
  const [sel, setSel] = useState<string | null>(null);
  const items = useMemo(() => q.data?.items ?? [], [q.data]);
  useEffect(() => {
    if (!sel && items.length) setSel(items[0].finding_id);
  }, [items, sel]);
  const cur = items.find((d) => d.finding_id === sel) ?? null;

  return (
    <div className="md:h-full flex flex-col">
      <PageHeader index="06" title="Detections" accent="→ raw" sub="Unsupervised findings across all vendors. Every finding links to the exact events — and from there to the raw bytes — that produced it."
        right={q.data?.baseline && <span className="mono text-[11px] text-ink-3 num">{fmtInt(q.data.baseline.windows_scored)} windows scored{q.data.baseline.false_positives != null && <> · {fmtInt(q.data.baseline.false_positives)} baseline false positives</>}</span>} />
      <div className="px-4 md:px-8 pb-6 md:flex-1 min-h-0">
        {q.isPending ? <div className="grid grid-cols-1 md:grid-cols-12 gap-4"><Skeleton className="md:col-span-4 h-96" /><Skeleton className="md:col-span-8 h-96" /></div>
          : q.isError && !q.data ? <Panel><ErrorState what="Detections" error={q.error} onRetry={() => q.refetch()} /></Panel>
          : items.length === 0 ? <Panel><EmptyState icon="alert" title="No findings">The analytics task scores 60-second windows continuously. Nothing has crossed the anomaly threshold yet.</EmptyState></Panel>
          : (
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 md:h-full min-h-0">
              <Panel className="md:col-span-4 min-h-0 max-md:max-h-[40vh]" bodyClass="overflow-auto" kicker="findings" title={`${items.length} detected`}>
                <ul role="listbox" aria-label="Findings">
                  {items.map((d) => (
                    <li key={d.finding_id} role="option" aria-selected={d.finding_id === sel}>
                      <button onClick={() => setSel(d.finding_id)} className={cx("w-full text-left px-4 py-3 border-b border-line/60 transition-colors relative", d.finding_id === sel ? "bg-raised" : "hover:bg-raised/50")}>
                        {d.finding_id === sel && <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-signal" />}
                        <div className="flex items-center gap-2"><span className={cx("chip", sevClass(d.severity_id))}>{severityName(d.severity_id)}</span><span className="mono text-[11px] text-ink-3 ml-auto">{fmtDateTime(d.time).slice(5)}</span></div>
                        <div className="font-display text-[16px] leading-snug mt-1.5">{d.title}</div>
                        <div className="mono text-[12px] text-signal mt-0.5">{d.entity.value}</div>
                        <div className="mt-2 flex items-center justify-between"><ScoreBar v={d.score} /><span className="mono text-[11px] text-ink-3 num">{fmtInt(d.evidence_total)} events · {d.sources.length} src</span></div>
                      </button>
                    </li>
                  ))}
                </ul>
              </Panel>
              <Panel className="md:col-span-8 min-h-0 max-md:min-h-[520px]" bodyClass="min-h-0 flex flex-col">{cur && <Detail d={cur} />}</Panel>
            </div>
          )}
      </div>
    </div>
  );
}
