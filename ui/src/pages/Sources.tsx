import { useState } from "react";
import { useSourceHealth, useSources } from "@/api/hooks";
import type { SourceSummary } from "@/api/types";
import { Icon } from "@/components/ui/Icon";
import { EmptyState, ErrorState, Meter, PageHeader, Panel, Skeleton, Sparkline, Stat } from "@/components/ui/primitives";
import { sourceColor } from "@/lib/color";
import { cx, fmtAgo, fmtCompact, fmtInt, pct } from "@/lib/format";
import { href } from "@/lib/router";

const STALE_MS = 60_000;

function Freshness({ ts }: { ts: number | null }) {
  const age = ts == null ? Infinity : Date.now() - ts;
  const live = age < STALE_MS;
  return (
    <span className={cx("inline-flex items-center gap-1.5 mono text-[11px]", live ? "text-parsed" : "text-partial")}>
      <span className={cx("h-1.5 w-1.5 rounded-full", live ? "bg-parsed animate-pulseDot" : "bg-partial")} />{fmtAgo(ts)}
    </span>
  );
}

function StackBar({ s }: { s: SourceSummary["status_counts"] }) {
  const total = s.parsed + s.partial + s.unparsed || 1;
  return (
    <div className="flex h-1.5 w-full gap-px rounded-full overflow-hidden bg-well" title={`parsed ${fmtInt(s.parsed)} · partial ${fmtInt(s.partial)} · unparsed ${fmtInt(s.unparsed)}`}>
      <div className="bg-parsed" style={{ width: `${(s.parsed / total) * 100}%` }} />
      <div className="bg-partial" style={{ width: `${(s.partial / total) * 100}%` }} />
      <div className="bg-unparsed" style={{ width: `${(s.unparsed / total) * 100}%` }} />
    </div>
  );
}

function SourceCard({ s, onOpen }: { s: SourceSummary; onOpen: () => void }) {
  const accent = sourceColor(s.source_id);
  return (
    <button onClick={onOpen} className="panel ticks text-left p-4 flex flex-col gap-3.5 transition-transform hover:-translate-y-0.5 hover:border-line-strong group">
      <span className="absolute left-0 top-4 bottom-4 w-[3px] rounded-r" style={{ background: accent }} />
      <div className="flex items-start gap-2 pl-1.5">
        <div className="min-w-0 flex-1">
          <div className="font-display text-[18px] leading-tight truncate">{s.product}</div>
          <div className="mono text-[11px] text-ink-3 truncate">{s.vendor} · {s.source_id}@{s.pack_version}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className="chip chip-neutral">{s.category}</span>
          {s.drift.flag
            ? <span className="chip chip-partial" title={s.drift.reasons.join("\n")}><Icon name="drift" size={10} />schema drift</span>
            : <span className="chip chip-parsed"><Icon name="check" size={10} strokeWidth={2.4} />stable</span>}
        </div>
      </div>

      <div className="flex items-end gap-4 pl-1.5">
        <div className="shrink-0"><div className="kicker">eps</div><div className="font-display text-[32px] leading-none num mt-1">{s.eps >= 100 ? fmtInt(s.eps) : s.eps.toFixed(1)}</div></div>
        <div className="flex-1 min-w-0"><Sparkline data={s.eps_series} height={42} fmt={(n) => (n >= 100 ? fmtInt(n) : n.toFixed(1))} unit="/s" /></div>
      </div>

      <div className="grid grid-cols-2 gap-x-5 gap-y-2.5 pl-1.5">
        <div><div className="flex justify-between kicker"><span>parse rate</span><span className="text-ink num">{s.total_events === 0 ? "—" : pct(s.parse_rate)}</span></div><Meter value={s.parse_rate} goal={0.99} className="mt-1.5" /></div>
        <div><div className="flex justify-between kicker"><span>coverage</span><span className="text-ink num">{s.total_events === 0 ? "—" : pct(s.mean_coverage)}</span></div><Meter value={s.total_events === 0 ? 0 : s.mean_coverage} goal={0.85} className="mt-1.5" /></div>
      </div>
      <div className="pl-1.5"><StackBar s={s.status_counts} /></div>

      <div className="pl-1.5 min-h-[44px]">
        <div className="kicker mb-1.5">top unmapped</div>
        {s.total_events === 0
          ? <span className="text-ink-3 text-[12px]">no events seen yet</span>
          : s.top_unmapped.length === 0
          ? <span className="text-ink-3 text-[12px]">none — every extracted field is mapped</span>
          : <div className="flex flex-wrap gap-1">{s.top_unmapped.slice(0, 5).map((u) => <span key={u.field} className="chip chip-neutral !normal-case">{u.field}<b className="text-ink-3 font-medium num">{fmtCompact(u.count)}</b></span>)}</div>}
      </div>

      <div className="pl-1.5 flex items-center justify-between border-t border-line pt-2.5 -mb-0.5">
        <Freshness ts={s.last_seen} />
        <span className="mono text-[11px] text-ink-3 num">{fmtCompact(s.total_events)} events</span>
        {!s.verified && <span className="chip chip-partial" title="Pack not yet checked against vendor docs / real captures (R12)">unverified pack</span>}
      </div>
    </button>
  );
}

function Drawer({ id, onClose }: { id: string; onClose: () => void }) {
  const h = useSourceHealth(id);
  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-label={`Source ${id}`}>
      <button className="absolute inset-0 bg-black/55 backdrop-blur-[2px]" aria-label="Close" onClick={onClose} />
      <aside className="relative w-[480px] max-w-full h-full panel !rounded-none !border-y-0 !border-r-0 overflow-auto animate-rise">
        <div className="panel-head sticky top-0 bg-panel z-10">
          <div><div className="kicker">source health</div><h2 className="text-[18px]">{id}</h2></div>
          <button className="btn btn-ghost ml-auto !px-1.5" onClick={onClose} aria-label="Close"><Icon name="x" size={15} /></button>
        </div>
        {h.isPending ? <div className="p-5 space-y-3"><Skeleton className="h-24" /><Skeleton className="h-24" /><Skeleton className="h-40" /></div>
          : h.isError ? <ErrorState what="Source" error={h.error} onRetry={() => h.refetch()} />
          : (
            <div className="p-5 space-y-6">
              {h.data.drift.flag && (
                <div className="rounded border border-partial/40 bg-partial/10 p-3 text-[12.5px]">
                  <div className="flex items-center gap-2 text-partial font-semibold"><Icon name="drift" size={14} />Schema drift detected</div>
                  <ul className="mt-1.5 list-disc pl-5 text-ink-2">{h.data.drift.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                </div>
              )}
              <div className="grid grid-cols-3 gap-4">
                <Stat label="parse rate" value={pct(h.data.parse_rate)} />
                <Stat label="coverage" value={pct(h.data.mean_coverage)} />
                <Stat label="events" value={fmtCompact(h.data.total_events)} />
              </div>
              {([["Throughput", h.data.eps_series, "/s", "signal"], ["Parse rate", h.data.parse_rate_series, "", "parsed"], ["Mean coverage", h.data.coverage_series, "", "info"]] as const).map(([t, d, u, tone]) => (
                <div key={t}><div className="kicker mb-1.5">{t}</div>
                  <Sparkline data={d as never} width={430} height={56} tone={tone} unit={u} fmt={(n) => (u ? n.toFixed(1) : `${(n * 100).toFixed(1)}%`)} /></div>
              ))}
              <div>
                <div className="kicker mb-2">unmapped fields ({h.data.unmapped_all.length})</div>
                <div className="rounded border border-line divide-y divide-line">
                  {h.data.unmapped_all.length === 0 && <div className="p-3 text-ink-3 text-[12.5px]">Nothing unmapped.</div>}
                  {h.data.unmapped_all.slice(0, 14).map((u) => (
                    <div key={u.field} className="flex items-center gap-3 px-3 h-8 mono text-[12px]">
                      <span className="text-partial w-[130px] truncate">{u.field}</span><span className="text-ink-3 truncate flex-1">{u.example ?? ""}</span><span className="num text-ink-2">{fmtInt(u.count)}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div className="kicker mb-2">peers</div>
                <div className="flex flex-wrap gap-1.5">{h.data.peers.map((p) => <span key={p.ip} className="chip chip-neutral !normal-case">{p.ip} · {fmtCompact(p.events)}</span>)}{h.data.peers.length === 0 && <span className="text-ink-3 text-[12px]">no peer data</span>}</div>
              </div>
              <a className="btn btn-primary w-full" href={href("/explorer", { source: id })}><Icon name="search" size={13} />Open in Explorer</a>
            </div>
          )}
      </aside>
    </div>
  );
}

export function SourcesPage() {
  const q = useSources();
  const [open, setOpen] = useState<string | null>(null);
  const items = q.data?.items ?? [];
  const totalEps = items.reduce((a, s) => a + s.eps, 0);
  const total = items.reduce((a, s) => a + s.total_events, 0);
  const parsed = items.reduce((a, s) => a + s.status_counts.parsed, 0);
  const drift = items.filter((s) => s.drift.flag).length;

  return (
    <div className="pb-10">
      <PageHeader index="03" title="Sources" accent="& health" sub="Each device feeding the node, with the signals that tell you its parser is still telling the truth." />
      <div className="px-4 md:px-8 space-y-5">
        {q.isPending ? (
          <div className="grid grid-cols-3 gap-4">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[330px]" />)}</div>
        ) : q.isError && !q.data ? (
          <Panel><ErrorState what="Sources" error={q.error} onRetry={() => q.refetch()} /></Panel>
        ) : items.length === 0 ? (
          <Panel><EmptyState icon="server" title="No sources have reported yet">Sources appear automatically once a device sends its first event. Onboard an unseen format from the Onboarding Studio.</EmptyState></Panel>
        ) : (
          <>
            <Panel ticks={false} bodyClass="grid grid-cols-2 md:grid-cols-4 gap-6 px-5 py-4">
              <Stat label="sources" value={items.length} />
              <Stat label="throughput" value={totalEps >= 100 ? fmtInt(totalEps) : totalEps.toFixed(1)} unit="eps" />
              <Stat label="parse rate (all)" value={total ? pct(parsed / total) : "—"} tone={total && parsed / total >= 0.99 ? "ok" : "warn"} />
              <Stat label="schema drift" value={drift} tone={drift ? "warn" : "ok"} sub={drift ? "sources need a pack review" : "all stable"} />
            </Panel>
            <div className="grid gap-4 stagger" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(min(360px, 100%), 1fr))" }}>
              {items.map((s) => <SourceCard key={s.source_id} s={s} onOpen={() => setOpen(s.source_id)} />)}
            </div>
          </>
        )}
      </div>
      {open && <Drawer id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
