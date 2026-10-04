import { ApiError } from "@/api/client";
import { useBenchmark } from "@/api/hooks";
import type { BenchmarkResults } from "@/api/types";
import { ScalingChart } from "@/components/ScalingChart";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton, Stat } from "@/components/ui/primitives";
import { cx, fmtBytes, fmtCompact, fmtDateTime, fmtInt, pct } from "@/lib/format";

const ms = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)} s` : `${n < 10 ? n.toFixed(1) : Math.round(n)} ms`);

function Latency({ l, target }: { l: BenchmarkResults["latency_ms"]; target?: number }) {
  const rows = ([["p50", l.p50], ["p95", l.p95], ["p99", l.p99], ["max", l.max]] as const).filter(([, v]) => v != null) as [string, number][];
  const top = Math.max(...rows.map(([, v]) => v), target ?? 0);
  return (
    <div className="space-y-3">
      {rows.map(([k, v]) => (
        <div key={k} className="grid grid-cols-[38px_1fr_70px] items-center gap-3 mono text-[12px]">
          <span className="text-ink-3">{k}</span>
          <div className="relative h-2.5 rounded-full bg-well border border-line overflow-hidden">
            <div className={cx("h-full rounded-full", k === "p99" ? "bg-signal" : "bg-ink-3/70")} style={{ width: `${(v / top) * 100}%` }} />
            {k === "p99" && target != null && <div className="absolute inset-y-0 w-px bg-partial" style={{ left: `${(target / top) * 100}%` }} title={`target ${ms(target)}`} />}
          </div>
          <span className="text-right num text-ink">{ms(v)}</span>
        </div>
      ))}
      {target != null && <div className="mono text-[10.5px] text-partial">▏ p99 target {ms(target)}</div>}
    </div>
  );
}

export function BenchmarkPage() {
  const q = useBenchmark();
  const d = q.data;
  const notFound = q.error instanceof ApiError && q.error.status === 404;
  return (
    <div className="pb-10">
      <PageHeader index="07" title="Benchmark" accent="measured, not claimed" sub="Rendered straight from bench/results.json. Every number below was produced by `ulpf bench` on the hardware stated."
        right={d && <span className="mono text-[11px] text-ink-3">run {fmtDateTime(d.generated_at)}</span>} />
      <div className="px-4 md:px-8 space-y-4">
        {q.isPending ? <div className="grid grid-cols-3 gap-4"><Skeleton className="h-52" /><Skeleton className="h-52 col-span-2" /></div>
          : notFound ? <Panel><EmptyState icon="gauge" title="No benchmark has been run yet">Run <code className="mono text-ink">ulpf bench</code> on the target hardware. It writes <code className="mono text-ink">bench/results.json</code>, which this page renders as-is.</EmptyState></Panel>
          : q.isError ? <Panel><ErrorState what="Benchmark" error={q.error} onRetry={() => q.refetch()} /></Panel>
          : d && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 stagger">
                <Panel className="md:col-span-5" bodyClass="p-6 flex flex-col gap-5" kicker="sustained throughput">
                  <div>
                    <div className="font-display num text-[84px] leading-[0.9] text-signal tracking-tight">{fmtInt(d.sustained.eps)}</div>
                    <div className="mono text-ink-2 mt-1.5">events / second · {d.config.duration_s}s sustained</div>
                  </div>
                  <div className="grid grid-cols-2 gap-5 pt-4 border-t border-line">
                    {d.sustained.per_worker_eps != null && <Stat label="per worker" value={fmtInt(d.sustained.per_worker_eps)} unit="eps" />}
                    {d.sustained.projected_daily_events != null && <Stat label="projected / day" value={fmtCompact(d.sustained.projected_daily_events)} unit="events" />}
                    {d.parse_rate != null && <Stat label="parse rate" value={pct(d.parse_rate, 2)} />}
                    {d.config.events != null && <Stat label="events replayed" value={fmtCompact(d.config.events)} />}
                  </div>
                </Panel>
                <Panel className="md:col-span-7" kicker="worker scaling" title="Throughput vs workers" bodyClass="p-3">
                  {d.scaling.length > 1 ? <ScalingChart data={d} /> : <EmptyState icon="layers" title="Single-point run" className="!py-10">The results file has fewer than two worker counts, so there is no scaling curve to draw.</EmptyState>}
                </Panel>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 stagger">
                <Panel className="md:col-span-4" kicker="ingest → queryable" title="Latency percentiles" bodyClass="p-5"><Latency l={d.latency_ms} target={d.targets?.latency_p99_ms} /></Panel>
                <Panel className="md:col-span-4" kicker="proof" title="Conservation & accuracy" bodyClass="p-5 grid grid-cols-2 gap-5">
                  {d.ledger && <>
                    <Stat label="ingested" value={fmtCompact(d.ledger.ingested)} />
                    <Stat label="lost" value={fmtInt(d.ledger.lost)} tone={d.ledger.lost === 0 ? "ok" : "bad"} sub={d.ledger.conserved ? "ledger conserved" : "ledger violated"} />
                  </>}
                  {d.accuracy && <>
                    <Stat label="precision" value={pct(d.accuracy.precision, 2)} />
                    <Stat label="recall" value={pct(d.accuracy.recall, 2)} />
                  </>}
                  {d.vault?.compression_ratio != null && <Stat label="vault compression" value={`${d.vault.compression_ratio.toFixed(1)}×`} />}
                  {d.lake?.bytes_per_event != null && <Stat label="lake / event" value={fmtBytes(d.lake.bytes_per_event)} />}
                  {!d.ledger && !d.accuracy && !d.vault && !d.lake && <span className="text-ink-3 text-[12.5px] col-span-2">The results file carries no ledger/accuracy sections.</span>}
                </Panel>
                <Panel className="md:col-span-4" kicker="hardware" title="Test machine" bodyClass="p-5">
                  <dl className="grid grid-cols-[84px_1fr] gap-y-2.5 mono text-[12px]">
                    <dt className="text-ink-3">cpu</dt><dd className="text-ink">{d.hardware.cpu}</dd>
                    <dt className="text-ink-3">cores</dt><dd className="text-ink num">{d.hardware.cores}</dd>
                    <dt className="text-ink-3">memory</dt><dd className="text-ink num">{d.hardware.ram_gb} GB</dd>
                    <dt className="text-ink-3">os</dt><dd className="text-ink">{d.hardware.os}</dd>
                    {d.hardware.python && <><dt className="text-ink-3">python</dt><dd className="text-ink">{d.hardware.python}</dd></>}
                    {d.hardware.storage && <><dt className="text-ink-3">storage</dt><dd className="text-ink">{d.hardware.storage}</dd></>}
                    {d.config.mix && <><dt className="text-ink-3">mix</dt><dd className="text-ink break-all">{d.config.mix}</dd></>}
                    {d.resources?.cpu_pct != null && <><dt className="text-ink-3">cpu use</dt><dd className="text-ink num">{d.resources.cpu_pct.toFixed(0)}%</dd></>}
                    {d.resources?.rss_mb != null && <><dt className="text-ink-3">rss</dt><dd className="text-ink num">{fmtInt(d.resources.rss_mb)} MB</dd></>}
                  </dl>
                  {d.hardware.label && <div className="mt-4 pt-3 border-t border-line text-ink-2 text-[12px]">{d.hardware.label}</div>}
                </Panel>
              </div>
            </>
          )}
      </div>
    </div>
  );
}
