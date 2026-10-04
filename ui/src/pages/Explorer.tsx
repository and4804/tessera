import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useCallback, useMemo, useState } from "react";
import { ApiError, api, exportUrl } from "@/api/client";
import { useSources } from "@/api/hooks";
import type { EventStatus, EventsFilter } from "@/api/types";
import { EventTable } from "@/components/EventTable";
import { Histogram } from "@/components/Histogram";
import { QueryBar } from "@/components/QueryBar";
import { TimeRangePicker, useResolvedRange } from "@/components/TimeRangePicker";
import { Icon } from "@/components/ui/Icon";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { fmtInt } from "@/lib/format";
import { eventHref, navigate, type Route } from "@/lib/router";
import { useUi } from "@/store/ui";

const PAGE = 200;

export function ExplorerPage({ route }: { route: Route }) {
  const range = useUi((s) => s.range);
  const setRange = useUi((s) => s.setRange);
  const { from, to } = useResolvedRange(range);
  const initialQ = route.params.get("q") ?? "";
  const [draft, setDraft] = useState(initialQ);
  const [q, setQ] = useState(initialQ);
  const [status, setStatus] = useState<EventStatus | "">((route.params.get("status") as EventStatus) || "");
  const [source, setSource] = useState(route.params.get("source") ?? "");
  const sources = useSources();

  const filter: EventsFilter = useMemo(() => ({ from, to, q, status: status || null, source: source || null }), [from, to, q, status, source]);
  const hist = useQuery({
    queryKey: ["histogram", filter],
    queryFn: ({ signal }) => api.histogram(filter, 60, signal),
    placeholderData: (p) => p
  });
  const events = useInfiniteQuery({
    queryKey: ["events", filter],
    queryFn: ({ pageParam, signal }) => api.events(filter, PAGE, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: (p) => p
  });
  const rows = useMemo(() => events.data?.pages.flatMap((p) => p.items) ?? [], [events.data]);
  const fetchNext = useCallback(() => {
    if (events.hasNextPage && !events.isFetchingNextPage) void events.fetchNextPage();
  }, [events]);

  const submit = (v: string) => {
    setQ(v);
    navigate("/explorer", { q: v || undefined, status: status || undefined, source: source || undefined });
  };
  const histTotal = hist.data?.buckets.reduce((a, b) => a + b.parsed + b.partial + b.unparsed, 0) ?? null;
  const badQuery = events.error instanceof ApiError && events.error.status === 400;

  return (
    <div className="md:h-full flex flex-col">
      <PageHeader index="02" title="Explorer" accent="one schema" sub="Every vendor, one table. Query the OCSF lake with the field DSL; drag the histogram to zoom."
        right={<TimeRangePicker />} />
      <div className="px-4 md:px-8 space-y-3">
        <QueryBar value={draft} onChange={setDraft} onSubmit={submit} />
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="kicker mr-1">status</span>
            {(["", "parsed", "partial", "unparsed"] as const).map((s) => (
              <button key={s || "all"} aria-pressed={status === s} onClick={() => setStatus(s)}
                className={`chip cursor-pointer ${s ? `chip-${s}` : "chip-neutral"} ${status !== s ? "opacity-45 hover:opacity-100" : ""}`}>{s || "all"}</button>
            ))}
          </div>
          <label className="flex items-center gap-2">
            <span className="kicker">source</span>
            <select className="input !w-auto mono !h-7" value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="">all sources</option>
              {sources.data?.items.map((s) => <option key={s.source_id} value={s.source_id}>{s.source_id}</option>)}
            </select>
          </label>
          <div className="ml-auto flex items-center gap-1.5">
            <span className="kicker mr-1">export</span>
            {(["csv", "json", "arrow"] as const).map((k) => (
              <a key={k} className="btn btn-sm" href={exportUrl(k, filter)} download><Icon name="download" size={12} />{k}</a>
            ))}
          </div>
        </div>
      </div>

      <div className="px-4 md:px-8 pt-4 grid grid-cols-[minmax(0,1fr)] grid-rows-[auto_minmax(0,1fr)] gap-4 md:flex-1 min-h-0 pb-6">
        <Panel kicker="volume" title={histTotal == null ? "Events over time" : <span className="num">{fmtInt(histTotal)} events</span>}
          right={range.kind === "abs" && <button className="btn btn-ghost btn-sm" onClick={() => setRange({ kind: "rel", ms: 3_600_000, label: "1h" })}>reset zoom</button>}>
          <div className="px-2 pt-2 pb-1">
            {hist.isPending ? <Skeleton className="h-[150px] m-2" />
              : hist.isError && !hist.data ? <ErrorState what="Histogram" error={hist.error} onRetry={() => hist.refetch()} className="!py-6" />
              : hist.data && histTotal === 0 ? <EmptyState icon="layers" className="!py-6" title="No events in this window">Widen the time range or relax the query.</EmptyState>
              : hist.data && <Histogram data={hist.data} onBrush={(f, t) => setRange({ kind: "abs", from: f, to: t })} />}
          </div>
        </Panel>

        <Panel className="min-h-0 max-md:h-[70vh]" bodyClass="flex flex-col" kicker="results"
          title={rows.length ? <span className="num">{fmtInt(rows.length)}{events.hasNextPage ? "+" : ""} rows</span> : "Results"}
          right={<span className="mono text-[11px] text-ink-3">{events.data?.pages[0] ? `${events.data.pages[0].took_ms} ms` : ""}{events.isFetching && <span className="ml-3 text-signal animate-pulseDot">fetching…</span>}</span>}>
          {events.isPending ? (
            <div className="p-4 space-y-2">{Array.from({ length: 9 }, (_, i) => <Skeleton key={i} className="h-6" style={{ opacity: 1 - i * 0.09 }} />)}</div>
          ) : events.isError && !events.data ? (
            badQuery ? <EmptyState icon="alert" tone="warn" title="The server rejected this query">{(events.error as ApiError).message}</EmptyState>
              : <ErrorState what="Events" error={events.error} onRetry={() => events.refetch()} />
          ) : (
            <EventTable rows={rows} withDate={to - from > 24 * 3_600_000} onEnd={fetchNext} className="flex-1"
              onOpen={(r) => { location.hash = eventHref(r.event_id).slice(1); }}
              empty={<EmptyState icon="search" title="No events match" >{q ? <>Nothing for <code className="mono text-signal">{q}</code> in this window.</> : "Nothing has been ingested in this window."}</EmptyState>}
              footer={events.isFetchingNextPage ? <div className="h-7 grid place-items-center mono text-[11px] text-ink-3 border-t border-line">loading more…</div> : undefined} />
          )}
        </Panel>
      </div>
    </div>
  );
}
