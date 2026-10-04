import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { LIVE_CAP, LiveFeed } from "@/api/live-feed";
import type { EventStatus, TailRow } from "@/api/types";
import { EventTable } from "@/components/EventTable";
import { QueryBar } from "@/components/QueryBar";
import { Icon } from "@/components/ui/Icon";
import { EmptyState, PageHeader, Panel, Sparkline } from "@/components/ui/primitives";
import { cx, fmtInt } from "@/lib/format";
import { eventHref } from "@/lib/router";

const STATUSES: EventStatus[] = ["parsed", "partial", "unparsed"];

export function LivePage() {
  const [feed] = useState(() => new LiveFeed());
  const snap = useSyncExternalStore(feed.subscribe, feed.getSnapshot);
  useEffect(() => {
    feed.start();
    return () => feed.stop();
  }, [feed]);

  const [qDraft, setQDraft] = useState("");
  const [q, setQ] = useState("");
  const [statuses, setStatuses] = useState<Set<EventStatus>>(new Set());
  const [sources, setSources] = useState<Set<string>>(new Set());
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<{ rows: TailRow[]; at: number } | null>(null);
  const seenSources = useRef(new Set<string>());

  // push filters to the server; q changes also reset the buffer so the list is internally consistent
  useEffect(() => {
    feed.setFilter(q, [...sources], [...statuses]);
  }, [feed, q, sources, statuses]);
  const firstQ = useRef(true);
  useEffect(() => {
    if (firstQ.current) { firstQ.current = false; return; }
    feed.clear();
  }, [feed, q]);

  // snap.version is the change signal: the ring buffer is mutated in place.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const live = useMemo(() => snap.buffer.toArray(), [snap.version, snap.buffer]);
  const base = paused && frozen ? frozen.rows : live;
  for (const r of live) seenSources.current.add(r.source_id);

  const rows = useMemo(
    () => (statuses.size || sources.size ? base.filter((r) => (!statuses.size || statuses.has(r.status)) && (!sources.size || sources.has(r.source_id))) : base),
    [base, statuses, sources]
  );

  const prevTop = useRef<string | null>(null);
  const prepended = useMemo(() => {
    if (paused || !prevTop.current) return 0;
    const i = rows.findIndex((r) => r.event_id === prevTop.current);
    return i < 0 ? Math.min(rows.length, 5000) : i;
  }, [rows, paused]);
  useEffect(() => {
    prevTop.current = rows[0]?.event_id ?? prevTop.current;
  }, [rows]);

  const togglePause = () => {
    if (paused) { setPaused(false); setFrozen(null); }
    else { setFrozen({ rows: live, at: snap.total }); setPaused(true); }
  };
  const buffered = paused && frozen ? snap.total - frozen.at : 0;
  const toggle = <T,>(set: Set<T>, v: T, apply: (s: Set<T>) => void) => {
    const n = new Set(set);
    if (n.has(v)) n.delete(v); else n.add(v);
    apply(n);
  };

  const connected = snap.status === "open";
  const eps = snap.eps;

  const empty = !connected ? (
    <EmptyState icon="plug" tone="warn" title={snap.status === "connecting" ? "Opening the stream…" : "Stream disconnected"}>
      {snap.status === "retrying"
        ? <>The WebSocket to <code className="mono text-ink">/api/v1/stream</code> is down{snap.error ? ` (${snap.error})` : ""}. Reconnecting with backoff — attempt {snap.attempt}.</>
        : "Waiting for the node to accept the WebSocket."}
    </EmptyState>
  ) : base.length === 0 ? (
    <EmptyState icon="live" title="Listening — no events yet">
      The stream is connected{q ? <> and filtered by <code className="mono text-signal">{q}</code></> : ""}. Replay a file or point a device at the syslog listener and rows will land here the moment they are normalized.
    </EmptyState>
  ) : (
    <EmptyState icon="filter" title="Nothing in the buffer matches">
      {base.length} rows are buffered but none match the status/source toggles. Clear them to see everything.
    </EmptyState>
  );

  return (
    <div className="md:h-full flex flex-col">
      <PageHeader index="01" title="Live" accent="tail" sub="Normalized events as they leave the pipeline, newest first, bounded to the last 5,000."
        right={
          <>
            <button className="btn" onClick={togglePause} aria-pressed={paused}>
              <Icon name={paused ? "play" : "pause"} size={13} />{paused ? `Resume${buffered ? ` (+${fmtInt(buffered)})` : ""}` : "Pause"}
            </button>
            <button className="btn btn-ghost" onClick={() => { feed.clear(); setFrozen(paused ? { rows: [], at: snap.total } : null); }}><Icon name="trash" size={13} />Clear</button>
          </>
        } />

      <div className="px-4 md:px-8 grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_auto] gap-4 md:gap-6 items-start">
        <div className="space-y-3 min-w-0">
          <QueryBar value={qDraft} onChange={setQDraft} onSubmit={(v) => setQ(v)} placeholder="filter incoming events — src_ip:203.0.113.50" />
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="kicker mr-1">status</span>
            {STATUSES.map((s) => (
              <button key={s} className={cx("chip cursor-pointer transition-opacity", `chip-${s}`, statuses.size > 0 && !statuses.has(s) && "opacity-35")}
                aria-pressed={statuses.has(s)} onClick={() => toggle(statuses, s, setStatuses)}>{s}</button>
            ))}
            <span className="kicker ml-4 mr-1">source</span>
            {[...seenSources.current].sort().map((s) => (
              <button key={s} onClick={() => toggle(sources, s, setSources)} aria-pressed={sources.has(s)}
                className={cx("chip chip-neutral cursor-pointer transition-opacity", sources.size > 0 && !sources.has(s) && "opacity-35")}>{s}</button>
            ))}
            {seenSources.current.size === 0 && <span className="text-ink-3 text-[12px]">discovered from traffic</span>}
            {(statuses.size > 0 || sources.size > 0) && <button className="btn btn-ghost btn-sm" onClick={() => { setStatuses(new Set()); setSources(new Set()); }}>reset</button>}
          </div>
        </div>

        <div className="flex items-stretch gap-6 pr-1">
          <div className="text-right">
            <div className="kicker">events / sec</div>
            <div className={cx("font-display num text-[44px] leading-none mt-1", connected ? "text-ink" : "text-ink-3")} aria-live="off">
              {connected ? (eps >= 100 ? fmtInt(eps) : eps.toFixed(1)) : "—"}
            </div>
          </div>
          <div className="w-[200px]">
            <div className="kicker mb-1 flex justify-between"><span>last 60 s</span><span className={connected ? "text-parsed" : "text-unparsed"}>{snap.status}</span></div>
            <Sparkline data={snap.epsSeries} width={200} height={40} fmt={(n) => fmtInt(n)} unit="/s" />
          </div>
        </div>
      </div>

      <div className="px-4 md:px-8 pb-6 pt-4 md:flex-1 min-h-0 max-md:h-[75vh]">
        <Panel className="h-full" bodyClass="flex flex-col"
          kicker="buffer"
          title={<span className="num">{fmtInt(snap.size)} <span className="text-ink-3">/ {fmtInt(LIVE_CAP)}</span></span>}
          right={
            <div className="mono text-[11px] text-ink-3 flex items-center gap-4">
              <span>received <b className="text-ink-2 font-medium num">{fmtInt(snap.total)}</b></span>
              {snap.evicted > 0 && <span>rolled off <b className="text-ink-2 font-medium num">{fmtInt(snap.evicted)}</b></span>}
              {snap.serverDropped > 0 && <span className="text-partial" title="Server-side backpressure on this connection (not a pipeline drop; every event is in the vault)">stream-skipped {fmtInt(snap.serverDropped)}</span>}
              {paused && <span className="chip chip-partial">paused</span>}
            </div>
          }>
          <EventTable rows={rows} className="flex-1" prepended={prepended} fresh={Math.min(prepended, 40)} empty={empty}
            onOpen={(r) => { location.hash = eventHref(r.event_id).slice(1); }} />
        </Panel>
      </div>
    </div>
  );
}
