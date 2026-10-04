import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ApiError } from "@/api/client";
import { qk, useEvent, useExplain } from "@/api/hooks";
import { api } from "@/api/client";
import { LineagePanel } from "@/components/LineagePanel";
import { OcsfTree } from "@/components/OcsfTree";
import { RawView, type HlMeta } from "@/components/RawView";
import { Icon } from "@/components/ui/Icon";
import { CopyButton, ErrorState, Panel, Segmented, Skeleton, SourceBadge, StatusChip } from "@/components/ui/primitives";
import { spanColors } from "@/lib/color";
import { className, cx, fmtDateTime, severityName } from "@/lib/format";
import type { HighlightItem } from "@/lib/spans";
import { base64ToBytes } from "@/lib/spans";
import { href } from "@/lib/router";
import type { OcsfEvent } from "@/api/types";

export function EventDetailPage({ id }: { id: string }) {
  const ev = useEvent(id);
  const synthetic = ev.data?.ulpf.synthetic === true; // analytics findings: no raw bytes, nothing to explain
  const raw = useQuery({ queryKey: qk.raw(id), queryFn: () => api.raw(id), staleTime: Infinity, retry: false, enabled: !!ev.data && !synthetic });
  const explain = useExplain(id, !!ev.data && !synthetic);
  const [mode, setMode] = useState<"text" | "hex">("text");
  const [active, setActive] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);

  const bytes = useMemo(() => (raw.data?.data_b64 ? base64ToBytes(raw.data.data_b64) : null), [raw.data]);

  const { items, meta } = useMemo(() => {
    const items: HighlightItem[] = [];
    const meta = new Map<string, HlMeta>();
    const add = (hid: string, label: string, spans: { start: number; end: number }[]) => {
      if (!spans.length) return;
      items.push({ id: hid, spans });
      meta.set(hid, { id: hid, label, color: spanColors(items.length - 1) });
    };
    const x = explain.data;
    if (x) {
      x.fields.forEach((f, i) => add(`f:${i}`, f.ocsf_path, f.spans));
      x.unmapped.forEach((u) => add(`u:${u.field}`, `unmapped.${u.field}`, u.spans));
    }
    return { items, meta };
  }, [explain.data]);

  const selected = active ? meta.get(active) : null;
  const selField = active?.startsWith("f:") ? explain.data?.fields[Number(active.slice(2))] : null;
  const selUn = active?.startsWith("u:") ? explain.data?.unmapped.find((u) => `u:${u.field}` === active) : null;

  if (ev.isPending) return <DetailSkeleton />;
  if (ev.isError || !ev.data) return <div className="p-8"><BackLink /><ErrorState what="Event" error={ev.error} onRetry={() => ev.refetch()} /></div>;
  const doc = ev.data;
  const rawErr = raw.error instanceof ApiError ? raw.error : null;
  const tampered = (raw.data && (!raw.data.verified || raw.data.error)) || rawErr?.code === "IntegrityError";

  return (
    <div className="md:h-full flex flex-col">
      <div className="px-4 md:px-8 pt-6 pb-4 animate-rise">
        <BackLink />
        <div className="flex items-center gap-3 mt-3 flex-wrap">
          <h1 className="text-[28px] leading-none">{className(doc.class_uid)}</h1>
          <StatusChip status={doc.ulpf.status} />
          <SourceBadge id={doc.ulpf.source_id} />
          <span className="chip chip-neutral">sev {severityName(doc.severity_id)}</span>
          <span className="mono text-ink-2 text-[12px]">{fmtDateTime(doc.time)}</span>
          <span className="ml-auto flex items-center gap-1 mono text-[11.5px] text-ink-3"><span className="truncate max-w-[200px] md:max-w-[340px]">{id}</span><CopyButton text={id} label="" /></span>
        </div>
      </div>

      {tampered && (
        <div role="alert" className="mx-4 md:mx-8 mb-3 flex items-center gap-3 px-4 py-2.5 rounded-[6px] border border-unparsed/50 bg-unparsed/10 text-unparsed animate-rise">
          <Icon name="alert" size={16} />
          <div className="text-[12.5px]"><b>Integrity failure.</b> The vault bytes for this event no longer match the SHA-256 recorded at ingest. {raw.data?.error?.message ?? rawErr?.message}</div>
        </div>
      )}

      <div className="px-4 md:px-8 grid grid-cols-1 md:grid-cols-12 gap-4 md:flex-1 min-h-0">
        <Panel className="md:col-span-5 min-h-0 max-md:h-[50vh]" bodyClass="overflow-auto" kicker="raw" title="Bytes on the wire"
          right={
            <>
              {bytes && <span className="mono text-[11px] text-ink-3 num">{bytes.length} B</span>}
              <Segmented value={mode} onChange={setMode} label="Raw view" options={[{ value: "text", label: "text" }, { value: "hex", label: "hex" }]} />
            </>
          }>
          {synthetic ? <SyntheticNote doc={doc} />
            : raw.isPending ? <div className="p-4 space-y-2"><Skeleton className="h-5" /><Skeleton className="h-5 w-4/5" /><Skeleton className="h-5 w-3/5" /></div>
            : bytes ? (
              <>
                {explain.isError && (
                  <div className="mx-4 mt-3 px-3 py-2 rounded border border-partial/40 bg-partial/10 text-partial text-[12px] mono">
                    Explain unavailable ({(explain.error as ApiError).code}) — showing bytes without field spans.
                  </div>
                )}
                {explain.data && !explain.data.spans_exact && (
                  <div className="mx-4 mt-3 text-ink-3 text-[11.5px]">Spans for {explain.data.format.toUpperCase()} are display-only approximations.</div>
                )}
                <RawView bytes={bytes} items={items} meta={meta} activeId={active} hoverId={hover} mode={mode}
                  onHover={setHover} onSelect={(i) => setActive((a) => (a === i ? null : i))} />
              </>
            ) : tampered ? (
              <div className="p-6 text-[12.5px] text-ink-2 space-y-2">
                <div className="flex items-center gap-2 text-unparsed"><Icon name="alert" size={15} /><b>The vault block holding these bytes failed verification</b></div>
                <p className="mono text-[11.5px] break-all">{raw.data?.error?.message ?? rawErr?.message}</p>
                <p>The normalized event on the right is intact in the lake; only the preserved original is damaged. Other events are unaffected — run verify on the Integrity page for the exact segment and block.</p>
              </div>
            ) : <ErrorState what="Raw bytes" error={raw.error ?? new Error("The vault returned no bytes for this event")} onRetry={() => raw.refetch()} className="!py-10" />}
          {selected && (
            <div className="mx-4 mb-4 p-3 rounded-[5px] border bg-well/70 text-[12px] animate-rise" style={{ borderColor: selected.color.solid }}>
              <div className="flex items-center gap-2"><span className="h-2 w-2 rounded-[2px]" style={{ background: selected.color.solid }} /><span className="mono text-ink">{selected.label}</span></div>
              {selField && (
                <dl className="mt-2 grid grid-cols-[80px_1fr] gap-y-1 mono text-[11.5px]">
                  <dt className="text-ink-3">source</dt><dd className="text-ink">{selField.source_fields.join(", ") || "—"}</dd>
                  <dt className="text-ink-3">bytes</dt><dd className="text-ink num">{selField.spans.map((s) => `${s.start}–${s.end}`).join(", ")}</dd>
                  <dt className="text-ink-3">rule</dt><dd className="text-ink break-all">{selField.pack_rule}</dd>
                  <dt className="text-ink-3">expr</dt><dd className="text-signal break-all">{selField.expr}</dd>
                </dl>
              )}
              {selUn && <div className="mt-2 mono text-[11.5px] text-ink-2">Extracted but not mapped — preserved in <span className="text-partial">unmapped</span>. bytes <span className="num text-ink">{selUn.spans.map((s) => `${s.start}–${s.end}`).join(", ")}</span></div>}
            </div>
          )}
        </Panel>

        <Panel className="md:col-span-7 min-h-0 max-md:h-[60vh]" bodyClass="overflow-auto" kicker="ocsf" title="Normalized event"
          right={explain.data && <span className="mono text-[11px] text-ink-3">{explain.data.pack_id}@{explain.data.pack_version} · {explain.data.format}</span>}>
          {explain.isPending && <div className="mx-3 mt-2 h-1 skeleton" />}
          <OcsfTree doc={doc} mapped={explain.data?.fields ?? null} meta={meta} activeId={active} hoverId={hover}
            onHover={setHover} onSelect={(i) => setActive((a) => (a === i ? null : i))} />
          {explain.data?.ignored && explain.data.ignored.length > 0 && (
            <div className="px-3 pb-3">
              <div className="kicker mb-1">ignored by pack · counted, never silent</div>
              {explain.data.ignored.map((g) => <div key={g.field} className="mono text-[12px] text-ink-2"><span className="text-ink-3">{g.field}</span> — {g.reason}</div>)}
            </div>
          )}
        </Panel>
      </div>

      <div className="px-4 md:px-8 py-4"><LineagePanel doc={doc} eventId={id} /></div>
    </div>
  );
}

/** Analytics findings carry no raw bytes of their own: they cite the raw lines (by raw_ref) that produced them. */
function SyntheticNote({ doc }: { doc: OcsfEvent }) {
  const refs = (Array.isArray(doc.evidences) ? (doc.evidences as { raw_ref?: string }[]) : []).map((e) => e.raw_ref).filter((r): r is string => !!r);
  const ent = doc.src_endpoint?.ip;
  return (
    <div className="p-4 space-y-3 text-[12.5px] text-ink-2">
      <p>This is a synthetic event produced by the analytics task, so there are no wire bytes to show. It cites {refs.length} raw event{refs.length === 1 ? "" : "s"} as evidence.</p>
      <div className="flex flex-wrap gap-2">
        {ent && <a className="btn btn-sm" href={href("/explorer", { q: `src_ip:${ent}` })}>All events for {ent}</a>}
        <a className="btn btn-sm" href={href("/detections")}>Back to detections</a>
      </div>
      {refs.length > 0 && (
        <ul className="mono text-[11.5px] space-y-1">
          {refs.slice(0, 50).map((r) => <li key={r}><a className="text-signal hover:underline" href={href("/explorer", { q: `raw_ref:${r}` })}>{r}</a></li>)}
        </ul>
      )}
    </div>
  );
}

function BackLink() {
  return (
    <a href="#/explorer" onClick={(e) => { if (history.length > 1) { e.preventDefault(); history.back(); } }}
      className={cx("inline-flex items-center gap-1.5 text-ink-2 hover:text-ink text-[12.5px]")}>
      <Icon name="chevR" size={12} className="rotate-180" /> Back to results
    </a>
  );
}

function DetailSkeleton() {
  return (
    <div className="p-8 space-y-4">
      <Skeleton className="h-8 w-80" />
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4"><Skeleton className="md:col-span-5 h-[420px]" /><Skeleton className="md:col-span-7 h-[420px]" /></div>
      <Skeleton className="h-20" />
    </div>
  );
}
