import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ApiError, verifyVault } from "@/api/client";
import { qk, useLedger, useSegments } from "@/api/hooks";
import type { ChainStatus, LedgerCounts, VaultSegment, VerifyMessage } from "@/api/types";
import { Icon } from "@/components/ui/Icon";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { cx, fmtAgo, fmtBytes, fmtDateTime, fmtDuration, fmtInt } from "@/lib/format";

const normalized = (c: LedgerCounts) => c.normalized_parsed + c.normalized_partial;
const delta = (c: LedgerCounts) => c.ingested - (c.sunk + c.dropped + c.in_flight);

const CHAIN_CHIP: Record<ChainStatus, string> = { ok: "chip-parsed", open: "chip-info", unverified: "chip-neutral", broken: "chip-unparsed" };

type Row = { source: string } & LedgerCounts;
const COLS: { key: string; label: string; get: (c: LedgerCounts) => number; tone?: "bad0" }[] = [
  { key: "ingested", label: "Ingested", get: (c) => c.ingested },
  { key: "vaulted", label: "Vaulted", get: (c) => c.vaulted },
  { key: "normalized", label: "Normalized", get: normalized },
  { key: "unparsed", label: "Unparsed", get: (c) => c.unparsed },
  { key: "sunk", label: "Sunk", get: (c) => c.sunk },
  { key: "dropped", label: "Dropped", get: (c) => c.dropped, tone: "bad0" },
  { key: "in_flight", label: "In flight", get: (c) => c.in_flight }
];

function LedgerTable({ rows, total }: { rows: Row[]; total: LedgerCounts }) {
  const cell = (key: string, n: number, tone?: "bad0") => (
    <td key={key} className={cx("px-3 text-right num mono text-[12.5px]", tone === "bad0" && (n === 0 ? "text-parsed" : "text-unparsed font-semibold"))}>{fmtInt(n)}</td>
  );
  return (
    <div className="overflow-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="kicker !text-[10px] h-8 border-b border-line text-right">
            <th className="px-4 text-left font-medium">Source</th>
            {COLS.map((c) => <th key={c.key} className="px-3 font-medium">{c.label}</th>)}
            <th className="px-3 font-medium">Δ</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.source} className="h-8 border-b border-line/50 hover:bg-raised/50">
              <td className="px-4 mono text-[12px] text-ink">{r.source}</td>
              {COLS.map((c) => <td key={c.key} className={cx("px-3 text-right num mono text-[12.5px]", c.tone === "bad0" && (c.get(r) === 0 ? "text-parsed" : "text-unparsed font-semibold"), c.tone !== "bad0" && "text-ink-2")}>{fmtInt(c.get(r))}</td>)}
              <td className={cx("px-3 text-right num mono text-[12.5px]", delta(r) === 0 ? "text-parsed" : "text-unparsed font-semibold")}>{delta(r) === 0 ? "0" : fmtInt(delta(r))}</td>
            </tr>
          ))}
        </tbody>
        <tfoot>
          <tr className="h-10 rule-double bg-well/50">
            <td className="px-4 font-display text-[15px]">Total</td>
            {COLS.map((c) => cell(c.key, c.get(total), c.tone))}
            <td className={cx("px-3 text-right num mono text-[13px] font-semibold", delta(total) === 0 ? "text-parsed" : "text-unparsed")}>{fmtInt(delta(total))}</td>
          </tr>
        </tfoot>
      </table>
    </div>
  );
}

interface VerifyState {
  running: boolean;
  progress: { segment: string; done: number; total: number } | null;
  results: Record<string, Extract<VerifyMessage, { type: "segment_result" }>>;
  done: Extract<VerifyMessage, { type: "done" }> | null;
  error: string | null;
}
const IDLE: VerifyState = { running: false, progress: null, results: {}, done: null, error: null };

export function IntegrityPage() {
  const ledger = useLedger();
  const segs = useSegments();
  const qc = useQueryClient();
  const [v, setV] = useState<VerifyState>(IDLE);
  const abort = useRef<AbortController | null>(null);

  const run = async () => {
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setV({ ...IDLE, running: true });
    try {
      for await (const m of verifyVault({ all: true }, ac.signal)) {
        setV((s) => {
          if (m.type === "progress") return { ...s, progress: m };
          if (m.type === "segment_result") return { ...s, results: { ...s.results, [m.segment]: m } };
          return { ...s, done: m, running: false };
        });
      }
      setV((s) => ({ ...s, running: false }));
    } catch (e) {
      if ((e as Error).name !== "AbortError") setV((s) => ({ ...s, running: false, error: e instanceof ApiError ? `${e.code}: ${e.message}` : (e as Error).message }));
    } finally {
      void qc.invalidateQueries({ queryKey: qk.segments });
    }
  };

  const L = ledger.data;
  const serverOk = L?.conserved;
  const clientOk = L ? delta(L.totals) === 0 && L.per_source.every((r) => delta(r) === 0) && L.totals.dropped === 0 : null;
  const disagree = L != null && serverOk !== clientOk;
  const verdict: "ok" | "bad" | null = L == null ? null : serverOk && clientOk ? "ok" : "bad";

  const segStatus = (s: VaultSegment): { status: ChainStatus; err: VaultSegment["error"] } => {
    const r = v.results[s.segment];
    if (r) return { status: r.ok ? "ok" : "broken", err: r.error ?? null };
    return { status: s.chain_status, err: s.error ?? null };
  };

  return (
    <div className="pb-10">
      <PageHeader index="05" title="Integrity" accent="& ledger" sub="Proof, not promise: every event is counted at every stage, and every vault block is hash-chained and signed."
        right={
          v.running
            ? <button className="btn" onClick={() => abort.current?.abort()}><Icon name="x" size={13} />Cancel</button>
            : <button className="btn btn-primary" onClick={run}><Icon name="shield" size={14} />Run verify</button>
        } />
      <div className="px-4 md:px-8 space-y-5">
        {/* verdict */}
        {ledger.isPending ? <Skeleton className="h-[132px]" />
          : ledger.isError && !L ? <Panel><ErrorState what="Ledger" error={ledger.error} onRetry={() => ledger.refetch()} /></Panel>
          : L && (
            <section className={cx("panel ticks overflow-hidden", verdict === "ok" ? "!border-parsed/35" : "!border-unparsed/50")}>
              <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(520px 160px at 0% 0%, rgb(var(--${verdict === "ok" ? "parsed" : "unparsed"}) / 0.12), transparent 70%)` }} />
              <div className="relative grid grid-cols-1 md:grid-cols-[auto_1fr_auto] gap-4 md:gap-8 items-center px-7 py-6">
                <div className={cx("grid place-items-center h-16 w-16 rounded-full border-2", verdict === "ok" ? "border-parsed text-parsed bg-parsed/10" : "border-unparsed text-unparsed bg-unparsed/10")}>
                  <Icon name={verdict === "ok" ? "check" : "alert"} size={30} strokeWidth={2.2} />
                </div>
                <div>
                  <div className="kicker">conservation</div>
                  <div className="font-display text-[34px] leading-tight">
                    {verdict === "ok" ? <>Zero loss. <em className="text-parsed font-light italic">Every event accounted for.</em></> : <>Conservation <em className="text-unparsed font-light italic">violated.</em></>}
                  </div>
                  <div className="mono text-[11.5px] text-ink-3 mt-1.5">ingested = vaulted = normalized + unparsed = sunk + dropped + in-flight · as of {fmtDateTime(L.as_of)}</div>
                  {disagree && <div className="mt-2 text-partial text-[12px]">The server's verdict and the counters disagree — treat this ledger as unverified.</div>}
                </div>
                <div className="md:text-right">
                  <div className="kicker">events ingested</div>
                  <div className="font-display text-[38px] num leading-none mt-1">{fmtInt(L.totals.ingested)}</div>
                  <div className={cx("mono text-[12px] mt-1.5", L.totals.dropped === 0 ? "text-parsed" : "text-unparsed")}>{fmtInt(L.totals.dropped)} dropped</div>
                </div>
              </div>
            </section>
          )}

        {L && (
          <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_280px] gap-4">
            <Panel kicker="ledger" title="Per-source conservation" bodyClass="">
              {L.per_source.length === 0 ? <EmptyState icon="layers" title="Nothing ingested yet" className="!py-8">Counters appear as soon as the first event is received.</EmptyState>
                : <LedgerTable rows={L.per_source} total={L.totals} />}
            </Panel>
            <div className="space-y-4">
              <Panel kicker="sinks" title="Sunk by sink" bodyClass="p-3 space-y-1.5">
                {Object.keys(L.sunk_by_sink).length === 0 && <span className="text-ink-3 text-[12px]">no sink activity</span>}
                {Object.entries(L.sunk_by_sink).map(([k, n]) => <div key={k} className="flex justify-between mono text-[12px]"><span className="text-ink-2">{k}</span><span className="num">{fmtInt(n)}</span></div>)}
              </Panel>
              <Panel kicker="drops" title="Dropped by reason" bodyClass="p-3 space-y-1.5">
                {Object.keys(L.dropped_by_reason).length === 0 ? <span className="text-parsed text-[12.5px]">None. Dropping is off by default (R3).</span>
                  : Object.entries(L.dropped_by_reason).map(([k, n]) => <div key={k} className="flex justify-between mono text-[12px]"><span className="text-ink-2">{k}</span><span className="num text-unparsed">{fmtInt(n)}</span></div>)}
              </Panel>
            </div>
          </div>
        )}

        {/* verify result */}
        {(v.running || v.done || v.error) && (
          <section role="status" className={cx("panel p-4 animate-rise", v.done && !v.done.ok && "!border-unparsed/60", v.done?.ok && "!border-parsed/40")}>
            {v.running && (
              <div>
                <div className="flex justify-between mono text-[12px] mb-2"><span>Verifying <span className="text-signal">{v.progress?.segment ?? "…"}</span></span><span className="num text-ink-3">{v.progress ? `${fmtInt(v.progress.done)} / ${fmtInt(v.progress.total)}` : ""}</span></div>
                <div className="h-1.5 rounded-full bg-well overflow-hidden"><div className="h-full bg-signal transition-[width] duration-200" style={{ width: `${v.progress && v.progress.total ? (v.progress.done / v.progress.total) * 100 : 4}%` }} /></div>
              </div>
            )}
            {v.error && <div className="text-unparsed mono text-[12.5px]">Verify failed to run: {v.error}</div>}
            {v.done && (v.done.ok ? (
              <div className="flex items-center gap-3 text-parsed"><Icon name="check" size={18} strokeWidth={2.4} />
                <div><b>Vault verified.</b> <span className="text-ink-2">{fmtInt(v.done.segments_checked)} segments · {fmtInt(v.done.frames_checked)} frames · chain and signatures intact · {fmtDuration(v.done.duration_ms)}</span></div></div>
            ) : (
              <div className="flex items-start gap-3 text-unparsed"><Icon name="alert" size={18} />
                <div><b>Tampering detected.</b>
                  {v.done.first_failure && <div className="mono text-[13px] mt-1 text-ink">first bad frame → segment <span className="text-unparsed">{v.done.first_failure.segment}</span> · block <span className="text-unparsed">{v.done.first_failure.block}</span>{v.done.first_failure.frame != null && <> · frame <span className="text-unparsed">{v.done.first_failure.frame}</span></>}</div>}
                  <div className="text-ink-2 text-[12px] mt-1">{fmtInt(v.done.segments_checked)} segments checked in {fmtDuration(v.done.duration_ms)}. Only events in the broken block are affected; Explain/raw return IntegrityError for those alone.</div></div></div>
            ))}
          </section>
        )}

        <Panel kicker="vault" title="Segments" bodyClass=""
          right={segs.data && <span className="mono text-[11px] text-ink-3 num">{fmtInt(segs.data.items.length)} segments · {fmtBytes(segs.data.items.reduce((a, s) => a + s.size_bytes, 0))}</span>}>
          {segs.isPending ? <div className="p-4 space-y-2">{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-7" />)}</div>
            : segs.isError && !segs.data ? <ErrorState what="Segments" error={segs.error} onRetry={() => segs.refetch()} />
            : segs.data!.items.length === 0 ? <EmptyState icon="shield" title="The vault is empty" className="!py-10">Segments are created as soon as the first raw event is appended.</EmptyState>
            : (
              <div className="overflow-auto">
                <table className="w-full border-collapse">
                  <thead><tr className="kicker !text-[10px] h-8 border-b border-line text-left">
                    {["Segment", "Opened", "State", "Events", "Blocks", "Size", "Chain head", "Chain", "Signature", "Verified"].map((h) => <th key={h} className="px-3 font-medium first:pl-4">{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {segs.data!.items.map((s) => {
                      const { status, err } = segStatus(s);
                      return (
                        <tr key={s.segment} className={cx("h-9 border-b border-line/50 hover:bg-raised/50 mono text-[12px]", status === "broken" && "bg-unparsed/[0.06]")}>
                          <td className="px-3 pl-4 text-ink">{s.segment}</td>
                          <td className="px-3 text-ink-2">{fmtDateTime(s.created_ms)}</td>
                          <td className="px-3 text-ink-2">{s.sealed_ms ? "sealed" : "open"}</td>
                          <td className="px-3 num">{fmtInt(s.n_events)}</td>
                          <td className="px-3 num">{fmtInt(s.n_blocks)}</td>
                          <td className="px-3 num text-ink-2">{fmtBytes(s.size_bytes)}</td>
                          <td className="px-3 text-ink-3" title={s.chain_head}>{s.chain_head.slice(0, 12)}…</td>
                          <td className="px-3">
                            <span className={cx("chip", CHAIN_CHIP[status])}>{status === "ok" ? "✔ ok" : status}</span>
                            {status === "broken" && err && <div className="text-unparsed text-[10.5px] mt-0.5">block {err.block}{err.frame != null ? ` · frame ${err.frame}` : ""}</div>}
                          </td>
                          <td className="px-3">{s.signature_ok == null ? <span className="text-ink-3">—</span> : s.signature_ok ? <span className="text-parsed">ed25519 ✔</span> : <span className="text-unparsed">invalid</span>}</td>
                          <td className="px-3 text-ink-3">{v.results[s.segment] ? "just now" : fmtAgo(s.last_verified_ms)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
        </Panel>
      </div>
    </div>
  );
}
