import { useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { ApiError, api } from "@/api/client";
import { qk } from "@/api/hooks";
import type { OcsfEvent, RawResponse } from "@/api/types";
import { cx, fmtDateTime, pct } from "@/lib/format";
import { base64ToBytes } from "@/lib/spans";
import { Icon } from "./ui/Icon";
import { CopyButton, Meter, StatusChip } from "./ui/primitives";

async function browserSha256(bytes: Uint8Array): Promise<string | null> {
  try {
    if (!globalThis.crypto?.subtle) return null; // insecure context
    const d = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}

type Check =
  | { state: "idle" }
  | { state: "running" }
  | { state: "done"; raw: RawResponse; browser: string | null; lineage: string }
  | { state: "error"; error: ApiError | Error };

function Cell({ label, children, mono = true }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="kicker !text-[9.5px]">{label}</div>
      <div className={cx("mt-1 truncate text-ink", mono && "mono text-[12px]")}>{children}</div>
    </div>
  );
}

export function LineagePanel({ doc, eventId }: { doc: OcsfEvent; eventId: string }) {
  const u = doc.ulpf;
  const hasRaw = !u.synthetic && !!u.raw_sha256;
  const qc = useQueryClient();
  const [check, setCheck] = useState<Check>({ state: "idle" });

  const verify = async () => {
    setCheck({ state: "running" });
    try {
      const raw = await qc.fetchQuery({ queryKey: qk.raw(eventId), queryFn: () => api.raw(eventId), staleTime: 0 });
      const browser = raw.data_b64 ? await browserSha256(base64ToBytes(raw.data_b64)) : null;
      setCheck({ state: "done", raw, browser, lineage: u.raw_sha256 ?? "" });
    } catch (e) {
      setCheck({ state: "error", error: e as Error });
    }
  };

  const ok = check.state === "done" && check.raw.verified && !check.raw.error && check.raw.sha256_actual === check.lineage && (check.browser == null || check.browser === check.lineage);
  const bad = (check.state === "done" && !ok) || check.state === "error";

  return (
    <section className={cx("panel ticks", bad && "!border-unparsed/50")}>
      <div className="px-4 py-3 grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_auto] gap-3 md:gap-6 items-center">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-x-6 gap-y-3 min-w-0">
          <Cell label="raw_ref">{u.raw_ref ?? "—"}</Cell>
          <Cell label="sha256">
            {u.raw_sha256
              ? <span className="inline-flex items-center gap-1 min-w-0"><span className="truncate" title={u.raw_sha256}>{u.raw_sha256.slice(0, 16)}…</span><CopyButton text={u.raw_sha256} label="" /></span>
              : "—"}
          </Cell>
          <Cell label="pack @ version">{u.source_id}<span className="text-ink-3">@{u.pack_version}</span></Cell>
          <Cell label="status" mono={false}><StatusChip status={u.status} /></Cell>
          <Cell label="coverage" mono={false}>
            <span className="flex items-center gap-2"><Meter value={u.coverage} goal={0.85} className="!w-16" /><span className="mono num text-[12px]">{pct(u.coverage, 0)}</span></span>
          </Cell>
          <Cell label="time quality">{u.time_quality}</Cell>
          <Cell label="received">{fmtDateTime(u.recv_time)}</Cell>
          <Cell label="collector">{u.collector_id} · {u.transport}</Cell>
          <Cell label="peer">{u.peer_ip || "—"}</Cell>
          <Cell label="schema">{u.schema}</Cell>
          <Cell label="event_id">{u.event_id}</Cell>
          {u.template_id && <Cell label="template">{u.template_id}</Cell>}
        </div>

        {!hasRaw ? (
          <div className="flex items-center gap-3 pl-6 border-l border-line min-w-[290px] text-[12px] text-ink-3">
            {u.synthetic ? "Synthetic analytics event: it has no raw bytes of its own; its evidence events do." : "No raw hash recorded for this event."}
          </div>
        ) : (
        <div className="flex items-center gap-3 pl-6 border-l border-line min-w-[290px]">
          <button className={cx("btn", !ok && !bad && "btn-primary")} onClick={verify} disabled={check.state === "running"}>
            <Icon name="shield" size={14} />{check.state === "running" ? "Verifying…" : check.state === "idle" ? "Verify raw" : "Verify again"}
          </button>
          <div className="text-[12px] leading-snug min-w-0" aria-live="polite">
            {check.state === "idle" && <span className="text-ink-3">Re-reads the bytes from the vault and recomputes SHA-256.</span>}
            {ok && check.state === "done" && (
              <div className="flex items-start gap-2 text-parsed animate-rise">
                <span className="grid place-items-center h-6 w-6 rounded-full bg-parsed/15 border border-parsed/40 shrink-0"><Icon name="check" size={13} strokeWidth={2.6} /></span>
                <div><div className="font-semibold">Hash match ✔</div>
                  <div className="text-ink-3 mono text-[10.5px]">vault · {check.browser ? "vault + browser agree" : "browser check n/a (insecure context)"} · {check.raw.size} B</div></div>
              </div>
            )}
            {bad && (
              <div className="flex items-start gap-2 text-unparsed animate-rise">
                <span className="grid place-items-center h-6 w-6 rounded-full bg-unparsed/15 border border-unparsed/40 shrink-0"><Icon name="x" size={13} strokeWidth={2.6} /></span>
                <div>
                  <div className="font-semibold">{check.state === "done" ? "Integrity check FAILED" : "Could not verify"}</div>
                  <div className="text-ink-2 mono text-[10.5px] break-all">
                    {check.state === "error" ? check.error.message
                      : check.state === "done" ? <>{check.raw.error?.message ?? "hash mismatch"}<br />expected {check.raw.sha256_expected.slice(0, 20)}…<br />actual&nbsp;&nbsp; {check.raw.sha256_actual.slice(0, 20)}…</> : null}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        )}
      </div>
    </section>
  );
}
