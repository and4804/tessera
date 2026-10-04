import { useMutation } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "@/api/client";
import { useClusters } from "@/api/hooks";
import type { AnalyzeResponse, PreviewResponse, PublishResponse, TemplateCluster } from "@/api/types";
import { CoverageGauge } from "@/components/CoverageGauge";
import { YamlEditor } from "@/components/YamlEditor";
import { Icon } from "@/components/ui/Icon";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton, StatusChip } from "@/components/ui/primitives";
import { cx, fmtCompact, fmtInt, pct } from "@/lib/format";
import { href } from "@/lib/router";

/** Onboarding goal from the product spec (≥ 85% of fields mapped); a UI threshold, not data. */
const COVERAGE_GOAL = 0.85;

const splitSamples = (t: string) => t.split(/\r?\n/).filter((l) => l.trim().length > 0);

function Steps({ step }: { step: number }) {
  const S = ["Paste samples", "Analyze → draft", "Edit & preview", "Publish"];
  return (
    <ol className="flex items-center gap-2 mono text-[11px]">
      {S.map((s, i) => (
        <li key={s} className="flex items-center gap-2">
          <span className={cx("grid place-items-center h-5 w-5 rounded-full border text-[10px]", i < step ? "bg-signal text-[#10140a] border-signal" : i === step ? "border-signal text-signal" : "border-line-strong text-ink-3")}>{i < step ? "✓" : i + 1}</span>
          <span className={i === step ? "text-ink" : "text-ink-3"}>{s}</span>
          {i < S.length - 1 && <span className="w-6 h-px bg-line-strong" />}
        </li>
      ))}
    </ol>
  );
}

function ClusterCard({ c, onPick }: { c: TemplateCluster; onPick: () => void }) {
  return (
    <div className="p-3 border-b border-line/60 last:border-0 group">
      <div className="flex items-center gap-2">
        <span className="chip chip-unparsed">{fmtCompact(c.count)} events</span>
        <span className="mono text-[10.5px] text-ink-3 num">{pct(c.share, 0)} of unparsed</span>
        <button className="btn btn-sm ml-auto opacity-80 group-hover:opacity-100" onClick={onPick}><Icon name="wand" size={12} />Onboard</button>
      </div>
      <div className="mono text-[11.5px] text-ink-2 mt-2 break-all line-clamp-2" title={c.template}>{c.template}</div>
    </div>
  );
}

export default function StudioPage() {
  const clusters = useClusters();
  const [text, setText] = useState("");
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const [yaml, setYaml] = useState("");
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [preview, setPreview] = useState<PreviewResponse | null>(null);
  const [previewErr, setPreviewErr] = useState<unknown>(null);
  const [previewing, setPreviewing] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [published, setPublished] = useState<PublishResponse | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const samples = useMemo(() => splitSamples(text), [text]);

  const analyze = useMutation({
    mutationFn: () => api.analyze({ samples, vendor: vendor || undefined, product: product || undefined }),
    onSuccess: (r) => { setAnalysis(r); setYaml(r.draft_pack_yaml); setPreview(null); setPublished(null); setConfirm(false); }
  });
  const publish = useMutation({
    mutationFn: () => api.publish({ pack_yaml: yaml }),
    onSuccess: (r) => { setPublished(r); setConfirm(false); }
  });

  // live preview: debounce edits, last-writer-wins
  const seq = useRef(0);
  useEffect(() => {
    if (!analysis || !yaml) return;
    const my = ++seq.current;
    setPreviewing(true);
    const t = setTimeout(async () => {
      try {
        const r = await api.preview({ pack_yaml: yaml, samples });
        if (my === seq.current) { setPreview(r); setPreviewErr(null); }
      } catch (e) {
        if (my === seq.current) setPreviewErr(e);
      } finally {
        if (my === seq.current) setPreviewing(false);
      }
    }, 650);
    return () => clearTimeout(t);
  }, [yaml, analysis, samples]);

  const lintErrors = preview?.lint.filter((i) => i.level === "error") ?? [];
  const cov = preview?.coverage ?? analysis?.coverage;
  const canPublish = !!preview && preview.ok && lintErrors.length === 0 && preview.coverage.lines_matched > 0 && !previewing;
  const step = published ? 4 : analysis ? (preview ? 3 : 2) : samples.length ? 1 : 0;

  const loadFile = async (f: File | undefined) => {
    if (!f) return;
    setText(await f.text());
  };

  return (
    <div className="pb-10">
      <PageHeader index="04" title="Onboarding" accent="studio" sub="Paste a few lines from a device we have never seen. We draft the pack, you correct it, and it goes live without a restart." right={<div className="max-md:hidden"><Steps step={step} /></div>} />
      <div className="px-4 md:px-8 grid grid-cols-1 md:grid-cols-[360px_minmax(0,1fr)] gap-4 items-start">
        {/* ── left: samples + clusters */}
        <div className="space-y-4">
          <Panel kicker="step 1" title="Sample lines" bodyClass="p-3 space-y-2.5">
            <textarea className="input mono !text-[11.5px] leading-[1.55] h-[220px] resize-y whitespace-pre" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)}
              placeholder={"Paste raw log lines here, one event per line.\n20+ varied lines give the best draft."} aria-label="Sample log lines" />
            <div className="grid grid-cols-2 gap-2">
              <input className="input" placeholder="vendor (optional)" value={vendor} onChange={(e) => setVendor(e.target.value)} aria-label="Vendor" />
              <input className="input" placeholder="product (optional)" value={product} onChange={(e) => setProduct(e.target.value)} aria-label="Product" />
            </div>
            <div className="flex items-center gap-2">
              <span className={cx("mono text-[11.5px] num", samples.length >= 20 ? "text-parsed" : samples.length ? "text-partial" : "text-ink-3")}>{fmtInt(samples.length)} lines{samples.length > 0 && samples.length < 20 ? " · 20+ recommended" : ""}</span>
              <input ref={file} type="file" accept=".log,.txt,.json,.csv,text/*" hidden onChange={(e) => void loadFile(e.target.files?.[0])} />
              <button className="btn btn-sm ml-auto" onClick={() => file.current?.click()}><Icon name="upload" size={12} />Load file</button>
              <button className="btn btn-primary btn-sm" disabled={!samples.length || analyze.isPending} onClick={() => analyze.mutate()}>
                <Icon name="bolt" size={12} />{analyze.isPending ? "Analyzing…" : "Analyze"}
              </button>
            </div>
            {analyze.isError && <div className="text-unparsed text-[12px] mono">{analyze.error instanceof ApiError ? `${analyze.error.code}: ${analyze.error.message}` : "Analysis failed"}</div>}
          </Panel>

          <Panel kicker="suggestions" title="Unparsed clusters" bodyClass="max-h-[340px] overflow-auto"
            right={clusters.data && <span className="mono text-[11px] text-ink-3 num">{clusters.data.items.length}</span>}>
            {clusters.isPending ? <div className="p-3 space-y-2"><Skeleton className="h-14" /><Skeleton className="h-14" /></div>
              : clusters.isError ? <ErrorState what="Clusters" error={clusters.error} onRetry={() => clusters.refetch()} className="!py-8" />
              : clusters.data.items.length === 0 ? <EmptyState icon="check" title="Nothing unparsed" className="!py-8">When events arrive that no pack matches, the template miner groups them here so you can onboard the biggest cluster first.</EmptyState>
              : clusters.data.items.map((c) => <ClusterCard key={c.template_id} c={c} onPick={() => { setText((c.samples?.length ? c.samples : [c.example_raw]).join("\n")); setAnalysis(null); setPreview(null); }} />)}
          </Panel>
        </div>

        {/* ── right: draft */}
        <div className="space-y-4 min-w-0">
          {!analysis ? (
            <Panel><EmptyState icon="wand" title={analyze.isPending ? "Reading your samples…" : "No draft yet"}>
              {analyze.isPending ? "Sniffing the format, mining templates, inferring field types and suggesting OCSF mappings."
                : "Paste samples (or pick an unparsed cluster) and press Analyze. The draft pack and a live preview appear here."}</EmptyState></Panel>
          ) : (
            <>
              <section className="panel ticks px-5 py-3.5 flex items-center gap-5 flex-wrap animate-rise">
                <div><div className="kicker">format</div><div className="mono text-[13px] mt-0.5 flex items-center gap-2"><span className="chip chip-signal">{analysis.format}</span><span className="text-ink-3 num">{pct(analysis.format_confidence, 0)} sure</span></div></div>
                <div><div className="kicker">class</div><div className="text-[13px] mt-0.5">{analysis.class_name} <span className="mono text-ink-3">{analysis.class_uid}</span></div></div>
                <div><div className="kicker">pack id</div><div className="mono text-[13px] mt-0.5 text-signal">{analysis.pack_id}</div></div>
                {analysis.est_minutes != null && <div><div className="kicker">est. time to onboard</div><div className="mono text-[13px] mt-0.5 num">{analysis.est_minutes.toFixed(1)} min</div></div>}
                {analysis.warnings.length > 0 && <div className="ml-auto text-partial text-[12px] mono max-w-md">{analysis.warnings.map((w) => <div key={w}>! {w}</div>)}</div>}
              </section>

              <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_300px] gap-4">
                <Panel kicker="step 3" title="Pack (YAML)" bodyClass="" right={
                  <>
                    <span className="mono text-[11px] text-ink-3">{previewing ? <span className="text-signal animate-pulseDot">previewing…</span> : preview ? "preview current" : ""}</span>
                    <button className="btn btn-ghost btn-sm" onClick={() => setYaml(analysis.draft_pack_yaml)} disabled={yaml === analysis.draft_pack_yaml}>reset to draft</button>
                  </>}>
                  <YamlEditor value={yaml} onChange={setYaml} issues={preview?.lint ?? []} />
                  {preview && preview.lint.length > 0 && (
                    <ul className="border-t border-line p-3 space-y-1 mono text-[11.5px]">
                      {preview.lint.map((i, k) => <li key={k} className={i.level === "error" ? "text-unparsed" : "text-partial"}>{i.level === "error" ? "✗" : "!"} {i.line ? `line ${i.line}: ` : ""}{i.message}</li>)}
                    </ul>
                  )}
                </Panel>

                <div className="space-y-4">
                  <Panel kicker="live preview" title="Coverage" bodyClass="p-4 flex flex-col items-center gap-4">
                    {cov ? <CoverageGauge value={cov.fields_mapped_pct} goal={COVERAGE_GOAL} /> : <Skeleton className="h-[110px] w-[200px]" />}
                    {cov && (
                      <div className="w-full grid grid-cols-2 gap-3 pt-3 border-t border-line">
                        <div><div className="kicker">lines matched</div><div className="mono num text-[15px] mt-0.5">{pct(cov.lines_matched_pct, 0)} <span className="text-ink-3 text-[11px]">{cov.lines_matched}/{cov.lines_total}</span></div></div>
                        <div><div className="kicker">event coverage</div><div className="mono num text-[15px] mt-0.5">{pct(cov.mean_event_coverage, 0)}</div></div>
                      </div>
                    )}
                    {preview && (
                      <div className="w-full flex items-center gap-2 mono text-[11.5px]">
                        <span className={cx("chip", preview.tests.failed ? "chip-unparsed" : "chip-parsed")}>tests {preview.tests.passed}✓ {preview.tests.failed ? `${preview.tests.failed}✗` : ""}</span>
                        <span className={cx("chip", lintErrors.length ? "chip-unparsed" : "chip-parsed")}>{lintErrors.length ? `${lintErrors.length} lint errors` : "lint clean"}</span>
                      </div>
                    )}
                    {cov && cov.unmapped.length > 0 && (
                      <div className="w-full"><div className="kicker mb-1.5">still unmapped</div>
                        <div className="flex flex-wrap gap-1">{cov.unmapped.slice(0, 8).map((u) => <span key={u.field} className="chip chip-neutral !normal-case">{u.field}</span>)}</div></div>
                    )}
                  </Panel>

                  <Panel kicker="step 4" title="Publish" bodyClass="p-4 space-y-3">
                    {published ? (
                      <div className="animate-rise space-y-2">
                        <div className="flex items-center gap-2 text-parsed"><Icon name="check" size={16} strokeWidth={2.4} /><b>Published</b></div>
                        <div className="mono text-[12px] text-ink-2 break-all">{published.pack_id}@{published.version}<br />{published.path}</div>
                        <div className="text-[12px] text-ink-2">{published.reloaded ? "Workers recompiled the pack; new events are normalized with it now." : "Written to disk — workers have not confirmed a reload."}</div>
                        <a className="btn btn-primary w-full" href={href("/live")}><Icon name="live" size={13} />Watch it live</a>
                      </div>
                    ) : confirm ? (
                      <div className="space-y-2 animate-rise">
                        <p className="text-[12.5px] text-ink-2">Write <span className="mono text-signal">{analysis.pack_id}</span> to <span className="mono">packs/custom/</span> and hot-reload all workers?</p>
                        <div className="flex gap-2"><button className="btn btn-primary flex-1" onClick={() => publish.mutate()} disabled={publish.isPending}>{publish.isPending ? "Publishing…" : "Confirm"}</button><button className="btn" onClick={() => setConfirm(false)}>Cancel</button></div>
                        {publish.isError && <div className="text-unparsed text-[12px] mono">{(publish.error as Error).message}</div>}
                      </div>
                    ) : (
                      <>
                        <button className="btn btn-primary w-full" disabled={!canPublish} onClick={() => setConfirm(true)}><Icon name="bolt" size={13} />Publish pack</button>
                        {!canPublish && <p className="text-ink-3 text-[11.5px]">{previewing ? "Waiting for the preview…" : !preview ? "Preview must run first." : lintErrors.length ? "Fix lint errors to publish." : "No sample line matches yet."}</p>}
                        {cov && cov.fields_mapped_pct < COVERAGE_GOAL && canPublish && <p className="text-partial text-[11.5px]">Below the {pct(COVERAGE_GOAL, 0)} goal — publishable, but unmapped fields stay in <code>unmapped</code>.</p>}
                      </>
                    )}
                  </Panel>
                </div>
              </div>

              <Panel kicker="preview" title="Normalized sample events" bodyClass=""
                right={preview && <span className="mono text-[11px] text-ink-3 num">{preview.rows.length} rows</span>}>
                {previewErr && !preview ? <ErrorState what="Preview" error={previewErr} className="!py-8" onRetry={() => setYaml((y) => y + "")} />
                  : !preview ? <div className="p-4 space-y-2"><Skeleton className="h-7" /><Skeleton className="h-7" /><Skeleton className="h-7" /></div>
                  : preview.rows.length === 0 ? <EmptyState icon="doc" title="No rows produced" className="!py-8">{lintErrors.length ? "The pack has lint errors, so nothing was evaluated." : "The pack matched none of the sample lines."}</EmptyState>
                  : (
                    <div className="overflow-auto max-h-[420px]">
                      <table className="w-full border-collapse">
                        <thead className="sticky top-0 bg-panel z-10"><tr className="kicker !text-[10px] h-8 border-b border-line text-left">
                          <th className="px-3 pl-4 font-medium w-10">#</th><th className="px-3 font-medium">Status</th><th className="px-3 font-medium">Cov</th><th className="px-3 font-medium">Mapped</th><th className="px-3 font-medium">Unmapped</th><th className="px-3 font-medium">Raw</th></tr></thead>
                        <tbody>
                          {preview.rows.slice(0, 60).map((r) => (
                            <tr key={r.line_no} className="border-b border-line/50 align-top hover:bg-raised/40">
                              <td className="px-3 pl-4 py-2 mono text-[11px] text-ink-3 num">{r.line_no}</td>
                              <td className="px-3 py-2"><StatusChip status={r.status} /></td>
                              <td className={cx("px-3 py-2 mono num text-[11.5px]", r.coverage >= COVERAGE_GOAL ? "text-parsed" : "text-partial")}>{Math.round(r.coverage * 100)}</td>
                              <td className="px-3 py-2"><div className="flex flex-wrap gap-1 max-w-[380px]">{Object.entries(r.mapped).slice(0, 6).map(([k, v]) => <span key={k} className="chip chip-neutral !normal-case !h-auto py-0.5"><span className="text-ink-3">{k}</span><span className="text-ink">{String(v)}</span></span>)}</div></td>
                              <td className="px-3 py-2 mono text-[11px] text-partial">{Object.keys(r.unmapped).join(", ") || <span className="text-ink-3">—</span>}</td>
                              <td className="px-3 py-2 mono text-[11px] text-ink-3 max-w-[300px] truncate" title={r.raw}>{r.raw}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
              </Panel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
