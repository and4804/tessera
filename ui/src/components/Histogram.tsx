import { useMemo } from "react";
import type { Histogram as H } from "@/api/types";
import { fmtClock, fmtDate, fmtInt } from "@/lib/format";
import { CHART_FONT, token, tooltipBase, type EChartsOption } from "@/lib/echarts";
import { EChart, type ChartInstance } from "./EChart";


/** Stacked status histogram. Drag across the bars to zoom the explorer to that window. */
export function Histogram({ data, onBrush, height = 150 }: { data: H; onBrush?: (from: number, to: number) => void; height?: number }) {
  const option = useMemo<EChartsOption>(() => {
    const span = data.to - data.from;
    const label = (t: number) => (span > 36 * 3_600_000 ? `${fmtDate(t).slice(5)} ${fmtClock(t, false).slice(0, 5)}` : fmtClock(t, false).slice(0, 5));
    const cats = data.buckets.map((b) => b.t);
    const mk = (name: "parsed" | "partial" | "unparsed", round: boolean) => ({
      name, type: "bar" as const, stack: "s", barCategoryGap: "18%",
      data: data.buckets.map((b) => b[name]),
      itemStyle: { color: token(name), borderColor: token("panel"), borderWidth: 1, borderRadius: round ? [2, 2, 0, 0] : 0 },
      emphasis: { focus: "series" as const }
    });
    return {
      animationDuration: 400,
      grid: { left: 44, right: 12, top: 10, bottom: 24 },
      aria: { enabled: true },
      tooltip: {
        ...tooltipBase(), trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: "rgba(255,255,255,0.04)" } },
        formatter: (ps: unknown) => {
          const arr = ps as { dataIndex: number; seriesName: string; value: number; color: string }[];
          if (!arr.length) return "";
          const b = data.buckets[arr[0].dataIndex];
          const total = b.parsed + b.partial + b.unparsed;
          const rows = arr.map((p) => `<div style="display:flex;gap:14px;justify-content:space-between"><span><span style="display:inline-block;width:8px;height:8px;background:${p.color};margin-right:6px;border-radius:2px"></span>${p.seriesName}</span><b>${fmtInt(p.value)}</b></div>`).join("");
          return `<div style="margin-bottom:4px;color:${token("ink-2")}">${fmtDate(b.t)} ${fmtClock(b.t, false)}Z</div>${rows}<div style="margin-top:4px;border-top:1px solid ${token("line-strong")};padding-top:4px;display:flex;justify-content:space-between"><span>total</span><b>${fmtInt(total)}</b></div>`;
        }
      },
      brush: { xAxisIndex: 0, brushType: "lineX", brushMode: "single", throttleType: "debounce", brushStyle: { borderWidth: 1, color: "rgba(212,255,58,0.10)", borderColor: token("signal") }, transformable: false },
      xAxis: {
        type: "category", data: cats, boundaryGap: true,
        axisLine: { lineStyle: { color: token("line-strong") } }, axisTick: { show: false },
        axisLabel: { color: token("ink-3"), fontFamily: CHART_FONT, fontSize: 10, formatter: (v: string) => label(Number(v)), hideOverlap: true }
      },
      yAxis: {
        type: "value", splitNumber: 3,
        axisLabel: { color: token("ink-3"), fontFamily: CHART_FONT, fontSize: 10 },
        splitLine: { lineStyle: { color: token("line"), type: "dashed" } }
      },
      series: [mk("parsed", false), mk("partial", false), mk("unparsed", true)]
    };
  }, [data]);

  const total = data.buckets.reduce((a, b) => a + b.parsed + b.partial + b.unparsed, 0);

  return (
    <EChart option={option} height={height} ariaLabel={`Event histogram, ${fmtInt(total)} events`}
      onReady={(c: ChartInstance) => c.dispatchAction({ type: "takeGlobalCursor", key: "brush", brushOption: { brushType: "lineX", brushMode: "single" } })}
      onEvents={{
        brushEnd: (p) => {
          const areas = (p as { areas?: { coordRange?: [number, number] }[] }).areas;
          const r = areas?.[0]?.coordRange;
          if (!r || !onBrush) return;
          const a = Math.max(0, Math.min(...r));
          const b = Math.min(data.buckets.length - 1, Math.max(...r));
          if (data.buckets[a] && data.buckets[b]) onBrush(data.buckets[a].t, data.buckets[b].t + data.interval_ms);
        }
      }} />
  );
}
