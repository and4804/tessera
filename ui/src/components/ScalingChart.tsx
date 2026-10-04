import { useMemo } from "react";
import type { BenchmarkResults } from "@/api/types";
import { fmtInt, pct } from "@/lib/format";
import { CHART_FONT, token, tooltipBase, type EChartsOption } from "@/lib/echarts";
import { EChart } from "./EChart";

/** Measured eps per worker count vs. the ideal-linear line extrapolated from the 1-worker (or smallest) point. */
export function ScalingChart({ data }: { data: BenchmarkResults }) {
  const option = useMemo<EChartsOption>(() => {
    const pts = [...data.scaling].sort((a, b) => a.workers - b.workers);
    const base = pts[0];
    const perWorker = base ? base.eps / base.workers : 0;
    const cats = pts.map((p) => String(p.workers));
    const marks = [
      data.targets?.eps != null && { yAxis: data.targets.eps, name: "target" },
      data.targets?.eps_stretch != null && { yAxis: data.targets.eps_stretch, name: "stretch" }
    ].filter(Boolean) as { yAxis: number; name: string }[];
    return {
      animationDuration: 600,
      aria: { enabled: true },
      grid: { left: 56, right: 18, top: 28, bottom: 34 },
      legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 3, textStyle: { color: token("ink-2"), fontFamily: CHART_FONT, fontSize: 11 } },
      tooltip: {
        ...tooltipBase(), trigger: "axis",
        formatter: (ps: unknown) => {
          const i = (ps as { dataIndex: number }[])[0].dataIndex;
          const p = pts[i];
          const eff = perWorker ? p.eps / (perWorker * p.workers) : null;
          return `<div style="color:${token("ink-2")}">${p.workers} worker${p.workers > 1 ? "s" : ""}</div><b>${fmtInt(p.eps)}</b> eps${eff != null ? `<br/><span style="color:${token("ink-2")}">${pct(eff, 0)} of linear</span>` : ""}`;
        }
      },
      xAxis: { type: "category", data: cats, name: "workers", nameLocation: "middle", nameGap: 22, nameTextStyle: { color: token("ink-3"), fontFamily: CHART_FONT, fontSize: 10 },
        axisLine: { lineStyle: { color: token("line-strong") } }, axisTick: { show: false }, axisLabel: { color: token("ink-2"), fontFamily: CHART_FONT, fontSize: 11 } },
      yAxis: { type: "value", name: "events / s", nameTextStyle: { color: token("ink-3"), fontFamily: CHART_FONT, fontSize: 10, align: "left" },
        axisLabel: { color: token("ink-3"), fontFamily: CHART_FONT, fontSize: 10, formatter: (v: number) => (v >= 1000 ? `${v / 1000}k` : String(v)) },
        splitLine: { lineStyle: { color: token("line"), type: "dashed" } } },
      series: [
        {
          name: "measured", type: "bar", data: pts.map((p) => p.eps), barMaxWidth: 46,
          itemStyle: { color: token("signal"), borderRadius: [4, 4, 0, 0] },
          label: { show: true, position: "top", color: token("ink"), fontFamily: CHART_FONT, fontSize: 11, formatter: (p: { value: number }) => fmtInt(p.value) },
          markLine: marks.length ? { symbol: "none", silent: true, lineStyle: { color: token("partial"), type: "dashed" }, label: { color: token("partial"), fontFamily: CHART_FONT, fontSize: 10, formatter: "{b}" }, data: marks } : undefined
        },
        { name: "ideal linear", type: "line", data: pts.map((p) => perWorker * p.workers), symbol: "circle", symbolSize: 5,
          lineStyle: { color: token("ink-3"), type: "dashed", width: 1.5 }, itemStyle: { color: token("ink-3") } }
      ]
    };
  }, [data]);
  return <EChart option={option} height={300} ariaLabel="Throughput scaling by worker count" />;
}
