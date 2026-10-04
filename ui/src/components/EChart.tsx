import { useEffect, useRef } from "react";
import { echarts, type EChartsOption } from "@/lib/echarts";

type Instance = ReturnType<typeof echarts.init>;
export type ChartInstance = Instance;

interface Props {
  option: EChartsOption;
  height: number | string;
  className?: string;
  ariaLabel?: string;
  onReady?: (chart: Instance) => void;
  onEvents?: Record<string, (params: unknown) => void>;
}

/** Minimal ECharts host: canvas renderer, ResizeObserver, disposal. */
export function EChart({ option, height, className, ariaLabel, onReady, onEvents }: Props) {
  const el = useRef<HTMLDivElement>(null);
  const chart = useRef<Instance | null>(null);
  const evRef = useRef(onEvents);
  evRef.current = onEvents;

  useEffect(() => {
    if (!el.current) return;
    const c = echarts.init(el.current, undefined, { renderer: "canvas" });
    chart.current = c;
    onReady?.(c);
    for (const name of ["brushEnd", "click", "datazoom"]) c.on(name, (p: unknown) => evRef.current?.[name]?.(p));
    const ro = new ResizeObserver(() => c.resize());
    ro.observe(el.current);
    return () => {
      ro.disconnect();
      c.dispose();
      chart.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    chart.current?.setOption(option, { notMerge: true });
  }, [option]);

  return <div ref={el} className={className} style={{ height }} role="img" aria-label={ariaLabel} />;
}
