import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import {
  AriaComponent, BrushComponent, GridComponent, LegendComponent, MarkLineComponent, TooltipComponent, ToolboxComponent
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

echarts.use([BarChart, LineChart, GridComponent, TooltipComponent, BrushComponent, ToolboxComponent, LegendComponent, MarkLineComponent, AriaComponent, CanvasRenderer]);

export { echarts };
export type { EChartsCoreOption as EChartsOption } from "echarts/core";

/** Resolve a design-token channel triplet ("53 214 176") into a CSS colour for canvas charts. */
export function token(name: string, alpha = 1): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim();
  const [r, g, b] = v.split(/\s+/);
  return alpha === 1 ? `rgb(${r}, ${g}, ${b})` : `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export const CHART_FONT = '"JetBrains Mono", ui-monospace, monospace';

/** Shared tooltip chrome. */
export function tooltipBase() {
  return {
    backgroundColor: token("raised"),
    borderColor: token("line-strong"),
    borderWidth: 1,
    padding: [8, 10],
    textStyle: { color: token("ink"), fontFamily: CHART_FONT, fontSize: 11 },
    extraCssText: "box-shadow:0 12px 32px -8px rgba(0,0,0,.7);border-radius:5px;"
  };
}
