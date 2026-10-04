import { pct } from "@/lib/format";

/** Half-circle gauge for field coverage, with a tick at the goal. value, goal in 0..1 */
export function CoverageGauge({ value, goal, label = "fields mapped" }: { value: number; goal: number; label?: string }) {
  const R = 54;
  const C = Math.PI * R;
  const v = Math.max(0, Math.min(1, value));
  const ok = v >= goal;
  const color = ok ? "parsed" : v >= goal * 0.6 ? "partial" : "unparsed";
  const a = Math.PI * (1 - goal);
  const gx = 70 + Math.cos(a) * R;
  const gy = 70 - Math.sin(a) * R;
  const gx2 = 70 + Math.cos(a) * (R + 9);
  const gy2 = 70 - Math.sin(a) * (R + 9);
  return (
    <div className="relative w-[200px]" role="meter" aria-label={label} aria-valuenow={Math.round(v * 100)} aria-valuemin={0} aria-valuemax={100}>
      <svg viewBox="0 0 140 84" className="w-full">
        <path d="M16 70 A54 54 0 0 1 124 70" fill="none" strokeWidth="9" strokeLinecap="round" style={{ stroke: "rgb(var(--well))" }} />
        <path d="M16 70 A54 54 0 0 1 124 70" fill="none" strokeWidth="9" strokeLinecap="round" style={{ stroke: `rgb(var(--${color}))`, transition: "stroke-dasharray .6s cubic-bezier(.2,.7,.2,1), stroke .3s", filter: `drop-shadow(0 0 6px rgb(var(--${color}) / .45))` }}
          strokeDasharray={`${v * C} ${C}`} />
        <line x1={gx} y1={gy} x2={gx2} y2={gy2} strokeWidth="1.6" style={{ stroke: "rgb(var(--ink))" }} />
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center">
        <div className="font-display num text-[34px] leading-none" style={{ color: `rgb(var(--${color}))` }}>{pct(v, 0)}</div>
        <div className="kicker mt-1">{label} · goal {pct(goal, 0)}</div>
      </div>
    </div>
  );
}
