import { useEffect, type ReactNode } from "react";
import { onApiActivity } from "@/api/client";
import { useHealth } from "@/api/hooks";
import { cx, fmtClock } from "@/lib/format";
import { href, useRoute } from "@/lib/router";
import { useUi } from "@/store/ui";
import { Icon, type IconName } from "./ui/Icon";

const NAV: { path: string; label: string; icon: IconName; n: string }[] = [
  { path: "/live", label: "Live", icon: "live", n: "01" },
  { path: "/explorer", label: "Explorer", icon: "search", n: "02" },
  { path: "/sources", label: "Sources", icon: "server", n: "03" },
  { path: "/studio", label: "Onboarding", icon: "wand", n: "04" },
  { path: "/integrity", label: "Integrity", icon: "shield", n: "05" },
  { path: "/detections", label: "Detections", icon: "alert", n: "06" },
  { path: "/benchmark", label: "Benchmark", icon: "gauge", n: "07" }
];

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true">
        <rect x="1" y="1" width="30" height="30" rx="7" fill="rgb(var(--well))" stroke="rgb(var(--line-strong))" />
        <path d="M7 10h18" stroke="rgb(var(--ink-3))" strokeWidth="2.6" strokeLinecap="round" />
        <path d="M7 16h12" stroke="rgb(var(--signal))" strokeWidth="2.6" strokeLinecap="round" />
        <path d="M7 22h18" stroke="rgb(var(--ink-3))" strokeWidth="2.6" strokeLinecap="round" />
        <circle cx="24" cy="16" r="2.2" fill="rgb(var(--signal))" />
      </svg>
      <div className="leading-none">
        <div className="font-display text-[19px] tracking-tight">ULPF</div>
        <div className="kicker mt-0.5 !text-[9px]">tessera</div>
      </div>
    </div>
  );
}

function ConnectionLed() {
  const conn = useUi((s) => s.connection);
  const health = useHealth();
  const ok = conn.ok;
  const color = ok === null ? "bg-ink-3" : ok ? "bg-parsed" : "bg-unparsed";
  return (
    <div className="px-3 py-3 border-t border-line max-md:hidden">
      <div className="flex items-center gap-2">
        <span className="relative flex h-2.5 w-2.5">
          {ok && <span className={cx("absolute inline-flex h-full w-full rounded-full opacity-60 animate-ping", color)} />}
          <span className={cx("relative inline-flex h-2.5 w-2.5 rounded-full", color, ok === false && "animate-pulseDot")} />
        </span>
        <span className="mono text-[11px] text-ink">{ok === null ? "connecting" : ok ? "api online" : "api offline"}</span>
      </div>
      <div className="mono text-[10.5px] text-ink-3 mt-1.5 leading-4">
        {health.data ? (
          <>node {health.data.node_id}<br />v{health.data.version} · ocsf {health.data.ocsf_version}</>
        ) : ok === false && conn.since ? (
          <>since {fmtClock(conn.since, false)} UTC<br />retrying every 5s</>
        ) : (
          "awaiting handshake"
        )}
      </div>
      {conn.mock && (
        <div className="mt-2 chip chip-partial w-full justify-center" title="Responses are produced by ui/dev-mock, not the real node">dev mock data</div>
      )}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const route = useRoute();
  const setConnection = useUi((s) => s.setConnection);
  const conn = useUi((s) => s.connection);
  useEffect(() => onApiActivity(({ ok, mock }) => setConnection(ok, mock)), [setConnection]);
  const active = "/" + (route.segments[0] ?? "live");
  return (
    <div className="h-full flex flex-col md:flex-row">
      <aside className="md:w-[188px] shrink-0 flex flex-row md:flex-col items-center md:items-stretch border-b md:border-b-0 md:border-r border-line bg-panel/70 backdrop-blur">
        <div className="px-3 md:px-4 py-2 md:pt-5 md:pb-5 shrink-0"><Logo /></div>
        <nav className="flex-1 min-w-0 flex md:block overflow-x-auto md:overflow-visible px-2 gap-0.5 md:gap-0 md:space-y-0.5" aria-label="Primary">
          {NAV.map((n) => {
            const on = active === n.path || (n.path === "/explorer" && active === "/event");
            return (
              <a key={n.path} href={href(n.path)} aria-current={on ? "page" : undefined}
                className={cx("group relative flex shrink-0 items-center gap-2.5 h-9 pl-3 pr-2 rounded-[5px] transition-colors",
                  on ? "bg-raised text-ink" : "text-ink-2 hover:text-ink hover:bg-raised/60")}>
                {on && <span className="absolute left-0 top-2 bottom-2 w-[2px] rounded-full bg-signal shadow-[0_0_10px_rgb(var(--signal))]" />}
                <Icon name={n.icon} size={15} className={on ? "text-signal" : "text-ink-3 group-hover:text-ink-2"} />
                <span className="flex-1 text-[13px]">{n.label}</span>
                <span className="mono text-[10px] text-ink-3 max-md:hidden">{n.n}</span>
              </a>
            );
          })}
        </nav>
        <ConnectionLed />
      </aside>
      <main className="flex-1 min-w-0 min-h-0 flex flex-col">
        {conn.ok === false && (
          <div role="status" className="flex items-center gap-2.5 px-4 md:px-6 min-h-8 bg-unparsed/10 border-b border-unparsed/30 text-unparsed mono text-[11.5px]">
            <Icon name="plug" size={13} /> API unreachable — the UI never fabricates data; showing last known state where cached. Retrying…
          </div>
        )}
        <div className="flex-1 min-h-0 overflow-auto">{children}</div>
      </main>
    </div>
  );
}
