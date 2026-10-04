import { create } from "zustand";

export type TimeRange =
  | { kind: "rel"; ms: number; label: string }
  | { kind: "abs"; from: number; to: number };

export const RANGE_PRESETS: { label: string; ms: number }[] = [
  { label: "15m", ms: 15 * 60_000 },
  { label: "1h", ms: 3_600_000 },
  { label: "6h", ms: 6 * 3_600_000 },
  { label: "24h", ms: 86_400_000 },
  { label: "7d", ms: 7 * 86_400_000 }
];

export function resolveRange(r: TimeRange, now = Date.now()): { from: number; to: number } {
  return r.kind === "rel" ? { from: now - r.ms, to: now } : { from: r.from, to: r.to };
}

interface UiState {
  connection: { ok: boolean | null; mock: boolean; since: number | null };
  setConnection: (ok: boolean, mock: boolean) => void;
  range: TimeRange;
  setRange: (r: TimeRange) => void;
  navCollapsed: boolean;
  toggleNav: () => void;
}

export const useUi = create<UiState>((set, get) => ({
  connection: { ok: null, mock: false, since: null },
  setConnection: (ok, mock) => {
    const c = get().connection;
    if (c.ok === ok && c.mock === mock) return;
    set({ connection: { ok, mock, since: c.ok === ok ? c.since : Date.now() } });
  },
  range: { kind: "rel", ms: RANGE_PRESETS[1].ms, label: RANGE_PRESETS[1].label },
  setRange: (range) => set({ range }),
  navCollapsed: false,
  toggleNav: () => set((s) => ({ navCollapsed: !s.navCollapsed }))
}));
