# ULPF UI — "Rosetta" console

React 18 + TypeScript + Vite, fully offline (R5): fonts via `@fontsource`, Monaco and ECharts bundled, no CDN, no telemetry.
Everything on screen comes from the real API (`/api/v1`, R9). Wire contract: [`../docs/api-contract.md`](../docs/api-contract.md).

## Run

```bash
pnpm i
pnpm dev            # dev server on :5173 with the DEV-ONLY mock API (dev-mock/) — shows a "dev mock data" badge
pnpm dev:nomock     # same, but proxies /api -> $ULPF_API (default http://127.0.0.1:8080), incl. WebSocket
pnpm build          # tsc --noEmit && vite build  -> dist/   (served by the FastAPI image)
pnpm smoke          # live check (also `make ui-smoke` at the repo root): throwaway node + loggen demo + Chromium; screenshots -> screenshots/live/
pnpm check:offline  # scans dist/ for external URLs / CDN hosts / mock leakage (exit 1 on failure; --strict is pickier)
pnpm test           # Vitest: query-bar parser + byte-span highlighter
pnpm lint | pnpm typecheck | pnpm verify   # verify = typecheck + lint + test + build + check:offline
```
Node >= 20, pnpm 9. Dependencies are pinned in `package.json` (commit `pnpm-lock.yaml` after the first online install).

## Pages (IMPLEMENTATION_GUIDE §7.14)

| Route | What |
|---|---|
| `#/live` | WebSocket tail → 5,000-row ring buffer, virtualized table, pause/resume (keeps buffering), status/source toggles, server-side DSL filter, measured eps + 60 s sparkline, reconnect with backoff |
| `#/explorer` | Field-DSL query bar (live validation, did-you-mean, autocomplete for fields/enums/server hints), time-range picker, stacked status histogram with drag-to-zoom, infinite virtualized results, CSV/JSON/Arrow export |
| `#/event/<id>` | Raw bytes (text or hex) with coloured byte-exact spans ⇄ OCSF tree (mapped / unmapped) driven by `/explain`; lineage panel; **Verify** re-reads the vault, compares SHA-256 (server and in-browser) |
| `#/sources` | Card per source: eps sparkline, parse rate, coverage, last seen, top unmapped, schema-drift badge; drawer with health series, peers |
| `#/studio` | Samples → analyze → Monaco YAML (bundled, lazy-loaded) → debounced live preview + coverage gauge + lint markers → Publish; unparsed template clusters as one-click suggestions |
| `#/integrity` | Conservation verdict + per-source ledger (Δ column must be 0), vault segment list with chain status, streaming **Run verify** that pinpoints segment/block/frame |
| `#/detections` | Findings → feature z-scores → evidence rows → Event Detail |
| `#/benchmark` | Renders `bench/results.json`: eps, scaling chart vs ideal-linear, latency percentiles, hardware |

Every page has designed loading (skeletons), empty (explains what will make data appear) and error states; when the API is
unreachable a banner + the sidebar LED say so and the UI never fabricates data.

## Design direction

"Archive mission-control": graphite panels with hairline rules and registration ticks, one chartreuse *signal* colour used
only for interaction/brand, status carried by teal/amber/vermilion chips with icons (never colour alone). Fraunces (display,
italic accents) against Instrument Sans (UI) and JetBrains Mono (data/bytes). Film-grain + corner bloom for depth, staggered
rise-in on load, tabular numerals everywhere, `prefers-reduced-motion` respected. Tokens live in `src/styles/index.css`
(RGB channel variables → Tailwind colours); source identity uses a fixed 8-slot categorical set stepped for the dark surface.

## Layout

```
src/api/        types.ts (contract), client.ts (fetch, errors, verify NDJSON, WS url), hooks.ts (TanStack Query), live-feed.ts (WS ring buffer)
src/lib/        query-dsl.ts (+test), spans.ts (+test), ring.ts, format.ts, fields.ts, monaco.ts (local bundle), echarts.ts, router.ts, color.ts
src/components/ Shell, EventTable (TanStack Table + react-virtual), QueryBar, RawView, OcsfTree, LineagePanel, Histogram, ScalingChart, YamlEditor, ui/*
src/pages/      one file per page
dev-mock/       DEV ONLY fake API (Vite plugin). Excluded from builds; see dev-mock/README.md
scripts/        offline-check.mjs
```

## Notes

* Hash router (`#/…`) so the bundle works from any static path; no server rewrites needed.
* Monaco: `loader.config({ monaco })` + a Vite `?worker` editor worker (src/lib/monaco.ts); only the YAML tokenizer is included.
* Auth: if the API requires a token, set `localStorage.ulpf_token`; it is sent as a bearer header (and `?access_token=` for WS/export).
* Dev proxy target: `ULPF_API=http://host:port pnpm dev:nomock`.
