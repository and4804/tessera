# Build ULPF locally with Claude Code

Prereqs: Python 3.12+, uv, Node 20+, pnpm, Redis, Docker, Claude Code.

1. Unpack, then: cd ulpf && git init && git add -A && git commit -m "scaffold: packs, loggen, onboard, analytics, docker, docs"
2. Run `claude` in the repo root. Run agents two at a time, in this order. Each prompt is a message to paste.

## Wave 1 (backend + frontend-scaffold can't start before backend contracts; so run backend + testing-harness prep first)

### Agent A: BACKEND
Read docs/IMPLEMENTATION_GUIDE.md fully. You own pyproject.toml, Makefile, configs/, src/ulpf/{config.py,cli.py,model,ingest,bus,vault,detect,extract,packs,normalize,pipeline,sinks,explain,api,obs}, tests/{unit,property,integration} for those. Do not touch ui/, tools/loggen, docker/, packs/*.yaml, src/ulpf/onboard, src/ulpf/analytics. Do in order: M0 foundations, vault, ingest+bus, extractors + pack DSL engine (must run existing packs/ and match docs/pack-dsl.md and src/ulpf/onboard/refengine.py behavior), pipeline workers + unparsed lane + ledger, sinks, explain, FastAPI API. Tests first. `make verify` green. Write docs/api-contract.md early. Report files, results, deviations.

### Agent B: OTHER (reconcile)
Run `ulpf packs lint` and `ulpf packs test packs` once Agent A has them; reconcile differences with src/ulpf/onboard/refengine.py (regex.alternatives, empty-value rule, ASA hms op). Run real pytest on tests/golden, tests/unit/onboard, tests/unit/analytics, tests/unit/loggen and fix failures. Run the DuckDB features path in analytics. Run `python tools/vendor_ocsf.py --version 1.3.0`. Build docker image, run `make airgap-test`.

## Wave 2

### Agent C: FRONTEND
Read the guide §7.14 and docs/api-contract.md. You own ui/ only. React 18 + Vite + TS, TanStack Query/Table/Virtual, Tailwind, ECharts, Monaco bundled locally (no CDN), Zustand, @fontsource. All 8 pages. No hardcoded data (R9). `tsc --noEmit`, ESLint, Vitest for query bar and span highlighter. Assert zero external requests.

### Agent D: TESTING
Own tests/ (property, integration, perf, airgap) and tools/bench. Hypothesis properties from guide §11, tamper test, conservation on 1M events, accuracy vs loggen truth, perf regression gate, Playwright smoke. Report measured numbers with hardware.

Then: M4 polish and M5 delivery per guide §12.
