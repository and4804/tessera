# dev-mock — DEVELOPMENT ONLY

A Vite dev-server plugin that impersonates the ULPF API (`/api/v1/*` + `WS /stream`) so the UI can be
developed and demoed without a running node.

* **Never part of the production build.** `vite.config.ts` only imports it for `vite` (serve), and nothing
  under `src/` imports from here. `pnpm build` output contains no mock code (verified by `pnpm check:offline`).
* Every response carries `X-ULPF-Mock: 1`; the UI shows a visible "DEV MOCK DATA" badge when it sees it.
* Data is synthesized from vendor-log *structure* (FortiGate kv, ASA text, Suricata JSON, CEF, pfSense CSV,
  Squid) with byte-accurate field spans, hash-chained-looking segments, and three injected incidents.
  The numbers are random draws, not measurements. Do not quote them.
* Disable with `pnpm dev:nomock` (proxies `/api` to `$ULPF_API`, default `http://127.0.0.1:8000`).
* Demo helpers: `POST /api/v1/__mock/tamper` flips a byte in a vault block (verify then pinpoints it);
  `POST /api/v1/__mock/untamper` restores it.
