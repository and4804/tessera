# Public-data realism checks (separate from generated truth)

The generated corpus (`tools.loggen`) comes with ground truth, but it is produced by our renderers from our reading of each
vendor format, so accuracy against it is self-consistency, not proof of fidelity (R12). Public data is the only external check
available offline. Keep it in a separate directory (`data/public/`, git-ignored) and never mix it into `*.truth.jsonl`.

| Source | Obtain (online machine, carry in on removable media) | Use against |
|---|---|---|
| Loghub (github.com/logpai/loghub) | zip per system (Linux, OpenSSH, Apache, Hadoop, ...) | miner/onboarding: template count, structure |
| Zeek logs from public pcaps (`zeek -r x.pcap`) | `conn.log`, `dns.log`, `http.log` | `packs/zeek/conn.yaml` parse rate on real TSV |
| Suricata EVE from the same pcaps (`suricata -r x.pcap -l out/`) | `eve.json` | `packs/suricata/eve.yaml` real alert/flow/dns/http shapes |

Procedure:

1. Place files under `data/public/<source>/`.
2. No truth exists, so measure parse rate and mean coverage only: `ulpf replay --file data/public/zeek/conn.log --hint zeek.conn`
   (or the reference engine: `PYTHONPATH=src python -m ulpf.onboard.refengine`).
3. Inspect `unparsed` and `partial` lines first. Each is a pack bug or a vendor variant with no golden vector. Add a vector
   rather than loosening a regex blindly.
4. Report per-source parse rate in `docs/benchmarks.md` labelled `public`, never merged with `generated` rows.

Licensing: do not commit third-party data; record URL, retrieval date and sha256 only.
