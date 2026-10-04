"""Vendor the pinned OCSF schema into schemas/ocsf/<version>/ (run on the ONLINE build machine; runtime never fetches, R5).

    python tools/vendor_ocsf.py --version 1.3.0 [--out schemas/ocsf] [--from-dir PATH]

Downloads https://schema.ocsf.io/<version>/export/schema (the full JSON export) plus the base classes' sample listing and
writes `schema.json` and `MANIFEST.json` (sha256, source URL, fetched_at). `--from-dir` copies a previously downloaded export
instead (for machines that fetched it by other means). Uses stdlib urllib only. Honours HTTPS_PROXY via urllib defaults.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
import urllib.request
from pathlib import Path

BASE = "https://schema.ocsf.io"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:   # noqa: S310 - fixed https base
        return r.read()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Vendor the pinned OCSF schema")
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "schemas" / "ocsf"))
    ap.add_argument("--from-dir", help="directory containing an already-downloaded schema.json")
    a = ap.parse_args(argv)
    dest = Path(a.out) / a.version
    dest.mkdir(parents=True, exist_ok=True)
    if a.from_dir:
        src = Path(a.from_dir) / "schema.json"
        shutil.copyfile(src, dest / "schema.json")
        url = f"file://{src}"
        data = (dest / "schema.json").read_bytes()
    else:
        url = f"{BASE}/{a.version}/export/schema"
        try:
            data = fetch(url)
        except Exception as e:  # noqa: BLE001
            print(f"error: could not fetch {url}: {e}\nRun this on a machine with internet access (or use --from-dir).", file=sys.stderr)
            return 2
        (dest / "schema.json").write_bytes(data)
    try:
        doc = json.loads(data)
    except ValueError as e:
        print(f"error: schema.json is not valid JSON: {e}", file=sys.stderr)
        return 3
    manifest = {"version": a.version, "source": url, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "classes": len(doc.get("classes", {})) if isinstance(doc, dict) else None}
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
