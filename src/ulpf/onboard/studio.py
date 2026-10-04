"""Onboarding Studio facade: analyze -> preview -> publish (steps 1-7 and 9 of §7.11).

The API layer (api/routes_onboard.py) calls exactly these functions:
    analyze(samples, label=None, ...)  -> Analysis        (POST /onboard/analyze)
    preview(pack_yaml, lines)          -> PreviewResult   (POST /onboard/preview)   -- uses the pack DSL engine, no restart
    publish(pack_yaml, dest_dir, ...)  -> dict            (POST /onboard/publish)   -- atomic write + `packs.reload` notification
Everything here is slow-path (I4); nothing is imported by the hot path. No network (R5).
"""
from __future__ import annotations

import os
import re
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import inferer, miner, refengine, suggester

MIN_SAMPLES = 20
RELOAD_CHANNEL = "packs.reload"


@dataclass
class Analysis:
    pack: dict[str, Any]
    pack_yaml: str
    report: dict[str, Any]
    sniff: inferer.Sniff
    fields: dict[str, inferer.FieldInfo]
    mapping: suggester.Mapping
    templates: list[miner.Template] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly view for the API/UI."""
        return {
            "pack_yaml": self.pack_yaml, "report": self.report,
            "sniff": {"format": self.sniff.format, "framing": self.sniff.framing, "syslog_style": self.sniff.syslog_style,
                      "confidence": round(self.sniff.confidence, 3), "notes": self.sniff.notes},
            "fields": [{"name": f.name, "type": f.type, "support": round(f.support, 3), "distinct": f.distinct, "examples": f.examples}
                       for f in self.fields.values()],
            "mapping": [{"field": s.field, "ocsf_path": s.path, "score": s.score, "reason": s.reason} for s in self.mapping.suggestions],
            "class": self.mapping.class_name,
            "templates": [{"id": t.id, "template": t.text, "count": t.count, "example": t.examples[0] if t.examples else ""}
                          for t in self.templates[:20]],
        }


@dataclass
class PreviewResult:
    events: list[dict[str, Any]]
    summary: dict[str, Any]


# ------------------------------------------------------------------------------------------------ yaml helpers
def dump_pack(doc: dict[str, Any], header: str = "") -> str:
    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=10_000, default_flow_style=None)
    return (header.rstrip() + "\n" if header else "") + body


def load_pack_yaml(text: str) -> dict[str, Any]:
    doc = yaml.safe_load(text)        # R7: safe loader only
    if not isinstance(doc, dict):
        raise ValueError("pack YAML must be a mapping")
    return doc


# ------------------------------------------------------------------------------------------------ preview
def _flat_mapped(ev: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def walk(d: Any, prefix: str) -> None:
        if isinstance(d, dict):
            for k, v in d.items():
                walk(v, f"{prefix}.{k}" if prefix else k)
        else:
            out[prefix] = d

    walk({k: v for k, v in ev.items() if k not in ("unmapped", "ulpf", "metadata")}, "")
    return out


def preview(pack: str | dict[str, Any], lines: Iterable[str | bytes], recv_ms: int = refengine.RECV_MS, limit: int = 500) -> PreviewResult:
    """Run a (draft) pack over lines with the DSL engine and report coverage. Raises ValueError on a malformed pack."""
    doc = load_pack_yaml(pack) if isinstance(pack, str) else pack
    p = refengine.Pack(doc)
    events: list[dict[str, Any]] = []
    n = matched = 0
    cov_sum = 0.0
    consumed: set[str] = set()
    seen: set[str] = set()
    residual = 0
    status = {"parsed": 0, "partial": 0, "unparsed": 0}
    for ln in lines:
        raw = ln if isinstance(ln, bytes) else ln.encode("utf-8", "surrogateescape")
        n += 1
        ev = None
        fields: dict[str, Any] | None = None
        if p.match(raw):
            try:
                fields, ctx = p.extract(raw, recv_ms)
                if fields is not None:
                    ev = p.normalize(fields, ctx, recv_ms)
            except Exception:  # noqa: BLE001 - preview must never raise on bad lines
                ev = None
        if ev is None or fields is None:
            status["unparsed"] += 1
            if len(events) < limit:
                events.append({"line": n - 1, "raw": raw.decode("utf-8", "replace"), "status": "unparsed"})
            continue
        matched += 1
        status[ev["ulpf"]["status"]] += 1
        keys = [k for k in fields if k != "_residual"]
        um = set(ev["unmapped"]) - {"_residual"}
        cov = (len(keys) - len(um & set(keys))) / len(keys) if keys else 0.0
        cov_sum += cov
        ev["ulpf"]["coverage"] = round(cov, 3)
        seen.update(keys)
        consumed.update(k for k in keys if k not in um)
        residual += 1 if "_residual" in fields else 0
        if len(events) < limit:
            events.append({"line": n - 1, "raw": raw.decode("utf-8", "replace"), "status": ev["ulpf"]["status"], "event": ev, "coverage": round(cov, 3)})
    summary = {
        "lines": n, "matched": matched, "matched_pct": round(100 * matched / n, 1) if n else 0.0,
        "status": status, "coverage_mean": round(cov_sum / matched, 4) if matched else 0.0,
        "fields_seen": len(seen), "fields_mapped": len(consumed),
        "fields_mapped_pct": round(100 * len(consumed) / len(seen), 1) if seen else 0.0,
        "unmapped_fields": sorted(seen - consumed), "lines_with_residual": residual,
    }
    return PreviewResult(events, summary)


# ------------------------------------------------------------------------------------------------ analyze
def _apply_renames(renames: dict[str, str], rows: list[dict | None], fields: dict[str, inferer.FieldInfo], spec: dict[str, Any],
                   synth: miner.Synth | None) -> None:
    if not renames:
        return
    for r in rows:
        if r:
            for old, new in renames.items():
                if old in r:
                    r[new] = r.pop(old)
    for old, new in renames.items():
        if old in fields:
            fi = fields.pop(old)
            fi.name = new
            fields[new] = fi
    opts = spec["options"]
    if spec["kind"] == "regex":
        opts["anchor"] = miner.rename_groups(opts["anchor"], renames)
        if "alternatives" in opts:
            opts["alternatives"] = [miner.rename_groups(a, renames) for a in opts["alternatives"]]
    elif spec["kind"] in ("csv", "tsv_zeek"):
        key = "columns" if spec["kind"] == "csv" else "fields"
        opts[key] = [renames.get(c, c) for c in opts[key]]


def _pick_tests(pack: dict[str, Any], lines: list[str], max_tests: int = 5) -> list[dict[str, Any]]:
    """Auto-generate golden vectors from sample lines (a human confirms them). Lines are chosen to be structurally diverse."""
    p = refengine.Pack(pack)
    seen_sig: set[tuple] = set()
    chosen: list[tuple[str, dict[str, Any]]] = []
    for ln in lines:
        raw = ln.encode("utf-8", "surrogateescape")
        if not p.match(raw):
            continue
        try:
            ev = p.process(raw, refengine.RECV_MS)
        except Exception:  # noqa: BLE001
            continue
        if ev is None:
            continue
        sig = (tuple(sorted(k for k in _flat_mapped(ev))), len(ev["unmapped"]))
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        chosen.append((ln, ev))
        if len(chosen) >= max_tests:
            break
    if len(chosen) < max_tests:     # top up with evenly spaced lines
        step = max(1, len(lines) // max_tests)
        have = {c[0] for c in chosen}
        for ln in lines[::step]:
            if len(chosen) >= max_tests:
                break
            raw = ln.encode("utf-8", "surrogateescape")
            if ln in have or not p.match(raw):
                continue
            try:
                ev = p.process(raw, refengine.RECV_MS)
            except Exception:  # noqa: BLE001
                continue
            if ev is not None:
                chosen.append((ln, ev))
                have.add(ln)
    tests = []
    for i, (ln, ev) in enumerate(chosen, 1):
        exp = _flat_mapped(ev)
        if ev["ulpf"]["time_quality"] == "recv_time":
            exp.pop("time", None)       # receive time is not deterministic
        exp = {k: v for k, v in exp.items() if v is not None}
        tests.append({"name": f"auto-{i}", "raw": ln, "expect": exp})
    return tests


def estimate_minutes(unmapped: int, unknown_enums: int, assumed: int, n_templates: int) -> float:
    """Heuristic time-to-onboard (minutes): 1 min to paste/review the draft + 0.2/unmapped field + 0.5/unknown enum value set
    + 0.5/assumption + 0.3/extra template. Documented in docs/onboarding.md; measured by the evaluator, not a promise."""
    return round(1.0 + 0.2 * unmapped + 0.5 * unknown_enums + 0.5 * assumed + 0.3 * max(0, n_templates - 1), 1)


def analyze(samples: Iterable[str], label: str | None = None, vendor: str | None = None, product: str | None = None,
            default_tz: str = "UTC", recv_ms: int = refengine.RECV_MS) -> Analysis:
    """Steps 1-7: sniff -> extract/mine -> type inference -> OCSF suggestion -> draft pack + tests -> report."""
    t0 = time.perf_counter()
    lines = [s.rstrip("\r\n") for s in samples if s and s.strip()]
    if not lines:
        raise ValueError("no sample lines")
    notes: list[str] = []
    if len(lines) < MIN_SAMPLES:
        notes.append(f"only {len(lines)} samples (< {MIN_SAMPLES}); mapping of rare variants may be incomplete")
    sn = inferer.sniff(lines)
    notes.extend(sn.notes)
    spec, rows, extra = inferer.extract_lines(lines, sn)
    synth: miner.Synth | None = extra.get("synth")
    ctxs = extra["ctx"]
    fields = inferer.infer_fields(rows, ctxs if sn.framing == "syslog" else None)
    renames = suggester.value_hint_renames(fields)
    _apply_renames(renames, rows, fields, spec, synth)
    mapping = suggester.suggest(fields, sn)
    mapping.renames = renames
    set_expr, info = suggester.build_set(mapping, fields, sn, default_tz)
    match = suggester.match_block(sn, fields, synth, lines)
    pack = suggester.build_pack(label, vendor, product, sn, spec, match, mapping, set_expr)
    pack["tests"] = []
    pack["tests"] = _pick_tests(pack, lines)
    pv = preview(pack, lines)
    n_unmapped = len(pv.summary["unmapped_fields"])
    unknown_enums = sum(1 for v in info["unknown_enum_values"].values() if v)
    templates = miner.cluster_templates(lines) if sn.format == "text" else []
    n_templates = synth.n_templates if synth else 1
    report = {
        "lines": len(lines), "format": sn.format, "extractor": spec["kind"], "class": mapping.class_name,
        "lines_matched_pct": pv.summary["matched_pct"], "coverage_mean": pv.summary["coverage_mean"],
        "fields_extracted": pv.summary["fields_seen"], "fields_mapped": pv.summary["fields_mapped"],
        "fields_mapped_pct": pv.summary["fields_mapped_pct"], "unmapped_fields": pv.summary["unmapped_fields"],
        "lines_with_residual": pv.summary["lines_with_residual"],
        "mapped": [{"field": s.field, "ocsf_path": s.path, "score": s.score} for s in mapping.suggestions],
        "unknown_enum_values": info["unknown_enum_values"], "assumptions": info["assumed"], "notes": notes + mapping.notes,
        "templates": n_templates, "dropped_variant_lines": synth.dropped_lines if synth else 0,
        "estimated_minutes": estimate_minutes(n_unmapped, unknown_enums, len(info["assumed"]), n_templates),
        "analysis_seconds": round(time.perf_counter() - t0, 3),
    }
    header = (f"# Draft pack generated by the ULPF Onboarding Studio. REVIEW BEFORE PUBLISHING.\n"
              f"# format={sn.format} extractor={spec['kind']} class={mapping.class_name} samples={len(lines)} "
              f"matched={pv.summary['matched_pct']}% coverage={pv.summary['coverage_mean']}\n"
              f"# verified: false (R12). The tests[] below were generated from the samples; confirm them against the real device.")
    return Analysis(pack, dump_pack(pack, header), report, sn, fields, mapping, templates)


# ------------------------------------------------------------------------------------------------ publish
def validate_for_publish(pack_yaml: str, min_tests: int = 1) -> dict[str, Any]:
    doc = load_pack_yaml(pack_yaml)
    errs = refengine.lint(refengine.Pack(doc), min_tests=min_tests)
    errs = [e for e in errs if "R12" not in e]     # custom packs also ship verified:false until a human flips it
    if not str(doc.get("id", "")).startswith("custom."):
        errs.append("Studio-published packs must have an id starting with 'custom.'")
    fails = refengine.run_tests(refengine.Pack(doc))
    if errs or fails:
        raise ValueError("; ".join(errs + fails))
    return doc


def publish(pack_yaml: str, dest_dir: str | os.PathLike[str], notify: Callable[[str, str], None] | None = None, redis_url: str | None = None) -> dict[str, Any]:
    """Validate, write `<dest_dir>/<id>.yaml` atomically, then announce `packs.reload` so workers swap compiled packs.

    `notify(channel, pack_id)` is injectable for tests; by default a Redis PUBLISH is attempted when `redis_url` is given.
    A failed notification does not fail the publish (workers also pick up files on their watcher/poll cycle)."""
    doc = validate_for_publish(pack_yaml)
    pid = doc["id"]
    if not re.fullmatch(r"custom\.[a-z0-9_]+", pid):
        raise ValueError(f"unsafe pack id {pid!r}")
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / f"{pid.split('.', 1)[1]}.yaml"
    fd, tmp = tempfile.mkstemp(dir=dest, prefix=".pub-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(pack_yaml)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)          # atomic swap: readers see the old or the new file, never a partial one
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    notified, err = False, None
    try:
        if notify is not None:
            notify(RELOAD_CHANNEL, pid)
            notified = True
        elif redis_url:
            import redis  # type: ignore[import-untyped]
            redis.Redis.from_url(redis_url).publish(RELOAD_CHANNEL, pid)
            notified = True
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {e}"
    return {"id": pid, "version": doc.get("version"), "path": str(target), "notified": notified, "notify_error": err}
