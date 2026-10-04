"""Pack linter (`ulpf packs lint`). Rejects: unknown ops, unknown OCSF paths, ReDoS-prone regexes (nested quantifiers), reserved/derived
paths, enum-inconsistent ids and missing tests; warns about classes without ``time`` (events would fall back to receive time)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..extract.regex_ import pattern_texts
from ..model.ocsf import ACTIVITY_IDS, CLASS_UID, known_path
from .dsl_ops import PackError, split_op
from .loader import load_yaml_text
from .schema import Const, Expr, From, PackDoc, iter_exprs, parse_pack

RESERVED_PATHS = ("class_uid", "category_uid", "type_uid", "ulpf", "unmapped", "metadata.version", "metadata.uid", "metadata.product")


@dataclass(frozen=True, slots=True)
class LintIssue:
    level: str          # "error" | "warning"
    message: str
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.level}: {self.message}" + (f" (line {self.line})" if self.line else "")


def _repeat_nesting(pattern: str) -> str | None:
    """Return a description when ``pattern`` has an unbounded repeat nested inside another repeat that can repeat (the classic
    catastrophic-backtracking shape, e.g. ``(a+)+`` or ``(.*a)*``), else None."""
    try:
        import re._parser as sp  # type: ignore[import-not-found,unused-ignore]
    except ImportError:  # pragma: no cover
        return None
    try:
        tree = sp.parse(pattern)
    except (re.error, RecursionError, OverflowError):
        return None
    MAXR = sp.MAXREPEAT
    BIG = 16   # a bounded repeat of <= 16 (e.g. `(\d{1,3}\.){3}` for an IPv4 address) cannot backtrack catastrophically

    def contains_unbounded(items: Any) -> bool:
        for op, av in items:
            name = str(op)
            if name in ("MAX_REPEAT", "MIN_REPEAT"):
                lo, hi, sub = av
                if hi == MAXR or hi > BIG:
                    return True
                if contains_unbounded(sub):
                    return True
            elif name == "SUBPATTERN":
                if contains_unbounded(av[-1]):
                    return True
            elif name == "BRANCH":
                if any(contains_unbounded(b) for b in av[1]):
                    return True
            elif name in ("ASSERT", "ASSERT_NOT"):
                continue
        return False

    def walk(items: Any) -> str | None:
        for op, av in items:
            name = str(op)
            if name in ("MAX_REPEAT", "MIN_REPEAT"):
                lo, hi, sub = av
                if (hi == MAXR or hi > BIG) and contains_unbounded(sub):
                    return "nested quantifier inside a repeating group"
                r = walk(sub)
                if r:
                    return r
            elif name == "SUBPATTERN":
                r = walk(av[-1])
                if r:
                    return r
            elif name == "BRANCH":
                for b in av[1]:
                    r = walk(b)
                    if r:
                        return r
        return None

    return walk(tree)


def lint_doc(doc: PackDoc, *, min_tests: int = 5, require_unverified: bool = True) -> list[LintIssue]:
    out: list[LintIssue] = []

    def err(m: str) -> None:
        out.append(LintIssue("error", f"{doc.id}: {m}"))

    def warn(m: str) -> None:
        out.append(LintIssue("warning", f"{doc.id}: {m}"))

    if require_unverified and doc.verified is not False:
        err("R12 requires `verified: false` on shipped packs")
    if len(doc.tests) < min_tests:
        err(f"needs >= {min_tests} tests (has {len(doc.tests)})")
    names = [t.get("name") for t in doc.tests if isinstance(t, dict)]
    if len(set(names)) != len(names):
        err("duplicate test names")
    for i, t in enumerate(doc.tests):
        if not isinstance(t, dict) or not isinstance(t.get("raw"), str) or not isinstance(t.get("expect", {}), dict):
            err(f"tests[{i}] must have raw: str and expect: mapping")

    # regexes: compile + ReDoS shape
    texts: list[str] = []
    if doc.kind == "regex":
        texts += pattern_texts(doc.options)
    for p in (*doc.match_all, *doc.match_any):
        if p.kind == "regex":
            texts.append(p.value)
    for _cname, sets in doc.classes.items():
        for _path, e in sets.items():
            for sub in iter_exprs(e):
                if isinstance(sub, From):
                    for op in sub.pipe:
                        n, a = split_op(op)
                        if n == "regex" and isinstance(a, dict) and isinstance(a.get("pattern"), str):
                            texts.append(a["pattern"])
    for rx in texts:
        try:
            re.compile(rx)
        except re.error as ex:
            err(f"regex does not compile: {ex}: {rx[:80]}")
            continue
        why = _repeat_nesting(rx)
        if why:
            err(f"possible ReDoS ({why}): {rx[:80]}")
    if doc.kind == "regex" and "anchor" not in doc.options:
        err("regex extractor needs options.anchor")
    if doc.kind == "regex" and doc.options.get("dispatch_on"):
        disp = doc.options["dispatch_on"]
        if not doc.options.get("patterns"):
            err("dispatch_on without patterns")
        if disp not in "".join(pattern_texts({"anchor": doc.options.get("anchor", "")})).replace("(?P<", "(?P<") and f"(?P<{disp}>" not in doc.options.get("anchor", ""):
            warn(f"dispatch_on field {disp!r} is not a named group of the anchor")
    if doc.kind == "tsv_zeek" and not doc.options.get("fields"):
        warn("tsv_zeek without options.fields only works on connections that send #fields headers")
    if doc.kind == "csv" and not (doc.options.get("columns") or doc.options.get("branch")):
        err("csv extractor needs options.columns or a branch layout")

    if not doc.match_all and not doc.match_any:
        err("match has no predicates (such a pack never matches)")

    sel_classes = {r.cls for r in doc.select}
    for c in sel_classes:
        if c not in doc.classes and c != "base_event":
            err(f"select refers to undefined class {c!r}")
    if not doc.select:
        warn("no select rules: every event becomes base_event")
    elif not any(r.when_field is None for r in doc.select):
        warn("select has no `otherwise` rule: unmatched events become base_event")
    for cname, sets in doc.classes.items():
        uid = CLASS_UID[cname]
        if "time" not in sets and cname != "base_event":
            warn(f"class {cname} sets no `time`: events will fall back to receive time (status partial)")
        for path, e in sets.items():
            if any(path == r or path.startswith(r + ".") for r in RESERVED_PATHS):
                err(f"classes.{cname}.{path}: path is derived by the engine and cannot be set")
            elif not known_path(uid, path):
                err(f"classes.{cname}.{path}: unknown OCSF attribute for class {uid}")
            if path == "activity_id":
                vals = _possible_ints(e)
                bad = sorted(v for v in vals if v not in ACTIVITY_IDS.get(uid, frozenset()))
                if bad:
                    err(f"classes.{cname}.activity_id: values {bad} are not valid activity ids for class {uid}")
            if path == "time" and isinstance(e, Const):
                warn(f"classes.{cname}.time is a constant")
    for fld in doc.ignore:
        if not fld:
            err("ignore has an empty field name")
    for fld, reason in doc.ignore.items():
        if not reason.strip():
            err(f"ignore.{fld}: a reason is required (no silent drops)")
    return out


def _possible_ints(e: Expr) -> set[int]:
    vals: set[int] = set()
    for sub in iter_exprs(e):
        if isinstance(sub, Const) and isinstance(sub.value, int) and not isinstance(sub.value, bool):
            vals.add(sub.value)
        if isinstance(sub, From):
            for op in sub.pipe:
                n, a = split_op(op)
                if n == "lookup" and isinstance(a, dict):
                    for v in list(a.get("map", {}).values()) + [a.get("default")]:
                        if isinstance(v, int) and not isinstance(v, bool):
                            vals.add(v)
    return vals


def _yaml_line_index(text: str) -> dict[tuple[str, ...], int]:
    """Map key paths (e.g. ('classes','network_activity','set','src_endpoint.ip')) to 1-based lines for editor markers."""
    idx: dict[tuple[str, ...], int] = {}
    try:
        root = yaml.compose(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    except yaml.YAMLError:
        return idx

    def walk(node: Any, path: tuple[str, ...]) -> None:
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                key = str(k.value)
                idx[(*path, key)] = k.start_mark.line + 1
                walk(v, (*path, key))

    if root is not None:
        walk(root, ())
    return idx


def lint_text(text: str, *, min_tests: int = 1, require_unverified: bool = False) -> list[LintIssue]:
    """Lint a pack given as YAML text (Studio preview): YAML/DSL errors become issues with a line number when known."""
    try:
        raw = load_yaml_text(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        return [LintIssue("error", f"YAML: {getattr(e, 'problem', None) or e}", mark.line + 1 if mark else None)]
    try:
        doc = parse_pack(raw)
    except PackError as e:
        return [LintIssue("error", str(e), _guess_line(text, str(e)))]
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        return [LintIssue("error", f"invalid pack: {e}")]
    issues = lint_doc(doc, min_tests=min_tests, require_unverified=require_unverified)
    idx = _yaml_line_index(text)
    out: list[LintIssue] = []
    for it in issues:
        line = it.line
        m = re.search(r"classes\.(\w+)\.([\w.]+)", it.message)
        if m:
            line = idx.get(("classes", m.group(1), "set", m.group(2).split(".", 0)[0])) or idx.get(("classes", m.group(1)))
            # dotted OCSF paths are single keys under `set`
            full = idx.get(("classes", m.group(1), "set", m.group(2)))
            line = full or line
        elif "tests" in it.message:
            line = idx.get(("tests",))
        elif "select" in it.message:
            line = idx.get(("select",))
        elif "regex" in it.message or "ReDoS" in it.message:
            line = idx.get(("extract",))
        out.append(LintIssue(it.level, it.message, line))
    return out


def _guess_line(text: str, msg: str) -> int | None:
    m = re.search(r"classes\.(\w+)\.set\.([\w.]+)", msg)
    if m:
        idx = _yaml_line_index(text)
        return idx.get(("classes", m.group(1), "set", m.group(2))) or idx.get(("classes", m.group(1)))
    m = re.search(r"unknown op '(\w+)'", msg)
    if m:
        for i, ln in enumerate(text.splitlines(), 1):
            if m.group(1) in ln:
                return i
    return None


def lint_file(path: str | Path, *, min_tests: int = 5, require_unverified: bool = True) -> list[LintIssue]:
    text = Path(path).read_text(encoding="utf-8")
    return lint_text(text, min_tests=min_tests, require_unverified=require_unverified)
