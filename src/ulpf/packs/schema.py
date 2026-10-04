"""Pack document shape and the expression AST (§7.6). Parsing is strict: anything outside the closed grammar raises PackError with a
path, so a bad pack fails at load time and never at event time."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..model.ocsf import CLASS_UID
from .dsl_ops import KNOWN_OPS, PackError, split_op

EXTRACT_KINDS = frozenset({"kv", "regex", "json", "csv", "cef", "leef", "xml", "tsv_zeek"})
FRAMINGS = frozenset({"none", "syslog"})
PREDICATES = frozenset({"contains", "regex", "starts_with", "field_eq"})
TOP_KEYS = frozenset({"pack", "id", "version", "verified", "meta", "match", "framing", "extract", "select", "classes", "ignore", "tests",
                      "default_tz", "description"})


@dataclass(frozen=True, slots=True)
class Const:
    value: Any


@dataclass(frozen=True, slots=True)
class FieldRef:
    name: str


@dataclass(frozen=True, slots=True)
class From:
    names: tuple[str, ...]
    is_list: bool
    pipe: tuple[Any, ...]       # raw op specs ("name" | {name: arg}), validated
    default: Any = None


@dataclass(frozen=True, slots=True)
class Coalesce:
    items: tuple[Expr, ...]
    default: Any = None


@dataclass(frozen=True, slots=True)
class When:
    field: str
    eq: Any
    then: Expr | None
    else_: Expr | None


Expr = Const | FieldRef | From | Coalesce | When


@dataclass(frozen=True, slots=True)
class SelectRule:
    when_field: str | None
    when_eq: Any
    cls: str


@dataclass(frozen=True, slots=True)
class Predicate:
    kind: str                   # contains | starts_with | regex | field_eq
    value: str
    field: str = ""


@dataclass(slots=True)
class PackDoc:
    """A validated pack. ``raw`` keeps the YAML mapping for the test runner and Studio round-trips."""

    id: str
    version: str
    verified: bool
    meta: dict[str, Any]
    priority: int
    match_all: list[Predicate]
    match_any: list[Predicate]
    framing: str
    kind: str
    options: dict[str, Any]
    select: list[SelectRule]
    classes: dict[str, dict[str, Expr]]
    ignore: dict[str, str]
    tests: list[dict[str, Any]]
    default_tz: str | None
    raw: dict[str, Any] = field(default_factory=dict)
    path: str = ""


def parse_expr(e: Any, where: str) -> Expr:
    if isinstance(e, str):
        if not e:
            raise PackError(f"{where}: empty field name")
        return FieldRef(e)
    if isinstance(e, bool | int | float) or e is None:
        raise PackError(f"{where}: a bare literal is not an expression (use {{const: ...}})")
    if not isinstance(e, dict):
        raise PackError(f"{where}: bad expression {e!r}")
    forms = [k for k in ("const", "from", "coalesce", "when") if k in e]
    if len(forms) != 1:
        raise PackError(f"{where}: an expression has exactly one of const/from/coalesce/when, got {sorted(e)}")
    form = forms[0]
    allowed = {"const": {"const"}, "from": {"from", "pipe", "default"}, "coalesce": {"coalesce", "default"},
               "when": {"when", "then", "else"}}[form]
    if set(e) - allowed:
        raise PackError(f"{where}: unknown keys {sorted(set(e) - allowed)} in {form} expression")
    if form == "const":
        return Const(e["const"])
    if form == "from":
        src = e["from"]
        if isinstance(src, list):
            if not src or not all(isinstance(x, str) and x for x in src):
                raise PackError(f"{where}: from: [..] must be a non-empty list of field names")
            names, is_list = tuple(src), True
        elif isinstance(src, str) and src:
            names, is_list = (src,), False
        else:
            raise PackError(f"{where}: from must be a field name or a list of names")
        pipe = e.get("pipe", [])
        if not isinstance(pipe, list):
            raise PackError(f"{where}: pipe must be a list")
        for op in pipe:
            name, _arg = split_op(op)
            if name not in KNOWN_OPS:
                raise PackError(f"{where}: unknown op {name!r}")
        return From(names, is_list, tuple(pipe), e.get("default"))
    if form == "coalesce":
        items = e["coalesce"]
        if not isinstance(items, list) or not items:
            raise PackError(f"{where}: coalesce must be a non-empty list")
        return Coalesce(tuple(parse_expr(x, f"{where}.coalesce[{i}]") for i, x in enumerate(items)), e.get("default"))
    c = e["when"]
    if not isinstance(c, dict) or set(c) != {"field", "eq"} or not isinstance(c["field"], str):
        raise PackError(f"{where}: when must be {{field: name, eq: value}}")
    then = parse_expr(e["then"], f"{where}.then") if "then" in e else None
    els = parse_expr(e["else"], f"{where}.else") if "else" in e else None
    return When(c["field"], c["eq"], then, els)


def referenced_fields(expr: Expr, acc: set[str]) -> None:
    """Source fields an expression reads (what it ``consumes`` when it produces a value)."""
    if isinstance(expr, FieldRef):
        acc.add(expr.name)
    elif isinstance(expr, From):
        acc.update(expr.names)
        for op in expr.pipe:
            name, arg = split_op(op)
            if name == "strptime" and isinstance(arg, dict) and "tz_from" in arg:
                acc.add(arg["tz_from"])
    elif isinstance(expr, Coalesce):
        for x in expr.items:
            referenced_fields(x, acc)
    elif isinstance(expr, When):
        acc.add(expr.field)
        for b in (expr.then, expr.else_):
            if b is not None:
                referenced_fields(b, acc)


def iter_exprs(expr: Expr) -> list[Expr]:
    out: list[Expr] = [expr]
    if isinstance(expr, Coalesce):
        for x in expr.items:
            out.extend(iter_exprs(x))
    elif isinstance(expr, When):
        for b in (expr.then, expr.else_):
            if b is not None:
                out.extend(iter_exprs(b))
    return out


def _preds(items: Any, where: str) -> list[Predicate]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise PackError(f"{where}: must be a list")
    out: list[Predicate] = []
    for i, p in enumerate(items):
        if not isinstance(p, dict) or len(p) != 1:
            raise PackError(f"{where}[{i}]: one predicate per entry")
        k, v = next(iter(p.items()))
        if k not in PREDICATES:
            raise PackError(f"{where}[{i}]: unknown predicate {k!r}")
        if k == "field_eq":
            if not isinstance(v, dict) or set(v) != {"field", "value"}:
                raise PackError(f"{where}[{i}]: field_eq needs {{field, value}}")
            out.append(Predicate("field_eq", str(v["value"]), str(v["field"])))
        else:
            if not isinstance(v, str) or not v:
                raise PackError(f"{where}[{i}]: {k} needs a non-empty string")
            out.append(Predicate(k, v))
    return out


def parse_pack(doc: Any, path: str = "") -> PackDoc:
    if not isinstance(doc, dict):
        raise PackError("pack file is not a mapping")
    unknown = set(doc) - TOP_KEYS
    if unknown:
        raise PackError(f"unknown top-level keys {sorted(unknown)}")
    for k in ("pack", "id", "version", "extract", "classes"):
        if k not in doc:
            raise PackError(f"missing required key {k!r}")
    if doc["pack"] != 1:
        raise PackError(f"unsupported pack DSL version {doc['pack']!r}")
    pid = doc["id"]
    if not isinstance(pid, str) or not pid:
        raise PackError("id must be a non-empty string")
    m = doc.get("match") or {}
    if not isinstance(m, dict) or set(m) - {"priority", "all", "any"}:
        raise PackError("match: only priority/all/any allowed")
    prio = m.get("priority", 0)
    if isinstance(prio, bool) or not isinstance(prio, int):
        raise PackError("match.priority must be an int")
    ex = doc["extract"]
    if not isinstance(ex, dict) or ex.get("kind") not in EXTRACT_KINDS or set(ex) - {"kind", "options"}:
        raise PackError(f"extract.kind must be one of {sorted(EXTRACT_KINDS)}")
    framing = doc.get("framing", "none")
    if framing not in FRAMINGS:
        raise PackError(f"framing must be one of {sorted(FRAMINGS)}")
    classes_raw = doc["classes"]
    if not isinstance(classes_raw, dict):
        raise PackError("classes must be a mapping")
    classes: dict[str, dict[str, Expr]] = {}
    for cname, cdef in classes_raw.items():
        if cname not in CLASS_UID:
            raise PackError(f"unknown class {cname!r}")
        if not isinstance(cdef, dict) or set(cdef) - {"set"} or not isinstance(cdef.get("set"), dict):
            raise PackError(f"classes.{cname}: needs a `set` mapping")
        classes[cname] = {}
        for path_, e in cdef["set"].items():
            if not isinstance(path_, str) or not path_ or path_.startswith(".") or path_.endswith(".") or ".." in path_:
                raise PackError(f"classes.{cname}.set: bad OCSF path {path_!r}")
            classes[cname][path_] = parse_expr(e, f"classes.{cname}.set.{path_}")
    select: list[SelectRule] = []
    for i, r in enumerate(doc.get("select") or []):
        if not isinstance(r, dict):
            raise PackError(f"select[{i}]: bad rule")
        if "otherwise" in r:
            if set(r) != {"otherwise"}:
                raise PackError(f"select[{i}]: otherwise takes no other keys")
            select.append(SelectRule(None, None, str(r["otherwise"])))
        else:
            c = r.get("when")
            if set(r) != {"when", "class"} or not isinstance(c, dict) or set(c) != {"field", "eq"}:
                raise PackError(f"select[{i}]: expected {{when: {{field, eq}}, class: name}} or {{otherwise: name}}")
            select.append(SelectRule(str(c["field"]), c["eq"], str(r["class"])))
    ign = doc.get("ignore") or {}
    if not isinstance(ign, dict):
        raise PackError("ignore must be a mapping field -> reason")
    tests = doc.get("tests") or []
    if not isinstance(tests, list):
        raise PackError("tests must be a list")
    opts = ex.get("options") or {}
    if not isinstance(opts, dict):
        raise PackError("extract.options must be a mapping")
    return PackDoc(
        id=pid, version=str(doc["version"]), verified=bool(doc.get("verified", False)), meta=dict(doc.get("meta") or {}),
        priority=prio, match_all=_preds(m.get("all"), "match.all"), match_any=_preds(m.get("any"), "match.any"),
        framing=framing, kind=ex["kind"], options=opts, select=select, classes=classes,
        ignore={str(k): str(v) for k, v in ign.items()}, tests=tests,
        default_tz=doc.get("default_tz"), raw=doc, path=path,
    )
