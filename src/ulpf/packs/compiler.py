"""Pack compiler (§7.6): a validated :class:`PackDoc` becomes Python closures at load time. No ``eval``, no string interpretation
per event; dotted-path setters, regexes, lookup tables and strptime specs are all precomputed here."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Protocol

from ..extract import MAX_INPUT, build_text_extractor
from ..extract.syslog_hdr import parse_syslog
from ..extract.tsv_zeek import ZeekState
from ..model.envelope import RawEnvelope
from ..model.lineage import VaultRef
from ..normalize.mapper import ClassSpec, PackMeta, Setter, build_event, make_class_spec
from .dsl_ops import PackError, build_op
from .schema import Coalesce, Const, Expr, FieldRef, From, PackDoc, Predicate, When, referenced_fields

Closure = Callable[[dict[str, Any]], Any]


class CompiledPack(Protocol):
    """§6.3 contract (``normalize`` gained an optional trailing ``ctx``: the syslog.* context produced by ``extract``)."""

    id: str
    version: str
    priority: int

    def match(self, data: bytes) -> bool: ...
    def extract(self, data: bytes, ctx: dict[str, Any]) -> dict[str, Any] | None: ...
    def normalize(self, fields: dict[str, Any], env: RawEnvelope, ref: VaultRef,
                  ctx: dict[str, Any] | None = None) -> list[dict[str, Any]]: ...


def _compile_from(e: From, tz: str) -> Closure:
    ops = [build_op(o, tz) for o in e.pipe]
    default = e.default
    if not e.is_list:
        name = e.names[0]
        n = len(ops)
        if n == 0:
            def f0(view: dict[str, Any]) -> Any:
                v = view.get(name)
                return default if v is None or v == "" else v
            return f0
        if n == 1:
            o1 = ops[0]

            def f1(view: dict[str, Any]) -> Any:
                v = view.get(name)
                if v is None or v == "":
                    return default
                v = o1(v, view)
                return default if v is None else v
            return f1
        if n == 2:
            p1, p2 = ops

            def f2(view: dict[str, Any]) -> Any:
                v = view.get(name)
                if v is None or v == "":
                    return default
                v = p1(v, view)
                if v is not None:
                    v = p2(v, view)
                return default if v is None else v
            return f2

        def fn(view: dict[str, Any]) -> Any:
            v = view.get(name)
            if v is None or v == "":
                return default
            for op in ops:
                v = op(v, view)
                if v is None:
                    break
            return default if v is None else v
        return fn

    names = e.names

    def fl(view: dict[str, Any]) -> Any:
        vals: list[Any] = []
        for nm in names:
            x = view.get(nm)
            if x is None or x == "":
                return default  # any missing part makes the whole value null (a partial concat would be a lie)
            vals.append(x)
        v: Any = vals
        for op in ops:
            v = op(v, view)
            if v is None:
                break
        return default if v is None else v
    return fl


def compile_expr(e: Expr, tz: str = "UTC") -> Closure:
    if isinstance(e, Const):
        val = e.value
        return lambda view: val
    if isinstance(e, FieldRef):
        name = e.name

        def fr(view: dict[str, Any]) -> Any:
            v = view.get(name)
            return None if v == "" else v
        return fr
    if isinstance(e, From):
        return _compile_from(e, tz)
    if isinstance(e, Coalesce):
        subs = [compile_expr(x, tz) for x in e.items]
        cdefault = e.default

        def co(view: dict[str, Any]) -> Any:
            for s in subs:
                v = s(view)
                if v is not None:
                    return v
            return cdefault
        return co
    assert isinstance(e, When)
    fld, eq = e.field, str(e.eq)
    then = compile_expr(e.then, tz) if e.then is not None else None
    els = compile_expr(e.else_, tz) if e.else_ is not None else None

    def wh(view: dict[str, Any]) -> Any:
        got = view.get(fld)
        branch = then if (got is not None and str(got) == eq) else els
        return None if branch is None else branch(view)
    return wh


def _formats_for(kind: str) -> frozenset[str]:
    if kind == "json":
        return frozenset({"json"})
    if kind == "xml":
        return frozenset({"xml"})
    if kind == "tsv_zeek":
        return frozenset({"tsv", "text"})
    if kind == "cef":
        return frozenset({"cef", "syslog", "text"})
    if kind == "leef":
        return frozenset({"leef", "syslog", "text"})
    return frozenset({"syslog", "text", "tsv"})


class _Pred:
    __slots__ = ("kind", "needle", "rx")

    def __init__(self, p: Predicate) -> None:
        self.kind = p.kind
        self.needle = p.value.encode("utf-8") if p.kind in ("contains", "starts_with") else b""
        self.rx: re.Pattern[bytes] | None = re.compile(p.value.encode("utf-8")) if p.kind == "regex" else None

    def check(self, data: bytes) -> bool:
        k = self.kind
        if k == "contains":
            return self.needle in data
        if k == "starts_with":
            return data.startswith(self.needle)
        if k == "regex":
            assert self.rx is not None
            return self.rx.search(data[:MAX_INPUT]) is not None
        return True  # field_eq is evaluated after extraction


class CompiledPackImpl:
    """The runtime object for one pack@version. Immutable after construction (hot reload swaps whole objects)."""

    def __init__(self, doc: PackDoc, default_tz: str = "UTC") -> None:
        self.doc = doc
        self.id, self.version, self.priority = doc.id, doc.version, doc.priority
        self.framing = doc.framing
        self.kind = doc.kind
        self.formats = _formats_for(doc.kind)
        self.verified = doc.verified
        self._all_pre = [_Pred(p) for p in doc.match_all if p.kind != "field_eq"]
        self._any_pre = [_Pred(p) for p in doc.match_any if p.kind != "field_eq"]
        self._post_all = [p for p in doc.match_all if p.kind == "field_eq"]
        self._post_any = [p for p in doc.match_any if p.kind == "field_eq"]
        self._has_any = bool(doc.match_any)
        self._has_preds = bool(doc.match_all or doc.match_any)
        self._text = build_text_extractor(doc.kind, doc.options)
        self._is_zeek = doc.kind == "tsv_zeek"
        self._syslog = doc.framing == "syslog"
        self.default_tz = doc.default_tz or default_tz
        self.meta = PackMeta(doc.id, doc.version, doc.meta.get("product"), doc.meta.get("vendor"), dict(doc.ignore),
                             frozenset(doc.ignore))
        self.classes: dict[str, ClassSpec] = {}
        for cname, sets in doc.classes.items():
            setters = []
            for path, expr in sets.items():
                refs: set[str] = set()
                referenced_fields(expr, refs)
                setters.append(Setter(path, tuple(path.split(".")), compile_expr(expr, self.default_tz), frozenset(refs)))
            self.classes[cname] = make_class_spec(cname, setters)
        if "base_event" not in self.classes:
            self.classes["base_event"] = make_class_spec("base_event", [])
        self._select = [(r.when_field, str(r.when_eq), r.cls) for r in doc.select]
        for _f, _e, c in self._select:
            if c not in self.classes:
                raise PackError(f"select refers to undefined class {c!r}")

    # ------------------------------------------------------------------ match
    def match(self, data: bytes) -> bool:
        """Cheap prefilter on raw bytes (contains / starts_with / regex). ``field_eq`` is checked after extraction
        (:meth:`post_match`). A pack with no predicates never matches."""
        if not self._has_preds:
            return False
        for p in self._all_pre:
            if not p.check(data):
                return False
        if self._has_any:
            if self._post_any:  # an `any` containing a field_eq cannot be decided before extraction
                return True
            return any(p.check(data) for p in self._any_pre)
        return True

    def post_match(self, fields: dict[str, Any]) -> bool:
        for p in self._post_all:
            if str(fields.get(p.field)) != p.value:
                return False
        if self._post_any and not self._any_pre:
            return any(str(fields.get(p.field)) == p.value for p in self._post_any)
        return True

    # ------------------------------------------------------------------ extract
    def extract(self, data: bytes, ctx: dict[str, Any]) -> dict[str, Any] | None:
        """Decode, strip the syslog header when ``framing: syslog`` (filling ``ctx`` with ``syslog.*``), run the extractor.

        ``ctx`` input keys: ``_recv_ms`` (int, for RFC 3164 year inference) and ``_zeek`` (a ZeekState for tsv_zeek packs)."""
        text = data.decode("utf-8", "surrogateescape")
        if self._syslog:
            text, sctx = parse_syslog(text, ctx.get("_recv_ms", 0))
            ctx.update(sctx)
        if self._is_zeek:
            st = ctx.get("_zeek")
            return self._text(text[:MAX_INPUT], st if isinstance(st, ZeekState) else None)
        return self._text(text[:MAX_INPUT])

    # ------------------------------------------------------------------ normalize
    def select_class(self, view: dict[str, Any]) -> str:
        for fld, eq, cls in self._select:
            if fld is None:
                return cls
            got = view.get(fld)
            if got is not None and str(got) == eq:
                return cls
        return "base_event"

    def normalize(self, fields: dict[str, Any], env: RawEnvelope, ref: VaultRef,
                  ctx: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        c = ctx or {}
        ctx_keys = tuple(k for k in c if k[:1] != "_")
        view = fields
        for k in ctx_keys:
            view[k] = c[k]
        spec = self.classes[self.select_class(view)]
        return [build_event(spec, view, ctx_keys, self.meta, env, ref, c, 0)]


def compile_pack(doc: PackDoc, default_tz: str = "UTC") -> CompiledPackImpl:
    return CompiledPackImpl(doc, default_tz)
