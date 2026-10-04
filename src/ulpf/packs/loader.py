"""Pack loading and the hot-reload registry (§7.6, §7.11 step 9).

``PackRegistry.snapshot`` is an immutable :class:`PackSet`; a reload builds a complete new set and swaps one reference, so a worker
that grabbed the old snapshot for its current batch finishes on the old version (``pack_version`` in lineage shows which)."""
from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .compiler import CompiledPackImpl, compile_pack
from .dsl_ops import PackError
from .schema import PackDoc, parse_pack

try:  # PyYAML ships the C loader on most platforms (R7: safe loaders only)
    _Loader: Any = yaml.CSafeLoader
except AttributeError:  # pragma: no cover
    _Loader = yaml.SafeLoader


def load_yaml_text(text: str) -> Any:
    return yaml.load(text, Loader=_Loader)  # noqa: S506 - CSafeLoader/SafeLoader only


def load_pack_doc(path: str | Path) -> PackDoc:
    """Parse + validate one pack file (raises PackError / yaml.YAMLError)."""
    p = Path(path)
    return parse_pack(load_yaml_text(p.read_text(encoding="utf-8")), str(p))


def load_pack_text(text: str, path: str = "<memory>") -> PackDoc:
    return parse_pack(load_yaml_text(text), path)


def pack_files(dirs: Sequence[str | Path] | str | Path) -> list[Path]:
    roots: list[str | Path] = [dirs] if isinstance(dirs, str | Path) else list(dirs)
    out: list[Path] = []
    for r in roots:
        rp = Path(r)
        if rp.is_file():
            out.append(rp)
        elif rp.is_dir():
            out.extend(sorted(p for p in rp.rglob("*.yaml") if not p.name.startswith("_")))
    return out


@dataclass(frozen=True, slots=True)
class PackSet:
    """Immutable, priority-ordered view of the compiled packs."""

    packs: tuple[CompiledPackImpl, ...]
    by_id: dict[str, CompiledPackImpl]
    by_format: dict[str, tuple[CompiledPackImpl, ...]]
    generation: int = 0

    @staticmethod
    def build(packs: list[CompiledPackImpl], generation: int = 0) -> PackSet:
        ordered = sorted(packs, key=lambda p: (-p.priority, p.id))
        by_id = {p.id: p for p in ordered}
        formats: dict[str, list[CompiledPackImpl]] = {}
        for p in ordered:
            for f in p.formats:
                formats.setdefault(f, []).append(p)
        return PackSet(tuple(ordered), by_id, {k: tuple(v) for k, v in formats.items()}, generation)

    def versions(self) -> dict[str, str]:
        return {p.id: p.version for p in self.packs}


@dataclass(slots=True)
class ReloadReport:
    generation: int
    loaded: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)       # path -> message (previous good version kept if there was one)
    changed: list[str] = field(default_factory=list)           # pack ids added or whose version/content changed
    removed: list[str] = field(default_factory=list)


class PackRegistry:
    def __init__(self, dirs: Sequence[str | Path] | str | Path, default_tz: str = "UTC", *, load: bool = True) -> None:
        self.dirs: list[str | Path] = [dirs] if isinstance(dirs, str | Path) else list(dirs)
        self.default_tz = default_tz
        self.snapshot: PackSet = PackSet.build([], 0)
        self._files: dict[str, tuple[int, int, CompiledPackImpl | None]] = {}   # path -> (mtime_ns, size, compiled)
        self.errors: dict[str, str] = {}
        if load:
            self.reload()

    def _sig(self, p: Path) -> tuple[int, int]:
        st = p.stat()
        return st.st_mtime_ns, st.st_size

    def changed_on_disk(self) -> bool:
        paths = {str(p): p for p in pack_files(self.dirs)}
        if set(paths) != set(self._files):
            return True
        try:
            return any(self._sig(p) != self._files[k][:2] for k, p in paths.items())
        except OSError:
            return True

    def poll(self) -> ReloadReport | None:
        """Reload when files were added/changed/removed (cheap stat scan); None when nothing changed."""
        return self.reload() if self.changed_on_disk() else None

    def reload(self) -> ReloadReport:
        old = self.snapshot
        rep = ReloadReport(generation=old.generation + 1)
        new_files: dict[str, tuple[int, int, CompiledPackImpl | None]] = {}
        errors: dict[str, str] = {}
        for p in pack_files(self.dirs):
            key = str(p)
            try:
                sig = self._sig(p)
            except OSError as e:
                errors[key] = f"stat failed: {e}"
                continue
            prev = self._files.get(key)
            if prev is not None and prev[:2] == sig:
                new_files[key] = prev
                continue
            try:
                compiled = compile_pack(load_pack_doc(p), self.default_tz)
                new_files[key] = (*sig, compiled)
            except (PackError, yaml.YAMLError, OSError, ValueError, KeyError, TypeError) as e:
                errors[key] = f"{type(e).__name__}: {e}"
                # keep the last good version of this file (atomic: a broken edit never removes a working pack)
                new_files[key] = (*sig, prev[2]) if prev is not None else (*sig, None)
        chosen: dict[str, CompiledPackImpl] = {}
        for _key, (_m, _s, c) in new_files.items():   # later dirs / files override earlier ones with the same id
            if c is not None:
                chosen[c.id] = c
        new = PackSet.build(list(chosen.values()), old.generation + 1)
        for pid, c in new.by_id.items():
            o = old.by_id.get(pid)
            if o is None or o is not c and (o.version != c.version or o.doc.raw != c.doc.raw):
                rep.changed.append(pid)
        rep.removed = sorted(set(old.by_id) - set(new.by_id))
        rep.loaded = sorted(new.by_id)
        rep.errors = errors
        self._files = new_files
        self.errors = errors
        self.snapshot = new   # the single atomic swap
        return rep

    def publish(self, text: str, target_dir: str | Path, filename: str | None = None) -> tuple[Path, ReloadReport]:
        """Validate ``text`` as a pack, write it atomically into ``target_dir`` and reload."""
        doc = load_pack_text(text)
        compile_pack(doc, self.default_tz)   # raises on anything uncompilable before touching disk
        d = Path(target_dir)
        d.mkdir(parents=True, exist_ok=True)
        name = filename or (doc.id.replace("/", "_") + ".yaml")
        dest = d / name
        tmp = dest.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, dest)
        return dest, self.reload()


def load_compiled(dirs: Sequence[str | Path] | str | Path, default_tz: str = "UTC") -> PackSet:
    """Strict one-shot load for CLI/tests: raises on the first broken pack."""
    packs = [compile_pack(load_pack_doc(p), default_tz) for p in pack_files(dirs)]
    return PackSet.build(packs, 1)
