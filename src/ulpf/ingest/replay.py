"""File replay and tail (§7.1): lines are read as bytes and never decoded."""
from __future__ import annotations

import glob
import os
import time
from collections.abc import Iterator
from pathlib import Path

from .publisher import Publisher


def iter_lines(path: str | Path, chunk: int = 1 << 20) -> Iterator[bytes]:
    """Yield each line of ``path`` without its terminator (``\\n`` or ``\\r\\n``); skips empty lines."""
    with open(path, "rb") as f:
        tail = b""
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            lines = (tail + buf).split(b"\n")
            tail = lines.pop()
            for ln in lines:
                if ln.endswith(b"\r"):
                    ln = ln[:-1]
                if ln:
                    yield ln
        if tail.endswith(b"\r"):
            tail = tail[:-1]
        if tail:
            yield tail


def replay_file(pub: Publisher, path: str | Path, hint: str | None = None, rate: float | None = None, transport: str = "replay",
                limit: int | None = None) -> int:
    """Publish every line of ``path``. ``rate`` is events/second (None = as fast as possible). Returns events published."""
    n = 0
    t0 = time.perf_counter()
    for ln in iter_lines(path):
        pub.ingest(ln, transport, "", 0, hint)
        n += 1
        if limit is not None and n >= limit:
            break
        if rate:
            lag = n / rate - (time.perf_counter() - t0)
            if lag > 0.005:
                pub.flush()
                time.sleep(lag)
    pub.flush()
    return n


class FileTailer:
    """Poll-based tailer for ``file_watch`` entries (glob + hint). Starts at EOF of existing files unless ``from_start``.

    New files (the demo's "drop a file in a folder") are read from the beginning. Rotation/truncation is detected by inode
    change or size shrink; a partially written last line is held until its newline arrives."""

    def __init__(self, pub: Publisher, patterns: list[tuple[str, str | None]], from_start: bool = False) -> None:
        self.pub = pub
        self.patterns = patterns
        self.state: dict[str, tuple[int, int, bytes]] = {}   # path -> (inode, offset, partial)
        self._first = True
        self.from_start = from_start

    def poll(self) -> int:
        n = 0
        for pattern, hint in self.patterns:
            for path in sorted(glob.glob(pattern)):
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                known = self.state.get(path)
                if known is None:
                    off = st.st_size if (self._first and not self.from_start) else 0
                    known = (st.st_ino, off, b"")
                ino, off, partial = known
                if ino != st.st_ino or st.st_size < off:
                    ino, off, partial = st.st_ino, 0, b""
                if st.st_size > off:
                    with open(path, "rb") as f:
                        f.seek(off)
                        data = f.read()
                    off += len(data)
                    parts = (partial + data).split(b"\n")
                    partial = parts.pop()
                    for ln in parts:
                        ln = ln[:-1] if ln.endswith(b"\r") else ln
                        if ln:
                            self.pub.ingest(ln, "file", "", 0, hint or None)
                            n += 1
                self.state[path] = (ino, off, partial)
        self._first = False
        self.pub.flush()
        return n
