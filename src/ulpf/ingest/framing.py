"""Transport de-framing. Pure, incremental, and byte-exact: no decoding, no stripping beyond the frame terminator."""
from __future__ import annotations

import re

_OCTET_PREFIX = re.compile(rb"^([1-9][0-9]{0,6}) ")


class Deframer:
    """Per-connection stream de-framer for syslog over TCP/TLS.

    Auto-detects RFC 6587 octet counting (``<len> <msg>``) versus newline delimiting from the first bytes of the stream
    (``framing`` can force either). Handles partial reads. Oversize messages are cut at ``max_bytes`` and flagged; the rest of
    the frame is skipped (never silently: the flag travels with the event).

    ``feed`` returns ``(message, truncated)`` tuples. A trailing ``\\r`` before ``\\n`` is part of the terminator, not the event.
    Empty lines carry no event and are skipped.
    """

    def __init__(self, max_bytes: int = 65536, framing: str = "auto") -> None:
        self.max = max_bytes
        self.mode = framing if framing in ("octet", "newline") else "auto"
        self.buf = bytearray()
        self._skip = 0           # bytes of an oversize frame still to discard
        self._discarding = False  # inside an oversize newline-delimited line

    @property
    def detected(self) -> str:
        return self.mode

    def _detect(self) -> bool:
        b = self.buf
        if not b:
            return False
        if not (48 <= b[0] <= 57):
            self.mode = "newline"
            return True
        m = _OCTET_PREFIX.match(bytes(b[:9]))
        if m:
            n = int(m.group(1))
            # a plausible octet frame is followed (after n bytes) by end-of-buffer or another frame start; otherwise treat the
            # leading digits as the start of an ordinary line (e.g. "12 users logged in\n")
            end = m.end() + n
            if len(b) >= end and len(b) > end and b[end] not in b"0123456789<\r\n{C":
                self.mode = "newline"
            else:
                self.mode = "octet"
            return True
        if len(b) >= 9 or b"\n" in b:
            self.mode = "newline"
            return True
        return False

    def feed(self, data: bytes) -> list[tuple[bytes, bool]]:
        self.buf += data
        if self.mode == "auto" and not self._detect():
            return []
        return self._octet() if self.mode == "octet" else self._newline()

    def _newline(self) -> list[tuple[bytes, bool]]:
        out: list[tuple[bytes, bool]] = []
        b = self.buf
        while True:
            i = b.find(b"\n")
            if i < 0:
                if len(b) > self.max and not self._discarding:
                    out.append((bytes(b[: self.max]), True))
                    self._discarding = True
                if self._discarding:
                    b.clear()
                break
            line = bytes(b[:i])
            del b[: i + 1]
            if self._discarding:
                self._discarding = False
                continue
            if line.endswith(b"\r"):
                line = line[:-1]
            if not line:
                continue
            if len(line) > self.max:
                out.append((line[: self.max], True))
            else:
                out.append((line, False))
        return out

    def _octet(self) -> list[tuple[bytes, bool]]:
        out: list[tuple[bytes, bool]] = []
        b = self.buf
        while True:
            if self._skip:
                n = min(self._skip, len(b))
                del b[:n]
                self._skip -= n
                if self._skip:
                    break
            # tolerate stray terminators between frames
            while b[:1] in (b"\n", b"\r"):
                del b[:1]
            if not b:
                break
            m = _OCTET_PREFIX.match(bytes(b[:9]))
            if not m:
                if len(b) < 9 and all(48 <= c <= 57 for c in b):
                    break  # length prefix not complete yet
                # corrupt framing: fall back to newline mode for the rest of the connection rather than losing the bytes
                self.mode = "newline"
                out.extend(self._newline())
                return out
            n = int(m.group(1))
            start = m.end()
            if len(b) < start + n:
                if n > self.max and len(b) - start >= self.max:  # emit the head now, discard the rest as it arrives
                    out.append((bytes(b[start : start + self.max]), True))
                    self._skip = n - (len(b) - start)
                    b.clear()
                    continue
                break
            msg = bytes(b[start : start + n])
            del b[: start + n]
            if n > self.max:
                out.append((msg[: self.max], True))
            elif msg:
                out.append((msg, False))
        return out

    def close(self) -> list[tuple[bytes, bool]]:
        """Connection closed: flush an unterminated final line (newline mode). A cut octet frame is emitted as-is, flagged."""
        out: list[tuple[bytes, bool]] = []
        if self.buf and not self._discarding and not self._skip:
            if self.mode == "octet":
                m = _OCTET_PREFIX.match(bytes(self.buf[:9]))
                rest = bytes(self.buf[m.end():]) if m else bytes(self.buf)
                if rest:
                    out.append((rest[: self.max], True))
            else:
                line = bytes(self.buf).rstrip(b"\r")
                if line:
                    out.append((line[: self.max], len(line) > self.max))
        self.buf.clear()
        return out
