"""Source cache (§7.4): ``(peer_ip | hint)`` -> the pack that matched last. After ``evict_after`` consecutive misses the entry goes."""
from __future__ import annotations


class SourceCache:
    __slots__ = ("_d", "max_entries", "evict_after", "hits", "misses")

    def __init__(self, max_entries: int = 4096, evict_after: int = 20) -> None:
        self._d: dict[str, list[object]] = {}   # key -> [pack_id, consecutive_misses]
        self.max_entries = max_entries
        self.evict_after = evict_after
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> str | None:
        e = self._d.get(key)
        return None if e is None else str(e[0])

    def hit(self, key: str, pack_id: str) -> None:
        e = self._d.get(key)
        if e is None:
            if len(self._d) >= self.max_entries:
                self._d.pop(next(iter(self._d)))     # drop the oldest insertion: bounded memory
            self._d[key] = [pack_id, 0]
        else:
            e[0] = pack_id
            e[1] = 0
        self.hits += 1

    def miss(self, key: str) -> None:
        e = self._d.get(key)
        self.misses += 1
        if e is None:
            return
        e[1] = int(e[1]) + 1  # type: ignore[call-overload]
        if int(e[1]) >= self.evict_after:  # type: ignore[call-overload]
            del self._d[key]

    def __len__(self) -> int:
        return len(self._d)

    def clear(self) -> None:
        self._d.clear()
