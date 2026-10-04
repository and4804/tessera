"""Vault references."""
from __future__ import annotations

import msgspec


class VaultRef(msgspec.Struct, frozen=True):
    segment: str             # "n1-000042"
    block: int
    idx: int                 # index inside block
    sha256: str              # hex SHA-256 of the raw bytes

    def __str__(self) -> str:
        return f"{self.segment}/{self.block}/{self.idx}"


def parse_raw_ref(ref: str) -> tuple[str, int, int]:
    """``"n1-000042/17/233"`` -> ``("n1-000042", 17, 233)``. Raises ValueError on malformed input."""
    seg, block, idx = ref.rsplit("/", 2)
    return seg, int(block), int(idx)
