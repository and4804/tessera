"""Raw Vault: byte-exact, content-hashed, hash-chained, signed segments (§7.3)."""
from .integrity import IntegrityError, SegmentReport, verify_all, verify_segment
from .reader import NotFoundError, RawRead, VaultReader
from .writer import VaultWriter, generate_keypair, load_signing_key

__all__ = [
    "IntegrityError", "NotFoundError", "RawRead", "SegmentReport", "VaultReader", "VaultWriter",
    "generate_keypair", "load_signing_key", "verify_all", "verify_segment",
]
