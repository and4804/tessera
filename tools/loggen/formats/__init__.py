"""Vendor renderers. Each module exposes NAME, PACK, KINDS and render(ev, dev) -> list[(line, expect, flags)].

`expect` is the ground-truth dict of OCSF dotted paths the corresponding pack MUST produce (excluding
derived fields: type_uid, category_uid, metadata.*, ulpf.*, unmapped.*). `flags` may contain
{"time_assumed": True} when the source timestamp lacks a year/zone and `time` cannot be checked exactly.
All formats are illustrative (R12) and need human verification against vendor docs / real captures.
"""
from __future__ import annotations

from . import asa, cef, dnsmasq, fortigate, leef, pfsense, squid, suricata, windows, zeek  # noqa: F401

REGISTRY = {m.NAME: m for m in (fortigate, asa, suricata, cef, pfsense, squid, zeek, windows, leef, dnsmasq)}
