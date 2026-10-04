"""Normalization: mapper (event assembly), timeparse, validate (OCSF conformance), lake_schema (typed Parquet columns)."""
from .mapper import ClassSpec, PackMeta, Setter, build_event, unparsed_event
from .validate import Violation, validate_event

__all__ = ["ClassSpec", "PackMeta", "Setter", "Violation", "build_event", "unparsed_event", "validate_event"]
