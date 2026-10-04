"""Optional local-LLM assist for onboarding (§7.11 step 8). Slow path only; OFF by default (R6).

Contract: the LLM proposes a *patch* (JSON object deep-merged into the draft pack). The patch is accepted only if the
patched pack passes the linter, passes ALL of its tests, and STRICTLY raises coverage over the samples. Otherwise the
draft is returned unchanged. Only a local endpoint is ever contacted (R5): loopback, RFC1918, or a single-label
hostname (compose service name such as `ollama`). Anything else raises EndpointError before any I/O.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from . import refengine, studio

Transport = Callable[[str, dict[str, Any], float], dict[str, Any]]

DSL_GRAMMAR = """Pack DSL (closed set, no code): top-level keys id, match, extract{kind,options}, normalize{class,select,classes.<name>.set,ignore}.
Expressions: {const: v} | {from: field, pipe: [ops], default: v} | {coalesce: [exprs]} | {when: cond, then: expr, else: expr}.
Pipe ops: str int float lower upper strip ip port mac epoch_s epoch_ms epoch_ns iso8601 strptime lookup regex split concat mul proto_name.
Reply with ONE JSON object: a patch deep-merged into the pack (dicts merge, lists replace). No prose."""


class EndpointError(ValueError):
    pass


class LLMDisabled(RuntimeError):
    pass


def check_endpoint(url: str) -> str:
    """Return the URL if it is local-only, else raise EndpointError."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise EndpointError(f"bad endpoint {url!r}")
    host = u.hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host == "localhost" or re.fullmatch(r"[A-Za-z0-9_-]+", host):   # single label: compose service name
            return url
        raise EndpointError(f"endpoint host {host!r} is not local (R5)") from None
    if ip.is_loopback or ip.is_private:
        return url
    raise EndpointError(f"endpoint {host} is not loopback/RFC1918 (R5)")


def http_transport(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Default transport: stdlib urllib POST (no new dependency). Never reached with a non-local URL."""
    import urllib.request
    check_endpoint(url)
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - scheme and host validated above
        return json.loads(r.read().decode())


def deep_merge(base: Any, patch: Any) -> Any:
    if isinstance(base, dict) and isinstance(patch, dict):
        out = dict(base)
        for k, v in patch.items():
            out[k] = deep_merge(base.get(k), v) if k in base else copy.deepcopy(v)
        return out
    return copy.deepcopy(patch)


def apply_patch(pack: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(patch, dict):
        raise ValueError("patch must be an object")
    for forbidden in ("id", "verified"):
        patch = {k: v for k, v in patch.items() if k != forbidden}   # the LLM may not rename or self-verify a pack
    return deep_merge(pack, patch)


def _coverage(pack: dict[str, Any], lines: list[str]) -> float:
    return float(studio.preview(pack, lines, limit=0).summary["coverage_mean"])


@dataclass
class Outcome:
    accepted: bool
    reason: str
    pack: dict[str, Any]
    before: float = 0.0
    after: float = 0.0
    patch: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)


def evaluate_patch(pack: dict[str, Any], patch: dict[str, Any], lines: list[str]) -> Outcome:
    """The accept rule: lint clean + all tests pass + coverage strictly increases."""
    before = _coverage(pack, lines)
    try:
        cand = apply_patch(pack, patch)
        p = refengine.Pack(cand)
        errs = [e for e in refengine.lint(p, min_tests=1) if "R12" not in e]
        fails = refengine.run_tests(p)
        after = _coverage(cand, lines)
    except Exception as e:  # noqa: BLE001 - any malformed patch is a rejection
        return Outcome(False, f"patch rejected: {type(e).__name__}: {e}", pack, before, before, patch)
    if errs or fails:
        return Outcome(False, "patch rejected: lint/tests failed", pack, before, after, patch, errs + fails)
    if after <= before:
        return Outcome(False, f"patch rejected: coverage {before:.4f} -> {after:.4f} did not increase", pack, before, after, patch)
    return Outcome(True, "accepted", cand, before, after, patch)


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in reply")
    obj = json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("reply is not an object")
    return obj


class LLMAssist:
    def __init__(self, enabled: bool = False, endpoint: str = "http://ollama:11434", model: str = "local", timeout: float = 60.0,
                 transport: Transport | None = None) -> None:
        self.enabled, self.endpoint, self.model, self.timeout = enabled, endpoint, model, timeout
        self.transport = transport or http_transport

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None, transport: Transport | None = None) -> LLMAssist:
        c = ((cfg or {}).get("onboard") or {}).get("llm") or {}
        return cls(bool(c.get("enabled", False)), c.get("endpoint", "http://ollama:11434"), c.get("model", "local"), transport=transport)

    def build_prompt(self, pack: dict[str, Any], samples: list[str], unmapped: list[str]) -> str:
        return (f"{DSL_GRAMMAR}\n\nDraft pack:\n{studio.dump_pack(pack)}\nUnmapped fields: {unmapped}\n"
                "Sample log lines:\n" + "\n".join(s[:400] for s in samples[:12]))

    def propose(self, pack: dict[str, Any], samples: list[str], unmapped: list[str]) -> dict[str, Any]:
        url = check_endpoint(self.endpoint).rstrip("/") + "/api/generate"
        body = {"model": self.model, "prompt": self.build_prompt(pack, samples, unmapped), "stream": False, "format": "json"}
        resp = self.transport(url, body, self.timeout)
        return _extract_json(str(resp.get("response", "")))

    def assist(self, pack: dict[str, Any], samples: list[str]) -> Outcome:
        """Never raises: any failure leaves the draft untouched."""
        if not self.enabled:
            return Outcome(False, "llm disabled", pack)
        lines = list(samples)
        try:
            summ = studio.preview(pack, lines, limit=0).summary
            patch = self.propose(pack, lines, summ["unmapped_fields"])
        except Exception as e:  # noqa: BLE001
            return Outcome(False, f"llm unavailable: {type(e).__name__}: {e}", pack)
        return evaluate_patch(pack, patch, lines)
