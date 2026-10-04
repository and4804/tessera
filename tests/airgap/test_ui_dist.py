"""R5/§10: the built UI must make no external request. Read-only scan of ui/dist (build it with `cd ui && pnpm build`)."""
import re
from pathlib import Path

import pytest

DIST = Path(__file__).resolve().parents[2] / "ui" / "dist"

# Hosts that appear only as inert strings inside bundled libraries (XML namespace identifiers, doc links in error messages, licence
# headers). Anything NOT on this list fails the test, so a new CDN/font/analytics host cannot slip in. Each is also checked below to never
# be the target of a request-making construct.
INERT_HOSTS = {"www.w3.org", "github.com", "code.visualstudio.com", "reactjs.org", "microsoft.com", "react.dev"}
CDN_MARKERS = ("cdn.", "unpkg.com", "cdnjs", "jsdelivr", "googleapis", "gstatic", "fonts.", "googletagmanager", "google-analytics",
               "sentry", "segment.", "cloudfront", "fastly", "bootstrapcdn")
URL = re.compile(r"(?:https?:)?//([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})(?::\d+)?[/\"'`)\s]", re.I)
ABS = re.compile(r"https?://([A-Za-z0-9][A-Za-z0-9._-]*)", re.I)
REQUESTING = re.compile(r"""(?:fetch|importScripts|sendBeacon|WebSocket|EventSource|Worker|SharedWorker|import)\s*\(\s*[`"']https?://|"""
                        r"""\.(?:src|href)\s*=\s*[`"']https?://|\.open\(\s*[`"'][A-Z]+[`"']\s*,\s*[`"']https?://""")


@pytest.fixture(scope="module")
def dist_files():
    if not (DIST / "index.html").is_file():
        pytest.skip("ui/dist not built (cd ui && pnpm build)")
    return [p for p in DIST.rglob("*") if p.is_file()]


def test_dist_has_only_local_asset_references(dist_files):
    html = (DIST / "index.html").read_text()
    for m in re.finditer(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", html):
        ref = m.group(1)
        assert not re.match(r"(https?:)?//", ref), f"index.html loads an external resource: {ref}"
    for p in dist_files:
        if p.suffix == ".css":
            css = p.read_text(errors="replace")
            assert not re.search(r"@import\s+(?:url\()?\s*[\"']?(?:https?:)?//", css), f"{p.name} @imports a remote stylesheet"
            for m in re.finditer(r"url\(\s*[\"']?([^)\"']+)", css):
                assert not re.match(r"(https?:)?//", m.group(1)), f"{p.name} references a remote url(): {m.group(1)}"


def test_no_external_hosts_in_bundle(dist_files):
    seen: dict[str, set[str]] = {}
    for p in dist_files:
        if p.suffix not in (".js", ".css", ".html", ".json", ".map"):
            continue
        text = p.read_text(errors="replace")
        for m in ABS.finditer(text):
            seen.setdefault(m.group(1).lower(), set()).add(p.name)
        for m in URL.finditer(text):
            if m.group(0).startswith("//"):          # protocol-relative URL literal
                seen.setdefault(m.group(1).lower(), set()).add(p.name)
    unknown = {h: sorted(f)[:3] for h, f in seen.items() if h not in INERT_HOSTS and h not in ("localhost", "127.0.0.1")}
    assert not unknown, f"external hosts referenced by the UI bundle: {unknown}"
    assert not [h for h in seen if any(c in h for c in CDN_MARKERS)]


def test_no_request_is_aimed_at_an_absolute_url(dist_files):
    bad = []
    for p in dist_files:
        if p.suffix != ".js":
            continue
        for m in REQUESTING.finditer(p.read_text(errors="replace")):
            bad.append((p.name, m.group(0)[:80]))
    assert not bad, bad


def test_fonts_and_monaco_workers_are_shipped_locally(dist_files):
    names = " ".join(p.name for p in dist_files)
    assert ".woff2" in names and "editor.worker" in names
