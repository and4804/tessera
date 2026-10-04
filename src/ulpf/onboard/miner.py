"""Template mining for free-text logs (Onboarding Studio, step 3 of §7.11). Slow path only (I4).

Two layers:
  1. `cluster_templates()`  - Drain-style clustering of masked lines (uses `drain3` when importable, else a bundled
     equivalent) -> templates + counts, used for Studio suggestions ("these 48k events look the same").
  2. `synthesize_regex()`   - aligns the atoms of many lines against each other (Needleman-Wunsch) and folds them into ONE
     regex: positions that never vary stay literal, positions that vary become typed named groups, positions present in only
     some lines become optional groups.  Variable names come from the literal keyword in front of the value
     (`src-mac`, `proto`, `len`, `in:`...), IP pairs around `->` become src_ip/dst_ip, `ip:port` pairs yield *_port.
The result is a plain `regex` extractor spec (anchor only) that the closed pack DSL (R7) can run - no DSL extension needed.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------------------------- atomization
_ATOM_RE = re.compile(
    r"""
    (?P<TS>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)
   |(?P<TS2>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d\d:\d\d:\d\d)
   |(?P<UUID>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})
   |(?P<MAC>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})
   |(?P<IP>(?:\d{1,3}\.){3}\d{1,3})
   |(?P<TIME>\d\d:\d\d:\d\d)
   |(?P<HEX>0x[0-9a-fA-F]+)
   |(?P<NUM>-?\d+(?:\.\d+)?)
   |(?P<WORD>[A-Za-z_][\w.-]*)
   |(?P<SP>\s+)
   |(?P<PAREN>\([^()\s][^()]*\))
   |(?P<PUNCT>->|=>|<-|.)
    """,
    re.X,
)
VAR_TYPES = {"TS", "TS2", "UUID", "MAC", "IP", "TIME", "HEX", "NUM", "WORD", "PAREN", "TOKEN"}
_RX_FOR = {
    "NUM": r"-?\d+(?:\.\d+)?",
    "IP": r"(?:\d{1,3}\.){3}\d{1,3}",
    "MAC": r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}",
    "WORD": r"[A-Za-z_][\w.-]*",
    "HEX": r"0x[0-9A-Fa-f]+",
    "UUID": r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
    "TIME": r"\d\d:\d\d:\d\d",
    "TS": r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?",
    "TS2": r"[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d\d:\d\d:\d\d",
    "PAREN": r"\([^()]*\)",
    "TOKEN": r"(?:\([^()]*\)|[A-Za-z_][\w.-]*)",     # a word or a parenthesised group (e.g. ether1 | (unknown 0))
}
MAX_LINE = 4096


def atomize(line: str) -> list[tuple[str, str]]:
    return [(m.lastgroup or "PUNCT", m.group()) for m in _ATOM_RE.finditer(line[:MAX_LINE])]


# --------------------------------------------------------------------------------------------- clustering (templates)
_MASK = [(re.compile(p), t) for p, t in [
    (r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?", "<TS>"),
    (r"[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d\d:\d\d:\d\d", "<TS>"),
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>"),
    (r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", "<MAC>"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>"),
    (r"\b0x[0-9a-fA-F]+\b", "<HEX>"),
    (r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])", "<NUM>"),
]]


def mask_line(line: str) -> str:
    for rx, tag in _MASK:
        line = rx.sub(tag, line[:MAX_LINE])
    return line


@dataclass
class Template:
    id: int
    tokens: list[str]
    count: int = 0
    examples: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(self.tokens)


class _MiniDrain:
    """Small Drain-like clusterer: bucket by token count, merge when similarity >= sim_th, differing tokens -> <*>."""

    def __init__(self, sim_th: float = 0.5):
        self.sim_th = sim_th
        self.buckets: dict[int, list[Template]] = {}
        self.n = 0

    def add(self, line: str) -> Template:
        toks = re.split(r"[ \t]+", mask_line(line).strip()) or [""]
        best, best_sim = None, -1.0
        for t in self.buckets.get(len(toks), []):
            same = sum(1 for a, b in zip(t.tokens, toks, strict=True) if a == b or a == "<*>")
            sim = same / len(toks)
            if sim > best_sim:
                best, best_sim = t, sim
        if best is not None and best_sim >= self.sim_th:
            best.tokens = [a if a == b else "<*>" for a, b in zip(best.tokens, toks, strict=True)]
        else:
            self.n += 1
            best = Template(self.n, toks)
            self.buckets.setdefault(len(toks), []).append(best)
        best.count += 1
        if len(best.examples) < 3:
            best.examples.append(line)
        return best


def cluster_templates(lines: list[str], sim_th: float = 0.5, use_drain3: bool | None = None) -> list[Template]:
    """Templates sorted by support. Uses `drain3` when available (use_drain3=None => auto) else the bundled clusterer."""
    if use_drain3 is None or use_drain3:
        try:
            return _cluster_drain3(lines, sim_th)
        except Exception:  # noqa: BLE001  (ImportError or API drift) -> bundled implementation
            if use_drain3:
                raise
    md = _MiniDrain(sim_th)
    for ln in lines:
        md.add(ln)
    return sorted((t for b in md.buckets.values() for t in b), key=lambda t: -t.count)


def _cluster_drain3(lines: list[str], sim_th: float) -> list[Template]:  # pragma: no cover - needs drain3 installed
    from drain3 import TemplateMiner
    from drain3.masking import MaskingInstruction
    from drain3.template_miner_config import TemplateMinerConfig

    cfg = TemplateMinerConfig()
    cfg.drain_sim_th = sim_th
    cfg.profiling_enabled = False
    cfg.masking_instructions = [MaskingInstruction(rx.pattern, tag.strip("<>")) for rx, tag in _MASK]
    tm = TemplateMiner(None, cfg)
    ex: dict[int, list[str]] = {}
    for ln in lines:
        r = tm.add_log_message(ln[:MAX_LINE])
        ex.setdefault(r["cluster_id"], []).append(ln)
    out = []
    for c in tm.drain.clusters:
        out.append(Template(c.cluster_id, c.get_template().split(" "), c.size, ex.get(c.cluster_id, [])[:3]))
    return sorted(out, key=lambda t: -t.count)


# --------------------------------------------------------------------------------------------- regex synthesis
@dataclass
class Node:
    kind: str                      # atom type
    text: str                      # literal text (valid while `lit`)
    lit: bool = True
    support: int = 1               # number of sample lines that contain this node
    values: list[str] = field(default_factory=list)
    name: str = ""


_TOKENISH = {"WORD", "PAREN", "TOKEN"}


def _node_score(a: Node, b: Node) -> int | None:
    if a.kind != b.kind:
        if a.kind in _TOKENISH and b.kind in _TOKENISH and not (a.lit and b.lit):
            if a.lit != b.lit and (a if a.lit else b).text not in (b if a.lit else a).values:
                return None
            return 2
        return None
    if a.kind in ("SP", "PUNCT"):
        return 2 if a.text == b.text else None
    if a.lit and b.lit:
        return 3 if a.text == b.text else None
    if a.lit != b.lit:                        # keyword vs variable: only if that keyword is one of the variable's values
        lit, var = (a, b) if a.lit else (b, a)
        return 2 if lit.text in var.values else None
    return 2 if a.kind in VAR_TYPES else None


def _join(a: Node, b: Node) -> Node:
    kind = a.kind if a.kind == b.kind else "TOKEN"
    return Node(kind, a.text, a.lit and b.lit and a.text == b.text, a.support + b.support, (a.values + b.values)[:400])


def _align(sa: list[Node], sb: list[Node]) -> list[tuple[int | None, int | None]]:
    """Needleman-Wunsch over two skeletons -> list of (i, j) index pairs (None = gap)."""
    n, m, gap = len(sa), len(sb), -1

    def prev_keys(sk: list[Node]) -> list[str]:
        out, last = [], ""
        for nd in sk:
            out.append(last)
            if nd.kind != "SP":
                last = nd.text if nd.lit else f"<{nd.kind}>"
        return out

    def next_keys(sk: list[Node]) -> list[str]:
        out, nxt = [""] * len(sk), ""
        for k in range(len(sk) - 1, -1, -1):
            out[k] = nxt
            if sk[k].kind != "SP":
                nxt = sk[k].text if sk[k].lit and sk[k].kind == "PUNCT" else ""   # only a delimiter is a reliable right context
        return out

    pa, pb = prev_keys(sa), prev_keys(sb)
    na, nb = next_keys(sa), next_keys(sb)

    def sc(i: int, j: int) -> int | None:
        v = _node_score(sa[i], sb[j])
        if v is not None and pa[i] == pb[j] and sa[i].kind in VAR_TYPES:
            v += 2           # same left context ("proto <X>") beats a lucky same-type match elsewhere
        if v is not None and na[i] and na[i] == nb[j] and sa[i].kind in VAR_TYPES and sa[i].kind == sb[j].kind:
            v += 3           # same right delimiter (`<X>:`): the token that touches the delimiter is the same slot
        return v

    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        dp[i][0] = i * gap
    for j in range(1, m + 1):
        dp[0][j] = j * gap
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            v = sc(i - 1, j - 1)
            best = max(dp[i - 1][j], dp[i][j - 1]) + gap
            if v is not None:
                best = max(best, dp[i - 1][j - 1] + v)
            dp[i][j] = best
    out: list[tuple[int | None, int | None]] = []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0:
            v = sc(i - 1, j - 1)
            if v is not None and dp[i][j] == dp[i - 1][j - 1] + v:
                out.append((i - 1, j - 1))
                i, j = i - 1, j - 1
                continue
        if i > 0 and dp[i][j] == dp[i - 1][j] + gap:
            out.append((i - 1, None))
            i -= 1
        else:
            out.append((None, j - 1))
            j -= 1
    out.reverse()
    return out


def _merge_skeletons(sa: list[Node], ta: int, sb: list[Node], tb: int) -> tuple[list[Node], int]:
    """Merge two skeletons. Returns (merged, new_runs): number of contiguous *newly optional* runs this merge introduced."""
    merged: list[Node] = []
    runs, prev_side = 0, ""
    for i, j in _align(sa, sb):
        if i is not None and j is not None:
            merged.append(_join(sa[i], sb[j]))
            prev_side = ""
        elif i is not None:
            merged.append(sa[i])
            if sa[i].support >= ta:           # was required in A, now optional
                if prev_side not in ("a", "b"):
                    runs += 1
                prev_side = "a"
        elif j is not None:
            merged.append(sb[j])
            if sb[j].support >= tb:
                if prev_side not in ("a", "b"):
                    runs += 1
                prev_side = "b"
    return merged, runs


def _structure_groups(lines: list[str], lit_threshold: float = 0.9) -> list[tuple[list[Node], int]]:
    """Group lines by structural shape (atom kinds; near-constant words stay literal) -> clean per-group skeletons."""
    atoms = [atomize(ln) for ln in lines]
    n = len(lines)
    freq: Counter[str] = Counter()
    for at in atoms:
        for w in {t for k, t in at if k == "WORD"}:
            freq[w] += 1
    const_words = {w for w, c in freq.items() if c >= lit_threshold * n}
    # a word right after ':' '=' or '(' is a *value* (e.g. in:ether1), never structure
    valuepos: set[str] = set()
    for at in atoms:
        prev = ""
        for k, t in at:
            if k == "WORD" and prev in (":", "=", "("):    # directly adjacent only ("in:ether1", not "input: in:")
                valuepos.add(t)
            prev = t
    const_words -= valuepos
    groups: dict[tuple, list[list[tuple[str, str]]]] = {}
    for at in atoms:
        key = tuple((k, t if (k in ("SP", "PUNCT") or (k == "WORD" and t in const_words)) else "") for k, t in at)
        groups.setdefault(key, []).append(at)
    # A rare word is a keyword (structure) when it opens a `, keyword value` clause: right after a comma separator and before a value
    # (`..., NAT 10.0.0.1:80->...`). Words elsewhere (`proto UDP`, `info <rule> forward:`) share their slot with other words: variables.
    clause_kw: set[str] = set()
    for at in atoms:
        sig = [(k, t) for k, t in at if k != "SP"]
        for i in range(1, len(sig) - 1):
            if sig[i][0] == "WORD" and sig[i - 1] == ("PUNCT", ",") and sig[i + 1][0] in ("IP", "NUM", "MAC", "PAREN"):
                clause_kw.add(sig[i][1])
    out = []
    for g in sorted(groups.values(), key=lambda g: -len(g)):
        skel = []
        for pos in range(len(g[0])):
            kind = g[0][pos][0]
            vals = [a[pos][1] for a in g]
            # only punctuation, whitespace and near-constant keywords are structure; every other atom is a typed variable.
            # A keyword that is rare overall but constant within its structural group (MikroTik `NAT a->(b)->c` on 5% of lines)
            # is structure too: purely alphabetic (rule names have hyphens/digits), seen at least twice, never in a value position.
            local_kw = (kind == "WORD" and len(set(vals)) == 1 and vals[0] not in valuepos and freq[vals[0]] >= 2
                        and vals[0].isalpha() and vals[0] in clause_kw)
            lit = len(set(vals)) == 1 and (kind in ("SP", "PUNCT") or (kind == "WORD" and (vals[0] in const_words or local_kw)))
            skel.append(Node(kind, vals[0], lit, len(g), vals[:400]))
        out.append((skel, len(g)))
    return out


def _slug(s: str) -> str:
    s = re.sub(r"[^0-9A-Za-z]+", "_", s).strip("_").lower()
    return s if s and not s[0].isdigit() else ("f_" + s if s else "")


def _name_nodes(nodes: list[Node], total: int) -> None:
    """Give every variable node a field name derived from its neighbours (see module docstring)."""
    used: Counter[str] = Counter()

    def claim(base: str) -> str:
        used[base] += 1
        return base if used[base] == 1 else f"{base}_{used[base]}"

    def nxt_text(i: int) -> str:
        j = i + 1
        while j < len(nodes) and nodes[j].kind == "SP":
            j += 1
        return nodes[j].text if j < len(nodes) else ""

    def prv_text(i: int) -> str:
        j = i - 1
        while j >= 0 and nodes[j].kind == "SP":
            j -= 1
        return nodes[j].text if j >= 0 else ""

    last_kw = ""
    clause = ""                              # `, NAT <ip>:<port>->...`: names inside a clause that opens with a keyword get its prefix
    for idx, nd in enumerate(nodes):
        if nd.lit:
            if nd.kind == "PUNCT" and nd.text == ",":
                clause = ""
            if nd.kind == "WORD":
                adjacent_comma = idx > 0 and nodes[idx - 1].lit and nodes[idx - 1].text == ","
                if not adjacent_comma:       # "firewall,info": `info` is a topic, not a keyword for the next value
                    last_kw = _slug(nd.text)
                if idx >= 2 and nodes[idx - 1].kind == "SP" and nodes[idx - 2].text == "," and nodes[idx - 2].lit \
                        and any(not n.lit for n in nodes[:idx]) and idx + 2 < len(nodes) and not nodes[idx + 2].lit:
                    clause = _slug(nd.text) + "_"
            elif nd.text not in (":", "=", "(") and nd.kind != "SP":
                last_kw = ""
            continue
        # variable node
        if nd.kind == "IP":
            j = idx + 1                     # IP [:NUM] ->   => source
            if j + 1 < len(nodes) and nodes[j].text == ":" and nodes[j + 1].kind == "NUM":
                j += 2
            while j < len(nodes) and nodes[j].kind == "SP":
                j += 1
            if j < len(nodes) and nodes[j].text in ("->", "=>"):
                nd.name = claim(clause + "src_ip")
            elif prv_text(idx) in ("->", "=>") or (prv_text(idx) == "(" and idx >= 2 and nodes[idx - 2].text in ("->", "=>")):
                nd.name = claim(clause + "dst_ip")
            else:
                nd.name = claim(f"{last_kw}_ip" if last_kw and not last_kw.endswith("ip") else (last_kw or "ip"))
        elif nd.kind == "NUM" and idx >= 2 and nodes[idx - 1].text == ":" and nodes[idx - 2].kind == "IP" and nodes[idx - 2].name:
            ipn = nodes[idx - 2].name
            nd.name = claim(ipn[:-3] + "_port" if ipn.endswith("_ip") else "port")
        elif nd.kind == "MAC":
            nd.name = claim(last_kw or "mac")
        elif nd.kind == "PAREN" and idx > 0 and nodes[idx - 1].kind == "SP" and idx > 1 and not nodes[idx - 2].lit and nodes[idx - 2].name:
            nd.name = claim(nodes[idx - 2].name + "_detail")
        elif clause and nd.kind == "PAREN":
            nd.name = claim(clause + "translated")
        else:
            base = last_kw if (last_kw and nxt_text(idx) != ":") else ""
            nd.name = claim(base or "field")
        last_kw = ""


@dataclass
class Synth:
    regex: str                     # first (main) regex
    alternatives: list[str]        # all regexes in priority order (len 1 => plain `anchor`)
    fields: list[str]
    optional_fields: list[str]
    anchors: list[str]
    n_lines: int
    types: dict[str, str]
    values: dict[str, list[str]]
    n_groups: int = 0              # structural variants seen
    n_templates: int = 0           # regexes after merging
    dropped_lines: int = 0         # lines of variants that were not given a regex (too rare)


def _render(skel: list[Node], total: int) -> tuple[str, list[str], list[str], list[str]]:
    """Skeleton -> (regex, fields, optional_fields, literal anchors). Consecutive optional nodes with equal support share a group."""
    parts: list[str] = []
    fields: list[str] = []
    optional: list[str] = []
    anchors: list[str] = []
    cur = ""

    def one(nd: Node, opt: bool) -> str:
        nonlocal cur
        if nd.lit:
            if not opt:
                cur += nd.text
            elif cur:
                anchors.append(cur)
                cur = ""
            return r"\s+" if nd.kind == "SP" else re.escape(nd.text)
        if cur:
            anchors.append(cur)
            cur = ""
        fields.append(nd.name)
        if opt:
            optional.append(nd.name)
        return f"(?P<{nd.name}>{_RX_FOR[nd.kind]})"

    i = 0
    while i < len(skel):
        nd = skel[i]
        if nd.support >= total:
            parts.append(one(nd, False))
            i += 1
            continue
        j = i
        while j < len(skel) and skel[j].support == nd.support:
            j += 1
        parts.append("(?:" + "".join(one(x, True) for x in skel[i:j]) + ")?")
        i = j
    if cur:
        anchors.append(cur)
    return "^" + "".join(parts) + r"(?P<_residual>.*)$", fields, optional, anchors


def _unify_names(ref: list[Node], other: list[Node]) -> None:
    """Keep `other`'s own semantic names (src_ip, dst_port, nat_*, ...), which already agree with `ref` wherever the slots mean the
    same thing; only a generic `field*` name is replaced by the name of the aligned variable node in `ref` (when that name is free)."""
    used = {nd.name for nd in other if not nd.lit and nd.name}
    for i, j in _align(ref, other):
        if i is None or j is None or ref[i].lit or other[j].lit or ref[i].kind != other[j].kind:
            continue
        if re.fullmatch(r"field(_\d+)?", other[j].name) and ref[i].name not in used:
            used.discard(other[j].name)
            other[j].name = ref[i].name
            used.add(ref[i].name)


def _inherit_optionality(ref: list[Node], ref_total: int, other: list[Node], other_total: int) -> None:
    """A variant seen in only a few training lines has every token required, even those the main template proves optional (the NAT lines of
    the samples all carried a rule name, the unseen ones do not). Nodes aligned with an optional node of the main template become optional."""
    for i, j in _align(ref, other):
        if i is not None and j is not None and ref[i].support < ref_total and other[j].support >= other_total:
            other[j].support = max(1, other_total - 1)


def synthesize_regex(lines: list[str], max_lines: int = 400, max_templates: int = 6, max_new_runs: int = 4) -> Synth:
    """Fold many lines into a few anchored regexes with named groups (see module docstring)."""
    lines = [ln for ln in lines if ln.strip()]
    if not lines:
        raise ValueError("no sample lines")
    step = max(1, len(lines) // max_lines)
    sample = lines[::step][:max_lines]
    groups = _structure_groups(sample)
    n_groups = len(groups)
    pool: list[tuple[list[Node], int]] = groups[:40]
    dropped = sum(c for _, c in groups[40:])
    # progressive safe merging: allow more optional runs per merge only when nothing cheaper is left
    for tol in range(0, max_new_runs + 1):
        changed = True
        while changed and len(pool) > 1:
            changed = False
            best: tuple[int, int, int, list[Node]] | None = None
            for x in range(len(pool)):
                for y in range(x + 1, len(pool)):
                    (sa, ta), (sb, tb) = pool[x], pool[y]
                    if abs(len(sa) - len(sb)) > 12:
                        continue
                    merged, runs = _merge_skeletons(sa, ta, sb, tb)
                    if runs <= tol and (best is None or runs < best[0] or (runs == best[0] and ta + tb > best[1])):
                        best = (runs, ta + tb, x * 1000 + y, merged)
                        if runs == 0:
                            break
                if best is not None and best[0] == 0:
                    break
            if best is not None:
                x, y = divmod(best[2], 1000)
                pool = [p for k, p in enumerate(pool) if k not in (x, y)] + [(best[3], best[1])]
                pool.sort(key=lambda p: -p[1])
                changed = True
    pool.sort(key=lambda p: -p[1])
    kept = pool[:max_templates]
    dropped += sum(c for _, c in pool[max_templates:])
    total_main = kept[0][1]
    _name_nodes(kept[0][0], total_main)
    for sk, tot in kept[1:]:
        _name_nodes(sk, 10**9)
        _unify_names(kept[0][0], sk)
        _inherit_optionality(kept[0][0], total_main, sk, tot)
    regexes, fields, optional, anchors = [], [], [], []
    types: dict[str, str] = {}
    values: dict[str, list[str]] = {}
    for sk, total in kept:
        rx, f, o, an = _render(sk, total)
        regexes.append(rx)
        for nd in sk:
            if not nd.lit:
                types.setdefault(nd.name, nd.kind)
                values.setdefault(nd.name, []).extend(nd.values)
        for x in f:
            if x not in fields:
                fields.append(x)
        optional.extend(x for x in o if x not in optional)
        anchors.extend(an)
    n = sum(c for _, c in kept)
    return Synth(regexes[0], regexes, fields, optional, [x for x in anchors if len(x.strip()) >= 4], n, types, values, n_groups, len(regexes), dropped)


def rename_groups(regex: str, mapping: dict[str, str]) -> str:
    for old, new in mapping.items():
        regex = regex.replace(f"(?P<{old}>", f"(?P<{new}>")
    return regex


def apply_regex(regex: str, line: str) -> dict[str, Any] | None:
    m = re.compile(regex).match(line[:MAX_LINE])
    if not m:
        return None
    out = {k: v for k, v in m.groupdict().items() if v is not None and not (k == "_residual" and v == "")}
    return out
