"""Log pattern mining: typed masking of variable parts, Drain-style template clustering and range comparison.

Feeds the Patterns panel ("which kinds of messages does this range contain, how often?"), *new since baseline* and
*compare two ranges/files*:

1. :func:`mask_variables` removes the record timestamp and replaces variable parts (ids, numbers, addresses, paths,
   quoted strings, key=value values, bracketed thread ids) with typed placeholders, so lines of one kind become
   nearly identical.
2. :class:`PatternMiner` clusters the masked lines with the Drain algorithm (He et al., ICWS 2017): a fixed-depth prefix
   tree routes a line by its token count and leading words to a few candidate clusters; the line joins the most
   similar one when enough of its words agree, and template positions that differ become :data:`WILDCARD`.
3. :func:`compare` matches the templates of two ranges and reports the new, gone and noticeably more/less frequent ones,
   using per-total rates so ranges of different sizes compare fairly.

Everything is bounded (tree fan-out, clusters, line numbers per cluster, masking cache, characters per line) and the
per-line work is a few C-level regex/str calls, so callers feed a bounded sample of lines (:data:`DEFAULT_MAX_LINES`).
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from itertools import chain, islice

from .timestamps import find_timestamp

WILDCARD = "<*>"  # a template position whose tokens differ between the lines of a cluster

# ---- clustering --------------------------------------------------------------------------------------------------
SIM_THRESHOLD = 0.5  # Drain's default: a line joins a cluster when at least half of its words match the template
TREE_DEPTH = 2  # leading words that route a line (Drain's "depth 4" = root + token-count level + 2 token levels)
MAX_CHILDREN = 100  # distinct words per tree node; further ones share the wildcard child so the tree stays bounded
MAX_LEAF_CLUSTERS = 300  # bounds the clusters one line is scored against; a full leaf merges into its most similar one
MAX_CLUSTERS = 5_000  # templates per miner; beyond it lines join their most similar cluster or one catch-all "<*>"
MAX_LINES_PER_PATTERN = 10_000  # line numbers kept per pattern for "show these lines"; the count itself stays exact
MASK_CACHE_SIZE = 50_000  # distinct masked lines remembered (a few MB) so repeated messages skip the tree walk
MAX_LINE_CHARS = 1_000  # longer lines are clustered by their beginning: payload dumps would otherwise dominate the time
DEFAULT_MAX_LINES = 250_000  # lines :func:`mine` reads at most (a few seconds); callers sample bigger ranges

# ---- comparison --------------------------------------------------------------------------------------------------
CHANGE_RATIO = 2.0  # a pattern "changed" when its share of all lines grew or shrank by at least this factor
MIN_CHANGE_COUNT = 5  # ... and it occurs this often in at least one range, so 1 -> 2 occurrences is not reported

# ---- masking -----------------------------------------------------------------------------------------------------
# Masking is most of the mining time, and Python's regex engine tries every alternative at every position. So it runs
# in three passes: (1) rare constructs, each only when a marker substring occurs in the line; (2) constructs starting
# with punctuation, whose alternatives all start with a literal, so the engine jumps between those characters; (3)
# constructs starting with a hex digit at a word start, behind one leading character class. Conditions that would
# normally precede a match (word boundaries) are lookbehinds placed after that first character for the same reason.
_HEX = "[0-9A-Fa-f]"
_H4 = f"{_HEX}{{1,4}}"
_IPV6 = (
    rf"(?:{_H4}(?::{_H4}){{7}}"  # full form
    rf"|{_H4}(?::{_H4}){{0,6}}::(?:{_H4}(?::{_H4}){{0,6}})?"  # compressed, e.g. fe80::1
    rf"|::{_H4}(?::{_H4}){{0,6}})"  # leading "::", e.g. ::1
)
_PATH_SEGMENT = r"[\w.@%+~-]+"
_DQ_STRING = r'"(?:[^"\\\n]|\\.)*"'
_SQ_STRING = r"'(?:[^'\\\n]|\\.)*'"

# Rare constructs: (gate, regex, replacement), applied in this order. A gate is a substring test that is true for every
# line the regex can match in, so skipping the pass when it is false never changes the result.
_RARE_MASKS: tuple[tuple[Callable[[str], bool], re.Pattern[str], str], ...] = (
    (
        lambda text: "://" in text,
        re.compile(r"[A-Za-z](?<!\w[A-Za-z])[A-Za-z0-9+.-]*://[^\s\"'<>]+"),
        "<URL>",
    ),
    (
        lambda text: "@" in text,
        re.compile(r"[\w.+-](?<![\w.+-]{2})[\w.+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?!\w)"),
        "<EMAIL>",
    ),
    (  # bracketed with an optional port ([::1]:443) or bare; a compressed form has "::", the full form 7 colons
        lambda text: "::" in text or text.count(":") >= 7,
        re.compile(rf"\[{_IPV6}(?:%\w+)?\](?::\d{{1,5}})?|(?<![\w:.]){_IPV6}(?:%\w+)?(?![\w:])"),
        "<IP>",
    ),
    (  # drive (C:\x, C:/x) or UNC (\\server\share) paths; they end at whitespace, so quote paths that contain spaces
        lambda text: ":\\" in text or ":/" in text or "\\\\" in text,
        re.compile(r"(?:[A-Za-z](?<!\w[A-Za-z]):[\\/]|\\\\[\w.$-]+\\)[^\s\"'<>|?*]*"),
        "<PATH>",
    ),
    (  # absolute paths need two segments so "/health" and "and/or" stay readable; ./x, ../x and ~/x need one
        lambda text: "/" in text,
        re.compile(
            rf"/(?<![\w:/.~]/){_PATH_SEGMENT}(?:/{_PATH_SEGMENT})+/?"
            rf"|[.~](?<![\w:/.~][.~])\.?(?:/{_PATH_SEGMENT})+/?"
        ),
        "<PATH>",
    ),
)

_NUMBER_TAIL = r"\d*(?:[.,]\d+)*(?:[eE][-+]?\d+)?(?:[A-Za-z]{1,4}|%)?(?!\w)"  # 1,234.5 / 1e-3 / 12ms / 64KB / 75%

# Constructs that start with punctuation: (name, first character as a literal, rest, replacement). Every alternative
# starts with a literal, so the engine jumps straight to the few positions holding one of these characters.
_PUNCT_MASKS: tuple[tuple[str, str, str, str], ...] = (
    # quoted strings; a single quote only opens outside words, so apostrophes ("don't") are left alone
    ("dq", '"', r'(?:[^"\\\n]|\\.)*"', "<STR>"),
    ("sq", "'", r"(?<![\w']')(?:[^'\\\n]|\\.)*'(?![\w'])", "<STR>"),
    # the value of key=value (the key stays); "==" is a comparison, not an assignment
    ("kv", "=", rf"(?<=[\w\]]=)(?!=)(?:{_DQ_STRING}|{_SQ_STRING}|[^\s,;&)\]}}\"']+)", f"={WILDCARD}"),
    ("guid_braced", r"\{", rf"{_HEX}{{8}}-(?:{_HEX}{{4}}-){{3}}{_HEX}{{12}}\}}", "<GUID>"),
    # bracketed thread / request ids such as [12], [req-abc], [pool-1-thread-3]; [INFO] or [main] stay as they are
    ("tid", r"\[", r"[^\s\[\]]*[\d-][^\s\[\]]*\]", f"[{WILDCARD}]"),
    ("minus", "-", rf"(?<![\w.]-)\d{_NUMBER_TAIL}", "<NUM>"),
    ("plus", r"\+", rf"(?<![\w.]\+)\d{_NUMBER_TAIL}", "<NUM>"),
)
# Constructs that start with a hex digit at the start of a word: (name, condition on that first character, rest,
# replacement), in priority order - at one position the first alternative that matches wins.
_DIGIT_START = r"(?<=\d)(?<!\.\d)"  # a decimal digit not preceded by "." (so "v1.2" keeps its ".2")
_WORD_MASKS: tuple[tuple[str, str, str, str], ...] = (
    # dates and times inside the message (the record's own timestamp is removed before masking)
    (
        "ts",
        _DIGIT_START,
        r"(?:\d{3}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?"
        r"|\d?:\d{2}:\d{2}(?:[.,]\d+)?)(?!\w)",
        "<TS>",
    ),
    ("guid", "", rf"{_HEX}{{7}}-(?:{_HEX}{{4}}-){{3}}{_HEX}{{12}}(?!\w)", "<GUID>"),
    ("ip4", _DIGIT_START, r"\d{0,2}\.(?:\d{1,3}\.){2}\d{1,3}(?::\d{1,5})?(?!\w|\.\d)", "<IP>"),
    ("hex0x", "(?<=0)", rf"[xX]{_HEX}+(?!\w)", "<HEX>"),
    # hex runs of 8+ that mix letters and digits (hashes, handles); pure digit runs are numbers
    ("hex", f"(?={_HEX}{{7}})", rf"(?:(?<=[A-Fa-f]){_HEX}*?\d|(?<=\d)\d*[A-Fa-f]){_HEX}*(?!\w)", "<HEX>"),
    ("num", _DIGIT_START, _NUMBER_TAIL, "<NUM>"),
)
# The empty named group in each alternative tells _replace which one matched; it comes after the first character
# and the conditions, so a rejected alternative costs one or two character tests.
_PUNCT_RE = re.compile("|".join(f"{first}(?P<{name}>){rest}" for name, first, rest, _ in _PUNCT_MASKS))
# one leading character class: the engine skips everything but hex digits, then checks for a word start
_WORD_RE = re.compile(
    rf"{_HEX}(?<!\w{_HEX})(?:" + "|".join(f"{cond}(?P<{name}>){rest}" for name, cond, rest, _ in _WORD_MASKS) + ")"
)
_REPLACEMENTS = {name: replacement for name, *_, replacement in (*_PUNCT_MASKS, *_WORD_MASKS)}
_CLOSERS = {"[": "]", "(": ")", "{": "}", "<": ">"}  # brackets that may wrap a record timestamp
_WORD = re.compile(r"(?:[^\w<]|_)*[^\W\d_][^\d<]*")  # a token with a letter, no digit and no placeholder


def _replace(match: re.Match[str]) -> str:
    kind = match.lastgroup
    return _REPLACEMENTS[kind] if kind is not None else match.group()


def _strip_timestamp(text: str) -> str:
    """``text`` without its record timestamp (and the brackets that only wrapped it)."""
    found = find_timestamp(text)
    if found is None:
        return text
    head = text[: found.start].rstrip()
    tail = text[found.end :].lstrip()
    if head and tail and _CLOSERS.get(head[-1]) == tail[0]:
        head, tail = head[:-1].rstrip(), tail[1:].lstrip()
    return f"{head} {tail}" if head else tail


def _mask(text: str) -> str:
    """``text`` without its record timestamp, then masked by the three passes described above."""
    text = _strip_timestamp(text)
    for gate, regex, replacement in _RARE_MASKS:
        if gate(text):
            text = regex.sub(replacement, text)
    return _WORD_RE.sub(_replace, _PUNCT_RE.sub(_replace, text))


def mask_variables(text: str) -> str:
    """``text`` without its record timestamp, variable parts replaced by typed placeholders, whitespace collapsed.

    Placeholders: ``<STR>`` ``<URL>`` ``<EMAIL>`` ``<TS>`` ``<GUID>`` ``<IP>`` ``<PATH>`` ``<HEX>`` ``<NUM>``; values
    of ``key=value`` become ``key=<*>`` and bracketed ids ``[<*>]``.
    """
    return " ".join(_mask(text).split())


def _min_shared(token_count: int, threshold: float) -> int:
    """Tokens that must agree for ``threshold`` similarity (guarded against float error, e.g. 0.7 * 10)."""
    return math.ceil(token_count * threshold - 1e-9)


# ---- mining ------------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Pattern:
    """One template and the lines it covers."""

    id: int
    template: str  # masked tokens joined by single spaces; WILDCARD where the lines differ
    count: int
    first_line: int
    last_line: int
    sample: str  # the first raw line that created the pattern
    lines: tuple[int, ...]  # line numbers in arrival order, at most MAX_LINES_PER_PATTERN of them

    @property
    def lines_complete(self) -> bool:
        """False when more lines matched than :attr:`lines` keeps."""
        return len(self.lines) == self.count


@dataclass(slots=True)
class _Cluster:
    """Mutable mining state of one pattern."""

    tokens: list[str]
    params: int = 0  # template tokens that are WILDCARD
    count: int = 0
    first_line: int = 0
    last_line: int = 0
    sample: str = ""
    lines: list[int] = field(default_factory=list)


@dataclass(slots=True)
class _Node:
    """Prefix-tree node: children by routing word; the node reached after the routing words holds clusters."""

    children: dict[str, _Node] = field(default_factory=dict)
    clusters: list[int] = field(default_factory=list)
    # (position, word) -> clusters whose template has that word there: a line is compared only with the clusters
    # sharing a word with it, which keeps big leaves (one logger, many messages) cheap
    postings: dict[tuple[int, str], list[int]] = field(default_factory=dict)


class PatternMiner:
    """Incremental Drain clustering of log lines into templates.

    A cache maps masked texts seen before (up to :data:`MASK_CACHE_SIZE` of them) to their cluster, so repeated
    messages skip the tree. At most ``max_clusters`` templates are created; after that, lines join their most similar
    cluster or a single catch-all ``<*>`` pattern.
    """

    def __init__(self, *, sim_threshold: float = SIM_THRESHOLD, max_clusters: int = MAX_CLUSTERS) -> None:
        self._sim_threshold = sim_threshold
        self._max_clusters = max_clusters
        self._by_length: dict[int, _Node] = {}
        self._clusters: list[_Cluster] = []
        self._by_text: dict[str, int] = {}  # masked line -> cluster id
        self._catch_all: int | None = None

    def __len__(self) -> int:
        return len(self._clusters)

    def add(self, line_number: int, text: str) -> int:
        """Cluster one line; returns its cluster id (the :attr:`Pattern.id`)."""
        masked = _mask(text[:MAX_LINE_CHARS])
        cluster_id = self._by_text.get(masked)
        if cluster_id is None:
            cluster_id = self._place(masked.split())
            if len(self._by_text) < MASK_CACHE_SIZE:
                self._by_text[masked] = cluster_id
        cluster = self._clusters[cluster_id]
        if cluster.count == 0:
            cluster.first_line = cluster.last_line = line_number
            cluster.sample = text
        elif line_number < cluster.first_line:
            cluster.first_line = line_number
        elif line_number > cluster.last_line:
            cluster.last_line = line_number
        cluster.count += 1
        if len(cluster.lines) < MAX_LINES_PER_PATTERN:
            cluster.lines.append(line_number)
        return cluster_id

    def clusters(self) -> list[Pattern]:
        """All patterns, most frequent first."""
        patterns = [
            Pattern(
                id=cluster_id,
                template=" ".join(cluster.tokens),
                count=cluster.count,
                first_line=cluster.first_line,
                last_line=cluster.last_line,
                sample=cluster.sample,
                lines=tuple(cluster.lines),
            )
            for cluster_id, cluster in enumerate(self._clusters)
            if cluster.count
        ]
        patterns.sort(key=lambda p: (-p.count, p.first_line))
        return patterns

    def _place(self, tokens: list[str]) -> int:
        """Id of the cluster ``tokens`` joins (generalizing its template) or of a newly created one.

        Drain routes a line by its first tokens; here the first *words*, so "[<*>] INFO Db - ..." routes by
        "INFO Db" rather than by a "[<*>]" that every line has. Tokens with digits do not route (likely variables).
        """
        positions = [i for i, token in enumerate(tokens) if token.isalpha() or _WORD.fullmatch(token)]
        leaf = self._leaf(len(tokens), [tokens[i] for i in positions[:TREE_DEPTH]])
        # Similarity counts the other words only: placeholders and punctuation ("[<*>]", "-") are alike in most lines
        # and the routing words in all lines of a leaf, so counting them would merge any two short messages.
        probe = [(i, tokens[i]) for i in positions[TREE_DEPTH:]]
        postings = leaf.postings
        # cluster id -> words at the same position as in the template
        same = Counter(chain.from_iterable(postings.get(key, ()) for key in probe))
        needed = _min_shared(len(probe), self._sim_threshold)
        room = len(self._clusters) < self._max_clusters and len(leaf.clusters) < MAX_LEAF_CLUSTERS
        # Drain: the most similar cluster wins, on a tie the more general template (then the older one)
        candidates: Iterable[int] = same if needed and room else leaf.clusters
        best = max(candidates, key=lambda c: (same[c], self._clusters[c].params, -c), default=None)
        if best is not None and (same[best] >= needed or not room):
            self._generalize(leaf, best, tokens)
            return best
        if not room:
            return self._catch_all_id()
        cluster_id = len(self._clusters)
        self._clusters.append(_Cluster(tokens=tokens))
        leaf.clusters.append(cluster_id)
        for key in probe:
            leaf.postings.setdefault(key, []).append(cluster_id)
        return cluster_id

    def _leaf(self, token_count: int, routing: list[str]) -> _Node:
        """The tree node for lines of ``token_count`` tokens whose first words are ``routing``."""
        node = self._by_length.get(token_count)
        if node is None:
            node = self._by_length[token_count] = _Node()
        for token in routing:
            child = node.children.get(token)
            if child is None:
                key = token if len(node.children) < MAX_CHILDREN else WILDCARD
                child = node.children.get(key)
                if child is None:
                    child = node.children[key] = _Node()
            node = child
        return node

    def _generalize(self, leaf: _Node, cluster_id: int, tokens: list[str]) -> None:
        """Turn the template positions where ``tokens`` differ into WILDCARD."""
        cluster = self._clusters[cluster_id]
        merged = [mine if mine == theirs else WILDCARD for mine, theirs in zip(cluster.tokens, tokens, strict=True)]
        if merged == cluster.tokens:  # the usual case: the line differs only where the template has wildcards
            return
        for position, (old, new) in enumerate(zip(cluster.tokens, merged, strict=True)):
            posting = leaf.postings.get((position, old)) if old != new else None
            if posting is not None and cluster_id in posting:
                posting.remove(cluster_id)
        cluster.tokens = merged
        cluster.params = merged.count(WILDCARD)

    def _catch_all_id(self) -> int:
        if self._catch_all is None:
            self._catch_all = len(self._clusters)
            self._clusters.append(_Cluster(tokens=[WILDCARD], params=1))
        return self._catch_all


def mine(lines: Iterable[tuple[int, str]], *, max_lines: int = DEFAULT_MAX_LINES) -> list[Pattern]:
    """Patterns of the first ``max_lines`` (line number, text) pairs, most frequent first."""
    miner = PatternMiner()
    for line_number, text in islice(lines, max_lines):
        miner.add(line_number, text)
    return miner.clusters()


# ---- comparison --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class PatternChange:
    """A pattern present in both ranges whose share of lines changed noticeably."""

    baseline: Pattern  # the most frequent matching baseline pattern
    current: Pattern  # the most frequent matching current pattern
    baseline_count: int  # all baseline patterns matched with the current ones (usually just ``baseline.count``)
    current_count: int
    baseline_rate: float  # baseline_count / all baseline lines
    current_rate: float

    @property
    def template(self) -> str:
        return self.current.template

    @property
    def ratio(self) -> float:
        """current_rate / baseline_rate: above 1 the pattern became more frequent."""
        return self.current_rate / self.baseline_rate if self.baseline_rate else math.inf


@dataclass(frozen=True, slots=True)
class PatternDiff:
    """How the patterns of a current range differ from a baseline range."""

    new: tuple[Pattern, ...]  # current patterns without a baseline counterpart, most frequent first
    gone: tuple[Pattern, ...]  # baseline patterns without a current counterpart, most frequent first
    changed: tuple[PatternChange, ...]  # biggest rate change first
    baseline_total: int  # lines covered by the baseline patterns
    current_total: int


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        parent = self._parent
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_b] = root_a


def templates_match(a: Sequence[str], b: Sequence[str], *, threshold: float = SIM_THRESHOLD) -> bool:
    """Whether two template token lists describe the same kind of line.

    They must have the same length, may differ only where one side has :data:`WILDCARD` (e.g. ``User alice logged in``
    vs ``User <*> logged in``), and must share enough constant tokens for Drain similarity ``threshold``.
    """
    if len(a) != len(b):
        return False
    shared = 0
    for x, y in zip(a, b, strict=True):
        if x == y:
            shared += x != WILDCARD
        elif WILDCARD not in (x, y):
            return False
    return shared >= _min_shared(len(a), threshold)


def _anchor_positions(token_count: int) -> range:
    """Positions among which two matching templates must share a constant token.

    Sharing at least ``k`` of ``n`` positions means sharing one of the first ``n - k + 1`` (pigeonhole).
    """
    return range(token_count - _min_shared(token_count, SIM_THRESHOLD) + 1 if token_count else 0)


def _group_kinds(templates: list[str], split: int) -> list[list[int]]:
    """Indices of ``templates`` grouped by kind of line; ``templates[:split]`` is one side, the rest the other.

    Equal templates are one kind. A template without an equal one on the other side also joins every template there
    that :func:`templates_match` it; candidates come from an index of (side, length, position, constant token) over
    the :func:`_anchor_positions`, so only templates sharing an anchor token are compared.
    """
    links = _UnionFind(len(templates))
    first_with: dict[str, int] = {}
    for item, template in enumerate(templates):
        links.union(first_with.setdefault(template, item), item)

    sides = (set(templates[:split]), set(templates[split:]))
    tokens = [template.split() for template in templates]
    index: dict[tuple[bool, int, int, str], list[int]] = defaultdict(list)
    for item, toks in enumerate(tokens):
        for position in _anchor_positions(len(toks)):
            if toks[position] != WILDCARD:
                index[item >= split, len(toks), position, toks[position]].append(item)
    for item, toks in enumerate(tokens):
        other_side = item < split
        if templates[item] in sides[other_side]:
            continue
        seen: set[int] = set()
        for position in _anchor_positions(len(toks)):
            for other in index.get((other_side, len(toks), position, toks[position]), ()):
                if other not in seen:
                    seen.add(other)
                    if templates_match(toks, tokens[other]):
                        links.union(item, other)

    groups: dict[int, list[int]] = defaultdict(list)
    for item in range(len(templates)):
        groups[links.find(item)].append(item)
    return list(groups.values())


def _change(base: list[Pattern], cur: list[Pattern], totals: tuple[int, int]) -> PatternChange:
    baseline_count = sum(p.count for p in base)
    current_count = sum(p.count for p in cur)
    return PatternChange(
        baseline=max(base, key=lambda p: p.count),
        current=max(cur, key=lambda p: p.count),
        baseline_count=baseline_count,
        current_count=current_count,
        baseline_rate=baseline_count / max(totals[0], 1),
        current_rate=current_count / max(totals[1], 1),
    )


def _spread(ratio: float) -> float:
    """How far ``ratio`` is from 1 in either direction (2.0 for both doubling and halving)."""
    if ratio <= 0 or math.isinf(ratio):
        return math.inf
    return max(ratio, 1 / ratio)


def compare(
    baseline: Sequence[Pattern],
    current: Sequence[Pattern],
    *,
    change_ratio: float = CHANGE_RATIO,
    min_count: int = MIN_CHANGE_COUNT,
) -> PatternDiff:
    """Match the patterns of two ranges (equal templates, or templates that :func:`templates_match`) and diff them.

    Counts are compared as shares of each side's total lines, so a 10-minute range compares fairly with a day.
    """
    patterns = [*baseline, *current]
    split = len(baseline)
    totals = (sum(p.count for p in baseline), sum(p.count for p in current))
    new: list[Pattern] = []
    gone: list[Pattern] = []
    changed: list[PatternChange] = []
    for members in _group_kinds([p.template for p in patterns], split):
        base = [patterns[i] for i in members if i < split]
        cur = [patterns[i] for i in members if i >= split]
        if not base:
            new.extend(cur)
        elif not cur:
            gone.extend(base)
        else:
            change = _change(base, cur, totals)
            if max(change.baseline_count, change.current_count) >= min_count and _spread(change.ratio) >= change_ratio:
                changed.append(change)

    def by_count(p: Pattern) -> tuple[int, int]:
        return -p.count, p.first_line

    return PatternDiff(
        new=tuple(sorted(new, key=by_count)),
        gone=tuple(sorted(gone, key=by_count)),
        changed=tuple(sorted(changed, key=lambda c: (-_spread(c.ratio), -c.current_count))),
        baseline_total=totals[0],
        current_total=totals[1],
    )


# ---- finding a pattern's lines -----------------------------------------------------------------------------------
_PLACEHOLDER = re.compile(r"<(?:\*|[A-Z]+)>")
MIN_TEMPLATE_LITERAL_CHARS = 4  # a regex with less fixed text than this would match nearly every line


def template_regex(template: str) -> str | None:
    """A search regex for the lines of a pattern: literal text kept, placeholders become lazy wildcards.

    Returns None when the template has too little fixed text to be a useful filter.
    """
    literals = [part.strip() for part in _PLACEHOLDER.split(template)]
    if sum(len(part) for part in literals) < MIN_TEMPLATE_LITERAL_CHARS:
        return None
    pieces = [r"\s+".join(re.escape(word) for word in part.split()) for part in literals if part]
    return ".*?".join(pieces)
