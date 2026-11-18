"""Pattern mining: variable masking, Drain-style clustering and range comparison (synthetic lines only)."""

from __future__ import annotations

import random
import re
import time

import pytest

from loglens.core import patterns as patterns_mod
from loglens.core.patterns import (
    WILDCARD,
    Pattern,
    PatternMiner,
    compare,
    mask_variables,
    mine,
    template_regex,
    templates_match,
)


@pytest.mark.parametrize(
    ("line", "masked"),
    [
        ("2026-11-13 10:15:02,123 [12] INFO  Svc - took 12ms", "[<*>] INFO Svc - took <NUM>"),
        ("[2026-11-13 10:15:02] start", "start"),  # brackets that only wrapped the timestamp go too
        ("Jun 14 15:16:01 host sshd[19939]: session opened", "host sshd[<*>]: session opened"),
        (
            "id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 and {3F2504E0-4F89-11D3-9A0C-0305E82C3301}",
            "id <GUID> and <GUID>",
        ),
        (
            "addr 0x7ffe1234 hash 9f86d081884c7d65 word deadbeef id 12345678",
            "addr <HEX> hash <HEX> word deadbeef id <NUM>",
        ),
        ("from 10.0.0.1:8080 to 192.168.1.1.", "from <IP> to <IP>."),
        ("peer fe80::1%eth0 via [2001:db8::1]:443 and std::string", "peer <IP> via <IP> and std::string"),
        ("full 2001:0db8:85a3:0000:0000:8a2e:0370:7334 end", "full <IP> end"),
        ("mail bob.smith@example.com now", "mail <EMAIL> now"),
        ("GET https://example.com/a?b=1 done", "GET <URL> done"),
        (r"open C:\data\in\file.xml failed and \\server\share\f.txt", "open <PATH> failed and <PATH>"),
        (
            "read /var/log/app.log, ./a/b, ~/x/y; keep /health and and/or",
            "read <PATH>, <PATH>, <PATH>; keep /health and and/or",
        ),
        ("user \"John Smith\" said 'hi there' but don't stop", "user <STR> said <STR> but don't stop"),
        (
            "took 1.5s, 300 rows, -4 delta, 75%, 1,234,567 bytes, 1e-5",
            "took <NUM>, <NUM> rows, <NUM> delta, <NUM>, <NUM> bytes, <NUM>",
        ),
        (  # dates and times in the message, after the record's own timestamp
            "2026-11-13 10:00:00,000 at 10:15:02.5 on 2026-01-02 and 2026-01-02T03:04:05Z",
            "at <TS> on <TS> and <TS>",
        ),
        ('user=alice count=5 name="J S" a==b', "user=<*> count=<*> name=<*> a==b"),
        ("[req-abc] [INFO] [main] [pool-1-thread-3]", "[<*>] [INFO] [main] [<*>]"),
        ("log4net v2 user42 Win32", "log4net v2 user42 Win32"),  # identifiers with digits are words, not numbers
        ("GET /api/users/123?id=5&x=2 200", "GET <PATH>?id=<*>&x=<*> <NUM>"),
        ("plain   text\tline", "plain text line"),
        ("", ""),
    ],
)
def test_mask_variables(line: str, masked: str) -> None:
    assert mask_variables(line) == masked


def _fragment_corpus(count: int) -> list[str]:
    fragments = [
        "2026-11-13 10:00:00,001",
        "[7]",
        "INFO",
        "Svc -",
        "http://host/a/b?x=1",
        "a.b@example.org",
        "fe80::1",
        "[::1]:80",
        r"C:\temp\x.log",
        r"\\srv\share\y",
        "/var/lib/z",
        "./rel/path",
        '"quoted text"',
        "'single'",
        "key=value",
        "0xBEEF",
        "deadbeef0123",
        "10.1.2.3:443",
        "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        "12ms",
        "-5",
        "1,234.5",
        "word",
        "a:b:c:d:e:f:g:h",
        "x/y",
    ]
    rng = random.Random(7)
    return [" ".join(rng.choices(fragments, k=rng.randrange(1, 8))) for _ in range(count)]


def test_rare_pass_gates_do_not_change_masking(monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = _fragment_corpus(2_000)
    gated = [mask_variables(line) for line in corpus]
    ungated = tuple((lambda _text: True, regex, replacement) for _, regex, replacement in patterns_mod._RARE_MASKS)
    monkeypatch.setattr(patterns_mod, "_RARE_MASKS", ungated)
    assert [mask_variables(line) for line in corpus] == gated


def test_lines_differing_only_in_variables_share_a_template() -> None:
    lines = [
        f"2026-11-13 10:00:{i:02d},000 [{i % 7}] INFO Api - Request {1000 + i} from 10.0.0.{i} took {i}ms id={i:08x}"
        for i in range(50)
    ]
    patterns = mine(enumerate(lines))
    assert [p.template for p in patterns] == ["[<*>] INFO Api - Request <NUM> from <IP> took <NUM> id=<*>"]
    assert patterns[0].count == 50


def test_differing_word_becomes_wildcard() -> None:
    lines = [f"INFO Auth - user {name} logged in from the office" for name in ("alice", "bob", "carol")]
    patterns = mine(enumerate(lines))
    assert [p.template for p in patterns] == [f"INFO Auth - user {WILDCARD} logged in from the office"]


def test_distinct_messages_stay_distinct() -> None:
    lines = [
        "INFO Db - connection opened to primary",
        "INFO Db - connection closed by peer",  # same length and routing words, too few shared words
        "WARN Db - connection opened to primary",  # other level
        "INFO Db - disk almost full",  # other length
        "2026-11-13 10:00:00,000 [1] INFO Svc - cache warmed",
        "2026-11-13 10:00:01,000 [2] INFO Svc - queue drained",  # a shared header alone does not merge messages
    ]
    patterns = mine(enumerate(lines))
    assert len(patterns) == len(lines)
    assert all(WILDCARD not in p.template.split() for p in patterns)


def test_counts_first_last_sample_and_lines() -> None:
    miner = PatternMiner()
    ids = [miner.add(n, text) for n, text in [(10, "A started job 1"), (11, "B other"), (15, "A started job 2")]]
    ids.append(miner.add(12, "A started job 3"))
    assert ids[0] == ids[2] == ids[3] != ids[1]
    by_id = {p.id: p for p in miner.clusters()}
    job = by_id[ids[0]]
    assert (job.template, job.count, job.first_line, job.last_line) == ("A started job <NUM>", 3, 10, 15)
    assert job.sample == "A started job 1" and job.lines == (10, 15, 12) and job.lines_complete
    assert by_id[ids[1]].count == 1


def test_line_numbers_are_capped_but_counts_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(patterns_mod, "MAX_LINES_PER_PATTERN", 5)
    (pattern,) = mine((n, f"tick {n}") for n in range(20))
    assert pattern.count == 20 and pattern.lines == (0, 1, 2, 3, 4) and not pattern.lines_complete
    assert (pattern.first_line, pattern.last_line) == (0, 19)


def test_cluster_cap_falls_back_to_catch_all() -> None:
    miner = PatternMiner(max_clusters=3)
    for n in range(1, 11):  # ten token counts: ten templates without the cap
        miner.add(n, " ".join(["alpha"] * n))
    patterns = miner.clusters()
    assert len(patterns) == 4
    assert patterns[0].template == WILDCARD and patterns[0].count == 7
    assert sum(p.count for p in patterns) == 10


def test_mine_sorts_by_count_and_respects_max_lines() -> None:
    lines = ["B event"] * 2 + ["A event"] * 5
    assert [(p.template, p.count) for p in mine(enumerate(lines))] == [("A event", 5), ("B event", 2)]
    assert sum(p.count for p in mine(enumerate(lines), max_lines=3)) == 3


def test_long_and_empty_lines() -> None:
    patterns = mine(enumerate(["", "", "x " * 100_000]))
    assert sorted(p.count for p in patterns) == [1, 2]


def _synthetic_log(count: int, seed: int = 0) -> list[tuple[int, str]]:
    rng = random.Random(seed)
    users = ["alice", "bob", "carol", "dave"]
    makers = [
        lambda: (
            f"[{rng.randrange(1, 40)}] INFO Api - Request {rng.randrange(10**6)} completed in {rng.randrange(900)}ms"
        ),
        lambda: f"[{rng.randrange(1, 40)}] DEBUG Db - Opened connection to 10.0.{rng.randrange(255)}.7:1433",
        lambda: f"[{rng.randrange(1, 40)}] WARN Auth - User {rng.choice(users)} failed to log in twice",
        lambda: f"[{rng.randrange(1, 40)}] ERROR Io - Cannot open C:\\data\\f{rng.randrange(99)}.xml: access denied",
        lambda: (
            f"[{rng.randrange(1, 40)}] INFO Jobs - Job '{rng.choice(users)} export' finished, {rng.randrange(99)} rows"
        ),
        lambda: f"   at Service.Worker.Run(String job) in /src/app/Worker.cs:line {rng.randrange(500)}",
        lambda: f"[{rng.randrange(1, 40)}] INFO Http - GET https://api.example.com/items/{rng.randrange(10**4)} -> 200",
        lambda: (
            f"[{rng.randrange(1, 40)}] INFO Mail - Sent to {rng.choice(users)}@example.com id={rng.getrandbits(32):08x}"
        ),
    ]
    return [
        (n, f"2026-11-13 10:{n // 6000 % 60:02d}:{n // 100 % 60:02d},{n % 1000:03d} {rng.choice(makers)()}")
        for n in range(count)
    ]


def _random_word_log(count: int, seed: int = 0) -> list[tuple[int, str]]:
    """Many message kinds under one header, some words varying: exercises merging and big leaves."""
    rng = random.Random(seed)
    vocab = ["".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=rng.randrange(3, 8))) for _ in range(300)]
    kinds = []
    for _ in range(40):
        size = rng.randrange(2, 10)
        kinds.append((rng.sample(vocab, size), set(rng.sample(range(size), max(1, size // 3)))))
    lines = []
    for n in range(count):
        words, varying = rng.choice(kinds)
        body = " ".join(rng.choice(vocab) if i in varying else word for i, word in enumerate(words))
        lines.append((n, f"[{rng.randrange(9)}] {rng.choice(['INFO', 'WARN'])} Svc - {body}"))
    return lines


def _reference_mine(lines: list[tuple[int, str]]) -> list[tuple[str, int]]:
    """The miner's rules implemented plainly: every cluster of a leaf is scored, no index and no cache."""
    leaves: dict[tuple[int, tuple[str, ...]], list[list[str]]] = {}
    counts: dict[int, int] = {}  # id(template list) -> count
    templates: dict[int, list[str]] = {}
    for _, text in lines:
        tokens = mask_variables(text).split()
        words = [i for i, token in enumerate(tokens) if patterns_mod._WORD.fullmatch(token)]
        leaf = leaves.setdefault((len(tokens), tuple(tokens[i] for i in words[:2])), [])
        probe = words[2:]
        needed = -(-len(probe) // 2)  # half of the words, rounded up
        scored = [
            (sum(template[i] == tokens[i] for i in probe), template.count(WILDCARD), -k)
            for k, template in enumerate(leaf)
        ]
        best = max(scored, default=None)
        if best is not None and best[0] >= needed:
            template = leaf[-best[2]]
            template[:] = [mine if mine == theirs else WILDCARD for mine, theirs in zip(template, tokens, strict=True)]
        else:
            template = list(tokens)
            leaf.append(template)
            templates[id(template)] = template
        counts[id(template)] = counts.get(id(template), 0) + 1
    return sorted((" ".join(templates[key]), count) for key, count in counts.items())


def test_indexed_mining_matches_plain_drain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(patterns_mod, "MASK_CACHE_SIZE", 0)
    for lines in (_synthetic_log(3_000), _random_word_log(3_000)):
        assert sorted((p.template, p.count) for p in mine(lines)) == _reference_mine(lines)


def test_masked_text_cache_does_not_change_results(monkeypatch: pytest.MonkeyPatch) -> None:
    for lines in (_synthetic_log(5_000), _random_word_log(5_000)):
        cached = [(p.template, p.count, p.lines) for p in mine(lines)]
        monkeypatch.setattr(patterns_mod, "MASK_CACHE_SIZE", 0)
        assert [(p.template, p.count, p.lines) for p in mine(lines)] == cached
        monkeypatch.undo()


def test_mining_is_fast_enough() -> None:
    lines = _synthetic_log(100_000)
    started = time.perf_counter()
    patterns = mine(lines)
    elapsed = time.perf_counter() - started
    assert len(patterns) == 8 and sum(p.count for p in patterns) == 100_000
    assert elapsed < 20, f"mining 100k lines took {elapsed:.1f}s"  # ~1 s on a dev machine; generous for CI


def _match(a: str, b: str) -> bool:
    return templates_match(a.split(), b.split())


def test_templates_match() -> None:
    assert _match("User alice logged in", "User <*> logged in")
    assert not _match("Connection to <IP> failed", "Connection to <IP> established")
    assert not _match("a b c", "a b")
    assert not _match("Session <*> <*>", "Session alice bob")  # too few shared words


def _pattern(template: str, count: int, pattern_id: int = 0) -> Pattern:
    return Pattern(pattern_id, template, count, 0, 0, template, ())


def test_compare_new_gone_changed_with_rates() -> None:
    baseline = [
        _pattern("A started", 100),
        _pattern("B stopped", 10),
        _pattern("C went away", 5),
        _pattern("User alice logged in", 20),
        _pattern("Connection to <IP> established", 6),
    ]
    current = [
        _pattern("A started", 1000),  # ten times the lines, but a similar share
        _pattern("B stopped", 500),  # from ~7% to ~29% of the lines
        _pattern("D brand new", 4),
        _pattern("User <*> logged in", 200),  # same kind, generalized differently
        _pattern("Connection to <IP> failed", 3),  # conflicting words: a different kind
    ]
    diff = compare(baseline, current)
    assert (diff.baseline_total, diff.current_total) == (141, 1707)
    assert [p.template for p in diff.new] == ["D brand new", "Connection to <IP> failed"]
    assert [p.template for p in diff.gone] == ["Connection to <IP> established", "C went away"]
    (change,) = diff.changed
    assert change.template == "B stopped" and (change.baseline_count, change.current_count) == (10, 500)
    assert change.baseline_rate == pytest.approx(10 / 141) and change.current_rate == pytest.approx(500 / 1707)
    assert change.ratio == pytest.approx((500 / 1707) / (10 / 141))


def test_compare_ignores_small_counts_and_groups_similar_templates() -> None:
    baseline = [_pattern("rare event", 1), _pattern("User <*> logged in", 10, 1), _pattern("steady noise", 89, 2)]
    current = [
        _pattern("rare event", 3),  # three times its share, but too few lines to matter
        _pattern("User alice logged in", 10, 1),
        _pattern("User bob logged in", 30, 2),
        _pattern("steady noise", 60, 3),
    ]
    diff = compare(baseline, current)
    assert not diff.new and not diff.gone
    (change,) = diff.changed  # alice and bob together are the baseline's "User <*> logged in": 10% -> 39%
    assert (change.baseline_count, change.current_count) == (10, 40)
    assert change.baseline.template == "User <*> logged in" and change.current.template == "User bob logged in"


def test_compare_matches_brute_force() -> None:
    rng = random.Random(3)
    vocab = ["a", "b", "c", "d", WILDCARD]

    def random_patterns(count: int, first_id: int) -> list[Pattern]:
        return [
            _pattern(" ".join(rng.choices(vocab, k=rng.randrange(1, 6))), rng.randrange(1, 50), first_id + i)
            for i in range(count)
        ]

    for _ in range(20):
        baseline, current = random_patterns(60, 0), random_patterns(60, 1000)

        def unmatched(side: list[Pattern], other: list[Pattern]) -> set[int]:
            return {
                p.id
                for p in side
                if not any(
                    o.template == p.template or templates_match(o.template.split(), p.template.split()) for o in other
                )
            }

        diff = compare(baseline, current)
        assert {p.id for p in diff.new} == unmatched(current, baseline)
        assert {p.id for p in diff.gone} == unmatched(baseline, current)


def test_compare_empty_sides() -> None:
    patterns = [_pattern("A started", 4)]
    assert compare([], patterns).new == tuple(patterns)
    assert compare(patterns, []).gone == tuple(patterns)
    assert compare([], []) == compare([], [])


def test_template_regex_finds_the_pattern_lines() -> None:
    lines = [
        f"2026-11-13 10:00:{i:02d} INFO Cache - evicted {i * 7} entries from [shard-{i}] in {i}ms" for i in range(9)
    ]
    pattern = mine(enumerate(lines))[0]
    regex = template_regex(pattern.template)
    assert regex is not None and all(re.search(regex, line, re.IGNORECASE) for line in lines)
    assert not re.search(regex, "2026-11-13 10:00:00 INFO Cache - warmed 5 entries", re.IGNORECASE)
    assert template_regex("<*> <NUM>") is None
