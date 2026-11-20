"""Share-safe copy: consistent pseudonyms for people and machines, secrets masked, the story kept intact."""

from __future__ import annotations

from loglens.core.pseudonyms import Pseudonymizer


def p(**kw) -> Pseudonymizer:
    return Pseudonymizer(**kw)


def test_same_value_same_pseudonym_everywhere() -> None:
    z = p()
    a = z.line("login failed for alice@corp.com from 10.20.30.40")
    b = z.line("alice@corp.com retried from 10.20.30.40, then bob@corp.com from 10.20.30.41")
    assert "alice" not in a + b and "10.20.30" not in a + b and "bob@" not in b
    assert "person1@example.invalid" in a and "person1@example.invalid" in b and "person2@example.invalid" in b
    assert "192.0.2.1" in a and "192.0.2.1" in b and "192.0.2.2" in b


def test_case_insensitive_identity() -> None:
    z = p()
    assert z.line("Alice@Corp.com") == z.line("alice@corp.com")


def test_hosts_users_and_unc_paths() -> None:
    z = p()
    out = z.line(r"2026-11-13 10:00:00 INFO user=jsmith connected to db01.internal.corp.com via \\fileserver\share")
    assert "jsmith" not in out and "db01.internal" not in out and "fileserver" not in out
    assert "user=user1" in out and "host2.example.invalid" in out and "\\\\host1\\share" in out


def test_domain_user_and_for_user() -> None:
    z = p()
    out = z.line(r"CORP\jsmith logged on; password check failed for user jsmith")
    assert "jsmith" not in out and "CORP" not in out
    assert out.count("user1") == 2  # the same person, both spellings


def test_well_known_values_are_kept() -> None:
    z = p()
    out = z.line("user=SYSTEM from 127.0.0.1 on localhost, machine DESKTOP$ user=anonymous")
    assert "SYSTEM" in out and "127.0.0.1" in out and "localhost" in out and "anonymous" in out


def test_file_names_and_class_names_are_not_hosts() -> None:
    z = p()
    line = "at Shop.Orders.Service.Run() in C:\\src\\Service.cs:line 10 and app.config, loader.dll"
    assert z.line(line) == line


def test_secrets_are_masked_too_and_can_be_switched_off() -> None:
    token = "Zx9Kq7Lm2Np4Rs6Tu8Vw0Yb1Cd3Ef5Gh"
    assert token not in p().line(f"client_secret={token} user=bob")
    assert token in p(secrets=False).line(f"client_secret={token}")


def test_only_the_chosen_kinds_are_replaced() -> None:
    z = p(kinds=frozenset({"ip"}), secrets=False)
    out = z.line("alice@corp.com from 10.0.0.9 on db.corp.com")
    assert "alice@corp.com" in out and "db.corp.com" in out and "10.0.0.9" not in out


def test_ipv6_and_the_mapping_table() -> None:
    z = p()
    out = z.line("peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 and 10.1.1.1 alice@x.org")
    assert "8a2e" not in out
    kinds = {kind for kind, _o, _p in z.table()}
    assert kinds == {"ip", "email"} and z.counts() == {"email": 1, "ip": 2}


def test_version_numbers_and_times_are_left_alone() -> None:
    z = p()
    line = "2026-11-13 10:00:01,200 [7] INFO build 1.2.3 took 12.5 ms ratio 0.75"
    assert z.line(line) == line
