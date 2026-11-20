"""Personal-data scan: real values are found, look-alikes are not, examples are masked."""

from __future__ import annotations

from loglens.core.pii import iban_ok, luhn_ok, mask_value, render, scan

TOKEN = "Zx9" + "Kq7Lm2Np4Rs6Tu8Vw0Yb1Cd3Ef5Gh"


def run(*lines: str):
    return scan(enumerate(lines))


def test_luhn_and_iban_checks() -> None:
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert iban_ok("GB82 WEST 1234 5698 7654 32") and not iban_ok("GB82 WEST 1234 5698 7654 33")


def test_cards_need_a_valid_checksum_and_timestamps_are_not_cards() -> None:
    found = run("paid with 4111 1111 1111 1111 ok", "order 1234567890123456 failed", "2026-11-13 10:00:00 12345")
    assert found["card"].count == 1 and found["card"].examples == ["****1111"]


def test_email_phone_ssn_ip_iban_and_secret() -> None:
    found = run(
        "user alice@example.com called +49 170 123 4567",
        "ssn 123-45-6789 from 10.20.30.40 and 127.0.0.1",
        "iban GB82 WEST 1234 5698 7654 32",
        f"client_secret={TOKEN}",
    )
    assert set(found) >= {"email", "phone", "ssn", "ip", "iban", "secret"}
    assert (
        found["email"].examples == ["a***@example.com"]
        and found["ip"].count == 1
        and found["ip"].examples == ["10.20.x.x"]
    )
    assert found["ip"].first_line == 1 and found["secret"].first_line == 3


def test_ordinary_log_lines_have_no_findings() -> None:
    assert run("2026-11-13 10:00:00,123 [7] INFO build 1.2.3 took 120 ms", "request 5000 of 12000 done", "") == {}


def test_report_is_masked_and_counts_distinct_values() -> None:
    found = run("a@x.org", "a@x.org", "b@x.org")
    assert found["email"].count == 3 and len(found["email"].distinct) == 2 and found["email"].lines == 3
    text = render(found)
    assert "a***@x.org" in text and "b@x.org" not in text and "| E-mail address | 3 | 2 |" in text
    assert "No e-mail" in render({}) and mask_value("secret", "x") == "***"


def test_ids_and_urls_from_real_logs_are_not_cards_or_phones() -> None:
    avatar = 'x"image_original":"https://avatars.slack-edge.com/2023-12-27/6394681733813_03f67185fa_original.png"'
    guid = '"name":"dd78c0cf-3016-4155-8169-bf1090265fbd.png","created":1793657612,"id":"F0CE4FV0STX"'
    assert run(avatar, guid) == {}


def test_card_numbers_need_a_known_brand_and_a_clean_boundary() -> None:
    assert "card" in run("card 4111 1111 1111 1111 charged")
    assert "card" in run("amex 378282246310005 ok")
    assert run("id=6394681733813 done") == {}  # passes Luhn but no brand starts like that
    assert run("file/4111111111111111/x") == {}
