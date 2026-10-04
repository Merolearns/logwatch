"""Tests for the combined-log parser."""

import os

from parser import parse_file, parse_line

SAMPLE = os.path.join(os.path.dirname(__file__), "access.log.sample")

GOOD_LINE = (
    '203.0.113.21 - - [03/Oct/2026:13:02:11 +0000] "GET /about HTTP/1.1" '
    '200 6210 "http://example.com/" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"'
)


def test_parse_valid_line():
    e = parse_line(GOOD_LINE)
    assert e["ip"] == "203.0.113.21"
    assert e["user"] == "-"
    assert e["method"] == "GET"
    assert e["path"] == "/about"
    assert e["protocol"] == "HTTP/1.1"
    assert e["status"] == 200
    assert e["size"] == 6210
    assert e["referer"] == "http://example.com/"
    assert "Chrome/126.0.0.0" in e["agent"]
    assert (e["time"].year, e["time"].month, e["time"].day) == (2026, 10, 3)
    assert e["time"].hour == 13


def test_parse_dash_size_becomes_zero():
    e = parse_line(
        '203.0.113.21 - - [03/Oct/2026:13:02:11 +0000] "HEAD / HTTP/1.1" '
        '200 - "-" "curl/8.5.0"'
    )
    assert e["size"] == 0


def test_malformed_lines_return_none():
    assert parse_line("this is not a log line at all") is None
    assert parse_line("") is None
    assert parse_line("203.0.113.21 - - [garbage] \"GET / HTTP/1.1\" 200 12") is None


def test_bad_timestamp_is_malformed():
    line = GOOD_LINE.replace("03/Oct/2026:13:02:11 +0000", "not-a-date")
    assert parse_line(line) is None


def test_sample_log_parses_with_skip_count():
    entries, skipped = parse_file(SAMPLE)
    assert skipped == 2  # the two garbage lines
    assert len(entries) > 80
    ips = {e["ip"] for e in entries}
    assert "45.148.10.88" in ips  # the scanner
    assert "203.0.113.21" in ips
