"""Tests for the aggregation / flagging logic, using the sample log."""

import os
from datetime import datetime, timezone
from urllib.parse import unquote

from analyze import analyze, render_html, render_text
from parser import parse_file

SAMPLE = os.path.join(os.path.dirname(__file__), "access.log.sample")

entries, _ = parse_file(SAMPLE)
report = analyze(entries, top_n=10)


def test_totals():
    assert report["total_requests"] == len(entries)
    assert report["unique_ips"] == len({e["ip"] for e in entries})
    assert report["unique_ips"] == 10


def test_status_breakdown():
    codes = {r["code"]: r["count"] for r in report["status_codes"]}
    assert codes[200] > 20
    assert codes[404] >= 50  # scanner hammering 404s
    assert codes[500] == 1
    assert codes[301] == 1
    assert sum(codes.values()) == report["total_requests"]


def test_top_ips_finds_scanner_first():
    top = report["top_ips"]
    assert top[0]["ip"] == "45.148.10.88"
    assert top[0]["count"] >= 50
    assert len(top) <= 10


def test_top_n_is_respected():
    small = analyze(entries, top_n=3)
    assert len(small["top_ips"]) == 3
    assert len(small["top_paths"]) == 3


def test_requests_per_hour_sums_to_total():
    assert sum(h["count"] for h in report["requests_per_hour"]) == len(entries)
    hours = [h["hour"] for h in report["requests_per_hour"]]
    assert hours == sorted(hours)


def test_scanner_flagged():
    scanners = report["scanners"]
    assert len(scanners) == 1
    assert scanners[0]["ip"] == "45.148.10.88"
    assert scanners[0]["requests_404"] >= 50


def test_attack_probes_flagged():
    probes = report["probes"]
    assert len(probes) == 3
    decoded = [unquote(p["path"]).lower() for p in probes]
    assert any("union select" in d for d in decoded)
    assert any("../" in d for d in decoded)
    assert any("<script" in d for d in decoded)


def test_rare_agents():
    agents = {r["agent"] for r in report["rare_agents"]}
    assert any("sqlmap" in a for a in agents)
    assert any("UptimeRobot" in a for a in agents)
    # the scanner's UA is reused, so it must NOT be rare
    assert not any("masscan" in a for a in agents)


def _burst_entries(ip, seconds, count):
    """Synthetic all-200 entries for one IP at the given second offsets."""
    base = datetime(2026, 10, 3, 13, 0, 0, tzinfo=timezone.utc)
    from datetime import timedelta
    return [
        {"ip": ip, "time": base + timedelta(seconds=s), "status": 200,
         "path": "/", "agent": "curl/8.5.0"}
        for s in seconds for _ in range(count)
    ]


def test_high_rate_ip_flagged_without_404s():
    # 600 successful requests inside one minute: flagged on rate alone.
    entries = _burst_entries("198.51.100.99", [0], 600)
    scanners = analyze(entries)["scanners"]
    assert len(scanners) == 1
    assert scanners[0]["ip"] == "198.51.100.99"
    assert scanners[0]["requests_404"] == 0
    assert scanners[0]["peak_requests_per_min"] == 600


def test_burst_across_minute_boundary_flagged():
    # 300 requests at 13:00:59 and 300 at 13:01:00: a clock-minute
    # bucket count would miss this, the sliding window catches it.
    entries = _burst_entries("198.51.100.98", [59, 60], 300)
    scanners = analyze(entries)["scanners"]
    assert len(scanners) == 1
    assert scanners[0]["peak_requests_per_min"] == 600


def test_just_under_rate_threshold_not_flagged():
    entries = _burst_entries("198.51.100.97", [0], 499)
    assert analyze(entries)["scanners"] == []


def test_text_report_mentions_flags():
    text = render_text(report, skipped=2, top_n=10)
    assert "45.148.10.88" in text
    assert "possible scan" in text
    assert "possible attack probe" in text
    assert "skipped lines  : 2" in text


def test_html_report_has_same_sections():
    html = render_html(report, skipped=2, top_n=10)
    assert "<!DOCTYPE html>" in html
    assert "45.148.10.88" in html
    assert "possible scan" in html
    assert "possible attack probe" in html
    assert "skipped lines: 2" in html
    assert "requests per hour" in html


def test_html_report_escapes_log_content():
    # paths and user agents come straight from the log -- markup in them
    # must be escaped, not rendered as live HTML
    nasty = {
        "total_requests": 1,
        "unique_ips": 1,
        "status_codes": [{"code": 200, "count": 1}],
        "top_ips": [{"ip": "203.0.113.1", "count": 1}],
        "top_paths": [{"path": "/<script>alert(1)</script>", "count": 1}],
        "requests_per_hour": [{"hour": "13:00", "count": 1}],
        "scanners": [],
        "probes": [{
            "line": 1, "ip": "203.0.113.1",
            "path": "/<script>alert(1)</script>", "status": 200,
        }],
        "rare_agents": [{"agent": "<b>evil</b>", "ip": "203.0.113.1"}],
    }
    html = render_html(nasty)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;b&gt;evil&lt;/b&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "<b>evil</b>" not in html
