"""Aggregation and flagging logic for parsed access-log entries."""

import re
from collections import Counter
from datetime import timedelta
from urllib.parse import unquote

# An IP returning this many 404s in one file is almost certainly scanning.
SCANNER_404_THRESHOLD = 50

# An IP firing this many requests inside any 60-second window is bursting,
# even if every request succeeds, so it gets flagged on rate alone.
HIGH_RATE_THRESHOLD = 500
RATE_WINDOW_SECONDS = 60

# Deliberately naive signatures. Anything matching gets flagged for a human
# to look at; this is a first pass, not a WAF.
PROBE_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"\.\./"),
    re.compile(r"<\s*script", re.IGNORECASE),
]


def analyze(entries, top_n=10):
    """Aggregate parsed entries into a report dict (JSON-serializable)."""
    ips = [e["ip"] for e in entries]
    ip_counts = Counter(ips)

    return {
        "total_requests": len(entries),
        "unique_ips": len(set(ips)),
        "status_codes": [
            {"code": code, "count": count}
            for code, count in sorted(Counter(e["status"] for e in entries).items())
        ],
        "top_ips": [
            {"ip": ip, "count": count}
            for ip, count in ip_counts.most_common(top_n)
        ],
        "top_paths": [
            {"path": path, "count": count}
            for path, count in Counter(e["path"] for e in entries).most_common(top_n)
        ],
        "requests_per_hour": _requests_per_hour(entries),
        "scanners": _find_scanners(entries),
        "probes": _find_probes(entries),
        "rare_agents": _find_rare_agents(entries),
    }


def _requests_per_hour(entries):
    buckets = Counter(e["time"].strftime("%H:00") for e in entries)
    return [
        {"hour": hour, "count": buckets[hour]}
        for hour in sorted(buckets)
    ]


def _peak_requests_per_min(times):
    """Most requests in any RATE_WINDOW_SECONDS window (sliding, not
    clock-minute buckets, so a burst straddling a minute boundary still
    counts). Timestamps carry second precision, so this is exact."""
    ordered = sorted(times)
    window = timedelta(seconds=RATE_WINDOW_SECONDS)
    peak = 0
    start = 0
    for end, t in enumerate(ordered):
        while ordered[start] < t - window:
            start += 1
        peak = max(peak, end - start + 1)
    return peak


def _find_scanners(entries):
    """IPs with a suspicious number of 404s, or a suspicious request rate.

    An IP is flagged when it hits SCANNER_404_THRESHOLD 404s or fires
    HIGH_RATE_THRESHOLD requests inside any 60-second window. The two
    signals are independent: a fast IP returning all 200s still flags.
    """
    not_found = Counter(e["ip"] for e in entries if e["status"] == 404)
    total = Counter(e["ip"] for e in entries)
    times = {}
    for e in entries:
        times.setdefault(e["ip"], []).append(e["time"])
    peak = {ip: _peak_requests_per_min(ts) for ip, ts in times.items()}
    flagged = [
        {
            "ip": ip,
            "requests_404": not_found[ip],
            "total_requests": total[ip],
            "peak_requests_per_min": peak[ip],
        }
        for ip in total
        if not_found[ip] >= SCANNER_404_THRESHOLD
        or peak[ip] >= HIGH_RATE_THRESHOLD
    ]
    # 404-heavy IPs first, then the fastest burst.
    flagged.sort(key=lambda s: (s["requests_404"], s["peak_requests_per_min"]),
                 reverse=True)
    return flagged


def _find_probes(entries):
    """Requests whose (URL-decoded) path matches a naive attack signature."""
    probes = []
    for i, entry in enumerate(entries, start=1):
        decoded = unquote(entry["path"])
        if any(p.search(decoded) for p in PROBE_PATTERNS):
            probes.append({
                "line": i,
                "ip": entry["ip"],
                "path": entry["path"],
                "status": entry["status"],
            })
    return probes


def _find_rare_agents(entries):
    """User agents that appear exactly once. Usually bots or one-off scripts."""
    counts = Counter(e["agent"] for e in entries)
    first_seen = {}
    for e in entries:
        first_seen.setdefault(e["agent"], e["ip"])
    return [
        {"agent": agent, "ip": first_seen[agent]}
        for agent, count in counts.items()
        if count == 1
    ]


def _bar_chart(hourly, width=40):
    if not hourly:
        return "  (no data)"
    peak = max(h["count"] for h in hourly)
    lines = []
    for h in hourly:
        bar = "#" * round(h["count"] / peak * width) if peak else ""
        lines.append(f"  {h['hour']:>5} | {bar:<{width}} {h['count']}")
    return "\n".join(lines)


def render_text(report, skipped=0, top_n=10):
    """Render the report dict as a plain-text terminal report."""
    out = []
    add = out.append

    add("logwatch report")
    add("=" * 40)
    add("")
    add("traffic")
    add("-" * 40)
    add(f"  total requests : {report['total_requests']}")
    add(f"  unique IPs     : {report['unique_ips']}")
    add(f"  skipped lines  : {skipped}")
    add("")
    add("status codes")
    add("-" * 40)
    total = report["total_requests"] or 1
    for row in report["status_codes"]:
        pct = row["count"] / total * 100
        add(f"  {row['code']:<4} {row['count']:>6}  ({pct:5.1f}%)")
    add("")
    add(f"top {top_n} IPs")
    add("-" * 40)
    for row in report["top_ips"]:
        add(f"  {row['ip']:<18} {row['count']}")
    add("")
    add(f"top {top_n} paths")
    add("-" * 40)
    for row in report["top_paths"]:
        add(f"  {row['count']:>4}  {row['path']}")
    add("")
    add("requests per hour")
    add("-" * 40)
    add(_bar_chart(report["requests_per_hour"]))
    add("")
    add("suspicious")
    add("-" * 40)

    scanners = report["scanners"]
    if scanners:
        for s in scanners:
            line = (f"  [!] {s['ip']} returned {s['requests_404']} 404s "
                    f"({s['total_requests']} requests total) - possible scan")
            if s["peak_requests_per_min"] >= HIGH_RATE_THRESHOLD:
                line += (f" - burst: {s['peak_requests_per_min']} requests "
                         f"in a single minute")
            add(line)
    else:
        add("  no scanner-like IPs found")

    probes = report["probes"]
    if probes:
        for p in probes:
            add(f"  [!] line {p['line']}: {p['ip']} requested {p['path']} "
                f"(status {p['status']}) - possible attack probe")
    else:
        add("  no attack-probe patterns found")

    rare = report["rare_agents"]
    if rare:
        add("")
        add("  user agents seen once:")
        for r in rare:
            add(f"    {r['agent']}  ({r['ip']})")
    else:
        add("  no one-off user agents")

    return "\n".join(out)
