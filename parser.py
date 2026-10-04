"""Parse Apache/Nginx combined log format lines into dicts.

Example line:
    203.0.113.21 - - [03/Oct/2026:13:02:11 +0000] "GET / HTTP/1.1" 200 4523 "-" "Mozilla/5.0 ..."
"""

import re
from datetime import datetime

# https://httpd.apache.org/docs/2.4/logs.html#combined
COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line):
    """Parse a single combined-log line.

    Returns a dict with keys: ip, user, time (datetime), method, path,
    protocol, status (int), size (int, 0 when '-'), referer, agent.
    Returns None when the line doesn't look like a combined log entry.
    """
    match = COMBINED_RE.match(line)
    if not match:
        return None

    entry = match.groupdict()
    try:
        entry["time"] = datetime.strptime(entry["time"], TIME_FORMAT)
    except ValueError:
        return None  # timestamp didn't parse, treat as malformed

    entry["status"] = int(entry["status"])
    entry["size"] = 0 if entry["size"] == "-" else int(entry["size"])
    return entry


def parse_file(path):
    """Parse every line of a log file.

    Returns (entries, skipped): parsed entry dicts and the count of
    malformed/blank lines that were skipped.
    """
    entries = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            entry = parse_line(line)
            if entry is None:
                skipped += 1
            else:
                entries.append(entry)
    return entries, skipped
