#!/usr/bin/env python3
"""logwatch: parse a web server access log and print a traffic + security report.

Usage:
    python logwatch.py access.log
    python logwatch.py access.log --top 5
    python logwatch.py access.log --json
    python logwatch.py access.log --html > report.html
    zcat access.log.gz | python logwatch.py -
"""

import argparse
import json
import sys

from analyze import analyze, render_html, render_text
from parser import parse_file, parse_stream


def build_parser():
    p = argparse.ArgumentParser(
        prog="logwatch",
        description="Analyze an Apache/Nginx combined-format access log.",
    )
    p.add_argument("logfile",
                   help="path to the access log file, or '-' to read from stdin")
    p.add_argument("--top", type=int, default=10,
                   help="how many rows to show in the top-IP / top-path lists (default 10)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--json", action="store_true",
                       help="print the report as JSON instead of text")
    group.add_argument("--html", action="store_true",
                       help="print the report as a self-contained HTML page "
                            "instead of text (redirect to a .html file)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.logfile == "-":
        entries, skipped = parse_stream(sys.stdin)
    else:
        try:
            entries, skipped = parse_file(args.logfile)
        except OSError as e:
            print(f"logwatch: cannot read {args.logfile}: {e}", file=sys.stderr)
            return 1

    report = analyze(entries, top_n=args.top)

    if args.html:
        print(render_html(report, skipped=skipped, top_n=args.top))
    elif args.json:
        report["skipped_lines"] = skipped
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report, skipped=skipped, top_n=args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
