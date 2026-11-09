"""logwatch web UI: the same parser and analyzer behind a web page.

Thin layer over parser.py / analyze.py — the CLI in logwatch.py is
untouched and still the same code underneath. Upload or paste an
Apache/Nginx combined-format access log and get the traffic + security
report in the browser. Nothing is written to disk; the last report is
kept in memory only, for the /report.html and /report.json downloads.
"""

import io
import os

from flask import Flask, jsonify, redirect, render_template, request, url_for

from analyze import analyze, render_html
from parser import parse_file, parse_stream

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB uploads

SAMPLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "tests", "access.log.sample")

# The last report analyzed, kept in memory only. The download routes
# (/report.html, /report.json) serve this; nothing persists to disk.
LAST = {"report": None, "skipped": 0, "top_n": 10}


def parse_top(value):
    """A top-N between 1 and 50, or 10 when missing/invalid."""
    try:
        top = int(value)
    except (TypeError, ValueError):
        return 10
    return max(1, min(top, 50))


def _report_view(report, skipped, top_n):
    """Everything the report template needs, with bar percentages."""
    total = report["total_requests"] or 1
    peak = max((h["count"] for h in report["requests_per_hour"]), default=0) or 1
    return {
        "report": report,
        "skipped": skipped,
        "top_n": top_n,
        "status_rows": [
            {
                "code": row["code"],
                "count": row["count"],
                "pct": row["count"] / total * 100,
            }
            for row in report["status_codes"]
        ],
        "hourly": [
            {"hour": h["hour"], "count": h["count"],
             "pct": h["count"] / peak * 100}
            for h in report["requests_per_hour"]
        ],
    }


def _analyze_text(text, top_n):
    """Parse pasted/uploaded log text and build the report view data."""
    entries, skipped = parse_stream(io.StringIO(text))
    if not entries:
        return None, skipped
    report = analyze(entries, top_n=top_n)
    LAST["report"] = report
    LAST["skipped"] = skipped
    LAST["top_n"] = top_n
    return _report_view(report, skipped, top_n), skipped


def _render_index(error=None, status=200):
    return render_template("index.html", error=error), status


@app.route("/", methods=["GET"])
def index():
    return _render_index()


@app.route("/analyze", methods=["POST"])
def analyze_log():
    top_n = parse_top(request.form.get("top"))

    upload = request.files.get("logfile")
    text = ""
    if upload is not None and upload.filename:
        # parse_file reads with errors="replace"; match that here so a
        # stray bad byte doesn't fail the whole upload.
        text = upload.read().decode("utf-8", errors="replace")
    if not text.strip():
        text = (request.form.get("logtext") or "").strip()

    if not text.strip():
        return _render_index(
            error="Paste some log lines or upload a log file first.",
            status=400,
        )

    view, skipped = _analyze_text(text, top_n)
    if view is None:
        return _render_index(
            error=(f"Couldn't parse any lines from that log — check it's an "
                   f"Apache/Nginx combined-format access log. "
                   f"{skipped} line(s) skipped."),
            status=400,
        )
    return render_template("report.html", **view)


@app.route("/sample", methods=["GET"])
def sample():
    top_n = parse_top(request.args.get("top"))
    entries, skipped = parse_file(SAMPLE_PATH)
    report = analyze(entries, top_n=top_n)
    LAST["report"] = report
    LAST["skipped"] = skipped
    LAST["top_n"] = top_n
    return render_template("report.html",
                           **_report_view(report, skipped, top_n))


@app.route("/report.html", methods=["GET"])
def report_html():
    if LAST["report"] is None:
        return redirect(url_for("index"))
    return render_html(LAST["report"], skipped=LAST["skipped"],
                        top_n=LAST["top_n"]), 200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": "attachment; filename=logwatch-report.html",
    }


@app.route("/report.json", methods=["GET"])
def report_json():
    if LAST["report"] is None:
        return redirect(url_for("index"))
    report = dict(LAST["report"])
    report["skipped_lines"] = LAST["skipped"]
    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True)
