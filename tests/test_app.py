"""Smoke tests for the logwatch web UI, using Flask's test client."""

import io
import os

import pytest

from app import app

SAMPLE = os.path.join(os.path.dirname(__file__), "access.log.sample")
with open(SAMPLE, encoding="utf-8") as f:
    SAMPLE_TEXT = f.read()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Analyze a log" in resp.data
    assert b"Try the sample log" in resp.data


def test_sample_report_shows_real_numbers(client):
    resp = client.get("/sample")
    assert resp.status_code == 200
    assert b"88" in resp.data  # total requests
    assert b"10" in resp.data  # unique IPs
    assert b"45.148.10.88" in resp.data  # the scanner
    assert b"possible scan" in resp.data
    assert b"possible attack probe" in resp.data


def test_upload_sample_file(client):
    with open(SAMPLE, "rb") as f:
        resp = client.post(
            "/analyze",
            data={"logfile": (f, "access.log")},
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    assert b"88" in resp.data
    assert b"45.148.10.88" in resp.data


def test_paste_log_text(client):
    resp = client.post("/analyze", data={"logtext": SAMPLE_TEXT})
    assert resp.status_code == 200
    assert b"88" in resp.data
    assert b"45.148.10.88" in resp.data


def test_empty_input_shows_form_error(client):
    resp = client.post("/analyze", data={"logtext": ""})
    assert resp.status_code == 400
    assert b"Paste some log lines or upload a log file first." in resp.data


def test_unparseable_input_shows_form_error(client):
    resp = client.post("/analyze", data={"logtext": "this is not a log line\n"})
    assert resp.status_code == 400
    assert b"Couldn" in resp.data
    assert b"combined-format" in resp.data


def test_report_json_after_sample(client):
    client.get("/sample")
    resp = client.get("/report.json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total_requests"] == 88
    assert data["unique_ips"] == 10
    assert data["skipped_lines"] == 2
    assert data["top_ips"][0]["ip"] == "45.148.10.88"


def test_report_html_after_sample(client):
    client.get("/sample")
    resp = client.get("/report.html")
    assert resp.status_code == 200
    assert b"logwatch report" in resp.data
    assert b"45.148.10.88" in resp.data


def test_top_n_control_limits_lists(client):
    resp = client.post("/analyze", data={"logtext": SAMPLE_TEXT, "top": "3"})
    assert resp.status_code == 200
    # 203.0.113.21 is the 2nd-ranked IP, so it stays; 192.0.2.14 is 4th
    # (4 requests, only ever shown in the top-IP table) and must be hidden
    assert b"203.0.113.21" in resp.data
    assert b"192.0.2.14" not in resp.data


def test_log_content_is_escaped(client):
    nasty = ('203.0.113.1 - - [03/Oct/2026:13:02:11 +0000] '
             '"GET /<script>alert(1)</script> HTTP/1.1" 200 10 "-" "curl/8.5.0"\n')
    resp = client.post("/analyze", data={"logtext": nasty})
    assert resp.status_code == 200
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in resp.data
    assert b"<script>alert(1)</script>" not in resp.data
