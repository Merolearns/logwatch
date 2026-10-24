# logwatch

A small command-line tool that reads a web server access log (Apache/Nginx
**combined log format**) and prints a traffic + security summary: request
totals, status code breakdown, top IPs and paths, an hourly traffic chart, and
a few suspicious-activity flags.

I built this to get comfortable with regex parsing and log analysis in
Python. It's a learning project, not production software.

## Install

```bash
git clone https://github.com/Merolearns/logwatch.git
cd logwatch
pip install -r requirements.txt   # pytest, for the test suite only
```

No third-party dependencies at runtime — just the standard library.

## Usage

```bash
python logwatch.py tests/access.log.sample          # text report
python logwatch.py /var/log/nginx/access.log        # your own log
python logwatch.py access.log --top 5               # shorter top-N lists
python logwatch.py access.log --json                # JSON output instead
```

## What it reports

- total requests, unique IPs, malformed lines skipped
- status code breakdown with percentages
- top N IPs and top N requested paths
- requests per hour, drawn as an ASCII bar chart (no plotting library)
- suspicious flags:
  - IPs returning 50+ 404s (looks like directory scanning)
  - IPs firing 500+ requests inside any 60-second window (sliding window, so a burst straddling a minute boundary still flags), even when every request succeeds
  - requests matching naive attack signatures (`UNION SELECT`, `../`, `<script>`)
  - user agents seen exactly once (usually one-off bots or scripts)

## Example output

```
logwatch report
========================================

traffic
----------------------------------------
  total requests : 88
  unique IPs     : 10
  skipped lines  : 2

status codes
----------------------------------------
  200      26  ( 29.5%)
  301       1  (  1.1%)
  302       1  (  1.1%)
  403       1  (  1.1%)
  404      58  ( 65.9%)
  500       1  (  1.1%)

top 10 IPs
----------------------------------------
  45.148.10.88       56
  203.0.113.21       11
  198.51.100.77       7
  ...

requests per hour
----------------------------------------
  13:00 | ########                                 12
  14:00 | ######                                    8
  15:00 | ######                                    8
  16:00 | ######################################## 57
  17:00 | ##                                        3

suspicious
----------------------------------------
  [!] 45.148.10.88 returned 56 404s (56 requests total) - possible scan
  [!] line 24: 203.0.113.99 requested /search?q=%27%20UNION%20SELECT%201,2,3-- (status 200) - possible attack probe
  [!] line 25: 203.0.113.99 requested /static/..%2f..%2f..%2fetc%2fpasswd (status 403) - possible attack probe
  [!] line 26: 198.51.100.44 requested /search?q=%3Cscript%3Ealert(1)%3C/script%3E (status 200) - possible attack probe

  user agents seen once:
    Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)  (198.51.100.23)
    Wget/1.21.4  (192.0.2.99)
    ...
```

## Layout

- `logwatch.py` — CLI entry point (argparse)
- `parser.py` — combined-log-format regex parser; malformed lines are counted and skipped
- `analyze.py` — aggregation, flagging, and report rendering
- `tests/access.log.sample` — hand-written sample log (normal traffic, three attack probes, one scanner)
- `tests/test_parser.py`, `tests/test_analyze.py` — pytest suite

Run the tests with `pytest`.

## Limitations

- Only the **combined log format** is supported. Custom `LogFormat` lines and JSON logs won't parse.
- The attack signatures are deliberately naive — they flag requests for a human to review, not block anything. This is not a WAF and not a SIEM.
- Timestamps are parsed from the log as-is; mixed timezones in one file will skew the hourly chart.
