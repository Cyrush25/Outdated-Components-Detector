# Outdated Component Detector

A fast, concurrent scanner for detecting outdated and vulnerable web components across live subdomains. Built for security researchers, bug bounty hunters, and pentesters working from a Linux CLI.

---

## File Structure

All four files must live in the **same directory**. `scanner.py` imports directly from the three data modules — no install step needed.

```
outdated-components-detector/
  scanner.py         Main script — entry point
  component_db.py    JS/frontend library version database
  server_db.py       Server-side software database + body detection patterns
  patterns.py        All regex patterns for JS library detection
  README.md
```

---

## Requirements

- Python 3.7+
- No `pip install` — stdlib only

---

## Installation

```bash
git clone https://github.com/Cyrush25/outdated-components-detector.git
cd outdated-components-detector
chmod +x scanner.py
```

---

## Features

- **35+ JS libraries detected** — jQuery, Bootstrap, React, Vue, Angular, Lodash, Axios, TinyMCE, CKEditor, DOMPurify, and more
- **12 server-side components** — Nginx, Apache, IIS, PHP, Tomcat, Lighttpd, OpenSSL, Drupal, WordPress, Joomla, and more via headers and page source
- **Smart deduplication** — strip already-scanned URLs before running; accepts plain URL lists, CSVs, httpx/nuclei output, bare hostnames
- **Cross-reference reported findings** — tag results as `[NEW]` vs `[REPORTED]` against a prior findings CSV
- **Interactive mode** — prompts for dedup and reported-CSV options when flags are not supplied
- **Concurrent scanning** — configurable thread count for bulk scans
- **Retry logic** — exponential back-off for slow or unresponsive hosts
- **Coloured terminal output** — severity-coded, auto-disabled when piped
- **Live progress bar** with ETA
- **CSV + optional JSON output**
- **Graceful Ctrl+C** — flushes partial results before exit
- **Modular architecture** — version databases and regex patterns live in separate files; extend without touching scanner logic

---

## Usage

### Interactive mode

```bash
python3 scanner.py -i httpx-urls.txt
```

On first run the script will ask:
1. Whether to deduplicate URLs against a reference file
2. Whether to cross-reference against an already-reported findings CSV

### Non-interactive / scripted

```bash
python3 scanner.py -i httpx-urls.txt --no-interactive
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-i FILE` | required | Input file with live URLs (one per line, httpx output) |
| `-r FILE` | — | CSV of already-reported findings for `[NEW]` vs `[REPORTED]` tagging |
| `-o FILE` | auto-timestamped | Output CSV filename |
| `--dedup FILE` | — | Deduplicate input URLs against this reference file before scanning |
| `--no-dedup` | — | Skip deduplication entirely (suppresses interactive prompt too) |
| `-t N` | 30 | Concurrent threads |
| `--timeout N` | 20 | HTTP timeout per request in seconds |
| `--retries N` | 4 | Max retries for slow/unresponsive URLs |
| `--new-only` | — | Only output findings not already in the reported CSV |
| `--limit N` | 0 (all) | Scan only the first N URLs |
| `--min-findings N` | 0 (all) | Min findings per host required to include in output |
| `--json-output FILE` | — | Also write full results to a JSON file |
| `--no-interactive` | — | Disable all interactive prompts |
| `--no-color` | — | Disable coloured terminal output |

---

## Examples

**Interactive scan — prompted for dedup and reported CSV:**
```bash
python3 scanner.py -i httpx-urls.txt
```

**Fully automated scan with all options:**
```bash
python3 scanner.py \
  -i httpx-urls.txt \
  -r reported-findings.csv \
  --dedup master-scope.txt \
  -o results.csv \
  --threads 50 \
  --timeout 25 \
  --new-only
```

**Deduplicate against a previous scan's output CSV:**
```bash
python3 scanner.py \
  -i httpx-urls.txt \
  --dedup previous_scan_20240101.csv \
  --no-interactive
```

**Export both CSV and JSON:**
```bash
python3 scanner.py \
  -i httpx-urls.txt \
  --json-output results.json \
  --no-interactive
```

**Quick test — first 100 URLs, new findings only:**
```bash
python3 scanner.py \
  -i httpx-urls.txt \
  -r old-findings.csv \
  --limit 100 \
  --new-only
```

**Pipe-friendly — no colour, no prompts:**
```bash
python3 scanner.py -i httpx-urls.txt --no-interactive --no-color | tee scan.log
```

---

## Deduplication

`--dedup` (or the interactive prompt) accepts any of these file formats:

| Format | Notes |
|---|---|
| Plain URL list | `https://sub.example.com` one per line |
| httpx output | Standard `-o` output from httpx |
| nuclei output | Standard nuclei text output |
| CSV (any column) | Any CSV containing URLs in any column |
| Bare hostnames | `sub.example.com` one per line |

Matching is done on **full URL** and **hostname**. Feed in the output of a previous scan to avoid re-scanning already-covered targets.

---

## Output

### CSV columns

| Column | Description |
|---|---|
| `URL` | Scanned URL |
| `Component` | Detected library or server name |
| `Installed_Version` | Version found on the target |
| `Min_Safe_Version` | Oldest version with no known exploitable CVEs |
| `Latest_Version` | Current stable release |
| `CVEs` | Associated CVE identifiers |
| `Detection_Source` | How it was found: header, page source, or meta tag |
| `Already_Reported` | Yes / No |
| `Severity` | Medium (has CVEs) / Low / Info |
| `Server_Header` | Raw `Server` response header value |
| `Scan_Date` | Timestamp |

### Terminal output sample

```
----------------------------------------------------------------------
  [NEW]  https://sub.example.com
  +-- jQuery 1.11.3  (min safe: 3.5.0, latest: 3.7.1)
  |   CVEs : CVE-2020-11023, CVE-2020-11022, CVE-2019-11358
  |   Via  : Page source
  +-- Bootstrap 3.4.1  (min safe: 4.6.2, latest: 5.3.3)
  |   CVEs : CVE-2019-8331, CVE-2018-14041
  |   Via  : Page source
```

---

## Extending the Databases

The tool is split into three data files. Adding new signatures never requires touching `scanner.py`.

### Add a new JS library

**Step 1** — add an entry to `COMPONENT_DB` in `component_db.py`:
```python
"mylib": {
    "latest":   "2.1.0",
    "min_safe": "2.0.0",
    "cves": ["CVE-2024-XXXXX"],
},
```

**Step 2** — add detection patterns to `JS_PATTERNS` in `patterns.py`:
```python
# MyLib
(r'mylib[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js', "mylib"),
(r'"mylib":\s*"[~^]?(\d+\.\d+[\.\d]*)"',      "mylib"),
```

### Add a new server/runtime (header-based)

Add an entry to `SERVER_DB` in `server_db.py` with a `header` and `pattern`:
```python
"myserver": {
    "latest":   "5.0.0",
    "min_safe": "4.8.0",
    "cves": ["CVE-2024-XXXXX"],
    "header":  "server",
    "pattern": r"MyServer[/ ](\d+\.\d+[\.\d]*)",
},
```

### Add a new CMS (body/meta-tag detection)

Set `header=None` and `pattern=None` in `SERVER_DB`, then add a pattern to `SERVER_BODY_PATTERNS`:
```python
# In SERVER_DB:
"mycms": {
    "latest": "3.0.0", "min_safe": "2.9.0", "cves": [],
    "header": None, "pattern": None,
},

# In SERVER_BODY_PATTERNS:
(r'<meta name="generator" content="MyCMS (\d+\.\d+[\.\d]*)"', "mycms"),
```

---

## Detected Components

### JavaScript Libraries
jQuery, jQuery UI, jQuery Migrate, Bootstrap, Moment.js, AngularJS, Angular, React, Vue, Lodash, Underscore, Backbone, Handlebars, Mustache, Modernizr, Core-JS, Prototype, MooTools, Ember, D3, Three.js, Knockout, Swiper, Slick, DataTables, Axios, Chart.js, Select2, Popper, Highlight.js, DOMPurify, CKEditor, TinyMCE, Font Awesome

### Server-Side / Frameworks
Nginx, Apache, IIS, PHP, WordPress, Drupal, Joomla, OpenSSL, Tomcat, Lighttpd, Akka HTTP, Sun ONE Web Server

---

## Typical Workflow

```bash
# 1. Discover live hosts
httpx -l subdomains.txt -o live-hosts.txt

# 2. First scan
python3 scanner.py -i live-hosts.txt -o scan-week1.csv --no-interactive

# 3. Next week — deduplicate against last run, show only new findings
python3 scanner.py \
  -i live-hosts.txt \
  --dedup scan-week1.csv \
  -r scan-week1.csv \
  --new-only \
  -o scan-week2.csv
```

---

## Architecture

```
scanner.py
  |-- imports COMPONENT_DB          from component_db.py
  |-- imports SERVER_DB             from server_db.py
  |-- imports SERVER_BODY_PATTERNS  from server_db.py
  +-- imports JS_PATTERNS           from patterns.py

Detection flow per URL:
  fetch_url()
    |-- detect_server_components()     header-based, driven by SERVER_DB
    |-- detect_js_components()         body-based, driven by JS_PATTERNS + COMPONENT_DB
    +-- detect_body_server_components() body-based, driven by SERVER_BODY_PATTERNS
```

---

## License

MIT — free to use, modify, and distribute.

---

## Contributing

PRs welcome for:
- New component signatures in `component_db.py` and `patterns.py`
- New server entries in `server_db.py`
- Output format support (SARIF, JSON-Lines, Markdown tables, etc.)
