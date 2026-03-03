# 🔍 Outdated Component Detector

A fast, concurrent scanner for detecting **outdated and vulnerable web components** across live subdomains. Designed for security researchers, bug bounty hunters, and pentesters working from a Linux CLI.

---

## Features

- **35+ components detected** — jQuery, Bootstrap, React, Vue, Angular, Lodash, Axios, TinyMCE, CKEditor, DOMPurify, and many more
- **Server-side detection** — Nginx, Apache, IIS, PHP, Tomcat, Lighttpd, OpenSSL, Drupal, WordPress, Joomla via response headers and page source
- **Smart deduplication** — remove already-scanned URLs before running; accepts plain lists, CSVs, httpx/nuclei output files
- **Cross-reference reported findings** — tag results as `[NEW]` vs `[REPORTED]` against a prior findings CSV
- **Interactive mode** — walks you through dedup and reported-CSV options on first run (skippable with flags)
- **Concurrent scanning** — configurable thread count for high-speed bulk scans
- **Retry logic** — exponential back-off for slow/flaky hosts
- **Coloured terminal output** — severity-coded, auto-disabled when piped
- **Live progress bar** with ETA
- **CSV + JSON output** — structured results ready for triage or further processing
- **Graceful Ctrl+C** — flushes partial results before exiting
- **Zero external dependencies** — stdlib only, runs on any Python 3.7+ Linux install

---

## Requirements

- Python 3.7+
- No external packages needed

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/outdated-components-detector.git
cd outdated-components-detector
chmod +x outdated-components-detector.py
```

---

## Usage

### Interactive (recommended for first-time use)

```bash
python3 outdated-components-detector.py -i httpx-urls.txt
```

The script will interactively ask:
1. Whether to deduplicate URLs against a reference file
2. Whether to cross-reference against an already-reported findings CSV

---

### Full flag reference

```
usage: outdated-components-detector.py [-h] -i INPUT [-r REPORTED] [-o OUTPUT]
                                        [--dedup FILE] [--no-dedup]
                                        [-t THREADS] [--timeout TIMEOUT]
                                        [--retries RETRIES] [--new-only]
                                        [--limit LIMIT] [--min-findings N]
                                        [--json-output FILE]
                                        [--no-interactive] [--no-color]
```

| Flag | Description |
|---|---|
| `-i FILE` | **Required.** Input file with live URLs (one per line, httpx output) |
| `-r FILE` | CSV of already-reported findings for NEW vs REPORTED tagging |
| `-o FILE` | Output CSV filename (default: timestamped auto-name) |
| `--dedup FILE` | Deduplicate input URLs against this reference file |
| `--no-dedup` | Skip deduplication entirely (suppresses interactive prompt too) |
| `-t N` | Concurrent threads (default: 30) |
| `--timeout N` | HTTP timeout per request in seconds (default: 20) |
| `--retries N` | Max retries for slow URLs (default: 4) |
| `--new-only` | Only output findings not already in the reported CSV |
| `--limit N` | Scan only the first N URLs (useful for quick tests) |
| `--min-findings N` | Minimum number of findings per host to include in output |
| `--json-output FILE` | Also write full results to a JSON file |
| `--no-interactive` | Disable all interactive prompts; use flag values only |
| `--no-color` | Disable coloured terminal output |

---

## Examples

**Basic scan — interactive mode decides dedup and reporting:**
```bash
python3 outdated-components-detector.py -i httpx-urls.txt
```

**Full automated scan with all options:**
```bash
python3 outdated-components-detector.py \
  -i httpx-urls.txt \
  -r reported-findings.csv \
  --dedup master-scope.txt \
  -o new_results.csv \
  --threads 50 \
  --timeout 25 \
  --new-only
```

**Deduplicate against a previous scan's CSV output:**
```bash
python3 outdated-components-detector.py \
  -i httpx-urls.txt \
  --dedup previous_scan_20240101.csv \
  --no-interactive
```

**Export to JSON for downstream processing:**
```bash
python3 outdated-components-detector.py \
  -i httpx-urls.txt \
  --json-output results.json \
  --no-interactive
```

**Quick test on first 100 URLs, new findings only:**
```bash
python3 outdated-components-detector.py \
  -i httpx-urls.txt \
  -r old-findings.csv \
  --limit 100 \
  --new-only
```

**Pipe-friendly (no colour, no prompts):**
```bash
python3 outdated-components-detector.py \
  -i httpx-urls.txt \
  --no-interactive \
  --no-color \
  | tee scan.log
```

---

## Deduplication

The `--dedup` flag (or the interactive prompt) accepts any of these file formats:

| Format | Example |
|---|---|
| Plain URL list | `https://sub.example.com` one per line |
| httpx output | Standard httpx `-o` output |
| nuclei output | Standard nuclei text output |
| CSV (any column) | Any CSV that contains URLs in any column |
| Bare hostnames | `sub.example.com` one per line |

URLs are matched by **full URL** or **hostname**. This makes it easy to feed in the output of a previous scan to avoid rescanning the same targets.

---

## Detected Components

### JavaScript Libraries
jQuery · jQuery UI · jQuery Migrate · Bootstrap · Moment.js · AngularJS · Angular · React · Vue · Lodash · Underscore · Backbone · Handlebars · Mustache · Modernizr · Core-JS · Prototype · MooTools · Ember · D3 · Three.js · Knockout · Swiper · Slick · DataTables · Axios · Chart.js · Select2 · Popper · Highlight.js · DOMPurify · CKEditor · TinyMCE

### Server-Side / Frameworks
Nginx · Apache · IIS · PHP · WordPress · Drupal · Joomla · OpenSSL · Tomcat · Lighttpd · Akka HTTP · Sun ONE Web Server

---

## Output

### CSV columns

| Column | Description |
|---|---|
| `URL` | Scanned URL |
| `Component` | Detected library/server name |
| `Installed_Version` | Version found on the target |
| `Min_Safe_Version` | Minimum version without known vulns |
| `Latest_Version` | Current stable release |
| `CVEs` | Associated CVE IDs |
| `Detection_Source` | How it was found (header, page source, meta tag) |
| `Already_Reported` | Yes / No |
| `Severity` | Medium (has CVEs) / Low / Info |
| `Server_Header` | Raw Server response header |
| `Scan_Date` | Timestamp |

### Terminal output sample

```
──────────────────────────────────────────────────────────────────────
  [NEW]  https://sub.example.com
  ├─ jQuery 1.11.3  (min safe: 3.5.0, latest: 3.7.1)
  │   CVEs : CVE-2020-11023, CVE-2020-11022, CVE-2019-11358
  │   Via  : Page source
  ├─ Bootstrap 3.4.1  (min safe: 4.6.2, latest: 5.3.3)
  │   CVEs : CVE-2019-8331, CVE-2018-14041
  │   Via  : Page source
```

---

## Typical Workflow

```bash
# 1. Discover live hosts with httpx
httpx -l subdomains.txt -o live-hosts.txt

# 2. First scan
python3 outdated-components-detector.py \
  -i live-hosts.txt \
  -o scan-week1.csv \
  --no-interactive

# 3. Next week — deduplicate against last week and only show new findings
python3 outdated-components-detector.py \
  -i live-hosts.txt \
  --dedup scan-week1.csv \
  -r scan-week1.csv \
  --new-only \
  -o scan-week2.csv
```

---

## License

MIT — free to use, modify, and distribute.

---

## Contributing

PRs welcome for:
- Additional component signatures
- New detection methods (JS source map parsing, CDN URL detection, etc.)
- Output format integrations (Markdown tables, SARIF, etc.)
