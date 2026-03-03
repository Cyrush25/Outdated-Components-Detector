#!/usr/bin/env python3
"""
Outdated Component Detector v2.0
=================================
Scans live subdomains for outdated web components and cross-references
with already-reported findings.

Requires these files in the same directory:
    component_db.py  - JS/frontend library version database
    server_db.py     - server-side software version database + body patterns
    patterns.py      - regex patterns for JS library detection

Features: concurrent scanning, deduplication, interactive prompts,
coloured output, live progress bar, CSV + JSON export, graceful Ctrl+C.
Zero external dependencies - stdlib only, Python 3.7+.
"""

import re
import csv
import sys
import time
import json
import random
import argparse
import threading
import urllib.request
import urllib.error
import urllib.parse
import ssl
import gzip
import os
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from component_db import COMPONENT_DB
from server_db    import SERVER_DB, SERVER_BODY_PATTERNS
from patterns     import JS_PATTERNS

# ── Colour helpers ─────────────────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""
def _c(code, t): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
def red(t):    return _c("91", t)
def green(t):  return _c("92", t)
def yellow(t): return _c("93", t)
def cyan(t):   return _c("96", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

# ── Version comparison ─────────────────────────────────────────────────────────
def parse_version(v):
    try:
        return tuple(int(x) for x in re.sub(r'[^0-9.]', '', str(v)).split('.') if x)
    except Exception:
        return (0,)

def is_outdated(installed, min_safe):
    try:
        return parse_version(installed) < parse_version(min_safe)
    except Exception:
        return False

# ── HTTP fetcher ───────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode    = ssl.CERT_NONE

def fetch_url(url, timeout=20, retries=4, retry_delay=5):
    """Fetch a URL with retry/back-off. Returns (headers_dict, body_str) or (None, None)."""
    hdrs = {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection":      "close",
    }
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=hdrs), timeout=timeout, context=ssl_ctx
            ) as resp:
                raw  = resp.read()
                rhdr = {k.lower(): v for k, v in resp.headers.items()}
                if rhdr.get("content-encoding") == "gzip":
                    try: raw = gzip.decompress(raw)
                    except Exception: pass
                return rhdr, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            try: return {k.lower(): v for k, v in e.headers.items()}, ""
            except Exception: pass
            break
        except Exception as e:
            if any(x in str(e).lower() for x in
                   ["timed out","timeout","connection reset","connection refused",
                    "temporarily","remote end"]):
                time.sleep(retry_delay * (2 ** attempt) + random.uniform(0, 2))
                continue
            break
    return None, None

# ── Detection ─────────────────────────────────────────────────────────────────
def detect_server_components(headers):
    """Match response headers against SERVER_DB entries that have a header+pattern."""
    findings = []
    for key, info in SERVER_DB.items():
        hdr_name = info.get("header")
        pattern  = info.get("pattern")
        if not hdr_name or not pattern:
            continue
        m = re.search(pattern, headers.get(hdr_name, ""), re.IGNORECASE)
        if m:
            ver = m.group(1)
            if is_outdated(ver, info["min_safe"]):
                findings.append({
                    "component": key.upper() if key in ("iis","php") else key.title(),
                    "installed": ver, "min_safe": info["min_safe"],
                    "latest":    info["latest"], "cves": info["cves"],
                    "source":    f"{hdr_name.title()} header",
                })
    return findings

def detect_js_components(body):
    """Run JS_PATTERNS over the page body; keep the lowest version per component."""
    seen = {}
    for pattern, comp_key in JS_PATTERNS:
        for m in re.finditer(pattern, body, re.IGNORECASE):
            ver = m.group(1)
            if re.match(r'^\d+\.\d+', ver):
                if comp_key not in seen or parse_version(ver) < parse_version(seen[comp_key]):
                    seen[comp_key] = ver
    findings = []
    for comp_key, ver in seen.items():
        info = COMPONENT_DB.get(comp_key)
        if info and is_outdated(ver, info["min_safe"]):
            findings.append({
                "component": comp_key.title(), "installed": ver,
                "min_safe":  info["min_safe"],  "latest":   info["latest"],
                "cves":      info["cves"],       "source":   "Page source",
            })
    return findings

def detect_body_server_components(body):
    """Detect CMS/server software via SERVER_BODY_PATTERNS (WordPress, Joomla, etc.)."""
    findings, seen_keys = [], set()
    for pattern, comp_key in SERVER_BODY_PATTERNS:
        if comp_key in seen_keys:
            continue
        m = re.search(pattern, body, re.IGNORECASE)
        if not m:
            continue
        seen_keys.add(comp_key)
        info = SERVER_DB.get(comp_key, {})
        if not info:
            continue
        try:
            ver = m.group(1) if m.lastindex and m.group(1) else None
        except IndexError:
            ver = None
        if ver and is_outdated(ver, info["min_safe"]):
            findings.append({
                "component": comp_key.title(), "installed": ver,
                "min_safe":  info["min_safe"],  "latest":   info["latest"],
                "cves":      info["cves"],       "source":   "Meta generator",
            })
        elif ver is None:
            findings.append({
                "component": comp_key.title(), "installed": "unknown",
                "min_safe":  info["min_safe"],  "latest":   info["latest"],
                "cves":      info["cves"],       "source":   "Page source (version unknown)",
            })
    return findings

def scan_url(url, reported_set, timeout=20, retries=4):
    """Full scan of a single URL. Returns result dict."""
    result = {"url": url, "findings": [], "already_reported": url in reported_set,
              "server_header": "", "status": "ok"}
    headers, body = fetch_url(url, timeout=timeout, retries=retries)
    if headers is None:
        result["status"] = "unreachable"
        return result
    result["server_header"] = headers.get("server", "")
    result["findings"].extend(detect_server_components(headers))
    if body:
        result["findings"].extend(detect_js_components(body))
        result["findings"].extend(detect_body_server_components(body))
    return result

# ── Reported CSV ───────────────────────────────────────────────────────────────
def load_reported(csv_path):
    """Load already-reported assets from CSV. Returns set of URLs/domains."""
    reported = set()
    if not csv_path or not os.path.exists(csv_path):
        return reported
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            for key in ["ASSET","TARGET","EXPOSURE INSTANCE","URL"]:
                val = row.get(key, "").strip()
                if val:
                    m = re.match(r'(https?://[^\s|]+)', val)
                    reported.add((m.group(1) if m else val).rstrip('/'))
    print(f"[*] Loaded {len(reported)} reported assets from {cyan(csv_path)}")
    return reported

def is_already_reported(url, reported_set):
    return url.rstrip('/') in reported_set or \
           urllib.parse.urlparse(url).netloc in reported_set

# ── Deduplication ──────────────────────────────────────────────────────────────
def extract_urls_from_file(filepath):
    """
    Extract URLs/hosts from any text-based file.
    Handles plain URL lists, CSV files, httpx/nuclei output, bare hostnames.
    """
    entries = set()
    if not os.path.exists(filepath):
        print(red(f"[!] Dedup file not found: {filepath}"))
        return entries
    with open(filepath, encoding="utf-8-sig", errors="replace") as f:
        if os.path.splitext(filepath)[1].lower() == ".csv":
            try:
                for row in csv.DictReader(f):
                    for val in row.values():
                        for m in re.finditer(r'https?://[^\s,"\'<>|]+', str(val)):
                            entries.add(m.group(0).rstrip('/'))
                        dm = re.match(r'^([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})$', str(val).strip())
                        if dm: entries.add(dm.group(1))
                return entries
            except Exception:
                f.seek(0)
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line.rstrip('/'))
    return entries

def deduplicate_urls(urls, dedup_file):
    """Remove URLs matching entries in dedup_file. Returns (kept, removed_count)."""
    reference = extract_urls_from_file(dedup_file)
    if not reference:
        print(yellow("[!] Dedup reference file yielded no entries -- skipping."))
        return urls, 0
    kept, removed = [], 0
    for url in urls:
        host = urllib.parse.urlparse(url).netloc
        if url.rstrip('/') in reference or host in reference:
            removed += 1
        else:
            kept.append(url)
    return kept, removed

# ── Utilities ─────────────────────────────────────────────────────────────────
def load_urls(input_file):
    with open(input_file) as f:
        return [l.strip() for l in f
                if l.strip().startswith(("http://","https://"))
                and "nonexistant-dnsjedi" not in l]

def severity_of(findings):
    if not findings: return "Info"
    return "Medium" if any(f.get("cves") for f in findings) else "Low"

def print_finding(url, findings, already_reported, lock):
    if not findings: return
    tag = dim("[REPORTED]") if already_reported else green("[NEW]")
    with lock:
        print(f"\n{'--'*35}")
        print(f"  {tag}  {bold(url)}")
        for f in findings:
            cves = ", ".join(f["cves"][:3]) if f["cves"] else "No CVE"
            print(f"  +-- {cyan(f['component'])} {yellow(f['installed'])}  "
                  f"(min safe: {f['min_safe']}, latest: {f['latest']})")
            print(f"  |   CVEs : {red(cves) if f['cves'] else dim(cves)}")
            print(f"  |   Via  : {dim(f['source'])}")

def progress_bar(done, total, t0, width=35):
    pct = done / total if total else 0
    bar = "#" * int(width * pct) + "-" * (width - int(width * pct))
    elapsed = time.time() - t0
    eta = (elapsed / done * (total - done)) if done else 0
    return f"[{bar}] {done}/{total}  ETA {int(eta//60):02d}:{int(eta%60):02d}"

def prompt_yes_no(q, default="n"):
    hint = "[Y/n]" if default.lower() == "y" else "[y/N]"
    while True:
        try:
            ans = input(f"  {q} {hint} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); return default.lower() == "y"
        if ans == "": return default.lower() == "y"
        if ans in ("y","yes"): return True
        if ans in ("n","no"):  return False
        print("  Please answer y or n.")

def prompt_file(q, must_exist=False):
    while True:
        try:
            ans = input(f"  {q}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); return ""
        if not ans: return ""
        if must_exist and not os.path.exists(ans):
            print(red(f"  File not found: {ans}")); continue
        return ans

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Outdated Component Detector v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python3 outdated-components-detector.py -i httpx-urls.txt

  # Fully automated
  python3 outdated-components-detector.py -i urls.txt -r reported.csv \\
      --dedup prev_scan.csv -o results.csv --threads 50 --new-only

  # Export JSON + CSV, no prompts
  python3 outdated-components-detector.py -i urls.txt \\
      --json-output results.json --no-interactive
        """
    )
    parser.add_argument("-i","--input",       required=True,
                        help="Input file with live URLs (one per line)")
    parser.add_argument("-r","--reported",    default=None,
                        help="CSV of already-reported findings (for NEW vs REPORTED tagging)")
    parser.add_argument("-o","--output",
                        default=f"outdated_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        help="Output CSV filename (default: auto-timestamped)")
    parser.add_argument("--dedup",            default=None, metavar="FILE",
                        help="Deduplicate input URLs against this file before scanning")
    parser.add_argument("--no-dedup",         action="store_true",
                        help="Skip deduplication entirely (suppresses interactive prompt too)")
    parser.add_argument("-t","--threads",     type=int, default=30,
                        help="Concurrent threads (default: 30)")
    parser.add_argument("--timeout",          type=int, default=20,
                        help="HTTP timeout per request in seconds (default: 20)")
    parser.add_argument("--retries",          type=int, default=4,
                        help="Max retries for slow URLs (default: 4)")
    parser.add_argument("--new-only",         action="store_true",
                        help="Only output findings not already in the reported CSV")
    parser.add_argument("--limit",            type=int, default=0,
                        help="Scan only the first N URLs (0 = all)")
    parser.add_argument("--min-findings",     type=int, default=0,
                        help="Min findings per host to include in output (0 = all)")
    parser.add_argument("--json-output",      default=None, metavar="FILE",
                        help="Also write full results to a JSON file")
    parser.add_argument("--no-interactive",   action="store_true",
                        help="Disable all interactive prompts (use flags only)")
    parser.add_argument("--no-color",         action="store_true",
                        help="Disable coloured terminal output")
    args = parser.parse_args()

    global USE_COLOR
    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False

    print(cyan(r"""
  ___      __      __     __          ___
 |_ _|_ _ / _|___ _ __ _ ___ ___    / __| __ __ _ _ _  _ _  ___ _ _
  | || ' \  _/ _ \ '_ \ '_/ -_) -_) \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___|_||_|_| \___/ .__/_| \___\___|  |___/\__\__,_|_||_|_||_\___|_|
                  |_|""") + bold("          Outdated Component Detector v2.0\n"))

    if not os.path.exists(args.input):
        print(red(f"[!] Input file not found: {args.input}")); sys.exit(1)

    all_urls = load_urls(args.input)
    print(f"[*] Loaded {bold(str(len(all_urls)))} live URLs from {cyan(args.input)}")
    print(f"[*] DB: {bold(str(len(COMPONENT_DB)))} JS components, "
          f"{bold(str(len(SERVER_DB)))} server entries, "
          f"{bold(str(len(JS_PATTERNS)))} regex patterns")

    # Interactive dedup prompt
    dedup_file = args.dedup
    if not args.no_dedup and not args.no_interactive and dedup_file is None:
        print()
        print(bold("-- Deduplication --------------------------------------------------"))
        if prompt_yes_no("Deduplicate URLs against a reference/master file?", default="n"):
            dedup_file = prompt_file(
                "Path to reference file (plain list, CSV, httpx/nuclei output)",
                must_exist=True
            )

    if dedup_file and os.path.exists(dedup_file):
        print(f"[*] Deduplicating against: {cyan(dedup_file)}")
        all_urls, removed = deduplicate_urls(all_urls, dedup_file)
        if removed:
            print(f"[*] Removed {yellow(str(removed))} duplicates. "
                  f"{bold(str(len(all_urls)))} remain.")
        else:
            print(green("[*] No duplicates found."))
    elif dedup_file:
        print(yellow(f"[!] Dedup file not found: {dedup_file} -- skipping."))

    # Interactive reported CSV prompt
    if not args.no_interactive and args.reported is None:
        print()
        print(bold("-- Already-Reported CSV -------------------------------------------"))
        if prompt_yes_no("Cross-reference against an already-reported findings CSV?", default="n"):
            args.reported = prompt_file("Path to reported CSV file", must_exist=True)

    reported_set = load_reported(args.reported) if args.reported else set()

    if args.limit:
        all_urls = all_urls[:args.limit]
        print(f"[*] Limiting scan to {args.limit} URLs")

    if not all_urls:
        print(red("[!] No URLs to scan. Exiting.")); sys.exit(0)

    print(f"\n[*] Threads  : {args.threads}")
    print(f"[*] Timeout  : {args.timeout}s  |  Retries: {args.retries}")
    print(f"[*] Output   : {cyan(args.output)}")
    if args.json_output:
        print(f"[*] JSON out : {cyan(args.json_output)}")
    print(f"[*] Scanning {bold(str(len(all_urls)))} URLs ...\n")

    results  = []
    lock     = threading.Lock()
    counters = {"scanned": 0, "vuln": 0, "new": 0, "reported": 0, "unreachable": 0}
    start_ts = time.time()

    shutdown = threading.Event()
    def _sigint(sig, frame):
        print(yellow("\n[!] Interrupted -- flushing results ..."))
        shutdown.set()
    signal.signal(signal.SIGINT, _sigint)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {
            executor.submit(scan_url, url, reported_set, args.timeout, args.retries): url
            for url in all_urls
        }
        for future in as_completed(future_map):
            if shutdown.is_set(): break
            url = future_map[future]
            try:
                res = future.result(timeout=120)
            except Exception:
                with lock: counters["unreachable"] += 1
                continue

            with lock:
                counters["scanned"] += 1
                done = counters["scanned"]
                if done % 50 == 0 or done == len(all_urls):
                    bar = progress_bar(done, len(all_urls), start_ts)
                    print(f"\r  {bar}  Vuln: {counters['vuln']}  "
                          f"Unreachable: {counters['unreachable']}",
                          end="", flush=True)

            if res["status"] == "unreachable":
                with lock: counters["unreachable"] += 1
                continue

            if res["findings"]:
                if args.min_findings and len(res["findings"]) < args.min_findings:
                    continue
                already = is_already_reported(url, reported_set)
                if args.new_only and already: continue
                with lock:
                    counters["vuln"] += 1
                    counters["reported" if already else "new"] += 1
                results.append(res)
                print_finding(url, res["findings"], already, lock)

    print()

    # Write CSV
    scan_date  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fieldnames = ["URL","Component","Installed_Version","Min_Safe_Version",
                  "Latest_Version","CVEs","Detection_Source",
                  "Already_Reported","Severity","Server_Header","Scan_Date"]
    output_rows = []
    for res in results:
        for f in res["findings"]:
            output_rows.append({
                "URL":               res["url"],
                "Component":         f["component"],
                "Installed_Version": f["installed"],
                "Min_Safe_Version":  f["min_safe"],
                "Latest_Version":    f["latest"],
                "CVEs":              "; ".join(f["cves"]),
                "Detection_Source":  f["source"],
                "Already_Reported":  "Yes" if is_already_reported(res["url"], reported_set) else "No",
                "Severity":          severity_of(res["findings"]),
                "Server_Header":     res.get("server_header", ""),
                "Scan_Date":         scan_date,
            })
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(output_rows)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as jf:
            json.dump({"scan_date": scan_date, "input_file": args.input,
                       "dedup_file": dedup_file, "reported_file": args.reported,
                       "summary": counters, "results": results}, jf, indent=2)
        print(f"[*] JSON written: {cyan(args.json_output)}")

    # Summary
    elapsed = time.time() - start_ts
    print(f"\n{'='*70}")
    print(bold("  SCAN COMPLETE -- SUMMARY"))
    print(f"{'='*70}")
    print(f"  Elapsed              : {elapsed:.1f}s")
    print(f"  Total URLs scanned   : {counters['scanned']}")
    print(f"  Unreachable          : {yellow(str(counters['unreachable']))}")
    print(f"  Hosts with findings  : {counters['vuln']}")
    print(f"  +-- NEW findings     : {green(str(counters['new']))}")
    print(f"  +-- Already reported : {dim(str(counters['reported']))}")
    print(f"  Total findings rows  : {bold(str(len(output_rows)))}")
    print(f"  Output CSV           : {cyan(args.output)}")
    print(f"{'='*70}\n")

    comp_count = defaultdict(int)
    for row in output_rows:
        comp_count[row["Component"]] += 1
    if comp_count:
        print(bold("  Top Outdated Components:"))
        for comp, count in sorted(comp_count.items(), key=lambda x: -x[1])[:10]:
            print(f"    {comp:<28} {yellow(str(count)):>4}  {dim('|' * min(count, 30))}")

    print(f"\n  {green('Done!')} Results saved to: {cyan(args.output)}\n")


if __name__ == "__main__":
    main()
