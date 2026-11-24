#!/usr/bin/env python3
"""Pull CVE records from the NVD CVE API 2.0 and save one flat CSV row per CVE.

Usage (from this folder):
    python pull_nvd.py                                   # default: CVEs published 2023-01-01 .. 2024-12-31
    python pull_nvd.py --start 2022-01-01 --end 2024-12-31 --out nvd_cves.csv

Optional: a free NVD API key makes the pull about 10x faster. Request one at
https://nvd.nist.gov/developers/request-an-api-key and set it before running:
    export NVD_API_KEY="your-key"          (Mac/Linux)
    $env:NVD_API_KEY="your-key"            (Windows PowerShell)

Data: NVD CVE API 2.0, https://nvd.nist.gov/developers/vulnerabilities
This product uses data from the NVD API but is not endorsed or certified by the NVD.

How the pull works
- The API caps any date-range filter at 120 consecutive days, so we walk through the period in windows.
- Each window is read in pages of up to 2,000 CVEs (the API's page-size limit).
- Without an API key the limit is 5 requests per rolling 30 seconds, with a key 50 per 30 seconds,
  so the script pauses between requests and retries politely if it is throttled.
- Progress is saved after every window, so a failed run can be restarted with --resume. (A window that was
  interrupted may be re-read, so drop duplicate CVE IDs when you load the file; the notebook does this.)
"""
import argparse
import csv
import os
import sys
import time
from collections import Counter
from datetime import date, datetime, timedelta

import requests

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW_DAYS = 100          # comfortably under the 120-day maximum
PAGE_SIZE = 2000           # the API's maximum page size

COLUMNS = [
    "cve_id", "published", "source", "vuln_status", "n_references",
    "cwe_primary", "cwe_all", "vendor", "cpe_part",
    "cvss_version", "base_score", "base_severity", "attack_vector", "attack_complexity",
    "privileges_required", "user_interaction", "scope", "confidentiality", "integrity", "availability",
]


# ------------------------------------------------------------------ flattening one CVE record
def _primary_or_first(items):
    """NVD lists a 'Primary' (NVD analyst) entry and sometimes 'Secondary' ones; prefer Primary."""
    if not items:
        return None
    for item in items:
        if item.get("type") == "Primary":
            return item
    return items[0]


def flatten_cve(cve):
    """Turn one nested NVD 'cve' object into a flat dict (or None if it should be skipped)."""
    if cve.get("vulnStatus") == "Rejected":
        return None

    row = {c: "" for c in COLUMNS}
    row["cve_id"] = cve.get("id", "")
    row["published"] = cve.get("published", "")
    row["source"] = cve.get("sourceIdentifier", "")
    row["vuln_status"] = cve.get("vulnStatus", "")
    row["n_references"] = len(cve.get("references", []))

    # CVSS v3.x metrics: prefer v3.1, fall back to v3.0. (v2 has no "Critical" rating, and we skip v4.)
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entry = _primary_or_first(metrics.get(key, []))
        if entry:
            d = entry.get("cvssData", {})
            row.update({
                "cvss_version": d.get("version", ""),
                "base_score": d.get("baseScore", ""),
                "base_severity": d.get("baseSeverity", ""),
                "attack_vector": d.get("attackVector", ""),
                "attack_complexity": d.get("attackComplexity", ""),
                "privileges_required": d.get("privilegesRequired", ""),
                "user_interaction": d.get("userInteraction", ""),
                "scope": d.get("scope", ""),
                "confidentiality": d.get("confidentialityImpact", ""),
                "integrity": d.get("integrityImpact", ""),
                "availability": d.get("availabilityImpact", ""),
            })
            break

    # Weakness type (CWE). A CVE can list several; keep the primary one and the full list.
    weaknesses = [w for w in cve.get("weaknesses", [])]
    primary = _primary_or_first(weaknesses)
    all_cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang", "en") == "en" and desc.get("value"):
                all_cwes.append(desc["value"])
    if primary:
        for desc in primary.get("description", []):
            if desc.get("lang", "en") == "en" and desc.get("value"):
                row["cwe_primary"] = desc["value"]
                break
    row["cwe_all"] = "|".join(dict.fromkeys(all_cwes))

    # Vendor comes from the CPE strings, e.g. "cpe:2.3:o:suse:suse_linux:6.0:*:*..." -> part "o", vendor "suse".
    vendors, parts = Counter(), Counter()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                pieces = match.get("criteria", "").split(":")
                if len(pieces) > 4 and pieces[0] == "cpe":
                    parts[pieces[2]] += 1
                    vendors[pieces[3]] += 1
    if vendors:
        row["vendor"] = vendors.most_common(1)[0][0]
        row["cpe_part"] = parts.most_common(1)[0][0]
    return row


# ------------------------------------------------------------------ talking to the API
def fetch_page(session, url, params, headers, max_tries=6):
    """GET one page, retrying with a growing wait if the API throttles us or has a hiccup."""
    for attempt in range(1, max_tries + 1):
        try:
            resp = session.get(url, params=params, headers=headers, timeout=60)
        except requests.RequestException as err:
            wait = 10 * attempt
            print(f"   network problem ({err.__class__.__name__}); retrying in {wait}s")
            time.sleep(wait)
            continue
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429, 503):
            wait = 15 * attempt
            print(f"   HTTP {resp.status_code} (throttled or busy); waiting {wait}s (try {attempt}/{max_tries})")
            time.sleep(wait)
            continue
        if resp.status_code == 404:
            # NVD answers 404 for a rejected request, e.g. an invalid or not-yet-activated API key.
            why = resp.headers.get("message", "no explanation sent")
            sys.exit(f"NVD rejected the request (404): {why}\n"
                     "If this mentions the API key: check you pasted it correctly and clicked the activation link "
                     "in the NVD email. To try without a key (slower), run:  unset NVD_API_KEY")
        resp.raise_for_status()          # any other error is a real problem: stop and show it
    raise RuntimeError(f"Gave up after {max_tries} tries: {resp.status_code if 'resp' in locals() else 'no response'}")


def windows(start, end):
    """Split [start, end] into consecutive windows of WINDOW_DAYS days."""
    cur = start
    while cur <= end:
        stop = min(cur + timedelta(days=WINDOW_DAYS - 1), end)
        yield cur, stop
        cur = stop + timedelta(days=1)


def stamp(d, end_of_day=False):
    return d.strftime("%Y-%m-%dT") + ("23:59:59.999" if end_of_day else "00:00:00.000")


def pull(start, end, out_path, base_url=BASE_URL, pause=None, resume=False):
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    if pause is None:
        pause = 0.7 if api_key else 6.5          # stay under 50 / 5 requests per 30 seconds
    print("API key found: fast mode" if api_key else "No API key: slow mode (about 6.5 s per request)")

    done_windows = set()
    mode = "w"
    marker = out_path + ".progress"
    if resume and os.path.exists(out_path):
        mode = "a"
        if os.path.exists(marker):
            done_windows = set(open(marker).read().split())
    elif os.path.exists(marker):
        os.remove(marker)                         # a fresh pull must not inherit an old progress file
    session = requests.Session()
    total_rows = 0
    with open(out_path, mode, newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        if mode == "w":
            writer.writeheader()
        for w_start, w_end in windows(start, end):
            tag = w_start.isoformat()
            if tag in done_windows:
                print(f"{tag}: already done, skipping")
                continue
            index, window_rows = 0, 0
            while True:
                params = {"pubStartDate": stamp(w_start), "pubEndDate": stamp(w_end, True),
                          "resultsPerPage": PAGE_SIZE, "startIndex": index}
                data = fetch_page(session, base_url, params, headers)
                vulns = data.get("vulnerabilities", [])
                for item in vulns:
                    row = flatten_cve(item["cve"])
                    if row:
                        writer.writerow(row)
                        window_rows += 1
                index += len(vulns)
                total = data.get("totalResults", 0)
                time.sleep(pause)
                if not vulns or index >= total:
                    break
            fh.flush()
            total_rows += window_rows
            with open(marker, "a") as marker_fh:
                marker_fh.write(tag + "\n")
            print(f"{w_start} to {w_end}: {window_rows} CVEs saved ({total_rows} so far)")
    return total_rows


def main():
    parser = argparse.ArgumentParser(description="Pull CVEs from the NVD API into a flat CSV.")
    parser.add_argument("--start", default="2023-01-01", help="first publication date, YYYY-MM-DD")
    parser.add_argument("--end", default="2024-12-31", help="last publication date, YYYY-MM-DD")
    parser.add_argument("--out", default="nvd_cves.csv")
    parser.add_argument("--resume", action="store_true", help="continue a pull that stopped part-way")
    parser.add_argument("--base-url", default=BASE_URL, help=argparse.SUPPRESS)
    parser.add_argument("--pause", type=float, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    start = datetime.strptime(args.start, "%Y-%m-%d").date()
    end = datetime.strptime(args.end, "%Y-%m-%d").date()
    if end < start:
        sys.exit("--end must not be before --start")
    n = pull(start, end, args.out, args.base_url, args.pause, args.resume)
    if os.path.exists(args.out + ".progress"):
        os.remove(args.out + ".progress")        # finished: no progress file needed
    print(f"Done: {n} CVEs written to {args.out}")


if __name__ == "__main__":
    main()
