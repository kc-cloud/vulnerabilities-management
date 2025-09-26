# prepare_and_generate_nvd_jsonl.py
import os
import json
import gzip
import shutil
import requests
from pathlib import Path
from datetime import datetime

# -------------------------
# CONFIG
# -------------------------
NVD_DIR = Path("./nvd_feeds")
NVD_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = Path("./nvd_train.jsonl")
YEARS = list(range(datetime.now().year - 10, datetime.now().year))  # last 10 years

# -------------------------
# FUNCTIONS
# -------------------------
def download_nvd_json(year):
    url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
    gz_path = NVD_DIR / f"nvdcve-2.0-{year}.json.gz"
    json_path = NVD_DIR / f"nvdcve-2.0-{year}.json"

    if json_path.exists():
        print(f"[INFO] {json_path} already exists, skipping download.")
        return json_path

    print(f"[INFO] Downloading {url} ...")
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open(gz_path, "wb") as f:
        shutil.copyfileobj(r.raw, f)

    # Extract
    print(f"[INFO] Extracting {gz_path} ...")
    with gzip.open(gz_path, "rb") as f_in, open(json_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)

    # Remove .gz file
    gz_path.unlink()
    return json_path


def get_cvss_data(metrics: dict):
    """
    Try CVSS v3.1 -> v3.0 -> v2 in order, return (score, severity).
    """
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return data.get("baseScore", "N/A"), data.get("baseSeverity", "N/A")
    return "N/A", "N/A"


def extract_cve_examples(cve_record):
    """
    Convert a single CVE record to multiple training examples.
    """
    examples = []

    cve_id = cve_record.get("cve", {}).get("id", "UNKNOWN")
    descriptions = cve_record.get("cve", {}).get("descriptions", [])
    en_desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    metrics = cve_record.get("cve", {}).get("metrics", {})
    base_score, severity = get_cvss_data(metrics)

    # Mitigation info can sometimes be in references
    references = cve_record.get("cve", {}).get("references", [])
    mitigation_refs = [r.get("url") for r in references if r.get("tags") and "Mitigation" in r["tags"]]
    mitigation_text = (
        "Mitigation information is not explicitly provided."
        if not mitigation_refs
        else "Refer to: " + "; ".join(mitigation_refs)
    )

    # Q1: Severity
    examples.append({
        "input": f"What is the severity of {cve_id}?",
        "target": f"The severity of {cve_id} is {severity}."
    })

    # Q2: Risk score
    examples.append({
        "input": f"What is the risk score of {cve_id}?",
        "target": f"The CVSS base score of {cve_id} is {base_score}."
    })

    # Q3: Summarize
    examples.append({
        "input": f"Summarize {cve_id}.",
        "target": en_desc or "No summary available."
    })

    # Q4: Mitigation
    examples.append({
        "input": f"How can I mitigate {cve_id}?",
        "target": mitigation_text
    })

    return examples, (cve_id, base_score, severity)


# -------------------------
# MAIN
# -------------------------
all_examples = []

for year in YEARS:
    try:
        json_path = download_nvd_json(year)
    except Exception as e:
        print(f"[ERROR] Failed to download or extract {year}: {e}")
        continue

    print(f"[INFO] Processing {json_path} ...")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", [])

    # Track per-year stats
    year_cves = []

    for vuln in vulnerabilities:
        examples, summary_info = extract_cve_examples(vuln)
        all_examples.extend(examples)
        year_cves.append(summary_info)  # (cve_id, score, severity)

    # Aggregate Q&A for this year
    if year_cves:
        # Convert score safely
        scored = [(cve, float(score) if isinstance(score, (int, float)) or str(score).replace('.', '', 1).isdigit() else -1, sev)
                  for cve, score, sev in year_cves]

        # Top 10 critical
        criticals = [x for x in scored if x[2].upper() == "CRITICAL"]
        criticals_sorted = sorted(criticals, key=lambda x: x[1], reverse=True)
        top10 = [c[0] for c in criticals_sorted[:10]]
        top10_text = ", ".join(top10) if top10 else "No critical CVEs found."

        all_examples.append({
            "input": f"What are the top 10 critical CVEs found in year {year}?",
            "target": top10_text
        })

        # Count high + critical
        high_count = sum(1 for _, _, sev in scored if str(sev).upper() == "HIGH")
        crit_count = sum(1 for _, _, sev in scored if str(sev).upper() == "CRITICAL")
        all_examples.append({
            "input": f"Can you give me the count of high and critical severity CVEs found in {year}?",
            "target": f"In {year}, there were {high_count} high severity CVEs and {crit_count} critical severity CVEs."
        })

    # Delete raw JSON after processing
    json_path.unlink()

print(f"[INFO] Writing {len(all_examples)} examples to {OUTPUT_FILE}")
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for ex in all_examples:
        f.write(json.dumps(ex, ensure_ascii=False) + "\n")

print("[DONE] JSONL file ready for training:", OUTPUT_FILE)
