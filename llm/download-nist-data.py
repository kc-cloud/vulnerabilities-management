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

def extract_cve_examples(cve_record):
    """
    Convert a single CVE record to one training example.
    """
    cve_id = cve_record.get("cve", {}).get("id", "UNKNOWN")
    descriptions = cve_record.get("cve", {}).get("descriptions", [])
    en_desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
    
    metrics = cve_record.get("cve", {}).get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
    base_score = cvss_v3.get("baseScore", "N/A")
    severity = cvss_v3.get("baseSeverity", "N/A")
    
    input_text = f"CVE ID: {cve_id}\nSummary: {en_desc}\nCVSS Score: {base_score}, Severity: {severity}\nQuestion: Describe the vulnerability."
    target_text = en_desc

    return {"input": input_text, "target": target_text}

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
    for vuln in vulnerabilities:
        example = extract_cve_examples(vuln)
        all_examples.append(example)

    # Delete raw JSON after processing
    json_path.unlink()

print(f"[INFO] Writing {len(all_examples)} examples to {OUTPUT_FILE}")
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for ex in all_examples:
        f.write(json.dumps(ex, ensure_ascii=False) + "\n")

print("[DONE] JSONL file ready for training:", OUTPUT_FILE)
