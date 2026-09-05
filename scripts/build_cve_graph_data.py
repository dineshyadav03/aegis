"""Builds the local CVE/CWE/CAPEC/ATT&CK dataset for GraphRAG (Phase 3).

Sources (verified live before writing this script, 2026-09-05):
  - NVD CVE API v2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0),
    filtered by CWE ID. No API key required for this modest, demo-scale pull
    (public rate limit: 5 requests/30s).
  - CAPEC's official "ATT&CK Related Patterns" CSV view
    (https://capec.mitre.org/data/csv/658.csv.zip) — confirmed to contain
    both `Related Weaknesses` (CWE IDs) and `Taxonomy Mappings` (real ATT&CK
    technique IDs) per attack pattern. There is no direct CWE-to-ATT&CK
    mapping published anywhere; CAPEC is the real bridge
    (CVE -> CWE -> CAPEC -> ATT&CK), confirmed via live research.

Output: data/cve_graph_data.json — a cached intermediate dataset so the
Neo4j-loading step (scripts/load_cve_graph.py) doesn't re-fetch from NVD/
CAPEC on every run, and so this stays reproducible/inspectable.
"""

from __future__ import annotations

import csv
import io
import json
import time
import zipfile
from pathlib import Path

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CAPEC_ATTACK_VIEW_URL = "https://capec.mitre.org/data/csv/658.csv.zip"

# CWEs matched to Aegis's own detection patterns (tools/detection.py, tools/classification.py)
RELEVANT_CWES = {
    "CWE-307": "brute_force",              # Improper Restriction of Excessive Authentication Attempts
    "CWE-269": "privilege_escalation",     # Improper Privilege Management
    "CWE-287": "foreign_login",            # Improper Authentication
    "CWE-200": "offhours_large_download",  # Exposure of Sensitive Information to an Unauthorized Actor
}

CVES_PER_CWE = 15
NVD_REQUEST_DELAY_SECONDS = 6  # public rate limit is 5 req/30s; stay well under it


def fetch_cves_for_cwe(cwe_id: str) -> list[dict]:
    response = requests.get(
        NVD_API,
        params={"cweId": cwe_id, "resultsPerPage": CVES_PER_CWE},
        timeout=15,
    )
    response.raise_for_status()
    data = response.json()

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
        )
        cvss = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key)
            if metrics:
                cvss = metrics[0]["cvssData"].get("baseScore")
                break
        cves.append(
            {
                "id": cve["id"],
                "description": description,
                "cvss_score": cvss,
                "published": cve.get("published"),
                "cwe_id": cwe_id,
            }
        )
    return cves


def fetch_capec_attack_mappings() -> list[dict]:
    """Downloads CAPEC's ATT&CK-related view and extracts CWE<->CAPEC<->ATT&CK edges."""
    response = requests.get(CAPEC_ATTACK_VIEW_URL, timeout=30)
    response.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        csv_name = next(n for n in zf.namelist() if n.endswith(".csv"))
        raw = zf.read(csv_name).decode("utf-8")

    # The file starts with a stray leading quote before the header row.
    raw = raw.lstrip("'")
    reader = csv.DictReader(io.StringIO(raw))

    mappings = []
    for row in reader:
        related_weaknesses = row.get("Related Weaknesses", "") or ""
        taxonomy = row.get("Taxonomy Mappings", "") or ""
        if "ENTRY ID:" not in taxonomy:
            continue

        cwe_ids = [f"CWE-{c}" for c in related_weaknesses.split("::") if c.strip().isdigit()]
        if not any(c in RELEVANT_CWES for c in cwe_ids):
            continue

        for entry in taxonomy.split("::"):
            if "ENTRY ID:" not in entry:
                continue
            try:
                entry_id = entry.split("ENTRY ID:")[1].split(":ENTRY NAME:")[0].strip()
                entry_name = entry.split("ENTRY NAME:")[1].strip()
            except IndexError:
                continue
            mappings.append(
                {
                    "capec_id": f"CAPEC-{row['ID']}",
                    "capec_name": row["Name"],
                    "cwe_ids": [c for c in cwe_ids if c in RELEVANT_CWES],
                    "attack_id": entry_id,
                    "attack_name": entry_name,
                }
            )
    return mappings


def main() -> None:
    print("Fetching CVEs from NVD (no API key — pacing requests)...")
    all_cves = []
    for i, cwe_id in enumerate(RELEVANT_CWES):
        print(f"  {cwe_id} ({RELEVANT_CWES[cwe_id]})...")
        all_cves.extend(fetch_cves_for_cwe(cwe_id))
        if i < len(RELEVANT_CWES) - 1:
            time.sleep(NVD_REQUEST_DELAY_SECONDS)

    print(f"Fetched {len(all_cves)} CVEs.")

    print("Fetching CAPEC ATT&CK-related patterns...")
    capec_mappings = fetch_capec_attack_mappings()
    print(f"Fetched {len(capec_mappings)} CWE->CAPEC->ATT&CK mapping rows.")

    output = {
        "cwes": [{"id": cwe_id, "detection_pattern": pattern} for cwe_id, pattern in RELEVANT_CWES.items()],
        "cves": all_cves,
        "capec_attack_mappings": capec_mappings,
    }

    out_path = Path("data") / "cve_graph_data.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Wrote {out_path} ({len(all_cves)} CVEs, {len(capec_mappings)} CAPEC/ATT&CK mappings).")


if __name__ == "__main__":
    main()
