"""
NIST NVD API Client
Queries CVE data from the National Vulnerability Database
"""

import requests
import time
from typing import Dict, Optional, Any
from datetime import datetime


class NVDClient:
    """Client for querying NIST National Vulnerability Database API v2.0"""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD API client

        Args:
            api_key: Optional API key for higher rate limits (50 requests/30 seconds)
                    Without key: 5 requests/30 seconds
        """
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve detailed CVE information

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')

        Returns:
            Dictionary containing CVE data or None if not found
        """
        try:
            params = {"cveId": cve_id}
            response = self.session.get(self.BASE_URL, params=params, timeout=30)

            # Handle rate limiting
            if response.status_code == 403:
                print("Rate limit exceeded. Waiting 30 seconds...")
                time.sleep(30)
                response = self.session.get(self.BASE_URL, params=params, timeout=30)

            response.raise_for_status()
            data = response.json()

            if data.get("totalResults", 0) == 0:
                print(f"CVE {cve_id} not found in NVD database")
                return None

            return data["vulnerabilities"][0]

        except requests.exceptions.RequestException as e:
            print(f"Error querying NVD API: {e}")
            return None

    def extract_cve_details(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and structure relevant CVE information

        Args:
            cve_data: Raw CVE data from NVD API

        Returns:
            Structured dictionary with key CVE details
        """
        if not cve_data:
            return {}

        cve = cve_data.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        # Extract CVSS scores (prefer v3.1, fallback to v3.0, then v2.0)
        metrics = cve.get("metrics", {})
        cvss_data = {}

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_data = {
                "version": "3.1",
                "baseScore": cvss_v3.get("baseScore", 0.0),
                "baseSeverity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                "attackVector": cvss_v3.get("attackVector", "UNKNOWN"),
                "attackComplexity": cvss_v3.get("attackComplexity", "UNKNOWN"),
                "privilegesRequired": cvss_v3.get("privilegesRequired", "UNKNOWN"),
                "userInteraction": cvss_v3.get("userInteraction", "UNKNOWN"),
                "scope": cvss_v3.get("scope", "UNKNOWN"),
                "confidentialityImpact": cvss_v3.get("confidentialityImpact", "NONE"),
                "integrityImpact": cvss_v3.get("integrityImpact", "NONE"),
                "availabilityImpact": cvss_v3.get("availabilityImpact", "NONE"),
                "vectorString": cvss_v3.get("vectorString", ""),
            }
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_data = {
                "version": "3.0",
                "baseScore": cvss_v3.get("baseScore", 0.0),
                "baseSeverity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                "attackVector": cvss_v3.get("attackVector", "UNKNOWN"),
                "attackComplexity": cvss_v3.get("attackComplexity", "UNKNOWN"),
                "privilegesRequired": cvss_v3.get("privilegesRequired", "UNKNOWN"),
                "userInteraction": cvss_v3.get("userInteraction", "UNKNOWN"),
                "scope": cvss_v3.get("scope", "UNKNOWN"),
                "confidentialityImpact": cvss_v3.get("confidentialityImpact", "NONE"),
                "integrityImpact": cvss_v3.get("integrityImpact", "NONE"),
                "availabilityImpact": cvss_v3.get("availabilityImpact", "NONE"),
                "vectorString": cvss_v3.get("vectorString", ""),
            }
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_data = {
                "version": "2.0",
                "baseScore": cvss_v2.get("baseScore", 0.0),
                "baseSeverity": self._cvss_v2_severity(cvss_v2.get("baseScore", 0.0)),
                "attackVector": cvss_v2.get("accessVector", "UNKNOWN"),
                "attackComplexity": cvss_v2.get("accessComplexity", "UNKNOWN"),
                "confidentialityImpact": cvss_v2.get("confidentialityImpact", "NONE"),
                "integrityImpact": cvss_v2.get("integrityImpact", "NONE"),
                "availabilityImpact": cvss_v2.get("availabilityImpact", "NONE"),
                "vectorString": cvss_v2.get("vectorString", ""),
            }

        # Extract descriptions
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        # Extract CWE (weakness type)
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        if weaknesses:
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe_ids.append(desc["value"])

        # Extract references
        references = cve.get("references", [])
        reference_urls = [ref.get("url", "") for ref in references[:5]]  # Limit to first 5

        # Extract published and modified dates
        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss": cvss_data,
            "cwe_ids": cwe_ids,
            "references": reference_urls,
            "published_date": published,
            "last_modified_date": last_modified,
        }

    @staticmethod
    def _cvss_v2_severity(score: float) -> str:
        """Convert CVSS v2 score to severity rating"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
