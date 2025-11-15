#!/usr/bin/env python3
"""
Quick Start Example
Process multiple CVEs from a JSON file and output to a single CSV file
"""

import os
import json
import sys
import csv
import argparse
from dotenv import load_dotenv
from src.cve_analyzer import CVEAnalyzer

# Load environment variables
load_dotenv()


def load_vulnerabilities(json_file_path):
    """Load vulnerabilities from JSON file"""
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Error: File '{json_file_path}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format - {e}")
        sys.exit(1)


def process_vulnerabilities(data, analyzer, output_file):
    """Process all vulnerabilities and write to CSV file"""

    csv_rows = []
    total_vulns = 0
    successful_analyses = 0

    # Process fixable CVEs
    print("\n" + "=" * 80)
    print("PROCESSING FIXABLE CVEs")
    print("=" * 80)

    if "fixable_cves" in data:
        for cve_id, vulnerabilities in data["fixable_cves"].items():
            print(f"\n{'─' * 80}")
            print(f"CVE: {cve_id} ({len(vulnerabilities)} instances)")
            print(f"{'─' * 80}")

            for idx, vuln in enumerate(vulnerabilities, 1):
                total_vulns += 1

                component = vuln.get("Package", "unknown")
                version = vuln.get("Version", "unknown")
                vuln_type = vuln.get("Vulnerability Type", "unknown")
                image = vuln.get("Image", "unknown")
                severity = vuln.get("Severity", "unknown")
                summary = vuln.get("Summary", "")

                print(f"\n  [{idx}/{len(vulnerabilities)}] Analyzing {component} v{version}")
                print(f"      Type: {vuln_type} | Severity: {severity} | Image: {image}")

                # Analyze the CVE
                result = analyzer.analyze_cve(
                    cve_id=cve_id,
                    component_name=component,
                    component_version=version,
                    source_type=vuln_type,
                    image_name=image
                )

                if result:
                    successful_analyses += 1
                    print(f"      ✓ Risk: {result.risk_level} | Exploitability: {result.exploitability_score}/10 | Decision: {result.exemption_decision}")

                    # Build CSV row
                    csv_row = {
                        "CVE ID": cve_id,
                        "Fixable": "Yes",
                        "Package": component,
                        "Version": version,
                        "Vulnerability Type": vuln_type,
                        "Image": image,
                        "Original Severity": severity,
                        "Summary": summary,
                        "Risk Level": result.risk_level,
                        "Exploitability Score": result.exploitability_score,
                        "Exploitability Explanation": result.exploitability_explanation,
                        "Active Exploits Exist": "Yes" if result.active_exploits_exist else "No",
                        "Patch Available": "Yes" if result.patch_available else "No",
                        "Patch Details": result.patch_details,
                        "Exemption Decision": result.exemption_decision,
                        "Exemption Justification": result.exemption_justification,
                        "Caveats and Conditions": result.caveats_and_conditions,
                        "Runtime Policy Recommendations": result.runtime_policy_recommendations,
                        "External Controls Recommendations": result.external_controls_recommendations,
                        "Mitigation Strategies": result.mitigation_strategies,
                        "Container Specific Risks": result.container_specific_risks,
                    }
                    csv_rows.append(csv_row)
                else:
                    print(f"      ✗ Analysis failed")
                    csv_row = {
                        "CVE ID": cve_id,
                        "Fixable": "Yes",
                        "Package": component,
                        "Version": version,
                        "Vulnerability Type": vuln_type,
                        "Image": image,
                        "Original Severity": severity,
                        "Summary": summary,
                        "Error": "Analysis failed"
                    }
                    csv_rows.append(csv_row)

    # Process non-fixable CVEs
    print("\n\n" + "=" * 80)
    print("PROCESSING NON-FIXABLE CVEs")
    print("=" * 80)

    if "nonfixable_cves" in data:
        for cve_id, vulnerabilities in data["nonfixable_cves"].items():
            print(f"\n{'─' * 80}")
            print(f"CVE: {cve_id} ({len(vulnerabilities)} instances)")
            print(f"{'─' * 80}")

            for idx, vuln in enumerate(vulnerabilities, 1):
                total_vulns += 1

                component = vuln.get("Package", "unknown")
                version = vuln.get("Version", "unknown")
                vuln_type = vuln.get("Vulnerability Type", "unknown")
                image = vuln.get("Image", "unknown")
                severity = vuln.get("Severity", "unknown")
                summary = vuln.get("Summary", "")

                print(f"\n  [{idx}/{len(vulnerabilities)}] Analyzing {component} v{version}")
                print(f"      Type: {vuln_type} | Severity: {severity} | Image: {image}")

                # Analyze the CVE
                result = analyzer.analyze_cve(
                    cve_id=cve_id,
                    component_name=component,
                    component_version=version,
                    source_type=vuln_type,
                    image_name=image
                )

                if result:
                    successful_analyses += 1
                    print(f"      ✓ Risk: {result.risk_level} | Exploitability: {result.exploitability_score}/10 | Decision: {result.exemption_decision}")

                    # Build CSV row
                    csv_row = {
                        "CVE ID": cve_id,
                        "Fixable": "No",
                        "Package": component,
                        "Version": version,
                        "Vulnerability Type": vuln_type,
                        "Image": image,
                        "Original Severity": severity,
                        "Summary": summary,
                        "Risk Level": result.risk_level,
                        "Exploitability Score": result.exploitability_score,
                        "Exploitability Explanation": result.exploitability_explanation,
                        "Active Exploits Exist": "Yes" if result.active_exploits_exist else "No",
                        "Patch Available": "Yes" if result.patch_available else "No",
                        "Patch Details": result.patch_details,
                        "Exemption Decision": result.exemption_decision,
                        "Exemption Justification": result.exemption_justification,
                        "Caveats and Conditions": result.caveats_and_conditions,
                        "Runtime Policy Recommendations": result.runtime_policy_recommendations,
                        "External Controls Recommendations": result.external_controls_recommendations,
                        "Mitigation Strategies": result.mitigation_strategies,
                        "Container Specific Risks": result.container_specific_risks,
                    }
                    csv_rows.append(csv_row)
                else:
                    print(f"      ✗ Analysis failed")
                    csv_row = {
                        "CVE ID": cve_id,
                        "Fixable": "No",
                        "Package": component,
                        "Version": version,
                        "Vulnerability Type": vuln_type,
                        "Image": image,
                        "Original Severity": severity,
                        "Summary": summary,
                        "Error": "Analysis failed"
                    }
                    csv_rows.append(csv_row)

    # Write all results to CSV file
    if csv_rows:
        # Get all unique field names from all rows
        fieldnames = []
        for row in csv_rows:
            for key in row.keys():
                if key not in fieldnames:
                    fieldnames.append(key)

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)

    return {
        "total_cves_processed": total_vulns,
        "successful_analyses": successful_analyses,
        "failed_analyses": total_vulns - successful_analyses
    }


def main(input_file: str, output_file: str):
    """Main execution function"""

    print("\n" + "=" * 80)
    print("CVE VULNERABILITY ANALYSIS TOOL - BATCH PROCESSOR")
    print("=" * 80)

    print(f"\nInput File:  {input_file}")
    print(f"Output File: {output_file}")

    # Initialize the analyzer
    print("\n1. Initializing CVE Analyzer...")
    analyzer = CVEAnalyzer(
        aws_region=os.getenv("AWS_REGION", "us-east-1"),
        model_id=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0"),
        nvd_api_key=os.getenv("NVD_API_KEY"),
    )
    print("   ✓ Analyzer initialized")

    # Load vulnerabilities
    print("\n2. Loading vulnerabilities from JSON file...")
    data = load_vulnerabilities(input_file)

    fixable_count = sum(len(vulns) for vulns in data.get("fixable_cves", {}).values())
    nonfixable_count = sum(len(vulns) for vulns in data.get("nonfixable_cves", {}).values())
    total_cves = len(data.get("fixable_cves", {})) + len(data.get("nonfixable_cves", {}))

    print(f"   ✓ Loaded {total_cves} unique CVEs")
    print(f"     - Fixable: {len(data.get('fixable_cves', {}))} CVEs ({fixable_count} instances)")
    print(f"     - Non-fixable: {len(data.get('nonfixable_cves', {}))} CVEs ({nonfixable_count} instances)")

    # Process all vulnerabilities
    print("\n3. Processing vulnerabilities...")
    results = process_vulnerabilities(data, analyzer, output_file)

    # Print summary
    print("\n\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"\nTotal Vulnerabilities Processed: {results['total_cves_processed']}")
    print(f"Successful Analyses: {results['successful_analyses']}")
    print(f"Failed Analyses: {results['failed_analyses']}")
    print(f"\nResults saved to: {output_file}")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE Vulnerability Analysis Tool - Batch Processor"
    )
    parser.add_argument(
        "--input-json-file",
        help="Path to input vulnerabilities JSON file",
        required=True
    )
    parser.add_argument(
        "--output-csv-file",
        help="Path to output CSV file",
        default="cve_analysis_results.csv"
    )
    args = parser.parse_args()

    try:
        main(args.input_json_file, args.output_csv_file)
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        print("\nTroubleshooting:")
        print("  1. Ensure AWS credentials are configured: aws configure")
        print("  2. Enable Bedrock model access in AWS Console")
        print("  3. Check .env file configuration")
        print("  4. Verify JSON file format matches expected structure")
        sys.exit(1)
