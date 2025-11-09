#!/usr/bin/env python3
"""
Quick Start Example
Process multiple CVEs from a JSON file and output to a single analysis file
"""

import os
import json
import sys
from datetime import datetime
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
    """Process all vulnerabilities and write to output file"""

    all_results = {
        "analysis_timestamp": datetime.now().isoformat(),
        "total_cves_processed": 0,
        "fixable_cves": {},
        "nonfixable_cves": {}
    }

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

            all_results["fixable_cves"][cve_id] = {
                "instances": [],
                "total_instances": len(vulnerabilities)
            }

            for idx, vuln in enumerate(vulnerabilities, 1):
                total_vulns += 1

                component = vuln.get("Package", "unknown")
                version = vuln.get("Version", "unknown")
                vuln_type = vuln.get("Vulnerability Type", "unknown")
                image = vuln.get("Image", "unknown")
                severity = vuln.get("Severity", "unknown")

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

                    # Add to results
                    instance_data = {
                        "package": component,
                        "version": version,
                        "vulnerability_type": vuln_type,
                        "image": image,
                        "severity": severity,
                        "summary": vuln.get("Summary", ""),
                        "analysis": result.model_dump()
                    }
                    all_results["fixable_cves"][cve_id]["instances"].append(instance_data)
                else:
                    print(f"      ✗ Analysis failed")
                    all_results["fixable_cves"][cve_id]["instances"].append({
                        "package": component,
                        "version": version,
                        "error": "Analysis failed"
                    })

    # Process non-fixable CVEs
    print("\n\n" + "=" * 80)
    print("PROCESSING NON-FIXABLE CVEs")
    print("=" * 80)

    if "nonfixable_cves" in data:
        for cve_id, vulnerabilities in data["nonfixable_cves"].items():
            print(f"\n{'─' * 80}")
            print(f"CVE: {cve_id} ({len(vulnerabilities)} instances)")
            print(f"{'─' * 80}")

            all_results["nonfixable_cves"][cve_id] = {
                "instances": [],
                "total_instances": len(vulnerabilities)
            }

            for idx, vuln in enumerate(vulnerabilities, 1):
                total_vulns += 1

                component = vuln.get("Package", "unknown")
                version = vuln.get("Version", "unknown")
                vuln_type = vuln.get("Vulnerability Type", "unknown")
                image = vuln.get("Image", "unknown")
                severity = vuln.get("Severity", "unknown")

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

                    # Add to results
                    instance_data = {
                        "package": component,
                        "version": version,
                        "vulnerability_type": vuln_type,
                        "image": image,
                        "severity": severity,
                        "summary": vuln.get("Summary", ""),
                        "analysis": result.model_dump()
                    }
                    all_results["nonfixable_cves"][cve_id]["instances"].append(instance_data)
                else:
                    print(f"      ✗ Analysis failed")
                    all_results["nonfixable_cves"][cve_id]["instances"].append({
                        "package": component,
                        "version": version,
                        "error": "Analysis failed"
                    })

    # Update summary stats
    all_results["total_cves_processed"] = total_vulns
    all_results["successful_analyses"] = successful_analyses
    all_results["failed_analyses"] = total_vulns - successful_analyses

    # Write all results to output file
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)

    return all_results


def main():
    """Main execution function"""

    print("\n" + "=" * 80)
    print("CVE VULNERABILITY ANALYSIS TOOL - BATCH PROCESSOR")
    print("=" * 80)

    # Check for input file argument
    if len(sys.argv) < 2:
        print("\nUsage: python quick_start.py <vulnerabilities.json> [output_file.json]")
        print("\nExample:")
        print("  python quick_start.py vulnerabilities.json")
        print("  python quick_start.py vulnerabilities.json cve_analysis_results.json")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "cve_analysis_results.json"

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
    try:
        main()
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
