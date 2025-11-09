#!/usr/bin/env python3
"""
Quick Start Example
Simple example showing how to use the CVE Analyzer
"""

import os
from dotenv import load_dotenv
from src.cve_analyzer import CVEAnalyzer

# Load environment variables
load_dotenv()


def main():
    """Quick start example"""

    print("CVE Vulnerability Analysis Tool - Quick Start")
    print("=" * 60)

    # Initialize the analyzer
    print("\n1. Initializing CVE Analyzer...")
    analyzer = CVEAnalyzer(
        aws_region=os.getenv("AWS_REGION", "us-east-1"),
        model_id=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0"),
        nvd_api_key=os.getenv("NVD_API_KEY"),
    )
    print("   ✓ Analyzer initialized")

    # Example CVE to analyze
    cve_id = "CVE-2024-3094"  # Famous xz-utils backdoor
    component = "xz-utils"
    version = "5.6.0"
    source = "OS"
    image = "ubuntu:22.04"

    print(f"\n2. Analyzing {cve_id}...")
    print(f"   Component: {component} v{version}")
    print(f"   Source: {source}")
    print(f"   Image: {image}")

    # Perform analysis
    result = analyzer.analyze_cve(
        cve_id=cve_id,
        component_name=component,
        component_version=version,
        source_type=source,
        image_name=image,
    )

    if result:
        print("\n3. Analysis Complete!")
        print("=" * 60)
        print(f"\n   CVE ID: {result.cve_id}")
        print(f"   Risk Level: {result.risk_level}")
        print(f"   Exploitability: {result.exploitability_score}/10")
        print(f"   Active Exploits: {'YES' if result.active_exploits_exist else 'NO'}")
        print(f"\n   CIA Impact:")
        print(f"     - Confidentiality: {result.cia_impact.get('confidentiality', 'N/A')}")
        print(f"     - Integrity: {result.cia_impact.get('integrity', 'N/A')}")
        print(f"     - Availability: {result.cia_impact.get('availability', 'N/A')}")
        print(f"\n   Patch Available: {'YES' if result.patch_available else 'NO'}")
        print(f"\n   Exemption Decision: {result.exemption_decision}")
        print(f"\n   Justification:")
        print(f"     {result.exemption_justification}")
        print(f"\n   Recommended Controls:")
        print(f"     {result.runtime_policy_recommendations}")

        # Save to JSON
        json_output = result.model_dump_json(indent=2)
        output_file = f"{cve_id}_analysis.json"
        with open(output_file, "w") as f:
            f.write(json_output)
        print(f"\n4. Full analysis saved to: {output_file}")

    else:
        print("\n   ✗ Analysis failed")

    print("\n" + "=" * 60)
    print("Quick start complete!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        print("\nTroubleshooting:")
        print("  1. Ensure AWS credentials are configured: aws configure")
        print("  2. Enable Bedrock model access in AWS Console")
        print("  3. Check .env file configuration")
