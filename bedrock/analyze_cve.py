#!/usr/bin/env python3
"""
CVE Exemption Analysis Tool
Main script for analyzing CVE exemption requests
"""

import os
import sys
import json
import argparse
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from src.cve_analyzer import CVEAnalyzer


# Load environment variables
load_dotenv()

console = Console()


def print_analysis_result(result):
    """Pretty print the analysis result"""

    if not result:
        console.print("[red]Analysis failed or CVE not found[/red]")
        return

    # Create header panel
    header = Panel(
        f"[bold cyan]{result.cve_id}[/bold cyan]\n"
        f"Risk Level: [bold {'red' if result.risk_level in ['CRITICAL', 'HIGH'] else 'yellow' if result.risk_level == 'MEDIUM' else 'green'}]{result.risk_level}[/bold]\n"
        f"Exploitability: {result.exploitability_score}/10\n"
        f"Active Exploits: [bold {'red' if result.active_exploits_exist else 'green'}]{'YES' if result.active_exploits_exist else 'NO'}[/bold]",
        title="CVE Analysis Summary",
        border_style="cyan",
    )
    console.print(header)

    # Impact table
    console.print("\n[bold]CIA Impact:[/bold]")
    impact_table = Table(show_header=True, header_style="bold magenta")
    impact_table.add_column("Confidentiality", style="cyan")
    impact_table.add_column("Integrity", style="cyan")
    impact_table.add_column("Availability", style="cyan")
    impact_table.add_row(
        result.cia_impact.get("confidentiality", "N/A"),
        result.cia_impact.get("integrity", "N/A"),
        result.cia_impact.get("availability", "N/A"),
    )
    console.print(impact_table)

    # Patch status
    console.print(f"\n[bold]Patch Available:[/bold] [{'green' if result.patch_available else 'red'}]{'YES' if result.patch_available else 'NO'}[/]")
    console.print(f"[bold]Details:[/bold] {result.patch_details}")

    # Security controls
    console.print("\n[bold]Runtime Policy Recommendations (ACS/Prisma):[/bold]")
    console.print(f"  {result.runtime_policy_recommendations}")

    console.print("\n[bold]External Security Controls:[/bold]")
    console.print(f"  {result.external_controls_recommendations}")

    console.print("\n[bold]Mitigation Strategies:[/bold]")
    console.print(f"  {result.mitigation_strategies}")

    console.print("\n[bold]Container-Specific Risks:[/bold]")
    console.print(f"  {result.container_specific_risks}")

    # Exemption decision
    decision_color = "green" if result.exemption_decision == "APPROVED" else "red" if result.exemption_decision == "DENIED" else "yellow"
    decision_panel = Panel(
        f"[bold {decision_color}]{result.exemption_decision}[/bold {decision_color}]\n\n"
        f"[bold]Justification:[/bold]\n{result.exemption_justification}\n\n"
        f"[bold]Caveats & Conditions:[/bold]\n{result.caveats_and_conditions}",
        title="Exemption Recommendation",
        border_style=decision_color,
    )
    console.print(f"\n{decision_panel}")


def main():
    parser = argparse.ArgumentParser(
        description="CVE Exemption Analysis Tool for Container Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single CVE
  python analyze_cve.py --cve CVE-2024-1234 --component curl --version 7.68.0 --source OS --image nginx:latest

  # Analyze with JSON output
  python analyze_cve.py --cve CVE-2024-1234 --component curl --version 7.68.0 --source OS --image nginx:latest --json

  # Batch analysis from JSON file
  python analyze_cve.py --batch cve_requests.json --output results.json
        """,
    )

    # Single CVE analysis arguments
    parser.add_argument("--cve", help="CVE ID (e.g., CVE-2024-1234)")
    parser.add_argument("--component", help="Affected component name")
    parser.add_argument("--version", help="Component version")
    parser.add_argument(
        "--source",
        help="Source type (python, java, nodejs, OS)",
        choices=["python", "java", "nodejs", "OS", "go", "ruby", "dotnet"],
    )
    parser.add_argument("--image", help="Container image name")

    # Batch analysis arguments
    parser.add_argument("--batch", help="JSON file with multiple CVE requests")
    parser.add_argument("--output", help="Output file for results (JSON)")

    # Output format
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    # AWS configuration overrides
    parser.add_argument("--aws-region", help="AWS region (default: from .env or us-east-1)")
    parser.add_argument("--model-id", help="Bedrock model ID (default: from .env)")

    args = parser.parse_args()

    # Validate arguments
    if not args.batch and not all([args.cve, args.component, args.version, args.source, args.image]):
        parser.error("Either --batch or all of (--cve, --component, --version, --source, --image) are required")

    # Initialize analyzer
    aws_region = args.aws_region or os.getenv("AWS_REGION", "us-east-1")
    model_id = args.model_id or os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")
    nvd_api_key = os.getenv("NVD_API_KEY")

    try:
        analyzer = CVEAnalyzer(
            aws_region=aws_region,
            model_id=model_id,
            nvd_api_key=nvd_api_key,
        )
    except Exception as e:
        console.print(f"[red]Error initializing analyzer: {e}[/red]")
        console.print("\n[yellow]Make sure:[/yellow]")
        console.print("  1. AWS credentials are configured (aws configure)")
        console.print("  2. AWS Bedrock is enabled in your region")
        console.print("  3. You have access to Claude models in Bedrock")
        sys.exit(1)

    # Single CVE analysis
    if not args.batch:
        result = analyzer.analyze_cve(
            cve_id=args.cve,
            component_name=args.component,
            component_version=args.version,
            source_type=args.source,
            image_name=args.image,
        )

        if args.json:
            if result:
                print(result.model_dump_json(indent=2))
            else:
                print(json.dumps({"error": "Analysis failed"}, indent=2))
        else:
            print_analysis_result(result)

    # Batch analysis
    else:
        try:
            with open(args.batch, "r") as f:
                cve_requests = json.load(f)

            console.print(f"[cyan]Processing {len(cve_requests)} CVE requests...[/cyan]\n")

            results = analyzer.batch_analyze_cves(cve_requests)

            if args.output:
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=2)
                console.print(f"\n[green]Results saved to {args.output}[/green]")
            else:
                print(json.dumps(results, indent=2))

        except FileNotFoundError:
            console.print(f"[red]Error: Batch file '{args.batch}' not found[/red]")
            sys.exit(1)
        except json.JSONDecodeError:
            console.print(f"[red]Error: Invalid JSON in batch file[/red]")
            sys.exit(1)


if __name__ == "__main__":
    main()
