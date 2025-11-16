#!/usr/bin/env python3
"""
Multi-Model Comparison Page
Compare CVE analysis results across different Bedrock models
"""

import os
import streamlit as st
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional
import time

# Optional: Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.cve_analyzer import CVEAnalysisResult
from src.multi_model_analyzer import MultiModelCVEAnalyzer


# Model configurations
MODELS = {
    "Claude 3.5 Sonnet": {
        "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "description": "Anthropic's balanced model (Current)",
        "color": "#8B5CF6"
    },
    "Claude Sonnet 4.1": {
        "model_id": "anthropic.claude-sonnet-4-1-20250805-v1:0",
        "description": "Anthropic's latest, most capable model",
        "color": "#7C3AED"
    },
    "Claude 4.1 Opus": {
        "model_id": "anthropic.claude-4-1-opus-20250805-v1:0",
        "description": "Anthropic's most capable model (flagship)",
        "color": "#A78BFA"
    },
    "Amazon Nova Pro": {
        "model_id": "amazon.nova-pro-v1:0",
        "description": "Amazon's flagship reasoning model",
        "color": "#FF9900"
    }
}


def analyze_with_model(
    model_name: str,
    model_config: Dict[str, str],
    cve_id: str,
    component_name: str,
    component_version: str,
    source_type: str,
    image_name: str
) -> Dict[str, Any]:
    """
    Analyze CVE with a specific model

    Returns:
        Dict with model_name, result, error (if any), and timing info
    """
    start_time = time.time()

    try:
        # Use MultiModelCVEAnalyzer with model-specific optimizations
        analyzer = MultiModelCVEAnalyzer(
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            model_id=model_config["model_id"],
            nvd_api_key=os.getenv("NVD_API_KEY"),
        )

        result = analyzer.analyze_cve(
            cve_id=cve_id,
            component_name=component_name,
            component_version=component_version,
            source_type=source_type,
            image_name=image_name
        )

        elapsed_time = time.time() - start_time

        return {
            "model_name": model_name,
            "result": result,
            "error": None,
            "elapsed_time": elapsed_time
        }

    except Exception as e:
        elapsed_time = time.time() - start_time
        return {
            "model_name": model_name,
            "result": None,
            "error": str(e),
            "elapsed_time": elapsed_time
        }


def create_comparison_dataframe(results: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    """
    Create a comparison DataFrame from model results

    Args:
        results: Dict mapping model names to analysis results

    Returns:
        DataFrame with comparison metrics
    """
    comparison_data = []

    for model_name, data in results.items():
        if data["error"] or data["result"] is None:
            error_msg = data["error"] if data["error"] else "Analysis returned no result"
            comparison_data.append({
                "Model": model_name,
                "Status": "❌ Error",
                "Risk Level": "N/A",
                "Exploitability": "N/A",
                "Active Exploits": "N/A",
                "Patch Available": "N/A",
                "Decision": "N/A",
                "Time (s)": f"{data['elapsed_time']:.2f}"
            })
        else:
            result = data["result"]
            comparison_data.append({
                "Model": model_name,
                "Status": "✅ Success",
                "Risk Level": result.risk_level,
                "Exploitability": f"{result.exploitability_score}/10",
                "Active Exploits": "Yes" if result.active_exploits_exist else "No",
                "Patch Available": "Yes" if result.patch_available else "No",
                "Decision": result.exemption_decision,
                "Time (s)": f"{data['elapsed_time']:.2f}"
            })

    return pd.DataFrame(comparison_data)


def render_detailed_comparison(results: Dict[str, Dict[str, Any]]):
    """Render detailed side-by-side comparison of all model outputs"""

    st.markdown("## 📊 Detailed Model Outputs")

    # Get successful results
    successful_results = {
        name: data for name, data in results.items()
        if data["result"] is not None
    }

    if not successful_results:
        st.error("No successful results to compare")
        return

    # Create tabs for each comparison aspect
    tabs = st.tabs([
        "🎯 Decisions & Justifications",
        "🔢 Exploitability Analysis",
        "🔧 Patch & Mitigation",
        "🛡️ Security Recommendations",
        "📋 Full Details"
    ])

    # Tab 1: Decisions & Justifications
    with tabs[0]:
        st.markdown("### Exemption Decisions Comparison")

        for model_name, data in successful_results.items():
            result = data["result"]

            decision_emoji = {
                "APPROVED": "✅",
                "DENIED": "🚫",
                "CONDITIONAL": "⚠️"
            }.get(result.exemption_decision, "❓")

            with st.expander(f"{model_name}: {decision_emoji} **{result.exemption_decision}**", expanded=True):
                st.markdown(f"**Justification:**")
                st.info(result.exemption_justification)

                if result.caveats_and_conditions:
                    st.markdown(f"**Conditions:**")
                    st.warning(result.caveats_and_conditions)

    # Tab 2: Exploitability Analysis
    with tabs[1]:
        st.markdown("### Exploitability Scoring Comparison")

        # Create a bar chart for exploitability scores
        exploit_data = {
            name: data["result"].exploitability_score
            for name, data in successful_results.items()
        }

        df_exploit = pd.DataFrame({
            "Model": list(exploit_data.keys()),
            "Exploitability Score": list(exploit_data.values())
        })

        st.bar_chart(df_exploit.set_index("Model"))

        st.markdown("---")

        for model_name, data in successful_results.items():
            result = data["result"]

            with st.expander(f"{model_name}: {result.exploitability_score}/10", expanded=False):
                st.markdown(f"**Explanation:**")
                st.write(result.exploitability_explanation)

                st.markdown(f"**Active Exploits:** {'Yes ⚠️' if result.active_exploits_exist else 'No ✓'}")

    # Tab 3: Patch & Mitigation
    with tabs[2]:
        st.markdown("### Patch Information & Mitigation Strategies")

        cols = st.columns(2)

        with cols[0]:
            st.markdown("#### 🔧 Patch Details")
            for model_name, data in successful_results.items():
                result = data["result"]

                with st.expander(f"{model_name}", expanded=False):
                    patch_status = "✅ Available" if result.patch_available else "❌ Not Available"
                    st.markdown(f"**Status:** {patch_status}")
                    st.write(result.patch_details)

        with cols[1]:
            st.markdown("#### ⚙️ Mitigation Strategies")
            for model_name, data in successful_results.items():
                result = data["result"]

                with st.expander(f"{model_name}", expanded=False):
                    st.write(result.mitigation_strategies)

    # Tab 4: Security Recommendations
    with tabs[3]:
        st.markdown("### Security Control Recommendations")

        for model_name, data in successful_results.items():
            result = data["result"]

            with st.expander(f"{model_name}", expanded=False):
                st.markdown("**🛡️ Runtime Policy Recommendations (ACS/Prisma):**")
                st.write(result.runtime_policy_recommendations)

                st.markdown("---")

                st.markdown("**🔐 External Controls (WAF/Firewall/SIEM):**")
                st.write(result.external_controls_recommendations)

                st.markdown("---")

                st.markdown("**🐳 Container-Specific Risks:**")
                st.write(result.container_specific_risks)

    # Tab 5: Full Details (All Fields)
    with tabs[4]:
        st.markdown("### Complete Analysis Details")

        for model_name, data in successful_results.items():
            result = data["result"]

            with st.expander(f"{model_name} - Full Output", expanded=False):
                # Convert to dict and display as JSON
                result_dict = result.model_dump()

                # Display in organized sections
                st.markdown("#### Key Metrics")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Risk Level", result.risk_level)
                with col2:
                    st.metric("Exploitability", f"{result.exploitability_score}/10")
                with col3:
                    st.metric("Decision", result.exemption_decision)
                with col4:
                    st.metric("Time", f"{data['elapsed_time']:.2f}s")

                st.markdown("---")
                st.markdown("#### Full JSON Output")
                st.json(result_dict)


def main():
    """Main comparison page"""

    # Page config
    st.set_page_config(
        page_title="Model Comparison - CVE Analyzer",
        page_icon="🔬",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Header
    st.title("🔬 Multi-Model CVE Analysis Comparison")
    st.markdown("""
    Compare CVE analysis results across **4 different Bedrock models** to evaluate their performance,
    accuracy, and decision-making capabilities for security assessments.
    """)

    # Model info in sidebar
    with st.sidebar:
        st.header("🤖 Models Being Compared")

        for model_name, config in MODELS.items():
            st.markdown(f"**{model_name}**")
            st.caption(config["description"])
            st.code(config["model_id"], language=None)
            st.markdown("---")

        st.info("""
        **Note:** All models will be queried in parallel for faster comparison.
        This may take 30-90 seconds depending on model response times.
        """)

    st.markdown("---")

    # Input Form
    st.markdown("## 📝 CVE Information")

    col1, col2 = st.columns(2)

    with col1:
        cve_id = st.text_input(
            "CVE ID *",
            placeholder="CVE-2024-1234",
            help="Enter the CVE identifier (e.g., CVE-2024-1234)"
        )

        package = st.text_input(
            "Package Name *",
            placeholder="e.g., openssl, lodash, jetty",
            help="Name of the affected package or component"
        )

        version = st.text_input(
            "Package Version *",
            placeholder="e.g., 1.2.3",
            help="Version of the affected package"
        )

    with col2:
        severity = st.selectbox(
            "Original Severity *",
            options=["", "Critical", "High", "Medium", "Low"],
            help="Severity rating from your scanner"
        )

        vuln_type = st.selectbox(
            "Vulnerability Type (Source) *",
            options=["", "java", "python", "nodejs", "go", "ruby", "OS", "other"],
            help="Type/source of the vulnerability"
        )

        image = st.text_input(
            "Container Image *",
            placeholder="e.g., nginx:1.19, myapp/backend:v2.1",
            help="Container image where this vulnerability was found"
        )

    st.markdown("---")

    # Compare button
    col1, col2, col3 = st.columns([1, 1, 3])

    with col1:
        compare_button = st.button("🔬 Compare Models", type="primary", width="stretch")

    with col2:
        if st.button("🔄 Clear Form", width="stretch"):
            st.rerun()

    # Validation and Analysis
    if compare_button:
        # Validate required fields
        if not cve_id or not package or not version or not severity or not vuln_type or not image:
            st.error("⚠️ Please fill in all required fields marked with *")
        elif not cve_id.upper().startswith("CVE-"):
            st.error("⚠️ CVE ID must start with 'CVE-' (e.g., CVE-2024-1234)")
        else:
            st.markdown("---")
            st.markdown("## 🔄 Running Multi-Model Analysis")

            # Create progress indicators
            progress_text = st.empty()
            progress_bar = st.progress(0)

            # Results container
            results = {}

            # Run analyses in parallel
            with ThreadPoolExecutor(max_workers=4) as executor:
                # Submit all model analyses
                future_to_model = {
                    executor.submit(
                        analyze_with_model,
                        model_name,
                        model_config,
                        cve_id.upper(),
                        package,
                        version,
                        vuln_type,
                        image
                    ): model_name
                    for model_name, model_config in MODELS.items()
                }

                # Collect results as they complete
                completed = 0
                total = len(MODELS)

                for future in as_completed(future_to_model):
                    model_name = future_to_model[future]

                    try:
                        result_data = future.result()
                        results[model_name] = result_data

                        completed += 1
                        progress = completed / total
                        progress_bar.progress(progress)
                        progress_text.text(f"Completed: {model_name} ({completed}/{total})")

                    except Exception as e:
                        st.error(f"Failed to get result for {model_name}: {str(e)}")
                        results[model_name] = {
                            "model_name": model_name,
                            "result": None,
                            "error": str(e),
                            "elapsed_time": 0
                        }

            # Clear progress indicators
            progress_text.empty()
            progress_bar.empty()

            # Display results
            if results:
                st.success(f"✅ Analysis complete! Compared {len(results)} models")

                st.markdown("---")
                st.markdown("## 📊 Quick Comparison Summary")

                # Create comparison table
                df_comparison = create_comparison_dataframe(results)

                # Style the dataframe
                def style_decision(val):
                    if val == "APPROVED":
                        return 'background-color: #10b981; color: white'
                    elif val == "DENIED":
                        return 'background-color: #ef4444; color: white'
                    elif val == "CONDITIONAL":
                        return 'background-color: #f59e0b; color: white'
                    return ''

                def style_risk(val):
                    if val == "CRITICAL":
                        return 'background-color: #dc2626; color: white'
                    elif val == "HIGH":
                        return 'background-color: #ea580c; color: white'
                    elif val == "MEDIUM":
                        return 'background-color: #eab308; color: black'
                    elif val == "LOW":
                        return 'background-color: #22c55e; color: white'
                    return ''

                # Display styled dataframe
                st.dataframe(
                    df_comparison.style.applymap(
                        style_decision, subset=['Decision']
                    ).applymap(
                        style_risk, subset=['Risk Level']
                    ),
                    width="stretch",
                    hide_index=True
                )

                # Show errors if any
                failed_models = {name: data for name, data in results.items()
                                if data["error"] or data["result"] is None}

                if failed_models:
                    st.markdown("---")
                    st.markdown("## ⚠️ Model Errors")

                    for model_name, data in failed_models.items():
                        error_msg = data["error"] if data["error"] else "Analysis returned no result"
                        with st.expander(f"❌ {model_name} - Error Details", expanded=True):
                            st.error(error_msg)
                            st.caption(f"Elapsed time: {data['elapsed_time']:.2f}s")

                            # Troubleshooting tips
                            st.markdown("**Possible solutions:**")
                            if "access" in error_msg.lower() or "denied" in error_msg.lower():
                                st.markdown("- Enable this model in AWS Bedrock console")
                                st.markdown("- Check IAM permissions for Bedrock")
                            elif "parse" in error_msg.lower() or "json" in error_msg.lower():
                                st.markdown("- Model may have returned invalid JSON format")
                                st.markdown("- Check CloudWatch logs for raw output")
                            else:
                                st.markdown("- Check network connectivity to AWS")
                                st.markdown("- Verify AWS credentials are valid")
                                st.markdown("- Check CloudWatch logs for details")

                # Show detailed comparison
                st.markdown("---")
                render_detailed_comparison(results)

                # Download section
                st.markdown("---")
                st.markdown("## 📥 Download Results")

                col1, col2 = st.columns(2)

                with col1:
                    # Download comparison CSV
                    csv = df_comparison.to_csv(index=False)
                    st.download_button(
                        label="📊 Download Summary (CSV)",
                        data=csv,
                        file_name=f"{cve_id}_model_comparison.csv",
                        mime="text/csv"
                    )

                with col2:
                    # Download full results as JSON
                    import json

                    full_results = {
                        "cve_id": cve_id.upper(),
                        "metadata": {
                            "package": package,
                            "version": version,
                            "severity": severity,
                            "type": vuln_type,
                            "image": image
                        },
                        "models": {}
                    }

                    for model_name, data in results.items():
                        if data["result"]:
                            full_results["models"][model_name] = {
                                "analysis": data["result"].model_dump(),
                                "elapsed_time": data["elapsed_time"]
                            }
                        else:
                            full_results["models"][model_name] = {
                                "error": data["error"],
                                "elapsed_time": data["elapsed_time"]
                            }

                    json_str = json.dumps(full_results, indent=2)

                    st.download_button(
                        label="📄 Download Full Results (JSON)",
                        data=json_str,
                        file_name=f"{cve_id}_full_comparison.json",
                        mime="application/json"
                    )

            else:
                st.error("❌ Failed to retrieve any results. Please check your configuration and try again.")


if __name__ == "__main__":
    main()
