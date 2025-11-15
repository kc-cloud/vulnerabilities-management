#!/usr/bin/env python3
"""
Streamlit UI for CVE Analysis
Interactive web interface for analyzing individual CVEs
"""

import os
import streamlit as st

# Optional: Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, will use environment variables directly
    pass

from src.cve_analyzer import CVEAnalyzer


def init_analyzer():
    """Initialize the CVE Analyzer (cached for performance)"""
    if "analyzer" not in st.session_state:
        with st.spinner("Initializing CVE Analyzer..."):
            st.session_state.analyzer = CVEAnalyzer(
                aws_region=os.getenv("AWS_REGION", "us-east-1"),
                model_id=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0"),
                nvd_api_key=os.getenv("NVD_API_KEY"),
            )
    return st.session_state.analyzer


def render_analysis_result(result):
    """Render the analysis result in a nice format"""

    # Risk Level with color coding
    risk_colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }

    decision_colors = {
        "DENIED": "🚫",
        "CONDITIONAL": "⚠️",
        "APPROVED": "✅"
    }

    st.markdown("---")
    st.markdown("## 📊 Analysis Results")

    # Key Metrics Row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        risk_emoji = risk_colors.get(result.risk_level, "⚪")
        st.metric("Risk Level", f"{risk_emoji} {result.risk_level}")

    with col2:
        st.metric("Exploitability Score", f"{result.exploitability_score}/10")
        with st.expander("ℹ️ How was this calculated?"):
            st.info(result.exploitability_explanation)

    with col3:
        exploit_status = "YES ⚠️" if result.active_exploits_exist else "NO ✓"
        st.metric("Active Exploits", exploit_status)

    with col4:
        patch_status = "YES ✓" if result.patch_available else "NO ⚠️"
        st.metric("Patch Available", patch_status)

    # Exemption Decision
    st.markdown("---")
    decision_emoji = decision_colors.get(result.exemption_decision, "❓")
    st.markdown(f"### {decision_emoji} Exemption Decision: **{result.exemption_decision}**")

    st.info(result.exemption_justification)

    if result.caveats_and_conditions:
        st.warning(f"**Conditions:** {result.caveats_and_conditions}")

    # Detailed Analysis Sections
    st.markdown("---")
    st.markdown("## 📋 Detailed Analysis")

    # Patch Information
    with st.expander("🔧 Patch Information", expanded=True):
        st.write(result.patch_details)

    # Runtime Policy Recommendations
    with st.expander("🛡️ Runtime Policy Recommendations (ACS/Prisma)", expanded=True):
        st.write(result.runtime_policy_recommendations)

    # External Controls
    with st.expander("🔐 External Security Controls (WAF/Firewall/SIEM)", expanded=True):
        st.write(result.external_controls_recommendations)

    # Mitigation Strategies
    with st.expander("⚙️ Mitigation Strategies", expanded=True):
        st.write(result.mitigation_strategies)

    # Container Specific Risks
    with st.expander("🐳 Container/Kubernetes Specific Risks", expanded=True):
        st.write(result.container_specific_risks)


def main():
    """Main Streamlit app"""

    # Page config
    st.set_page_config(
        page_title="CVE Security Analyzer",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Header
    st.title("🔒 CVE Security Analysis Tool")
    st.markdown("""
    **Context-Aware CVE Risk Assessment** for containerized environments with defense-in-depth security controls.

    This tool analyzes CVEs considering your existing security architecture:
    - PaloAlto Network Firewall, AWS WAF
    - CrowdStrike, Elastic-agent, Carbon Black endpoint protection
    - RedHat ACS & Prisma Compute runtime security
    - Elastic SIEM & Prisma Cloud monitoring
    """)

    st.markdown("---")

    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        st.info(f"""
        **AWS Region:** {os.getenv('AWS_REGION', 'us-east-1')}

        **Model:** Claude 3.5 Sonnet

        **Profile:** sectool-dev
        """)

        st.markdown("---")
        st.markdown("### 📚 Quick Links")
        st.markdown("- [NIST NVD Database](https://nvd.nist.gov/)")
        st.markdown("- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)")
        st.markdown("- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)")

    # Initialize analyzer
    analyzer = init_analyzer()

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

        severity = st.selectbox(
            "Original Severity *",
            options=["", "Critical", "High", "Medium", "Low"],
            help="Severity rating from your scanner"
        )

    with col2:
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

        summary = st.text_area(
            "Summary",
            placeholder="Brief description of the vulnerability...",
            help="Optional: Brief description of the CVE (will be fetched from NVD if empty)",
            height=100
        )

    st.markdown("---")

    # Analyze button
    col1, col2, col3 = st.columns([1, 1, 3])

    with col1:
        analyze_button = st.button("🔍 Analyze CVE", type="primary", use_container_width=True)

    with col2:
        if st.button("🔄 Clear Form", use_container_width=True):
            st.rerun()

    # Validation and Analysis
    if analyze_button:
        # Validate required fields
        if not cve_id or not package or not version or not severity or not vuln_type or not image:
            st.error("⚠️ Please fill in all required fields marked with *")
        elif not cve_id.upper().startswith("CVE-"):
            st.error("⚠️ CVE ID must start with 'CVE-' (e.g., CVE-2024-1234)")
        else:
            # Perform analysis
            with st.spinner(f"🔍 Analyzing {cve_id}... This may take 30-60 seconds..."):
                try:
                    result = analyzer.analyze_cve(
                        cve_id=cve_id.upper(),
                        component_name=package,
                        component_version=version,
                        source_type=vuln_type,
                        image_name=image
                    )

                    if result:
                        st.success(f"✅ Analysis complete for {cve_id}")
                        render_analysis_result(result)

                        # Download button for JSON
                        st.markdown("---")
                        st.download_button(
                            label="📥 Download Analysis (JSON)",
                            data=result.model_dump_json(indent=2),
                            file_name=f"{cve_id}_analysis.json",
                            mime="application/json"
                        )
                    else:
                        st.error(f"""
                        ❌ Failed to analyze {cve_id}

                        **Possible reasons:**
                        - CVE not found in NIST NVD database
                        - Network connectivity issues
                        - Invalid CVE ID format

                        Please verify the CVE ID and try again.
                        """)

                except Exception as e:
                    st.error(f"""
                    ❌ Error during analysis: {str(e)}

                    **Troubleshooting:**
                    1. Verify AWS credentials are configured
                    2. Check Bedrock model access
                    3. Ensure .env file is properly configured
                    4. Check network connectivity
                    """)

                    with st.expander("🐛 Debug Information"):
                        st.code(str(e))

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 20px;'>
        <small>
        CVE Security Analysis Tool | Powered by AWS Bedrock (Claude 3.5 Sonnet) & NIST NVD
        <br>
        Context-aware risk assessment with defense-in-depth security controls
        </small>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
