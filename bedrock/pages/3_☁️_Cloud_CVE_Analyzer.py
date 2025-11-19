#!/usr/bin/env python3
"""
Cloud CVE Analyzer Page
Interactive web interface for analyzing CVEs on Cloud Infrastructure
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

from src.cloud_cve_analyzer import CloudCVEAnalyzer


def init_analyzer():
    """Initialize the Cloud CVE Analyzer (cached for performance)"""
    if "cloud_analyzer" not in st.session_state:
        with st.spinner("Initializing Cloud CVE Analyzer..."):
            st.session_state.cloud_analyzer = CloudCVEAnalyzer(
                aws_region=os.getenv("AWS_REGION", "us-east-1"),
                model_id=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0"),
                nvd_api_key=os.getenv("NVD_API_KEY"),
            )
    return st.session_state.cloud_analyzer


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

    # Cloud Security Recommendations
    with st.expander("🛡️ Cloud Security Recommendations (Prisma Cloud/AWS Services)", expanded=True):
        st.write(result.cloud_security_recommendations)

    # External Controls
    with st.expander("🔐 External Security Controls (WAF/GuardDuty/Shield)", expanded=True):
        st.write(result.external_controls_recommendations)

    # Mitigation Strategies
    with st.expander("⚙️ Mitigation Strategies", expanded=True):
        st.write(result.mitigation_strategies)

    # Cloud Specific Risks
    with st.expander("☁️ Cloud Infrastructure Specific Risks", expanded=True):
        st.write(result.cloud_specific_risks)


def main():
    """Main Streamlit app"""

    # Page config
    st.set_page_config(
        page_title="Cloud CVE Security Analyzer",
        page_icon="☁️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Header
    st.title("☁️ Cloud Infrastructure CVE Analysis Tool")
    st.markdown("""
    **Context-Aware CVE Risk Assessment** for AWS cloud infrastructure with comprehensive security controls.

    This tool analyzes CVEs considering your existing cloud security architecture:
    - **CSPM:** Prisma Cloud Enterprise (CIS AWS Foundations + AWS Security Best Practices)
    - **Vulnerability Scanning:** Prisma Cloud (agentless workloads, containers, serverless, IaC)
    - **Cloud-Native Security:** GuardDuty, Security Hub, Config, CloudTrail, Systems Manager
    - **Network Security:** PaloAlto Firewall, AWS WAF, Shield, Private Endpoints
    - **Identity Security:** IAM, MFA, SCPs, temporary credentials, IAM Access Analyzer
    - **Data Protection:** KMS encryption, S3 policies, Secrets Manager, Macie
    - **Monitoring:** Elastic SIEM, real-time alerting, incident response runbooks
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
        st.markdown("### 📄 Other Pages")
        st.page_link("streamlit_app.py", label="🏠 Home", icon="🏠")
        st.page_link("pages/0_🐳_Container_CVE_Analyzer.py", label="🐳 Container CVE Analyzer", icon="🐳")
        st.page_link("pages/2_💻_VM_CVE_Analyzer.py", label="💻 VM CVE Analyzer", icon="💻")
        st.page_link("pages/1_🔬_Model_Comparison.py", label="🔬 Multi-Model Comparison", icon="🔬")

        st.markdown("---")
        st.markdown("### 📚 Quick Links")
        st.markdown("- [NIST NVD Database](https://nvd.nist.gov/)")
        st.markdown("- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)")
        st.markdown("- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)")
        st.markdown("- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)")
        st.markdown("- [Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud)")

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
            "Package/Component Name *",
            placeholder="e.g., AWS SDK, boto3, Terraform provider",
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
            help="Severity rating from your scanner (Prisma Cloud/AWS Inspector)"
        )

    with col2:
        vuln_type = st.selectbox(
            "Vulnerability Type (Source) *",
            options=["", "API", "service", "configuration", "IAM", "network", "IaC", "container", "serverless", "other"],
            help="Type/source of the vulnerability"
        )

        resource_type = st.selectbox(
            "Resource Type *",
            options=["", "EC2 instance", "S3 bucket", "Lambda function", "RDS database", "ECS task",
                     "EKS cluster", "API Gateway", "CloudFront distribution", "IAM role/policy",
                     "VPC/Security Group", "Load Balancer", "SNS/SQS", "DynamoDB table", "Other"],
            help="Type of AWS resource affected (generic type, not specific ARN)"
        )

        scanner = st.selectbox(
            "Scanner Source",
            options=["Prisma Cloud", "AWS Inspector", "AWS Security Hub", "GuardDuty", "Other"],
            help="Which security tool detected this CVE"
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
        if not cve_id or not package or not version or not severity or not vuln_type or not resource_type:
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
                        resource_type=resource_type
                    )

                    if result:
                        st.success(f"✅ Analysis complete for {cve_id}")
                        render_analysis_result(result)

                        # Download button for JSON
                        st.markdown("---")
                        st.download_button(
                            label="📥 Download Analysis (JSON)",
                            data=result.model_dump_json(indent=2),
                            file_name=f"{cve_id}_cloud_analysis.json",
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
        Cloud CVE Security Analysis Tool | Powered by AWS Bedrock (Claude 3.5 Sonnet) & NIST NVD
        <br>
        Context-aware risk assessment with Prisma Cloud CSPM, AWS-native security services, and defense-in-depth controls
        </small>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
