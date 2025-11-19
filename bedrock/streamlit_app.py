#!/usr/bin/env python3
"""
CVE Security Analysis Platform - Landing Page
Main entry point for the CVE vulnerability management system
"""

import os
import streamlit as st

# Optional: Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def main():
    """Main landing page"""

    # Page config
    st.set_page_config(
        page_title="CVE Security Analysis Platform",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

    # Header
    st.markdown("""
    <div style='text-align: center; padding: 20px 0;'>
        <h1 style='font-size: 3em; margin-bottom: 10px;'>🔒 CVE Security Analysis Platform</h1>
        <p style='font-size: 1.3em; color: #666;'>
            Context-Aware Vulnerability Risk Assessment with AI-Powered Analysis
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Introduction
    st.markdown("""
    Welcome to the **CVE Security Analysis Platform** - a comprehensive vulnerability management system
    powered by AWS Bedrock (Claude 3.5 Sonnet) and NIST NVD database.

    This platform provides **context-aware risk assessment** that considers your existing defense-in-depth
    security architecture, rather than relying solely on CVSS scores.
    """)

    st.markdown("### Select Your Analysis Environment:")
    st.markdown("")

    # Navigation Cards
    col1, col2 = st.columns(2)

    with col1:
        # Container CVE Analyzer Card
        with st.container(border=True):
            st.markdown("### 🐳 Container CVE Analyzer")
            st.markdown("""
            Analyze CVEs in **containerized environments** (Kubernetes, ECS, Docker).

            **Security Controls:**
            - RedHat ACS & Prisma Compute
            - PaloAlto Firewall & AWS WAF
            - CrowdStrike & Carbon Black
            - Pod exec restrictions
            - CIS-hardened infrastructure

            Perfect for: Container images, K8s pods, ECS tasks
            """)
            st.page_link("pages/0_🐳_Container_CVE_Analyzer.py",
                        label="🚀 Launch Container Analyzer",
                        icon="🐳",
                        use_container_width=True)

        st.markdown("")

        # VM CVE Analyzer Card
        with st.container(border=True):
            st.markdown("### 💻 VM CVE Analyzer")
            st.markdown("""
            Analyze CVEs on **virtual machines** (EC2, on-prem VMs).

            **Security Controls:**
            - Tenable Nessus & BigFix scanners
            - CIS Benchmark compliance (>85%)
            - Endpoint protection (CrowdStrike, Carbon Black)
            - PAM, MFA, RBAC
            - Network segmentation

            Perfect for: EC2 instances, VMware VMs, OS packages
            """)
            st.page_link("pages/2_💻_VM_CVE_Analyzer.py",
                        label="🚀 Launch VM Analyzer",
                        icon="💻",
                        use_container_width=True)

    with col2:
        # Cloud CVE Analyzer Card
        with st.container(border=True):
            st.markdown("### ☁️ Cloud CVE Analyzer")
            st.markdown("""
            Analyze CVEs in **AWS cloud infrastructure** and services.

            **Security Controls:**
            - Prisma Cloud CSPM (CIS AWS + Security Best Practices)
            - GuardDuty, Security Hub, Config
            - IAM policies, SCPs, MFA
            - KMS encryption, Secrets Manager
            - Network isolation (Private Endpoints)

            Perfect for: AWS services, APIs, IaC, cloud resources
            """)
            st.page_link("pages/3_☁️_Cloud_CVE_Analyzer.py",
                        label="🚀 Launch Cloud Analyzer",
                        icon="☁️",
                        use_container_width=True)

        st.markdown("")

        # Model Comparison Card
        with st.container(border=True):
            st.markdown("### 🔬 Multi-Model Comparison")
            st.markdown("""
            Compare CVE analysis across **4 different AI models**.

            **Models Compared:**
            - Claude 3.5 Sonnet
            - Claude Sonnet 4.1
            - Claude 4.1 Opus
            - Amazon Nova Pro

            Perfect for: Evaluating model performance, accuracy testing
            """)
            st.page_link("pages/1_🔬_Model_Comparison.py",
                        label="🚀 Launch Model Comparison",
                        icon="🔬",
                        use_container_width=True)

    st.markdown("---")

    # Key Features Section
    st.markdown("## 🌟 Key Features")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        #### 🎯 Context-Aware Analysis
        - Evaluates actual exploitability given YOUR security controls
        - Reduces false positives from generic CVSS scoring
        - Considers defense-in-depth architecture
        """)

    with col2:
        st.markdown("""
        #### 🤖 AI-Powered Intelligence
        - Powered by Claude 3.5 Sonnet
        - Analyzes attack vectors, exploitability, impact
        - Provides exemption recommendations
        """)

    with col3:
        st.markdown("""
        #### 📊 Comprehensive Reporting
        - Detailed risk analysis and justifications
        - Compensating control recommendations
        - Exportable JSON results
        """)

    st.markdown("---")

    # System Information
    col1, col2, col3 = st.columns(3)

    with col1:
        st.info(f"""
        **AWS Region**
        {os.getenv('AWS_REGION', 'us-east-1')}
        """)

    with col2:
        st.info("""
        **AI Model**
        Claude 3.5 Sonnet
        """)

    with col3:
        st.info("""
        **Data Source**
        NIST NVD Database
        """)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 20px;'>
        <small>
        CVE Security Analysis Platform | Powered by AWS Bedrock & NIST NVD
        <br>
        Context-aware vulnerability risk assessment with defense-in-depth security controls
        <br><br>
        📚 <b>Quick Links:</b>
        <a href="https://nvd.nist.gov/" target="_blank">NIST NVD</a> |
        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">CISA KEV</a> |
        <a href="https://www.cisecurity.org/cis-benchmarks" target="_blank">CIS Benchmarks</a>
        </small>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
