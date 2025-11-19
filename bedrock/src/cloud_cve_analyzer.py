"""
Cloud CVE Security Analysis Engine
Uses LangChain + AWS Bedrock (Claude) to analyze CVE exemption requests for Cloud Infrastructure
"""

import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from langchain_aws import ChatBedrock
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

from .nvd_client import NVDClient


class CloudCVEAnalysisResult(BaseModel):
    """Structured output format for Cloud CVE analysis"""

    cve_id: str = Field(description="CVE identifier")
    risk_level: str = Field(description="Risk level: CRITICAL, HIGH, MEDIUM, or LOW")
    exploitability_score: int = Field(
        description="Exploitability score from 1-10 (10=easiest to exploit)", ge=1, le=10
    )
    exploitability_explanation: str = Field(
        description="Detailed explanation of how the exploitability score was calculated, including base score and reductions from each security control layer"
    )
    active_exploits_exist: bool = Field(description="Whether active exploits exist in the wild")
    cia_impact: Dict[str, str] = Field(
        description="Impact on Confidentiality, Integrity, Availability"
    )
    patch_available: bool = Field(description="Whether a patch/update is available")
    patch_details: str = Field(description="Patch availability details or timeline")
    cloud_security_recommendations: str = Field(
        description="Prisma Cloud Enterprise or AWS-native security service recommendations"
    )
    external_controls_recommendations: str = Field(
        description="External security controls recommended (WAF, Shield, GuardDuty, etc.)"
    )
    mitigation_strategies: str = Field(description="Recommended mitigation strategies")
    cloud_specific_risks: str = Field(
        description="Risks specific to cloud infrastructure and services"
    )
    exemption_decision: str = Field(description="APPROVED, DENIED, or CONDITIONAL")
    exemption_justification: str = Field(
        description="2-3 sentence justification for the decision"
    )
    caveats_and_conditions: str = Field(
        description="Conditions if approved (time-bound, compensating controls, etc.)"
    )


class CloudCVEAnalyzer:
    """Main Cloud CVE analysis engine using AWS Bedrock and LangChain"""

    def __init__(
        self,
        aws_region: str = "us-east-1",
        model_id: str = "anthropic.claude-3-5-sonnet-20240620-v1:0",
        nvd_api_key: Optional[str] = None,
    ):
        """
        Initialize Cloud CVE Analyzer

        Args:
            aws_region: AWS region for Bedrock
            model_id: Bedrock model ID (default: Claude 3.5 Sonnet)
            nvd_api_key: Optional NIST NVD API key for higher rate limits
        """
        self.nvd_client = NVDClient(api_key=nvd_api_key)

        # Initialize AWS Bedrock LLM
        self.llm = ChatBedrock(
            credentials_profile_name='sectool-dev',
            model_id=model_id,
            region_name=aws_region,
            model_kwargs={
                "temperature": 0.1,  # Low temperature for consistent security analysis
                "max_tokens": 4000,
            },
        )

        # Setup output parser
        self.output_parser = PydanticOutputParser(pydantic_object=CloudCVEAnalysisResult)

        # Create the analysis prompt template
        self.prompt_template = self._create_prompt_template()

    def _create_prompt_template(self) -> ChatPromptTemplate:
        """Create the Cloud CVE analysis prompt template"""

        format_instructions = self.output_parser.get_format_instructions()

        template = """You are a senior cybersecurity analyst specializing in cloud security and CVE risk assessment for AWS cloud infrastructure.

Your task is to analyze a CVE exemption request for cloud infrastructure and provide a comprehensive security assessment that accounts for the EXISTING SECURITY CONTROLS already protecting this environment.

**CVE INFORMATION:**
- CVE ID: {cve_id}
- Affected Component: {component_name}
- Component Version: {component_version}
- Source Type: {source_type}
- Cloud Resource: {cloud_resource}
- CVSS Score: {cvss_score}
- Severity: {severity}
- Attack Vector: {attack_vector}
- Attack Complexity: {attack_complexity}
- Privileges Required: {privileges_required}
- User Interaction: {user_interaction}
- Impact Scope: Confidentiality={confidentiality_impact}, Integrity={integrity_impact}, Availability={availability_impact}
- Description: {description}
- CWE IDs: {cwe_ids}
- References: {references}

**EXISTING SECURITY CONTROLS IN CLOUD ENVIRONMENT:**

Our AWS cloud infrastructure has comprehensive defense-in-depth security controls:

**Network Security:**
- All VPCs route through a central VPC protected by PaloAlto Network Firewall (no direct internet access)
- VPC-to-VPC communication uses AWS Private Endpoints and PrivateLink only
- All web application traffic is routed through AWS WAF with managed rule sets and custom rules
- AWS Shield Standard protection on all resources (DDoS protection)
- Network segmentation with Security Groups and NACLs enforcing least privilege
- VPC Flow Logs enabled for all VPCs with centralized logging

**Cloud-Native Security Services:**
- AWS GuardDuty monitoring for threat detection across accounts
  * Anomalous API calls and unusual behavior detection
  * Cryptocurrency mining detection
  * Compromised instance detection
  * Reconnaissance activity monitoring
- AWS Security Hub aggregating security findings across services
- AWS Config tracking configuration changes and compliance
- AWS CloudTrail logging all API activity with integrity validation
- AWS Systems Manager for patch management and compliance

**Cloud Security Posture Management & Vulnerability Scanning:**
- Prisma Cloud Enterprise (CSPM) provides comprehensive cloud security monitoring
  * **Compliance Monitoring:**
    - CIS AWS Foundations Benchmark compliance scanning and enforcement
    - AWS Security Best Practices benchmark validation
    - Continuous compliance assessment with automated remediation
    - Multi-framework compliance reporting (PCI DSS, SOC 2, HIPAA, NIST)
    - Policy-as-code enforcement for infrastructure compliance
  * **Vulnerability Scanning:**
    - Agentless workload vulnerability scanning for VMs and containers
    - Serverless function vulnerability assessment
    - Registry scanning for container images
    - Infrastructure-as-Code (IaC) vulnerability scanning (CloudFormation, Terraform)
    - Runtime vulnerability protection and detection
    - Prioritized vulnerability remediation based on risk context
  * **Security Monitoring:**
    - Real-time misconfiguration detection and remediation
    - Network visualization and policy enforcement
    - Anomaly detection for unusual cloud activity
    - Identity and access management (IAM) security analysis
    - Secrets scanning and exposure detection
    - Attack path analysis showing exploitable paths

**Access Controls & Identity Security:**
- AWS IAM with least privilege principle enforced
- Multi-factor authentication (MFA) required for all users
- IAM Access Analyzer identifying unintended resource access
- Service Control Policies (SCPs) enforcing organizational security policies
- AWS SSO with SAML integration for centralized identity management
- Temporary credentials via IAM roles (no long-term access keys)
- Automatic credential rotation for service accounts

**Data Protection:**
- Encryption at rest using AWS KMS with customer-managed keys
- Encryption in transit with TLS 1.2+ enforced
- S3 bucket policies enforcing encryption and blocking public access
- AWS Secrets Manager for sensitive credential storage
- AWS Macie for sensitive data discovery and protection

**Detection & Response:**
- Elastic SIEM with detection rules monitoring cloud infrastructure and API activity
- Automated remediation workflows for common security findings
- Centralized logging with 90-day retention for forensic analysis
- Real-time alerting for critical security events
- Automated incident response playbooks

**Compliance & Hardening:**
- CIS AWS Foundations Benchmark compliance monitored via Prisma Cloud
- Automated compliance reporting and remediation
- Resource tagging enforcement for governance
- Backup and disaster recovery policies enforced

**CRITICAL INSTRUCTION:**
Do NOT simply map CVSS scores directly to risk levels. You must perform a CONTEXT-AWARE risk assessment that considers:
1. How the existing security controls reduce the attack surface
2. Which attack vectors are blocked or significantly hindered by current defenses
3. Whether the vulnerability can actually be exploited given the security architecture
4. What additional layers an attacker must bypass to exploit this CVE
5. Cloud-specific factors like managed services, automatic patching, and ephemeral resources

**ANALYSIS REQUIREMENTS:**

1. **Context-Aware Risk Assessment**
   - Start with the CVE's attack vector and determine which existing controls block or mitigate it:
     * Network-based exploits: Consider PaloAlto firewall, WAF, Shield, private endpoints, security groups, NACLs
     * API-based attacks: Consider CloudTrail logging, GuardDuty detection, IAM policies, SCPs
     * Configuration exploits: Consider Prisma Cloud CSPM compliance scanning (CIS AWS Foundations + AWS Security Best Practices), Security Hub, AWS Config
     * Identity/credential attacks: Consider IAM policies, MFA, temporary credentials, IAM Access Analyzer
     * Data exposure: Consider encryption (KMS), S3 policies, Macie, Secrets Manager
     * Web application attacks: Consider WAF with managed/custom rules
     * Workload vulnerabilities: Consider Prisma Cloud vulnerability scanning for VMs, containers, serverless
   - Assess the REALISTIC risk level after accounting for defense-in-depth, not just the CVSS score
   - For cloud environments, consider if:
     * The vulnerability affects managed services (AWS responsibility under shared responsibility model)
     * Prisma Cloud vulnerability scanning has already detected and prioritized this CVE
     * The vulnerability is prevented by CIS AWS Foundations or AWS Security Best Practices compliance (enforced by Prisma Cloud)
     * Automatic patching or updates mitigate the vulnerability
     * The resource is ephemeral and regularly replaced
     * Network isolation prevents external access to vulnerable components
     * CSPM tools detect and alert on vulnerable configurations
     * IaC scanning prevents vulnerable configurations from being deployed

2. **Exploitability Analysis with Defense Considerations**
   - Rate exploitability from 1-10, but REDUCE the score based on:
     * Attack vector blocked by existing controls (e.g., Network attack blocked by firewall/Shield = -3 to -5 points)
     * Multiple security layers attacker must bypass (each layer = -1 to -2 points)
     * Active detection/prevention by GuardDuty, SIEM, Prisma Cloud (= -2 to -3 points)
     * IAM policies and MFA blocking unauthorized access (= -2 to -3 points)
     * Managed service with AWS-controlled patching (= -3 to -4 points)
     * Vulnerability actively monitored by Prisma Cloud with automated remediation (= -2 points)
     * CIS AWS Foundations or AWS Security Best Practices compliance preventing exploitation (= -2 to -3 points)
   - Identify if CVE is in CISA KEV catalog or has known active exploitation in cloud environments
   - Check for public PoCs, but consider if they're viable given the security architecture
   - Consider if Prisma Cloud vulnerability scanning has already detected and prioritized this CVE for remediation
   - Consider if the vulnerability requires configurations that would violate CIS/AWS compliance benchmarks monitored by Prisma Cloud
   - **IMPORTANT**: Provide a detailed explanation of the exploitability score calculation in the exploitability_explanation field using this format:
     "Base exploitability: X/10 (reason). Reduced by Y points due to [specific control]. Reduced by Z points due to [another control]. Final score: N/10."
     Example: "Base exploitability: 9/10 (public exploit available, API vulnerability). Reduced by 3 points due to WAF blocking common attack patterns. Reduced by 2 points due to GuardDuty detecting anomalous API calls. Reduced by 2 points due to IAM policies limiting blast radius. Reduced by 2 points due to Prisma Cloud vulnerability detection and CIS compliance enforcement. Final score: 0/10 (minimum 1/10 applied)."

3. **Defense Evasion Analysis**
   - Determine if the exploit can bypass:
     * PaloAlto Firewall and AWS WAF threat prevention
     * AWS Shield DDoS protection
     * GuardDuty threat detection and anomaly detection
     * Prisma Cloud CSPM configuration monitoring and compliance enforcement
     * Prisma Cloud vulnerability scanning and detection
     * Security Hub and AWS Config compliance checks
     * CloudTrail logging and SIEM correlation rules
     * IAM policies and service control policies
     * Network segmentation (security groups, NACLs, private endpoints)
   - Consider if exploitation requires:
     * Public network access (blocked by private endpoints/VPC architecture)
     * Specific IAM permissions that are restricted
     * API calls that trigger GuardDuty alerts
     * Configuration changes that Prisma Cloud would detect
     * Configurations that violate CIS AWS Foundations or AWS Security Best Practices benchmarks
     * Credentials or access keys (mitigated by temporary credentials, MFA)
     * Vulnerable workload configurations that Prisma Cloud scanning would identify
   - Consider that Prisma Cloud provides:
     * Continuous vulnerability scanning that would detect this CVE
     * CIS AWS Foundations and AWS Security Best Practices compliance validation
     * Automated remediation workflows for both vulnerabilities and compliance violations
     * Attack path analysis showing if the vulnerability is exploitable given the current security posture
     * IaC scanning that would prevent deploying vulnerable configurations
   - If exploit requires multiple evasions, significantly reduce exploitability score
   - Consider cloud-specific defenses like:
     * Automatic credential rotation
     * Immutable infrastructure and frequent redeployment
     * Serverless functions with limited execution time

4. **Practical Impact Analysis**
   - Assess REALISTIC business/operational impact IF the vulnerability were successfully exploited:
     * Can an attacker access sensitive data (customer PII, credentials, API keys, business data)?
     * Can an attacker disrupt services or cause downtime?
     * Can an attacker modify critical data or configurations?
     * Can an attacker pivot to other AWS accounts or services?
     * What is the worst-case scenario in OUR cloud environment specifically?
   - Evaluate how containment controls limit blast radius:
     * IAM policies and SCPs preventing lateral movement to other accounts/services
     * Network segmentation and private endpoints limiting network-based pivoting
     * GuardDuty and SIEM alerting enabling rapid detection and response
     * Automated remediation reducing mean time to respond (MTTR)
     * CloudTrail audit logs providing forensic evidence
     * Backup and disaster recovery capabilities for data restoration
   - Determine REALISTIC impact given our security architecture, not theoretical maximum impact from CVSS scores
   - Consider AWS shared responsibility model (what AWS manages vs. customer responsibility)
   - Assess if the vulnerability is in the infrastructure layer (AWS responsibility) or application layer (customer responsibility)

5. **Patch Status**
   - Determine if patch/update exists and specific version that fixes the CVE
   - For managed services, check if AWS has already patched the infrastructure
   - Assess if patch can be deployed via Infrastructure as Code (IaC) updates
   - If no patch, provide vendor timeline or workaround availability
   - Consider if automated patching (Systems Manager Patch Manager) can deploy the fix

6. **Additional Compensating Controls (If Needed)**
   - ONLY recommend additional controls if existing ones are insufficient
   - Suggest specific Prisma Cloud policies or AWS service configurations
   - Recommend additional GuardDuty, Security Hub, or Config rules
   - Propose enhanced WAF rules or security group restrictions
   - Suggest IAM policy refinements or additional SCPs
   - Recommend AWS-native services that could provide additional protection

7. **Exemption Decision - Context-Aware Criteria**

   **DENIED** if:
   - Active exploits exist AND existing controls cannot reliably prevent exploitation
   - Patch available via IaC/managed service update AND vulnerability is HIGH risk AFTER considering existing controls
   - CVSS >= 9.0 AND attack vector is NOT blocked by existing cloud security architecture
   - Vulnerability could lead to account takeover or cross-account lateral movement
   - Data exposure risk affecting customer PII or regulated data (compliance violation)

   **CONDITIONAL** if:
   - CVSS >= 7.0 BUT existing controls significantly reduce exploitability (e.g., API attack detected by GuardDuty)
   - Active exploits exist BUT would require multiple evasions to succeed (WAF, GuardDuty, IAM policies)
   - Minor gaps in coverage that can be addressed with specific policy enhancements
   - Time-bound approval while patch is being tested/deployed via IaC (not to exceed 30 days)
   - Additional monitoring or temporary compensating controls can be implemented (e.g., enhanced CloudWatch alarms)
   - Affects non-production environment with additional network isolation

   **APPROVED** if:
   - CVSS < 7.0 AND existing controls provide adequate protection
   - Attack vector is fully blocked by existing architecture (e.g., requires public access but all resources are private)
   - Vulnerability is in AWS-managed infrastructure layer (AWS responsibility to patch)
   - Exploit requires IAM permissions that are not granted and blocked by SCPs
   - Attack complexity is HIGH AND GuardDuty/SIEM provides detection/prevention
   - Vulnerability is theoretical/requires conditions that cannot occur in our environment (e.g., requires specific misconfigurations that Prisma Cloud prevents)
   - Resource is ephemeral and regularly replaced (e.g., auto-scaling groups, Lambda functions)
   - Managed service with AWS-controlled automatic patching

   Provide 2-3 sentence justification that explicitly references which existing security controls mitigate this CVE and why the residual risk is acceptable (or not).

{format_instructions}

Provide your analysis:"""

        return ChatPromptTemplate.from_template(template)

    def analyze_cve(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        source_type: str,
        cloud_resource: str,
    ) -> Optional[CloudCVEAnalysisResult]:
        """
        Analyze a CVE for cloud infrastructure and provide exemption recommendation

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            component_name: Affected component name
            component_version: Component version
            source_type: Source type (API, service, configuration, IAM, network)
            cloud_resource: Cloud resource identifier (ARN, resource ID, service name)

        Returns:
            CloudCVEAnalysisResult with comprehensive analysis or None if CVE not found
        """
        # Fetch CVE data from NIST NVD
        print(f"Fetching CVE data for {cve_id}...")
        raw_cve_data = self.nvd_client.get_cve(cve_id)

        if not raw_cve_data:
            print(f"Failed to retrieve CVE data for {cve_id}")
            return None

        cve_details = self.nvd_client.extract_cve_details(raw_cve_data)

        # Prepare prompt variables
        cvss = cve_details.get("cvss", {})
        prompt_vars = {
            "cve_id": cve_id,
            "component_name": component_name,
            "component_version": component_version,
            "source_type": source_type,
            "cloud_resource": cloud_resource,
            "cvss_score": cvss.get("baseScore", "N/A"),
            "severity": cvss.get("baseSeverity", "N/A"),
            "attack_vector": cvss.get("attackVector", "N/A"),
            "attack_complexity": cvss.get("attackComplexity", "N/A"),
            "privileges_required": cvss.get("privilegesRequired", "N/A"),
            "user_interaction": cvss.get("userInteraction", "N/A"),
            "confidentiality_impact": cvss.get("confidentialityImpact", "N/A"),
            "integrity_impact": cvss.get("integrityImpact", "N/A"),
            "availability_impact": cvss.get("availabilityImpact", "N/A"),
            "description": cve_details.get("description", "N/A"),
            "cwe_ids": ", ".join(cve_details.get("cwe_ids", [])) or "N/A",
            "references": ", ".join(cve_details.get("references", [])[:3]) or "N/A",
            "format_instructions": self.output_parser.get_format_instructions(),
        }

        # Generate analysis
        print(f"Analyzing {cve_id} with Claude via AWS Bedrock...")
        chain = self.prompt_template | self.llm | self.output_parser

        try:
            result = chain.invoke(prompt_vars)
            return result

        except Exception as e:
            print(f"Error during analysis: {e}")
            return None

    def analyze_cve_to_json(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        source_type: str,
        cloud_resource: str,
    ) -> Optional[str]:
        """
        Analyze CVE and return JSON string

        Returns:
            JSON string with analysis results or None if failed
        """
        result = self.analyze_cve(
            cve_id, component_name, component_version, source_type, cloud_resource
        )

        if result:
            return result.model_dump_json(indent=2)
        return None

    def batch_analyze_cves(self, cve_requests: list[Dict[str, str]]) -> list[Dict[str, Any]]:
        """
        Analyze multiple CVEs in batch

        Args:
            cve_requests: List of dicts with keys: cve_id, component_name, component_version,
                         source_type, cloud_resource

        Returns:
            List of analysis results
        """
        results = []

        for request in cve_requests:
            result = self.analyze_cve(
                cve_id=request["cve_id"],
                component_name=request["component_name"],
                component_version=request["component_version"],
                source_type=request["source_type"],
                cloud_resource=request["cloud_resource"],
            )

            if result:
                results.append(result.model_dump())
            else:
                results.append({"cve_id": request["cve_id"], "error": "Analysis failed"})

        return results
