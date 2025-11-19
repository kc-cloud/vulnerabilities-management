"""
VM CVE Security Analysis Engine
Uses LangChain + AWS Bedrock (Claude) to analyze CVE exemption requests for Virtual Machines
"""

import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from langchain_aws import ChatBedrock
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

from .nvd_client import NVDClient


class VMCVEAnalysisResult(BaseModel):
    """Structured output format for VM CVE analysis"""

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
    endpoint_protection_recommendations: str = Field(
        description="CrowdStrike, Elastic-agent, or Carbon Black policy recommendations"
    )
    external_controls_recommendations: str = Field(
        description="External security controls recommended (WAF, IDS/IPS, SIEM, etc.)"
    )
    mitigation_strategies: str = Field(description="Recommended mitigation strategies")
    vm_specific_risks: str = Field(
        description="Risks specific to virtual machine environments"
    )
    exemption_decision: str = Field(description="APPROVED, DENIED, or CONDITIONAL")
    exemption_justification: str = Field(
        description="2-3 sentence justification for the decision"
    )
    caveats_and_conditions: str = Field(
        description="Conditions if approved (time-bound, compensating controls, etc.)"
    )


class VMCVEAnalyzer:
    """Main VM CVE analysis engine using AWS Bedrock and LangChain"""

    def __init__(
        self,
        aws_region: str = "us-east-1",
        model_id: str = "anthropic.claude-3-5-sonnet-20240620-v1:0",
        nvd_api_key: Optional[str] = None,
    ):
        """
        Initialize VM CVE Analyzer

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
        self.output_parser = PydanticOutputParser(pydantic_object=VMCVEAnalysisResult)

        # Create the analysis prompt template
        self.prompt_template = self._create_prompt_template()

    def _create_prompt_template(self) -> ChatPromptTemplate:
        """Create the VM CVE analysis prompt template"""

        format_instructions = self.output_parser.get_format_instructions()

        template = """You are a senior cybersecurity analyst specializing in virtual machine security and CVE risk assessment for enterprise VM environments.

Your task is to analyze a CVE exemption request for a virtual machine and provide a comprehensive security assessment that accounts for the EXISTING SECURITY CONTROLS already protecting this environment.

**CVE INFORMATION:**
- CVE ID: {cve_id}
- Affected Component: {component_name}
- Component Version: {component_version}
- Source Type: {source_type}
- Virtual Machine: {vm_identifier}
- Operating System: {os_name}
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

**EXISTING SECURITY CONTROLS IN DATACENTER:**

Our AWS-based datacenter already has multiple layers of defense-in-depth security controls for virtual machines:

**Network Security:**
- All VPCs route through a central VPC protected by PaloAlto Network Firewall (no direct internet access)
- VPC-to-VPC communication uses AWS Private Endpoints only
- All web application traffic is routed through AWS WAF
- Network segmentation with security groups and NACLs restricting VM-to-VM communication

**Hardened Virtual Machines:**
- All virtual machines run on hardened OS images based on {os_name}
- VM hardening meets >85% compliance with OS-specific CIS benchmark for {os_name}
- CIS benchmark controls are validated and enforced through Tenable Nessus and BigFix scanning
- Security baselines include:
  * Disabled unnecessary services and ports per CIS {os_name} benchmark
  * Restricted network access and minimal open ports
  * Secure system configurations and kernel hardening specific to {os_name}
  * Minimal attack surface with only required packages installed
  * Regular security patching schedules
  * Strong authentication and access controls

**Vulnerability & Compliance Scanning:**
- Tenable Nessus performs comprehensive vulnerability scanning on all VMs
  * Continuous vulnerability assessment and prioritization
  * CIS benchmark compliance scanning and validation
  * Credentialed scanning for deeper vulnerability detection
  * Plugin-based scanning with regularly updated vulnerability signatures
  * Risk-based vulnerability management with CVSS scoring
  * Integration with patch management workflows
- BigFix (HCL) provides endpoint management and security scanning
  * Real-time vulnerability scanning and assessment
  * CIS compliance monitoring and enforcement
  * Automated patch deployment and tracking
  * Configuration compliance checking
  * Software inventory and license management
  * Remediation workflow automation
- Both scanners provide:
  * Continuous compliance validation against CIS benchmarks
  * Automated vulnerability detection and reporting
  * Integration with remediation workflows
  * Historical trending and metrics
  * False positive identification and suppression

**Endpoint & Host Protection:**
- CrowdStrike Falcon provides advanced endpoint protection on all VMs
  * Real-time threat detection and prevention
  * Anti-malware and exploit prevention
  * Host-based firewall management
  * Process and file integrity monitoring
- Elastic-agent provides centralized security monitoring and logging
- Carbon Black provides application control and endpoint detection/response
  * Application whitelisting capabilities
  * Behavioral analysis and threat hunting
  * Memory protection and exploit blocking

**Detection & Response:**
- Elastic SIEM with detection rules monitoring VMs, firewalls, and cloud infrastructure
- Prisma Cloud Enterprise monitoring for AWS cloud anomalies and misconfigurations
- Centralized logging with 90-day retention for forensic analysis
- Automated alerting for suspicious activities and security events

**Access Controls:**
- Privileged access management (PAM) for administrative access
- Multi-factor authentication (MFA) required for all VM access
- Role-based access control (RBAC) with least privilege principle
- Session recording and audit logging for all privileged sessions

**CRITICAL INSTRUCTION:**
Do NOT simply map CVSS scores directly to risk levels. You must perform a CONTEXT-AWARE risk assessment that considers:
1. How the existing security controls reduce the attack surface
2. Which attack vectors are blocked or significantly hindered by current defenses
3. Whether the vulnerability can actually be exploited given the security architecture
4. What additional layers an attacker must bypass to exploit this CVE

**ANALYSIS REQUIREMENTS:**

1. **Context-Aware Risk Assessment**
   - Start with the CVE's attack vector and determine which existing controls block or mitigate it:
     * Network-based exploits: Consider PaloAlto firewall, WAF, private endpoints, network segmentation, security groups
     * Local exploits: Consider endpoint protection (CrowdStrike, Elastic-agent, Carbon Black) AND CIS-hardened VMs (>85% compliance validated by Nessus/BigFix)
     * Privilege escalation: Consider PAM, MFA, RBAC, and hardened OS configurations
     * Web application exploits: Consider WAF protection
     * Host-level exploits: Consider CIS-hardened VMs with disabled unnecessary services, restricted access, and minimal attack surface
   - Assess the REALISTIC risk level after accounting for defense-in-depth, not just the CVSS score
   - For VM environments, consider if:
     * The vulnerability requires services/ports that are disabled in CIS-hardened VMs running {os_name} (validated by Nessus/BigFix scanning)
     * The vulnerability is already detected and tracked by Tenable Nessus or BigFix scanners
     * Privilege escalation is mitigated by PAM, MFA, and hardened configurations specific to {os_name}
     * Endpoint protection actively prevents exploitation attempts
     * Network segmentation limits lateral movement
     * OS-specific CIS benchmark controls for {os_name} (monitored by Nessus/BigFix) prevent the vulnerable configuration

2. **Exploitability Analysis with Defense Considerations**
   - Rate exploitability from 1-10, but REDUCE the score based on:
     * Attack vector blocked by existing controls (e.g., Network attack blocked by firewall = -3 to -5 points)
     * Multiple security layers attacker must bypass (each layer = -1 to -2 points)
     * Active detection/prevention by SIEM, endpoint protection (= -2 to -3 points)
     * Services/ports required by exploit are disabled on CIS-hardened VMs (= -3 to -4 points)
     * Vulnerability actively monitored and tracked by Nessus/BigFix with automated remediation (= -2 points)
   - Identify if CVE is in CISA KEV catalog or has known active exploitation
   - Check for public PoCs, but consider if they're viable given the security architecture
   - Consider if Tenable Nessus or BigFix scanners have already detected this vulnerability and flagged it for remediation
   - **IMPORTANT**: Provide a detailed explanation of the exploitability score calculation in the exploitability_explanation field using this format:
     "Base exploitability: X/10 (reason). Reduced by Y points due to [specific control]. Reduced by Z points due to [another control]. Final score: N/10."
     Example: "Base exploitability: 8/10 (public exploit available, network vector). Reduced by 4 points due to PaloAlto firewall blocking network attack vector. Reduced by 2 points due to CrowdStrike endpoint protection. Reduced by 2 points due to Nessus detection and tracking. Final score: 0/10 (minimum 1/10 applied)."

3. **Defense Evasion Analysis**
   - Determine if the exploit can bypass:
     * PaloAlto Firewall threat prevention
     * AWS WAF rules (for web exploits)
     * Endpoint detection (CrowdStrike/Elastic-agent/Carbon Black)
     * Vulnerability scanning and detection (Tenable Nessus/BigFix)
     * CIS-hardened VM configurations (disabled services, restricted access, kernel hardening) validated by Nessus/BigFix
     * Network segmentation and security groups
     * PAM and MFA requirements
     * SIEM detection rules
   - Consider if exploitation requires:
     * Services/ports that are disabled in CIS-hardened {os_name} VMs (validated by compliance scans)
     * Privilege escalation on hardened infrastructure with PAM/MFA
     * Packages or software not installed due to minimal attack surface policy for {os_name}
     * Network access that is restricted by security groups/NACLs
     * Configurations that would be flagged as non-compliant by Nessus/BigFix CIS benchmark scans for {os_name}
   - Consider that Nessus and BigFix provide:
     * Continuous monitoring that would detect vulnerable configurations
     * Automated remediation workflows that could patch the vulnerability
     * CIS compliance validation that prevents vulnerable configurations
   - If exploit requires multiple evasions, significantly reduce exploitability score

4. **Practical Impact Analysis**
   - Assess REALISTIC business/operational impact IF the vulnerability were successfully exploited:
     * Can an attacker access sensitive data (customer PII, credentials, API keys, business data)?
     * Can an attacker disrupt services or cause downtime?
     * Can an attacker modify critical data or configurations?
     * What is the worst-case scenario in OUR environment specifically?
   - Evaluate how containment controls limit blast radius:
     * Network segmentation preventing lateral movement to other VPCs/VMs/services
     * Endpoint protection preventing persistence mechanisms
     * CIS-hardened VMs limiting host-level exploitation and privilege escalation
     * PAM and MFA preventing unauthorized administrative access
     * SIEM alerting enabling rapid detection and response (mean time to detect)
     * Application whitelisting (Carbon Black) preventing malicious code execution
   - Determine REALISTIC impact given our security architecture, not theoretical maximum impact from CVSS scores
   - Consider that VM hardening significantly reduces the attack surface and available exploitation techniques

5. **Patch Status**
   - Determine if patch/update exists and specific version that fixes the CVE
   - Assess if patch can be applied during regular patching window or requires emergency patching
   - If no patch, provide vendor timeline or workaround availability
   - Consider if patch deployment is compatible with existing VM configurations

6. **Additional Compensating Controls (If Needed)**
   - ONLY recommend additional controls if existing ones are insufficient
   - Suggest specific endpoint protection policy enhancements (CrowdStrike, Carbon Black, Elastic-agent)
   - Recommend additional SIEM detection rules or firewall policies if gaps exist
   - Propose network segmentation improvements or additional access controls

7. **Exemption Decision - Context-Aware Criteria**

   **DENIED** if:
   - Active exploits exist AND existing controls cannot reliably prevent exploitation
   - Patch available with easy upgrade path AND vulnerability is HIGH risk AFTER considering existing controls
   - CVSS >= 9.0 AND attack vector is NOT blocked by existing security architecture
   - Vulnerability allows privilege escalation that could bypass PAM/MFA controls

   **CONDITIONAL** if:
   - CVSS >= 7.0 BUT existing controls significantly reduce exploitability (e.g., network attack blocked by firewall)
   - Active exploits exist BUT would require multiple evasions to succeed
   - Minor gaps in coverage that can be addressed with specific policy enhancements
   - Time-bound approval while patch is being tested/deployed (not to exceed 30 days)
   - Additional monitoring or temporary compensating controls can be implemented

   **APPROVED** if:
   - CVSS < 7.0 AND existing controls provide adequate protection
   - Attack vector is fully blocked by existing architecture (e.g., requires direct internet access but none exists)
   - Exploit requires services/ports that are disabled on CIS-hardened {os_name} VMs
   - Exploit requires multiple privilege escalations AND endpoint protection actively monitors for this behavior
   - Attack complexity is HIGH AND SIEM/endpoint protection provides detection/prevention
   - Vulnerability is theoretical/requires conditions that cannot occur in our environment (e.g., requires packages not installed on {os_name} per minimal attack surface policy)

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
        vm_identifier: str,
        os_name: str,
    ) -> Optional[VMCVEAnalysisResult]:
        """
        Analyze a CVE for a virtual machine and provide exemption recommendation

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            component_name: Affected component name
            component_version: Component version
            source_type: Source type (python, java, nodejs, OS, system package)
            vm_identifier: Virtual machine identifier (hostname, instance ID, etc.)
            os_name: Operating system name and version (e.g., 'Ubuntu 22', 'RHEL 8')

        Returns:
            VMCVEAnalysisResult with comprehensive analysis or None if CVE not found
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
            "vm_identifier": vm_identifier,
            "os_name": os_name,
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
        vm_identifier: str,
        os_name: str,
    ) -> Optional[str]:
        """
        Analyze CVE and return JSON string

        Returns:
            JSON string with analysis results or None if failed
        """
        result = self.analyze_cve(
            cve_id, component_name, component_version, source_type, vm_identifier, os_name
        )

        if result:
            return result.model_dump_json(indent=2)
        return None

    def batch_analyze_cves(self, cve_requests: list[Dict[str, str]]) -> list[Dict[str, Any]]:
        """
        Analyze multiple CVEs in batch

        Args:
            cve_requests: List of dicts with keys: cve_id, component_name, component_version,
                         source_type, vm_identifier, os_name

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
                vm_identifier=request["vm_identifier"],
                os_name=request["os_name"],
            )

            if result:
                results.append(result.model_dump())
            else:
                results.append({"cve_id": request["cve_id"], "error": "Analysis failed"})

        return results
