"""
Multi-Model CVE Analyzer
Enhanced analyzer that handles model-specific configurations and prompting strategies
"""

import json
from typing import Dict, Any, Optional
from pydantic import ValidationError

from langchain_aws import ChatBedrock
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

from .nvd_client import NVDClient
from .cve_analyzer import CVEAnalysisResult
from .model_configs import (
    get_model_config,
    get_enhanced_format_instructions,
    get_prompt_suffix,
)


class MultiModelCVEAnalyzer:
    """
    Enhanced CVE Analyzer with model-specific optimizations
    Handles differences between Claude, Nova, and Llama models
    """

    def __init__(
        self,
        aws_region: str = "us-east-1",
        model_id: str = "anthropic.claude-3-5-sonnet-20240620-v1:0",
        nvd_api_key: Optional[str] = None,
    ):
        """
        Initialize Multi-Model CVE Analyzer

        Args:
            aws_region: AWS region for Bedrock
            model_id: Bedrock model ID
            nvd_api_key: Optional NIST NVD API key
        """
        self.model_id = model_id
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.model_config = get_model_config(model_id)

        # Initialize AWS Bedrock LLM with model-specific parameters
        self.llm = ChatBedrock(
            credentials_profile_name='sectool-dev',
            model_id=model_id,
            region_name=aws_region,
            model_kwargs=self.model_config.get_model_kwargs(),
        )

        # Setup output parser
        self.output_parser = PydanticOutputParser(pydantic_object=CVEAnalysisResult)

        # Create the analysis prompt template
        self.prompt_template = self._create_prompt_template()

    def _create_prompt_template(self) -> ChatPromptTemplate:
        """Create model-optimized CVE analysis prompt template"""

        # Get base format instructions
        base_format_instructions = self.output_parser.get_format_instructions()

        # Enhance based on model requirements
        format_instructions = get_enhanced_format_instructions(
            self.model_id, base_format_instructions
        )

        # Get model-specific suffix
        prompt_suffix = get_prompt_suffix(self.model_id)

        # Core analysis template (same for all models)
        template = """You are a senior cybersecurity analyst specializing in container security and CVE risk assessment for Kubernetes and ECS environments.

Your task is to analyze a CVE exemption request and provide a comprehensive security assessment that accounts for the EXISTING SECURITY CONTROLS already protecting this environment.

**CVE INFORMATION:**
- CVE ID: {cve_id}
- Affected Component: {component_name}
- Component Version: {component_version}
- Source Type: {source_type}
- Container Image: {image_name}
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

Our AWS-based datacenter already has multiple layers of defense-in-depth security controls:

**Network Security:**
- All VPCs route through a central VPC protected by PaloAlto Network Firewall (no direct internet access)
- VPC-to-VPC communication uses AWS Private Endpoints only
- All web application traffic is routed through AWS WAF

**Hardened Infrastructure:**
- All EKS cluster nodes and Docker hosts run on hardened Virtual Machines
- VM hardening meets >85% compliance with CIS (Center for Internet Security) benchmark requirements
- Security baselines include: disabled unnecessary services, restricted network access, secure configurations, and minimal attack surface

**Endpoint & Runtime Security:**
- CrowdStrike, Elastic-agent, and Carbon Black provide endpoint protection on all VMs
- RedHat ACS and Prisma Compute provide runtime security for EKS, ECS clusters, and Docker hosts
  * Runtime threat detection and prevention
  * Network segmentation enforcement
  * Admission control policies
  * Vulnerability runtime protection
  * **Pod exec restrictions**: kubectl exec commands to pods are blocked by policy (prevents interactive shell access to containers)

**Detection & Response:**
- Elastic SIEM with detection rules monitoring VMs, firewalls, and cloud infrastructure
- Prisma Cloud Enterprise monitoring for AWS cloud anomalies and misconfigurations

**CRITICAL INSTRUCTION:**
Do NOT simply map CVSS scores directly to risk levels. You must perform a CONTEXT-AWARE risk assessment that considers:
1. How the existing security controls reduce the attack surface
2. Which attack vectors are blocked or significantly hindered by current defenses
3. Whether the vulnerability can actually be exploited given the security architecture
4. What additional layers an attacker must bypass to exploit this CVE

**ANALYSIS REQUIREMENTS:**

1. **Context-Aware Risk Assessment**
   - Start with the CVE's attack vector and determine which existing controls block or mitigate it
   - Assess the REALISTIC risk level after accounting for defense-in-depth, not just the CVSS score
   - For containerized environments, consider if container escape/privilege escalation is prevented

2. **Exploitability Analysis with Defense Considerations**
   - Rate exploitability from 1-10, but REDUCE the score based on existing controls
   - Identify if CVE is in CISA KEV catalog or has known active exploitation
   - **IMPORTANT**: Provide detailed explanation in exploitability_explanation field:
     "Base exploitability: X/10 (reason). Reduced by Y points due to [control]. Final score: N/10."

3. **Defense Evasion Analysis**
   - Determine if the exploit can bypass security layers
   - Consider if exploitation requires interactive shell access (blocked by pod exec restrictions)
   - If exploit requires multiple evasions, significantly reduce exploitability score

4. **Practical Impact Analysis**
   - Assess REALISTIC business/operational impact IF successfully exploited
   - Evaluate how containment controls limit blast radius
   - Determine REALISTIC impact given our security architecture

5. **Patch Status**
   - Determine if patch/update exists and specific version that fixes the CVE
   - If no patch, provide vendor timeline or workaround availability

6. **Additional Compensating Controls (If Needed)**
   - ONLY recommend additional controls if existing ones are insufficient
   - Suggest specific RedHat ACS or Prisma Compute policy enhancements

7. **Exemption Decision - Context-Aware Criteria**

   **DENIED** if:
   - Active exploits exist AND existing controls cannot reliably prevent exploitation
   - Patch available with easy upgrade path AND vulnerability is HIGH risk AFTER considering controls
   - CVSS >= 9.0 AND attack vector is NOT blocked by existing architecture

   **CONDITIONAL** if:
   - CVSS >= 7.0 BUT existing controls significantly reduce exploitability
   - Active exploits exist BUT would require multiple evasions
   - Minor gaps in coverage that can be addressed with policy enhancements

   **APPROVED** if:
   - CVSS < 7.0 AND existing controls provide adequate protection
   - Attack vector is fully blocked by existing architecture
   - Attack complexity is HIGH AND detection/prevention is in place
   - Vulnerability is theoretical/requires conditions that cannot occur

   Provide 2-3 sentence justification that explicitly references which existing security controls mitigate this CVE.

{format_instructions}{prompt_suffix}

Provide your analysis:"""

        return ChatPromptTemplate.from_template(
            template.replace("{prompt_suffix}", prompt_suffix)
        )

    def analyze_cve(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        source_type: str,
        image_name: str,
    ) -> Optional[CVEAnalysisResult]:
        """
        Analyze a CVE with model-specific optimizations

        Args:
            cve_id: CVE identifier
            component_name: Affected component name
            component_version: Component version
            source_type: Source type (python, java, nodejs, OS)
            image_name: Container image name

        Returns:
            CVEAnalysisResult or None if analysis failed
        """
        # Fetch CVE data from NIST NVD
        print(f"[{self.model_id}] Fetching CVE data for {cve_id}...")
        raw_cve_data = self.nvd_client.get_cve(cve_id)

        if not raw_cve_data:
            print(f"[{self.model_id}] Failed to retrieve CVE data for {cve_id}")
            return None

        cve_details = self.nvd_client.extract_cve_details(raw_cve_data)

        # Prepare prompt variables
        cvss = cve_details.get("cvss", {})
        prompt_vars = {
            "cve_id": cve_id,
            "component_name": component_name,
            "component_version": component_version,
            "source_type": source_type,
            "image_name": image_name,
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
            "format_instructions": get_enhanced_format_instructions(
                self.model_id, self.output_parser.get_format_instructions()
            ),
        }

        # Generate analysis
        print(f"[{self.model_id}] Analyzing {cve_id}...")
        chain = self.prompt_template | self.llm

        try:
            # Get raw output from LLM
            response = chain.invoke(prompt_vars)

            # Extract content
            if hasattr(response, 'content'):
                raw_output = response.content
            else:
                raw_output = str(response)

            # Try to parse the output
            result = self._parse_output(raw_output)
            return result

        except Exception as e:
            print(f"[{self.model_id}] Error during analysis: {e}")
            print(f"[{self.model_id}] Attempting fallback parsing...")

            # Try alternative parsing methods
            try:
                # Some models might wrap JSON in markdown
                if "```json" in str(e) or "```" in str(e):
                    import re
                    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', str(response.content), re.DOTALL)
                    if json_match:
                        json_str = json_match.group(1)
                        result = self.output_parser.parse(json_str)
                        return result
            except:
                pass

            return None

    def _parse_output(self, raw_output: str) -> Optional[CVEAnalysisResult]:
        """
        Parse model output with fallback strategies

        Args:
            raw_output: Raw text output from model

        Returns:
            Parsed CVEAnalysisResult or None
        """
        # Fix common Llama typos before parsing
        if "meta.llama" in self.model_id:
            raw_output = raw_output.replace('"exemption_justice":', '"exemption_justification":')
            raw_output = raw_output.replace("'exemption_justice':", '"exemption_justification":')

        try:
            # Try standard parsing first
            return self.output_parser.parse(raw_output)
        except (ValidationError, json.JSONDecodeError) as e:
            print(f"[{self.model_id}] Standard parsing failed: {e}")

            # Try to extract JSON from markdown code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if json_match:
                try:
                    json_str = json_match.group(1)
                    # Apply Llama fixes to extracted JSON too
                    if "meta.llama" in self.model_id:
                        json_str = json_str.replace('"exemption_justice":', '"exemption_justification":')
                        json_str = json_str.replace("'exemption_justice':", '"exemption_justification":')
                    return self.output_parser.parse(json_str)
                except:
                    pass

            # Try to find JSON object in text
            json_match = re.search(r'\{.*\}', raw_output, re.DOTALL)
            if json_match:
                try:
                    json_str = json_match.group(0)
                    # Apply Llama fixes to extracted JSON too
                    if "meta.llama" in self.model_id:
                        json_str = json_str.replace('"exemption_justice":', '"exemption_justification":')
                        json_str = json_str.replace("'exemption_justice':", '"exemption_justification":')
                    return self.output_parser.parse(json_str)
                except:
                    pass

            raise ValueError(f"Could not parse output from {self.model_id}")

    def analyze_cve_to_json(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        source_type: str,
        image_name: str,
    ) -> Optional[str]:
        """Analyze CVE and return JSON string"""
        result = self.analyze_cve(
            cve_id, component_name, component_version, source_type, image_name
        )

        if result:
            return result.model_dump_json(indent=2)
        return None
