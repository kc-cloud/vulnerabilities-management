"""
CVE Security Analysis Engine
Uses LangChain + AWS Bedrock (Claude) to analyze CVE exemption requests
"""

import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from langchain_aws import ChatBedrock
from langchain.prompts import ChatPromptTemplate
from langchain.output_parsers import PydanticOutputParser

from .nvd_client import NVDClient


class CVEAnalysisResult(BaseModel):
    """Structured output format for CVE analysis"""

    cve_id: str = Field(description="CVE identifier")
    risk_level: str = Field(description="Risk level: CRITICAL, HIGH, MEDIUM, or LOW")
    exploitability_score: int = Field(
        description="Exploitability score from 1-10 (10=easiest to exploit)", ge=1, le=10
    )
    active_exploits_exist: bool = Field(description="Whether active exploits exist in the wild")
    cia_impact: Dict[str, str] = Field(
        description="Impact on Confidentiality, Integrity, Availability"
    )
    patch_available: bool = Field(description="Whether a patch/update is available")
    patch_details: str = Field(description="Patch availability details or timeline")
    runtime_policy_recommendations: str = Field(
        description="RedHat ACS or Prisma Compute policy recommendations"
    )
    external_controls_recommendations: str = Field(
        description="External security controls recommended (WAF, IDS/IPS, SIEM, etc.)"
    )
    mitigation_strategies: str = Field(description="Recommended mitigation strategies")
    container_specific_risks: str = Field(
        description="Risks specific to containerized K8s/ECS environments"
    )
    exemption_decision: str = Field(description="APPROVED, DENIED, or CONDITIONAL")
    exemption_justification: str = Field(
        description="2-3 sentence justification for the decision"
    )
    caveats_and_conditions: str = Field(
        description="Conditions if approved (time-bound, compensating controls, etc.)"
    )


class CVEAnalyzer:
    """Main CVE analysis engine using AWS Bedrock and LangChain"""

    def __init__(
        self,
        aws_region: str = "us-east-1",
        model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
        nvd_api_key: Optional[str] = None,
    ):
        """
        Initialize CVE Analyzer

        Args:
            aws_region: AWS region for Bedrock
            model_id: Bedrock model ID (default: Claude 3.5 Sonnet)
            nvd_api_key: Optional NIST NVD API key for higher rate limits
        """
        self.nvd_client = NVDClient(api_key=nvd_api_key)

        # Initialize AWS Bedrock LLM
        self.llm = ChatBedrock(
            model_id=model_id,
            region_name=aws_region,
            model_kwargs={
                "temperature": 0.1,  # Low temperature for consistent security analysis
                "max_tokens": 4000,
            },
        )

        # Setup output parser
        self.output_parser = PydanticOutputParser(pydantic_object=CVEAnalysisResult)

        # Create the analysis prompt template
        self.prompt_template = self._create_prompt_template()

    def _create_prompt_template(self) -> ChatPromptTemplate:
        """Create the CVE analysis prompt template"""

        format_instructions = self.output_parser.get_format_instructions()

        template = """You are a senior cybersecurity analyst specializing in container security and CVE risk assessment for Kubernetes and ECS environments protected by RedHat Advanced Cluster Security (ACS) and Prisma Compute.

Your task is to analyze a CVE exemption request and provide a comprehensive security assessment.

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
- CIA Impact: C={confidentiality_impact}, I={integrity_impact}, A={availability_impact}
- Description: {description}
- CWE IDs: {cwe_ids}
- References: {references}

**ANALYSIS REQUIREMENTS:**

1. **Risk Assessment**
   - Determine overall risk level considering CVSS score, attack vector, and environment
   - For containerized environments, assess potential for container escape, privilege escalation, or lateral movement

2. **Exploitability Analysis**
   - Rate exploitability from 1-10 based on attack complexity, privileges required, and public exploit availability
   - Identify if CVE is in CISA KEV catalog or has known active exploitation
   - Check for public PoCs on ExploitDB, Metasploit, GitHub

3. **Impact Analysis**
   - Analyze CIA triad impact in context of container runtime
   - Assess blast radius in K8s/ECS cluster environment

4. **Patch Status**
   - Determine if patch/update exists and specific version that fixes the CVE
   - If no patch, provide vendor timeline or workaround availability

5. **Compensating Controls**
   - Recommend specific RedHat ACS or Prisma Compute runtime policies (e.g., network policies, admission controllers, runtime monitoring)
   - Suggest external controls: WAF for web exploits, network segmentation, SIEM alerting, IDS/IPS

6. **Exemption Decision**
   Use these criteria:
   - **DENIED** if: CVSS >= 9.0 OR active exploits exist OR patch available with easy upgrade path
   - **CONDITIONAL** if: 7.0 <= CVSS < 9.0 AND compensating controls can significantly reduce risk
   - **APPROVED** if: CVSS < 7.0 AND (attack complexity is HIGH OR significant privileges required) AND compensating controls in place

   Provide 2-3 sentence justification and specific caveats/conditions (time-bound approval, required controls, monitoring requirements).

{format_instructions}

Provide your analysis:"""

        return ChatPromptTemplate.from_template(template)

    def analyze_cve(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        source_type: str,
        image_name: str,
    ) -> Optional[CVEAnalysisResult]:
        """
        Analyze a CVE and provide exemption recommendation

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            component_name: Affected component name
            component_version: Component version
            source_type: Source type (python, java, nodejs, OS)
            image_name: Container image name

        Returns:
            CVEAnalysisResult with comprehensive analysis or None if CVE not found
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
        image_name: str,
    ) -> Optional[str]:
        """
        Analyze CVE and return JSON string

        Returns:
            JSON string with analysis results or None if failed
        """
        result = self.analyze_cve(
            cve_id, component_name, component_version, source_type, image_name
        )

        if result:
            return result.model_dump_json(indent=2)
        return None

    def batch_analyze_cves(self, cve_requests: list[Dict[str, str]]) -> list[Dict[str, Any]]:
        """
        Analyze multiple CVEs in batch

        Args:
            cve_requests: List of dicts with keys: cve_id, component_name, component_version,
                         source_type, image_name

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
                image_name=request["image_name"],
            )

            if result:
                results.append(result.model_dump())
            else:
                results.append({"cve_id": request["cve_id"], "error": "Analysis failed"})

        return results
