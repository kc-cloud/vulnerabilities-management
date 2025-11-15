"""
Model-specific configurations for different Bedrock models
Handles differences in prompting, parameters, and output parsing
"""

from typing import Dict, Any


class ModelConfig:
    """Configuration for a specific Bedrock model"""

    def __init__(
        self,
        model_id: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        prompt_style: str = "detailed",
        supports_json_mode: bool = True,
        needs_explicit_format: bool = False,
    ):
        self.model_id = model_id
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.prompt_style = prompt_style
        self.supports_json_mode = supports_json_mode
        self.needs_explicit_format = needs_explicit_format

    def get_model_kwargs(self) -> Dict[str, Any]:
        """Get model-specific parameters for ChatBedrock"""
        return {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

    def get_system_prefix(self) -> str:
        """Get model-specific system instruction prefix"""
        if "anthropic" in self.model_id:
            return ""  # Claude handles system messages well
        elif "amazon.nova" in self.model_id:
            return ""  # Nova also handles system messages well
        elif "meta.llama" in self.model_id:
            # Llama prefers explicit role definition
            return "You are a helpful AI assistant. "
        else:
            return ""

    def get_format_instruction_style(self) -> str:
        """Get how to present format instructions to this model"""
        if "anthropic.claude-3-opus" in self.model_id:
            return "detailed"  # Opus can handle complex instructions
        elif "anthropic.claude-3-5-sonnet" in self.model_id:
            return "detailed"  # Sonnet 3.5 is also very capable
        elif "amazon.nova" in self.model_id:
            return "structured"  # Nova prefers clear structure
        elif "meta.llama" in self.model_id:
            return "explicit"  # Llama needs very explicit formatting
        else:
            return "detailed"


# Pre-configured model settings
MODEL_CONFIGS = {
    "anthropic.claude-3-5-sonnet-20240620-v1:0": ModelConfig(
        model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
        temperature=0.1,
        max_tokens=4000,
        prompt_style="detailed",
        supports_json_mode=True,
        needs_explicit_format=False,
    ),
    "amazon.nova-pro-v1:0": ModelConfig(
        model_id="amazon.nova-pro-v1:0",
        temperature=0.1,
        max_tokens=4000,
        prompt_style="structured",
        supports_json_mode=True,
        needs_explicit_format=True,  # Nova benefits from explicit format examples
    ),
    "anthropic.claude-sonnet-4-1-20250805-v1:0": ModelConfig(
        model_id="anthropic.claude-sonnet-4-1-20250805-v1:0",
        temperature=0.1,
        max_tokens=4000,
        prompt_style="detailed",
        supports_json_mode=True,
        needs_explicit_format=False,
    ),
    "anthropic.claude-4-1-opus-20250805-v1:0": ModelConfig(
        model_id="anthropic.claude-4-1-opus-20250805-v1:0",
        temperature=0.1,
        max_tokens=4000,
        prompt_style="detailed",
        supports_json_mode=True,
        needs_explicit_format=False,
    ),
    "anthropic.claude-3-haiku-20240307-v1:0": ModelConfig(
        model_id="anthropic.claude-3-haiku-20240307-v1:0",
        temperature=0.1,
        max_tokens=4000,
        prompt_style="detailed",
        supports_json_mode=True,
        needs_explicit_format=False,
    ),
    "anthropic.claude-3-opus-20240229-v1:0": ModelConfig(
        model_id="anthropic.claude-3-opus-20240229-v1:0",
        temperature=0.1,
        max_tokens=4000,
        prompt_style="detailed",
        supports_json_mode=True,
        needs_explicit_format=False,
    ),
    "meta.llama3-70b-instruct-v1:0": ModelConfig(
        model_id="meta.llama3-70b-instruct-v1:0",
        temperature=0.1,
        max_tokens=4000,
        prompt_style="explicit",
        supports_json_mode=True,
        needs_explicit_format=True,  # Llama needs very explicit JSON format
    ),
}


def get_model_config(model_id: str) -> ModelConfig:
    """Get configuration for a specific model"""
    return MODEL_CONFIGS.get(
        model_id,
        ModelConfig(model_id=model_id)  # Default config for unknown models
    )


def get_enhanced_format_instructions(model_id: str, base_instructions: str) -> str:
    """
    Enhance format instructions based on model requirements

    Args:
        model_id: The Bedrock model ID
        base_instructions: Base format instructions from Pydantic parser

    Returns:
        Enhanced format instructions tailored to the model
    """
    config = get_model_config(model_id)

    if not config.needs_explicit_format:
        return base_instructions

    # For models that need explicit format examples
    if "meta.llama" in model_id or "amazon.nova" in model_id:
        enhanced = f"""{base_instructions}

**IMPORTANT OUTPUT FORMAT REQUIREMENTS:**

1. Your response MUST be valid JSON that exactly matches the schema above
2. Do NOT include any text before or after the JSON object
3. Do NOT use markdown code blocks (no ```json)
4. Start your response directly with the opening brace {{
5. All string values must be properly escaped
6. All required fields must be present

**Example of correct output format:**
{{
  "cve_id": "CVE-2024-1234",
  "risk_level": "HIGH",
  "exploitability_score": 7,
  "exploitability_explanation": "Base exploitability: 9/10 (public exploit available). Reduced by 2 points due to firewall protection.",
  "active_exploits_exist": true,
  ...
}}

Provide your analysis in this exact JSON format:"""
        return enhanced

    return base_instructions


def get_prompt_prefix(model_id: str) -> str:
    """
    Get model-specific prompt prefix for better instruction following

    Args:
        model_id: The Bedrock model ID

    Returns:
        Prompt prefix string
    """
    config = get_model_config(model_id)

    if "meta.llama" in model_id:
        return """<|begin_of_text|><|start_header_id|>system<|end_header_id|>

"""

    return ""


def get_prompt_suffix(model_id: str) -> str:
    """
    Get model-specific prompt suffix

    Args:
        model_id: The Bedrock model ID

    Returns:
        Prompt suffix string
    """
    config = get_model_config(model_id)

    if "meta.llama" in model_id:
        return """

<|eot_id|><|start_header_id|>assistant<|end_header_id|>

I will provide my security analysis in valid JSON format:
"""

    elif "amazon.nova" in model_id:
        return """

Please provide your analysis as a valid JSON object that matches the schema exactly:"""

    return ""
