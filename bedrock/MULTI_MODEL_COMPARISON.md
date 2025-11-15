# Multi-Model Comparison Feature

## Overview

The CVE Analyzer now includes a **Multi-Model Comparison** page that allows you to analyze the same CVE across 4 different AWS Bedrock models simultaneously and compare their outputs side-by-side.

**Key Feature**: Uses **model-specific prompt optimizations** to ensure each model produces accurate, structured results. See [MODEL_SPECIFIC_PROMPTING.md](MODEL_SPECIFIC_PROMPTING.md) for technical details.

## Models Compared

1. **Claude 3.5 Sonnet** (`anthropic.claude-3-5-sonnet-20240620-v1:0`)
   - Current production model
   - Balanced performance and cost
   - Excellent reasoning capabilities

2. **Amazon Nova Pro** (`amazon.nova-pro-v1:0`)
   - Amazon's flagship reasoning model
   - Cost-effective option
   - Strong multi-step analysis

3. **Claude 3 Opus** (`anthropic.claude-3-opus-20240229`)
   - Most capable Claude model
   - Best for high-stakes decisions
   - Superior nuanced analysis

4. **Llama 3.3 70B Instruct** (`meta.llama3-3-70b-instruct-v1:0`)
   - Open-source alternative
   - Very cost-effective
   - Good technical reasoning

## How to Use

### 1. Start the Streamlit Application

```bash
cd /Users/mac/git-kc-cloud/vulnerabilities-management/bedrock
streamlit run streamlit_app.py
```

### 2. Navigate to the Comparison Page

- The main page is now "🔒 Single CVE Analysis Tool"
- In the sidebar, click on "🔬 Multi-Model Comparison" or use the page navigation

### 3. Enter CVE Details

Fill in the required fields:
- **CVE ID**: e.g., CVE-2024-1234
- **Package Name**: e.g., openssl, lodash, jetty
- **Package Version**: e.g., 1.2.3
- **Original Severity**: Critical, High, Medium, or Low
- **Vulnerability Type**: java, python, nodejs, go, ruby, OS, or other
- **Container Image**: e.g., nginx:1.19, myapp/backend:v2.1

### 4. Run Comparison

Click **"🔬 Compare Models"** button

The system will:
- Query all 4 models in parallel (faster execution)
- Display progress for each model
- Show results in ~30-90 seconds

## Output Features

### 1. Quick Comparison Summary (Table)

A side-by-side comparison table showing:
- Model name
- Analysis status (success/error)
- Risk level
- Exploitability score (1-10)
- Active exploits (Yes/No)
- Patch availability (Yes/No)
- Exemption decision (APPROVED/DENIED/CONDITIONAL)
- Response time

### 2. Detailed Comparisons (Tabs)

#### Tab 1: Decisions & Justifications
- Shows each model's exemption decision
- Includes full justification text
- Displays any conditions or caveats

#### Tab 2: Exploitability Analysis
- Bar chart comparing exploitability scores
- Detailed scoring explanations for each model
- Active exploit detection status

#### Tab 3: Patch & Mitigation
- Patch availability details from each model
- Recommended mitigation strategies
- Version upgrade paths

#### Tab 4: Security Recommendations
- Runtime policy recommendations (ACS/Prisma)
- External security controls (WAF, Firewall, SIEM)
- Container-specific risks and mitigations

#### Tab 5: Full Details
- Complete JSON output from each model
- All analysis fields
- Execution timing

### 3. Download Options

Two download formats:
- **CSV Summary**: Quick comparison table for spreadsheet analysis
- **Full JSON**: Complete analysis results with all fields

## Use Cases

### 1. Model Selection
Compare model performance to choose the best one for production:
- Accuracy of risk assessments
- Quality of recommendations
- Consistency of decisions
- Cost vs. performance trade-offs

### 2. Quality Assurance
Validate CVE analysis by checking if multiple models agree:
- Consensus on high-risk vulnerabilities
- Divergent opinions requiring manual review
- Edge cases where models disagree

### 3. Cost Optimization
Evaluate if cheaper models provide acceptable results:
- Compare Nova Pro vs. Claude Sonnet
- Test if Llama 3.3 70B meets quality standards
- Determine when to use expensive Opus model

### 4. Benchmarking
Test model capabilities on specific CVE types:
- Network vulnerabilities
- Container escape scenarios
- Web application exploits
- Supply chain risks

## Performance Considerations

- **Parallel Execution**: All 4 models run simultaneously for faster results
- **Expected Time**: 30-90 seconds total (vs. 2-6 minutes if run sequentially)
- **Rate Limits**: AWS Bedrock may throttle requests; adjust concurrency if needed
- **Costs**: Running 4 models will consume 4x API credits

## Cost Estimate (per CVE analysis)

Assuming ~2,500 input tokens and ~1,500 output tokens:

| Model | Input Cost | Output Cost | Total |
|-------|------------|-------------|-------|
| Claude 3.5 Sonnet | $0.0075 | $0.0225 | $0.03 |
| Amazon Nova Pro | $0.0020 | $0.0048 | $0.0068 |
| Claude 3 Opus | $0.0375 | $0.1125 | $0.15 |
| Llama 3.3 70B | $0.0025 | $0.0015 | $0.004 |

**Total per comparison: ~$0.19**

## Troubleshooting

### Model Access Issues
If you get errors about model access:
1. Verify AWS Bedrock model access in AWS Console
2. Enable required models in your region
3. Check IAM permissions for Bedrock

### Timeout Errors
If models timeout:
1. Check network connectivity
2. Verify AWS region configuration
3. Try running single model first to isolate issue

### Different Results
It's normal for models to produce slightly different results:
- Different reasoning approaches
- Varying levels of caution
- Model-specific biases
- Different training data

## Next Steps

1. **Run Test Analysis**: Try with a known CVE to verify setup
2. **Compare Results**: Analyze differences in model outputs
3. **Select Production Model**: Choose based on accuracy and cost
4. **Configure Alerts**: Set up notifications for specific decision patterns

## Support

For issues or questions:
- Check AWS Bedrock documentation
- Verify environment variables in `.env`
- Review model-specific documentation
- Test with individual model analysis first
