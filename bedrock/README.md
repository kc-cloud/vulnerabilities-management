# CVE Vulnerability Management Automation

Automated CVE exemption analysis tool for container security teams managing AWS Kubernetes, ECS clusters, and Docker hosts protected by RedHat Advanced Cluster Security (ACS) and Prisma Compute.

Uses **LangChain + AWS Bedrock (Claude 3.5 Sonnet)** to analyze CVE exemption requests and provide security recommendations.

## Features

- **Automated CVE Analysis**: Queries NIST NVD database for CVE details
- **AI-Powered Risk Assessment**: Uses Claude 3.5 Sonnet for comprehensive security analysis
- **Container-Specific Insights**: Analyzes risks in K8s/ECS context (container escape, privilege escalation)
- **Exemption Recommendations**: Provides APPROVED/DENIED/CONDITIONAL decisions with justifications
- **Security Controls**: Recommends runtime policies and external controls (WAF, SIEM, IDS/IPS)
- **Batch Processing**: Analyze multiple CVEs in one run
- **Structured Output**: JSON output for integration with ticketing systems

## Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   NIST NVD API  │─────▶│  CVE Analyzer    │─────▶│  AWS Bedrock    │
│  (CVE Details)  │      │   (LangChain)    │      │ (Claude 3.5)    │
└─────────────────┘      └──────────────────┘      └─────────────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │ Exemption Report │
                         │   (JSON/CLI)     │
                         └──────────────────┘
```

## Prerequisites

1. **AWS Account** with Bedrock access
2. **AWS CLI** configured with credentials
3. **Python 3.9+**
4. **NIST NVD API Key** (optional, but recommended for higher rate limits)

## Setup

### 1. Clone or Download

```bash
cd /Users/mac/claude/vulnerability-management
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure AWS Credentials

```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, Region (e.g., us-east-1)
```

### 4. Enable AWS Bedrock Access

1. Go to AWS Bedrock console in your region
2. Navigate to "Model access"
3. Request access to **Anthropic Claude 3.5 Sonnet** model
4. Wait for approval (usually instant)

### 5. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env and add your configuration
```

**Optional**: Get NIST NVD API key for higher rate limits:
- Visit: https://nvd.nist.gov/developers/request-an-api-key
- Without key: 5 requests/30 seconds
- With key: 50 requests/30 seconds

## Usage

### Single CVE Analysis

```bash
python analyze_cve.py \
  --cve CVE-2024-3094 \
  --component xz-utils \
  --version 5.6.0 \
  --source OS \
  --image ubuntu:22.04
```

**Output Example:**

```
╭─────────────────── CVE Analysis Summary ────────────────────╮
│ CVE-2024-3094                                               │
│ Risk Level: CRITICAL                                        │
│ Exploitability: 9/10                                        │
│ Active Exploits: YES                                        │
╰─────────────────────────────────────────────────────────────╯

CIA Impact:
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Confidentiality ┃ Integrity ┃ Availability ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ HIGH            │ HIGH      │ HIGH         │
└─────────────────┴───────────┴──────────────┘

...

╭─────────── Exemption Recommendation ───────────╮
│ DENIED                                         │
│                                                │
│ Justification:                                 │
│ This CVE has active exploits and CRITICAL     │
│ severity. Patch is available. No exemption    │
│ should be granted.                            │
╰────────────────────────────────────────────────╯
```

### JSON Output

```bash
python analyze_cve.py \
  --cve CVE-2024-3094 \
  --component xz-utils \
  --version 5.6.0 \
  --source OS \
  --image ubuntu:22.04 \
  --json > result.json
```

### Batch Analysis

Create a JSON file with multiple CVE requests:

```json
[
  {
    "cve_id": "CVE-2024-3094",
    "component_name": "xz-utils",
    "component_version": "5.6.0",
    "source_type": "OS",
    "image_name": "ubuntu:22.04"
  },
  {
    "cve_id": "CVE-2024-21626",
    "component_name": "runc",
    "component_version": "1.1.11",
    "source_type": "OS",
    "image_name": "alpine:3.19"
  }
]
```

Run batch analysis:

```bash
python analyze_cve.py --batch example_batch.json --output results.json
```

## Analysis Criteria

The tool uses the following exemption decision criteria:

| Decision | Criteria |
|----------|----------|
| **DENIED** | CVSS ≥ 9.0 OR active exploits exist OR patch available with easy upgrade |
| **CONDITIONAL** | 7.0 ≤ CVSS < 9.0 AND compensating controls can reduce risk |
| **APPROVED** | CVSS < 7.0 AND (high attack complexity OR privileges required) AND controls in place |

## Integration Examples

### Python Integration

```python
from src.cve_analyzer import CVEAnalyzer

analyzer = CVEAnalyzer(
    aws_region="us-east-1",
    nvd_api_key="your-nvd-api-key"  # Optional
)

result = analyzer.analyze_cve(
    cve_id="CVE-2024-1234",
    component_name="curl",
    component_version="7.68.0",
    source_type="OS",
    image_name="nginx:latest"
)

print(f"Decision: {result.exemption_decision}")
print(f"Justification: {result.exemption_justification}")
```

### CI/CD Pipeline Integration

```yaml
# .github/workflows/cve-analysis.yml
name: CVE Exemption Analysis

on:
  issues:
    types: [opened, labeled]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      - name: Analyze CVE
        run: |
          python analyze_cve.py \
            --cve ${{ github.event.issue.title }} \
            --component curl \
            --version 7.68.0 \
            --source OS \
            --image nginx:latest \
            --json > analysis.json
      - name: Post Comment
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const analysis = JSON.parse(fs.readFileSync('analysis.json'));
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## CVE Analysis\n**Decision:** ${analysis.exemption_decision}\n\n${analysis.exemption_justification}`
            });
```

## Output Schema

```json
{
  "cve_id": "CVE-2024-1234",
  "risk_level": "CRITICAL | HIGH | MEDIUM | LOW",
  "exploitability_score": 1-10,
  "active_exploits_exist": true|false,
  "cia_impact": {
    "confidentiality": "HIGH|LOW|NONE",
    "integrity": "HIGH|LOW|NONE",
    "availability": "HIGH|LOW|NONE"
  },
  "patch_available": true|false,
  "patch_details": "...",
  "runtime_policy_recommendations": "...",
  "external_controls_recommendations": "...",
  "mitigation_strategies": "...",
  "container_specific_risks": "...",
  "exemption_decision": "APPROVED | DENIED | CONDITIONAL",
  "exemption_justification": "...",
  "caveats_and_conditions": "..."
}
```

## Cost Estimation

**AWS Bedrock (Claude 3.5 Sonnet) Pricing** (as of 2024):
- Input: $3 per 1M tokens
- Output: $15 per 1M tokens

**Typical CVE analysis**:
- Input tokens: ~2,000
- Output tokens: ~1,500
- **Cost per analysis: ~$0.03**

**Monthly estimates**:
- 100 CVEs/month: ~$3
- 500 CVEs/month: ~$15
- 1000 CVEs/month: ~$30

## Alternative Models

You can use different Bedrock models by setting `BEDROCK_MODEL_ID` in `.env`:

| Model | Best For | Speed | Cost |
|-------|----------|-------|------|
| `anthropic.claude-3-5-sonnet-20241022-v2:0` | **Recommended** - Best balance | Fast | Medium |
| `anthropic.claude-3-opus-20240229-v1:0-v1:0` | Most thorough analysis | Slow | High |
| `anthropic.claude-3-haiku-20240307-v1:0` | Quick screening | Very Fast | Low |

## Troubleshooting

### Error: "Access denied to model"

**Solution**: Enable Bedrock model access in AWS Console:
```bash
1. Go to AWS Bedrock Console
2. Click "Model access" in left sidebar
3. Click "Manage model access"
4. Enable "Claude 3.5 Sonnet"
5. Wait for approval
```

### Error: "Rate limit exceeded" (NVD API)

**Solution**:
1. Get NVD API key: https://nvd.nist.gov/developers/request-an-api-key
2. Add to `.env`: `NVD_API_KEY=your-key-here`

### Error: "AWS credentials not found"

**Solution**:
```bash
aws configure
# Or export credentials
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
```

## Project Structure

```
vulnerability-management/
├── src/
│   ├── __init__.py
│   ├── nvd_client.py          # NIST NVD API client
│   └── cve_analyzer.py        # Main analysis engine
├── analyze_cve.py             # CLI tool
├── requirements.txt           # Python dependencies
├── .env.example              # Environment template
├── example_batch.json        # Batch analysis example
└── README.md                 # This file
```

## Security Considerations

- **Never commit `.env` file** with real credentials
- Store AWS credentials securely (use IAM roles in production)
- Review AI recommendations - they are guidance, not absolute truth
- Implement approval workflows for exemptions
- Log all exemption decisions for audit trails

## Support

For issues or questions:
1. Check AWS Bedrock service health
2. Verify NIST NVD API status: https://nvd.nist.gov/
3. Review AWS CloudWatch logs for Bedrock API calls

## License

MIT License - Use freely for your security operations.

## Contributing

Contributions welcome! Areas for improvement:
- Integration with Jira/ServiceNow for ticketing
- Support for other LLM providers (OpenAI, Azure)
- Enhanced exploit database checks (ExploitDB, Metasploit API)
- CISA KEV catalog integration
- Custom exemption criteria per environment
