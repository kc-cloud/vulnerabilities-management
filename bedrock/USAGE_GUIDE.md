# CVE Analyzer - Detailed Usage Guide

## Quick Start (5 minutes)

### Step 1: Setup

```bash
# Run the setup script
./setup.sh

# Activate virtual environment
source venv/bin/activate
```

### Step 2: Configure AWS

Ensure AWS Bedrock is enabled:
1. Go to AWS Console → Bedrock → Model access
2. Enable "Anthropic Claude 3.5 Sonnet"
3. Wait for approval (usually instant)

### Step 3: Run Your First Analysis

```bash
# Run the quick start example
python quick_start.py
```

This will analyze CVE-2024-3094 (xz-utils backdoor) and generate a report.

## Command Line Usage

### Basic CVE Analysis

```bash
python analyze_cve.py \
  --cve CVE-2024-1234 \
  --component curl \
  --version 7.68.0 \
  --source OS \
  --image nginx:latest
```

### Parameters Explained

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| `--cve` | CVE identifier | CVE-2024-1234 |
| `--component` | Package/library name | curl, openssl, python |
| `--version` | Component version | 7.68.0, 1.2.3 |
| `--source` | Source type | OS, python, java, nodejs, go, ruby, dotnet |
| `--image` | Container image | nginx:latest, ubuntu:22.04 |

### JSON Output

For programmatic access:

```bash
python analyze_cve.py \
  --cve CVE-2024-1234 \
  --component curl \
  --version 7.68.0 \
  --source OS \
  --image nginx:latest \
  --json > result.json
```

### Batch Processing

Create a JSON file `cve_list.json`:

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

Process multiple CVEs:

```bash
python analyze_cve.py --batch cve_list.json --output results.json
```

## Python API Usage

### Basic Usage

```python
from src.cve_analyzer import CVEAnalyzer

# Initialize
analyzer = CVEAnalyzer(
    aws_region="us-east-1",
    model_id="anthropic.claude-3-5-sonnet-20241022-v2:0"
)

# Analyze single CVE
result = analyzer.analyze_cve(
    cve_id="CVE-2024-1234",
    component_name="curl",
    component_version="7.68.0",
    source_type="OS",
    image_name="nginx:latest"
)

# Access results
print(f"Decision: {result.exemption_decision}")
print(f"Risk Level: {result.risk_level}")
print(f"Justification: {result.exemption_justification}")
```

### Batch Processing in Python

```python
cve_requests = [
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

results = analyzer.batch_analyze_cves(cve_requests)

for result in results:
    print(f"{result['cve_id']}: {result['exemption_decision']}")
```

### Custom Model Configuration

```python
# Use Claude Opus for more thorough analysis
analyzer = CVEAnalyzer(
    aws_region="us-east-1",
    model_id="anthropic.claude-3-opus-20240229-v1:0"
)

# Use Claude Haiku for faster, cheaper analysis
analyzer = CVEAnalyzer(
    aws_region="us-east-1",
    model_id="anthropic.claude-3-haiku-20240307-v1:0"
)
```

## Integration Patterns

### 1. Jira/ServiceNow Integration

```python
import requests
from src.cve_analyzer import CVEAnalyzer

def analyze_and_update_ticket(ticket_id, cve_data):
    analyzer = CVEAnalyzer()

    result = analyzer.analyze_cve(
        cve_id=cve_data["cve_id"],
        component_name=cve_data["component"],
        component_version=cve_data["version"],
        source_type=cve_data["source"],
        image_name=cve_data["image"]
    )

    # Update Jira ticket
    jira_comment = f"""
    ## CVE Analysis Results

    **Decision:** {result.exemption_decision}
    **Risk Level:** {result.risk_level}

    **Justification:**
    {result.exemption_justification}

    **Recommended Actions:**
    {result.mitigation_strategies}
    """

    # Post to Jira API
    requests.post(
        f"https://your-jira.atlassian.net/rest/api/2/issue/{ticket_id}/comment",
        json={"body": jira_comment},
        auth=("user@example.com", "api_token")
    )
```

### 2. Slack Integration

```python
from slack_sdk import WebClient
from src.cve_analyzer import CVEAnalyzer

def analyze_and_notify_slack(cve_id, component, version, source, image, channel):
    analyzer = CVEAnalyzer()

    result = analyzer.analyze_cve(
        cve_id=cve_id,
        component_name=component,
        component_version=version,
        source_type=source,
        image_name=image
    )

    slack_client = WebClient(token="xoxb-your-token")

    color = "danger" if result.exemption_decision == "DENIED" else \
            "warning" if result.exemption_decision == "CONDITIONAL" else "good"

    slack_client.chat_postMessage(
        channel=channel,
        text=f"CVE Analysis: {cve_id}",
        attachments=[{
            "color": color,
            "fields": [
                {"title": "CVE", "value": cve_id, "short": True},
                {"title": "Decision", "value": result.exemption_decision, "short": True},
                {"title": "Risk Level", "value": result.risk_level, "short": True},
                {"title": "Exploitability", "value": f"{result.exploitability_score}/10", "short": True},
                {"title": "Justification", "value": result.exemption_justification, "short": False}
            ]
        }]
    )
```

### 3. GitHub Actions Workflow

```yaml
# .github/workflows/cve-check.yml
name: CVE Exemption Check

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  cve-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Extract CVEs from PR
        id: extract-cves
        run: |
          # Extract CVE IDs from PR body/title
          echo "cves=$(echo '${{ github.event.pull_request.body }}' | grep -oE 'CVE-[0-9]{4}-[0-9]+' | jq -R -s -c 'split("\n") | map(select(length > 0))')" >> $GITHUB_OUTPUT

      - name: Analyze CVEs
        run: |
          CVES='${{ steps.extract-cves.outputs.cves }}'
          echo "$CVES" | jq -r '.[]' | while read cve; do
            python analyze_cve.py \
              --cve "$cve" \
              --component "unknown" \
              --version "unknown" \
              --source OS \
              --image "${{ github.event.pull_request.head.ref }}" \
              --json > "${cve}_analysis.json"
          done

      - name: Comment on PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const files = fs.readdirSync('.').filter(f => f.endsWith('_analysis.json'));

            let comment = '## CVE Analysis Results\n\n';

            for (const file of files) {
              const analysis = JSON.parse(fs.readFileSync(file));
              comment += `### ${analysis.cve_id}\n`;
              comment += `- **Decision:** ${analysis.exemption_decision}\n`;
              comment += `- **Risk Level:** ${analysis.risk_level}\n`;
              comment += `- **Exploitability:** ${analysis.exploitability_score}/10\n`;
              comment += `- **Justification:** ${analysis.exemption_justification}\n\n`;
            }

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

## Real-World Scenarios

### Scenario 1: Weekly Security Review

Analyze all CVEs pending exemption:

```bash
# Export CVEs from your tracking system to batch.json
python analyze_cve.py --batch pending_cves.json --output weekly_report.json

# Generate summary
python -c "
import json
data = json.load(open('weekly_report.json'))
approved = sum(1 for r in data if r['exemption_decision'] == 'APPROVED')
denied = sum(1 for r in data if r['exemption_decision'] == 'DENIED')
conditional = sum(1 for r in data if r['exemption_decision'] == 'CONDITIONAL')
print(f'Summary: {approved} approved, {denied} denied, {conditional} conditional')
"
```

### Scenario 2: Emergency CVE Assessment

New critical CVE announced, need immediate assessment:

```bash
python analyze_cve.py \
  --cve CVE-2024-XXXX \
  --component log4j \
  --version 2.14.0 \
  --source java \
  --image production-app:latest \
  --json | jq '.exemption_decision, .exemption_justification'
```

### Scenario 3: Exemption Request Workflow

Developer submits exemption request:

```python
def process_exemption_request(request):
    """Process CVE exemption request from ticketing system"""
    analyzer = CVEAnalyzer()

    result = analyzer.analyze_cve(
        cve_id=request["cve_id"],
        component_name=request["component"],
        component_version=request["version"],
        source_type=request["source"],
        image_name=request["image"]
    )

    if result.exemption_decision == "APPROVED":
        # Auto-approve low risk
        update_ticket(request["ticket_id"], "APPROVED", result.exemption_justification)
        notify_team(f"CVE {request['cve_id']} exemption auto-approved")

    elif result.exemption_decision == "DENIED":
        # Require patching
        update_ticket(request["ticket_id"], "DENIED", result.exemption_justification)
        create_patching_task(request["cve_id"], result.patch_details)

    else:  # CONDITIONAL
        # Escalate to security team
        update_ticket(request["ticket_id"], "PENDING_REVIEW", result.exemption_justification)
        assign_to_security_team(request["ticket_id"], result)
```

## Advanced Configuration

### Custom Exemption Criteria

Modify `src/cve_analyzer.py` prompt to adjust decision criteria:

```python
# Example: Stricter criteria for production images
if "production" in image_name.lower():
    decision_criteria = """
    - DENIED if: CVSS >= 7.0 OR active exploits exist
    - CONDITIONAL if: 5.0 <= CVSS < 7.0 AND multiple compensating controls
    - APPROVED if: CVSS < 5.0 AND controls in place
    """
```

### Custom Output Format

```python
# Generate custom report format
result = analyzer.analyze_cve(...)

custom_report = f"""
SECURITY ASSESSMENT REPORT
========================
CVE: {result.cve_id}
Date: {datetime.now().strftime('%Y-%m-%d')}

RISK RATING: {result.risk_level}
CVSS: {cvss_score}
Exploitability: {result.exploitability_score}/10

DECISION: {result.exemption_decision}

RATIONALE:
{result.exemption_justification}

REQUIRED CONTROLS:
{result.caveats_and_conditions}

Analyst: Claude AI (AWS Bedrock)
"""

# Email to stakeholders
send_email(recipients, "CVE Assessment Complete", custom_report)
```

## Troubleshooting

### Issue: "Model not found"

```bash
# Check available models
aws bedrock list-foundation-models --region us-east-1 \
  --query "modelSummaries[?contains(modelId, 'claude')]" \
  --output table
```

### Issue: "Rate limit exceeded"

For NVD API rate limits, either:
1. Add NVD API key to `.env`
2. Add delays between requests
3. Cache CVE data locally

```python
import time

for cve in cve_list:
    result = analyzer.analyze_cve(...)
    time.sleep(6)  # 5 requests per 30 seconds = 6 seconds per request
```

### Issue: "Insufficient permissions"

Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet*"
    }
  ]
}
```

## Best Practices

1. **Cache CVE Data**: Store NVD API responses to avoid rate limits
2. **Version Control**: Track exemption decisions in Git
3. **Audit Trail**: Log all analysis results with timestamps
4. **Regular Reviews**: Re-analyze approved exemptions monthly
5. **Human Oversight**: Always review AI recommendations before final approval
6. **Context Matters**: Provide accurate image and component info for better analysis

## Support

For questions or issues:
- Check AWS Bedrock status: https://status.aws.amazon.com/
- Verify NVD API status: https://nvd.nist.gov/
- Review CloudWatch logs for API errors

## Additional Resources

- [NIST NVD API Documentation](https://nvd.nist.gov/developers)
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [LangChain Documentation](https://python.langchain.com/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
