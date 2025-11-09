#!/bin/bash
# Setup script for CVE Vulnerability Management Tool

set -e

echo "=================================================="
echo "CVE Vulnerability Management Tool - Setup"
echo "=================================================="

# Check Python version
echo ""
echo "1. Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo "   ✓ Python $PYTHON_VERSION found"
else
    echo "   ✗ Python 3 not found. Please install Python 3.9 or higher."
    exit 1
fi

# Check AWS CLI
echo ""
echo "2. Checking AWS CLI..."
if command -v aws &> /dev/null; then
    AWS_VERSION=$(aws --version 2>&1 | cut -d' ' -f1)
    echo "   ✓ $AWS_VERSION found"
else
    echo "   ✗ AWS CLI not found. Please install: https://aws.amazon.com/cli/"
    exit 1
fi

# Check AWS credentials
echo ""
echo "3. Checking AWS credentials..."
if aws sts get-caller-identity &> /dev/null; then
    AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    echo "   ✓ AWS credentials configured (Account: $AWS_ACCOUNT)"
else
    echo "   ✗ AWS credentials not configured. Run: aws configure"
    exit 1
fi

# Create virtual environment
echo ""
echo "4. Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "   ✓ Virtual environment created"
else
    echo "   ✓ Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
echo ""
echo "5. Installing dependencies..."
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo "   ✓ Dependencies installed"

# Setup .env file
echo ""
echo "6. Setting up environment variables..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "   ✓ .env file created from template"
    echo ""
    echo "   ⚠️  Please edit .env and configure:"
    echo "      - AWS_REGION (if different from us-east-1)"
    echo "      - NVD_API_KEY (optional, get from https://nvd.nist.gov/developers/request-an-api-key)"
else
    echo "   ✓ .env file already exists"
fi

# Check Bedrock access
echo ""
echo "7. Checking AWS Bedrock access..."
AWS_REGION=$(grep AWS_REGION .env | cut -d'=' -f2 | tr -d ' ' || echo "us-east-1")
if aws bedrock list-foundation-models --region $AWS_REGION &> /dev/null; then
    echo "   ✓ AWS Bedrock is accessible in $AWS_REGION"

    # Check for Claude model access
    if aws bedrock list-foundation-models --region $AWS_REGION --query "modelSummaries[?contains(modelId, 'claude-3-5-sonnet')]" | grep -q "claude"; then
        echo "   ✓ Claude 3.5 Sonnet model is available"
    else
        echo "   ⚠️  Claude 3.5 Sonnet model access needed"
        echo "      Go to: https://console.aws.amazon.com/bedrock/home?region=$AWS_REGION#/modelaccess"
        echo "      Enable: Anthropic Claude 3.5 Sonnet"
    fi
else
    echo "   ⚠️  Cannot access AWS Bedrock in $AWS_REGION"
    echo "      1. Check if Bedrock is available in your region"
    echo "      2. Verify IAM permissions (bedrock:InvokeModel)"
fi

echo ""
echo "=================================================="
echo "Setup Complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run quick start example: python quick_start.py"
echo "  3. Or analyze a CVE: python analyze_cve.py --help"
echo ""
echo "For detailed documentation, see README.md"
echo ""
