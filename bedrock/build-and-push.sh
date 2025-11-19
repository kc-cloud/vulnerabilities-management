#!/bin/bash
#
# Build and Push CVE Analyzer Docker Image to AWS ECR
#
# Usage:
#   ./build-and-push.sh [ECR_REPO_NAME] [AWS_REGION] [AWS_PROFILE]
#
# Example:
#   ./build-and-push.sh cve-analyzer us-east-1 sectool-dev
#

set -e

# Configuration
ECR_REPO_NAME="${1:-cve-analyzer}"
AWS_REGION="${2:-us-east-1}"
AWS_PROFILE="${3:-sectool-dev}"
IMAGE_TAG="${4:-latest}"

# Derived variables
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --profile $AWS_PROFILE --query Account --output text)
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_REPO="${ECR_REGISTRY}/${ECR_REPO_NAME}"

echo "========================================="
echo "CVE Analyzer - Build & Push to ECR"
echo "========================================="
echo "AWS Account:  $AWS_ACCOUNT_ID"
echo "AWS Region:   $AWS_REGION"
echo "AWS Profile:  $AWS_PROFILE"
echo "ECR Registry: $ECR_REGISTRY"
echo "ECR Repo:     $ECR_REPO_NAME"
echo "Image Tag:    $IMAGE_TAG"
echo "========================================="

# Step 1: Create ECR repository if it doesn't exist
echo ""
echo "Step 1: Checking if ECR repository exists..."
if ! aws ecr describe-repositories \
    --repository-names $ECR_REPO_NAME \
    --region $AWS_REGION \
    --profile $AWS_PROFILE > /dev/null 2>&1; then

    echo "Creating ECR repository: $ECR_REPO_NAME"
    aws ecr create-repository \
        --repository-name $ECR_REPO_NAME \
        --region $AWS_REGION \
        --profile $AWS_PROFILE \
        --image-scanning-configuration scanOnPush=true \
        --encryption-configuration encryptionType=AES256

    echo "✓ ECR repository created"
else
    echo "✓ ECR repository already exists"
fi

# Step 2: Authenticate Docker to ECR
echo ""
echo "Step 2: Authenticating Docker to ECR..."
aws ecr get-login-password \
    --region $AWS_REGION \
    --profile $AWS_PROFILE | docker login \
    --username AWS \
    --password-stdin $ECR_REGISTRY

echo "✓ Docker authenticated to ECR"

# Step 3: Build Docker image
echo ""
echo "Step 3: Building Docker image..."
docker build \
    --platform linux/amd64 \
    -t $ECR_REPO_NAME:$IMAGE_TAG \
    -t $ECR_REPO:$IMAGE_TAG \
    -t $ECR_REPO:$(date +%Y%m%d-%H%M%S) \
    .

echo "✓ Docker image built"

# Step 4: Push to ECR
echo ""
echo "Step 4: Pushing image to ECR..."
docker push $ECR_REPO:$IMAGE_TAG
docker push $ECR_REPO:$(date +%Y%m%d-%H%M%S)

echo "✓ Image pushed to ECR"

# Step 5: Display summary
echo ""
echo "========================================="
echo "✓ BUILD AND PUSH COMPLETE"
echo "========================================="
echo "Image URI: $ECR_REPO:$IMAGE_TAG"
echo ""
echo "To deploy to EKS, update k8s/deployment.yaml with:"
echo "  image: $ECR_REPO:$IMAGE_TAG"
echo ""
echo "Then run:"
echo "  kubectl apply -f k8s/"
echo "========================================="
