# CVE Analyzer - EKS Deployment Guide

Complete guide for building and deploying the CVE Analyzer to AWS EKS with public LoadBalancer access.

## Prerequisites

### Required Tools
- Docker
- AWS CLI v2
- kubectl
- eksctl (optional, for IRSA setup)

### AWS Requirements
- AWS Account with EKS cluster already running
- IAM permissions for:
  - ECR (create repository, push images)
  - Bedrock (invoke models)
  - EKS (deploy workloads)
- AWS Load Balancer Controller installed in EKS cluster

### EKS Cluster Requirements
- Running EKS cluster
- AWS Load Balancer Controller installed
- Metrics Server installed (for HPA)

---

## Step 1: Create IAM Role for Bedrock Access (IRSA)

The application needs AWS Bedrock permissions. Use IRSA (IAM Roles for Service Accounts) for secure authentication.

### 1.1 Get your EKS cluster's OIDC provider

```bash
export CLUSTER_NAME="your-eks-cluster-name"
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Get OIDC provider
aws eks describe-cluster --name $CLUSTER_NAME --region $AWS_REGION --query "cluster.identity.oidc.issuer" --output text
```

### 1.2 Create IAM policy for Bedrock access

Create file `bedrock-policy.json`:

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
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-1-20250805-v1:0",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-4-1-opus-20250805-v1:0",
        "arn:aws:bedrock:*::foundation-model/amazon.nova-pro-v1:0",
        "arn:aws:bedrock:*::foundation-model/meta.llama3-70b-instruct-v1:0"
      ]
    }
  ]
}
```

Create the policy:

```bash
aws iam create-policy \
  --policy-name CVEAnalyzerBedrockPolicy \
  --policy-document file://bedrock-policy.json
```

### 1.3 Create IAM role with trust policy

Using eksctl (easiest method):

```bash
eksctl create iamserviceaccount \
  --name cve-analyzer-sa \
  --namespace cve-analyzer \
  --cluster $CLUSTER_NAME \
  --region $AWS_REGION \
  --attach-policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/CVEAnalyzerBedrockPolicy \
  --approve \
  --override-existing-serviceaccounts
```

This creates:
- IAM role with trust policy for EKS OIDC
- Kubernetes ServiceAccount with annotation

### 1.4 Get the IAM Role ARN

```bash
eksctl get iamserviceaccount \
  --cluster $CLUSTER_NAME \
  --namespace cve-analyzer \
  --name cve-analyzer-sa
```

Copy the Role ARN - you'll need it for `k8s/serviceaccount.yaml`.

---

## Step 2: Build and Push Docker Image to ECR

### 2.1 Set environment variables

```bash
export ECR_REPO_NAME="cve-analyzer"
export AWS_REGION="us-east-1"
export AWS_PROFILE="sectool-dev"  # Your AWS profile
export IMAGE_TAG="latest"
```

### 2.2 Run the build script

```bash
cd /Users/mac/git-kc-cloud/vulnerabilities-management/bedrock

./build-and-push.sh $ECR_REPO_NAME $AWS_REGION $AWS_PROFILE $IMAGE_TAG
```

The script will:
1. Create ECR repository (if it doesn't exist)
2. Authenticate Docker to ECR
3. Build multi-arch Docker image
4. Push to ECR with tags: `latest` and `YYYYMMDD-HHMMSS`

### 2.3 Get the ECR image URI

```bash
export ECR_IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}"
echo $ECR_IMAGE_URI
```

Copy this URI - you'll need it for `k8s/deployment.yaml`.

---

## Step 3: Configure Kubernetes Manifests

### 3.1 Update ServiceAccount with IAM Role ARN

Edit `k8s/serviceaccount.yaml`:

```yaml
annotations:
  eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/eksctl-cluster-addon-iamserviceaccount-cve-Role1-XXX"
```

Replace with your actual IAM Role ARN from Step 1.4.

### 3.2 Update Deployment with ECR Image URI

Edit `k8s/deployment.yaml`:

```yaml
spec:
  template:
    spec:
      containers:
      - name: cve-analyzer
        image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/cve-analyzer:latest"
```

Replace with your actual ECR Image URI from Step 2.3.

### 3.3 (Optional) Add NVD API Key

If you have an NIST NVD API key for higher rate limits:

```bash
kubectl create secret generic cve-analyzer-secrets \
  --from-literal=NVD_API_KEY=your-nvd-api-key-here \
  --namespace cve-analyzer \
  --dry-run=client -o yaml | kubectl apply -f -
```

Or edit `k8s/secret.yaml` and add your key.

### 3.4 (Optional) Configure SSL/TLS

If you have an ACM certificate for HTTPS:

Edit `k8s/service.yaml` and uncomment:

```yaml
annotations:
  service.beta.kubernetes.io/aws-load-balancer-ssl-cert: "arn:aws:acm:region:account:certificate/cert-id"
  service.beta.kubernetes.io/aws-load-balancer-ssl-ports: "443"
```

---

## Step 4: Deploy to EKS

### 4.1 Create namespace and deploy

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
```

Or deploy all at once:

```bash
kubectl apply -f k8s/
```

### 4.2 Verify deployment

```bash
# Check namespace
kubectl get ns cve-analyzer

# Check pods
kubectl get pods -n cve-analyzer

# Check deployment
kubectl get deployment -n cve-analyzer

# Check service
kubectl get svc -n cve-analyzer

# Check HPA
kubectl get hpa -n cve-analyzer
```

### 4.3 Get LoadBalancer URL

```bash
kubectl get svc cve-analyzer -n cve-analyzer -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

Wait 2-3 minutes for the NLB to be provisioned and become active.

---

## Step 5: Access the Application

### 5.1 Get the LoadBalancer DNS

```bash
export LB_URL=$(kubectl get svc cve-analyzer -n cve-analyzer -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "Application URL: http://$LB_URL"
```

### 5.2 Open in browser

```bash
open "http://$LB_URL"
```

Or navigate to the URL in your browser.

---

## Monitoring and Troubleshooting

### View pod logs

```bash
# Get pod name
kubectl get pods -n cve-analyzer

# View logs
kubectl logs <pod-name> -n cve-analyzer -f

# View logs from all pods
kubectl logs -l app=cve-analyzer -n cve-analyzer --tail=100
```

### Describe pod for issues

```bash
kubectl describe pod <pod-name> -n cve-analyzer
```

### Check events

```bash
kubectl get events -n cve-analyzer --sort-by='.lastTimestamp'
```

### Exec into pod

```bash
kubectl exec -it <pod-name> -n cve-analyzer -- /bin/bash
```

### Check HPA metrics

```bash
kubectl get hpa -n cve-analyzer -w
```

### View service endpoints

```bash
kubectl get endpoints -n cve-analyzer
```

---

## Scaling

### Manual scaling

```bash
# Scale to 5 replicas
kubectl scale deployment cve-analyzer -n cve-analyzer --replicas=5
```

### Auto-scaling (HPA)

The HPA is configured to scale between 2-10 replicas based on:
- CPU utilization: 70%
- Memory utilization: 80%

To adjust:

```bash
kubectl edit hpa cve-analyzer-hpa -n cve-analyzer
```

---

## Updates and Rollouts

### Update to new image version

```bash
# Build and push new image
./build-and-push.sh cve-analyzer us-east-1 sectool-dev v2.0

# Update deployment
kubectl set image deployment/cve-analyzer \
  cve-analyzer=123456789012.dkr.ecr.us-east-1.amazonaws.com/cve-analyzer:v2.0 \
  -n cve-analyzer

# Watch rollout status
kubectl rollout status deployment/cve-analyzer -n cve-analyzer
```

### Rollback

```bash
# Rollback to previous version
kubectl rollout undo deployment/cve-analyzer -n cve-analyzer

# Rollback to specific revision
kubectl rollout undo deployment/cve-analyzer --to-revision=2 -n cve-analyzer
```

### View rollout history

```bash
kubectl rollout history deployment/cve-analyzer -n cve-analyzer
```

---

## Cleanup

### Delete application

```bash
kubectl delete -f k8s/
```

### Delete ECR repository

```bash
aws ecr delete-repository \
  --repository-name cve-analyzer \
  --region us-east-1 \
  --force
```

### Delete IAM resources (if using eksctl)

```bash
eksctl delete iamserviceaccount \
  --cluster $CLUSTER_NAME \
  --namespace cve-analyzer \
  --name cve-analyzer-sa
```

---

## Security Best Practices

### 1. Network Security
- ✅ Service uses NLB with health checks
- ✅ Pods run as non-root user (UID 1000)
- ✅ ReadOnlyRootFilesystem where possible
- ⚠️ Consider adding WAF in front of NLB
- ⚠️ Consider restricting source IPs via security groups

### 2. Secrets Management
- ✅ Use Kubernetes Secrets for sensitive data
- ✅ Use IRSA instead of access keys
- ⚠️ Consider AWS Secrets Manager integration
- ⚠️ Enable encryption at rest for secrets

### 3. Access Control
- ⚠️ Configure RBAC for namespace access
- ⚠️ Use Pod Security Standards/Policies
- ⚠️ Enable audit logging

### 4. Monitoring
- ⚠️ Integrate with CloudWatch Container Insights
- ⚠️ Set up alarms for pod failures
- ⚠️ Monitor Bedrock API costs

---

## Cost Optimization

1. **Right-size resources**: Adjust CPU/memory requests/limits based on actual usage
2. **Use Spot instances**: For non-critical workloads
3. **Configure HPA**: Auto-scale based on actual load
4. **Monitor Bedrock costs**: Track model invocation costs

---

## Support

For issues:
1. Check pod logs
2. Review events
3. Verify IAM permissions
4. Check AWS Load Balancer Controller logs
5. Verify security group configurations

For application issues, see [README.md](README.md) and [MULTI_MODEL_COMPARISON.md](MULTI_MODEL_COMPARISON.md).
