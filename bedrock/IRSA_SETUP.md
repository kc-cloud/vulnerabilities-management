# IRSA Setup Guide for CVE Analyzer

This guide explains how to set up IAM Roles for Service Accounts (IRSA) to allow your CVE Analyzer application running in EKS to access AWS Bedrock without hardcoded credentials.

## Overview

IRSA allows Kubernetes pods to assume AWS IAM roles using the EKS OIDC provider. This is more secure than using access keys because:
- No credentials stored in the application
- Fine-grained permissions per service
- Automatic credential rotation
- Audit trail in CloudTrail

---

## Step 1: Create IAM Policy for Bedrock Access

First, create a policy with the Bedrock permissions your application needs:

```bash
cat > bedrock-policy.json <<EOF
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
EOF
```

Create the policy in AWS:

```bash
aws iam create-policy \
  --policy-name CVEAnalyzerBedrockPolicy \
  --policy-document file://bedrock-policy.json \
  --profile YOUR_PROFILE
```

Save the policy ARN from the output - you'll need it in the next step.

---

## Step 2: Create IRSA Role (Recommended Method with eksctl)

Using `eksctl` is the easiest method as it handles the trust policy and OIDC configuration automatically.

### Set environment variables:

```bash
export CLUSTER_NAME="your-cluster-name"
export AWS_REGION="us-east-1"
export AWS_PROFILE="your-aws-profile"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile $AWS_PROFILE)
```

### Create the IAM role and ServiceAccount:

```bash
eksctl create iamserviceaccount \
  --name cve-analyzer-sa \
  --namespace cve-analyzer \
  --cluster $CLUSTER_NAME \
  --region $AWS_REGION \
  --attach-policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/CVEAnalyzerBedrockPolicy \
  --approve \
  --override-existing-serviceaccounts \
  --profile $AWS_PROFILE
```

This command will:
1. Create an IAM role with the trust policy for your EKS cluster's OIDC provider
2. Attach the CVEAnalyzerBedrockPolicy to the role
3. Create the Kubernetes ServiceAccount with the proper annotation
4. Output the role ARN

---

## Step 3: Get the IAM Role ARN

After creating the service account, retrieve the IAM role ARN:

```bash
eksctl get iamserviceaccount \
  --cluster $CLUSTER_NAME \
  --namespace cve-analyzer \
  --name cve-analyzer-sa \
  --profile $AWS_PROFILE
```

Example output:
```
NAMESPACE       NAME              ROLE ARN
cve-analyzer    cve-analyzer-sa   arn:aws:iam::123456789012:role/eksctl-your-cluster-addon-iamserviceacco-Role1-XXXXX
```

Copy the Role ARN - you'll need it for Step 4.

---

## Step 4: Update ServiceAccount Manifest (if needed)

If you used `eksctl`, it already created the ServiceAccount in your cluster with the correct annotation.

However, if you want to apply it manually or verify the configuration, update `k8s/serviceaccount.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cve-analyzer-sa
  namespace: cve-analyzer
  labels:
    app: cve-analyzer
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/eksctl-your-cluster-addon-iamserviceacco-Role1-XXXXX"
```

Replace the ARN with your actual IAM role ARN from Step 3.

---

## Step 5: Verify the Setup

### Check if the ServiceAccount exists:

```bash
kubectl get serviceaccount cve-analyzer-sa -n cve-analyzer -o yaml
```

You should see the `eks.amazonaws.com/role-arn` annotation.

### Check if the OIDC provider is configured:

```bash
aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --region $AWS_REGION \
  --query "cluster.identity.oidc.issuer" \
  --output text \
  --profile $AWS_PROFILE
```

### Verify IAM role trust policy:

```bash
aws iam get-role \
  --role-name eksctl-your-cluster-addon-iamserviceacco-Role1-XXXXX \
  --profile $AWS_PROFILE
```

The trust policy should include your EKS OIDC provider and the service account.

---

## Alternative: Manual IAM Role Creation

If you cannot use `eksctl` or prefer manual setup, follow these steps:

### 1. Get your EKS OIDC provider URL:

```bash
OIDC_PROVIDER=$(aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --region $AWS_REGION \
  --query "cluster.identity.oidc.issuer" \
  --output text \
  --profile $AWS_PROFILE | sed -e "s/^https:\/\///")

echo $OIDC_PROVIDER
```

Extract the OIDC provider ID (last part after `/id/`):

```bash
OIDC_PROVIDER_ID=$(echo $OIDC_PROVIDER | awk -F'/' '{print $NF}')
echo $OIDC_PROVIDER_ID
```

### 2. Create trust policy:

```bash
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:cve-analyzer:cve-analyzer-sa",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF
```

### 3. Create the IAM role:

```bash
aws iam create-role \
  --role-name cve-analyzer-bedrock-role \
  --assume-role-policy-document file://trust-policy.json \
  --profile $AWS_PROFILE
```

### 4. Attach the Bedrock policy:

```bash
aws iam attach-role-policy \
  --role-name cve-analyzer-bedrock-role \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/CVEAnalyzerBedrockPolicy \
  --profile $AWS_PROFILE
```

### 5. Get the role ARN:

```bash
aws iam get-role \
  --role-name cve-analyzer-bedrock-role \
  --query 'Role.Arn' \
  --output text \
  --profile $AWS_PROFILE
```

### 6. Update serviceaccount.yaml and apply:

Edit `k8s/serviceaccount.yaml` with the role ARN, then:

```bash
kubectl apply -f k8s/serviceaccount.yaml
```

---

## Troubleshooting

### Pod cannot assume the IAM role

**Symptoms:** Pods fail with "AccessDeniedException" or "Unable to locate credentials"

**Check:**
1. Verify OIDC provider is configured:
   ```bash
   aws eks describe-cluster --name $CLUSTER_NAME --region $AWS_REGION --query "cluster.identity.oidc.issuer"
   ```

2. Verify ServiceAccount annotation:
   ```bash
   kubectl get sa cve-analyzer-sa -n cve-analyzer -o yaml
   ```

3. Check pod environment variables:
   ```bash
   kubectl exec -it <pod-name> -n cve-analyzer -- env | grep AWS
   ```

   You should see:
   - `AWS_ROLE_ARN`
   - `AWS_WEB_IDENTITY_TOKEN_FILE`

4. Verify IAM role trust policy includes the correct ServiceAccount

### Bedrock access denied

**Symptoms:** Pods can assume the role but get "AccessDeniedException" when calling Bedrock

**Check:**
1. Verify the IAM policy is attached to the role:
   ```bash
   aws iam list-attached-role-policies --role-name <role-name>
   ```

2. Verify the policy has the correct Bedrock permissions:
   ```bash
   aws iam get-policy-version \
     --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/CVEAnalyzerBedrockPolicy \
     --version-id v1
   ```

3. Check if the models are available in your region:
   ```bash
   aws bedrock list-foundation-models \
     --region $AWS_REGION \
     --query 'modelSummaries[?modelId==`anthropic.claude-3-5-sonnet-20240620-v1:0`]' \
     --profile $AWS_PROFILE
   ```

### OIDC provider not found

**Symptoms:** Error: "OpenIDConnect provider not found"

**Solution:** Create the OIDC provider for your cluster:

```bash
eksctl utils associate-iam-oidc-provider \
  --cluster $CLUSTER_NAME \
  --region $AWS_REGION \
  --approve \
  --profile $AWS_PROFILE
```

---

## Testing IRSA

Deploy a test pod to verify IRSA is working:

```bash
kubectl run -it --rm debug \
  --image=amazon/aws-cli \
  --serviceaccount=cve-analyzer-sa \
  --namespace=cve-analyzer \
  -- sts get-caller-identity
```

You should see output showing the assumed role ARN.

---

## Security Best Practices

1. **Least Privilege:** Only grant access to the specific Bedrock models you need
2. **Separate Roles:** Use different IAM roles for different applications/namespaces
3. **Monitor Usage:** Enable CloudTrail logging for Bedrock API calls
4. **Regular Audits:** Review IAM policies and trust relationships regularly
5. **Resource Tags:** Tag IAM roles for cost tracking and governance

---

## Additional Resources

- [AWS IRSA Documentation](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [eksctl IAM Service Accounts](https://eksctl.io/usage/iamserviceaccounts/)
- [AWS Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html)

---

## Quick Reference

### Environment Variables to Set
```bash
export CLUSTER_NAME="your-cluster-name"
export AWS_REGION="us-east-1"
export AWS_PROFILE="your-aws-profile"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile $AWS_PROFILE)
```

### One-liner to Create Everything
```bash
# Create policy
aws iam create-policy --policy-name CVEAnalyzerBedrockPolicy --policy-document file://bedrock-policy.json --profile $AWS_PROFILE

# Create IRSA
eksctl create iamserviceaccount \
  --name cve-analyzer-sa \
  --namespace cve-analyzer \
  --cluster $CLUSTER_NAME \
  --region $AWS_REGION \
  --attach-policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/CVEAnalyzerBedrockPolicy \
  --approve \
  --override-existing-serviceaccounts \
  --profile $AWS_PROFILE
```

### Get Role ARN
```bash
eksctl get iamserviceaccount --cluster $CLUSTER_NAME --namespace cve-analyzer --name cve-analyzer-sa --profile $AWS_PROFILE
```
