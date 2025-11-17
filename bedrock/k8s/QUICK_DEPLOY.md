# Quick Deploy Reference

## Prerequisites Checklist
- [ ] EKS cluster running
- [ ] AWS Load Balancer Controller installed
- [ ] kubectl configured
- [ ] AWS CLI configured with profile

## Quick Deploy Commands

### 1. Build & Push (5 min)
```bash
./build-and-push.sh cve-analyzer us-east-1 sectool-dev latest
```

### 2. Create IRSA (2 min)
```bash
eksctl create iamserviceaccount \
  --name cve-analyzer-sa \
  --namespace cve-analyzer \
  --cluster YOUR_CLUSTER_NAME \
  --region us-east-1 \
  --attach-policy-arn arn:aws:iam::YOUR_ACCOUNT:policy/CVEAnalyzerBedrockPolicy \
  --approve
```

### 3. Update Manifests (1 min)
```bash
# Edit k8s/serviceaccount.yaml - add IAM role ARN
# Edit k8s/deployment.yaml - add ECR image URI
```

### 4. Deploy (1 min)
```bash
kubectl apply -f k8s/
```

### 5. Get URL (2 min)
```bash
kubectl get svc cve-analyzer -n cve-analyzer
```

## Total Time: ~10 minutes

## Verify
```bash
kubectl get all -n cve-analyzer
```

## Access
```bash
export LB_URL=$(kubectl get svc cve-analyzer -n cve-analyzer -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "http://$LB_URL"
```
