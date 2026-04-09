# EP on AWS — Deployment Guide

**Deploy a fully conformant EP operator on AWS infrastructure.**

This guide covers deploying EP Core as a second federation operator using AWS services. This is the reference architecture for organizations that need AWS-native deployment (compliance, data residency, existing AWS footprint).

---

## Architecture Overview

```
                    ┌─────────────────────────────────┐
                    │         CloudFront CDN           │
                    │    (/.well-known/*, /embed.js)   │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │       API Gateway (REST)         │
                    │    Rate limiting + WAF           │
                    └──────────────┬──────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
    ┌─────────▼────────┐ ┌────────▼─────────┐ ┌────────▼────────┐
    │  Lambda: Core    │ │  Lambda: Cron    │ │  Lambda: Auth   │
    │  (Trust API)     │ │  (Anchor/Expire) │ │  (Key rotation) │
    └─────────┬────────┘ └────────┬─────────┘ └────────┬────────┘
              │                    │                     │
              └────────────────────┼────────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │    Aurora Serverless v2          │
                    │    (PostgreSQL 16)               │
                    │    RLS policies + EP schema      │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │    ElastiCache (Redis)           │
                    │    Rate limiting backend         │
                    └─────────────────────────────────┘
```

---

## Prerequisites

- AWS account with CloudFormation access
- AWS CLI v2 configured (`aws configure`)
- Node.js >= 20
- EP source code (`git clone https://github.com/emiliaprotocol/emilia-protocol`)

---

## Step 1: Deploy Infrastructure (CloudFormation)

```bash
# Deploy the EP stack
aws cloudformation deploy \
  --template-file infrastructure/aws/template.yaml \
  --stack-name ep-operator \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    OperatorId=ep_operator_your_org \
    DomainName=ep.your-org.com \
    DBMasterPassword=$(openssl rand -hex 32)
```

This creates:
- Aurora Serverless v2 (PostgreSQL 16) with EP schema
- Lambda functions for API, cron, and auth
- API Gateway with WAF rules
- CloudFront distribution
- ElastiCache Redis cluster
- Secrets Manager for credentials
- EventBridge rules for cron tasks

---

## Step 2: Apply EP Schema

```bash
# Connect to Aurora and apply migrations
export DATABASE_URL=$(aws secretsmanager get-secret-value \
  --secret-id ep-operator/database-url \
  --query SecretString --output text)

# Apply all EP migrations
for f in supabase/migrations/*.sql; do
  psql "$DATABASE_URL" -f "$f"
done
```

---

## Step 3: Deploy Lambda Functions

```bash
# Package and deploy
cd infrastructure/aws
./deploy-lambdas.sh
```

The deploy script:
1. Bundles EP Core (`lib/`) into Lambda deployment packages
2. Configures environment variables from Secrets Manager
3. Deploys via `aws lambda update-function-code`

---

## Step 4: Configure Discovery Endpoints

EP operators must publish two discovery documents:

### `/.well-known/ep-trust.json`

```json
{
  "version": "1.0",
  "protocol_version": "EP-CORE-v1.0",
  "operator_id": "ep_operator_your_org",
  "operator_name": "Your Organization",
  "api_base": "https://ep.your-org.com/api",
  "keys_url": "https://ep.your-org.com/.well-known/ep-keys.json",
  "extensions": ["handshake", "signoff", "commit", "eye"],
  "federation": {
    "accepts_cross_operator_receipts": true,
    "verification_endpoint": "/api/verify/{receipt_id}"
  }
}
```

### `/.well-known/ep-keys.json`

```json
{
  "version": "1.0",
  "operator_id": "ep_operator_your_org",
  "keys": {}
}
```

Keys are auto-populated as entities register.

---

## Step 5: Run Conformance Test

```bash
npx ep-conformance-test https://ep.your-org.com

# Expected output:
# ✓ Discovery (/.well-known/ep-trust.json)
# ✓ Key publication (/.well-known/ep-keys.json)
# ✓ Entity registration
# ✓ Trust Receipt format (EP-RECEIPT-v1)
# ✓ Ed25519 receipt signature
# ✓ Trust Profile schema
# ✓ Trust Decision schema
# ✓ Handshake extension (PIP-002)
# CONFORMANT: EP Core v1.0
```

---

## Cost Estimate

| Service | Monthly Cost (estimated) |
|---------|------------------------|
| Aurora Serverless v2 (2 ACU min) | ~$90 |
| Lambda (1M invocations) | ~$20 |
| API Gateway | ~$15 |
| CloudFront | ~$10 |
| ElastiCache (cache.t4g.micro) | ~$15 |
| Secrets Manager | ~$5 |
| **Total** | **~$155/month** |

---

## Security Considerations

- All secrets stored in AWS Secrets Manager (never in env files)
- Aurora encryption at rest (AES-256) and in transit (TLS 1.3)
- Lambda runs in VPC with private subnets
- WAF rules block common attack patterns
- API Gateway throttling as first-line rate limiting
- ElastiCache for application-level rate limiting (fail-closed)
- CloudWatch alarms for anomaly detection

---

## Federation Registration

Once conformant, register your operator:

1. **GitHub Registry (Phase 1):** Submit PR to `emiliaprotocol/federation-registry`
2. **On-chain Registry (Phase 2):** Register operator_id on Base L2
3. **DNS Discovery (Phase 3):** Add `_ep-operator` TXT record

See [FEDERATION-SPEC.md](../FEDERATION-SPEC.md) for details.
