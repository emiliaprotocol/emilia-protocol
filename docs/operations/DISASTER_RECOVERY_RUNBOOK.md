# EP Disaster Recovery Runbook
**Version:** 1.0  
**Last Updated:** 2026-04-07  
**Owner:** On-call operator  
**RTO Target:** 4 hours  
**RPO Target:** 1 hour  

---

## Overview

This runbook covers full and partial disaster recovery for the Emilia Protocol infrastructure:
- Vercel deployment (Next.js app)
- Supabase database (Postgres 15, project `xmiiwehtivksdjbultym`)
- Base L2 anchoring wallet

It does **not** cover user data breach response (see `INCIDENT_RESPONSE.md`).

---

## 1. Failure Classification

| Severity | Description | Target recovery |
|----------|-------------|-----------------|
| SEV-1 | Total API outage (all routes returning 5xx) | 1 hour |
| SEV-2 | Partial outage (specific route category failing) | 2 hours |
| SEV-3 | Degraded performance (elevated latency, no data loss) | 4 hours |
| SEV-4 | Data inconsistency without outage | 24 hours |

---

## 2. Pre-Requisites

Before any DR action, confirm you have access to:
- [ ] Vercel dashboard (vercel.com/team)
- [ ] Supabase dashboard (`xmiiwehtivksdjbultym`)
- [ ] GitHub repo (emilia-protocol)
- [ ] Environment variable store (Vercel env settings)
- [ ] Basescan (basescan.org) to verify anchor transactions

---

## 3. Scenario: Vercel Deployment Failure

### Symptoms
- All API routes returning 500/503
- Vercel deployment stuck in "Building" or "Error" state
- Build logs show compilation error

### Steps

**3a. Identify the bad deployment**
```bash
vercel list --limit 10
```
Find the last-known-good deployment URL (format: `ep-abc123.vercel.app`).

**3b. Roll back to last-known-good deployment**
```bash
vercel rollback [deployment-url]
```
Or via Vercel dashboard: Deployments → select the prior green deployment → "Promote to Production".

**3c. Verify**
```bash
curl https://emiliaprotocol.com/api/health
# Expected: { "status": "ok" }
```

**3d. Root-cause the build failure**
```bash
vercel logs [deployment-url] --since 1h
```

---

## 4. Scenario: Supabase Database Outage

### 4a. Total Supabase outage (Supabase infrastructure failure)

**Symptoms:** All Supabase queries timing out, Supabase status page shows incident.

**Steps:**
1. Check Supabase status: status.supabase.com
2. If Supabase infrastructure incident: wait — this is outside your control
3. Enable read-only degraded mode if implemented (returns cached data or 503 with Retry-After)
4. Post status to customers via status page

**This is the key reason Supabase Pro (or higher) with PITR is required for regulated deployment.**

### 4b. Accidental data deletion / corruption

**Symptoms:** Missing rows, data anomalies, queries returning unexpected results.

**Steps:**

1. **Stop the bleeding — put the API in maintenance mode immediately:**
   Set `MAINTENANCE_MODE=true` in Vercel environment variables.
   Redeploy or use Vercel's instant rollback to a pre-incident deployment.

2. **Identify the scope:**
   ```sql
   -- Check recent deletions in key tables
   SELECT * FROM audit_events
   WHERE action_type LIKE '%delete%'
   ORDER BY created_at DESC
   LIMIT 50;
   ```

3. **Use Supabase Point-in-Time Recovery (PITR):**
   - Dashboard → Project → Settings → Database → Point in Time Recovery
   - Select a timestamp before the incident
   - Create a recovery branch
   - Validate the recovered data matches expectations
   - Merge or promote the recovery branch

4. **If PITR is not available (free plan):**
   - Use the most recent manual backup (see Section 7: Backup Schedule)
   - Restore to a new Supabase project
   - Update connection strings in Vercel env vars
   - Redeploy

5. **Reconcile blockchain anchors:**
   Any receipt batches anchored to Base L2 during the incident window must be reconciled.
   ```sql
   -- Find orphaned anchor batches (on-chain but no DB record)
   -- Query anchor_batches for the incident time window
   SELECT batch_id, transaction_hash, created_at
   FROM anchor_batches
   WHERE created_at BETWEEN '[incident_start]' AND '[incident_end]'
   ORDER BY created_at;
   ```
   Verify each `transaction_hash` on basescan.org. If a transaction exists on-chain but the
   DB record is missing, manually insert the batch record before restoring receipts.

---

## 5. Scenario: API Key Compromise

**Symptoms:** Anomalous API usage, unauthorized actions appearing in audit_events.

### Steps

1. **Immediately revoke the compromised key:**
   ```sql
   -- Via Supabase SQL editor (service role)
   UPDATE api_keys
   SET revoked_at = NOW(), revoke_reason = 'security_incident'
   WHERE key_hash = '[compromised_key_hash]';
   ```

2. **Audit actions taken by the key:**
   ```sql
   SELECT *
   FROM audit_events
   WHERE actor_key_hash = '[key_hash]'
   ORDER BY created_at DESC;
   ```

3. **Notify the affected entity** (the entity whose `entity_id` the key belongs to).

4. **If the `SUPABASE_SERVICE_ROLE_KEY` itself is compromised:**
   - Rotate immediately in Supabase dashboard: Settings → API → Service Role Key → Rotate
   - Update `SUPABASE_SERVICE_ROLE_KEY` in Vercel environment variables
   - Redeploy all active deployments
   - Audit all Supabase access logs for the exposure window

5. **If `EP_WALLET_PRIVATE_KEY` is compromised:**
   - Generate a new keypair: `openssl rand -hex 32`
   - Fund the new address with ETH on Base (~0.01 ETH)
   - Update `EP_WALLET_PRIVATE_KEY` in Vercel
   - The old wallet's on-chain history remains valid (blockchain is immutable)
   - Old key is permanently retired — zero its balance if possible

---

## 6. Scenario: Blockchain Anchor Failure

**Symptoms:** `anchor_batches` rows with `skipped_onchain: true`, or anchor cron returning errors.

### Steps

1. **Check wallet balance:**
   Wallet address can be derived from `EP_WALLET_PRIVATE_KEY` using:
   ```bash
   node -e "
   const { privateKeyToAccount } = require('viem/accounts');
   const a = privateKeyToAccount('0x' + process.env.EP_WALLET_PRIVATE_KEY);
   console.log(a.address);
   "
   ```
   Check balance on basescan.org. Fund if below 0.005 ETH.

2. **Retry failed anchors:**
   Failed batches that have a Merkle root but no `transaction_hash` can be re-anchored:
   ```sql
   SELECT batch_id, merkle_root, created_at
   FROM anchor_batches
   WHERE transaction_hash IS NULL
     AND skipped_onchain = false
   ORDER BY created_at;
   ```
   Re-run the anchor cron manually: `POST /api/blockchain/anchor` with cron auth.

3. **If Base L2 is down:**
   Receipts continue to be issued and Merkle trees continue to be built.
   Anchoring will succeed when Base L2 recovers.
   The `anchor_batch` DB record is the source of truth — Base L2 is the tamper-evidence layer.

---

## 7. Backup Schedule

| Resource | Method | Frequency | Retention |
|----------|--------|-----------|-----------|
| Supabase (schema + data) | PITR (Supabase Pro) | Continuous | 7 days |
| Supabase (schema only) | `pg_dump` via cron | Daily | 30 days |
| Vercel deployments | Immutable in Vercel | All builds | 90 days |
| Env vars | Manual copy in secure vault | On every change | Indefinite |
| Wallet private key | Hardware-backed secret store | N/A | Indefinite |

### Manual backup command (schema + data)
```bash
pg_dump \
  "postgresql://postgres:[SERVICE_ROLE_KEY]@db.xmiiwehtivksdjbultym.supabase.co:5432/postgres" \
  --no-owner \
  --no-acl \
  -F c \
  -f "ep_backup_$(date +%Y%m%d_%H%M%S).dump"
```

---

## 8. Recovery Drill (Run Quarterly)

Run this drill on a staging branch, not production.

1. [ ] Verify you can access all pre-requisites in Section 2
2. [ ] Create a Supabase branch: `main → staging-dr-drill-[date]`
3. [ ] Restore from PITR to 1 hour ago on the staging branch
4. [ ] Verify row counts on key tables match expectation
5. [ ] Run `vercel rollback` to the previous deployment on a preview URL
6. [ ] Verify `/api/health` returns 200
7. [ ] Post results to `#security` Slack channel with timestamp and duration
8. [ ] Update this runbook with any gaps found

---

## 9. Contacts

| Role | Contact |
|------|---------|
| Operator / On-call | (set in team runbook) |
| Supabase support | support.supabase.com (Pro plan: priority support) |
| Vercel support | vercel.com/support |
| Base L2 status | status.base.org |
