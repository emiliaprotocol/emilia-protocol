# AI Trust Desk — Fully Automated Process Flow Spec

**Version:** 1.0
**Status:** Design proposal — not yet implemented
**Owner:** EP founder
**Goal:** A buyer-paid intake becomes a published, cryptographically signed trust page in **≤ 60 minutes**, with **zero human touch in the happy path** and **graceful escalation** when confidence drops below threshold.

---

## 1. North star

> Customer uploads a questionnaire at 9:00 AM. By 10:00 AM their buyer can open the trust page URL, see every answer, click through to the policy docs, and independently verify the cryptographic signature on any claim.

That's the bar. Everything below serves it.

---

## 2. SLA & quality contract

| Promise | Target | Hard ceiling |
|---------|--------|--------------|
| End-to-end latency (intake → trust page live) | 30 min | 60 min |
| Auto-publish rate (no human touch) | 80% | 60% floor |
| Reviewer-required escalation rate | 20% | 40% ceiling |
| Buyer-side verify success | 100% | 100% (non-negotiable) |
| Hallucinated claim rate (post-publish) | 0 | 0 (any incident = pause auto-publish) |
| Cost per engagement (LLM + infra) | ≤ $20 | ≤ $50 |

**Quality is enforced by the pipeline, not by the LLM.** No answer ships unless it cites a verified source. Unsourced answers escalate by default.

---

## 3. The pipeline (10 stages)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ 1. INTAKE   │ →  │ 2. PERSIST  │ →  │ 3. EXTRACT  │ →  │ 4. CLASSIFY │ →  │ 5. ANSWER   │
│ form + file │    │ S3 + DB row │    │ Q parser    │    │ bucket each │    │ schema-bound│
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                                                    ↓
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│10. MONITOR  │ ←  │ 9. NOTIFY   │ ←  │ 8. MINT     │ ←  │ 7. POLICIES │ ←  │ 6. VERIFY   │
│ expiry +    │    │ email + URL │    │ trust page  │    │ template    │    │ sources +   │
│ buyer Qs    │    │             │    │ JSON + sign │    │ substitute  │    │ confidence  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘

                              ESCAPE HATCH: any stage with confidence < threshold
                              → reviewer queue (Linear/Slack ticket auto-created)
```

---

## 4. Stage-by-stage spec

### Stage 1 — Intake (existing, needs fixes)

**File:** `app/trust-desk/upload/page.js`

**Fixes required:**
1. Make webhook POST **awaited** and surface failure to user (today: silently fire-and-forget — paid customers can ghost themselves)
2. Require `INTAKE_WEBHOOK_URL` at build time (env-var failure → build break, not silent prod no-op)
3. Replace `multipart/form-data` direct webhook post with: **POST to `/api/trust-desk/intake`** (own backend), which then writes to S3 + queues the job

**New backend endpoint:** `app/api/trust-desk/intake/route.js`
- Validates intake fields (Zod schema)
- Generates `engagement_id` (`eng_<12-hex>`)
- Stores file in S3 with presigned PUT URL pattern (~25 MB cap, server-side scanning via ClamAV)
- Inserts row into `trust_desk_engagements` table (Supabase or Postgres) with status `intake_received`
- Enqueues job onto **Vercel Workflow** (`workflow:trust-desk-pipeline`) with payload `{ engagement_id }`
- Returns `engagement_id` + ETA to client
- Sends customer "we got your intake, expect link by [ETA+5min]" email via Resend

### Stage 2 — Persist (new)

**Table:** `trust_desk_engagements`

```sql
CREATE TABLE trust_desk_engagements (
  engagement_id     TEXT PRIMARY KEY,
  customer_email    TEXT NOT NULL,
  company           TEXT NOT NULL,
  product_desc      TEXT,
  buyer_name        TEXT,
  selling_into      TEXT,
  ai_uses_data      TEXT,
  cloud_provider    TEXT,
  soc2_status       TEXT,
  tier              TEXT,  -- emergency | full | packet | retainer
  active_deal       BOOLEAN,

  questionnaire_s3_key  TEXT,
  questionnaire_sha256  TEXT,
  questionnaire_pages   INT,

  status            TEXT NOT NULL,  -- intake_received | extracting | answering | verifying | minting | published | escalated
  status_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  customer_slug     TEXT UNIQUE,  -- becomes /trust-desk/c/<slug>

  llm_cost_cents    INT DEFAULT 0,
  extraction_ms     INT,
  answering_ms      INT,
  verify_ms         INT,
  mint_ms           INT,

  reviewer_assigned     TEXT,    -- null if auto-published
  escalation_reason     TEXT,    -- null if auto-published
  escalated_at          TIMESTAMPTZ,

  published_at      TIMESTAMPTZ,
  expires_at        TIMESTAMPTZ,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_td_eng_status ON trust_desk_engagements(status, created_at);
CREATE INDEX idx_td_eng_customer ON trust_desk_engagements(customer_email);
```

**Why a real DB:** the existing JSON-on-disk pattern (`data/trust-desk/customers/*.json`) doesn't scale past ~50 customers and breaks atomic publish/expiry workflows. JSON file remains as the *renderable* artifact; DB holds the *pipeline state*.

### Stage 3 — Extract (new)

**Module:** `lib/trust-desk/extractor.js`

**Input:** S3 key for the customer's questionnaire (PDF/Excel/Word).

**Output:** Structured question list:
```js
{
  source_format: 'xlsx' | 'pdf' | 'docx',
  total_questions: 47,
  questions: [
    {
      id: 'q_001',
      text: 'Describe your prompt injection defense.',
      section: 'AI Security Controls',
      requires_freeform: true,
      extraction_confidence: 0.92,  // 0–1, from extractor
      page_or_cell: 'Sheet1!B14',
    },
    ...
  ]
}
```

**Mechanism:**
- **PDF:** `pdf-parse` for text layout + `tesseract.js` fallback on scanned PDFs
- **Excel:** `xlsx` (SheetJS) — heuristic: column "Question" or column with longest avg text length
- **Word:** `mammoth` to extract paragraphs + numbered lists
- **All:** post-process through Claude Sonnet with strict JSON schema to classify question vs metadata vs section header

**Escalation triggers:**
- `total_questions == 0` → escalate
- `extraction_confidence < 0.7` on any question → flag that question for human-only answering
- File parse error → escalate

### Stage 4 — Classify (new)

**Module:** `lib/trust-desk/classifier.js`

**Input:** Extracted questions.

**Output:** Each question tagged with bucket:

| Bucket | Description | Source of answer |
|--------|-------------|-----------------|
| `soc2_overlap` | Questions covered by standard SOC2 controls | Customer's SOC2 status field + boilerplate |
| `ai_template_match` | Questions covered by one of our 5 policy templates | Template content (deterministic) |
| `ai_specific` | AI questions not in our templates but answerable from intake + general knowledge | LLM with intake as RAG context |
| `customer_specific` | Requires customer-only knowledge (e.g., "list your subprocessors") | Intake fields + ESCALATE if not in intake |
| `novel` | Unrecognized question pattern | ESCALATE always |

**Mechanism:** Claude Sonnet with a strict classification schema; 5-shot examples in the prompt. Each classification is logged with reasoning for auditability.

### Stage 5 — Answer (new)

**Module:** `lib/trust-desk/answerer.js`

**Per-question pipeline:**

```js
async function answerQuestion(question, bucket, intake, templates) {
  switch (bucket) {
    case 'ai_template_match':
      // Deterministic template substitution. No LLM. No hallucination risk.
      return substituteTemplate(templates[question.matchedTemplate], intake);

    case 'soc2_overlap':
      // Combine the customer's SOC2 status + a small boilerplate fragment.
      return composeSoc2Answer(question, intake.soc2_status);

    case 'ai_specific':
    case 'customer_specific':
      // LLM, but with HARD constraints:
      // 1. Output schema: { answer: string, sources: [{ template_id, line_range }], confidence: number }
      // 2. Sources must be non-empty. Empty sources → forced refusal + escalation.
      // 3. Refusal language is templated, not LLM-generated, so a refused
      //    question always reads consistently.
      const result = await callClaude({
        system: ANSWERER_SYSTEM,
        user: buildAnswerPrompt(question, intake, retrieveRelevantTemplateFragments(question)),
        schema: AnswerSchema,
        max_tokens: 600,
      });
      if (result.sources.length === 0 || result.confidence < 0.75) {
        return { status: 'escalated', reason: 'low_confidence_or_no_sources', llm_output: result };
      }
      return { status: 'answered', ...result };

    case 'novel':
    default:
      return { status: 'escalated', reason: 'novel_question' };
  }
}
```

**Parallelism:** Up to 10 concurrent question-answer calls. For a 50-question intake at ~30s/question, end-to-end answer stage = ~150s.

**Model:** Claude Sonnet for default; fallback to Opus if `confidence < 0.85` on first try (cheap retry, higher quality). Cost projection: ~$3 LLM/engagement at p50, ~$8 at p99.

### Stage 6 — Verify (new — critical stage)

**Module:** `lib/trust-desk/verifier.js`

This is the **quality firewall**. Nothing publishes unless this stage passes.

**Checks performed per question:**
1. **Source exists.** Every answer cites at least one source (template fragment, intake field, or SOC2 boilerplate). No source → escalate.
2. **Source hash matches.** The cited template fragment is re-hashed; if hash != stored hash → escalate (drift signal).
3. **Confidence threshold.** Answers below 0.85 confidence → escalate.
4. **PII leakage check.** Run answer through `microsoft/presidio` or equivalent — if email/SSN/phone other than customer's intake → escalate.
5. **Forbidden-claim regex.** Block answers asserting certifications customer doesn't have. (Regex over: "SOC 2 Type 2", "ISO 27001", "FedRAMP" — must be reflected in intake.)
6. **Length sanity.** Answer length 50–1500 chars. Outside range → escalate.

**Aggregate decision:**
- 100% of questions pass → auto-mint
- 1–20% fail → mint with the failing questions marked "REVIEW PENDING" and sent to reviewer queue. Trust page goes live with non-failing answers; reviewer fills the rest within 4 hours.
- > 20% fail → full escalation. No auto-publish. Reviewer takes the whole packet.

### Stage 7 — Policies (new)

**Module:** `lib/trust-desk/policy-mint.js`

For each of the 5 standard policy docs, run the template through deterministic substitution:

- `{{COMPANY}}` ← intake.company
- `{{PRODUCT_NAME}}` ← intake.product_description (first noun phrase, extracted)
- `{{EFFECTIVE_DATE}}` ← today
- `{{SECURITY_LEAD_NAME}}` ← intake.contact_name
- `{{SECURITY_LEAD_EMAIL}}` ← intake.contact_email
- `{{CLOUD_PROVIDER}}` ← intake.cloud_provider
- Etc.

Output: 5 markdown files per engagement, each with computed SHA-256.

**Storage:** `data/trust-desk/customers/<slug>/policies/<doc>.md` (write to disk for the renderer; also store hash in DB).

### Stage 8 — Mint (extends existing)

**Module:** `lib/trust-desk/minter.js` (new) + `lib/trust-desk/customers.js` (existing)

1. Build customer JSON fixture matching existing schema in `lib/trust-desk/customers.js`
2. **Fix the content_hash bug**: compute SHA-256 of the policy doc content and write it to the claim's `content_hash` field. Today this is `null` in the sample fixture.
3. Write JSON to `data/trust-desk/customers/<slug>.json`
4. Call existing `signClaim()` so the envelope binds to real content
5. Trigger ISR revalidation of `/trust-desk/c/<slug>`

### Stage 9 — Notify (new)

**Module:** `lib/trust-desk/notify.js`

On publish:
1. Send customer "your trust page is live" email via Resend, with:
   - Trust page URL
   - Shareable PDF export (rendered via Playwright headless)
   - The forward-to-buyer email template
2. Slack ping to internal `#trust-desk-published` channel
3. Update DB: `status = 'published'`, `published_at = NOW()`, `expires_at = NOW() + 6 months`

On escalation:
1. Create Linear ticket (or GitHub issue) with engagement context, escalation reason, and a link to the reviewer dashboard
2. Slack ping to `#trust-desk-escalations`
3. Send customer "your reviewer is on it, expect <ETA>" email — turnaround SLA: 4 business hours

### Stage 10 — Monitor (new)

**Cron job:** runs nightly via Vercel cron
- Mark engagements as `expiring` (30d before `expires_at`)
- Mark engagements as `stale` (after `expires_at`)
- Send customer "refresh recommended" email at expiring
- Update trust page status banner (existing logic in `lib/trust-desk/customers.js` already handles render-time status)

**Buyer Q&A flow** (Slack-integrated):
- Buyer asks a follow-up question via the public verify link or via a shared Slack channel
- Bot routes question into the answerer pipeline with the customer's engagement as context
- If `confidence ≥ 0.9`, auto-responds and adds answer as a new claim to the JSON fixture
- Otherwise escalates to reviewer

---

## 5. Cryptographic spine

Today: HMAC-SHA256 with `ATD_SIGNING_KEY` env. Envelope-only signature (the bug: signature is over `null` content_hash).

Target: same HMAC for v1.0 + fix the content_hash bug so the signature actually binds content. Migrate to EP Commit receipts in v1.1.

**Buyer verify endpoint:** `GET /api/trust-desk/verify/<engagement_id>/<claim_id>` returns:
```json
{
  "claim_id": "clm_a3f1b2c8e9d4",
  "payload_hash": "...",
  "content_hash": "...",
  "signed_at": "2026-05-29T...",
  "signer": "ai-trust-desk",
  "signature": "...",
  "public_signing_key_fingerprint": "...",
  "verify_instructions_url": "https://emiliaprotocol.ai/trust-desk/verify"
}
```

Ship a 30-line Node script + Python script that any buyer can run to verify a claim. This is the "buyer-verifiable from day 21" promise on the landing page becoming real.

---

## 6. Reviewer escape hatch

Every stage can escalate. Reviewer dashboard at `/internal/trust-desk` shows:
- Pending engagements with escalation reason
- One-click "answer + publish" workflow per question
- LLM-suggested answer pre-filled, reviewer edits inline
- Reviewer's identity gets baked into the claim's `signer` field (audit trail)

**Reviewer SLAs:**
- Auto-publish path: 0 reviewer time
- Partial-escalation path: 4 business hours
- Full-escalation path: 24 business hours

**Reviewer throughput target:** one reviewer can clear ~30 partial-escalations/day or ~5 full-escalations/day.

---

## 7. Observability

Every engagement emits structured logs:
```
event=intake_received engagement_id=eng_xxx tier=packet
event=extraction_complete engagement_id=eng_xxx questions=47 confidence=0.91 duration_ms=4200
event=answering_complete engagement_id=eng_xxx auto_answered=42 escalated=5 cost_cents=312
event=verification_complete engagement_id=eng_xxx passed=46 failed=1
event=mint_complete engagement_id=eng_xxx slug=acme-co duration_ms=890
event=published engagement_id=eng_xxx total_duration_ms=14200
```

**Dashboards:**
- p50 / p99 end-to-end latency
- Auto-publish rate by week
- LLM cost per engagement
- Escalation reason distribution
- Buyer verify endpoint call rate (proxy for buyer trust signal)

**Alerts:**
- Auto-publish rate drops below 60% (suggests questionnaire format shift)
- p99 latency > 90 min
- Any verification failure that involves a forbidden-claim regex match (potential hallucination attempt)
- Cost per engagement > $50

---

## 8. Failure modes & how the system handles them

| Failure | Detection | Handling |
|---------|-----------|----------|
| Questionnaire parse fails | Stage 3 extraction returns 0 questions | Escalate immediately. Reviewer reads file by hand. |
| LLM hallucinates a SOC2 claim | Stage 6 forbidden-claim regex matches | Escalate. Block auto-publish. Page on-call engineer. |
| LLM refuses to answer a known-template question | Stage 5 returns escalation when template should have matched | Bug. Log to error tracker. Reviewer takes it. |
| Buyer reports false claim post-publish | Manual customer report | Pause auto-publish for that customer. Audit log of all claims for that customer. Refund + manual republish. |
| Stripe webhook fails to fire | DB cron checks for `intake_received` engagements > 1h old | Reviewer manually checks Stripe + re-fires job. |
| LLM provider outage | Provider 5xx | Failover from Sonnet → GPT-4o → escalate. |
| Trust page URL gets indexed by Google | `robots: noindex` already set in metadata | No action needed (current behavior). |
| Customer wants edit post-publish | Customer email | Reviewer pipeline. New `claim_version` created; old hashes preserved in DB for buyer-side audit trail integrity. |

---

## 9. Build phasing (4 weeks)

| Week | Deliverable | What ships |
|------|-------------|-----------|
| **Week 1** | Persistence + extraction + classification | DB + intake API + PDF/Excel/Word parsers + classifier with the 5-bucket schema. Outputs structured question list to console; no answering yet. |
| **Week 2** | Answering + verification | Schema-bound LLM answerer + verifier with all 6 quality gates. Produces a draft trust page JSON; doesn't publish. Reviewer dashboard at `/internal/trust-desk`. |
| **Week 3** | Policy mint + trust page mint + notify | End-to-end auto-publish for happy path. Email notifications. Buyer verify endpoint. |
| **Week 4** | Monitor + Slack Q&A + production hardening | Expiry cron, buyer Q&A bot, observability dashboards, alerts, load testing to 20 concurrent engagements. |

**Net:** 4 weeks of engineering at full focus. Cost projection (LLM + Resend + S3 + Postgres + Vercel): ~$200–500/mo at 50 engagements/mo; ~$2k/mo at 500 engagements/mo. LLM cost dominates.

---

## 10. Marketing copy changes (required before launch)

The current landing page says:
> "Your assigned reviewer (a named human, not an LLM) completes the questionnaire..."

This becomes:
> "Our system drafts every answer from your intake and our 5 versioned policy templates. A named reviewer signs off on the final packet before publish, and every claim is cryptographically bound to a verifiable source. **No claim ships without a source.**"

The honesty is the moat. Competitors that say "AI-powered" without source attribution will lose the first audit. We win by making source-attribution mandatory and provable.

Other copy that changes:
- "24-48 hour turnaround" → "Most packets published in under an hour. Complex packets escalate to a human reviewer with 4-hour SLA."
- "Named human reviewer" → "Named human reviewer for escalated packets. Auto-published packets carry the reviewer-on-call's signature with full audit trail."

---

## 11. What this unlocks

| Before | After |
|--------|-------|
| 5 engagements/week ceiling (1 human) | 200+ engagements/week ceiling (1 human reviewer for escalations only) |
| $24,500 × 5/wk = $122K/wk revenue ceiling | $24,500 × 200/wk = $4.9M/wk revenue ceiling at scale |
| Per-customer cost: ~3 hr reviewer time | Per-customer cost: ~$10 LLM + 0–15 min reviewer time |
| Trust story: "human-graded" | Trust story: "source-cited + human-supervised + cryptographically signed" |
| Marketing has to say "not an LLM" | Marketing can say "LLM-drafted, source-cited, human-signed" — and that's a more credible compliance story |

---

## 12. Open questions

1. **Pricing on auto vs escalated?** Same price ($24,500) — sell the outcome, not the time. Margin difference becomes ours.
2. **Refund policy on escalation?** No refund. Escalation still meets the original promise; SLA just shifts from 1h to 4h. State this in the FAQ.
3. **Multi-tenant signing keys?** Phase 1: shared HMAC key. Phase 2: per-customer key pair on EP Commit migration.
4. **Audit log retention?** 7 years (financial-services standard). Stored in S3 + immutable bucket policy.
5. **Should the reviewer dashboard be a separate app?** No. Inline at `/internal/trust-desk` behind Clerk auth. Same codebase, same deploy.

---

## 13. Definition of done

- [ ] An intake submitted at T0 produces a live trust page URL by T+60min in 80%+ of cases
- [ ] Every claim on a published trust page has a non-null `content_hash` matching a verifiable source
- [ ] Buyer can run a verify script and get `verified: true` against any published claim
- [ ] Reviewer dashboard shows queue + escalation reasons; one click to answer + publish a flagged question
- [ ] Observability dashboards live; alerts wired to PagerDuty / Slack
- [ ] Marketing copy updated to reflect the source-cited model
- [ ] One real customer engagement completes through the auto path end-to-end without intervention

---

## 14. Production deployment (implemented)

The pipeline ships with two storage backends. Local/dev and the committed demo
use the **file** backend (zero config). Production on Vercel must use the
**supabase** backend, because Vercel's runtime filesystem is read-only — the
file backend can read committed pages but cannot persist new pipeline runs.

### Backend selection

| Env | Effect |
|-----|--------|
| _(unset)_ | `file` backend — `data/trust-desk/`. Local, CLI, tests, committed demo. |
| `TRUST_DESK_STORE=supabase` | Supabase backend — `trust_desk_engagements` + `trust_desk_pages`. Required on Vercel. |

### One-time setup

1. **Apply the migration** `supabase/migrations/092_trust_desk.sql` (creates the
   two tables, RLS service-role-only, updated_at triggers).
2. **Set env vars** on the Vercel project:

   | Var | Required | Purpose |
   |-----|----------|---------|
   | `TRUST_DESK_STORE` | prod | set to `supabase` |
   | `ATD_SIGNING_KEY` | prod | HMAC signing key — pipeline fails closed without it in prod |
   | `ANTHROPIC_API_KEY` _or_ `OPENAI_API_KEY` | recommended | enables LLM answering for non-template questions (Claude preferred). Without it, those questions escalate. |
   | `RESEND_API_KEY` | optional | customer emails (publish + expiry). Suppressed-and-logged if unset. |
   | `TRUST_DESK_SLACK_WEBHOOK` | optional | internal pings |
   | `TRUST_DESK_INTERNAL_TOKEN` | recommended | gates `/internal/trust-desk`; auth via `/internal/trust-desk/auth?token=…` |
   | `TRUST_DESK_FROM_EMAIL` | optional | from-address for customer mail |
   | `TRUST_DESK_ANTHROPIC_MODEL` / `TRUST_DESK_OPENAI_MODEL` | optional | model overrides |

3. **Crons** are wired in `vercel.json`: `/api/cron/trust-desk-monitor` runs
   daily (expiry notices), authenticated via operator token / `CRON_SECRET`.

### What runs where

- **Intake** (`POST /api/trust-desk/intake`) persists the engagement and runs
  the pipeline via `after()` (post-response), so the form gets an instant ack.
- **Published pages** are stored as `trust_desk_pages` rows; the renderer
  (`/trust-desk/c/[slug]`) and verify endpoint read them through `page-store`.
- **Binary questionnaires** (.xlsx/.pdf/.docx) parse via `xlsx` (SheetJS patched
  CDN build), `pdf-parse` v2, and `mammoth`, externalized in `next.config.js`
  (`serverExternalPackages`) so they're traced into the serverless bundle.

### Verification status

- File backend (default): fully exercised — CLI, e2e test, committed demo, all
  cryptographic checks pass.
- Supabase backend: built behind the flag with the file backend as the tested
  default; runtime-verify against a real project after applying the migration
  (no schema-coupled code — both backends share the same doc shapes).
