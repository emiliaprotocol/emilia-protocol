/**
 * AI Trust Desk — pipeline end-to-end test.
 * @license Apache-2.0
 *
 * Runs the full intake → published trust page flow on a fixture questionnaire,
 * then independently verifies every cryptographic binding on the published page.
 *
 * Also the regression guard for the human sign-off boundary: the pipeline must
 * PARK rather than publish, publication must refuse an unnamed reviewer, and an
 * approval must not be replayable against an engagement that already left the
 * review state. Those three are what stop machine-drafted answers reaching a
 * bank's risk team under a customer's name without a person reading them.
 */

import { describe, it, expect, afterAll, vi } from 'vitest';

// The composed-answer path needs a provider. Rather than reach the network, the
// stub answers from the policy text it is handed and quotes it verbatim, so the
// grounding check is exercised against real template content rather than bypassed.
let stubMode: 'grounded' | 'fabricated' = 'grounded';
vi.mock('./llm.js', () => ({
  llmAvailable: () => true,
  activeProvider: () => 'stub',
  llmJSON: async ({ user }: { user: string }) => {
    const policy = user.split('Policy text (the ONLY permitted source):\n')[1] || '';
    const real = policy.replace(/\s+/g, ' ').trim().slice(0, 120);
    return {
      ok: true,
      provider: 'stub',
      data: {
        answer: 'Composed answer addressing the question directly.',
        supporting_quotes: [
          stubMode === 'grounded' ? real : 'This sentence was never written in any policy document.',
        ],
        confidence: 0.95,
      },
    };
  },
}));
import fs from 'node:fs';
import path from 'node:path';
import { runPipeline, publishReviewed, rejectReviewed, requiresReview } from './pipeline.js';
import { verifyPublishedPage } from './page-verify.js';
import { loadCustomer } from './customers.js';
import { putEngagement, getEngagement, STATUS } from './store.js';

const CUSTOMER_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'customers');
const createdSlugs = [];

function cleanup(slug) {
  fs.rmSync(path.join(CUSTOMER_DIR, `${slug}.json`), { force: true });
  fs.rmSync(path.join(CUSTOMER_DIR, slug), { recursive: true, force: true });
}

afterAll(() => createdSlugs.forEach(cleanup));

const SAMPLE = `
## Data
- Do you use customer data for model training?
- What is your data retention and deletion policy?
## Security
- Describe your prompt injection defenses.
- How do you enforce least-privilege tool access for agents?
## Incident
- What is your breach notification SLA?
## Infra
- Do you encrypt data at rest and in transit?
- Do you enforce MFA for employees?
- Which cloud provider and region hosts the production AI workload?
`;

const intake = {
  company: 'Testco AI',
  contact_name: 'Test Lead',
  contact_email: 'security@testco.example',
  product_description: 'Fraud detection AI for banks',
  selling_into: 'financial_services',
  cloud_provider: 'AWS us-east-1',
  soc2_status: 'type2',
  tier_preference: 'packet',
};

describe('trust-desk pipeline (composed answers, stubbed provider)', () => {
  it('publishes a fully-verified trust page from a markdown questionnaire', async () => {
    const engagement = {
      engagement_id: `eng_${'test01'}${Date.now().toString(16)}`,
      intake,
      questionnaire_content: SAMPLE,
      questionnaire_filename: 'q.md',
    };

    // Straight-through path: the crypto bindings are what this case covers, so
    // the sign-off gate is opted out of explicitly rather than left ambiguous.
    process.env.TRUST_DESK_REQUIRE_REVIEW = 'false';
    const result = await runPipeline({ engagement, persist: false });
    delete process.env.TRUST_DESK_REQUIRE_REVIEW;
    createdSlugs.push(result.slug);

    // Published (auto or partial — both are "published"), never failed.
    expect(['published', 'published_partial']).toContain(result.outcome);
    expect(result.counts.passed).toBeGreaterThanOrEqual(7);

    // Every claim carries a non-null content_hash (the bug this build fixes).
    for (const claim of result.claims) {
      expect(claim.content_hash).toBeTruthy();
      expect(claim.content_hash).toMatch(/^[0-9a-f]{64}$/);
    }

    // Independent verification of the published artifacts passes for all claims.
    const verified = verifyPublishedPage(result.slug);
    expect(verified.found).toBe(true);
    expect(verified.ok).toBe(true);
    for (const c of verified.claims) {
      expect(c.checks.content_integrity.ok).toBe(true);
      expect(c.checks.payload_binding.ok).toBe(true);
      expect(c.checks.signature.ok).toBe(true);
    }

    // The renderer loads it and reports the minted (stable) signature origin.
    const customer = loadCustomer(result.slug);
    expect(customer).not.toBeNull();
    expect(customer.claims.length).toBe(result.claims.length);
    expect(customer.claims[0].signature_origin).toBe('minted');
  });

  it('escalates (does not publish) when no questions can be extracted', async () => {
    const engagement = {
      engagement_id: `eng_${'test02'}${Date.now().toString(16)}`,
      intake,
      questionnaire_content: 'This file has no questions at all, just prose about nothing.',
      questionnaire_filename: 'empty.md',
    };
    const result = await runPipeline({ engagement, persist: false });
    expect(result.outcome).toBe('escalated');
    expect(result.reason).toBe('no_questions_extracted');
  });
});

describe('trust-desk answer grounding', () => {
  it('refuses an answer whose supporting quote is not in the policy', async () => {
    const { answerAll } = await import('./answerer.js');
    const { classifyQuestions } = await import('./classifier.js');
    const { buildPolicyVars } = await import('./policy-defaults.js');

    const questions = await classifyQuestions(
      [{ id: 'q1', text: 'Describe your defenses against prompt injection.', section: 'Security' }],
      intake,
    );
    const policyVars = buildPolicyVars(intake, { slug: 'grounding-test' });

    stubMode = 'fabricated';
    const [fabricated] = await answerAll(questions, { intake, policyVars });
    stubMode = 'grounded';
    const [grounded] = await answerAll(questions, { intake, policyVars });

    // A quote the model invented cannot be located in the policy, so the
    // composed answer is discarded and the excerpt ships flagged for rewrite.
    expect(fabricated.grounded).toBe(false);
    expect(fabricated.needs_rewrite).toBe(true);
    expect(fabricated.compose_fallback_reason).toBe('no_verifiable_quote');
    expect(fabricated.confidence).toBeLessThan(0.85);

    // A quote actually copied from the policy is accepted.
    expect(grounded.grounded).toBe(true);
    expect(grounded.answer).toBe('Composed answer addressing the question directly.');
    expect(grounded.sources.some((s: any) => s.kind === 'policy_quote')).toBe(true);
  });
});

describe('trust-desk human sign-off boundary', () => {
  const engagementIds: string[] = [];
  const ENGAGEMENT_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'engagements');

  afterAll(() => {
    for (const id of engagementIds) {
      fs.rmSync(path.join(ENGAGEMENT_DIR, `${id}.json`), { force: true });
    }
  });

  it('requires review by default, and only an explicit opt-out disables it', () => {
    delete process.env.TRUST_DESK_REQUIRE_REVIEW;
    expect(requiresReview()).toBe(true);
    // A misspelled or unexpected value must NOT disable the gate.
    process.env.TRUST_DESK_REQUIRE_REVIEW = 'FALSE';
    expect(requiresReview()).toBe(true);
    process.env.TRUST_DESK_REQUIRE_REVIEW = 'false';
    expect(requiresReview()).toBe(false);
    delete process.env.TRUST_DESK_REQUIRE_REVIEW;
  });

  it('parks at awaiting_review instead of publishing', async () => {
    const id = `eng_a01be${Date.now().toString(16)}`;
    engagementIds.push(id);
    await putEngagement({ engagement_id: id, intake, status: STATUS.INTAKE_RECEIVED });

    const result = await runPipeline({
      engagement: {
        engagement_id: id,
        intake,
        questionnaire_content: SAMPLE,
        questionnaire_filename: 'q.md',
      },
    });

    expect(result.outcome).toBe('awaiting_review');
    expect(result.trust_url).toBeUndefined();

    const stored = await getEngagement(id);
    expect(stored?.status).toBe(STATUS.AWAITING_REVIEW);
    expect(Array.isArray(stored?.answers)).toBe(true);
    // Nothing is public yet: no customer page exists for the slug.
    expect(loadCustomer(result.slug)).toBeNull();
  });

  it('refuses to publish without a named reviewer', async () => {
    const id = `eng_a02be${Date.now().toString(16)}`;
    engagementIds.push(id);
    await putEngagement({
      engagement_id: id, intake, status: STATUS.AWAITING_REVIEW,
      answers: [{ id: 'q1', status: 'answered', answer: 'x' }],
    });

    for (const reviewer of ['', '   ']) {
      const res = await publishReviewed({ engagementId: id, reviewer });
      expect(res.ok).toBe(false);
      expect(res.error).toBe('reviewer_required');
    }
    expect((await getEngagement(id))?.status).toBe(STATUS.AWAITING_REVIEW);
  });

  it('refuses an approval replayed against an engagement that already left review', async () => {
    const id = `eng_a03be${Date.now().toString(16)}`;
    engagementIds.push(id);
    await putEngagement({
      engagement_id: id, intake, status: STATUS.PUBLISHED,
      answers: [{ id: 'q1', status: 'answered', answer: 'x' }],
    });

    const res = await publishReviewed({ engagementId: id, reviewer: 'iman@emiliaprotocol.ai' });
    expect(res.ok).toBe(false);
    expect(res.error).toBe('not_awaiting_review');
  });

  it('records a rejection against the reviewer and publishes nothing', async () => {
    const id = `eng_a04be${Date.now().toString(16)}`;
    engagementIds.push(id);
    await putEngagement({
      engagement_id: id, intake, status: STATUS.AWAITING_REVIEW,
      answers: [{ id: 'q1', status: 'answered', answer: 'x' }],
    });

    const missingReason = await rejectReviewed({
      engagementId: id, reviewer: 'iman@emiliaprotocol.ai', reason: '',
    });
    expect(missingReason.ok).toBe(false);
    expect(missingReason.error).toBe('reason_required');

    const res = await rejectReviewed({
      engagementId: id,
      reviewer: 'iman@emiliaprotocol.ai',
      reason: 'answer 4 overstates our retention guarantee',
    });
    expect(res.ok).toBe(true);

    const stored = await getEngagement(id);
    expect(stored?.status).toBe(STATUS.REJECTED);
    expect(stored?.reviewer).toBe('iman@emiliaprotocol.ai');
    expect(stored?.reason).toContain('retention');
  });

  it('allows only one concurrent reviewer decision to acquire the engagement', async () => {
    const id = `eng_a05be${Date.now().toString(16)}`;
    engagementIds.push(id);
    await putEngagement({
      engagement_id: id, intake, status: STATUS.AWAITING_REVIEW,
      answers: [{ id: 'q1', status: 'answered', answer: 'x' }],
    });

    const [first, second] = await Promise.all([
      rejectReviewed({ engagementId: id, reviewer: 'reviewer-one', reason: 'first decision' }),
      rejectReviewed({ engagementId: id, reviewer: 'reviewer-two', reason: 'second decision' }),
    ]);

    expect([first.ok, second.ok].filter(Boolean)).toHaveLength(1);
    expect([first.error, second.error]).toContain('not_awaiting_review');
    const stored = await getEngagement(id);
    expect(stored?.status).toBe(STATUS.REJECTED);
    expect(['reviewer-one', 'reviewer-two']).toContain(stored?.reviewer);
  });
});
