/**
 * AI Trust Desk — pipeline end-to-end test.
 * @license Apache-2.0
 *
 * Runs the full intake → published trust page flow on a fixture questionnaire
 * with NO API key (deterministic template path), then independently verifies
 * every cryptographic binding on the published page. This is the regression
 * guard for the "fully automated" claim.
 */

import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { runPipeline } from './pipeline.js';
import { verifyPublishedPage } from './page-verify.js';
import { loadCustomer } from './customers.js';

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

describe('trust-desk pipeline (deterministic, no LLM)', () => {
  it('publishes a fully-verified trust page from a markdown questionnaire', async () => {
    const engagement = {
      engagement_id: `eng_${'test01'}${Date.now().toString(16)}`,
      intake,
      questionnaire_content: SAMPLE,
      questionnaire_filename: 'q.md',
    };

    const result = await runPipeline({ engagement, persist: false });
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
