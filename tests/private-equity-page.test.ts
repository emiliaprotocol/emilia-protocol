// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../lib/canonical-json.js';

const ROOT = resolve(import.meta.dirname, '..');
const page = readFileSync(resolve(ROOT, 'app/private-equity/page.tsx'), 'utf8');
const lab = readFileSync(resolve(ROOT, 'app/private-equity/PortfolioActionRiskLab.tsx'), 'utf8');
const fixture = readFileSync(resolve(ROOT, 'app/private-equity/finance-lab-fixture.ts'), 'utf8');
const openGraphImage = readFileSync(resolve(ROOT, 'app/private-equity/opengraph-image.tsx'), 'utf8');
const analytics = readFileSync(resolve(ROOT, 'app/private-equity/portfolio-analytics.ts'), 'utf8');
const trackedLink = readFileSync(resolve(ROOT, 'app/private-equity/PortfolioTrackedLink.tsx'), 'utf8');
const boundaryExample = JSON.parse(readFileSync(
  resolve(ROOT, 'public/examples/portfolio-authority/payment-release-boundary.example.json'),
  'utf8',
));
const boundarySchema = JSON.parse(readFileSync(
  resolve(ROOT, 'public/schemas/portfolio-authority-boundary-example.v1.schema.json'),
  'utf8',
));
const sitemap = readFileSync(resolve(ROOT, 'app/sitemap.ts'), 'utf8');
const footer = readFileSync(resolve(ROOT, 'components/SiteFooter.tsx'), 'utf8');

describe('private-equity portfolio customer page', () => {
  it('is an indexable, finance-first customer route with dedicated share metadata', () => {
    expect(page).toContain("alternates: { canonical: '/private-equity' }");
    expect(page).toContain('The Universal Authority Tollgate for Portfolio AI');
    expect(page).toContain('Give every consequential agent action a tollgate.');
    expect(page).toContain("url: '/private-equity/opengraph-image'");
    expect(page).toContain('robots: { index: true, follow: true }');
    expect(openGraphImage).toContain('export const size = { width: 1200, height: 630 }');
    expect(sitemap).toContain("{ path: '/private-equity'");
    expect(footer).toContain("['/private-equity', 'Private Equity']");
  });

  it('keeps the portfolio promise inside the complete-mediation boundary', () => {
    expect(page).toContain('On completely mediated covered paths');
    expect(page).toContain('must arrive with accepted');
    expect(page).toContain('authority and required evidence before it can enter');
    expect(page).toContain('Gate does not establish');
    expect(page).toContain('does not cover every agent risk or make an investment safe');
    expect(page).toContain('Source truth, bypass paths, fraud absence, provider outcome');
    expect(page).not.toContain('eliminates agent risk');
    expect(page).not.toContain('guarantees your investment');
  });

  it('keeps private investment outreach separate from the public customer conversion', () => {
    expect(page).toContain('Protect one portfolio boundary');
    expect(page).toContain('Customer deployment path only');
    expect(page).not.toContain('href="/investors"');
    expect(page).not.toMatch(/invest now|request investment|investment opportunity/i);
  });

  it('publishes WebPage and FAQ schema with script-breaking characters sanitized', () => {
    expect(page).toContain("'@type': 'WebPage'");
    expect(page).toContain("'@type': 'Service'");
    expect(page).toContain("'@type': 'BreadcrumbList'");
    expect(page).toContain("'@type': 'FAQPage'");
    expect(page).toContain(".replace(/</g, '\\\\u003c')");
    expect(page).toContain('dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA_JSON }}');
  });

  it('uses one existing observe-mode payment boundary across three fictional conditions', () => {
    expect(fixture).toContain('/api/v1/adapters/fin/payment-release/precheck');
    expect(fixture).not.toContain('/api/v1/adapters/fin/vendor-bank-change/precheck');
    expect(fixture.match(/enforcement_mode: 'observe'/g)).toHaveLength(3);
    expect(fixture).toContain("id: 'single_signoff'");
    expect(fixture).toContain("id: 'dual_signoff'");
    expect(fixture).toContain("id: 'hard_refusal'");
    expect(fixture).toContain("risk_flags: ['known_compromised_device']");
    expect(fixture).toContain('Northstar Components (fictional, consenting sandbox company)');
    expect(lab).toContain('/api/pilot/sandbox/provision');
    expect(lab).toContain('does not authorize, block, mutate, or execute');
    expect(lab).toContain('Keep the boundary fixed. Change the evidence condition.');
    expect(lab).toContain('Copy the exact observe-mode request.');
    expect(lab).toContain('rejects tenant');
    expect(lab).toContain('aria-pressed={selectedScenarioId === scenario.id}');
    expect(lab).toContain('aria-live="polite"');
    expect(lab).not.toContain('/api/pilot/sandbox/report');
    expect(lab).not.toContain('GG-1');
    expect(lab).not.toContain('offline-verifiable');
    expect(lab).not.toContain("'\\n+  -H");
  });

  it('keeps one canonical fixed-price offer inside a three-entry portfolio ladder', () => {
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.workflowLabel');
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.durationLabel');
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.shortPriceLabel');
    expect(page).toContain('One finance workflow. 90 days. $25K.');
    expect(page).toContain('Portfolio Action Risk Lab');
    expect(page).toContain('Portfolio Authority Pilot');
    expect(page).toContain('Portfolio Authority Program');
    expect(page).toContain('Scoped after boundary acceptance');
    expect(page).not.toMatch(/free pilot|portfolio-wide platform commitment required/i);
  });

  it('offers the shipped assurance surfaces without presenting a certificate or audit opinion', () => {
    expect(page).toContain('Open verification');
    expect(page).toContain('Deployment Assurance');
    expect(page).toContain('Continuous Assurance');
    expect(page).toContain('Warranted Gate');
    expect(page).toContain('Evidence, not a certificate.');
    expect(page).toContain('Posture and coverage evidence are not action admission.');
    expect(page).toContain('does not currently operate a public certification scheme');
    expect(page).toContain('customer-appointed auditor, underwriter, regulator');
    expect(page).not.toMatch(/certified portfolio|audit opinion issued by EMILIA/i);
  });

  it('publishes an explicit non-authoritative boundary example with sponsor data minimization', () => {
    expect(page).toContain('/examples/portfolio-authority/payment-release-boundary.example.json');
    expect(page).toContain('/schemas/portfolio-authority-boundary-example.v1.schema.json');
    expect(page).toContain('canonical SHA-256 digest');
    const validate = new Ajv2020({ strict: true }).compile(boundarySchema);
    expect(validate(boundaryExample), JSON.stringify(validate.errors)).toBe(true);
    expect(boundaryExample.schema).toBe(boundarySchema.$id);
    expect(boundaryExample.artifact_version).toBe('1');
    const { digest, ...unsignedArtifact } = boundaryExample;
    const measuredDigest = createHash('sha256').update(canonicalize(unsignedArtifact), 'utf8').digest('hex');
    expect(digest).toMatchObject({
      algorithm: 'sha-256',
      canonicalization: 'EMILIA_STRICT_JSON_V1',
      scope: 'entire_document_excluding_digest_member',
      value: `sha256:${measuredDigest}`,
    });
    expect(boundaryExample.status).toBe('illustrative_non_authoritative');
    expect(boundaryExample.authority_control.owner).toBe('portfolio company');
    expect(new Set(Object.values(boundaryExample.identifier_handling))).toContain('reject');
    expect(boundaryExample.identifier_handling.unknown_boundary_id).toBe('reject');
    expect(boundaryExample.evidence_semantics.posture_evidence).toContain('not action admission');
    expect(boundaryExample.evidence_semantics.admission_evidence).toContain('not provider outcome');
    expect(boundaryExample.complete_mediation_review.required).toBe(true);
    expect(boundaryExample.sponsor_visibility.buyer_agreed_outputs).toContain('boundary coverage status');
    expect(boundaryExample.sponsor_visibility.retained_by_portfolio_company).toContain('provider credentials');
    expect(boundaryExample.non_claims.join(' ')).toContain('not a certificate');
  });

  it('exposes privacy-minimized conversion events without identities, credentials, or free text', () => {
    expect(analytics).toContain("PORTFOLIO_EVENT_CHANNEL = 'emilia:portfolio-event'");
    expect(analytics).toContain('Only closed enum values leave the component');
    expect(analytics).not.toMatch(/email_address|organization_id|api_key|credential_id|free_text/);
    expect(trackedLink).toContain('data-analytics-event={eventDetail.event}');
    expect(trackedLink).toContain('emitPortfolioEvent(eventDetail)');
    expect(page).toContain("event: 'pilot_scope_started'");
    expect(lab).toContain("event: 'sandbox_precheck_completed'");
  });

  it('keeps competitor strategy and private capital asks out of the public page', () => {
    expect(page).not.toMatch(/certisyn|hillier|target list|limited partner list|fundraising|invest in emilia/i);
    expect(boundaryExample).not.toHaveProperty('pricing');
  });
});
