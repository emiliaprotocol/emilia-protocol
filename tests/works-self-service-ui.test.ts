// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildJoinPayloads,
  buildOpportunityPayload,
  buildSubmissionPayload,
} from '../app/works/form-payloads.ts';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

describe('Works self-service payloads', () => {
  it('builds entity registration, accountable builder, and first listing records from one intake', () => {
    const payloads = buildJoinPayloads({
      builderId: 'northstar-labs',
      builderKind: 'legal_entity',
      builderName: 'Northstar Labs',
      builderSummary: 'Accountable team behind Northstar Agent.',
      contactRoute: 'mailto:team@northstar.example',
      affiliationName: 'Independent',
      affiliationRelation: 'builder',
      listingId: 'northstar-agent',
      listingKind: 'agent',
      listingName: 'Northstar Agent',
      listingSummary: 'Coordinates bounded research tasks.',
      repositoryUrl: 'https://example.com/northstar',
      serviceUrl: '',
      license: 'Apache-2.0',
      supportedTasks: 'research, synthesis',
      interfaces: 'MCP\nHTTP',
      operatingConstraints: 'Requires sponsor approval\nNo payment execution',
    });

    expect(payloads.entity).toMatchObject({
      entity_id: 'northstar-labs',
      display_name: 'Northstar Labs',
      entity_type: 'agent',
      capabilities: ['research', 'synthesis'],
    });
    expect(payloads.builder).toMatchObject({
      builder_id: 'northstar-labs',
      kind: 'legal_entity',
      affiliations: [{ name: 'Independent', relation: 'builder' }],
    });
    expect(payloads.listing).toMatchObject({
      listing_id: 'northstar-agent',
      builder_id: 'northstar-labs',
      supported_tasks: ['research', 'synthesis'],
      interfaces: ['MCP', 'HTTP'],
      operating_constraints: ['Requires sponsor approval', 'No payment execution'],
      status: 'active',
    });
  });

  it('never creates a sponsor claim as VERIFIED', () => {
    const payload = buildOpportunityPayload({
      opportunityId: 'bounded-research',
      kind: 'challenge',
      title: 'Reproduce a bounded research workflow',
      description: 'Run the named workflow and publish the observed result.',
      postedBy: 'Northstar Sponsor',
      contactRoute: 'mailto:sponsor@northstar.example',
      funding: {
        statement: 'Up to $5,000 is available after sponsor review.',
        status: 'ASSERTED',
        scope: 'This private-beta opportunity only.',
        limitations: 'No payment mechanism is provided by Works.',
      },
      authority: {
        statement: 'The poster states it can select a participant.',
        status: 'VERIFIED' as never,
        scope: 'Participant selection for this opportunity only.',
        limitations: '',
      },
      eligibility: null,
    }, '2026-08-08T20:00:00.000Z');

    expect(payload.claims.map((claim) => claim.status)).toEqual(['ASSERTED', 'UNKNOWN']);
    expect(payload.claims[0].source).toEqual({
      kind: 'claimant',
      reference: 'mailto:sponsor@northstar.example',
    });
    expect(payload.claims[1].source).toBeNull();
    expect(JSON.stringify(payload)).not.toContain('VERIFIED');
  });

  it('defaults submissions to private and requires an explicit value for public visibility', () => {
    const input = {
      opportunityId: 'bounded-research',
      builderId: 'northstar-labs',
      listingId: 'northstar-agent',
      proposal: 'We will run the pinned workflow and publish the results.',
      team: 'Iman, Alex\nSam',
      visibility: 'private' as const,
    };

    const privatePayload = buildSubmissionPayload(input, 'submission-123');
    expect(privatePayload.visibility).toBe('private');
    expect(privatePayload.team).toEqual(['Iman', 'Alex', 'Sam']);
    expect(privatePayload.listing_id).toBe('northstar-agent');

    const publicPayload = buildSubmissionPayload(
      { ...input, visibility: 'public' },
      'submission-124',
    );
    expect(publicPayload.visibility).toBe('public');
  });
});

describe('Works self-service UI and copy contract', () => {
  it('keeps join flag-gated, previews before consent, and uses existing or one-time keys only for publication', () => {
    const page = read('app/works/join/page.tsx');
    const form = read('app/works/JoinForm.tsx');

    expect(page).toContain('isWorksV0Enabled()');
    expect(page).toContain('notFound()');
    expect(page).toContain('const registrationEnabled = isPublicEntityRegistrationEnabled();');
    expect(page).toContain('registrationEnabled={registrationEnabled}');
    expect(page).toContain('Publishing requires an existing EMILIA entity key.');
    expect(page).toContain('Scan privately first');
    expect(page).toContain('Create a public listing, not a checkout.');
    expect(form).toContain("fetch('/api/entities/register'");
    expect(form).toContain("postWorksRecord('builders'");
    expect(form).toContain("postWorksRecord('listings'");
    expect(form).toContain('One-time API key');
    expect(form).toContain('Retry Works setup');
    expect(form).toContain("accessMode === 'existing'");
    expect(form).toContain("accessMode === 'new' && !registrationEnabled");
    expect(form).toContain('name="existingKey" type="password"');
    expect(form).toContain('Your existing key is held only in this page for retries.');
    expect(form).toContain('if (!draft || !publicConsent)');
    expect(form).toContain('name="publicConsent" type="checkbox"');
    expect(form).toContain('setPublicConsent(false)');
    expect(form).toContain('Preview my listing');
    expect(form).toContain('Nothing is sent or published when you preview.');
    expect(form).toContain('Review every public field');
    expect(form).toContain('function preparePreview');
    const preparePreview = form.slice(form.indexOf('function preparePreview'), form.indexOf('async function handlePublish'));
    expect(preparePreview).not.toContain('fetch(');
    expect(preparePreview).toContain('setDraft(buildJoinPayloads(input))');
    expect(form).toContain('keyCreatedHere: false');
    expect(form).toContain('keyCreatedHere: true');
    expect(form).toContain('if (!next.builderCreated)');
    expect(form).toContain('if (!next.listingCreated)');
    expect(form).toContain('activeRequest.current?.abort()');
    expect(form).toContain('if (inFlight.current) return;');
    expect(form).toContain('No payment is taken here.');
    expect(form).not.toContain('localStorage');
    expect(form).not.toContain('sessionStorage');
    expect(form).not.toContain('URLSearchParams');
    const slugPattern = form.match(/pattern="([^"]+)"/)?.[1];
    expect(slugPattern).toBeTruthy();
    const slug = new RegExp(`^(?:${slugPattern})$`, 'v');
    expect(slug.test('ledger-assistant')).toBe(true);
    expect(slug.test('bad ID')).toBe(false);
    const css = read('app/works/join/join.module.css');
    expect(css).toContain('font-size:18px');
    expect(css).toContain('@media(max-width:650px)');
    expect(css).toContain('focus-visible');
  });

  it('keeps opportunity claims bounded and proposal publication explicit', () => {
    const newPage = read('app/works/opportunities/new/page.tsx');
    const opportunityForm = read('app/works/OpportunityForm.tsx');
    const submissionForm = read('app/works/SubmissionForm.tsx');
    const detailPage = read('app/works/opportunities/[id]/page.tsx');

    expect(newPage).toContain('isWorksV0Enabled()');
    expect(opportunityForm).toContain("value=\"ASSERTED\"");
    expect(opportunityForm).toContain("value=\"UNKNOWN\"");
    expect(opportunityForm).not.toContain("value=\"VERIFIED\"");
    expect(submissionForm).toContain('shared only with the opportunity owner');
    expect(submissionForm).toContain('Public publication is optional');
    expect(submissionForm).toContain('type="checkbox"');
    expect(submissionForm).toContain("useState(false)");
    expect(submissionForm).toContain("visibility: publishPublicly ? 'public' : 'private'");
    expect(submissionForm).not.toContain('name="publicConsent" type="checkbox" required');
    expect(submissionForm).toContain('Contact the sponsor privately');
    expect(detailPage).toContain('<SubmissionForm');
    expect(detailPage).toContain('opportunity.example ?');
    expect(detailPage).toContain('This is a read-only example opportunity.');
    expect(detailPage).toContain('Browse live opportunities');
    expect(detailPage).toContain('Post a live opportunity');
    expect(detailPage).not.toContain('POST /api/works/submissions');
    expect(detailPage).toContain("sub.visibility === 'public' || sub.example === true");
  });

  it('uses inspectable-market wording and gives visitors direct marketplace actions', () => {
    const directory = read('app/works/page.tsx');
    const opportunities = read('app/works/opportunities/page.tsx');
    const discipline = read('app/works/ui.tsx');
    const combined = `${directory}\n${opportunities}\n${discipline}`;

    expect(directory).toContain('What would you<br />like <em>taken care of?</em>');
    expect(directory).toContain('Bring your agent');
    expect(combined.toLowerCase()).not.toContain('verified market');
    expect(discipline).toContain('Capability, funding, authority, and eligibility statements');
    expect(directory).toContain('href="/works/join"');
    expect(directory).toContain('href="/works/opportunities/new"');
    expect(directory).toContain('Browse agent listings');
    expect(opportunities).toContain('Post an opportunity');
    expect(opportunities).toContain('View and respond');
  });

  it('offers a clear reset when filters produce an empty directory', () => {
    const directory = read('app/works/page.tsx');

    expect(directory).toContain('filtersActive && visible.length === 0');
    expect(directory).toContain('href="/works"');
    expect(directory).toContain('Reset filters');
  });
});
