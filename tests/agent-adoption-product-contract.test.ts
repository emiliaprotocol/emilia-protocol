// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '..');
const read = (path: string) => readFileSync(resolve(root, path), 'utf8');
const experience = read('app/adopt/AdoptExperience.tsx');
const layout = read('app/adopt/layout.tsx');
const docs = read('docs/AGENT-ADOPTION.md');
const pilot = read('app/pilot/page.tsx');
const offers = read('lib/commercial-offer.ts');
const publicPage = read('app/adopt/r/[shareId]/page.tsx');
const arenaPublicPage = read('app/arena/r/[shareId]/page.tsx');
const arenaExperience = read('app/arena/ArenaExperience.tsx');
const css = read('app/adopt/adopt.module.css');
const federation = read('docs/conformance/FEDERATION-PROOF.md');
const openapi = read('openapi.yaml');
const middleware = read('middleware.ts');
const homepage = read('app/HomePageClient.tsx');

describe('Agent Adoption public claim and funnel contract', () => {
  it('describes a synthetic candidate demonstration, not a participating agent or accountable identity', () => {
    const surface = `${experience}\n${layout}\n${docs}\n${publicPage}\n${homepage}\n${openapi}`;
    expect(surface).not.toContain('Adopt any agent');
    expect(surface).not.toContain('someone accountable');
    expect(surface).not.toContain('User-present account control');
    expect(surface).not.toContain('account-control ceremony');
    expect(surface).not.toContain('proves account control');
    expect(surface).toContain('agent candidate');
    expect(surface).toContain('No agent is connected to or executed');
  });

  it('attributes synthetic decisions to the Arena and keeps Gate for a separate production scope', () => {
    expect(experience).toContain('Arena decision');
    expect(experience).toContain('It is not Gate admission');
    expect(docs).toContain('This is not a Gate admission');
  });

  it('allows publication after any synthetic attempt rather than requiring a refusal', () => {
    expect(experience).toContain('const latestAttempt = attempts.at(-1)');
    expect(experience).toContain('if (!session || !latestAttempt || !publicationConfirmed || revoked) return');
    expect(experience).not.toContain('A refusal is required before publication');
  });

  it('routes adoption graduates into the one canonical 90-day $25K offer', () => {
    expect(experience).not.toContain('/pilot?offer=agent-adoption');
    expect(experience).toContain("`/pilot?artifact_id=${encodeURIComponent(publicArtifactId)}`");
    expect(pilot).toContain('PROTECTED_WORKFLOW_PILOT.id');
    expect(offers).toMatch(/PROTECTED_WORKFLOW_PILOT[\s\S]*?durationLabel: '90 days'/);
    expect(offers).toMatch(/PROTECTED_WORKFLOW_PILOT[\s\S]*?shortPriceLabel: '\$25K'/);
    expect(publicPage).toContain("`/pilot?artifact_id=${encodeURIComponent(shareId)}`");
    expect(arenaPublicPage).toContain("`/pilot?artifact_id=${encodeURIComponent(shareId)}`");
    for (const page of [arenaPublicPage, publicPage]) {
      expect(page).toContain('Continue the factual record');
      expect(page).toContain('Scope the protected-workflow pilot');
      expect(page).toContain('Public record ID');
    }
  });

  it('distinguishes store outage from unknown or revoked public records', () => {
    expect(publicPage).toContain('This record cannot be checked right now.');
    expect(publicPage).toContain('This public record is unavailable.');
    expect(publicPage).toContain('makes no claim about whether the record exists');
  });

  it('pins public claims, OpenAPI, active navigation, and readable disclaimers', () => {
    expect(read('app/adopt/page.tsx')).toContain('activePage="adopt"');
    expect(federation).not.toContain('`app/adopt` Level 5');
    expect(openapi).toContain("pattern: '^https://");
    expect(openapi).toContain("'410': { description: 'Adoption capability expired' }");
    expect(openapi).toContain("'413': { description: 'Request body exceeds the Agent Adoption limit' }");
    expect(middleware).toContain("'GET /api/adopt/sessions/*':                            { rateCategory: 'submit'");
    expect(css).toContain('outline: 3px solid #073b2c');
    expect(homepage).toContain('See where your AI can act. Put a human in control before it matters.');
    expect(publicPage).toContain('USER-SUPPLIED, UNVERIFIED CANDIDATE LABEL');
    expect(publicPage).toContain('creating browser session may have revoked it, or it may have expired');
    expect(css).toMatch(/\.publicationNote \{[\s\S]*?font-size: 12px;/);
    expect(css).toMatch(/\.envelopeFinePrint \{[\s\S]*?font-size: 12px;/);
    expect(arenaPublicPage).not.toContain('What this proves');
    expect(arenaPublicPage).toContain('What this record verifies');
    expect(arenaPublicPage).toContain('included session key');
    expect(arenaPublicPage).toContain('does not establish who controlled that key');
    expect(arenaExperience).not.toContain('<h3>Prove</h3>');
    expect(arenaExperience).toContain('<h3>Record</h3>');
  });
});
