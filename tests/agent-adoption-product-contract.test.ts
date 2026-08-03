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

  it('routes adoption graduates into the fixed 90-day $25K offer', () => {
    expect(experience.match(/\/pilot\?offer=agent-adoption/g)).toHaveLength(2);
    expect(pilot).toContain('AGENT_ADOPTION_DESIGN_PARTNER.id');
    expect(pilot).toContain("offer_id: ''");
    expect(offers).toMatch(/AGENT_ADOPTION_DESIGN_PARTNER[\s\S]*?durationLabel: '90 days'/);
    expect(offers).toMatch(/AGENT_ADOPTION_DESIGN_PARTNER[\s\S]*?shortPriceLabel: '\$25K'/);
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
    expect(homepage).toContain('Scan what your agents can reach');
    expect(publicPage).toContain('USER-SUPPLIED, UNVERIFIED CANDIDATE LABEL');
    expect(publicPage).toContain('creating browser session may have revoked it, or it may have expired');
    expect(css).toMatch(/\.publicationNote \{[\s\S]*?font-size: 12px;/);
    expect(css).toMatch(/\.envelopeFinePrint \{[\s\S]*?font-size: 12px;/);
  });
});
