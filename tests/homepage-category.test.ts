import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

function read(relPath) {
  // Routes/pages/components are migrating .js -> .ts/.tsx file-by-file; read
  // whichever extension actually exists on disk.
  const full = path.join(ROOT, relPath);
  if (!fs.existsSync(full) && relPath.endsWith('.js')) {
    for (const ext of ['.ts', '.tsx']) {
      const candidate = path.join(ROOT, `${relPath.slice(0, -3)}${ext}`);
      if (fs.existsSync(candidate)) return fs.readFileSync(candidate, 'utf8');
    }
  }
  return fs.readFileSync(full, 'utf8');
}

function compact(value) {
  return value
    .replace(/^\s*>\s?/gm, '')
    .replace(/&(?:apos|rsquo);/g, '’')
    .replace(/\s+/g, ' ');
}

describe('homepage category contract', () => {
  it('leads with workforce management and keeps the product, Gate and open Protocol distinct', () => {
    const page = read('app/HomePageClient.js');
    const story = read('components/workforce/WorkforceStory.tsx');
    const route = read('app/page.js');

    expect(route).toContain('Build Your AI Workforce | EMILIA');
    expect(route).toContain('Find specialized agents or bring your own.');
    expect(page).toContain("from '@/components/workforce/WorkforceStory'");
    for (const section of ['WorkforceIntroduction', 'WorkforceHandover', 'WorkforceResponsibilities', 'WorkforceFoundation', 'WorkforceNextStep']) {
      expect(page).toContain(`<${section} />`);
    }
    expect(story).toContain('Build your<br />AI workforce.');
    expect(story).toContain('The job stays. The agent can change.');
    expect(story).toContain('EMILIA is the company.');
    expect(story).toContain('Gate applies your authority.');
    expect(story).toContain('The Protocol stays open.');
    expect(story).toContain('Workforce workspace: private local alpha.');
    expect(story).toContain('href="/contact#workforce"');
    expect(story).toContain('href="/scan#run-local"');
    expect(page).toContain('href="/workforce"');
    expect(page).toContain('href="/products"');
    expect(page).toContain('href="/proof"');
    expect(page).toContain('Those are engineering results, not customer adoption or proof of a complete deployment.');
    expect(page).toContain('No customer savings or ROI are claimed.');
    expect(page).not.toContain('<CrashTestDemo />');
    expect(page).not.toContain('emilia-sequence.mp4');
  });

  it('binds public proof counts to generated repo evidence instead of stale literals', () => {
    const proofStats = JSON.parse(read('lib/proof-stats.json'));
    const securityCase = JSON.parse(read('security/security-case.json'));
    const page = read('app/HomePageClient.js');
    const proofBlock = read('components/ProofBlock.js');

    expect(proofStats.tests.total).toBeGreaterThan(4500);
    expect(proofStats.tests.files).toBeGreaterThan(200);
    expect(proofStats.tla.invariants).toBe(26);
    expect(proofStats.alloy.facts).toBe(35);
    expect(proofStats.tamarin.verifiedObligations).toBe(20);
    expect(proofStats.tamarin.deliberatelyUnsafeCounterexamples).toBe(8);
    expect(proofStats.securityCase.claims).toBe(securityCase.claim_count);
    expect(proofStats.conformance.vectors).toBeGreaterThan(150);
    expect(proofStats.externalImplementation.hostilityCases).toBeGreaterThan(350);
    expect(page).not.toContain('TESTS_PASSED');
    expect(proofStats.redTeamCases).toBe(86);

    expect(page).toContain("proofStats from '@/lib/proof-stats.json'");
    expect(page).not.toContain('4,220');

    // ProofBlock must also read its counts from proof-stats.json (finding #4:
    // the TLA/Alloy numbers were hardcoded literals that could silently drift).
    expect(proofBlock).toContain("proofStats from '@/lib/proof-stats.json'");
    expect(proofBlock).not.toContain('15 assertions');
    expect(proofBlock).toContain('Anyone can copy a schema');
    expect(proofBlock).toContain('execution_requires_full_composition');
    expect(proofBlock).toContain('no_issuer_laundering');
    expect(proofBlock).toContain('injective_execution_with_consumption');
    expect(proofBlock).toContain('unchecked_composition_is_injective');
    expect(proofBlock).toContain('Open does not mean interchangeable.');
    // The Alloy assertion count is interpolated from proofStats, not a hardcoded
    // literal. It is 32 across the four models now executed headless in CI
    // (ep_relations 15 + ep_federation 7 + ep_quorum 6 + ep_delegation 4); it was
    // 22 when only ep_relations + ep_federation were counted.
    expect(proofStats.alloy.assertions).toBe(32);
  });

  it('keeps the technical composition hierarchy off the buyer homepage and bounded on diligence surfaces', () => {
    const hierarchy =
      'AgentROA governs calls. ORPRG proves policy permitted the effect. EMILIA verifies the exact authority and any required approver evidence under the relying party’s pinned rules, then controls admission at covered consequence boundaries.';
    const homepage = compact(read('app/HomePageClient.js'));
    const productStories = compact(read('lib/product-stories.ts'));
    const gate = compact(read('app/gate/page.js'));
    const investors = compact(read('app/investors/page.js'));
    const productBrief = compact(read('docs/EMILIA-GATE-PRODUCT-BRIEF.md'));

    for (const surface of [gate, productBrief]) {
      expect(surface).toContain(hierarchy);
    }

    expect(homepage).not.toContain('AgentROA governs calls.');
    expect(homepage).not.toContain('ORPRG proves policy permitted the effect.');
    expect(productStories).toContain('EMILIA supports the procedure. It does not issue an audit opinion');
    expect(gate).toContain('A match is not authorization');
    expect(gate).toContain('consumes the reservation as indeterminate: no blind retry or refund');
    expect(gate).toContain('RECEIPT PROGRAMS');
    expect(gate).toContain('npm run demo:receipt-program');
    expect(gate).toContain('It is not a ZK proof, consensus result, provider attestation');
    expect(investors).toContain('Your AI workforce needs management.');
    expect(investors).toContain('Give every agent a job, set its authority, and know what happened.');
    expect(investors).toContain('EMILIA is the company. Gate is the commercial product.');
    expect(investors).toContain('The workforce workspace is a private local alpha.');
    expect(investors).toContain('currently claims no customer traction, recurring revenue, production deployment');
    expect(investors).toContain('certification, RFC status, or standards-body endorsement.');
    expect(productBrief).toContain('No independently administered operator has produced external witness evidence');
    expect(productBrief).toContain('they do not prove the deployed service, provider, or physical world.');
  });
});
