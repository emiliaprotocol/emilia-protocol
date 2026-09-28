import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { deriveSourceProofStats } from '../scripts/generate-proof-stats.mjs';

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
  it('leads with the new-hire gate story and keeps its claim boundaries on the page', () => {
    const client = read('app/HomePageClient.js');
    const page = read('components/home/NewHireStory.tsx');
    const route = read('app/page.js');

    expect(route).toContain('Hire the AI. Keep Your Rules. | EMILIA');
    expect(route).toContain('checks them at a gate the AI can’t go around');
    expect(client).toContain("from '@/components/home/NewHireStory'");
    expect(client).toContain('<NewHireStory />');
    for (const headline of [
      'Hire the AI.<br />Keep your rules.',
      'Rosa pays the bills',
      'EMILIA is the gate',
      'The new hire never<br />holds the keys',
      'Same bill.<br />Wrong account.',
      'Nobody grades their<br />own homework',
      'Free blueprint.<br />Running it is our job.',
    ]) {
      expect(page).toContain(headline);
    }
    expect(page).toContain('An illustrative story with AI-generated images. Rosa, her company and every amount in it are made up.');
    expect(page).toContain('This covers the payment paths a company connects through EMILIA.');
    expect(page).toContain('A check shows a receipt is genuine and unchanged. Which signers to trust stays the accountant&apos;s call.');
    expect(page).toContain('Each payment the gate allows gets a signed receipt');
    expect(page).toContain('never from the AI&apos;s say-so');
    expect(page).toContain('$3,046,598,558');
    expect(page).toContain('href="/try"');
    expect(page).toContain('href="/gate"');
    expect(page).toContain('href="/verify"');
    expect(page).not.toMatch(/\bindependent|certified|approved by|guarantee/i);

    const workforceRoute = read('app/workforce/page.tsx');
    const story = read('components/workforce/WorkforceStory.tsx');
    for (const section of ['WorkforceIntroduction', 'WorkforceHandover', 'WorkforceResponsibilities', 'WorkforceFoundation', 'WorkforceNextStep']) {
      expect(workforceRoute).toContain(`<${section} />`);
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
    // The pinned counts are derived from the checked-in sources with the
    // proof-stats writer's own extraction, so a source change fails here
    // directly. CI separately holds lib/proof-stats.json's derived fields to
    // the sources; only its test counts may lag (main refreshes them).
    const proofStats = JSON.parse(read('lib/proof-stats.json'));
    const derived = deriveSourceProofStats(ROOT);
    const securityCase = JSON.parse(read('security/security-case.json'));
    const page = read('components/home/NewHireStory.tsx');
    const proofBlock = read('components/ProofBlock.js');

    expect(proofStats.tests.total).toBeGreaterThan(4500);
    expect(proofStats.tests.files).toBeGreaterThan(200);
    expect(derived.tla.invariants).toBe(26);
    expect(derived.alloy.facts).toBe(35);
    expect(derived.tamarin.verifiedObligations).toBe(20);
    expect(derived.tamarin.deliberatelyUnsafeCounterexamples).toBe(8);
    expect(derived.securityCase.claims).toBe(securityCase.claim_count);
    expect(derived.conformance.vectors).toBeGreaterThan(150);
    expect(derived.externalImplementation.hostilityCases).toBeGreaterThan(350);
    expect(page).not.toContain('TESTS_PASSED');
    expect(derived.redTeamCases).toBe(86);

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
    const homepage = compact(read('app/HomePageClient.js') + read('components/home/NewHireStory.tsx'));
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
    expect(investors).toContain('Hire the AI. Keep your rules.');
    expect(investors).toContain('Nobody grades their own homework.');
    expect(investors).toContain('Rosa, her company and the amounts are made up');
    expect(investors).toContain('EMILIA is the company. Gate is the commercial product.');
    expect(investors).toContain('The workforce workspace is a private local alpha.');
    expect(investors).toContain('currently claims no customer traction, recurring revenue, production deployment');
    expect(investors).toContain('certification, RFC status, or standards-body endorsement.');
    expect(productBrief).toContain('No independently administered operator has produced external witness evidence');
    expect(productBrief).toContain('they do not prove the deployed service, provider, or physical world.');
  });
});
