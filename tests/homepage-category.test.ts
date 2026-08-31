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
  it('leads with the authority toll booth, keeps Gate customer-owned, and starts the five-product story', () => {
    const page = read('app/HomePageClient.js');
    const productStories = read('lib/product-stories.ts');
    const route = read('app/page.js');
    const css = read('app/ep.css');

    expect(route).toContain('Authority Toll Booth for Autonomous Work | EMILIA');
    expect(route).toContain('At configured protected boundaries, consequential agent actions must present customer authority before provider entry');
    expect(page).toContain('EMILIA <span>· The authority toll booth for autonomous work</span>');
    expect(page).toContain('Protected crossings require authority before action, then preserve what happened.');
    expect(page).toContain('EMILIA is building the universal agentic authority toll booth.');
    expect(page).toContain('each Gate remains customer-owned and local to its configured boundary.');
    expect(page).toContain('Even if AI writes the binary, it cannot write its own authority.');
    expect(page).toContain('The system may change how it decides. It cannot quietly expand what it is authorized to do.');
    expect(page).toContain('One creates intent. The other enforces authority.');
    expect(page).toContain('Intelligence system');
    expect(page).toContain('Authority system');
    expect(page).toContain('Intelligence is not authority.');
    expect(page).toContain('Mandate loaded');
    expect(page).toContain('One admitted provider attempt or refusal');
    expect(page).toContain('No invented certainty.');
    expect(page).toContain('This is not proof of success.');
    expect(page).toContain('Never retry blindly.');
    expect(css).toContain('emilia-authority-tollbooth-v1.png');
    expect(page).toContain('Public evidence');
    expect(page).toContain('unsafe counterexamples');
    expect(page).toContain("{ PRODUCT_STORIES } from '@/lib/product-stories'");
    expect(productStories).toContain("name: 'Authority Brain'");
    expect(productStories).toContain("name: 'EMILIA Gate'");
    expect(productStories).toContain("name: 'EMILIA Approver'");
    expect(productStories).toContain("name: 'EMILIA Protocol'");
    expect(productStories).toContain("name: 'Assurance Plane'");
    expect(page).toContain('href="/scan#run-local"');
    expect(page).toContain('href="/pilot"');
    expect(page).toContain('href="/products"');
    expect(page).toContain('href="/proof"');
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
    expect(investors).toContain('Every consequential agent action enters with authority and exits with a receipt.');
    expect(investors).toContain('EMILIA charges where authorized intent becomes consequential action.');
    expect(investors).toContain('Gate is the customer-owned authority toll booth.');
    expect(investors).toContain('currently claims no customer traction, recurring revenue, production deployment');
    expect(investors).toContain('certification, RFC status, or standards-body endorsement.');
    expect(productBrief).toContain('No independently administered operator has produced external witness evidence');
    expect(productBrief).toContain('they do not prove the deployed service, provider, or physical world.');
  });
});
