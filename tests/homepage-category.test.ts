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
  it('leads with the authority control plane, keeps Gate as the enforcement product, and keeps Authority Brain as the free entry point', () => {
    const page = read('app/HomePageClient.js');
    const route = read('app/page.js');
    const css = read('app/ep.css');

    expect(route).toContain('Authority Control Plane for Autonomous Work | EMILIA');
    expect(route).toContain('Set a finite operating mandate once');
    expect(page).toContain('EMILIA <span>· Authority control plane for autonomous work</span>');
    expect(page).toContain('Set authority once. Let agents work.');
    expect(page).toContain('Not every action needs a human. Every consequential action needs valid authority.');
    expect(page).toContain('Protocol proves. Gate prevents.');
    expect(page).toContain('Identity tells you who. Authority defines the work.');
    expect(page).toContain('Existing authorization stack');
    expect(page).toContain('EMILIA authority control plane');
    expect(page).toContain('Mandate loaded');
    expect(page).toContain('Once before credentialed provider entry');
    expect(page).toContain('No invented certainty.');
    expect(page).toContain('This is not proof of success.');
    expect(page).toContain('Never retry blindly.');
    expect(css).toContain('hero-human-machine-shoreline-v1.webp');
    expect(page).toContain('Public evidence');
    expect(page).toContain('unsafe counterexamples');
    expect(page).toContain("href: '/authority-brain'");
    expect(page).toContain('href="/scan"');
    expect(page).toContain('href="/pilot"');
    expect(page).toContain('href="/gate/live"');
    expect(page).toContain("href: '/gate'");
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
    expect(proofStats.redTeamCases).toBe(85);

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
    const gate = compact(read('app/gate/page.js'));
    const investors = compact(read('app/investors/page.js'));
    const productBrief = compact(read('docs/EMILIA-GATE-PRODUCT-BRIEF.md'));

    for (const surface of [gate, productBrief]) {
      expect(surface).toContain(hierarchy);
    }

    expect(homepage).not.toContain('AgentROA governs calls.');
    expect(homepage).not.toContain('ORPRG proves policy permitted the effect.');
    expect(homepage).toContain('EMILIA supports the procedure; it does not issue the audit opinion.');
    expect(gate).toContain('A match is not authorization');
    expect(gate).toContain('consumes the reservation as indeterminate: no blind retry or refund');
    expect(gate).toContain('RECEIPT PROGRAMS');
    expect(gate).toContain('npm run demo:receipt-program');
    expect(gate).toContain('It is not a ZK proof, consensus result, provider attestation');
    expect(investors).toContain('EMILIA is the authority control plane for autonomous work.');
    expect(investors).toContain('Policy describes what is generally allowed. Neither defines the finite job an autonomous worker may perform under current limits.');
    expect(investors).toContain('currently claims no customer traction, recurring revenue, live payer integration');
    expect(investors).toContain('certification, RFC status, or standards-body endorsement.');
    expect(productBrief).toContain('No independently administered operator has produced external witness evidence');
    expect(productBrief).toContain('they do not prove the deployed service, provider, or physical world.');
  });
});
