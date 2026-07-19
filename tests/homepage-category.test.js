import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

function read(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

describe('homepage category contract', () => {
  it('leads with the Consequence Firewall product and keeps technical proof in a restrained band', () => {
    const page = read('app/HomePageClient.js');
    const layout = read('app/layout.js');
    const css = read('app/ep.css');

    expect(layout).toContain('The Consequence Firewall for AI Agents');
    expect(layout).toContain('secure agent actions');
    expect(layout).toContain('AI agent firewall');
    expect(page).toContain('EMILIA Gate <span>· The Consequence Firewall</span>');
    expect(page).toContain('Before a machine changes the world, make it prove the action was authorized.');
    expect(page).toContain('On a fully mediated protected path: no valid receipt, no movement of money, code,');
    expect(css).toContain('hero-human-machine-shoreline-v1.webp');
    expect(page).toContain('Proof, not promises');
    expect(page).toContain('IETF Internet-Drafts');
    expect(page).toContain('verified lemmas');
    expect(page).toContain('counterexample traces');
    expect(page).toContain('href="/gate/live"');
    expect(page).toContain('href="/gate"');
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
    expect(proofStats.tamarin.verifiedObligations).toBe(10);
    expect(proofStats.tamarin.deliberatelyUnsafeCounterexamples).toBe(2);
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
});
