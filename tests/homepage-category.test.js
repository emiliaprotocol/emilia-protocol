import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

function read(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

describe('homepage category contract', () => {
  it('leads with the trust mission and keeps technical proof in a restrained band', () => {
    const page = read('app/page.js');
    const layout = read('app/layout.js');

    expect(layout).toContain('The Consequence Firewall for AI Agents');
    expect(layout).toContain('secure agent actions');
    expect(layout).toContain('AI agent firewall');
    expect(page).toContain('Building the foundation of trust for the agentic era.');
    expect(page).toContain('AI is moving from answering questions to taking consequential action.');
    expect(page).toContain('EMILIA is the open trust layer');
    expect(page).toContain('Technical foundation');
    expect(page).toContain('IETF Internet-Drafts');
    expect(page).toContain('CF-1 conformance');
    expect(page).toContain('href="/protocol"');
    expect(page).toContain('href="/proof"');
    expect(page).not.toContain('<CrashTestDemo />');
    expect(page).not.toContain('emilia-sequence.mp4');
  });

  it('binds public proof counts to generated repo evidence instead of stale literals', () => {
    const proofStats = JSON.parse(read('lib/proof-stats.json'));
    const securityCase = JSON.parse(read('security/security-case.json'));
    const page = read('app/page.js');
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
    // The Alloy assertion count is now interpolated from proofStats, not a
    // hardcoded literal — but the generated stats must still be 22.
    expect(proofStats.alloy.assertions).toBe(22);
  });
});
