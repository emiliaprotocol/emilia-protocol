import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

function read(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

describe('homepage category contract', () => {
  it('leads with the Consequence Firewall category and secure-agent-action promise', () => {
    const page = read('app/page.js');
    const layout = read('app/layout.js');

    expect(layout).toContain('The Consequence Firewall for AI Agents');
    expect(layout).toContain('secure agent actions');
    expect(layout).toContain('AI agent firewall');
    expect(page).toContain('The open Consequence Firewall for AI agents');
    expect(page).toContain('Stop AI agents from executing irreversible actions');
    expect(page).toContain('CF-1 conformance');
    expect(page).toContain('/try/receipt-required');
  });

  it('binds public proof counts to generated repo evidence instead of stale literals', () => {
    const proofStats = JSON.parse(read('lib/proof-stats.json'));
    const page = read('app/page.js');
    const proofBlock = read('components/ProofBlock.js');

    expect(proofStats.tests.total).toBeGreaterThan(4500);
    expect(proofStats.tests.files).toBeGreaterThan(200);
    expect(proofStats.tla.invariants).toBe(26);
    expect(proofStats.alloy.facts).toBe(35);
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
