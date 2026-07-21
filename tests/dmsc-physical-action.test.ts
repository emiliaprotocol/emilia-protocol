// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import { runCrossGatewayDemo } from '../examples/cross-gateway/dmsc-physical-action.mjs';

describe('DMSC cross-gateway action authorization', () => {
  it('allows the exact pinned approval and refuses every required failure class', async () => {
    const result = await runCrossGatewayDemo();

    expect(result.valid.allow).toBe(true);
    expect(result.valid.base_verdict).toBe('admissible');
    expect(result.valid.decision.payload.verdict).toBe('admissible');

    expect(result.missingApproval.allow).toBe(false);
    expect(result.missingApproval.base_verdict).toBe('unverifiable');
    expect(result.missingApproval.base.reasons).toContain('malformed_graph: graph has no nodes');

    expect(result.revokedApproval.allow).toBe(false);
    expect(result.revokedApproval.base_verdict).toBe('stale');
    expect(result.revokedApproval.base.reasons.join(' ')).toMatch(/revoked evidence/i);

    expect(result.expiredChallenge.allow).toBe(false);
    expect(result.expiredChallenge.reason).toBe('challenge expired');

    expect(result.unavailableStore.allow).toBe(false);
    expect(result.unavailableStore.reason).toBe('challenge_storage_unavailable');

    expect(result.actionSubstitution.allow).toBe(false);
    expect(result.actionSubstitution.reason).toMatch(/different action|action swap/i);

    expect(result.unpinnedAuthority.allow).toBe(false);
    expect(result.unpinnedAuthority.base_verdict).toBe('unverifiable');

    expect(result.replay.allow).toBe(false);
    expect(result.replay.reason).toMatch(/already consumed|replay/i);

    expect(result.secondClearance.allow).toBe(false);
    expect(result.secondClearance.reason).toBe('action_already_consumed');

    expect(result.offlineAudit.verified).toBe(true);
    expect(result.offlineTamper.verified).toBe(false);
    expect(result.demoStateOnly).toBe(true);
  });
});
