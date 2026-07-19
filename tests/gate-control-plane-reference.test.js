// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { runGateControlPlaneReference } from '../lib/gate/control-plane-reference.js';

describe('Gate three-plane reference', () => {
  const now = Date.parse('2026-07-16T20:00:00.000Z');

  it('earns gated only with attestation and the active refusal probe', async () => {
    const result = await runGateControlPlaneReference({ mode: 'complete', now });
    expect(result.reference_only).toBe(true);
    expect(result.physical_claim).toBe(false);
    expect(result.planes.enforcement.state).toBe('gated');
    expect(result.planes.enforcement.deployment_attested).toBe(true);
    expect(result.planes.enforcement.refusal_probe_verified).toBe(true);
    expect(result.planes.witness.verified).toBe(true);
    expect(result.planes.control.settlement_verdict).toBe('eligible');
  });

  it('keeps a passive witness healthy while refusing to call it enforcement', async () => {
    const result = await runGateControlPlaneReference({ mode: 'witness_only', now });
    expect(result.planes.enforcement.state).toBe('witness_only');
    expect(result.planes.witness.verified).toBe(true);
    expect(result.planes.control.settlement_verdict).toBe('refuse_coverage');
    expect(result.planes.control.settlement_eligible).toBe(false);
  });

  it('refuses unknown modes', async () => {
    await expect(runGateControlPlaneReference({ mode: 'trust-me', now })).rejects.toThrow('unknown_control_plane_mode');
  });
});
