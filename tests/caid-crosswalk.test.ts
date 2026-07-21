// SPDX-License-Identifier: Apache-2.0
// Gate on the CAID crosswalk demo (examples/caid-crosswalk.mjs) — the
// running-code artifact for the Canonical Action Identifier + evidence-
// composition split-out. Asserts the ALLOW case and all three refuse cases.
import { describe, expect, it } from 'vitest';

import {
  ACTION, CAID, REQUIREMENT,
  mintEpLeg, mintAp2Leg, mintScittLeg,
  genuineChain, splicedChain, forgedBindingChain, missingLegChain,
  verifyCrosswalk,
} from '../examples/caid-crosswalk.mjs';

const byType = (res, type) => res.components.find((c) => c.type === type);

describe('CAID crosswalk (EP + AP2-shaped + SCITT-style legs)', () => {
  it('is a real crosswalk: each leg digests the same action in its own native form', () => {
    // EP's native digest IS the CAID; the other legs' native digests differ …
    expect(mintEpLeg(ACTION).binding.leg_digest).toBe('sha256:' + CAID);
    expect(mintAp2Leg(ACTION).binding.leg_digest).not.toBe('sha256:' + CAID);
    expect(mintScittLeg(ACTION).binding.leg_digest).not.toBe('sha256:' + CAID);
    // … yet every leg's signed binding record names the same CAID.
    for (const leg of [mintEpLeg(ACTION), mintAp2Leg(ACTION), mintScittLeg(ACTION)]) {
      expect(leg.binding.caid).toBe('sha256:' + CAID);
    }
  });

  it('ALLOWs when all three legs bind the same CAID', () => {
    const res = verifyCrosswalk(genuineChain());
    expect(res.allow).toBe(true);
    expect(res.action_digest).toBe(CAID);
    expect(res.expected_action_bound).toBe(true);
    expect(res.requirement_source).toBe('relying_party');
    for (const type of REQUIREMENT.split(' AND ')) {
      expect(byType(res, type)).toMatchObject({ valid: true, bound: true });
    }
  });

  it('DENYs a cross-binding splice: leg B binds a DIFFERENT action', () => {
    const res = verifyCrosswalk(splicedChain());
    expect(res.allow).toBe(false);
    // The spliced mandate is genuinely signed — it verifies under its own
    // rules — but its binding names another action's CAID. Only the chain's
    // digest-equality check catches it.
    expect(byType(res, 'ap2-cart-mandate')).toMatchObject({ valid: true, bound: false });
    expect(byType(res, 'ap2-cart-mandate').reason).toMatch(/DIFFERENT action/);
  });

  it('DENYs a binding record whose signature does not verify', () => {
    const res = verifyCrosswalk(forgedBindingChain());
    expect(res.allow).toBe(false);
    expect(byType(res, 'scitt-statement')).toMatchObject({ valid: false, bound: false });
  });

  it('DENYs when a required leg is missing', () => {
    const res = verifyCrosswalk(missingLegChain());
    expect(res.allow).toBe(false);
    expect(byType(res, 'scitt-statement')).toBeUndefined();
    expect(res.reasons.join('\n')).toMatch(/requirement not satisfied/);
  });
});
