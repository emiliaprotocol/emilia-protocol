// SPDX-License-Identifier: Apache-2.0
// Regression for the Strix full-stack Critical (2026-07-18): a public
// observe-mode pilot key could be pivoted into SCIM directory administration
// and the SSO control plane. The observe-scope guard closes that pivot while
// leaving real tenant keys untouched.

import { describe, it, expect } from 'vitest';
import { isObserveScoped, refuseObserveScope } from '../lib/auth/observe-scope.js';

const epProblem = (status, code, detail) => ({ status, code, detail });

const pilotAuth = {
  entity: { entity_id: 'ep_entity_x', metadata: { pilot_sandbox: true, scope: 'observe' } },
  permissions: [],
};
const scopeOnly = { entity: { metadata: { scope: 'observe' } } };
const tenantAuth = {
  entity: { entity_id: 'ep_entity_real', metadata: { plan: 'enterprise' } },
  permissions: ['admin'],
};
const noMeta = { entity: { entity_id: 'ep_entity_bare' } };

describe('observe-scope control-plane guard', () => {
  it('flags a pilot-provisioned key as observe-scoped', () => {
    expect(isObserveScoped(pilotAuth)).toBe(true);
    expect(isObserveScoped(scopeOnly)).toBe(true);
  });

  it('does not flag a real tenant key or a key without metadata', () => {
    expect(isObserveScoped(tenantAuth)).toBe(false);
    expect(isObserveScoped(noMeta)).toBe(false);
    expect(isObserveScoped({})).toBe(false);
    expect(isObserveScoped(null)).toBe(false);
  });

  it('refuses a pilot key at the control plane with a 403 and a named reason', () => {
    const denied = refuseObserveScope(pilotAuth, epProblem);
    expect(denied).not.toBeNull();
    expect(denied.status).toBe(403);
    expect(denied.code).toBe('observe_scope_forbidden');
  });

  it('lets a real tenant key through (returns null)', () => {
    expect(refuseObserveScope(tenantAuth, epProblem)).toBeNull();
    expect(refuseObserveScope(noMeta, epProblem)).toBeNull();
  });

  it('fails closed on a poisoned metadata type', () => {
    expect(isObserveScoped({ entity: { metadata: 'observe' } })).toBe(false); // string, not object
    expect(isObserveScoped({ entity: { metadata: ['observe'] } })).toBe(false);
  });
});
