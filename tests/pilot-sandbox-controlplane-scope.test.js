// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { isObserveScoped, refuseObserveScope } from '../lib/auth/observe-scope.js';

const epProblem = (status, code, detail) => ({ status, code, detail });

const pilotAuth = {
  entity: {
    entity_id: 'ep_entity_0123456789abcdef01234567',
    organization_id: 'ep_entity_0123456789abcdef01234567',
    display_name: 'Pilot · Example',
    description: 'Observe-mode pilot sandbox for Example',
    entity_type: 'agent',
    metadata: { pilot_sandbox: true, scope: 'observe' },
  },
  permissions: [],
};

const legacyPilotAuth = {
  entity: {
    entity_id: 'ep_entity_0123456789abcdef01234567',
    organization_id: 'ep_entity_0123456789abcdef01234567',
    display_name: 'Pilot · Legacy Example',
    description: 'Observe-mode pilot sandbox for Legacy Example',
    entity_type: 'agent',
  },
  permissions: ['read', 'write'],
};

const tenantAuth = {
  entity: {
    entity_id: 'ep_entity_real',
    organization_id: 'org_real',
    owner_id: 'ep_owner_123',
    display_name: 'Real tenant',
    description: 'A real tenant',
    entity_type: 'agent',
    metadata: { plan: 'enterprise' },
  },
  permissions: ['admin'],
};

describe('observe-scope control-plane guard', () => {
  it('flags current and legacy pilot identities', () => {
    expect(isObserveScoped(pilotAuth)).toBe(true);
    expect(isObserveScoped(legacyPilotAuth)).toBe(true);
  });

  it('does not flag a real tenant or an unrelated entity with a partial shape', () => {
    expect(isObserveScoped(tenantAuth)).toBe(false);
    expect(isObserveScoped({ entity: { entity_id: 'ep_entity_bare' } })).toBe(false);
    expect(isObserveScoped({})).toBe(false);
    expect(isObserveScoped(null)).toBe(false);
  });

  it('refuses both pilot generations with a named 403 reason', () => {
    for (const auth of [pilotAuth, legacyPilotAuth]) {
      expect(refuseObserveScope(auth, epProblem)).toMatchObject({
        status: 403,
        code: 'observe_scope_forbidden',
      });
    }
  });

  it('fails closed on poisoned metadata and does not broaden the legacy match', () => {
    expect(isObserveScoped({ entity: { metadata: 'observe' } })).toBe(false);
    expect(isObserveScoped({ entity: { metadata: ['observe'] } })).toBe(false);
    expect(isObserveScoped({
      entity: {
        entity_id: 'ep_entity_0123456789abcdef01234567',
        organization_id: 'org_other',
        display_name: 'Pilot · Spoof',
        description: 'Observe-mode pilot sandbox for Spoof',
        entity_type: 'agent',
      },
    })).toBe(false);
  });
});
