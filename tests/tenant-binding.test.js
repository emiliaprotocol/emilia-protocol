// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { resolveAuthorizedOrg } from '../lib/tenant-binding.js';

const bound = { entity: { entity_id: 'ent_1', organization_id: 'org_real' } };
const unbound = { entity: { entity_id: 'ent_2' } };           // no organization_id
const stringEntity = { entity: 'ent_3' };                      // legacy string mock

describe('resolveAuthorizedOrg — tenant/org binding', () => {
  it('derives org from the authenticated entity, ignoring an omitted body', () => {
    expect(resolveAuthorizedOrg(bound, undefined)).toEqual({ organizationId: 'org_real' });
  });

  it('accepts a body org that matches the authenticated entity', () => {
    expect(resolveAuthorizedOrg(bound, 'org_real')).toEqual({ organizationId: 'org_real' });
  });

  it('REJECTS a body org that does not match the authenticated entity (cross-tenant)', () => {
    const r = resolveAuthorizedOrg(bound, 'org_attacker');
    expect(r.error?.status).toBe(403);
    expect(r.error?.code).toBe('organization_mismatch');
    expect(r.organizationId).toBeUndefined();
  });

  it('falls back to the body org for a not-yet-bound entity (transitional), flagged unbound', () => {
    expect(resolveAuthorizedOrg(unbound, 'org_x')).toEqual({ organizationId: 'org_x', unbound: true });
    expect(resolveAuthorizedOrg(stringEntity, 'org_x')).toEqual({ organizationId: 'org_x', unbound: true });
  });

  it('requires an org when neither the entity nor the body supplies one', () => {
    const r = resolveAuthorizedOrg(unbound, undefined);
    expect(r.error?.status).toBe(400);
    expect(r.error?.code).toBe('missing_organization_id');
  });

  it('fails closed for an unbound entity when requireBound is set (post-backfill mode)', () => {
    const r = resolveAuthorizedOrg(unbound, 'org_x', { requireBound: true });
    expect(r.error?.status).toBe(403);
    expect(r.error?.code).toBe('entity_not_org_bound');
  });
});
