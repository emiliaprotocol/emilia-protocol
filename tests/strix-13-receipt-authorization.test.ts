// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { canMutateReceipt, canReadReceipt } from '../lib/tenant-binding.js';

const receipt = { organizationId: 'org_real', creatorActorId: 'ent_creator' };

describe('STRIX-13 receipt actor authorization', () => {
  it('allows the creating actor to read and mutate its own receipt', () => {
    const creator = {
      entity: { entity_id: 'ent_creator', organization_id: 'org_real' },
      permissions: [],
    };

    expect(canReadReceipt(creator, receipt)).toBe(true);
    expect(canMutateReceipt(creator, receipt, 'receipt.consume')).toBe(true);
    expect(canMutateReceipt(creator, receipt, 'receipt.execute')).toBe(true);
  });

  it('blocks a same-organization peer with generic read and write permissions', () => {
    const peer = {
      entity: { entity_id: 'ent_peer', organization_id: 'org_real' },
      permissions: ['read', 'write'],
    };

    expect(canReadReceipt(peer, receipt)).toBe(false);
    expect(canMutateReceipt(peer, receipt, 'receipt.consume')).toBe(false);
    expect(canMutateReceipt(peer, receipt, 'receipt.execute')).toBe(false);
  });

  it('allows only the exact scoped receipt capability inside the same organization', () => {
    const reader = {
      entity: { entity_id: 'ent_reader', organization_id: 'org_real' },
      permissions: ['receipt.read'],
    };
    const evidenceReader = {
      entity: { entity_id: 'ent_evidence', organization_id: 'org_real' },
      permissions: ['receipt.evidence'],
    };
    const executor = {
      entity: { entity_id: 'ent_executor', organization_id: 'org_real' },
      permissions: ['receipt.execute'],
    };

    expect(canReadReceipt(reader, receipt)).toBe(true);
    expect(canReadReceipt(reader, receipt, 'receipt.evidence')).toBe(false);
    expect(canReadReceipt(evidenceReader, receipt, 'receipt.evidence')).toBe(true);
    expect(canReadReceipt(evidenceReader, receipt)).toBe(false);
    expect(canMutateReceipt(reader, receipt, 'receipt.execute')).toBe(false);
    expect(canReadReceipt(executor, receipt)).toBe(false);
    expect(canMutateReceipt(executor, receipt, 'receipt.execute')).toBe(true);
    expect(canMutateReceipt(executor, receipt, 'receipt.consume')).toBe(false);
  });

  it('allows a same-organization administrator but never a cross-organization administrator', () => {
    const localAdmin = {
      entity: { entity_id: 'ent_admin', organization_id: 'org_real' },
      permissions: ['admin'],
    };
    const foreignAdmin = {
      entity: { entity_id: 'ent_admin', organization_id: 'org_attacker' },
      permissions: ['admin'],
    };

    expect(canReadReceipt(localAdmin, receipt)).toBe(true);
    expect(canMutateReceipt(localAdmin, receipt, 'receipt.execute')).toBe(true);
    expect(canReadReceipt(foreignAdmin, receipt)).toBe(false);
    expect(canMutateReceipt(foreignAdmin, receipt, 'receipt.execute')).toBe(false);
  });
});
