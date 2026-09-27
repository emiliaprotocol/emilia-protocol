// SPDX-License-Identifier: Apache-2.0
//
// draft-schrock-canonical-action-identifier-04, Section 4.2.4: status never
// affects verification, and a verifier MUST NOT refuse a CAID because its
// type is deprecated. An issuer may stop minting under a deprecated type.
// This deprecates payment.release.1 in the registry view the approval
// contract reads, then checks both halves.

import { describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/caid-registry', async (importOriginal) => {
  const actual: any = await importOriginal();
  const deprecated = (actionType: string) => {
    const definition = actual.registryDefinition(actionType);
    return definition && actionType === 'payment.release.1'
      ? { ...definition, status: 'deprecated', superseded_by: 'payment.release.2' }
      : definition;
  };
  return {
    ...actual,
    registryDefinition: deprecated,
    activeCaidDefinition: (actionType: string) => {
      const definition = deprecated(actionType);
      return definition?.status === 'active' ? definition : undefined;
    },
  };
});

const MATERIAL = Object.freeze({
  action_type: 'payment.release',
  amount_usd: 200,
  currency: 'USD',
  payment_instruction_id: 'payment:bike:0001',
  beneficiary_account_hash: `sha256:${'a'.repeat(64)}`,
  counterparty_name: 'Bicycle Shop',
});

describe('approval CAIDs under a deprecated payment.release.1', () => {
  it('refuses to mint a new approval CAID', async () => {
    const { buildPaymentReleaseActionIdentity } = await import('../lib/approval-acquisition/contract.ts');
    expect(buildPaymentReleaseActionIdentity({ ...MATERIAL })).toEqual({
      ok: false,
      detail: 'payment.release.1 is not an active CAID action type',
    });
  });

  it('still recomputes the CAID of an approval issued while the type was active', async () => {
    const { recomputePaymentReleaseActionIdentity } = await import('../lib/approval-acquisition/contract.ts');
    const { computeCaid } = await import('../caid/impl/js/caid.mjs');
    const actual: any = await vi.importActual('@/lib/caid-registry');
    const issued = computeCaid({
      action_type: 'payment.release.1',
      amount: '200',
      currency: 'USD',
      beneficiary_account: MATERIAL.beneficiary_account_hash,
      payment_instruction_id: MATERIAL.payment_instruction_id,
      memo: 'Bicycle Shop',
    }, {
      suite: 'jcs-sha256',
      definitions: [actual.registryDefinition('payment.release.1')],
      enumSnapshots: actual.CAID_REGISTRY_ENUM_SNAPSHOTS,
    });
    expect(typeof issued.caid).toBe('string');
    expect(recomputePaymentReleaseActionIdentity({ ...MATERIAL })).toMatchObject({
      ok: true,
      actionCaid: issued.caid,
      caidDigest: issued.digest,
    });
  });
});
