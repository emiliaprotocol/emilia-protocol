// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  PROVENANCE_V2_REQUIRED_ALGORITHMS,
  PROVENANCE_V2_VERSION,
  assembleProvenanceV2,
  signDelegationLinkV2,
} from '../lib/provenance/chain.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

describe('EP-PROVENANCE-CHAIN-v2 issuer contract', () => {
  it('emits both registered delegation-proof legs over one link', async () => {
    const ed = crypto.generateKeyPairSync('ed25519');
    const pq = ml_dsa65.keygen(crypto.randomBytes(32));
    const signed = await signDelegationLinkV2({
      delegation_id: 'delegation:hybrid:001',
      delegator: 'org:example',
      delegatee: 'agent:buyer',
      scope: ['vendor.payment.release'],
      max_value_usd: 1000,
      expires_at: '2026-09-01T00:00:00Z',
      constraints: { environment: 'sandbox' },
    }, {
      private_key: ed.privateKey,
      pq_private_key: pq.secretKey,
    });

    expect(signed.proof_set.required_algorithms)
      .toEqual([...PROVENANCE_V2_REQUIRED_ALGORITHMS]);
    expect(signed.proof_set.signatures.map((entry: any) => entry.alg))
      .toEqual([...PROVENANCE_V2_REQUIRED_ALGORITHMS]);
  });

  it('refuses incomplete or wrong-curve issuer custody', async () => {
    const ed = crypto.generateKeyPairSync('ed25519');
    const ed448 = crypto.generateKeyPairSync('ed448');
    await expect(signDelegationLinkV2({}, {
      private_key: ed448.privateKey,
      pq_private_key: new Uint8Array([1]),
    })).rejects.toThrow(/Ed25519 private KeyObject/);
    await expect(signDelegationLinkV2({}, {
      private_key: ed.privateKey,
      pq_private_key: null as any,
    })).rejects.toThrow(/pq_private_key is required/);
  });

  it('assembles the v2 document and preserves optional evidence without inventing trust', () => {
    const actionHash = `sha256:${'a'.repeat(64)}`;
    const doc = assembleProvenanceV2({
      rootSignoff: {
        receipt: { receipt_id: 'receipt:root', action_hash: actionHash },
        verification: { valid: true },
        human_key_classes: ['A'],
      },
      delegationChain: [{ delegation_id: 'delegation:one' }],
      actionApproval: {
        receipt: { receipt_id: 'receipt:approval', action_hash: actionHash },
        verification: { valid: true },
      },
      execution: { action_hash: actionHash, irreversible: true },
      agentIdentity: { agent_id: 'agent:buyer' },
      liability: { owner: 'org:example' },
      metadata: { test_vector: 'issuer-contract' },
    });

    expect(doc['@version']).toBe(PROVENANCE_V2_VERSION);
    expect(doc.delegation_chain[0].sequence).toBe(0);
    expect(doc.action_approval.receipt.receipt_id).toBe('receipt:approval');
    expect(doc.agent_identity.agent_id).toBe('agent:buyer');
    expect(doc.liability.owner).toBe('org:example');
    expect(doc.provenance_metadata).toMatchObject({
      chain_depth: 1,
      test_vector: 'issuer-contract',
    });
  });

  it('refuses missing anchors and irreversible execution without action approval', () => {
    expect(() => assembleProvenanceV2({
      rootSignoff: {},
      execution: { action_hash: 'x', irreversible: false },
    })).toThrow(/rootSignoff/);
    expect(() => assembleProvenanceV2({
      rootSignoff: { receipt: {}, verification: {} },
      execution: {},
    })).toThrow(/execution/);
    expect(() => assembleProvenanceV2({
      rootSignoff: { receipt: {}, verification: {} },
      execution: { action_hash: 'x', irreversible: true },
    })).toThrow(/actionApproval/);
  });
});
