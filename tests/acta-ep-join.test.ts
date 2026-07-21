import { describe, expect, it } from 'vitest';

import {
  ACTA_COMPONENT_TYPE,
  artifactDigest,
  computeActaActionRef,
  createActaDecisionVerifier,
} from '../examples/acta-ep-join/acta-profile.mjs';
import {
  buildActaEpFixture,
  gateFor,
  runActaEpJoinDemo,
} from '../examples/acta-ep-join/demo.mjs';

function componentContext(fixture, keysByType) {
  return {
    action: fixture.action,
    verificationTime: fixture.verificationTime,
    keysByType,
  };
}

function verifierFor(fixture, expectedReceipt = fixture.epReceipt) {
  return createActaDecisionVerifier({
    expectedActionRef: computeActaActionRef(fixture.expectedActaEvaluation),
    expectedHumanAuthorizationDigest: artifactDigest(expectedReceipt),
    policy: fixture.trust.actaPolicy,
  });
}

describe('ACTA + EP interoperability profile', () => {
  it('executes the conjunctive machine + human proof once and refuses every hostile scenario', async () => {
    await expect(runActaEpJoinDemo()).resolves.toEqual({
      valid_pair: 'executed_once',
      replay: 'replay_refused',
      action_substitution: 'aec_refused',
      unpinned_acta_key: 'aec_refused',
      machine_as_human: 'aec_refused',
      stale_human_approval: 'aec_refused',
      different_ep_receipt: 'aec_refused',
      embedded_acta_key: 'aec_refused',
    });
  });

  it('computes ACTA action_ref independently of scope input order and rejects impossible dates', () => {
    const input = {
      agentId: 'urn:agent:7',
      actionType: 'payment.release.1',
      scopeRequired: ['z', 'a'],
      timestamp: '2026-07-14T18:00:00Z',
    };
    expect(computeActaActionRef(input)).toBe(computeActaActionRef({
      ...input,
      scopeRequired: ['a', 'z'],
    }));
    expect(computeActaActionRef({ ...input, timestamp: '2026-02-30T18:00:00Z' })).toBeNull();
  });

  it('does not let a key pinned for another role verify the ACTA component', async () => {
    const fixture = await buildActaEpFixture();
    const verifier = verifierFor(fixture);
    const result = verifier(fixture.actaReceipt, componentContext(fixture, {
      'unrelated-policy-role': fixture.trust.actaIssuerKeys,
    }));
    expect(result.valid).toBe(false);
    expect(result.detail.reason).toMatch(/not active and pinned for the ACTA role/);
  });

  it('refuses revoked keys, stale registry state, and embedded signature keys', async () => {
    const fixture = await buildActaEpFixture();
    const verifier = verifierFor(fixture);
    const revokedKeys = structuredClone(fixture.trust.actaIssuerKeys);
    const [kid] = Object.keys(revokedKeys);
    revokedKeys[kid].revoked_at = '2026-07-14T18:00:00Z';
    expect(verifier(fixture.actaReceipt, componentContext(fixture, {
      [ACTA_COMPONENT_TYPE]: revokedKeys,
    })).detail.reason).toMatch(/not active and pinned/);

    const stalePolicy = {
      ...fixture.trust.actaPolicy,
      registry_checked_at: '2026-07-14T17:00:00Z',
    };
    const staleVerifier = createActaDecisionVerifier({
      expectedActionRef: computeActaActionRef(fixture.expectedActaEvaluation),
      expectedHumanAuthorizationDigest: artifactDigest(fixture.epReceipt),
      policy: stalePolicy,
    });
    expect(staleVerifier(fixture.actaReceipt, componentContext(fixture, {
      [ACTA_COMPONENT_TYPE]: fixture.trust.actaIssuerKeys,
    })).detail.reason).toMatch(/registry snapshot is stale/);

    const embedded = structuredClone(fixture.actaReceipt);
    embedded.signature.public_key = fixture.trust.actaIssuerKeys[kid].public_key;
    expect(verifier(embedded, componentContext(fixture, {
      [ACTA_COMPONENT_TYPE]: fixture.trust.actaIssuerKeys,
    })).detail.reason).toMatch(/unexpected ACTA signature member/);
  });

  it('binds the ACTA decision to the exact independently verified EP receipt', async () => {
    const fixture = await buildActaEpFixture();
    const otherReceipt = await fixture.issueEpReceipt('ep:receipt:acta-join-test-other');
    const verifier = verifierFor(fixture, otherReceipt);
    const result = verifier(fixture.actaReceipt, componentContext(fixture, {
      [ACTA_COMPONENT_TYPE]: fixture.trust.actaIssuerKeys,
    }));
    expect(result.valid).toBe(false);
    expect(result.detail.reason).toMatch(/does not reference the exact EP human receipt/);
  });

  it('binds ACTA CAID and ep_action_digest to the relying party action', async () => {
    const fixture = await buildActaEpFixture();
    const verifier = verifierFor(fixture);
    const changedAction = { ...fixture.action, amount: '24000000.00' };
    const result = verifier(fixture.actaReceipt, {
      ...componentContext(fixture, {
        [ACTA_COMPONENT_TYPE]: fixture.trust.actaIssuerKeys,
      }),
      action: changedAction,
    });
    expect(result.valid).toBe(false);
    expect(result.detail.reason).toMatch(/CAID does not match/);
  });

  it('uses the shared AEC consumption domain to refuse a second execution', async () => {
    const fixture = await buildActaEpFixture();
    const gate = gateFor(fixture);
    const request = {
      chain: fixture.chain,
      expectedAction: fixture.action,
      expectedActaEvaluation: fixture.expectedActaEvaluation,
    };
    let executions = 0;
    const first = await gate.run(request, async () => { executions += 1; });
    const second = await gate.run(request, async () => { executions += 1; });
    expect(first.allow).toBe(true);
    expect(second).toMatchObject({ allow: false, reason: 'replay_refused' });
    expect(executions).toBe(1);
  });
});
