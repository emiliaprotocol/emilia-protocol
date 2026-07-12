// SPDX-License-Identifier: Apache-2.0
// Safety-critical acceptance contract for EP-AEC. These tests intentionally
// distinguish "the presenter's bundle is internally self-consistent" from
// "a relying party accepts this bundle for execution". The latter always
// requires relying-party-owned policy and bounded, unambiguous inputs.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import fc from 'fast-check';

import { canonicalize } from '../packages/verify/index.js';
import { verifyAuthorizationChain } from '../packages/verify/evidence-chain.js';

const action = { action_type: 'safety.critical.test', target: 'simulator', sequence: '1' };
const digest = `sha256:${crypto.createHash('sha256').update(canonicalize(action), 'utf8').digest('hex')}`;
const executionBinding = { expectedActionDigest: digest };
const policyVerifier = () => ({ valid: true, action_digest: digest });
const chain = (component, requirement = 'policy_decision') => ({
  '@version': 'EP-AEC-v1',
  action,
  requirement,
  components: [component],
});

function validSingleMemberQuorum() {
  const rpId = 'untrusted.example';
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKey = kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const context = {
    ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: digest,
    policy: 'presenter-policy', nonce: 'n1', approver: 'ep:approver:one',
    initiator: 'ep:agent:other', issued_at: '2026-07-11T12:00:00.000Z',
    expires_at: '2036-07-11T12:00:00.000Z',
  };
  const challenge = crypto.createHash('sha256').update(canonicalize(context), 'utf8').digest().toString('base64url');
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: `https://${rpId}` }));
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(rpId).digest(),
    Buffer.from([0x05, 0, 0, 0, 0]),
  ]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signoff = {
    '@type': 'ep.signoff.webauthn', context,
    webauthn: {
      authenticator_data: authData.toString('base64url'),
      client_data_json: clientData.toString('base64url'),
      signature: crypto.sign('sha256', signed, kp.privateKey).toString('base64url'),
    },
  };
  return {
    publicKey,
    quorum: {
      '@type': 'ep.quorum', action_hash: digest,
      policy: {
        mode: 'threshold', required: 1, distinct_humans: true,
        window_sec: 315360000,
        approvers: [{ role: 'sole', approver: 'ep:approver:one' }],
      },
      members: [{ role: 'sole', approver_public_key: publicKey, signoff }],
    },
  };
}

describe('EP-AEC safety-critical acceptance contract', () => {
  it('requires a relying-party-pinned requirement before returning allow', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'policy_decision', evidence: {} }),
      { verifiers: { policy_decision: policyVerifier }, ...executionBinding },
    );
    expect(r.requirement_source).toBe('presenter');
    expect(r.allow).toBe(false);
  });

  it('keeps presenter-controlled labels informational, never authoritative', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'policy_decision', label: 'cfo', evidence: {} }),
      { verifiers: { policy_decision: policyVerifier }, requirement: 'cfo', ...executionBinding },
    );
    expect(r.components[0]).toMatchObject({ valid: true, bound: true, label: 'cfo' });
    expect(r.allow).toBe(false);
  });

  it('rejects requirement strings containing unparsed characters', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'policy_decision', evidence: {} }),
      { verifiers: { policy_decision: policyVerifier }, requirement: 'policy_decision!!!', ...executionBinding },
    );
    expect(r.allow).toBe(false);
  });

  it('does not permit a custom verifier to override a reserved built-in role', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'ep-receipt', evidence: {} }, 'ep-receipt'),
      { verifiers: { 'ep-receipt': policyVerifier }, requirement: 'ep-receipt', ...executionBinding },
    );
    expect(r.allow).toBe(false);
  });

  it('returns a refusal rather than throwing on a malformed component', () => {
    let r;
    expect(() => {
      r = verifyAuthorizationChain({
        '@version': 'EP-AEC-v1', action, requirement: 'ep-receipt', components: [null],
      }, { requirement: 'ep-receipt', ...executionBinding });
    }).not.toThrow();
    expect(r.allow).toBe(false);
  });

  it('requires an exact boolean true from a component verifier', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'policy_decision', evidence: {} }),
      { verifiers: { policy_decision: () => ({ valid: 'false', action_digest: digest }) }, requirement: 'policy_decision', ...executionBinding },
    );
    expect(r.allow).toBe(false);
  });

  it('bounds component count and requirement length before evaluation', () => {
    const component = { type: 'policy_decision', evidence: {} };
    const tooMany = verifyAuthorizationChain({
      '@version': 'EP-AEC-v1', action, requirement: 'policy_decision', components: Array(65).fill(component),
    }, { verifiers: { policy_decision: policyVerifier }, requirement: 'policy_decision', ...executionBinding });
    const tooLong = verifyAuthorizationChain(
      chain(component),
      { verifiers: { policy_decision: policyVerifier }, requirement: `policy_decision${' '.repeat(4097)}`, ...executionBinding },
    );
    expect(tooMany.allow).toBe(false);
    expect(tooLong.allow).toBe(false);
  });

  it('rejects an array where the Action Object is required', () => {
    const r = verifyAuthorizationChain({
      '@version': 'EP-AEC-v1', action: [], requirement: 'policy_decision',
      components: [{ type: 'policy_decision', evidence: {} }],
    }, { verifiers: { policy_decision: policyVerifier }, requirement: 'policy_decision', ...executionBinding });
    expect(r.allow).toBe(false);
  });

  it('requires a relying-party quorum profile, not merely pinned member keys', () => {
    const { publicKey, quorum } = validSingleMemberQuorum();
    const r = verifyAuthorizationChain(
      chain({ type: 'ep-quorum', evidence: quorum }, 'ep-quorum'),
      {
        keysByType: { 'ep-quorum': { [publicKey]: publicKey } },
        requirement: 'ep-quorum',
        ...executionBinding,
      },
    );
    expect(r.allow).toBe(false);
  });

  it('still accepts a valid custom component under an explicit relying-party bar', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'policy_decision', evidence: {} }),
      { verifiers: { policy_decision: policyVerifier }, requirement: 'policy_decision', ...executionBinding },
    );
    expect(r.allow).toBe(true);
    expect(r.requirement_source).toBe('relying_party');
  });

  it('requires the executor to pin the expected action independently of the chain', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'policy_decision', evidence: {} }),
      { verifiers: { policy_decision: policyVerifier }, requirement: 'policy_decision' },
    );
    expect(r.allow).toBe(false);
    expect(r.expected_action_bound).toBe(false);
  });

  it('refuses a valid chain when the executor expects a different action', () => {
    const r = verifyAuthorizationChain(
      chain({ type: 'policy_decision', evidence: {} }),
      {
        verifiers: { policy_decision: policyVerifier },
        requirement: 'policy_decision',
        expectedAction: { ...action, sequence: '2' },
      },
    );
    expect(r.allow).toBe(false);
  });

  it('rejects over-depth and invalid-Unicode JSON before canonicalization', () => {
    let deep = { leaf: true };
    for (let i = 0; i < 65; i++) deep = { nested: deep };
    const overDepth = verifyAuthorizationChain({
      '@version': 'EP-AEC-v1', action: deep, requirement: 'policy_decision',
      components: [{ type: 'policy_decision', evidence: {} }],
    }, { verifiers: { policy_decision: policyVerifier }, requirement: 'policy_decision', expectedActionDigest: digest });
    const unpaired = verifyAuthorizationChain({
      '@version': 'EP-AEC-v1', action: { text: '\ud800' }, requirement: 'policy_decision',
      components: [{ type: 'policy_decision', evidence: {} }],
    }, { verifiers: { policy_decision: policyVerifier }, requirement: 'policy_decision', expectedActionDigest: digest });
    expect(overDepth.allow).toBe(false);
    expect(unpaired.allow).toBe(false);
  });

  it('never throws for arbitrary parsed-JSON-shaped input', () => {
    fc.assert(fc.property(fc.jsonValue(), (value) => {
      expect(() => verifyAuthorizationChain(value, {
        requirement: 'policy_decision', expectedActionDigest: digest,
      })).not.toThrow();
    }), { numRuns: 1000 });
  });

  it('never throws for hostile native objects with throwing accessors', () => {
    const getter = {};
    Object.defineProperty(getter, '@version', {
      enumerable: true,
      get() { throw new Error('getter trap'); },
    });
    const proxy = new Proxy({}, {
      ownKeys() { throw new Error('proxy trap'); },
    });
    for (const value of [getter, proxy]) {
      let result;
      expect(() => { result = verifyAuthorizationChain(value, {
        requirement: 'policy_decision', expectedActionDigest: digest,
      }); }).not.toThrow();
      expect(result).toMatchObject({ allow: false, action_digest: null });
    }
  });

  it('returns an exact fail-closed envelope when native input inspection throws', () => {
    const hostileChain = new Proxy({}, {
      get() { throw new Error('chain getter trap'); },
      getOwnPropertyDescriptor() { throw new Error('chain descriptor trap'); },
    });
    const refusal = (requirementSource) => ({
      allow: false,
      action_digest: null,
      expected_action_bound: false,
      components: [],
      reasons: ['unexpected verification error'],
      requirement_source: requirementSource,
    });

    expect(verifyAuthorizationChain(hostileChain, { requirement: 'policy_decision' }))
      .toEqual(refusal('relying_party'));
    for (const options of [
      null,
      7,
      { requirement: '' },
      { requirement: '   ' },
      { requirement: new String('policy_decision') },
      new Proxy({}, { get() { throw new Error('options getter trap'); } }),
    ]) {
      expect(verifyAuthorizationChain(hostileChain, options)).toEqual(refusal('presenter'));
    }
  });
});
