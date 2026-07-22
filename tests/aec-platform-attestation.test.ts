// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  __aecSecurityInternals,
  actionDigest,
  verifyAuthorizationChain,
} from '../packages/verify/src/evidence-chain.ts';
import {
  EP_PLATFORM_ATTESTATION_COMPONENT,
  EP_PLATFORM_ATTESTATION_PROFILE,
  EP_PLATFORM_ATTESTATION_VERSION,
} from '../packages/verify/src/platform-attestation.ts';

const NOW = '2026-07-21T12:00:00Z';
const NOW_SECONDS = Date.parse(NOW) / 1000;
const ISSUER = 'https://attestation.example/verifiers/primary';
const AUDIENCE = 'https://gate.example/authorize';
const KEY_ID = 'platform-attester-2026-07';
const NONCE = 'R4ndomGateNonce-20260721';
const BUILD_MEASUREMENT = `sha256:${'b'.repeat(64)}`;
const ACTION = Object.freeze({
  action_type: 'payment.release',
  tenant_id: 'tenant-acme',
  amount_minor: 125_000,
  currency: 'USD',
  beneficiary: 'merchant-42',
});
const ACTION_DIGEST = `sha256:${actionDigest(ACTION)}`;

const signer = crypto.generateKeyPairSync('ed25519');
const substituteSigner = crypto.generateKeyPairSync('ed25519');
const PUBLIC_KEY = signer.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function makeEvidence({
  key = signer.privateKey,
  payloadOverrides = {},
}: {
  key?: crypto.KeyObject;
  payloadOverrides?: Record<string, unknown>;
} = {}) {
  const header = { alg: 'EdDSA', kid: KEY_ID, typ: 'eat+jwt' };
  const payload = {
    iss: ISSUER,
    aud: AUDIENCE,
    iat: NOW_SECONDS - 30,
    exp: NOW_SECONDS + 90,
    eat_nonce: NONCE,
    eat_profile: EP_PLATFORM_ATTESTATION_PROFILE,
    measres: [['ep-build', [[BUILD_MEASUREMENT, 'success']]]],
    ep_action_digest: ACTION_DIGEST,
    ...payloadOverrides,
  };
  const input = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = crypto.sign(null, Buffer.from(input, 'ascii'), key).toString('base64url');
  return {
    '@version': EP_PLATFORM_ATTESTATION_VERSION,
    token: `${input}.${signature}`,
  };
}

function context(overrides: Record<string, unknown> = {}) {
  return {
    requirement: EP_PLATFORM_ATTESTATION_COMPONENT,
    expectedAction: ACTION,
    verificationTime: NOW,
    keysByType: {
      [EP_PLATFORM_ATTESTATION_COMPONENT]: {
        [ISSUER]: { [KEY_ID]: PUBLIC_KEY },
      },
    },
    policiesByType: {
      [EP_PLATFORM_ATTESTATION_COMPONENT]: {
        expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
        expected_audience: AUDIENCE,
        expected_nonce: NONCE,
        reference_measurements: [BUILD_MEASUREMENT],
        max_age_sec: 120,
      },
    },
    ...overrides,
  };
}

function chain(evidence = makeEvidence()) {
  return {
    '@version': 'EP-AEC-v1',
    action: ACTION,
    components: [{ type: EP_PLATFORM_ATTESTATION_COMPONENT, evidence }],
    requirement: EP_PLATFORM_ATTESTATION_COMPONENT,
  };
}

const platformVerifier = __aecSecurityInternals.builtinVerifiers()[EP_PLATFORM_ATTESTATION_COMPONENT];

function verifierContext(overrides: Record<string, unknown> = {}) {
  const relyingParty = context(overrides);
  return {
    action: ACTION,
    verificationTime: relyingParty.verificationTime,
    keysByType: relyingParty.keysByType,
    policiesByType: relyingParty.policiesByType,
  };
}

describe('AEC platform-attestation mutation boundary', () => {
  it('accepts only the exact relying-party-pinned attestation for the exact action', () => {
    const result = verifyAuthorizationChain(chain(), context());
    expect(result.satisfied).toBe(true);
    expect(result.allow).toBe(true);
    expect(result.action_digest).toBe(ACTION_DIGEST.slice('sha256:'.length));
    expect(result.expected_action_bound).toBe(true);
    expect(result.components).toEqual([{
      type: EP_PLATFORM_ATTESTATION_COMPONENT,
      label: EP_PLATFORM_ATTESTATION_COMPONENT,
      valid: true,
      bound: true,
      reason: null,
    }]);

    const component = platformVerifier(makeEvidence(), verifierContext());
    expect(component.valid).toBe(true);
    expect(component.action_digest).toBe(ACTION_DIGEST);
    expect(component.detail).toMatchObject({
      reason: null,
      issuer: ISSUER,
      key_id: KEY_ID,
      build_measurement: BUILD_MEASUREMENT,
      profile: EP_PLATFORM_ATTESTATION_PROFILE,
    });
  });

  it('returns exact fail-closed reasons for missing policy and non-canonical actions', () => {
    expect(platformVerifier(makeEvidence(), undefined)).toEqual({
      valid: false,
      action_digest: null,
      detail: { reason: 'missing relying-party platform-attestation profile' },
    });
    expect(platformVerifier(makeEvidence(), {})).toEqual({
      valid: false,
      action_digest: null,
      detail: { reason: 'missing relying-party platform-attestation profile' },
    });
    expect(platformVerifier(makeEvidence(), verifierContext({
      policiesByType: { [EP_PLATFORM_ATTESTATION_COMPONENT]: {} },
    }))).toMatchObject({ valid: false, detail: { reason: 'relying_party_policy_invalid' } });

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(platformVerifier(makeEvidence(), {
      ...verifierContext(),
      action: cyclic,
    })).toEqual({
      valid: false,
      action_digest: null,
      detail: { reason: 'platform-attestation action is not canonicalizable' },
    });
  });

  it('maps every relying-party trust input into the verifier profile', () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ keysByType: {} }, 'relying_party_policy_invalid'],
      [{ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: 'urn:example:wrong-profile',
          expected_audience: AUDIENCE,
          expected_nonce: NONCE,
          reference_measurements: [BUILD_MEASUREMENT],
          max_age_sec: 120,
        },
      } }, 'relying_party_policy_invalid'],
      [{ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
          expected_audience: 'https://other.example/authorize',
          expected_nonce: NONCE,
          reference_measurements: [BUILD_MEASUREMENT],
          max_age_sec: 120,
        },
      } }, 'audience_mismatch'],
      [{ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
          expected_audience: AUDIENCE,
          expected_nonce: 'different-nonce',
          reference_measurements: [BUILD_MEASUREMENT],
          max_age_sec: 120,
        },
      } }, 'nonce_mismatch'],
      [{ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
          expected_audience: AUDIENCE,
          expected_nonce: NONCE,
          reference_measurements: [`sha256:${'c'.repeat(64)}`],
          max_age_sec: 120,
        },
      } }, 'measurement_untrusted'],
      [{ verificationTime: '2026-07-21T12:02:01Z' }, 'token_expired'],
      [{ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
          expected_audience: AUDIENCE,
          expected_nonce: NONCE,
          reference_measurements: [BUILD_MEASUREMENT],
          max_age_sec: 29,
        },
      } }, 'token_too_old'],
    ];

    for (const [overrides, reason] of cases) {
      expect(platformVerifier(makeEvidence(), verifierContext(overrides))).toMatchObject({
        valid: false,
        action_digest: null,
        detail: { reason },
      });
    }
  });

  it('fails closed when any relying-party attestation input is absent or wrong', () => {
    const wrongKey = substituteSigner.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const cases = [
      context({ policiesByType: {} }),
      context({ keysByType: {} }),
      context({ keysByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          [ISSUER]: { [KEY_ID]: wrongKey },
        },
      } }),
      context({ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: 'urn:example:wrong-profile',
          expected_audience: AUDIENCE,
          expected_nonce: NONCE,
          reference_measurements: [BUILD_MEASUREMENT],
          max_age_sec: 120,
        },
      } }),
      context({ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
          expected_audience: 'https://other.example/authorize',
          expected_nonce: NONCE,
          reference_measurements: [BUILD_MEASUREMENT],
          max_age_sec: 120,
        },
      } }),
      context({ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
          expected_audience: AUDIENCE,
          expected_nonce: 'different-nonce',
          reference_measurements: [BUILD_MEASUREMENT],
          max_age_sec: 120,
        },
      } }),
      context({ policiesByType: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: {
          expected_profile: EP_PLATFORM_ATTESTATION_PROFILE,
          expected_audience: AUDIENCE,
          expected_nonce: NONCE,
          reference_measurements: [`sha256:${'c'.repeat(64)}`],
          max_age_sec: 120,
        },
      } }),
      context({ verificationTime: '2026-07-21T12:02:01Z' }),
      context({ expectedAction: { ...ACTION, amount_minor: ACTION.amount_minor + 1 } }),
    ];

    for (const relyingPartyContext of cases) {
      const result = verifyAuthorizationChain(chain(), relyingPartyContext);
      expect(result.satisfied).toBe(false);
      expect(result.allow).toBe(false);
    }
  });

  it('does not allow presenter code or presenter keys to replace the built-in verifier', () => {
    const forged = makeEvidence({ key: substituteSigner.privateKey });
    const result = verifyAuthorizationChain(chain(forged), context({
      verifiers: {
        [EP_PLATFORM_ATTESTATION_COMPONENT]: () => ({
          valid: true,
          action_digest: ACTION_DIGEST,
        }),
      },
    }));
    expect(result.satisfied).toBe(false);
    expect(result.components[0]).toMatchObject({ valid: false, bound: false });
  });
});
