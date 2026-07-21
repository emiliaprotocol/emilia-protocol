// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { actionDigest, verifyAuthorizationChain } from './evidence-chain.js';
import {
  EP_PLATFORM_ATTESTATION_COMPONENT,
  EP_PLATFORM_ATTESTATION_PROFILE,
  EP_PLATFORM_ATTESTATION_VERSION,
  verifyPlatformAttestation,
} from './platform-attestation.js';

const NOW = '2026-07-21T12:00:00Z';
const NOW_SEC = Date.parse(NOW) / 1000;
const ISSUER = 'https://attestation.example/verifiers/primary';
const AUDIENCE = 'https://gate.example/authorize';
const KEY_ID = 'platform-attester-2026-07';
const NONCE = 'R4ndomGateNonce-20260721';
const BUILD_MEASUREMENT = `sha256:${'b'.repeat(64)}`;
const OTHER_MEASUREMENT = `sha256:${'c'.repeat(64)}`;
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
const here = dirname(fileURLToPath(import.meta.url));
const conformanceSuite = JSON.parse(readFileSync(
  resolve(here, '../../conformance/vectors/platform-attestation.v1.json'),
  'utf8',
));

type JwtHeader = { alg: string; kid: string; typ: string; [key: string]: unknown };
type JwtPayload = {
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  eat_nonce: string;
  eat_profile: string;
  measres: Array<[string, Array<[string, string]>]>;
  ep_action_digest: string;
  [key: string]: unknown;
};

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function signEncoded(headerSegment: string, payloadSegment: string, key = signer.privateKey): string {
  const input = `${headerSegment}.${payloadSegment}`;
  const signature = crypto.sign(null, Buffer.from(input, 'ascii'), key).toString('base64url');
  return `${input}.${signature}`;
}

function baseHeader(): JwtHeader {
  return { alg: 'EdDSA', kid: KEY_ID, typ: 'eat+jwt' };
}

function basePayload(): JwtPayload {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    iat: NOW_SEC - 30,
    exp: NOW_SEC + 90,
    eat_nonce: NONCE,
    eat_profile: EP_PLATFORM_ATTESTATION_PROFILE,
    measres: [['ep-build', [[BUILD_MEASUREMENT, 'success']]]],
    ep_action_digest: ACTION_DIGEST,
  };
}

function makeEvidence({
  mutateHeader,
  mutatePayload,
  key = signer.privateKey,
}: {
  mutateHeader?: (header: JwtHeader) => void;
  mutatePayload?: (payload: JwtPayload) => void;
  key?: crypto.KeyObject;
} = {}) {
  const header = baseHeader();
  const payload = basePayload();
  mutateHeader?.(header);
  mutatePayload?.(payload);
  return {
    '@version': EP_PLATFORM_ATTESTATION_VERSION,
    token: signEncoded(encodeJson(header), encodeJson(payload), key),
  };
}

function options(overrides: Record<string, unknown> = {}) {
  return {
    trustedAttesters: {
      [ISSUER]: {
        [KEY_ID]: PUBLIC_KEY,
      },
    },
    expectedProfile: EP_PLATFORM_ATTESTATION_PROFILE,
    expectedAudience: AUDIENCE,
    expectedNonce: NONCE,
    expectedActionDigest: ACTION_DIGEST,
    referenceMeasurements: [BUILD_MEASUREMENT],
    verificationTime: NOW,
    maxAgeSeconds: 120,
    ...overrides,
  };
}

function expectDenied(evidence: unknown, overrides: Record<string, unknown> = {}, reason?: string) {
  const result = verifyPlatformAttestation(evidence, options(overrides));
  assert.equal(result.valid, false);
  assert.equal(result.action_digest, null);
  if (reason) assert.equal(result.detail.reason, reason);
}

for (const v of conformanceSuite.vectors) {
  test(v.title, () => {
    assert.equal(typeof v.id, 'string');
    if (v.mutation === 'reserved_override') {
      const chain = {
        '@version': 'EP-AEC-v1',
        action: ACTION,
        components: [{
          type: EP_PLATFORM_ATTESTATION_COMPONENT,
          evidence: { '@version': EP_PLATFORM_ATTESTATION_VERSION, token: 'presenter-controlled' },
        }],
        requirement: EP_PLATFORM_ATTESTATION_COMPONENT,
      };
      const result = verifyAuthorizationChain(chain, {
        requirement: EP_PLATFORM_ATTESTATION_COMPONENT,
        expectedAction: ACTION,
        verifiers: {
          [EP_PLATFORM_ATTESTATION_COMPONENT]: () => ({ valid: true, action_digest: ACTION_DIGEST }),
        },
      });
      assert.equal(result.satisfied, v.expect.valid);
      assert.equal(result.components[0].reason, v.expect.reason);
      return;
    }

    const key = v.mutation === 'key_substitution'
      ? substituteSigner.privateKey
      : signer.privateKey;
    const mutatePayload = (payload: JwtPayload) => {
      switch (v.mutation) {
        case 'none': break;
        case 'nonce_mismatch': payload.eat_nonce = 'DifferentNonce-20260721'; break;
        case 'action_mismatch': payload.ep_action_digest = `sha256:${'d'.repeat(64)}`; break;
        case 'build_mismatch': payload.measres = [['ep-build', [[OTHER_MEASUREMENT, 'success']]]]; break;
        case 'expired': payload.exp = NOW_SEC - 1; break;
        case 'future_issued': payload.iat = NOW_SEC + 1; payload.exp = NOW_SEC + 60; break;
        case 'over_age': payload.iat = NOW_SEC - 121; break;
        case 'key_substitution': break;
        default: throw new Error(`unknown platform-attestation conformance mutation ${v.id}: ${v.mutation}`);
      }
    };
    const result = verifyPlatformAttestation(makeEvidence({ mutatePayload, key }), options());
    assert.equal(result.valid, v.expect.valid);
    assert.equal(result.detail.reason, v.expect.reason);
  });
}

test('accepts only the exact RP-pinned EAT/JWT platform-attestation result', () => {
  const result = verifyPlatformAttestation(makeEvidence(), options());
  assert.equal(result.valid, true, result.detail.reason);
  assert.equal(result.action_digest, ACTION_DIGEST);
  assert.equal(result.detail.profile, EP_PLATFORM_ATTESTATION_PROFILE);
  assert.equal(result.detail.issuer, ISSUER);
  assert.equal(result.detail.key_id, KEY_ID);
  assert.equal(result.detail.build_measurement, BUILD_MEASUREMENT);
  assert.equal(result.detail.profile_alignment, 'RFC9334-attestation-result/RFC9711-EAT-JWT');
  assert.equal(result.detail.hardware_verified, false);
});

test('is a non-overridable built-in AEC component bound to the chain action', () => {
  const aec = {
    '@version': 'EP-AEC-v1',
    action: ACTION,
    components: [{ type: EP_PLATFORM_ATTESTATION_COMPONENT, evidence: makeEvidence() }],
    requirement: EP_PLATFORM_ATTESTATION_COMPONENT,
  };
  const context = {
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
    // Reserved means a caller cannot replace the verifier with this accept-all stub.
    verifiers: {
      [EP_PLATFORM_ATTESTATION_COMPONENT]: () => ({ valid: true, action_digest: ACTION_DIGEST }),
    },
  };

  const accepted = verifyAuthorizationChain(aec, context);
  assert.equal(accepted.satisfied, true, accepted.reasons.join('; '));
  assert.equal(accepted.components[0].valid, true);
  assert.equal(accepted.components[0].bound, true);

  const wrongAction = verifyAuthorizationChain(aec, {
    ...context,
    expectedAction: { ...ACTION, amount_minor: ACTION.amount_minor + 1 },
  });
  assert.equal(wrongAction.satisfied, false);
});

test('rejects key substitution and never consumes presenter-supplied trust anchors', () => {
  expectDenied(makeEvidence({ key: substituteSigner.privateKey }), {}, 'signature_invalid');

  const attackerKey = substituteSigner.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  expectDenied({
    ...makeEvidence(),
    public_key: attackerKey,
  }, {}, 'evidence_shape_invalid');
});

test('rejects nonce, action, build measurement, profile, and audience mismatches', () => {
  const cases: Array<[string, (payload: JwtPayload) => void, string]> = [
    ['nonce', (payload) => { payload.eat_nonce = 'DifferentNonce-20260721'; }, 'nonce_mismatch'],
    ['action', (payload) => { payload.ep_action_digest = `sha256:${'d'.repeat(64)}`; }, 'action_digest_mismatch'],
    ['build', (payload) => { payload.measres = [['ep-build', [[OTHER_MEASUREMENT, 'success']]]]; }, 'measurement_untrusted'],
    ['profile', (payload) => { payload.eat_profile = 'urn:example:other-eat-profile'; }, 'profile_mismatch'],
    ['audience', (payload) => { payload.aud = 'https://attacker.example'; }, 'audience_mismatch'],
  ];
  for (const [name, mutatePayload, reason] of cases) {
    expectDenied(makeEvidence({ mutatePayload }), {}, reason);
    assert.ok(name);
  }

  expectDenied(makeEvidence(), { expectedProfile: 'urn:example:other-eat-profile' }, 'relying_party_policy_invalid');
  expectDenied(makeEvidence(), { referenceMeasurements: [OTHER_MEASUREMENT] }, 'measurement_untrusted');
});

test('rejects expired, future-issued, over-age, and malformed freshness claims', () => {
  expectDenied(makeEvidence({
    mutatePayload(payload) { payload.exp = NOW_SEC - 1; },
  }), {}, 'token_expired');
  expectDenied(makeEvidence({
    mutatePayload(payload) { payload.iat = NOW_SEC + 1; payload.exp = NOW_SEC + 60; },
  }), {}, 'token_from_future');
  expectDenied(makeEvidence({
    mutatePayload(payload) { payload.iat = NOW_SEC - 121; },
  }), {}, 'token_too_old');
  expectDenied(makeEvidence({
    mutatePayload(payload) { payload.iat = 1.5; },
  }), {}, 'time_claims_invalid');
  expectDenied(makeEvidence(), { maxAgeSeconds: Number.MAX_VALUE }, 'relying_party_policy_invalid');
  expectDenied(makeEvidence(), { maxAgeSeconds: 86_401 }, 'relying_party_policy_invalid');
});

test('rejects algorithm confusion, malformed keys, and non-success measurement results', () => {
  expectDenied(makeEvidence({
    mutateHeader(header) { header.alg = 'HS256'; },
  }), {}, 'protected_header_invalid');
  expectDenied(makeEvidence(), {
    trustedAttesters: { [ISSUER]: { [KEY_ID]: Buffer.from('not a key').toString('base64url') } },
  }, 'attester_key_invalid');
  expectDenied(makeEvidence({
    mutatePayload(payload) { payload.measres = [['ep-build', [[BUILD_MEASUREMENT, 'fail']]]]; },
  }), {}, 'measurement_result_invalid');
});

test('rejects duplicate JSON members before interpretation and all unknown fields', () => {
  const header = baseHeader();
  const payload = basePayload();
  const duplicatePayloadText = JSON.stringify(payload).replace(
    `"iss":"${ISSUER}"`,
    `"iss":"${ISSUER}","iss":"${ISSUER}"`,
  );
  const duplicatePayloadToken = signEncoded(
    encodeJson(header),
    Buffer.from(duplicatePayloadText, 'utf8').toString('base64url'),
  );
  expectDenied({ '@version': EP_PLATFORM_ATTESTATION_VERSION, token: duplicatePayloadToken }, {}, 'payload_json_invalid');

  const duplicateHeaderText = `{"alg":"EdDSA","alg":"EdDSA","kid":"${KEY_ID}","typ":"eat+jwt"}`;
  const duplicateHeaderToken = signEncoded(
    Buffer.from(duplicateHeaderText, 'utf8').toString('base64url'),
    encodeJson(payload),
  );
  expectDenied({ '@version': EP_PLATFORM_ATTESTATION_VERSION, token: duplicateHeaderToken }, {}, 'protected_header_json_invalid');

  expectDenied(makeEvidence({
    mutateHeader(value) { value.extra = true; },
  }), {}, 'protected_header_invalid');
  expectDenied(makeEvidence({
    mutatePayload(value) { value.extra = true; },
  }), {}, 'payload_shape_invalid');
});
