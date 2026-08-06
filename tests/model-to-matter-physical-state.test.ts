// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  M2M_EVIDENCE_TYPES,
  createModelToMatterAction,
  createModelToMatterProfile,
  modelToMatterActionDigest,
  physicalStateMeasurementDigest,
  signModelToMatterEvidence,
  verifyModelToMatterEvidence,
} from '../lib/frontier/model-to-matter.js';

const NOW = '2026-07-11T16:00:00Z';
const MEASURED_AT = '2026-07-11T15:59:00Z';
const EXPIRES_AT = '2026-07-11T16:14:00Z';
const sensorKey = crypto.generateKeyPairSync('ed25519').privateKey;
const executorKey = crypto.generateKeyPairSync('ed25519').privateKey;

function digest(label) {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function publicKey(privateKey) {
  return crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
}

const action = createModelToMatterAction({
  action_type: 'science.bio.experiment.execute.1',
  model: {
    provider: 'example-frontier-lab',
    model_id: 'frontier-bio-model-2026-07',
    manifest_digest: digest('model-manifest'),
    harness_digest: digest('agent-harness'),
    safeguards_digest: digest('deployment-safeguards'),
  },
  experiment: {
    protocol_digest: digest('benign-protocol'),
    materials_commitment: digest('opaque-materials'),
    expected_effects_digest: digest('approved-effects'),
  },
  principal: {
    organization_id: 'org:example-university',
    principal_id: 'researcher:alice',
  },
  executor: {
    executor_id: 'cloud-lab:example',
    facility_id: 'facility:safe-demo-01',
  },
  purpose: { code: 'defensive-research', jurisdiction: 'US' },
  destination_digest: digest('approved-destination'),
  requested_at: '2026-07-11T15:58:00Z',
  max_executions: 1,
});

const physicalStatePolicy = Object.freeze({
  required_precondition_digest: digest('required-physical-preconditions'),
  max_measurement_age_sec: 120,
  max_validity_duration_sec: 900,
  executor_control_domain: 'control:cloud-lab:example',
  executor_public_keys: [publicKey(executorKey)],
});

const sensorPin = Object.freeze({
  issuer_id: 'issuer:physical_state_attestation',
  public_key: publicKey(sensorKey),
  sensor_network_id: 'sensor-network:facility-safe-demo-01',
  control_domain: 'control:independent-facility-sensors',
});

function physicalEvidence(overrides: any = {}) {
  return signModelToMatterEvidence({
    evidence_type: 'physical_state_attestation',
    action_digest: modelToMatterActionDigest(action),
    issuer_id: sensorPin.issuer_id,
    issued_at: overrides.issued_at ?? MEASURED_AT,
    expires_at: overrides.expires_at ?? EXPIRES_AT,
    claims: {
      sensor_network_id: sensorPin.sensor_network_id,
      required_precondition_digest: physicalStatePolicy.required_precondition_digest,
      measured_state_digest: digest('measured-room-state'),
      measured_at: MEASURED_AT,
      match: true,
      ...(overrides.claims ?? {}),
    },
  }, overrides.privateKey ?? sensorKey);
}

function verify(artifact, overrides: any = {}) {
  return verifyModelToMatterEvidence(artifact, {
    expectedType: 'physical_state_attestation',
    expectedAction: action,
    as_of: NOW,
    pinnedIssuerKeys: [sensorPin],
    physicalStatePolicy,
    retiredPhysicalMeasurementDigests: new Set(),
    ...overrides,
  });
}

describe('Model-to-Matter physical-state attestation', () => {
  it('adds a seventh required role and preserves the physical-truth boundary', () => {
    expect(M2M_EVIDENCE_TYPES).toContain('physical_state_attestation');
    const result = verify(physicalEvidence());
    expect(result).toMatchObject({
      verified: true,
      accepted: true,
      establishes_physical_truth: false,
      reason: null,
    });
    expect(result.measurement_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(result.limitation).toMatch(/signed claim.*not physical truth/i);
  });

  it('requires an independently controlled sensor key and control domain', () => {
    const acceptedIssuers = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, [
      type === 'physical_state_attestation'
        ? sensorPin
        : { issuer_id: `issuer:${type}`, public_key: publicKey(sensorKey) },
    ]]));
    const input = {
      profile_id: 'ep:m2m:physical-state:v1',
      accepted_issuers: acceptedIssuers,
      physical_state_policy: physicalStatePolicy,
    };
    expect(createModelToMatterProfile(input).physical_state_policy)
      .toEqual(physicalStatePolicy);

    const sameDomain = structuredClone(input);
    sameDomain.accepted_issuers.physical_state_attestation[0].control_domain =
      physicalStatePolicy.executor_control_domain;
    expect(() => createModelToMatterProfile(sameDomain)).toThrow(/control domain.*independent/i);

    const sameKey = structuredClone(input);
    sameKey.accepted_issuers.physical_state_attestation[0].public_key = publicKey(executorKey);
    expect(() => createModelToMatterProfile(sameKey)).toThrow(/key.*independent/i);
  });

  it('rejects mismatched identity, preconditions, measurements, and match verdicts', () => {
    const cases = [
      ['sensor_network_mismatch', { sensor_network_id: 'sensor-network:other' }],
      ['required_precondition_mismatch', { required_precondition_digest: digest('other-preconditions') }],
      ['physical_state_mismatch', { match: false }],
    ];
    for (const [reason, claims] of cases) {
      expect(verify(physicalEvidence({ claims })).reason).toBe(reason);
    }
    expect(() => physicalEvidence({ claims: { measured_state_digest: 'not-a-digest' } }))
      .toThrow(/measured_state_digest/i);
    expect(() => physicalEvidence({ claims: { measured_at: 'not-an-instant' } }))
      .toThrow(/measured_at/i);
  });

  it('enforces the signed window, measurement age, and relying-party duration ceiling', () => {
    expect(verify(physicalEvidence(), { as_of: EXPIRES_AT }).reason).toBe('expired');
    expect(verify(physicalEvidence({
      issued_at: '2026-07-11T15:57:59Z',
      expires_at: '2026-07-11T16:12:59Z',
      claims: { measured_at: '2026-07-11T15:57:59Z' },
    })).reason).toBe('measurement_stale');
    expect(verify(physicalEvidence({
      claims: { measured_at: '2026-07-11T16:00:01Z' },
    })).reason).toBe('measurement_not_yet_valid');
    expect(verify(physicalEvidence({
      expires_at: '2026-07-11T16:20:00Z',
    })).reason).toBe('measurement_validity_window_noncanonical');
    expect(verify(physicalEvidence({
      issued_at: '2026-07-11T15:59:01Z',
    })).reason).toBe('measurement_issuance_mismatch');
  });

  it('cannot renew a retired measurement by changing only its signed window', () => {
    const original = physicalEvidence();
    const renewed = physicalEvidence({
      issued_at: '2026-07-11T16:04:00Z',
      expires_at: '2026-07-11T16:14:00Z',
    });
    expect(physicalStateMeasurementDigest(renewed))
      .toBe(physicalStateMeasurementDigest(original));

    const measurementDigest = physicalStateMeasurementDigest(original);
    expect(verify(original, {
      retiredPhysicalMeasurementDigests: new Set([measurementDigest]),
    })).toMatchObject({
      verified: true,
      accepted: false,
      reason: 'measurement_reused',
      measurement_digest: measurementDigest,
    });
    const result = verify(renewed, {
      as_of: '2026-07-11T16:05:00Z',
      retiredPhysicalMeasurementDigests: new Set([measurementDigest]),
    });
    expect(result).toMatchObject({
      verified: true,
      accepted: false,
      reason: 'measurement_issuance_mismatch',
      establishes_physical_truth: false,
    });
  });
});
