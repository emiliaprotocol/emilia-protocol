// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { __modelToMatterSecurityInternals } from '../lib/frontier/model-to-matter.js';
import { artifactDigest } from '../lib/evidence/evidence-graph.js';
import { canonicalize } from '../packages/verify/index.js';

const digest = (hex) => `sha256:${hex.repeat(64)}`;
const action = {
  '@version': 'EP-MODEL-TO-MATTER-ACTION-v1',
  action_type: 'science.bio.experiment.execute.1',
  model: {
    provider: 'model-provider',
    model_id: 'model-1',
    manifest_digest: digest('1'),
    harness_digest: digest('2'),
    safeguards_digest: digest('3'),
  },
  experiment: {
    protocol_digest: digest('4'),
    materials_commitment: digest('5'),
    expected_effects_digest: digest('6'),
  },
  principal: { organization_id: 'org-1', principal_id: 'person-1' },
  executor: { executor_id: 'executor-1', facility_id: 'facility-1' },
  purpose: { code: 'defensive-research', jurisdiction: 'US' },
  destination_digest: digest('7'),
  requested_at: '2026-07-12T12:00:00.000Z',
  max_executions: 1,
};

const claims = {
  model_attestation: {
    provider: action.model.provider,
    model_id: action.model.model_id,
    manifest_digest: action.model.manifest_digest,
    harness_digest: action.model.harness_digest,
    safeguards_digest: action.model.safeguards_digest,
  },
  safety_case_attestation: {
    manifest_digest: action.model.manifest_digest,
    harness_digest: action.model.harness_digest,
    safeguards_digest: action.model.safeguards_digest,
    safety_case_digest: digest('8'),
    assessment: 'acceptable',
  },
  institutional_authority: {
    organization_id: action.principal.organization_id,
    principal_id: action.principal.principal_id,
    action_type: action.action_type,
    purpose_code: action.purpose.code,
    decision: 'allow',
  },
  biosafety_review: {
    protocol_digest: action.experiment.protocol_digest,
    materials_commitment: action.experiment.materials_commitment,
    facility_id: action.executor.facility_id,
    decision: 'approve',
  },
  domain_screening: {
    materials_commitment: action.experiment.materials_commitment,
    destination_digest: action.destination_digest,
    screening_profile_digest: digest('9'),
    decision: 'pass',
  },
  human_authorization: {
    approver_id: 'approver-1',
    decision: 'approve',
    assurance_class: 'class_a',
  },
  physical_state_attestation: {
    sensor_network_id: 'sensor-network-1',
    required_precondition_digest: digest('a'),
    measured_state_digest: digest('b'),
    measured_at: '2026-07-12T12:00:00.000Z',
    match: true,
  },
};

describe('Model-to-Matter mutation oracles', () => {
  const {
    isObject, validDigest, strictInstantMs, deepFreeze,
    claimsMatchAction, graphIsSafeToEvaluate, clearanceResult,
    requirementBindingRefusal, clearanceBinding, boundReplayDigest,
  } = __modelToMatterSecurityInternals;

  it('keeps Reliance Program action and validity boundaries exact', () => {
    const actionDigest = digest('a');
    const actionCaid = 'caid:example-action';
    const binding = {
      reliance_program_id: 'rp.example:v1',
      reliance_program_version: 1,
      reliance_program_source_digest: digest('b'),
      reliance_program_digest: digest('c'),
      evidence_requirement_digest: digest('d'),
      bound_action_digest: actionDigest,
      bound_action_caid: actionCaid,
      valid_from: '2026-07-12T11:00:00Z',
      expires_at: '2026-07-12T13:00:00Z',
    };

    expect(requirementBindingRefusal(null, actionDigest, actionCaid, 'invalid')).toBeNull();
    expect(requirementBindingRefusal(binding, digest('e'), actionCaid, '2026-07-12T12:00:00Z'))
      .toMatch(/different Model-to-Matter action/);
    expect(requirementBindingRefusal(binding, actionDigest, 'caid:other', '2026-07-12T12:00:00Z'))
      .toMatch(/different Model-to-Matter action/);
    expect(requirementBindingRefusal(binding, actionDigest, actionCaid)).toBeNull();

    for (const [label, candidate, asOf] of [
      ['invalid evaluation time', binding, 'not-an-instant'],
      ['invalid start', { ...binding, valid_from: 'not-an-instant' }, '2026-07-12T12:00:00Z'],
      ['invalid expiry', { ...binding, expires_at: 'not-an-instant' }, '2026-07-12T12:00:00Z'],
      ['before start', binding, '2026-07-12T10:59:59Z'],
      ['at expiry', binding, '2026-07-12T13:00:00Z'],
    ]) {
      expect(requirementBindingRefusal(candidate, actionDigest, actionCaid, asOf), label)
        .toMatch(/not active/);
    }
    expect(requirementBindingRefusal(binding, actionDigest, actionCaid, binding.valid_from)).toBeNull();
    expect(requirementBindingRefusal(binding, actionDigest, actionCaid, '2026-07-12T12:59:59.999Z')).toBeNull();
  });

  it('binds replay identity to the exact Reliance Program fields', () => {
    const replayDigest = digest('a');
    const binding = {
      reliance_program_id: 'rp.example:v1',
      reliance_program_version: 1,
      reliance_program_source_digest: digest('b'),
      reliance_program_digest: digest('c'),
      evidence_requirement_digest: digest('d'),
      bound_action_digest: digest('e'),
      bound_action_caid: 'caid:example-action',
      valid_from: '2026-07-12T11:00:00Z',
      expires_at: '2026-07-12T13:00:00Z',
    };
    const projected = {
      reliance_program_id: binding.reliance_program_id,
      reliance_program_version: binding.reliance_program_version,
      reliance_program_source_digest: binding.reliance_program_source_digest,
      reliance_program_digest: binding.reliance_program_digest,
      evidence_requirement_digest: binding.evidence_requirement_digest,
    };

    expect(clearanceBinding(null)).toEqual({});
    expect(clearanceBinding(binding)).toEqual(projected);
    expect(boundReplayDigest(replayDigest, null)).toBe(replayDigest);
    expect(boundReplayDigest('invalid', binding)).toBe('invalid');

    const expected = `sha256:${crypto.createHash('sha256').update(canonicalize({
      '@version': 'EP-MODEL-TO-MATTER-CLEARANCE-v1',
      evidence_replay_digest: replayDigest,
      ...projected,
    }), 'utf8').digest('hex')}`;
    expect(boundReplayDigest(replayDigest, binding)).toBe(expected);
    expect(boundReplayDigest(digest('f'), binding)).not.toBe(expected);
    expect(boundReplayDigest(replayDigest, { ...binding, reliance_program_id: 'rp.other:v1' }))
      .not.toBe(expected);
  });

  it('keeps object, digest, timestamp, and freeze boundaries exact', () => {
    expect(isObject({})).toBe(true);
    for (const value of [null, [], 'x', 1, true]) expect(isObject(value)).toBe(false);
    expect(validDigest(digest('a'))).toBe(true);
    for (const value of [null, '', `sha256:${'A'.repeat(64)}`, `sha256:${'a'.repeat(63)}`, 'a'.repeat(64)]) {
      expect(validDigest(value)).toBe(false);
    }
    expect(validDigest({ toString: () => digest('a') })).toBe(false);

    expect(strictInstantMs('2024-02-29T23:59:59Z')).toBe(Date.parse('2024-02-29T23:59:59Z'));
    expect(strictInstantMs('2026-01-01T00:00:00+23:59')).toBe(Date.parse('2026-01-01T00:00:00+23:59'));
    for (const value of [
      null, '', '2026-02-29T00:00:00Z', '2026-01-01T24:00:00Z',
      '2026-01-01T00:60:00Z', '2026-01-01T00:00:60Z',
      '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00+00:60',
    ]) expect(Number.isNaN(strictInstantMs(value))).toBe(true);

    const nested = { one: { two: [1] } };
    expect(deepFreeze(nested)).toBe(nested);
    expect(Object.isFrozen(nested)).toBe(true);
    expect(Object.isFrozen(nested.one)).toBe(true);
    expect(Object.isFrozen(nested.one.two)).toBe(true);
    const partiallyFrozen = Object.freeze({ child: { value: 1 } });
    deepFreeze(partiallyFrozen);
    expect(Object.isFrozen(partiallyFrozen.child)).toBe(true);
    expect(deepFreeze(null)).toBeNull();
    expect(deepFreeze('x')).toBe('x');
  });

  it('rejects every unsafe evidence-graph dimension independently', () => {
    const artifact = { value: 'signed-evidence-placeholder' };
    const node = {
      id: artifactDigest(artifact),
      type: 'domain_screening',
      artifact,
    };
    const safe = {
      '@version': 'EP-AEG-v1',
      action_digest: digest('a'),
      nodes: [node],
      edges: [],
    };
    expect(graphIsSafeToEvaluate(safe)).toBe(true);

    const unsafe = [
      null,
      { ...safe, '@version': 'EP-AEG-v0' },
      { ...safe, extra: true },
      { ...safe, action_digest: 'bad' },
      { ...safe, nodes: {} },
      { ...safe, edges: {} },
      { ...safe, edges: [{ from: 'a', to: 'b' }] },
      { ...safe, nodes: [null] },
      { ...safe, nodes: [{ ...node, extra: true }] },
      { ...safe, nodes: [{ ...node, id: digest('b') }] },
      { ...safe, nodes: [{ ...node, type: 'unknown' }] },
      { ...safe, nodes: [node, { ...node, id: artifactDigest({ value: 'other' }), artifact: { value: 'other' } }] },
      { ...safe, nodes: [{ ...node, artifact: null }] },
      { ...safe, nodes: [{ ...node, artifact: { value: 'tampered' } }] },
    ];
    for (const candidate of unsafe) expect(graphIsSafeToEvaluate(candidate)).toBe(false);
  });

  it('requires every load-bearing claim-to-action join independently', () => {
    for (const [type, value] of Object.entries(claims)) {
      expect(claimsMatchAction(type, value, action, 'class_a'), type).toBe(true);
    }

    const mismatches = {
      model_attestation: {
        provider: 'other', model_id: 'other', manifest_digest: digest('a'),
        harness_digest: digest('b'), safeguards_digest: digest('c'),
      },
      safety_case_attestation: {
        manifest_digest: digest('a'), harness_digest: digest('b'),
        safeguards_digest: digest('c'), safety_case_digest: 'bad', assessment: 'unacceptable',
      },
      institutional_authority: {
        organization_id: 'other', principal_id: 'other', action_type: 'other',
        purpose_code: 'other', decision: 'deny',
      },
      biosafety_review: {
        protocol_digest: digest('a'), materials_commitment: digest('b'),
        facility_id: 'other', decision: 'deny',
      },
      domain_screening: {
        materials_commitment: digest('a'), destination_digest: digest('b'),
        screening_profile_digest: 'bad', decision: 'fail',
      },
      human_authorization: {
        approver_id: '', decision: 'deny', assurance_class: 'software',
      },
      physical_state_attestation: {
        sensor_network_id: '', required_precondition_digest: 'bad',
        measured_state_digest: 'bad', measured_at: 'not-an-instant', match: 'true',
      },
    };
    for (const [type, fields] of Object.entries(mismatches)) {
      for (const [field, replacement] of Object.entries(fields)) {
        expect(claimsMatchAction(
          type,
          { ...claims[type], [field]: replacement },
          action,
          'class_a',
        ), `${type}.${field}`).toBe(false);
      }
    }
    expect(claimsMatchAction('human_authorization', {
      ...claims.human_authorization,
      assurance_class: 'quorum',
    }, action, 'class_a')).toBe(true);
    expect(claimsMatchAction('unknown', {}, action, 'class_a')).toBe(false);
    expect(claimsMatchAction('model_attestation', null, action, 'class_a')).toBe(false);
  });

  it('maps every clearance state to one exact closed verdict', () => {
    const expected = {
      admissible: 'clear_to_execute',
      missing_evidence: 'do_not_execute_missing_evidence',
      stale: 'do_not_execute_stale_evidence',
      conflicted: 'do_not_execute_conflicted',
      unverifiable: 'do_not_execute_unverifiable',
      refused: 'do_not_execute_refused',
      malformed: 'do_not_execute_malformed',
      unknown: 'do_not_execute_malformed',
    };
    for (const [base, verdict] of Object.entries(expected)) {
      expect(clearanceResult(base)).toEqual({
        '@version': 'EP-MODEL-TO-MATTER-CLEARANCE-v1',
        verdict,
        clear_to_execute: base === 'admissible',
        base_verdict: base,
        action_digest: null,
        action_caid: null,
        replay_digest: null,
        reliance_program_id: null,
        reliance_program_version: null,
        reliance_program_source_digest: null,
        reliance_program_digest: null,
        evidence_requirement_digest: null,
        reasons: [],
        next_challenge: null,
        reconciliation_required: false,
        graph: null,
      });
    }
    expect(clearanceResult('refused', {
      action_digest: digest('a'),
      action_caid: 'caid:1:science.bio.experiment.execute.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      replay_digest: digest('b'),
      reasons: ['reason'],
      next_challenge: { id: 'next' },
      reconciliation_required: true,
      result: { graph: { nodes: 6 } },
    })).toMatchObject({
      action_digest: digest('a'),
      action_caid: 'caid:1:science.bio.experiment.execute.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      replay_digest: digest('b'),
      reasons: ['reason'],
      next_challenge: { id: 'next' },
      reconciliation_required: true,
      graph: { nodes: 6 },
    });
  });
});
