// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import {
  AUTHORITY_EVIDENCE_SOURCE_KINDS,
  authorityEvidenceObservationDigest,
  evaluateAuthorityEvidenceFreshness,
  validateAuthorityEvidenceObservation,
} from '../lib/works/authority-evidence-observation.ts';

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;

function observation(overrides: Record<string, unknown> = {}) {
  return {
    '@version': 'EMILIA-AUTHORITY-EVIDENCE-OBSERVATION-v1',
    observation_id: 'authority-evidence-acme-release',
    subject_id: 'authority-record-acme-agent',
    source: {
      kind: 'signed_release',
      locator: 'https://github.com/acme/agent/releases/tag/v1.2.3',
      watched_pointer: 'release-channel:stable',
      resolved_identifier: 'release:v1.2.3',
      artifact_digest: DIGEST_A,
      observed_at: '2026-08-14T18:00:00.000Z',
      expires_at: '2026-09-13T18:00:00.000Z',
    },
    collector: {
      name: '@emilia-protocol/scan',
      version: '0.2.0',
      profile_digest: DIGEST_B,
    },
    status: 'OBSERVED',
    status_reason: null,
    surface_ids: ['machine-command'],
    claim_boundary:
      'private_source_evidence_not_certification_not_safety_score_not_complete_mediation',
    ...overrides,
  };
}

describe('source-agnostic Authority Record evidence', () => {
  it('accepts every supported evidence source without changing the public v1 record schema', () => {
    expect(AUTHORITY_EVIDENCE_SOURCE_KINDS).toEqual([
      'repository_state',
      'signed_release',
      'build_provenance',
      'tool_schema',
      'deployment_manifest',
      'runtime_attestation',
      'observed_action_interface',
    ]);

    for (const kind of AUTHORITY_EVIDENCE_SOURCE_KINDS) {
      const candidate = observation();
      candidate.source.kind = kind;
      expect(validateAuthorityEvidenceObservation(candidate).ok, kind).toBe(true);
    }
  });

  it('requires immutable evidence bytes for OBSERVED and never accepts a score or verdict', () => {
    for (const mutation of [
      { field: 'artifact_digest', value: null },
      { field: 'resolved_identifier', value: null },
      { field: 'artifact_digest', value: 'moving-latest' },
    ]) {
      const candidate = observation();
      (candidate.source as any)[mutation.field] = mutation.value;
      expect(validateAuthorityEvidenceObservation(candidate).ok, mutation.field).toBe(false);
    }

    for (const extra of [
      { score: 98 },
      { verdict: 'SAFE' },
      { certification: 'EMILIA_APPROVED' },
    ]) {
      expect(validateAuthorityEvidenceObservation({ ...observation(), ...extra })).toMatchObject({
        ok: false,
        code: 'authority_evidence_unknown_field',
      });
    }
  });

  it('represents unavailable inspection as UNVERIFIABLE or INDETERMINATE, never as observed', () => {
    for (const status of ['UNVERIFIABLE', 'INDETERMINATE'] as const) {
      const candidate = observation({
        source: {
          ...observation().source,
          resolved_identifier: null,
          artifact_digest: null,
        },
        status,
        status_reason: status === 'UNVERIFIABLE'
          ? 'runtime_interface_not_exposed'
          : 'attestation_verifier_unavailable',
      });
      const parsed = validateAuthorityEvidenceObservation(candidate);
      expect(parsed.ok, status).toBe(true);
      if (!parsed.ok) continue;
      expect(parsed.observation.source.artifact_digest).toBeNull();
      expect(parsed.observation.status).toBe(status);
    }
  });

  it('rejects unknown nested fields and status-reason contradictions', () => {
    const nested = observation();
    (nested.source as any).raw_finding = 'unguarded endpoint';
    expect(validateAuthorityEvidenceObservation(nested)).toMatchObject({
      ok: false,
      code: 'authority_evidence_unknown_field',
    });

    expect(validateAuthorityEvidenceObservation(observation({
      status: 'OBSERVED',
      status_reason: 'this should not coexist with observed evidence',
    })).ok).toBe(false);
  });

  it('produces stable exact-byte digests and source-agnostic freshness outcomes', () => {
    const parsed = validateAuthorityEvidenceObservation(observation());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    expect(authorityEvidenceObservationDigest(parsed.observation)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(evaluateAuthorityEvidenceFreshness(parsed.observation, {
      kind: 'resolved', identifier: 'release:v1.2.3',
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'CURRENT',
      observed_identifier: 'release:v1.2.3',
      current_identifier: 'release:v1.2.3',
    });
    expect(evaluateAuthorityEvidenceFreshness(parsed.observation, {
      kind: 'resolved', identifier: 'release:v1.2.4',
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'STALE',
      observed_identifier: 'release:v1.2.3',
      current_identifier: 'release:v1.2.4',
    });
    expect(evaluateAuthorityEvidenceFreshness(parsed.observation, {
      kind: 'unavailable', reason: 'registry_rate_limited',
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'UNAVAILABLE', reason: 'registry_rate_limited',
    });
    expect(evaluateAuthorityEvidenceFreshness(parsed.observation, {
      kind: 'indeterminate', reason: 'ambiguous_release_pointer',
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'INDETERMINATE', reason: 'ambiguous_release_pointer',
    });
  });
});
