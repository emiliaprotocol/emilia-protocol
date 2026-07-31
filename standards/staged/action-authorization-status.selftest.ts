// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  ACTION_AUTHORIZATION_STATUS_VERSION,
  authorizationStatusDigest,
  validateActionAuthorizationStatus,
} from './action-authorization-status.reference.js';
import type { ActionAuthorizationStatusRecord } from './action-authorization-status.reference.js';

function validRecord(): ActionAuthorizationStatusRecord {
  return {
    '@version': ACTION_AUTHORIZATION_STATUS_VERSION,
    action: {
      reference: {
        scheme: 'caid',
        value: 'caid:1:example:release-payment',
      },
      type: 'payment.release',
      occurred_at: '2026-07-30T18:00:00Z',
    },
    boundary: {
      id: 'gate:production',
      role: 'provider_gateway',
    },
    classification: {
      requirement: 'exact_action',
      authority: 'valid',
      binding: 'exact_action',
      admission: 'admitted',
      effect: 'executed',
    },
    evidence: {
      class: 'E4_OFFLINE_PINNED_VERIFIABLE',
      as_of: '2026-07-30T18:05:00Z',
      population_basis: 'single_action',
      source_systems: ['gate:production'],
      verification_profile: {
        id: 'ep-verify:3.14.0',
        digest: `sha256:${'c'.repeat(64)}`,
      },
      artifacts: [
        {
          type: 'authorization-receipt',
          digest: `sha256:${'a'.repeat(64)}`,
          verification: 'verified',
        },
      ],
      limitations: [
        'This classification does not establish causation, legal liability, or population completeness.',
      ],
    },
    classified_at: '2026-07-30T18:06:00Z',
    classifier: {
      id: 'adjuster:example',
      method: 'mixed',
      ruleset_digest: `sha256:${'b'.repeat(64)}`,
    },
  };
}

describe('ACTION-AUTHORIZATION-STATUS-v1', () => {
  it('accepts a closed exact-action classification with pinned verification evidence', () => {
    const result = validateActionAuthorizationStatus(validRecord());
    assert.equal(result.valid, true);
    assert.deepEqual(result.errors, []);
    assert.match(result.digest ?? '', /^sha256:[0-9a-f]{64}$/);
  });

  it('derives the same digest regardless of object key insertion order', () => {
    const first = validRecord();
    const second = {
      classifier: first.classifier,
      classified_at: first.classified_at,
      evidence: first.evidence,
      classification: first.classification,
      boundary: first.boundary,
      action: first.action,
      '@version': first['@version'],
    };
    assert.equal(authorizationStatusDigest(first), authorizationStatusDigest(second));
  });

  it('rejects unknown members and hidden non-JSON surfaces', () => {
    const unknown = { ...validRecord(), vendor_score: 99 };
    assert.equal(validateActionAuthorizationStatus(unknown).valid, false);

    const hidden = validRecord();
    Object.defineProperty(hidden, Symbol('hidden'), { value: 'exfiltrate', enumerable: false });
    assert.ok(validateActionAuthorizationStatus(hidden).errors.includes('record_outside_strict_json_domain'));
  });

  it('preserves refused-plus-executed as evidence of bypass or failed mediation', () => {
    const record = validRecord();
    record.classification.admission = 'refused';
    record.evidence.limitations = [
      'The named boundary refused the action, but the effect was observed through an unmediated or different path.',
    ];
    assert.equal(validateActionAuthorizationStatus(record).valid, true);
  });

  it('does not let a no-requirement record imply evaluated authority or action binding', () => {
    const record = validRecord();
    record.classification = {
      requirement: 'none',
      authority: 'valid',
      binding: 'exact_action',
      admission: 'admitted',
      effect: 'executed',
    };
    const errors = validateActionAuthorizationStatus(record).errors;
    assert.ok(errors.includes('no_requirement_requires_authority_not_evaluated'));
    assert.ok(errors.includes('no_requirement_requires_binding_not_evaluated'));
  });

  it('keeps an unknown requirement from being promoted into a positive authorization claim', () => {
    const record = validRecord();
    record.classification = {
      requirement: 'unknown',
      authority: 'valid',
      binding: 'exact_action',
      admission: 'admitted',
      effect: 'executed',
    };
    const errors = validateActionAuthorizationStatus(record).errors;
    assert.ok(errors.includes('unknown_requirement_requires_indeterminate_authority'));
    assert.ok(errors.includes('unknown_requirement_requires_indeterminate_binding'));
    assert.ok(!errors.includes('unknown_requirement_cannot_claim_admission'));
  });

  it('requires evidence for every class above E0 and forbids laundering evidence into E0', () => {
    const missing = validRecord();
    missing.evidence.artifacts = [];
    assert.ok(validateActionAuthorizationStatus(missing).errors.includes('evidence_class_requires_artifact'));

    const laundered = validRecord();
    laundered.evidence.class = 'E0_NONE';
    assert.ok(validateActionAuthorizationStatus(laundered).errors.includes('e0_forbids_artifacts'));
  });

  it('requires E4 evidence to contain a successfully verified artifact', () => {
    const record = validRecord();
    record.evidence.artifacts[0].verification = 'not_checked';
    assert.ok(validateActionAuthorizationStatus(record).errors.includes('signed_class_requires_verified_artifact'));
  });

  it('requires E4 and E5 to bind the verification profile used', () => {
    const record = validRecord();
    record.evidence.verification_profile = null;
    assert.ok(validateActionAuthorizationStatus(record).errors.includes('verified_class_requires_verification_profile'));
  });

  it('does not promote an unchecked signed artifact into E3 evidence', () => {
    const record = validRecord();
    record.evidence.class = 'E3_ACTION_BOUND_SIGNED';
    record.evidence.verification_profile = null;
    record.evidence.artifacts[0].verification = 'not_checked';
    assert.ok(validateActionAuthorizationStatus(record).errors.includes('signed_class_requires_verified_artifact'));
  });

  it('limits E5 to reconciliation against named systems and refuses an empty source set', () => {
    const record = validRecord();
    record.evidence.class = 'E5_RECONCILED_NAMED_POPULATION';
    record.evidence.population_basis = 'declared_population';
    record.evidence.source_systems = [];
    const errors = validateActionAuthorizationStatus(record).errors;
    assert.ok(errors.includes('e5_requires_reconciled_population_basis'));
    assert.ok(errors.includes('e5_requires_named_source_systems'));
  });

  it('rejects malformed time ordering and non-canonical digests', () => {
    const record = validRecord();
    record.action.occurred_at = '2026-07-30T18:10:00Z';
    record.evidence.artifacts[0].digest = 'SHA256:ABC';
    const errors = validateActionAuthorizationStatus(record).errors;
    assert.ok(errors.includes('evidence_precedes_action'));
    assert.ok(errors.includes('invalid_artifact_digest'));
  });

  it('matches the language-neutral conformance vectors', () => {
    const suite = JSON.parse(readFileSync(
      new URL('./action-authorization-status.v1.vectors.json', import.meta.url),
      'utf8',
    ));
    for (const vector of suite.vectors) {
      const result = validateActionAuthorizationStatus(vector.record);
      assert.equal(result.valid, vector.expect.valid, vector.id);
      for (const expectedError of vector.expect.errors ?? []) {
        assert.ok(result.errors.includes(expectedError), `${vector.id}: missing ${expectedError}`);
      }
    }
  });
});
