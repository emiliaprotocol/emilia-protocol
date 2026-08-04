// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import { describe, expect, test } from 'vitest';
import {
  buildCpbCaidAebVector,
  evaluateCpbCaidAebComposition,
} from '../examples/scitt/cpb-caid-aeb-cross-vector.mjs';

describe('CPB typed reference -> CAID -> AEB composition', () => {
  test('keeps the checked-in vector synchronized with the generator', () => {
    const checkedIn = JSON.parse(fs.readFileSync(
      new URL('../examples/scitt/cpb-caid-aeb-cross-vector.v1.json', import.meta.url),
      'utf8',
    ));
    expect(checkedIn).toEqual(buildCpbCaidAebVector());
  });

  test('verifies the CPB content binding without promoting it to authorization', () => {
    const vector: any = buildCpbCaidAebVector();
    const result: any = evaluateCpbCaidAebComposition(vector);

    expect(result).toMatchObject({
      cpb_binding: 'VERIFIED',
      caid_match: 'MATCH',
      aeb_evidence_satisfaction: 'SATISFIED',
      execution_authorization: 'NOT_EVALUATED',
    });
  });

  test('returns INDETERMINATE when equal digest text is presented under another context', () => {
    const vector: any = buildCpbCaidAebVector();
    vector.registry['caid-action-object'] = {
      ...vector.registry['caid-action-object'],
      canonicalization: 'raw-json',
    };

    const result: any = evaluateCpbCaidAebComposition(vector);

    expect(result.cpb_binding).toBe('INDETERMINATE');
    expect(result.caid_match).toBe('MATCH');
    expect(result.aeb_evidence_satisfaction).toBe('INDETERMINATE');
    expect(result.reasons).toContain('digest_context_unresolved');
  });

  test('returns INDETERMINATE for bare digest equality without a typed registry entry', () => {
    const vector: any = buildCpbCaidAebVector();
    vector.reference = {
      digest_alg: vector.reference.digest_alg,
      digest: vector.reference.digest,
    };

    const result: any = evaluateCpbCaidAebComposition(vector);

    expect(result.cpb_binding).toBe('INDETERMINATE');
    expect(result.aeb_evidence_satisfaction).toBe('INDETERMINATE');
    expect(result.reasons).toContain('typed_reference_required');
  });

  test('refuses a substituted material action', () => {
    const vector: any = buildCpbCaidAebVector();
    vector.artifact = { ...vector.artifact, amount: '75001.00' };

    const result: any = evaluateCpbCaidAebComposition(vector);

    expect(result.cpb_binding).toBe('FAILED');
    expect(result.caid_match).toBe('MISMATCH');
    expect(result.aeb_evidence_satisfaction).toBe('UNSATISFIED');
    expect(result.execution_authorization).toBe('NOT_EVALUATED');
  });
});
