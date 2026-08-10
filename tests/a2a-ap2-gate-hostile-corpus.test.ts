// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

const schema = JSON.parse(readFileSync(
  new URL('../conformance/schemas/a2a-ap2-gate-hostile.v1.schema.json', import.meta.url),
  'utf8',
));
const corpus = JSON.parse(readFileSync(
  new URL('../conformance/vectors/a2a-ap2-gate-hostile.v1.json', import.meta.url),
  'utf8',
));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

describe('A2A/AP2 Gate hostile corpus', () => {
  it('validates the closed public catalog and names every executable hostile case', () => {
    expect(corpus.schema_ref).toBe(schema.$id);
    expect(validate(corpus), JSON.stringify(validate.errors, null, 2)).toBe(true);
    expect(corpus.vectors.map((vector: { id: string }) => vector.id)).toEqual([
      'native_ap2_admit',
      'approve_a_execute_b',
      'concurrent_admission',
      'replay_under_another_task',
      'revoked_or_malicious_as_evidence',
      'provider_timeout',
    ]);
  });

  it('does not claim an independent reproduction before one exists', () => {
    expect(corpus.claim_scope.status).toBe('same-team-reference-only');
    expect(corpus.external_reproductions).toEqual([]);
  });
});
