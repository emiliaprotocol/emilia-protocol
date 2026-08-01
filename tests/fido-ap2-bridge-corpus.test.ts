// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

const schema = JSON.parse(readFileSync(
  new URL(
    '../conformance/schemas/fido-ap2-bridge-semantic-corpus.v1.schema.json',
    import.meta.url,
  ),
  'utf8',
));
const corpus = JSON.parse(readFileSync(
  new URL('../conformance/vectors/fido-ap2-bridge.v1.json', import.meta.url),
  'utf8',
));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

describe('FIDO AP2 bridge semantic corpus schema', () => {
  it('validates the closed public corpus against its independently stored schema', () => {
    expect(corpus.schema_ref).toBe(schema.$id);
    expect(validate(corpus), JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it('refuses undeclared corpus members', () => {
    const mutated = structuredClone(corpus);
    mutated.unreviewed_claim = true;
    expect(validate(mutated)).toBe(false);
  });
});
