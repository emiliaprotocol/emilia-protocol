// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { runFormalChecks } from '../formal/check-outcome-authority-join.mjs';
import { evaluateFormalCase } from '../formal/outcome-authority-join.model.mjs';
import { runOutcomeAuthorityFormalGate } from '../scripts/check-outcome-authority-formal.mjs';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const suite = JSON.parse(fs.readFileSync(
  path.join(here, '..', 'formal', 'outcome-authority-join.cases.json'),
  'utf8',
));

describe(`bounded formal cases ${suite['@version']} (${suite.vectors.length} vectors)`, () => {
  for (const v of suite.vectors) {
    it(`formal case: ${v.id}`, () => {
      expect(evaluateFormalCase(v)).toBe(v.expect.valid);
    });
  }
});

it('all six load-bearing obligations hold in the bounded model', () => {
  const result = runFormalChecks();
  expect(result.verified).toBe(true);
  expect(Object.keys(result.obligations)).toEqual([
    'ExactActionReceiptBinding',
    'PolicyCannotWidenSignedPredictions',
    'ReplayResultDigestCommitsVerdict',
    'NewestAuthorityDocumentPreventsKeyResurrection',
    'RevokedRotationAndProofKeysFailClosed',
    'RegistryPinsMandatory',
  ]);
  for (const obligation of Object.values(result.obligations)) {
    expect(obligation.verified).toBe(true);
    expect(obligation.counterexample).toBe(null);
  }
});

it('every weakened invariant produces a counterexample', () => {
  const result = runFormalChecks();
  for (const obligation of Object.values(result.obligations)) {
    expect(obligation.mutation_counterexample).not.toBe(null);
  }
});

it('security claims preserve required exclusions and partial formal scope', () => {
  const result = runOutcomeAuthorityFormalGate();
  expect(result.verified).toBe(true);
  expect(result.claims).toHaveLength(2);
});
