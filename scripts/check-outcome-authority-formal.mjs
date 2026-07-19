#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runFormalChecks } from '../formal/check-outcome-authority-join.mjs';
import { evaluateFormalCase } from '../formal/outcome-authority-join.model.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLAIMS_PATH = path.join(ROOT, 'security', 'claims.v1.json');
const CASES_PATH = path.join(ROOT, 'formal', 'outcome-authority-join.cases.json');
const CLAIM_IDS = Object.freeze([
  'outcome-binding-is-exact-and-fail-closed',
  'authority-document-proof-join-is-pinned-and-non-resurrecting',
]);
const REQUIRED_EXCLUSIONS = Object.freeze([
  'physical truth',
  'trusted time source',
  'external witness',
  'independent implementation',
]);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

export function runOutcomeAuthorityFormalGate() {
  const formal = runFormalChecks();
  requireCondition(formal.verified, 'bounded formal obligations did not all verify');
  for (const [name, result] of Object.entries(formal.obligations)) {
    requireCondition(result.verified, `${name} failed`);
    requireCondition(
      result.mutation_counterexample,
      `${name} has no mutation counterexample and may be vacuous`,
    );
  }

  const cases = JSON.parse(fs.readFileSync(CASES_PATH, 'utf8'));
  for (const vector of cases.vectors ?? []) {
    const actual = evaluateFormalCase(vector);
    requireCondition(
      actual === vector.expect?.valid,
      `${vector.id}: model returned ${actual}; expected ${vector.expect?.valid}`,
    );
  }

  const source = JSON.parse(fs.readFileSync(CLAIMS_PATH, 'utf8'));
  for (const claimId of CLAIM_IDS) {
    const claim = source.claims?.find((candidate) => candidate.claim_id === claimId);
    requireCondition(claim, `missing security claim ${claimId}`);
    const exclusions = (claim.exclusions ?? []).join(' ').toLowerCase();
    for (const required of REQUIRED_EXCLUSIONS) {
      requireCondition(
        exclusions.includes(required),
        `${claimId} must explicitly exclude ${required}`,
      );
    }
    const bounded = (claim.formal ?? []).find(
      (entry) => entry.method === 'bounded_exhaustive_state_exploration',
    );
    requireCondition(bounded?.status === 'partial', `${claimId} must mark bounded formal scope partial`);
    requireCondition(
      Array.isArray(bounded.obligations) && bounded.obligations.length > 0,
      `${claimId} must name exact bounded formal obligations`,
    );
  }

  return {
    verified: true,
    claims: CLAIM_IDS,
    vectors: cases.vectors.length,
    formal,
  };
}

const invokedAsScript = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  try {
    const result = runOutcomeAuthorityFormalGate();
    console.log(
      `OUTCOME/AUTHORITY FORMAL GATE: PASS `
      + `(${Object.keys(result.formal.obligations).length} obligations, `
      + `${result.vectors} model vectors, ${result.claims.length} claims)`,
    );
  } catch (error) {
    console.error(`OUTCOME/AUTHORITY FORMAL GATE: FAIL\n${error.message}`);
    process.exitCode = 1;
  }
}
