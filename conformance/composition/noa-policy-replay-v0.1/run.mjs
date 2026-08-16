// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { evaluateAdmissibility } from '../../../lib/evidence/admissibility.js';
import { canonicalizeStrictJson } from '../../../packages/verify/strict-json.js';

export const EVALUATOR_PROFILE_ID = 'ep-admissibility-noa-replay/0.1';
const POLICY_VERSION = 'EP-ADMISSIBILITY-POLICY-v1';
const INPUT_VERSION = 'NOA-POLICY-REPLAY-INPUT-v0.1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;

const POLICY_KEYS = Object.freeze([
  '@version',
  'policy_id',
  'reliance_purpose',
  'requirement',
  'freshness_sec',
  'revocation_required',
  'require_action_agreement',
]);
const INPUT_KEYS = Object.freeze(['@version', 'as_of', 'bundle']);
const BUNDLE_KEYS = Object.freeze(['action_digest', 'components']);
const COMPONENT_KEYS = Object.freeze([
  'type',
  'verified',
  'action_digest',
  'issued_at',
  'outcome',
  'revoked',
]);
const COMMITMENT_KEYS = Object.freeze(['policyHash', 'readSetHash', 'inputsHash', 'verdict']);

function plain(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  if (!plain(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0 && value === value.normalize('NFC');
}

function validInstant(value) {
  if (!nonEmptyString(value)) return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, zone] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]
      || hour > 23 || minute > 59 || second > 59) return false;
  if (zone !== 'Z') {
    const offsetHour = Number(zone.slice(1, 3));
    const offsetMinute = Number(zone.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) return false;
  }
  return !Number.isNaN(Date.parse(value));
}

function validRequirement(source) {
  if (!nonEmptyString(source)) return false;
  const tokens = source.match(/\(|\)|AND|OR|[a-zA-Z0-9_]+/g) || [];
  if (tokens.join('') !== source.replace(/\s+/g, '')) return false;
  let cursor = 0;
  const peek = () => tokens[cursor];
  const consume = () => tokens[cursor++];
  const atom = () => {
    const token = consume();
    if (token === '(') {
      if (!orExpression() || consume() !== ')') return false;
      return true;
    }
    return typeof token === 'string' && token !== 'AND' && token !== 'OR' && token !== ')';
  };
  const andExpression = () => {
    if (!atom()) return false;
    while (peek() === 'AND') {
      consume();
      if (!atom()) return false;
    }
    return true;
  };
  function orExpression() {
    if (!andExpression()) return false;
    while (peek() === 'OR') {
      consume();
      if (!andExpression()) return false;
    }
    return true;
  }
  return orExpression() && cursor === tokens.length;
}

function validatePolicy(policy) {
  if (!exactKeys(policy, POLICY_KEYS)) return 'policy_shape_invalid';
  if (policy['@version'] !== POLICY_VERSION) return 'policy_version_unsupported';
  if (!nonEmptyString(policy.policy_id)
      || !nonEmptyString(policy.reliance_purpose)) return 'policy_identifier_invalid';
  if (!validRequirement(policy.requirement)) return 'policy_requirement_invalid';
  if (!plain(policy.freshness_sec)
      || Object.entries(policy.freshness_sec).some(([key, value]) => (
        !nonEmptyString(key) || !Number.isSafeInteger(value) || value < 0
      ))) return 'policy_freshness_invalid';
  if (!Array.isArray(policy.revocation_required)
      || policy.revocation_required.some((value) => !nonEmptyString(value))
      || new Set(policy.revocation_required).size !== policy.revocation_required.length) {
    return 'policy_revocation_set_invalid';
  }
  if (typeof policy.require_action_agreement !== 'boolean') return 'policy_action_agreement_invalid';
  try {
    canonicalizeStrictJson(policy);
  } catch {
    return 'policy_outside_canonical_json_domain';
  }
  return null;
}

function validateInputs(inputs) {
  if (!exactKeys(inputs, INPUT_KEYS)) return 'inputs_shape_invalid';
  if (inputs['@version'] !== INPUT_VERSION) return 'inputs_version_unsupported';
  if (!validInstant(inputs.as_of)) return 'inputs_as_of_invalid';
  if (!exactKeys(inputs.bundle, BUNDLE_KEYS) || !DIGEST.test(inputs.bundle.action_digest)) {
    return 'inputs_bundle_invalid';
  }
  if (!Array.isArray(inputs.bundle.components) || inputs.bundle.components.length === 0) {
    return 'inputs_components_invalid';
  }
  for (const component of inputs.bundle.components) {
    if (!exactKeys(component, COMPONENT_KEYS)
        || !nonEmptyString(component.type)
        || typeof component.verified !== 'boolean'
        || !(component.action_digest === null || DIGEST.test(component.action_digest))
        || !(component.issued_at === null || validInstant(component.issued_at))
        || !(component.outcome === null || ['allow', 'deny', 'denied', 'refused'].includes(component.outcome))
        || typeof component.revoked !== 'boolean') return 'inputs_component_invalid';
  }
  try {
    canonicalizeStrictJson(inputs);
  } catch {
    return 'inputs_outside_canonical_json_domain';
  }
  return null;
}

function validatePolicyInputs(policy, inputs) {
  const asOf = Date.parse(inputs.as_of);
  for (const component of inputs.bundle.components) {
    const freshnessRequired = Object.prototype.hasOwnProperty.call(policy.freshness_sec, component.type);
    if (freshnessRequired && component.issued_at === null) return 'inputs_freshness_unprovable';
    if (component.issued_at !== null && Date.parse(component.issued_at) > asOf) {
      return 'inputs_freshness_unprovable';
    }
  }
  return null;
}

function digest(value) {
  const bytes = canonicalizeStrictJson(value);
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function deriveReadSet(policy) {
  const invalid = validatePolicy(policy);
  if (invalid) throw new TypeError(invalid);

  const paths = new Set([
    'bundle.components[].outcome',
    'bundle.components[].type',
    'bundle.components[].verified',
  ]);
  if (policy.require_action_agreement) {
    paths.add('bundle.action_digest');
    paths.add('bundle.components[].action_digest');
  }
  if (Object.keys(policy.freshness_sec).length > 0) {
    paths.add('as_of');
    paths.add('bundle.components[].issued_at');
  }
  if (policy.revocation_required.length > 0) paths.add('bundle.components[].revoked');
  return [...paths].sort();
}

function runEvaluator(policy, inputs) {
  const evaluation = evaluateAdmissibility(inputs.bundle, policy, { as_of: inputs.as_of });
  const verdict = evaluation.verdict === 'admissible' ? 'ALLOW' : 'DENY';
  return { verdict, classified_verdict: evaluation.verdict };
}

function checkProfile(evaluatorProfile) {
  return evaluatorProfile === EVALUATOR_PROFILE_ID;
}

export function buildCommitment(policy, inputs, evaluatorProfile = EVALUATOR_PROFILE_ID) {
  if (!checkProfile(evaluatorProfile)) throw new TypeError('evaluator_profile_unavailable');
  const policyError = validatePolicy(policy);
  if (policyError) throw new TypeError(policyError);
  const inputError = validateInputs(inputs);
  if (inputError) throw new TypeError(inputError);
  const joinedError = validatePolicyInputs(policy, inputs);
  if (joinedError) throw new TypeError(joinedError);
  const evaluated = runEvaluator(policy, inputs);
  return {
    policyHash: digest(policy),
    readSetHash: digest(deriveReadSet(policy)),
    inputsHash: digest(inputs),
    verdict: evaluated.verdict,
  };
}

/**
 * @param {string} status
 * @param {string | null} reason
 * @param {string | null} [derivedVerdict]
 * @param {string | null} [classifiedVerdict]
 */
function result(status, reason, derivedVerdict = null, classifiedVerdict = null) {
  return {
    status,
    reason,
    derived_verdict: derivedVerdict,
    classified_verdict: classifiedVerdict,
  };
}

export function verifyReplay({ commitment, policy, inputs, evaluatorProfile }) {
  if (!checkProfile(evaluatorProfile)) {
    return result('UNRESOLVED', 'evaluator_profile_unavailable');
  }
  if (policy === null || policy === undefined) return result('UNRESOLVED', 'policy_unavailable');
  if (inputs === null || inputs === undefined) return result('UNRESOLVED', 'inputs_unavailable');
  if (commitment === null || commitment === undefined) return result('UNRESOLVED', 'commitment_unavailable');

  const policyError = validatePolicy(policy);
  if (policyError) return result('UNRESOLVED', policyError);
  const inputError = validateInputs(inputs);
  if (inputError) return result('UNRESOLVED', inputError);
  const joinedError = validatePolicyInputs(policy, inputs);
  if (joinedError) return result('UNRESOLVED', joinedError);
  if (!exactKeys(commitment, COMMITMENT_KEYS)
      || !DIGEST.test(commitment.policyHash)
      || !DIGEST.test(commitment.readSetHash)
      || !DIGEST.test(commitment.inputsHash)
      || !['ALLOW', 'DENY'].includes(commitment.verdict)) {
    return result('MISMATCH', 'commitment_malformed');
  }

  if (digest(policy) !== commitment.policyHash) return result('MISMATCH', 'policy_hash_mismatch');
  if (digest(deriveReadSet(policy)) !== commitment.readSetHash) return result('MISMATCH', 'read_set_hash_mismatch');
  if (digest(inputs) !== commitment.inputsHash) return result('MISMATCH', 'inputs_hash_mismatch');

  const evaluated = runEvaluator(policy, inputs);
  if (evaluated.verdict !== commitment.verdict) {
    return result('MISMATCH', 'verdict_mismatch', evaluated.verdict, evaluated.classified_verdict);
  }
  return result('MATCH', null, evaluated.verdict, evaluated.classified_verdict);
}

function deepEqual(left, right) {
  return canonicalizeStrictJson(left) === canonicalizeStrictJson(right);
}

export function materializeCase(corpus, entry) {
  const fixture = (name) => (name === undefined ? undefined : structuredClone(corpus.fixtures[name]));
  return {
    ...entry,
    policy: entry.policy_ref ? fixture(entry.policy_ref) : entry.policy,
    inputs: entry.inputs_ref ? fixture(entry.inputs_ref) : entry.inputs,
    commitment: entry.commitment_ref ? fixture(entry.commitment_ref) : entry.commitment,
  };
}

export function runCorpus(corpus) {
  const checks = corpus.cases.map((sourceEntry) => {
    const entry = materializeCase(corpus, sourceEntry);
    let actual;
    try {
      actual = entry.direction === 'construct'
        ? { commitment: buildCommitment(entry.policy, entry.inputs, entry.evaluator_profile) }
        : verifyReplay({
          commitment: entry.commitment,
          policy: entry.policy,
          inputs: entry.inputs,
          evaluatorProfile: entry.evaluator_profile,
        });
    } catch (error) {
      actual = { error: error instanceof Error ? error.message : 'unknown_error' };
    }
    return { id: entry.id, passed: deepEqual(actual, entry.expected), actual, expected: entry.expected };
  });
  const passedCases = checks.filter((entry) => entry.passed).length;
  return {
    '@version': 'NOA-POLICY-REPLAY-REPORT-v0.1',
    evaluator_profile: EVALUATOR_PROFILE_ID,
    implementation_owner: 'EMILIA Protocol',
    independent_implementation: false,
    total: checks.length,
    passed_cases: passedCases,
    passed: passedCases === checks.length,
    checks,
  };
}

function main() {
  const corpus = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
  const report = runCorpus(corpus);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
