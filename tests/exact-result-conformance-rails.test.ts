// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  EXACT_EXTERNAL_RESULT_KINDS,
  LIVE_SUITE_EXECUTION_FILES,
  LIVE_SUITE_FILES,
} from '../conformance/suites.mjs';
import {
  buildSuiteContract,
  compareResultRow,
} from '../conformance/result-contract.mjs';
import { verifyAuthorityProofViaDocument } from '../lib/authority/document-proof-join.js';
import {
  canonicalize,
  trustReceiptDigest,
  verifyOutcomeBinding,
  verifyRevocation,
} from '../packages/verify/index.js';

const readSuite = (file) => JSON.parse(fs.readFileSync(
  new URL(`../conformance/vectors/${file}`, import.meta.url),
  'utf8',
));
const digest = (value) => `sha256:${crypto.createHash('sha256')
  .update(Buffer.from(canonicalize(value), 'utf8')).digest('hex')}`;
const signatureBytes = (value) => Buffer.from(value, 'base64url').length;

function outcomeExpectation(suite, vector) {
  const options = {
    receiptOptions: suite.common.receipt_options,
    executorKeys: Object.hasOwn(vector, 'executor_keys')
      ? vector.executor_keys
      : suite.common.executor_keys,
    now: suite.common.now,
    ...(Object.hasOwn(vector, 'policy_predicted_effects')
      ? { policyPredictedEffects: vector.policy_predicted_effects }
      : {}),
  };
  const result = verifyOutcomeBinding(suite.common.receipt, vector.attestation, options);
  return {
    outcome: result.outcome_binding.outcome,
    valid: result.valid,
    checks: result.checks,
    reasons: result.outcome_binding.reasons,
    receipt_digest: trustReceiptDigest(suite.common.receipt),
    attestation_digest: digest(vector.attestation),
    result_digest: result.result_digest,
  };
}

function revocationExpectation(vector) {
  const result = verifyRevocation(vector.target, vector.revocation, {
    revokerKeys: vector.revoker_keys,
    maxAgeSeconds: vector.max_age_seconds,
    now: vector.now,
  });
  const exactResult = {
    valid: result.valid,
    checks: result.checks,
    reasons: Object.entries(result.checks)
      .filter(([, passed]) => !passed)
      .map(([check]) => check),
    target_digest: digest(vector.target),
    revocation_digest: digest(vector.revocation),
  };
  return { ...exactResult, result_digest: digest(exactResult) };
}

function authorityExpectation(vector) {
  const result = verifyAuthorityProofViaDocument(vector.proof, vector.docs, vector.opts);
  const { limitations: _limitations, ...machineResult } = result;
  const exactResult = {
    ...machineResult,
    proof_input_digest: digest(vector.proof),
    document_chain_digest: digest(vector.docs),
  };
  return { ...exactResult, result_digest: digest(exactResult) };
}

describe('exact external-result contracts', () => {
  it('promotes the completed same-team ports without changing external contracts', () => {
    expect(EXACT_EXTERNAL_RESULT_KINDS).toEqual({
      'outcome-binding.exec.v1.json': 'outcome',
      'revocation.exec.v2.json': 'valid',
      'authority-document-proof-join.exec.v1.json': 'accepted',
    });
    expect(LIVE_SUITE_FILES).toContain('revocation.exec.v2.json');
    expect(LIVE_SUITE_FILES).toContain('outcome-binding.v1.json');
    expect(LIVE_SUITE_FILES).toContain('outcome-binding.exec.v1.json');
    expect(LIVE_SUITE_FILES).toContain('authority-document-proof-join.v1.json');
    expect(LIVE_SUITE_FILES).not.toContain('authority-document-proof-join.exec.v1.json');
    expect(LIVE_SUITE_EXECUTION_FILES).toEqual({
      'authority-document-proof-join.v1.json':
        'authority-document-proof-join.exec.v1.json',
    });
    expect(readSuite('outcome-binding.v1.json').vectors).toHaveLength(35);
    expect(readSuite('outcome-binding.exec.v1.json').vectors).toHaveLength(10);
    expect(readSuite('authority-document-proof-join.v1.json').vectors).toHaveLength(26);
  });

  it('refuses boolean-only or truncated rows for exact-result suites', () => {
    const outcomeSuite = readSuite('outcome-binding.exec.v1.json');
    const outcomeContract = buildSuiteContract(
      'outcome-binding.exec.v1.json',
      outcomeSuite,
    );
    const vector = outcomeSuite.vectors[0];
    expect(compareResultRow(outcomeContract, {
      id: vector.id,
      ...vector.expect,
    }).ok).toBe(true);
    expect(compareResultRow(outcomeContract, {
      id: vector.id,
      valid: vector.expect.valid,
    }).ok).toBe(false);

    const authorityCatalogue = readSuite('authority-document-proof-join.v1.json');
    const authorityExec = readSuite('authority-document-proof-join.exec.v1.json');
    const authorityContract = buildSuiteContract(
      'authority-document-proof-join.v1.json',
      authorityCatalogue,
      authorityExec,
    );
    expect(compareResultRow(authorityContract, {
      id: authorityExec.vectors[0].id,
      ...authorityExec.vectors[0].expect,
    }).ok).toBe(true);
    expect(compareResultRow(authorityContract, {
      id: authorityExec.vectors[0].id,
      accepted: true,
    }).ok).toBe(false);
  });

  it('pins Outcome Binding to real receipt, attestation, and key bytes plus exact results', () => {
    const suite = readSuite('outcome-binding.exec.v1.json');
    const receipt = suite.common.receipt;
    expect(receipt.signoffs).toHaveLength(2);
    expect(receipt.signoffs.every((item) => signatureBytes(item.signature) === 64)).toBe(true);
    expect(signatureBytes(receipt.log_proof.checkpoint.log_signature)).toBe(64);
    expect(Buffer.from(suite.common.receipt_options.logPublicKey, 'base64url').length)
      .toBeGreaterThan(32);
    expect(Object.values(suite.common.receipt_options.approverKeys)
      .every((item) => Buffer.from(item.public_key, 'base64url').length > 32)).toBe(true);
    expect(Object.values(suite.common.executor_keys)
      .every((item) => Buffer.from(item.public_key, 'base64url').length > 32)).toBe(true);
    for (const vector of suite.vectors) {
      expect(signatureBytes(vector.attestation.proof.signature_b64u)).toBe(64);
      expect(vector.expect).toEqual(outcomeExpectation(suite, vector));
    }
  });

  it('pins Revocation to exact checks, typed refusal reasons, and input/result digests', () => {
    const suite = readSuite('revocation.exec.v2.json');
    for (const vector of suite.vectors) {
      expect(vector.expect).toEqual(revocationExpectation(vector));
    }
  });

  it('pins the Authority join to the complete machine result and digest set', () => {
    const suite = readSuite('authority-document-proof-join.exec.v1.json');
    for (const vector of suite.vectors) {
      expect(vector.expect).toEqual(authorityExpectation(vector));
    }
  });
});
