// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { canonicalize } from '../packages/verify/index.js';

const corpus = JSON.parse(readFileSync(new URL('../conformance/vectors/aeb-audit-provenance-join.v1.json', import.meta.url), 'utf8'));

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}

function mutate(root, path, mutation) {
  const parts = path.slice(1).split('/');
  const key = parts.pop();
  let current = root;
  for (const part of parts) current = current[part];
  current[key] = mutation.value;
}

function verifyJoin(aebDecision, expectedDigest, auditRecord) {
  const reasons = [];
  if (auditRecord.caid !== aebDecision.caid) reasons.push('caid_mismatch');
  if (auditRecord.aeb_event_digest !== digest(aebDecision)) reasons.push('aeb_event_digest_mismatch');
  if (auditRecord.outcome_state !== 'INDETERMINATE') reasons.push('outcome_state_mismatch');
  if (expectedDigest !== digest(aebDecision)) reasons.push('expected_aeb_event_digest_mismatch');
  if (!Array.isArray(auditRecord.provenance_refs) || auditRecord.provenance_refs.length !== 3) {
    reasons.push('provenance_reference_set_mismatch');
  }
  return { valid: reasons.length === 0, reasons };
}

describe('AEB to audit/provenance composition vector', () => {
  it('keeps native references separate while checking the shared join', () => {
    for (const vector of corpus.vectors) {
      const aebDecision = structuredClone(corpus.aeb_decision);
      const auditRecord = structuredClone(corpus.audit_record);
      for (const mutation of vector.mutations || []) {
        if (mutation.path.startsWith('/aeb_decision/')) mutate(aebDecision, mutation.path.slice('/aeb_decision'.length), mutation);
        else mutate(auditRecord, mutation.path.slice('/audit_record'.length), mutation);
      }
      expect(verifyJoin(aebDecision, corpus.expected_aeb_event_digest, auditRecord), vector.id).toEqual(vector.expect);
    }
  });
});
