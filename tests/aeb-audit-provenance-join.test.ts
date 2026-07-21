// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { canonicalize } from '../packages/verify/index.js';
import { computeCaid, parseCaid } from '../caid/impl/js/caid.mjs';

const corpus = JSON.parse(readFileSync(new URL('../conformance/vectors/aeb-audit-provenance-join.v1.json', import.meta.url), 'utf8'));
const registry = JSON.parse(readFileSync(new URL('../caid/registry/action-types.json', import.meta.url), 'utf8'));

function digest(value: unknown) {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}

function auditBinding(record) {
  return {
    session_ref: record.session_ref,
    provenance_refs: record.provenance_refs,
    outcome_state: record.outcome_state,
  };
}

function mutate(root, path, mutation) {
  const parts = path.slice(1).split('/');
  const key = parts.pop();
  let current = root;
  for (const part of parts) current = current[part];
  current[key] = mutation.value;
}

function verifyJoin(aebDecision, auditRecord) {
  const reasons: string[] = [];
  const computed = computeCaid(corpus.action_object, {
    suite: 'jcs-sha256',
    definitions: registry.types,
  });
  if (!parseCaid(aebDecision.caid).ok || computed.caid !== aebDecision.caid) {
    reasons.push('caid_derivation_mismatch');
  }
  if (auditRecord.caid !== aebDecision.caid) reasons.push('caid_mismatch');
  if (auditRecord.aeb_event_digest !== digest(aebDecision)) reasons.push('aeb_event_digest_mismatch');
  if (auditRecord.outcome_state !== 'INDETERMINATE') reasons.push('outcome_state_mismatch');
  if (corpus.expected_aeb_event_digest !== digest(aebDecision)) reasons.push('expected_aeb_event_digest_mismatch');
  if (corpus.expected_audit_binding_digest !== digest(auditBinding(auditRecord))) {
    reasons.push('audit_binding_digest_mismatch');
  }
  return { valid: reasons.length === 0, reasons };
}

describe('AEB to audit/provenance opaque-reference correlation vector', () => {
  it('derives a conforming CAID and pins every correlation reference', () => {
    for (const vector of corpus.vectors) {
      const aebDecision = structuredClone(corpus.aeb_decision);
      const auditRecord = structuredClone(corpus.audit_record);
      for (const mutation of vector.mutations || []) {
        if (mutation.path.startsWith('/aeb_decision/')) mutate(aebDecision, mutation.path.slice('/aeb_decision'.length), mutation);
        else mutate(auditRecord, mutation.path.slice('/audit_record'.length), mutation);
      }
      expect(verifyJoin(aebDecision, auditRecord), vector.id).toEqual(vector.expect);
    }
  });
});
