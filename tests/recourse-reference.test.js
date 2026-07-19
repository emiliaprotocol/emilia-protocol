// SPDX-License-Identifier: Apache-2.0
//
// EP-RECOURSE-REFERENCE — the recourse commitment is verifiable offline and
// bound to a genuine authorization; EMILIA proves it, does not bear it.

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import { buildRecourse, positive, SUBJECT_DIGEST, RECEIPT_PAYLOAD_DIGEST } from '../examples/recourse/recourse-reference-vector.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'public/schemas/ep-recourse-reference.schema.json'), 'utf8'));
const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

// Re-import the verifier via the vector module's exported buildRecourse + a fresh verify.
const { verifyRecourse } = await import('../examples/recourse/recourse-reference-vector.mjs');
const pinned = [positive.issuer_key];
const opts = { presentedSubjectDigest: SUBJECT_DIGEST, presentedReceiptPayloadDigest: RECEIPT_PAYLOAD_DIGEST, pinnedIssuerKeys: pinned, atTime: '2026-07-02T12:00:00Z' };

describe('EP-RECOURSE-REFERENCE', () => {
  it('the reference validates against its schema', () => {
    const ok = validate(positive);
    expect(ok, JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it('a genuine, pinned, in-window reference is verified AND accepted', () => {
    const v = verifyRecourse(positive, opts);
    expect(v.verified).toBe(true);
    expect(v.accepted).toBe(true);
  });

  it('verified != accepted: a valid reference from an UNPINNED issuer is never accepted', () => {
    const v = verifyRecourse(positive, { ...opts, pinnedIssuerKeys: [] });
    expect(v.verified).toBe(true);       // signature + bindings hold
    expect(v.accepted).toBe(false);      // but not pinned out-of-band
  });

  it('tampered terms fail the signature (coverage limit cannot be raised after signing)', () => {
    const r = buildRecourse();
    r.coverage = { ...r.coverage, limit: { amount: '999999999.00', currency: 'USD' } };
    const v = verifyRecourse(r, opts);
    expect(v.checks.signature).toBe(false);
    expect(v.accepted).toBe(false);
  });

  it('recourse for action A is refused against action B (subject binding)', () => {
    const v = verifyRecourse(positive, { ...opts, presentedSubjectDigest: 'f'.repeat(64) });
    expect(v.checks.subject_binding).toBe(false);
    expect(v.accepted).toBe(false);
  });

  it('recourse is refused when it does not bind the presented authorization', () => {
    const v = verifyRecourse(positive, { ...opts, presentedReceiptPayloadDigest: `sha256:${'a'.repeat(64)}` });
    expect(v.checks.authorization_binding).toBe(false);
    expect(v.accepted).toBe(false);
  });

  it('an action outside the coverage window is not accepted (verified terms, not live)', () => {
    const v = verifyRecourse(positive, { ...opts, atTime: '2027-06-01T00:00:00Z' });
    expect(v.verified).toBe(true);
    expect(v.checks.within_window).toBe(false);
    expect(v.accepted).toBe(false);
  });
});
