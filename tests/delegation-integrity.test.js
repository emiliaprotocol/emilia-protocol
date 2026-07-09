/**
 * EP-DELEGATION-INTEGRITY-v1 — conformance suite.
 *
 * Runs every vector in conformance/vectors/delegation-integrity.v1.json through
 * the real offline delegation-chain verifier (packages/verify/provenance.js) and
 * asserts the accept/refuse verdict AND the distinct refusal reason. The vectors
 * carry REAL Class-A/B receipts and REAL Ed25519 delegation proofs (minted over
 * canonical bytes), so each negative is a genuine forgery attempt, not hand-edited
 * JSON that would fail for an unrelated reason.
 *
 * Two classic delegation attacks are proven refused fail-closed:
 *   1. AUTHORITY LAUNDERING — a child scope/cap the ancestor chain never conferred
 *      (including a wildcard used to widen beyond a parent grant).
 *   2. DELEGATION CHAIN POISONING — an unsigned, tampered, wrong-key, or
 *      spliced/unanchored link.
 * Plus the ROOT case: no human root signoff yields no authority (authority from
 * nothing is refused).
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { verifyProvenanceOffline } from '../packages/verify/provenance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SUITE = JSON.parse(
  readFileSync(path.join(__dirname, '..', 'conformance', 'vectors', 'delegation-integrity.v1.json'), 'utf8'),
);

const runVector = (v) =>
  verifyProvenanceOffline(v.input.provenance_chain, {
    delegationKeys: v.input.delegation_keys,
    now: v.input.now_ms,
  });

describe('EP-DELEGATION-INTEGRITY-v1 — suite metadata', () => {
  it('is the expected wire tag with a self-consistent count and >=10 vectors', () => {
    expect(SUITE.suite).toBe('EP-DELEGATION-INTEGRITY-v1');
    expect(SUITE.count).toBe(SUITE.vectors.length);
    expect(SUITE.vectors.length).toBeGreaterThanOrEqual(10);
  });

  it('carries positive controls AND refusals for both attack classes plus the root case', () => {
    const kinds = new Set(SUITE.vectors.map((v) => v.kind));
    expect(kinds.has('positive')).toBe(true);
    expect(kinds.has('authority_laundering')).toBe(true);
    expect(kinds.has('chain_poisoning')).toBe(true);
    expect(kinds.has('root_authority')).toBe(true);
    expect(SUITE.vectors.some((v) => v.expect.valid === true)).toBe(true);
    expect(SUITE.vectors.some((v) => v.expect.valid === false)).toBe(true);
  });

  it('every vector id is unique', () => {
    const ids = SUITE.vectors.map((v) => v.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('EP-DELEGATION-INTEGRITY-v1 — verdict + distinct refusal reason', () => {
  for (const v of SUITE.vectors) {
    it(`${v.kind} · ${v.id}`, () => {
      const res = runVector(v);
      // 1. accept/refuse verdict matches.
      expect(res.valid, JSON.stringify({ id: v.id, errors: res.errors }, null, 2)).toBe(v.expect.valid);

      if (v.expect.valid === false) {
        // 2. the named check fails closed.
        if (v.expect.check) {
          expect(res.checks[v.expect.check], `${v.id}: expected check ${v.expect.check}=false; checks=${JSON.stringify(res.checks)}`).toBe(false);
        }
        // 3. a human-readable error names the reason (never a silent refusal).
        expect(Array.isArray(res.errors) && res.errors.length > 0, `${v.id}: refusal must carry a reason`).toBe(true);
        if (v.expect.error_includes) {
          expect(
            res.errors.some((e) => e.includes(v.expect.error_includes)),
            `${v.id}: expected an error containing "${v.expect.error_includes}"; got ${JSON.stringify(res.errors)}`,
          ).toBe(true);
        }
      } else {
        // positive controls must be clean — no errors at all.
        expect(res.errors, `${v.id}: positive control must have no errors`).toEqual([]);
      }
    });
  }
});

describe('EP-DELEGATION-INTEGRITY-v1 — determinism', () => {
  it('re-running every vector yields byte-identical verdicts, checks, and errors', () => {
    for (const v of SUITE.vectors) {
      const a = runVector(v);
      const b = runVector(v);
      expect(JSON.stringify(b)).toBe(JSON.stringify(a));
    }
  });
});

describe('EP-DELEGATION-INTEGRITY-v1 — attack-class coverage', () => {
  it('AUTHORITY LAUNDERING: every laundering vector is refused on scope/cap containment', () => {
    const vs = SUITE.vectors.filter((v) => v.kind === 'authority_laundering');
    expect(vs.length).toBeGreaterThanOrEqual(2); // scope broadening + wildcard widen (+cap)
    for (const v of vs) {
      const res = runVector(v);
      expect(res.valid).toBe(false);
      expect(res.checks.scope_containment).toBe(false);
    }
  });

  it('DELEGATION CHAIN POISONING: every poisoning vector is refused with a distinct binding/signature reason', () => {
    const vs = SUITE.vectors.filter((v) => v.kind === 'chain_poisoning');
    expect(vs.length).toBeGreaterThanOrEqual(2);
    const poisonChecks = new Set(['delegations_signed', 'proof_key_bound', 'chain_links_bound', 'chain_anchored', 'delegations_not_expired']);
    for (const v of vs) {
      const res = runVector(v);
      expect(res.valid).toBe(false);
      // at least one integrity check that is NOT scope/cap containment must have tripped.
      const tripped = Object.entries(res.checks).filter(([, ok]) => ok === false).map(([k]) => k);
      expect(tripped.some((c) => poisonChecks.has(c)), `${v.id}: tripped=${tripped}`).toBe(true);
    }
  });

  it('ROOT: no human root signoff yields no authority', () => {
    const vs = SUITE.vectors.filter((v) => v.kind === 'root_authority');
    expect(vs.length).toBeGreaterThanOrEqual(1);
    for (const v of vs) {
      const res = runVector(v);
      expect(res.valid).toBe(false);
      expect(res.checks.root_receipt_valid === false || res.checks.root_human_signoff === false).toBe(true);
    }
  });
});
