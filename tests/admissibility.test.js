// SPDX-License-Identifier: Apache-2.0
//
// EP-ADMISSIBILITY — decision-grade evidence. The verdict over a heterogeneous
// bundle is classified, purpose-relative, relying-party-policed, and replayable.

import { describe, it, expect } from 'vitest';
import { evaluateAdmissibility, evalRequirement, ADMISSIBILITY_VERDICTS } from '../lib/evidence/admissibility.js';
import { baseComponents, POLICIES, AS_OF, results } from '../examples/admissibility/admissibility-vector.mjs';

const AT = { as_of: AS_OF };
const ACTION = baseComponents()[0].action_digest;
const bundle = (components) => ({ action_digest: ACTION, components });

describe('EP-ADMISSIBILITY vector', () => {
  it('every scenario produced a verdict in the closed set', () => {
    for (const [k, v] of Object.entries(results)) {
      expect(ADMISSIBILITY_VERDICTS, `${k} -> ${v.verdict}`).toContain(v.verdict);
    }
  });

  it('the full bundle is admissible for money movement', () => {
    expect(results.admissible.verdict).toBe('admissible');
  });
});

describe('sufficiency is relative to the reliance purpose', () => {
  it('the SAME thin bundle is admissible for audit but missing_evidence for money movement', () => {
    const thin = baseComponents().filter((c) => !['recourse_reference', 'execution_attestation'].includes(c.type));
    expect(evaluateAdmissibility(bundle(thin), POLICIES.audit, AT).verdict).toBe('admissible');
    expect(evaluateAdmissibility(bundle(thin), POLICIES.money_movement, AT).verdict).toBe('missing_evidence');
  });
});

describe('the sufficiency policy is relying-party-supplied, never bundle-chosen', () => {
  it('no policy => unverifiable, even over a perfectly verified bundle', () => {
    const r = evaluateAdmissibility(bundle(baseComponents()), {}, AT);
    expect(r.verdict).toBe('unverifiable');
    expect(r.reasons.join(' ')).toMatch(/never read from the bundle/i);
  });
});

describe('verdict precedence: unverifiable > conflicted > stale > missing > admissible', () => {
  it('a broken required leg is unverifiable regardless of everything else', () => {
    const comps = baseComponents().map((c) => (c.type === 'authorization_receipt' ? { ...c, verified: false } : c));
    expect(evaluateAdmissibility(bundle(comps), POLICIES.money_movement, AT).verdict).toBe('unverifiable');
  });

  it('a leg binding a different action is conflicted even if the requirement is otherwise met', () => {
    const comps = baseComponents().map((c) => (c.type === 'policy_permit' ? { ...c, action_digest: 'e'.repeat(64) } : c));
    expect(evaluateAdmissibility(bundle(comps), POLICIES.money_movement, AT).verdict).toBe('conflicted');
  });

  it('a verified DENIAL in the bundle is conflicted, not admissible', () => {
    const comps = baseComponents().map((c) => (c.type === 'authorization_receipt' ? { ...c, outcome: 'deny' } : c));
    expect(evaluateAdmissibility(bundle(comps), POLICIES.money_movement, AT).verdict).toBe('conflicted');
  });

  it('stale beats missing: required-but-stale evidence yields stale, not missing_evidence', () => {
    const comps = baseComponents().map((c) => (c.type === 'authorization_receipt' ? { ...c, issued_at: '2026-07-02T11:00:00Z' } : c));
    expect(evaluateAdmissibility(bundle(comps), POLICIES.money_movement, AT).verdict).toBe('stale');
  });

  it('revocation of a policy-required leg yields stale', () => {
    const comps = baseComponents().map((c) => (c.type === 'recourse_reference' ? { ...c, revoked: true } : c));
    expect(evaluateAdmissibility(bundle(comps), POLICIES.money_movement, AT).verdict).toBe('stale');
  });
});

describe('determinism / policy replay', () => {
  it('same (policy, facts, as_of) => identical verdict and replay_digest', () => {
    const a = evaluateAdmissibility(bundle(baseComponents()), POLICIES.money_movement, AT);
    const b = evaluateAdmissibility(bundle(baseComponents()), POLICIES.money_movement, AT);
    expect(a.replay_digest).toBe(b.replay_digest);
    expect(a.verdict).toBe(b.verdict);
  });

  it('a different policy over the same bundle => a different replay_digest', () => {
    const a = evaluateAdmissibility(bundle(baseComponents()), POLICIES.money_movement, AT);
    const c = evaluateAdmissibility(bundle(baseComponents()), POLICIES.audit, AT);
    expect(a.replay_digest).not.toBe(c.replay_digest);
  });
});

describe('requirement expression evaluator is fail-closed', () => {
  it('AND / OR / parens evaluate over the present-type set', () => {
    const present = new Set(['a', 'b']);
    expect(evalRequirement('a AND b', present)).toBe(true);
    expect(evalRequirement('a AND c', present)).toBe(false);
    expect(evalRequirement('a OR c', present)).toBe(true);
    expect(evalRequirement('(a OR c) AND b', present)).toBe(true);
  });

  it('a malformed expression fails closed (false), never throws', () => {
    expect(evalRequirement('a AND', new Set(['a']))).toBe(false);
    expect(evalRequirement('AND a', new Set(['a']))).toBe(false);
    expect(evalRequirement('a )( b', new Set(['a', 'b']))).toBe(false);
  });
});
