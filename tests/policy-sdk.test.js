/**
 * EP Policy Authoring SDK — unit tests.
 *
 * Coverage:
 *   - linter: every rule (EP-L001 through EP-L008) triggers on at least one
 *     representative bad policy, and does not trigger on a canonical good policy.
 *   - simulator: happy-path accept, known failure modes deny with correct codes.
 *   - diff: every risk classification (loosening / tightening / neutral).
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  lintPolicy,
  filterBySeverity,
  simulateOne,
  simulateBatch,
  scenarioFromPolicy,
  diffPolicy,
} from '@/lib/policy-sdk';

// ── Canonical "good" policy for baseline tests ─────────────────────────────

const GOOD_POLICY_RULES = {
  required_parties: {
    initiator: { required_claims: ['entity_ref', 'authority_ref'], minimum_assurance: 'substantial' },
    responder: { required_claims: ['entity_ref'], minimum_assurance: 'substantial' },
  },
  binding: {
    payload_hash_required: true,
    nonce_required: true,
    expiry_minutes: 10,
  },
  storage: {
    store_raw_payload: true,
    store_normalized_claims: true,
  },
};

const GOOD_POLICY = {
  policy_id: 'test-policy-1',
  policy_version: '1.0.0',
  rules: GOOD_POLICY_RULES,
};

// ── Linter ──────────────────────────────────────────────────────────────────

describe('policy-sdk/linter — baseline', () => {
  it('good policy has no errors at the "high" action_class default', () => {
    const report = lintPolicy(GOOD_POLICY_RULES);
    expect(report.ok).toBe(true);
    expect(report.findings.filter(f => f.severity === 'error')).toEqual([]);
  });
});

describe('policy-sdk/linter — EP-L001 (assurance floor)', () => {
  it('flags substantial assurance on a critical action', () => {
    const report = lintPolicy(GOOD_POLICY_RULES, { action_class: 'critical' });
    const f = report.findings.filter(f => f.rule === 'EP-L001');
    expect(f.length).toBeGreaterThan(0);
  });

  it('does not flag substantial assurance on a high action (it meets the floor)', () => {
    const report = lintPolicy(GOOD_POLICY_RULES, { action_class: 'high' });
    expect(report.findings.filter(f => f.rule === 'EP-L001')).toEqual([]);
  });
});

describe('policy-sdk/linter — EP-L002 (binding strength)', () => {
  it('errors when nonce_required is false on a high action', () => {
    const rules = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, nonce_required: false } };
    const report = lintPolicy(rules);
    expect(report.ok).toBe(false);
    expect(report.findings.some(f => f.rule === 'EP-L002' && f.severity === 'error')).toBe(true);
  });

  it('warns when payload_hash_required is false on non-low actions', () => {
    const rules = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, payload_hash_required: false } };
    const report = lintPolicy(rules, { action_class: 'high' });
    expect(report.findings.some(f => f.rule === 'EP-L002' && f.severity === 'warning')).toBe(true);
  });
});

describe('policy-sdk/linter — EP-L003 (required_parties)', () => {
  it('errors on empty required_parties', () => {
    const rules = { ...GOOD_POLICY_RULES, required_parties: {} };
    const report = lintPolicy(rules);
    expect(report.ok).toBe(false);
    expect(report.findings.some(f => f.rule === 'EP-L003' && f.severity === 'error')).toBe(true);
  });

  it('emits info when only initiator is required', () => {
    const rules = {
      ...GOOD_POLICY_RULES,
      required_parties: { initiator: GOOD_POLICY_RULES.required_parties.initiator },
    };
    const report = lintPolicy(rules);
    expect(report.findings.some(f => f.rule === 'EP-L003' && f.severity === 'info')).toBe(true);
  });
});

describe('policy-sdk/linter — EP-L005 (expiry bounds)', () => {
  it('errors on critical action with 60m expiry', () => {
    const rules = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, expiry_minutes: 60 } };
    const report = lintPolicy(rules, { action_class: 'critical' });
    expect(report.findings.some(f => f.rule === 'EP-L005' && f.severity === 'error')).toBe(true);
  });

  it('does not flag 10m expiry on critical', () => {
    // 10m ≤ 15m critical ceiling, so expiry lint should not fire.
    // Deep-clone to avoid mutating the shared GOOD_POLICY_RULES across tests.
    const rules = JSON.parse(JSON.stringify(GOOD_POLICY_RULES));
    rules.binding.expiry_minutes = 10;
    rules.required_parties.initiator.minimum_assurance = 'high';
    rules.required_parties.responder.minimum_assurance = 'high';
    const report = lintPolicy(rules, { action_class: 'critical' });
    expect(report.findings.filter(f => f.rule === 'EP-L005')).toEqual([]);
  });
});

describe('policy-sdk/linter — EP-L007 (unreachable roles)', () => {
  it('errors on non-canonical role names', () => {
    const rules = {
      ...GOOD_POLICY_RULES,
      required_parties: {
        ...GOOD_POLICY_RULES.required_parties,
        manager: { required_claims: ['entity_ref'], minimum_assurance: 'substantial' },
      },
    };
    const report = lintPolicy(rules);
    expect(report.findings.some(f => f.rule === 'EP-L007')).toBe(true);
  });
});

describe('policy-sdk/linter — EP-L004 (storage consistency)', () => {
  it('emits info when payload_hash_required but raw payload not stored', () => {
    const rules = JSON.parse(JSON.stringify(GOOD_POLICY_RULES));
    rules.storage.store_raw_payload = false;
    const report = lintPolicy(rules);
    expect(report.findings.some(f => f.rule === 'EP-L004' && f.severity === 'info')).toBe(true);
  });
});

describe('policy-sdk/linter — EP-L006 (duplicate claims)', () => {
  it('emits info when duplicate claims are present', () => {
    const rules = JSON.parse(JSON.stringify(GOOD_POLICY_RULES));
    rules.required_parties.initiator.required_claims = ['entity_ref', 'entity_ref', 'authority_ref'];
    const report = lintPolicy(rules);
    expect(report.findings.some(f => f.rule === 'EP-L006')).toBe(true);
  });
});

describe('policy-sdk/linter — EP-L008 (signoff consistency)', () => {
  it('errors when signoff required but no party has substantial+ assurance', () => {
    const rules = JSON.parse(JSON.stringify(GOOD_POLICY_RULES));
    rules.signoff = { required: true };
    rules.required_parties.initiator.minimum_assurance = 'low';
    rules.required_parties.responder.minimum_assurance = 'low';
    const report = lintPolicy(rules);
    expect(report.findings.some(f => f.rule === 'EP-L008' && f.severity === 'error')).toBe(true);
  });

  it('warns when critical + signoff does not require re-auth', () => {
    const rules = JSON.parse(JSON.stringify(GOOD_POLICY_RULES));
    rules.signoff = { required: true, re_auth_required: false };
    rules.required_parties.initiator.minimum_assurance = 'high';
    rules.required_parties.responder.minimum_assurance = 'high';
    const report = lintPolicy(rules, { action_class: 'critical' });
    expect(report.findings.some(f => f.rule === 'EP-L008' && f.severity === 'warning')).toBe(true);
  });
});

describe('policy-sdk/linter — filterBySeverity', () => {
  it('filters out info and warning findings when minSeverity=error', () => {
    const rules = {
      ...GOOD_POLICY_RULES,
      required_parties: { initiator: GOOD_POLICY_RULES.required_parties.initiator }, // triggers info
      binding: { ...GOOD_POLICY_RULES.binding, nonce_required: false }, // triggers error
    };
    const report = lintPolicy(rules);
    const errorOnly = filterBySeverity(report, 'error');
    expect(errorOnly.findings.every(f => f.severity === 'error')).toBe(true);
  });
});

// ── Simulator ──────────────────────────────────────────────────────────────

describe('policy-sdk/simulator — happy path', () => {
  it('accepts a canonical scenario from a canonical policy', () => {
    const scenario = scenarioFromPolicy(GOOD_POLICY);
    const result = simulateOne({ policy: GOOD_POLICY, scenario });
    expect(result.decision).toBe('accept');
    expect(result.violations).toEqual([]);
    expect(result.duration_us).toBeGreaterThanOrEqual(0);
  });
});

describe('policy-sdk/simulator — failure modes', () => {
  it('denies an expired binding with BINDING_EXPIRED', () => {
    const scenario = scenarioFromPolicy(GOOD_POLICY);
    scenario.binding.expires_at = new Date(Date.now() - 60_000).toISOString();
    const result = simulateOne({ policy: GOOD_POLICY, scenario });
    expect(result.decision).toBe('deny');
    expect(result.violations.some(v => v.code === 'BINDING_EXPIRED')).toBe(true);
  });

  it('denies a missing interaction_id with MISSING_INTERACTION_REF', () => {
    const scenario = scenarioFromPolicy(GOOD_POLICY);
    scenario.handshake.interaction_id = null;
    const result = simulateOne({ policy: GOOD_POLICY, scenario });
    expect(result.decision).toBe('deny');
    expect(result.violations.some(v => v.code === 'MISSING_INTERACTION_REF')).toBe(true);
  });

  it('denies a revoked authority with AUTHORITY_REVOKED', () => {
    const scenario = scenarioFromPolicy(GOOD_POLICY);
    scenario.authorities = [{ key_id: 'issuer-trusted-ca', status: 'revoked' }];
    const result = simulateOne({ policy: GOOD_POLICY, scenario });
    expect(result.decision).toBe('deny');
    expect(result.violations.some(v => v.code === 'AUTHORITY_REVOKED')).toBe(true);
  });
});

describe('policy-sdk/simulator — simulateBatch', () => {
  it('reports pass/fail per case with expected violation codes', () => {
    const report = simulateBatch({
      policy: GOOD_POLICY,
      cases: [
        {
          name: 'happy path',
          scenario: scenarioFromPolicy(GOOD_POLICY),
          expect: 'accept',
        },
        {
          name: 'expired binding',
          scenario: (() => { const s = scenarioFromPolicy(GOOD_POLICY); s.binding.expires_at = new Date(Date.now() - 1000).toISOString(); return s; })(),
          expect: 'deny',
          expect_codes: ['BINDING_EXPIRED'],
        },
      ],
    });
    expect(report.ok).toBe(true);
    expect(report.passed).toBe(2);
    expect(report.failed).toEqual([]);
  });

  it('flags cases where expected codes were not triggered', () => {
    const report = simulateBatch({
      policy: GOOD_POLICY,
      cases: [
        {
          name: 'happy path (claims deny but accepts)',
          scenario: scenarioFromPolicy(GOOD_POLICY),
          expect: 'deny',
          expect_codes: ['BINDING_EXPIRED'],
        },
      ],
    });
    expect(report.ok).toBe(false);
    expect(report.failed.length).toBe(1);
  });
});

// ── Diff ────────────────────────────────────────────────────────────────────

describe('policy-sdk/diff — classifications', () => {
  it('classifies expiry increase as loosening', () => {
    const a = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, expiry_minutes: 5 } };
    const b = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, expiry_minutes: 30 } };
    const d = diffPolicy(a, b);
    expect(d.risk).toBe('loosening');
    expect(d.changes.some(c => c.path.endsWith('.expiry_minutes') && c.risk === 'loosening')).toBe(true);
  });

  it('classifies expiry decrease as tightening', () => {
    const a = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, expiry_minutes: 30 } };
    const b = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, expiry_minutes: 5 } };
    const d = diffPolicy(a, b);
    expect(d.risk).toBe('tightening');
  });

  it('classifies nonce_required true→false as loosening', () => {
    const a = GOOD_POLICY_RULES;
    const b = { ...GOOD_POLICY_RULES, binding: { ...GOOD_POLICY_RULES.binding, nonce_required: false } };
    const d = diffPolicy(a, b);
    expect(d.risk).toBe('loosening');
    expect(d.changes.some(c => c.path.endsWith('.nonce_required') && c.risk === 'loosening')).toBe(true);
  });

  it('classifies minimum_assurance raise as tightening', () => {
    const a = GOOD_POLICY_RULES;
    const b = {
      ...GOOD_POLICY_RULES,
      required_parties: {
        ...GOOD_POLICY_RULES.required_parties,
        initiator: { ...GOOD_POLICY_RULES.required_parties.initiator, minimum_assurance: 'high' },
      },
    };
    const d = diffPolicy(a, b);
    expect(d.risk).toBe('tightening');
  });

  it('classifies identical policies as no changes', () => {
    const d = diffPolicy(GOOD_POLICY_RULES, GOOD_POLICY_RULES);
    expect(d.changes).toEqual([]);
  });

  it('detects nonce_required removed (true → undefined) as loosening', () => {
    const a = GOOD_POLICY_RULES;
    const bBinding = { payload_hash_required: true, expiry_minutes: 10 };  // nonce_required key absent
    const b = { ...GOOD_POLICY_RULES, binding: bBinding };
    const d = diffPolicy(a, b);
    expect(d.risk).toBe('loosening');
    expect(d.changes.some(c => c.path.endsWith('.nonce_required') && c.risk === 'loosening')).toBe(true);
  });

  it('detects claim removal as loosening', () => {
    const a = GOOD_POLICY_RULES;
    const b = {
      ...GOOD_POLICY_RULES,
      required_parties: {
        ...GOOD_POLICY_RULES.required_parties,
        initiator: { required_claims: ['entity_ref'], minimum_assurance: 'substantial' },
      },
    };
    const d = diffPolicy(a, b);
    expect(d.changes.some(c => c.path.endsWith('.required_claims') && c.risk === 'loosening')).toBe(true);
  });
});
