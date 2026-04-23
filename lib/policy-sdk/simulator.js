/**
 * EP Policy Simulator
 *
 * Runs a policy against synthetic or real scenarios and returns a deterministic
 * evaluation trace. The goal is pre-deployment validation: before shipping a
 * policy, author and reviewers run representative scenarios and inspect the
 * trace for unexpected accept/deny decisions.
 *
 * The simulator re-uses the production invariant functions so the trace matches
 * what will actually execute at runtime. There is no parallel evaluator — that
 * would diverge and defeat the purpose.
 *
 * @license Apache-2.0
 */

import { runAllInvariants, ASSURANCE_RANK } from '@/lib/handshake/invariants.js';

/**
 * Simulate a policy evaluation for a single scenario.
 *
 * A scenario describes the inputs that would reach EP at evaluation time.
 * The simulator runs all production invariants and returns a structured trace.
 *
 * @param {object} params
 * @param {object} params.policy - Full policy row: { policy_id, policy_version, rules }.
 * @param {object} params.scenario - Scenario inputs:
 *   - handshake:    { interaction_id, assurance_level, required_assurance }
 *   - parties:      Array<{ party_role, entity_ref }>
 *   - presentations: Array<{ party_role, issuer_ref, disclosure_mode }>
 *   - binding:      { expires_at, nonce, payload_hash, ... }
 *   - authorities:  Array<{ key_id, status }>
 *   - authenticatedEntity: string (matched against presentation party)
 *   - verificationPayloadHash: string (re-computed at verify time)
 * @returns {{ decision: 'accept' | 'deny', trace: Array, violations: Array, duration_us: number }}
 */
export function simulateOne({ policy, scenario }) {
  if (!policy || !policy.rules) throw new Error('simulateOne: policy.rules is required');
  if (!scenario) throw new Error('simulateOne: scenario is required');

  const t0 = performance.now();
  const trace = [];

  // Build the context exactly as runAllInvariants expects at runtime.
  const context = {
    handshake: scenario.handshake || {},
    parties: scenario.parties || [],
    presentations: scenario.presentations || [],
    binding: scenario.binding || null,
    policy: policy,
    authorities: scenario.authorities || [],
    existingResults: scenario.existingResults || [],
    existingResult: scenario.existingResult || null,
    verificationPayloadHash: scenario.verificationPayloadHash || null,
    authenticatedEntity: scenario.authenticatedEntity || null,
  };

  trace.push({ step: 'context_built', keys: Object.keys(context) });

  const { passed, violations } = runAllInvariants(context);

  for (const v of violations) {
    trace.push({ step: 'invariant_failed', code: v.code, message: v.message });
  }

  if (passed) trace.push({ step: 'all_invariants_passed' });

  const duration_us = Math.round((performance.now() - t0) * 1000);

  return {
    decision: passed ? 'accept' : 'deny',
    trace,
    violations,
    duration_us,
  };
}

/**
 * Run a batch of scenarios with expected outcomes. Used as a test harness
 * for policy regression: every time a policy version bumps, rerun the batch.
 *
 * @param {object} params
 * @param {object} params.policy
 * @param {Array<{ name: string, scenario: object, expect: 'accept' | 'deny', expect_codes?: string[] }>} params.cases
 * @returns {{ ok: boolean, total: number, passed: number, failed: Array }}
 */
export function simulateBatch({ policy, cases }) {
  if (!Array.isArray(cases)) throw new Error('simulateBatch: cases must be an array');
  let passed = 0;
  const failed = [];

  for (const c of cases) {
    const result = simulateOne({ policy, scenario: c.scenario });
    let pass = result.decision === c.expect;

    // If the case specifies expected violation codes, verify at least those appeared.
    if (pass && c.expect === 'deny' && Array.isArray(c.expect_codes)) {
      const codes = new Set(result.violations.map(v => v.code));
      const missing = c.expect_codes.filter(code => !codes.has(code));
      if (missing.length) {
        pass = false;
        failed.push({ case: c.name, reason: `expected codes not triggered: ${missing.join(', ')}`, result });
        continue;
      }
    }

    if (pass) {
      passed++;
    } else {
      failed.push({
        case: c.name,
        reason: `expected ${c.expect}, got ${result.decision}`,
        violations: result.violations,
      });
    }
  }

  return {
    ok: failed.length === 0,
    total: cases.length,
    passed,
    failed,
  };
}

/**
 * Generate a minimal "happy path" scenario from a policy. Useful as a
 * starting point for authoring new scenario cases.
 *
 * @param {object} policy
 * @returns {object} scenario
 */
export function scenarioFromPolicy(policy) {
  if (!policy || !policy.rules) throw new Error('scenarioFromPolicy: policy.rules is required');
  const rules = policy.rules;

  // One party per required role, all with the minimum required assurance.
  const requiredRoles = Object.keys(rules.required_parties || {});
  const parties = requiredRoles.map((role, i) => ({
    party_role: role,
    entity_ref: `entity-${role}-${i}`,
  }));
  const presentations = requiredRoles.map((role) => ({
    party_role: role,
    issuer_ref: 'issuer-trusted-ca',
    disclosure_mode: 'full',
  }));

  const expiryMins = rules.binding?.expiry_minutes ?? 10;
  const expires = new Date(Date.now() + expiryMins * 60_000).toISOString();

  return {
    handshake: {
      interaction_id: 'interaction-test-1',
      assurance_level: 'high',
      required_assurance: 'substantial',
    },
    parties,
    presentations,
    binding: {
      expires_at: expires,
      nonce: 'a'.repeat(64),
      payload_hash: 'b'.repeat(64),
    },
    authorities: [{ key_id: 'issuer-trusted-ca', status: 'active' }],
    existingResults: [],
    existingResult: null,
    verificationPayloadHash: 'b'.repeat(64),
    // Leave authenticatedEntity null in the generated happy path. runAllInvariants
    // only runs the role-spoofing check when authenticatedEntity is set, and that
    // check is per-actor — in production it's called once per presenting actor
    // with that actor's authenticated identity. For a multi-party happy path
    // scenario, callers should run simulateOne once per actor, setting
    // authenticatedEntity to that actor's entity_ref each time.
    authenticatedEntity: null,
  };
}

// Re-export ranks for authors building custom scenarios.
export { ASSURANCE_RANK };
