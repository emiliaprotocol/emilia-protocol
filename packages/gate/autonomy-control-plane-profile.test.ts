// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {
  AUTONOMY_CONTROL_PLANE_VERSION,
  AutonomyControlPlaneValidationError,
  compileAutonomyControlPlaneProfile,
} from './autonomy-control-plane-profile.js';

const D = (character: string) => `sha256:${character.repeat(64)}`;
const C = (character: string) => `caid:1:code.change.1:jcs-sha256:${character.repeat(43)}`;

function profile(): any {
  return {
    '@version': AUTONOMY_CONTROL_PLANE_VERSION,
    control_plane_id: 'engineering-agent',
    version: 1,
    valid_from: '2026-07-26T12:00:00Z',
    expires_at: '2026-07-27T12:00:00Z',
    root: {
      objective_id: 'objective:repair-ci',
      root_caid: C('A'), action_digest: D('1'),
      actions: ['code.propose', 'code.canary', 'code.promote'],
      audiences: ['repo:emilia'], budget: { cents: 1000, calls: 20 },
      expires_at: '2026-07-27T12:00:00Z', initiator_id: 'human:owner',
      authorization: {
        evidence_type: 'ep-quorum', verifier_profile: 'ep-quorum:v1',
        policy_digest: D('2'), max_age_sec: 900, require_initiator_exclusion: true,
      },
    },
    status: { verifier_profile: 'ep-status:v1', policy_digest: D('3'), max_age_sec: 60 },
    children: [
      {
        goal_id: 'goal:canary', parent_goal_id: 'root', phase: 'canary',
        caid: C('B'), action_digest: D('4'), action_type: 'code.canary', audience: 'repo:emilia',
        budget: { cents: 400, calls: 8 }, expires_at: '2026-07-27T10:00:00Z',
        capability_template_digest: D('5'),
        proposer_id: 'agent:builder', evaluator_id: 'agent:evaluator', executor_id: 'service:runner',
        change: { before_digest: D('6'), after_digest: D('7'), changed_paths: ['src/a.ts'] },
        fitness: { suite_digest: D('8'), environment_digest: D('9'), policy_digest: D('a'), max_age_sec: 300 },
        canary: { exposure_percent: 10, max_exposure_percent: 10, policy_digest: D('b'), max_age_sec: 300 },
        rollback: null,
      },
      {
        goal_id: 'goal:promote', parent_goal_id: 'root', phase: 'promote',
        caid: C('C'), action_digest: D('c'), action_type: 'code.promote', audience: 'repo:emilia',
        budget: { cents: 500, calls: 10 }, expires_at: '2026-07-27T11:00:00Z',
        capability_template_digest: D('d'),
        proposer_id: 'agent:builder', evaluator_id: 'human:reviewer', executor_id: 'service:deployer',
        change: { before_digest: D('6'), after_digest: D('7'), changed_paths: ['src/a.ts'] },
        fitness: { suite_digest: D('8'), environment_digest: D('9'), policy_digest: D('e'), max_age_sec: 300 },
        canary: { goal_id: 'goal:canary', exposure_percent: 100, max_exposure_percent: 100, policy_digest: D('f'), max_age_sec: 300 },
        rollback: null,
      },
    ],
  };
}

function code(run: () => unknown): string | undefined {
  try { run(); return undefined; } catch (error) {
    assert.ok(error instanceof AutonomyControlPlaneValidationError);
    return error.code;
  }
}

test('compiles a closed profile into one existing Trust Program per exact child action', () => {
  const compiled = compileAutonomyControlPlaneProfile(profile());
  assert.equal(compiled.version, AUTONOMY_CONTROL_PLANE_VERSION);
  assert.equal(compiled.programs.length, 2);
  assert.equal(compiled.programs[0]?.['@version'], 'EP-GATE-TRUST-PROGRAM-PROFILE-v1');
  assert.equal(compiled.programs[0]?.root_caid, C('B'));
  assert.equal(compiled.programs[0]?.stages[0]?.requirements[0]?.evidence_type, 'ep-root-objective');
  assert.equal(compiled.programs[1]?.stages.some((stage: any) => stage.stage_id === 'canary-evidence'), true);
  assert.equal(compiled.profile_digest.startsWith('sha256:'), true);
});

test('requires a human Class-A or quorum root authorization, never an organization signature', () => {
  const candidate = profile();
  candidate.root.authorization.evidence_type = 'organization-signature';
  assert.equal(code(() => compileAutonomyControlPlaneProfile(candidate)), 'root_human_authorization_required');
});

test('refuses child action, audience, expiry, or per-child budget widening', () => {
  for (const mutate of [
    (value: any) => { value.children[0].action_type = 'code.delete'; },
    (value: any) => { value.children[0].audience = 'repo:other'; },
    (value: any) => { value.children[0].expires_at = '2026-07-28T12:00:00Z'; },
    (value: any) => { value.children[0].budget.cents = 1001; },
  ]) {
    const candidate = profile(); mutate(candidate);
    assert.equal(code(() => compileAutonomyControlPlaneProfile(candidate)), 'child_authority_widening');
  }
});

test('conserves aggregate sibling budgets independently across cents and calls', () => {
  const cents = profile(); cents.children[1].budget.cents = 601;
  assert.equal(code(() => compileAutonomyControlPlaneProfile(cents)), 'aggregate_sibling_budget_exceeded');
  const calls = profile(); calls.children[1].budget.calls = 13;
  assert.equal(code(() => compileAutonomyControlPlaneProfile(calls)), 'aggregate_sibling_budget_exceeded');
});

test('requires exact nonempty diff bindings and refuses role collapse', () => {
  const sameDigest = profile(); sameDigest.children[0].change.after_digest = D('6');
  assert.equal(code(() => compileAutonomyControlPlaneProfile(sameDigest)), 'change_binding_invalid');
  const duplicatePath = profile(); duplicatePath.children[0].change.changed_paths = ['src/a.ts', 'src/a.ts'];
  assert.equal(code(() => compileAutonomyControlPlaneProfile(duplicatePath)), 'change_binding_invalid');
  const collapsed = profile(); collapsed.children[0].evaluator_id = 'agent:builder';
  assert.equal(code(() => compileAutonomyControlPlaneProfile(collapsed)), 'independent_roles_required');
});

test('requires pinned, freshness-bounded fitness evidence for every child', () => {
  const candidate = profile(); candidate.children[0].fitness.max_age_sec = 0;
  assert.equal(code(() => compileAutonomyControlPlaneProfile(candidate)), 'fitness_policy_invalid');
});

test('requires bounded canary evidence before promotion', () => {
  const missing = profile(); missing.children[1].canary = null;
  assert.equal(code(() => compileAutonomyControlPlaneProfile(missing)), 'promotion_requires_canary');
  const unknown = profile(); unknown.children[1].canary.goal_id = 'goal:unknown';
  assert.equal(code(() => compileAutonomyControlPlaneProfile(unknown)), 'promotion_requires_canary');
  const excessive = profile(); excessive.children[0].canary.exposure_percent = 11;
  assert.equal(code(() => compileAutonomyControlPlaneProfile(excessive)), 'canary_exposure_exceeded');
});

test('rollback is a separately authorized action with a new CAID', () => {
  const candidate = profile();
  candidate.children.push({
    ...structuredClone(candidate.children[0]), goal_id: 'goal:rollback', phase: 'rollback',
    caid: C('D'), action_digest: D('0'), action_type: 'code.propose', budget: { cents: 50, calls: 1 },
    canary: null,
    rollback: { original_caid: C('B'), authorization_policy_digest: D('5') },
  });
  assert.equal(compileAutonomyControlPlaneProfile(candidate).programs.length, 3);
  candidate.children[2].caid = C('B');
  assert.equal(code(() => compileAutonomyControlPlaneProfile(candidate)), 'child_identity_replayed');
});

test('unknown fields and cyclic child derivation fail closed', () => {
  const extra = profile(); extra.root.surprise = true;
  assert.equal(code(() => compileAutonomyControlPlaneProfile(extra)), 'profile_shape_invalid');
  const cycle = profile(); cycle.children[0].parent_goal_id = 'goal:promote';
  cycle.children[1].parent_goal_id = 'goal:canary';
  assert.equal(code(() => compileAutonomyControlPlaneProfile(cycle)), 'child_goal_cycle');
});

test('executes every published autonomy control-plane conformance vector', () => {
  const suite = JSON.parse(fs.readFileSync(
    new URL('../../conformance/vectors/autonomy-control-plane.v1.json', import.meta.url),
    'utf8',
  ));
  for (const vector of suite.vectors) {
    const candidate = profile();
    if (vector.mutation) {
      const segments = vector.mutation.path.slice(1).split('/');
      let target = candidate;
      for (const segment of segments.slice(0, -1)) target = target[segment];
      target[segments.at(-1)] = vector.mutation.value;
    }
    if (vector.expect.valid) {
      assert.equal(compileAutonomyControlPlaneProfile(candidate).programs.length, vector.expect.programs, vector.case_id);
    } else {
      assert.equal(code(() => compileAutonomyControlPlaneProfile(candidate)), vector.expect.code, vector.case_id);
    }
  }
});
