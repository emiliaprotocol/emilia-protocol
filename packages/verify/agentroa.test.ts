// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { canonicalize } from './index.js';
import { actionDigest, verifyAuthorizationChain } from './evidence-chain.js';
import { verifyAgentROA } from './agentroa.js';

const POLICY_DIGEST = `sha256:${'a'.repeat(64)}`;
const SESSION_HASH = `sha256:${'b'.repeat(64)}`;
const INPUT_HASH = `sha256:${'c'.repeat(64)}`;
const NOW = '2026-04-08T14:03:00Z';

const rootKey = crypto.generateKeyPairSync('ed25519');
const delegateKey = crypto.generateKeyPairSync('ed25519');
const gatewayKey = crypto.generateKeyPairSync('ed25519');

function spki(keyPair) {
  return keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}

function sign(body, signer, keyPair) {
  const sig = crypto.sign(
    null,
    Buffer.from(canonicalize(body), 'utf8'),
    keyPair.privateKey,
  ).toString('base64url');
  return { ...structuredClone(body), signatures: [{ signer, alg: 'EdDSA', sig }] };
}

function makeBundle() {
  const action = {
    capability: 'api:payments.transfer',
    target_service_id: 'payments-service',
    operation: 'transfer',
    input_hash: INPUT_HASH,
  };
  const root = sign({
    schema_version: '1.0',
    envelope_id: 'env:4a7c9f2b1e8d3a6f',
    issued_at: '2026-04-08T14:00:00Z',
    expires_at: '2026-04-08T14:10:00Z',
    session: {
      session_id: 'sess:8b3d0e7f2a1c9b4e',
      channel: 'api',
      agent_id: 'aha:acme/ops/root-agent',
    },
    authorized_scope: {
      capabilities: ['api:payments.transfer', 'api:payments.read'],
      max_delegation_depth: 2,
      cross_org_permitted: false,
      budget_ceiling: 100,
      budget_unit: 'USD',
      price_class: 3,
      slo_class: 2,
    },
    policy: {
      policy_id: 'payments-v4',
      policy_version: '4.2.1',
      policy_digest: POLICY_DIGEST,
    },
    authorization: {
      auth_strength: 'session_only',
      approval_state: 'not_required',
    },
    evidence: {
      session_hash: SESSION_HASH,
      model_provenance: ['example:model:v1'],
    },
  }, 'policy-engine:prod', rootKey);

  const ara = sign({
    schema_version: '1.0',
    ara_id: 'ara:9c4e1f8a2b7d3e0f',
    issued_at: '2026-04-08T14:02:00Z',
    upstream_ref: {
      ref_type: 'roa_envelope',
      ref_id: root.envelope_id,
      ref_digest: digest(root),
    },
    delegating_agent: {
      agent_id: root.session.agent_id,
      session_id: root.session.session_id,
    },
    delegated_agent: {
      agent_id: 'aha:acme/ops/payment-agent',
    },
    delegated_scope: {
      capabilities: ['api:payments.transfer'],
      max_delegation_depth: 1,
      budget_ceiling: 50,
      budget_unit: 'USD',
      price_class: 2,
      slo_class: 3,
    },
    policy: {
      policy_digest: POLICY_DIGEST,
      policy_version: '4.2.1',
    },
  }, root.session.agent_id, rootKey);

  const chain = [root, ara];
  const aer = sign({
    schema_version: '1.0',
    aer_id: 'aer:2f5a8c1d4e7b0f3a',
    produced_at: '2026-04-08T14:02:30Z',
    enforcement_outcome: 'permit',
    enforcement_mode: 'normal',
    deployment_topology: 'topology_d_domain_boundary',
    session: {
      session_id: root.session.session_id,
      agent_id: ara.delegated_agent.agent_id,
    },
    action,
    policy: {
      policy_id: root.policy.policy_id,
      policy_digest: root.policy.policy_digest,
    },
    chain_summary: {
      chain_depth: 1,
      root_envelope_id: root.envelope_id,
      chain_digest: digest(chain),
    },
    border_gateway: {
      gateway_id: 'gateway:prod-us-east-1',
      gateway_version: '1.1.0',
    },
  }, 'gateway:prod-us-east-1', gatewayKey);

  const bundle = { chain, aer };
  Object.defineProperty(bundle, 'action', {
    value: action,
    enumerable: false,
    writable: true,
  });
  return bundle;
}

function makeContext(bundle, overrides = {}) {
  return {
    keysByType: {
      agentroa: {
        roa: { 'policy-engine:prod': spki(rootKey) },
        ara: {
          'aha:acme/ops/root-agent': spki(rootKey),
          'aha:acme/ops/payment-agent': spki(delegateKey),
        },
        aer: { 'gateway:prod-us-east-1': spki(gatewayKey) },
      },
    },
    policiesByType: {
      agentroa: {
        expected_policy_id: 'payments-v4',
        expected_policy_version: '4.2.1',
        expected_policy_digest: POLICY_DIGEST,
        allow_degraded: false,
        allowed_topologies: ['topology_d_domain_boundary'],
        capability_manifest: {},
      },
    },
    verificationTime: NOW,
    action: bundle.action,
    ...overrides,
  };
}

function resignRoot(bundle, mutate) {
  const body = structuredClone(bundle.chain[0]);
  delete body.signatures;
  mutate(body);
  bundle.chain[0] = sign(body, 'policy-engine:prod', rootKey);
  const araBody = structuredClone(bundle.chain[1]);
  delete araBody.signatures;
  araBody.upstream_ref.ref_digest = digest(bundle.chain[0]);
  bundle.chain[1] = sign(araBody, bundle.chain[0].session.agent_id, rootKey);
  resignAER(bundle, () => {});
}

function resignARA(bundle, mutate, signer = bundle.chain[0].session.agent_id) {
  const body = structuredClone(bundle.chain[1]);
  delete body.signatures;
  mutate(body);
  bundle.chain[1] = sign(body, signer, rootKey);
  resignAER(bundle, () => {});
}

function resignAER(bundle, mutate, recomputeChainDigest = true) {
  const body = structuredClone(bundle.aer);
  delete body.signatures;
  mutate(body);
  if (recomputeChainDigest) body.chain_summary.chain_digest = digest(bundle.chain);
  bundle.aer = sign(body, 'gateway:prod-us-east-1', gatewayKey);
}

function appendSecondHop(bundle) {
  const parent = bundle.chain.at(-1);
  const second = sign({
    schema_version: '1.0',
    ara_id: 'ara:1234567890abcdef',
    issued_at: '2026-04-08T14:02:15Z',
    upstream_ref: {
      ref_type: 'ara',
      ref_id: parent.ara_id,
      ref_digest: digest(parent),
    },
    delegating_agent: {
      agent_id: parent.delegated_agent.agent_id,
      session_id: bundle.chain[0].session.session_id,
    },
    delegated_agent: {
      agent_id: 'aha:acme/ops/settlement-agent',
    },
    delegated_scope: {
      capabilities: ['api:payments.transfer'],
      max_delegation_depth: 0,
      budget_ceiling: 25,
      budget_unit: 'USD',
      price_class: 1,
      slo_class: 4,
    },
    policy: {
      policy_digest: POLICY_DIGEST,
      policy_version: '4.2.1',
    },
  }, parent.delegated_agent.agent_id, delegateKey);
  bundle.chain.push(second);
  resignAER(bundle, (aer) => {
    aer.session.agent_id = second.delegated_agent.agent_id;
    aer.chain_summary.chain_depth = 2;
  });
}

test('verifies a pinned AgentROA -01 chain and returns its exact AEC action binding', () => {
  const bundle = makeBundle();
  const result = verifyAgentROA(bundle, makeContext(bundle));

  assert.deepEqual(result, {
    valid: true,
    verified: true,
    action_digest: `sha256:${actionDigest(bundle.action)}`,
    decision: 'permit',
    pre_execution: true,
    execution_proven: false,
    enforcement_mode: 'normal',
    chain_depth: 1,
    reason: null,
  });
});

test('composes as a real AEC verifier without an action-digest echo stub', () => {
  const bundle = makeBundle();
  const context = makeContext(bundle);
  const chain = {
    '@version': 'EP-AEC-v1',
    action: bundle.action,
    action_digest: `sha256:${actionDigest(bundle.action)}`,
    requirement: 'agentroa',
    components: [{ type: 'agentroa', evidence: bundle }],
  };
  const result = verifyAuthorizationChain(chain, {
    verifiers: { agentroa: verifyAgentROA },
    keysByType: context.keysByType,
    policiesByType: context.policiesByType,
    verificationTime: context.verificationTime,
    requirement: 'agentroa',
    expectedAction: bundle.action,
  });

  assert.equal(result.satisfied, true, result.reasons.join('; '));
  assert.deepEqual(result.components, [{
    type: 'agentroa',
    label: 'agentroa',
    valid: true,
    bound: true,
    reason: null,
  }]);
});

test('verifies every signature, parent digest, and narrowing step in a two-hop chain', () => {
  const bundle = makeBundle();
  appendSecondHop(bundle);
  let result = verifyAgentROA(bundle, makeContext(bundle));
  assert.equal(result.valid, true, result.reason);
  assert.equal(result.chain_depth, 2);

  const second = structuredClone(bundle.chain[2]);
  delete second.signatures;
  second.upstream_ref.ref_digest = `sha256:${'f'.repeat(64)}`;
  bundle.chain[2] = sign(second, second.delegating_agent.agent_id, delegateKey);
  resignAER(bundle, () => {});
  result = verifyAgentROA(bundle, makeContext(bundle));
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'ara_parent_digest_mismatch');

  const duplicate = makeBundle();
  appendSecondHop(duplicate);
  const duplicateBody = structuredClone(duplicate.chain[2]);
  delete duplicateBody.signatures;
  duplicateBody.ara_id = duplicate.chain[1].ara_id;
  duplicate.chain[2] = sign(
    duplicateBody,
    duplicateBody.delegating_agent.agent_id,
    delegateKey,
  );
  resignAER(duplicate, () => {});
  result = verifyAgentROA(duplicate, makeContext(duplicate));
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'duplicate_ara_id');
});

test('refuses unpinned, wrong-role, non-Ed25519, and invalid signatures', () => {
  for (const [name, mutateContext, mutateBundle, reason] of [
    ['unpinned root', (ctx) => { ctx.keysByType.agentroa.roa = {}; }, () => {}, 'unpinned_roa_signer'],
    ['root key reused as gateway', (ctx) => {
      ctx.keysByType.agentroa.aer['gateway:prod-us-east-1'] = spki(rootKey);
    }, () => {}, 'invalid_aer_signature'],
    ['non-Ed25519 key', (ctx) => {
      const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      ctx.keysByType.agentroa.roa['policy-engine:prod'] = spki(ec);
    }, () => {}, 'invalid_roa_key'],
    ['tampered root', () => {}, (bundle) => { bundle.chain[0].expires_at = '2026-04-08T14:11:00Z'; }, 'invalid_roa_signature'],
    ['tampered ARA', () => {}, (bundle) => { bundle.chain[1].delegated_agent.agent_id = 'aha:acme/ops/attacker'; }, 'invalid_ara_signature'],
    ['tampered AER', () => {}, (bundle) => { bundle.aer.action.operation = 'steal'; }, 'invalid_aer_signature'],
  ]) {
    const bundle = makeBundle();
    mutateBundle(bundle);
    const context = makeContext(bundle);
    mutateContext(context);
    const result = verifyAgentROA(bundle, context);
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
  }
});

test('strict closed validation rejects unknown fields at every signed layer', () => {
  const cases = [
    ['bundle', (bundle) => { bundle.unexpected = true; }],
    ['root', (bundle) => resignRoot(bundle, (root) => { root.unexpected = true; })],
    ['root session', (bundle) => resignRoot(bundle, (root) => { root.session.unexpected = true; })],
    ['root null device reference', (bundle) => resignRoot(bundle, (root) => { root.session.device_attestation_ref = null; })],
    ['root scope', (bundle) => resignRoot(bundle, (root) => { root.authorized_scope.unexpected = true; })],
    ['root signature', (bundle) => { bundle.chain[0].signatures[0].unexpected = true; }],
    ['ARA', (bundle) => resignARA(bundle, (ara) => { ara.unexpected = true; })],
    ['ARA upstream ref', (bundle) => resignARA(bundle, (ara) => { ara.upstream_ref.unexpected = true; })],
    ['ARA scope', (bundle) => resignARA(bundle, (ara) => { ara.delegated_scope.unexpected = true; })],
    ['AER', (bundle) => resignAER(bundle, (aer) => { aer.unexpected = true; })],
    ['AER action', (bundle) => resignAER(bundle, (aer) => { aer.action.unexpected = true; })],
    ['AER gateway', (bundle) => resignAER(bundle, (aer) => { aer.border_gateway.unexpected = true; })],
  ];
  for (const [name, mutate] of cases) {
    const bundle = makeBundle();
    mutate(bundle);
    const result = verifyAgentROA(bundle, makeContext(bundle));
    assert.equal(result.valid, false, name);
    assert.match(result.reason, /malformed|unknown_field/, name);
  }
});

test('refuses missing time, expired/future envelopes, and impossible event ordering', () => {
  for (const [name, mutate, context, reason] of [
    ['missing verifier time', () => {}, (bundle) => makeContext(bundle, { verificationTime: undefined }), 'invalid_verification_time'],
    ['expired', () => {}, (bundle) => makeContext(bundle, { verificationTime: '2026-04-08T14:11:00Z' }), 'roa_expired'],
    ['not yet valid', () => {}, (bundle) => makeContext(bundle, { verificationTime: '2026-04-08T13:59:59Z' }), 'roa_not_yet_valid'],
    ['ARA before root', (bundle) => resignARA(bundle, (ara) => { ara.issued_at = '2026-04-08T13:59:00Z'; }), makeContext, 'ara_time_outside_session'],
    ['AER before delegation', (bundle) => resignAER(bundle, (aer) => { aer.produced_at = '2026-04-08T14:01:00Z'; }), makeContext, 'aer_time_before_chain'],
    ['AER after root expiry', (bundle) => resignAER(bundle, (aer) => { aer.produced_at = '2026-04-08T14:11:00Z'; }), makeContext, 'aer_time_outside_session'],
  ]) {
    const bundle = makeBundle();
    mutate(bundle);
    const result = verifyAgentROA(bundle, context(bundle));
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
  }
});

test('requires a complete relying-party policy pin and exact current policy', () => {
  for (const [name, mutate, reason] of [
    ['missing profile', (ctx) => { delete ctx.policiesByType.agentroa; }, 'missing_policy_profile'],
    ['wrong policy id', (ctx) => { ctx.policiesByType.agentroa.expected_policy_id = 'other'; }, 'policy_id_mismatch'],
    ['wrong policy version', (ctx) => { ctx.policiesByType.agentroa.expected_policy_version = '5'; }, 'policy_version_mismatch'],
    ['wrong policy digest', (ctx) => { ctx.policiesByType.agentroa.expected_policy_digest = `sha256:${'f'.repeat(64)}`; }, 'policy_digest_mismatch'],
    ['unknown profile knob', (ctx) => { ctx.policiesByType.agentroa.unexpected = true; }, 'malformed_policy_profile'],
  ]) {
    const bundle = makeBundle();
    const context = makeContext(bundle);
    mutate(context);
    const result = verifyAgentROA(bundle, context);
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
  }
});

test('enforces ARA parent digests, identity continuity, policy continuity, and depth', () => {
  for (const [name, mutate, reason, mutateContext = () => {}] of [
    ['parent digest', (bundle) => resignARA(bundle, (ara) => { ara.upstream_ref.ref_digest = `sha256:${'f'.repeat(64)}`; }), 'ara_parent_digest_mismatch'],
    ['parent type', (bundle) => resignARA(bundle, (ara) => { ara.upstream_ref.ref_type = 'ara'; }), 'ara_parent_reference_mismatch'],
    ['parent id', (bundle) => resignARA(bundle, (ara) => { ara.upstream_ref.ref_id = 'env:0000000000000000'; }), 'ara_parent_reference_mismatch'],
    ['delegator', (bundle) => resignARA(
      bundle,
      (ara) => { ara.delegating_agent.agent_id = 'aha:acme/ops/other'; },
      'aha:acme/ops/other',
    ), 'ara_delegator_mismatch', (context) => {
      context.keysByType.agentroa.ara['aha:acme/ops/other'] = spki(rootKey);
    }],
    ['session', (bundle) => resignARA(bundle, (ara) => { ara.delegating_agent.session_id = 'sess:other'; }), 'ara_session_mismatch'],
    ['policy digest', (bundle) => resignARA(bundle, (ara) => { ara.policy.policy_digest = `sha256:${'f'.repeat(64)}`; }), 'ara_policy_mismatch'],
    ['policy version', (bundle) => resignARA(bundle, (ara) => { ara.policy.policy_version = 'wrong'; }), 'ara_policy_mismatch'],
    ['remaining depth not narrower', (bundle) => resignARA(bundle, (ara) => { ara.delegated_scope.max_delegation_depth = 2; }), 'delegation_depth_not_narrowed'],
  ]) {
    const bundle = makeBundle();
    mutate(bundle);
    const context = makeContext(bundle);
    mutateContext(context);
    const result = verifyAgentROA(bundle, context);
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
  }
});

test('enforces every monotonic scope dimension and refuses omitted inherited constraints', () => {
  for (const [name, mutate, reason] of [
    ['capability expansion', (scope) => { scope.capabilities.push('api:payments.admin'); }, 'scope_expansion'],
    ['budget expansion', (scope) => { scope.budget_ceiling = 101; }, 'budget_expansion'],
    ['budget omission', (scope) => { delete scope.budget_ceiling; delete scope.budget_unit; }, 'budget_constraint_omitted'],
    ['budget unit change', (scope) => { scope.budget_unit = 'EUR'; }, 'budget_unit_mismatch'],
    ['price expansion', (scope) => { scope.price_class = 4; }, 'price_class_expansion'],
    ['price omission', (scope) => { delete scope.price_class; }, 'price_class_constraint_omitted'],
    ['SLO relaxation', (scope) => { scope.slo_class = 1; }, 'slo_relaxation'],
    ['SLO omission', (scope) => { delete scope.slo_class; }, 'slo_constraint_omitted'],
  ]) {
    const bundle = makeBundle();
    resignARA(bundle, (ara) => mutate(ara.delegated_scope));
    const result = verifyAgentROA(bundle, makeContext(bundle));
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
  }
});

test('wildcards require a relying-party-pinned manifest instead of verifier guesswork', () => {
  const bundle = makeBundle();
  resignRoot(bundle, (root) => {
    root.authorized_scope.capabilities = ['api:payments.*'];
  });

  let result = verifyAgentROA(bundle, makeContext(bundle));
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'ambiguous_capability_wildcard');

  const context = makeContext(bundle);
  context.policiesByType.agentroa.capability_manifest = {
    'api:payments.*': ['api:payments.transfer', 'api:payments.read'],
  };
  result = verifyAgentROA(bundle, context);
  assert.equal(result.valid, true, result.reason);
});

test('cross-organization delegation is refused unless the signed root permits it', () => {
  const bundle = makeBundle();
  resignARA(bundle, (ara) => { ara.delegated_agent.agent_id = 'aha:other/ops/payment-agent'; });
  resignAER(bundle, (aer) => { aer.session.agent_id = 'aha:other/ops/payment-agent'; });
  let result = verifyAgentROA(bundle, makeContext(bundle));
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'cross_org_delegation_refused');

  resignRoot(bundle, (root) => { root.authorized_scope.cross_org_permitted = true; });
  result = verifyAgentROA(bundle, makeContext(bundle));
  assert.equal(result.valid, true, result.reason);
});

test('AER must bind the final agent, session, policy, chain, capability, and exact action', () => {
  for (const [name, mutate, reason, recomputeChainDigest = true] of [
    ['agent', (aer) => { aer.session.agent_id = 'aha:acme/ops/other'; }, 'aer_agent_mismatch'],
    ['session', (aer) => { aer.session.session_id = 'sess:other'; }, 'aer_session_mismatch'],
    ['policy id', (aer) => { aer.policy.policy_id = 'other'; }, 'aer_policy_mismatch'],
    ['policy digest', (aer) => { aer.policy.policy_digest = `sha256:${'f'.repeat(64)}`; }, 'aer_policy_mismatch'],
    ['chain depth', (aer) => { aer.chain_summary.chain_depth = 0; }, 'aer_chain_summary_mismatch'],
    ['root id', (aer) => { aer.chain_summary.root_envelope_id = 'env:0000000000000000'; }, 'aer_chain_summary_mismatch'],
    ['chain digest', (aer) => { aer.chain_summary.chain_digest = `sha256:${'f'.repeat(64)}`; }, 'aer_chain_digest_mismatch', false],
    ['capability', (aer) => { aer.action.capability = 'api:payments.read'; }, 'aer_action_mismatch'],
    ['operation', (aer) => { aer.action.operation = 'read'; }, 'aer_action_mismatch'],
    ['input', (aer) => { aer.action.input_hash = `sha256:${'d'.repeat(64)}`; }, 'aer_action_mismatch'],
  ]) {
    const bundle = makeBundle();
    resignAER(bundle, mutate, recomputeChainDigest);
    const result = verifyAgentROA(bundle, makeContext(bundle));
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
  }
});

test('DENY is verified negative evidence, never a valid AEC permit leg', () => {
  const bundle = makeBundle();
  resignAER(bundle, (aer) => {
    aer.enforcement_outcome = 'deny';
    aer.denial_reason = 'capability_not_in_scope';
  });
  const result = verifyAgentROA(bundle, makeContext(bundle));
  assert.deepEqual(result, {
    valid: false,
    verified: true,
    action_digest: `sha256:${actionDigest(bundle.action)}`,
    decision: 'deny',
    pre_execution: true,
    execution_proven: false,
    enforcement_mode: 'normal',
    chain_depth: 1,
    reason: 'aer_denied',
  });
});

test('degraded receipts require explicit relying-party opt-in and topology is pinned', () => {
  const bundle = makeBundle();
  resignAER(bundle, (aer) => { aer.enforcement_mode = 'degraded'; });
  let context = makeContext(bundle);
  let result = verifyAgentROA(bundle, context);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'degraded_mode_refused');

  context = makeContext(bundle);
  context.policiesByType.agentroa.allow_degraded = true;
  result = verifyAgentROA(bundle, context);
  assert.equal(result.valid, true, result.reason);

  context.policiesByType.agentroa.allowed_topologies = ['topology_c_egress_gateway'];
  result = verifyAgentROA(bundle, context);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'deployment_topology_refused');
});

test('malformed and hostile native inputs return a closed refusal without throwing', () => {
  for (const value of [null, [], {}, { chain: [], aer: {} }]) {
    assert.doesNotThrow(() => verifyAgentROA(value, {}));
    assert.equal(verifyAgentROA(value, {}).valid, false);
  }

  const hostile = new Proxy({}, { ownKeys() { throw new Error('trap'); } });
  let result;
  assert.doesNotThrow(() => { result = verifyAgentROA(hostile, hostile); });
  assert.deepEqual(result, {
    valid: false,
    verified: false,
    action_digest: null,
    decision: null,
    pre_execution: false,
    execution_proven: false,
    enforcement_mode: null,
    chain_depth: null,
    reason: 'unexpected_verification_error',
  });
});
