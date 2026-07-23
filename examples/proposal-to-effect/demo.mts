// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createEg1Harness,
  createTrustedActionFirewall,
  EG1_DEFAULT_SELECTOR,
} from '../../packages/gate/index.js';
import {
  createProposalToEffect,
  proposalToEffectConsumptionNonce,
} from '../../packages/gate/proposal-to-effect.js';
import {
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  pinnedConfigDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from '../../packages/verify/aeb-adapter-contract.js';

const NOW = '2026-07-22T12:00:00Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;

function entry(id: string, kind: string, definition: unknown): any {
  const value: any = { kind, version: '1', status: 'active', definition };
  value.definition_digest = registryEntryDigest(id, value);
  return value;
}

const harness = createEg1Harness({ now: () => Date.parse(NOW) });
const evaluator = crypto.generateKeyPairSync('ed25519');
const adapter: any = {
  id: 'demo:human-authorization',
  version: '1',
  verifyNative({ artifact, status, trust_roots }: any) {
    const trusted = trust_roots.includes(artifact.root);
    return {
      native_verification: trusted ? 'VERIFIED' : 'FAILED',
      acceptance: trusted ? 'ACCEPTED' : 'REJECTED',
      evidence_digest: digestAeb(artifact),
      replay_unit: digestAeb({ root: artifact.root, caid: artifact.caid }),
      status_digest: digestAeb({
        checked_at: status.checked_at,
        expires_at: status.expires_at,
        revocation_checked: status.revocation_checked,
        revoked: status.revoked,
        consumed: status.consumed,
        unavailable: status.unavailable === true,
      }),
      evidence_role: 'human-authorization',
      subject: { id: 'human:alice', kind: 'human' },
      reasons: trusted ? [] : ['native_trust_root_not_pinned'],
    };
  },
  mapAction({ artifact }: any) {
    return {
      mapping: 'MATCH',
      caid: artifact.caid,
      action_digest: digestAeb(artifact.action),
      reasons: [],
    };
  },
};

const profile: any = {
  version: 'payment-release-v1',
  definition: { action_type: 'payment.release' },
  registry_entry_ref: 'mapping:payment-release',
  mapper_id: 'mapper:payment-release',
  resolver: {
    id: 'resolver:payment-release',
    version: '1',
    implementation_digest: digestAeb({ implementation: 'resolver:payment-release:1' }),
  },
  semantic_equivalence: {
    assertion: 'EQUIVALENT_UNDER_PROFILE',
    loss_policy: 'NO_MATERIAL_FIELD_LOSS',
    omitted_material_fields: [],
    omitted_nonmaterial_fields: [],
  },
};
profile.profile_digest = mappingProfileDigest('payment-release', profile);
const entries: any = {
  'mapping:payment-release': entry('mapping:payment-release', 'mapping-profile', { profile_digest: profile.profile_digest }),
  'role:human-authorization': entry('role:human-authorization', 'evidence-role', {
    role: 'human-authorization', subject_kinds: ['human'],
  }),
};
const registry: any = {
  '@version': 'EP-EVIDENCE-REGISTRY-v1',
  registry_id: 'registry:proposal-to-effect-demo',
  epoch: 1,
  entries,
};
registry.registry_digest = unifiedRegistryDigest(registry);
const adapterPin: any = {
  version: '1', trust_roots: ['root:demo'], config: { mode: 'offline' }, max_status_age_sec: 300,
};
adapterPin.config_digest = adapterPinDigest(adapter.id, adapterPin);
const evaluatorPublicKey = evaluator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const aebConfig: any = {
  '@version': 'AEB-ADAPTER-v1',
  relying_party_id: 'rp:proposal-to-effect-demo',
  evaluator_keys: { 'eval:demo': { public_key: evaluatorPublicKey } },
  registry,
  accepted_mappers: ['mapper:payment-release'],
  adapters: { [adapter.id]: adapterPin },
  profiles: { 'payment-release': profile },
  requirements: {
    'requirement:proposal-to-effect': {
      '@version': 'AEB-REQUIREMENT-v1',
      all_of: ['human-authorization'],
      terms: [
        { type: 'initiator-exclusion', roles: ['human-authorization'] },
        { type: 'executor-exclusion', roles: ['human-authorization'] },
        { type: 'one-time-consumption' },
      ],
    },
  },
};
const artifact = { root: 'root:demo', caid: CAID, action: harness.action };
const evaluation = evaluateAebEvidence({
  config: aebConfig,
  adapters: { [adapter.id]: adapter },
  operation_id: 'operation:release-demo',
  consumption_nonce: proposalToEffectConsumptionNonce(
    'operation:release-demo',
    pinnedConfigDigest(aebConfig),
  ),
  initiator_id: 'agent:buyer',
  executor_id: 'agent:executor',
  requirement_ref: 'requirement:proposal-to-effect',
  caid: CAID,
  legs: [{
    adapter_id: adapter.id,
    profile_id: 'payment-release',
    artifact_ref: 'artifact:human-approval',
    artifact,
    status: {
      checked_at: '2026-07-22T11:59:00Z',
      expires_at: '2026-07-22T12:05:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
  }],
  evaluated_at: NOW,
  signer: { key_id: 'eval:demo', private_key: evaluator.privateKey },
}).record;

const states = new Map<string, 'RESERVED' | 'CONSUMED'>();
const nativeReplay = new Set<string>();
const aebStore: any = {
  durable: true,
  ownershipFenced: true,
  permanentConsumption: true,
  atomicReplayFenced: true,
  async reserve(key: string, replayKeys: readonly string[]) {
    if (states.has(key)) return false;
    if (replayKeys.some((replayKey) => nativeReplay.has(replayKey))) return 'NATIVE_REPLAY_CONFLICT';
    states.set(key, 'RESERVED');
    replayKeys.forEach((replayKey) => nativeReplay.add(replayKey));
    return 'RESERVED';
  },
  async commit(key: string) {
    if (states.get(key) !== 'RESERVED') return false;
    states.set(key, 'CONSUMED');
    return true;
  },
  async release(key: string) {
    if (states.get(key) !== 'RESERVED') return false;
    states.delete(key);
    // Demo-only single-process rollback. Production uses the PostgreSQL store,
    // which removes the operation's replay fences in the same transaction.
    nativeReplay.clear();
    return true;
  },
};
type AttemptState = 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED' | 'ESCALATED';
const attempts = new Map<string, { owner: string; state: AttemptState; binding: any }>();
const consequenceStore: any = {
  durable: true,
  ownershipFenced: true,
  compareAndSwap: true,
  atomicEvidenceBinding: true,
  async reserve(binding: any) {
    if (attempts.has(binding.attempt_id)) return { reserved: false, reason: 'consequence_attempt_conflict' };
    const owner = `demo-owner:${crypto.randomUUID()}`;
    attempts.set(binding.attempt_id, { owner, state: 'RESERVED', binding: structuredClone(binding) });
    return { reserved: true, owner };
  },
  async transition(input: any) {
    const row = attempts.get(input.attempt_id);
    if (!row || row.owner !== input.owner || row.binding.tenant_id !== input.tenant_id
        || row.state !== input.expected_state) return false;
    row.state = input.next_state;
    return true;
  },
  async reconcile(input: any) {
    const row = attempts.get(input.attempt_id);
    if (!row || row.owner !== input.owner || row.binding.tenant_id !== input.tenant_id
        || row.state !== input.expected_state) return false;
    row.state = input.next_state;
    return true;
  },
  async read(binding: any) {
    const row = attempts.get(binding.attempt_id);
    if (!row || row.binding.tenant_id !== binding.tenant_id
        || row.binding.provider_id !== binding.provider_id
        || row.binding.provider_account_id !== binding.provider_account_id
        || row.binding.environment !== binding.environment
        || row.binding.request_digest !== binding.request_digest) return null;
    return { state: row.state, evidence_digest: null };
  },
};
const gate = createTrustedActionFirewall({
  trustedKeys: [harness.publicKey],
  approverKeys: harness.approverKeys,
  rpId: harness.rpId,
  allowedOrigins: harness.allowedOrigins,
  allowEphemeralStore: true,
  now: () => Date.parse(NOW),
});
const controller = createProposalToEffect({
  gate,
  proposal_integrity: {
    hmac_sha256_key: crypto.createHash('sha256').update('proposal-to-effect-demo-key').digest(),
  },
  consequence: {
    tenant_id: 'tenant:demo',
    provider_id: 'provider:demo',
    provider_account_id: 'provider-account:demo',
    environment: 'demo',
    executor_id: 'agent:executor',
    store: consequenceStore,
  },
  profiles: {
    'payment-release': {
      id: 'payment-release',
      action_type: 'payment.release',
      selector: EG1_DEFAULT_SELECTOR,
      required_fields: Object.keys(harness.action),
      authorization: {
        authorization_endpoint: 'https://approve.example.test/v1/approvals',
        flow: 'EP-APPROVAL-v1',
      },
      aeb_requirement_ref: 'requirement:proposal-to-effect',
      ttl_sec: 300,
      canonicalize_action: (input: unknown) => ({
        action: structuredClone(input as Record<string, unknown>),
        caid: CAID,
      }),
    },
  },
  aeb: {
    config: aebConfig,
    adapters: { [adapter.id]: adapter },
    store: aebStore,
    resolve_artifacts: () => ({ 'artifact:human-approval': artifact }),
    // Demo fixture only. Production resolves EP-STATUS-v1 artifacts and runs
    // createProposalToEffectStatusVerifier with pinned authority/head state.
    currentStatusResolver: ({ leg }: any) => ({ artifact_ref: leg.artifact_ref }),
    statusVerifier: ({ status_artifact, expected }: any) => ({
      valid: status_artifact?.artifact_ref === expected.artifact_ref,
      outcome: status_artifact?.artifact_ref === expected.artifact_ref
        ? 'current_not_revoked' : 'indeterminate',
      status: status_artifact?.artifact_ref === expected.artifact_ref ? {
        checked_at: '2026-07-22T11:59:00Z',
        expires_at: '2026-07-22T12:05:00Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
      } : null,
    }),
    verify_provider_evidence: () => ({ valid: false, reason: 'demo_does_not_reconcile' }),
  },
  now: () => Date.parse(NOW),
});

const proposal = controller.prepare({
  proposal_id: 'proposal:release-demo',
  profile_id: 'payment-release',
  operation_id: 'operation:release-demo',
  initiator_id: 'agent:buyer',
  action: harness.action,
});
let effectCount = 0;
const executed = await controller.execute({ proposal, receipt: harness.mint(), evaluation }, async ({ action }: any) => {
  effectCount += 1;
  return { provider_reference: `release:${action.payment_instruction_id}` };
});
const replay = await controller.execute({ proposal, receipt: harness.mint(), evaluation }, async () => {
  effectCount += 1;
});

assert.equal(executed.ok, true);
assert.equal(replay.ok, false);
assert.equal(replay.reason, 'aeb_consumption_conflict');
assert.equal(effectCount, 1);
console.log(JSON.stringify({
  proposal: { caid: proposal.caid, action_digest: proposal.action_digest, authority: false },
  first_execution: { ok: executed.ok, aeb_state: executed.aeb.state },
  replay: { ok: replay.ok, reason: replay.reason },
  effect_count: effectCount,
}, null, 2));
