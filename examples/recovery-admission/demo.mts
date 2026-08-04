// SPDX-License-Identifier: Apache-2.0

import { generateKeyPairSync } from 'node:crypto';

import {
  ADMISSION_CURRENTNESS_VERSION,
  createMemoryAdmissionStore,
  type AdmissionSnapshotInput,
} from '../../packages/gate/admission-store.js';
import {
  RECOVERY_CAPABILITY_STATUS_VERSION,
  deriveRecoveryAdmissionSnapshotBindings,
  signRecoveryCapability,
} from '../../packages/gate/recovery-admission.js';
import {
  executeRecoveryAdmissionPostgresLocalAtomic,
} from '../../packages/gate/recovery-admission-postgres.js';

const d = (character: string) => `sha256:${character.repeat(64)}` as const;
const caid = `caid:1:operations.update.1:jcs-sha256:${'A'.repeat(43)}`;
const now = '2026-08-03T20:00:00.000Z';
const validUntil = '2026-08-03T20:30:00.000Z';
const admissionExpires = '2026-08-03T21:00:00.000Z';
const stateDomainDigest = d('3');
const adapterDigest = d('1');
const evidenceDigest = d('4');

const inputs: AdmissionSnapshotInput['inputs'] = [
  'candidate_manifest', 'runtime_measurement', 'test_result',
  'agent_evaluation_evidence', 'qualification_statement',
  'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
].map((role, index) => ({
  role: role as AdmissionSnapshotInput['inputs'][number]['role'],
  artifact_type: `artifact.${role}`,
  subject: role === 'candidate_manifest' || role === 'aeb'
    ? 'agent:recovery-demo' : `subject:${role}`,
  payload_digest: d(String((index % 9) + 1)),
  profile_digest: d('a'),
  verifier_id: `verifier:${role}`,
  trust_configuration_digest: d('b'),
  valid_until: admissionExpires,
}));

const admission: AdmissionSnapshotInput = {
  tenant_id: 'tenant:demo',
  admission_id: 'admission:recovery:01',
  operation_id: 'operation:recovery:01',
  candidate_manifest_digest: d('c'),
  runtime_measurement_digest: d('d'),
  candidate_custody: {
    request_construction: 'GATE',
    mutation_credential_custody: 'GATE',
    enforcement_placement: 'ACTUATOR',
    evidence_digest: d('e'),
  },
  assignment_digest: d('f'),
  qualification_policy_digest: d('0'),
  test_result_payload_digests: [d('1')],
  agent_evaluation_evidence_payload_digests: [d('2')],
  qualification_statement_payload_digest: d('3'),
  qualification_status: {
    authority_id: 'qualification-authority:primary',
    sequence: 1,
    head_payload_digest: d('4'),
    observed_at: now,
    expires_at: admissionExpires,
  },
  caid,
  action_digest: d('5'),
  effect_request_digest: d('6'),
  provider: {
    provider_id: 'provider:postgres:demo',
    account_id: 'account:production',
    environment: 'production',
  },
  executor_adapter_digest: adapterDigest,
  idempotency_key: 'idempotency:recovery:01',
  authorization_policy_digest: d('7'),
  trust_epoch: 1,
  trust_configuration_digest: d('8'),
  configuration_epoch: 1,
  configuration_digest: d('9'),
  inputs,
  resource_reservations: [{
    kind: 'provider_operation',
    resource_id: 'operation:recovery:01',
    reservation_id: 'reservation:recovery:01',
    digest: d('a'),
    expires_at: admissionExpires,
  }],
  admitted_at: now,
  expires_at: admissionExpires,
  supersedes_admission_id: null,
  remedy_for: null,
};

const admissionStore = createMemoryAdmissionStore({
  now,
  currentnessOracle: {
    read: async (snapshot) => ({
      '@version': ADMISSION_CURRENTNESS_VERSION,
      observed_at: now,
      qualification_status_authority_id: snapshot.body.qualification_status.authority_id,
      qualification_status_sequence: snapshot.body.qualification_status.sequence,
      qualification_status_head_digest: snapshot.body.qualification_status.head_payload_digest,
      qualification_status_expires_at: snapshot.body.qualification_status.expires_at,
      trust_epoch: snapshot.body.trust_epoch,
      trust_configuration_digest: snapshot.body.trust_configuration_digest,
      configuration_epoch: snapshot.body.configuration_epoch,
      configuration_digest: snapshot.body.configuration_digest,
      runtime_measurement_digest: snapshot.body.runtime_measurement_digest,
      candidate_match: 'EXACT_MATCH',
      external_leases: [],
    }),
  },
});
const reserved = await admissionStore.reserve(admission);
if (!reserved.ok) throw new Error(`ordinary admission refused: ${reserved.reason}`);

const bindings = deriveRecoveryAdmissionSnapshotBindings(reserved.snapshot.body);
const recovery = {
  scope: 'INTRA_TRANSACTION_ONLY' as const,
  state_domain_digest: stateDomainDigest,
  adapter_id: 'adapter:postgres:demo',
  adapter_digest: bindings.adapter_digest,
  max_transaction_ms: 5_000,
};
const keyPair = generateKeyPairSync('ed25519');
const signer = {
  issuer_id: 'rp:example-operations',
  key_id: 'key:rp:recovery:v1',
  private_key: keyPair.privateKey,
};
const capabilityInput = {
  capability_id: 'recovery-capability:demo:01',
  admission_id: admission.admission_id,
  admission_snapshot_digest: reserved.snapshot.snapshot_digest,
  tenant_id: admission.tenant_id,
  audience: 'gate:demo',
  action_caid: admission.caid,
  action_digest: admission.action_digest,
  action_capability_expires_at: validUntil,
  provider_id: bindings.provider_id,
  account_digest: bindings.account_digest,
  environment_digest: bindings.environment_digest,
  operation_id: admission.operation_id,
  issuer_digest: d('d'),
  trust_epoch_digest: bindings.trust_epoch_digest,
  config_epoch_digest: bindings.config_epoch_digest,
  adapter_id: recovery.adapter_id,
  adapter_digest: bindings.adapter_digest,
  resource_set_digest: bindings.resource_set_digest,
  issued_at: '2026-08-03T19:59:00.000Z',
  valid_from: now,
  expires_at: validUntil,
  mode: 'LOCAL_ATOMIC' as const,
  recovery,
};
const artifact = signRecoveryCapability(capabilityInput, signer);
const trustedKeys = {
  [signer.key_id]: {
    issuer_id: signer.issuer_id,
    public_key: keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  },
};
const expectedPolicy = {
  capability_id: capabilityInput.capability_id,
  admission_id: capabilityInput.admission_id,
  admission_snapshot_digest: capabilityInput.admission_snapshot_digest,
  mode: capabilityInput.mode,
  recovery,
  tenant_id: capabilityInput.tenant_id,
  audience: capabilityInput.audience,
  action_caid: capabilityInput.action_caid,
  action_digest: capabilityInput.action_digest,
  action_capability_expires_at: capabilityInput.action_capability_expires_at,
  provider_id: capabilityInput.provider_id,
  account_digest: capabilityInput.account_digest,
  environment_digest: capabilityInput.environment_digest,
  operation_id: capabilityInput.operation_id,
  issuer_id: signer.issuer_id,
  issuer_digest: capabilityInput.issuer_digest,
  trust_epoch_digest: capabilityInput.trust_epoch_digest,
  config_epoch_digest: capabilityInput.config_epoch_digest,
  adapter_id: capabilityInput.adapter_id,
  adapter_digest: capabilityInput.adapter_digest,
  resource_set_digest: capabilityInput.resource_set_digest,
};

const events: string[] = [];
const client = {
  async query(text: string) {
    events.push(text);
    return { rowCount: 0, rows: [] };
  },
  release(error?: Error) { events.push(error ? 'RELEASE_DISCARD' : 'RELEASE'); },
};
const execution = await executeRecoveryAdmissionPostgresLocalAtomic({
  artifact,
  verificationContext: { trusted_keys: trustedKeys, expected_policy: expectedPolicy, now },
  evaluatorDependencies: {
    current_status_resolver({ capability, capability_digest, issuer_id }) {
      return {
        '@version': RECOVERY_CAPABILITY_STATUS_VERSION,
        capability_id: capability.capability_id,
        capability_digest,
        tenant_id: capability.tenant_id,
        audience: capability.audience,
        action_caid: capability.action_caid,
        action_digest: capability.action_digest,
        provider_id: capability.provider_id,
        adapter_id: capability.adapter_id,
        issuer_id,
        status: 'CURRENT',
        observed_at: now,
        valid_from: now,
        valid_until: validUntil,
      };
    },
  },
  admissionStore,
  ownerToken: reserved.owner_token,
  invocationToken: `admission-invocation:v2:${'I'.repeat(43)}`,
  pool: {
    localAtomic: true,
    policyBoundToSingleTransaction: true,
    externalEffectsForbidden: true,
    stateDomainDigest,
    adapterDigest,
    async connect() { events.push('CONNECT'); return client; },
  },
  perform: async (transaction) => {
    await transaction.query('UPDATE demo_account SET status = $1');
    return { result: { changed: 1 }, evidence_digest: evidenceDigest };
  },
  validatePrecommit: () => true,
  recheckCurrent: () => true,
  now: () => Date.parse(now),
});
const record = await admissionStore.read({
  tenant_id: admission.tenant_id,
  admission_id: admission.admission_id,
});

console.log(JSON.stringify({
  recovery_mode: capabilityInput.mode,
  ordinary_admission_state: record?.state,
  execution_right: record?.execution_right,
  transaction_outcome: execution.outcome,
  retry_permitted: false,
  transaction_trace: events,
}, null, 2));
