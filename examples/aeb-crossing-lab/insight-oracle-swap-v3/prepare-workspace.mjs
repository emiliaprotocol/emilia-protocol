// SPDX-License-Identifier: Apache-2.0
// @ts-nocheck -- this deterministic generator consumes the JavaScript verifier surface.

import crypto from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  adapterPinDigest,
  digestAeb,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from '../../../packages/verify/aeb-adapter-contract.js';
import { computeCaid } from '../../../caid/impl/js/caid.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  await readFile(join(here, 'signed-nonproduction-fixture.json'), 'utf8')
);
const adapterBytes = await readFile(join(here, 'adapter.mjs'));

const ADAPTER_ID = 'native:insight-oracle-swap-authorization';
const ADAPTER_VERSION = '1.0.0';
const ACTION_TYPE = 'evm-swap-exact-input-single.1';
const MAPPER_ID = 'mapper:insight-evm-swap-exact-input-single.1';
const PROFILE_ID = 'insight-evm-swap-exact-input-single';
const PROFILE_VERSION = 'INSIGHT-EVM-SWAP-EXACT-INPUT-SINGLE-MAPPING-v1';
const ROLE = 'action-authorization';
const REQUIREMENT_REF = 'requirement:insight-swap-action-authorization';
const ARTIFACT_REF = 'insight:synthetic:swap-authorization:v3';
const ZERO_DIGEST = `sha256:${'0'.repeat(64)}`;

const definition = {
  '@version': PROFILE_VERSION,
  source: 'insight-oracle-safety-check-v3+swap-authorization-v2',
  source_media_type: 'application/json',
  projection: 'exact-executable-swap-and-bound-oracle-checks-v1',
  action_type: ACTION_TYPE,
  suite: 'jcs-sha256',
  definitions: [
    {
      action_type: ACTION_TYPE,
      required_fields: [
        { name: 'action_type', type: 'string' },
        { name: 'subject_chain_id', type: 'amount-string' },
        { name: 'execution_domain', type: 'string' },
        { name: 'spending_wallet', type: 'string' },
        { name: 'router', type: 'string' },
        { name: 'calldata', type: 'string' },
        { name: 'native_value', type: 'amount-string' },
        { name: 'source_asset_id', type: 'string' },
        { name: 'destination_asset_id', type: 'string' },
        { name: 'raw_input_amount', type: 'amount-string' },
        { name: 'minimum_output_amount', type: 'amount-string' },
        { name: 'recipient', type: 'string' },
        { name: 'deadline', type: 'amount-string' },
        { name: 'nonce', type: 'string' },
        { name: 'router_call', type: 'object' },
      ],
      optional_fields: [],
    },
  ],
};

const adapterDigest = `sha256:${crypto.createHash('sha256').update(adapterBytes).digest('hex')}`;
const artifact = {
  authorization: fixture.authorization,
  sourceCheck: fixture.sourceCheck,
  destinationCheck: fixture.destinationCheck,
  profile: fixture.nativeProfile,
};
const expectedAction = fixture.expectedAction;
const hostileExpectedAction = structuredClone(expectedAction);
hostileExpectedAction.minimum_output_amount = (
  BigInt(hostileExpectedAction.minimum_output_amount) + 1n
).toString();

const profile = {
  version: PROFILE_VERSION,
  definition,
  registry_entry_ref: `mapping:${PROFILE_ID}`,
  mapper_id: MAPPER_ID,
  resolver: {
    id: MAPPER_ID,
    version: ADAPTER_VERSION,
    implementation_digest: adapterDigest,
  },
  semantic_equivalence: {
    assertion: 'EQUIVALENT_UNDER_PROFILE',
    loss_policy: 'NO_MATERIAL_FIELD_LOSS',
    omitted_material_fields: [],
    omitted_nonmaterial_fields: [],
  },
  profile_digest: ZERO_DIGEST,
};
profile.profile_digest = mappingProfileDigest(PROFILE_ID, profile);

function registryEntry(id, kind, version, entryDefinition) {
  const entry = { kind, version, status: 'active', definition: entryDefinition };
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

const registry = {
  '@version': 'EP-EVIDENCE-REGISTRY-v1',
  registry_id: 'registry:insight-aeb-synthetic-review',
  epoch: 1,
  entries: {
    [`mapping:${PROFILE_ID}`]: registryEntry(
      `mapping:${PROFILE_ID}`,
      'mapping-profile',
      '1',
      { profile_digest: profile.profile_digest }
    ),
    [`role:${ROLE}`]: registryEntry(`role:${ROLE}`, 'evidence-role', '1', {
      role: ROLE,
      subject_kinds: ['human'],
    }),
  },
  registry_digest: ZERO_DIGEST,
};
registry.registry_digest = unifiedRegistryDigest(registry);

const adapterConfig = {
  '@version': 'INSIGHT-AEB-EVM-SWAP-ADAPTER-CONFIG-v1',
  evidence_role: ROLE,
  subject_kind: 'human',
};
const adapterPin = {
  version: ADAPTER_VERSION,
  trust_roots: [fixture.trust],
  config: adapterConfig,
  config_digest: ZERO_DIGEST,
  max_status_age_sec: 300,
};
adapterPin.config_digest = adapterPinDigest(ADAPTER_ID, adapterPin);

const config = {
  '@version': 'AEB-ADAPTER-v1',
  relying_party_id: 'rp:insight-emilia-synthetic-review',
  evaluator_keys: {
    'crossing-lab:self-test': {
      public_key: 'MCowBQYDK2VwAyEAc_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
    },
  },
  registry,
  accepted_mappers: [MAPPER_ID],
  adapters: { [ADAPTER_ID]: adapterPin },
  profiles: { [PROFILE_ID]: profile },
  requirements: {
    [REQUIREMENT_REF]: {
      '@version': 'AEB-REQUIREMENT-v1',
      all_of: [ROLE],
      terms: [{ type: 'one-time-consumption' }],
    },
  },
};

const caidResult = computeCaid(expectedAction, {
  suite: 'jcs-sha256',
  definitions: definition.definitions,
});
if ('refusals' in caidResult) {
  throw new Error(`CAID refused: ${JSON.stringify(caidResult.refusals)}`);
}

const checkedAt = fixture.testClock.checkedAt;
const status = {
  checked_at: new Date(checkedAt * 1000).toISOString(),
  expires_at: new Date((checkedAt + 250) * 1000).toISOString(),
  revocation_checked: true,
  revoked: false,
  consumed: false,
  unavailable: false,
};
const workspace = {
  '@version': 'EMILIA-CROSSING-LAB-LOCAL-WORKSPACE-v1',
  adapter: {
    id: ADAPTER_ID,
    version: ADAPTER_VERSION,
    module: 'adapter.mjs',
    module_digest: adapterDigest,
  },
  artifact: 'artifact.json',
  artifact_digest: digestAeb(artifact),
  config,
  evaluated_at: new Date((checkedAt + 100) * 1000).toISOString(),
  evaluation: {
    operation_id: 'operation:insight-synthetic-swap-001',
    consumption_nonce: 'nonce:insight-synthetic-swap-001',
    initiator_id: 'agent:insight-synthetic-caller',
    executor_id: 'executor:insight-synthetic-crossing',
    requirement_ref: REQUIREMENT_REF,
    profile_id: PROFILE_ID,
    artifact_ref: ARTIFACT_REF,
    caid: caidResult.caid,
    status,
    status_digest: digestAeb(status),
  },
  expected_action: expectedAction,
  expected_action_digest: digestAeb(expectedAction),
  hostile_expected_action: hostileExpectedAction,
  hostile_expected_action_digest: digestAeb(hostileExpectedAction),
};

await Promise.all([
  writeFile(join(here, 'artifact.json'), `${JSON.stringify(artifact, null, 2)}\n`),
  writeFile(join(here, 'workspace.json'), `${JSON.stringify(workspace, null, 2)}\n`),
]);
console.log(`prepared ${caidResult.caid}`);
