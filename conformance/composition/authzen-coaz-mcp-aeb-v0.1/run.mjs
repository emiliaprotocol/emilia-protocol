// SPDX-License-Identifier: Apache-2.0
/**
 * Source-pinned AuthZEN COAZ-MCP to AEB consequence-admission profile.
 *
 * The AuthZEN response is modeled only as a locally observed machine-policy
 * input. AEB supplies the separate exact-action, evidence-satisfaction,
 * local-authorization, reservation, custody, outcome, and reconciliation
 * axes. This runner does not turn the Authorization API response into a
 * signed receipt, human authorization, execution proof, or replay token.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DECLARED_RELEASE_PAYMENT_MAPPING,
  PROFILE as COAZ_TRANSLATION_PROFILE,
  canonicalBytes,
  relyingCheck,
  toyPdpDecide,
  translateWithCaid,
  typedSourceAction,
} from '../coaz-translation-v0.1/run.mjs';
import {
  AEB_CONSEQUENCE_CASE_VERSION,
  AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
  canonicalizeAebConsequenceConformance,
  evaluateAebConsequenceCase,
  parseAebConsequenceCase,
} from '../../../packages/verify/dist/aeb-consequence-conformance.js';
import {
  AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
  adapterPinDigest,
  createAebNativeVerificationAttestationAdapter,
  digestAeb,
  mappingProfileDigest,
  registryEntryDigest,
  signAebNativeVerificationAttestation,
  unifiedRegistryDigest,
} from '../../../packages/verify/dist/aeb-adapter-contract.js';
import {
  AEB_NATIVE_COMPILER_VERSION,
  AEB_NATIVE_DESCRIPTOR_VERSION,
  aebNativeDescriptorDigest,
  compileAebNativeEvidence,
} from '../../../packages/verify/dist/aeb-native-compiler.js';

export const PROFILE = 'AUTHZEN-COAZ-MCP-AEB-CONSEQUENCE-v0.1';
export const REPORT_VERSION = 'AUTHZEN-COAZ-MCP-AEB-REPORT-v0.1';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../../..');
const VECTORS_PATH = resolve(HERE, 'vectors.json');
const SOURCE_LOCK_PATH = resolve(HERE, 'source-lock.json');
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');

const VECTORS = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));
const SOURCE_LOCK = JSON.parse(readFileSync(SOURCE_LOCK_PATH, 'utf8'));
const COAZ_CORPUS = JSON.parse(
  readFileSync(resolve(HERE, '../coaz-translation-v0.1/vectors.json'), 'utf8'),
);

const mappingBytes = canonicalBytes(DECLARED_RELEASE_PAYMENT_MAPPING);
assert.equal(mappingBytes.ok, true, 'declared COAZ-MCP mapping must canonicalize');
export const PINNED_MAPPING_PROFILE_DIGEST = `sha256:${mappingBytes.sha256}`;

assert.equal(
  VECTORS.pinned_mapping_profile_digest,
  PINNED_MAPPING_PROFILE_DIGEST,
  'vector mapping-profile pin drifted',
);

const EVALUATED_AT = VECTORS.evaluated_at;
const STATUS_CHECKED_AT = '2026-08-31T18:59:00Z';
const STATUS_VALID_UNTIL = '2026-08-31T19:05:00Z';
const PROVIDER_ID = 'provider:payments-primary';
const INITIATOR_ID = 'agent:accounting';
const EXECUTOR_ID = 'executor:mcp-gate';
const PEP_ADAPTER_ID = 'bridge:authzen-local-pep-observation-envelope';
const PEP_ADAPTER_VERSION = '1';
const PEP_OBSERVATION_PROTOCOL_ID = 'authzen-local-pep-observation';
const PEP_COMPILER_ARTIFACT_PROTOCOL_ID = 'emilia-authzen-local-pep-envelope';
const PEP_AUDIENCE = 'rp:emilia:authzen-coaz-mcp-aeb-v0.1';
const PEP_PROFILE_ID = 'profile:authzen-coaz-mcp-release-payment-v0.1';
const PEP_PROFILE_VERSION = 'AUTHZEN-COAZ-MCP-AEB-MAPPING-v0.1';
const PEP_MAPPER_ID = 'mapper:emilia:authzen-coaz-mcp:v0.1';
const PEP_RESOLVER_ID = 'resolver:emilia:typed-mcp-action:v0.1';
const PEP_DESCRIPTOR_ID = 'descriptor:authzen-local-pep-observation-envelope:v0.1';
const PEP_VERIFIER_KEY_ID = 'test-verifier:authzen-local-pep:v0.1';
const PEP_VERIFIER_IMPLEMENTATION_ID = 'emilia:authzen-local-pep-envelope-verifier';
const PEP_VERIFIER_IMPLEMENTATION_REVISION = 'v0.1';

export const AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID = PEP_DESCRIPTOR_ID;

// Public, deterministic test-only key material keeps the checked-in report
// reproducible. It authenticates this local harness observation. It is not an
// AuthZEN key, an OpenID key, or a production credential.
const PEP_TEST_SEED = crypto.createHash('sha256')
  .update('EMILIA-AUTHZEN-LOCAL-PEP-TEST-KEY-v0.1', 'utf8')
  .digest();
const PEP_TEST_PRIVATE_KEY = crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    PEP_TEST_SEED,
  ]),
  format: 'der',
  type: 'pkcs8',
});
const PEP_TEST_PUBLIC_KEY = crypto.createPublicKey(PEP_TEST_PRIVATE_KEY)
  .export({ type: 'spki', format: 'der' })
  .toString('base64url');

function sha256Bytes(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function digestJson(value) {
  return sha256Bytes(Buffer.from(canonicalizeAebConsequenceConformance(value), 'utf8'));
}

function sameJson(left, right) {
  return canonicalizeAebConsequenceConformance(left)
    === canonicalizeAebConsequenceConformance(right);
}

function approvedBinding() {
  const call = COAZ_CORPUS.fixtures.benign_call;
  const translated = translateWithCaid(
    DECLARED_RELEASE_PAYMENT_MAPPING,
    call,
    COAZ_CORPUS.fixtures.token_claims,
  );
  assert.equal(translated.ok, true, 'approved fixture must translate');
  return Object.freeze({
    caid: translated.caid,
    normalized_action_digest: digestJson(typedSourceAction(call)),
    action: typedSourceAction(call),
  });
}

function substitutedBinding() {
  const call = COAZ_CORPUS.fixtures.substituted_call;
  const translated = translateWithCaid(
    DECLARED_RELEASE_PAYMENT_MAPPING,
    call,
    COAZ_CORPUS.fixtures.token_claims,
  );
  assert.equal(translated.ok, true, 'substituted fixture must translate');
  return Object.freeze({
    caid: translated.caid,
    normalized_action_digest: digestJson(typedSourceAction(call)),
  });
}

const APPROVED = approvedBinding();
const SUBSTITUTED = substitutedBinding();

function registryEntry(id, kind, definition) {
  const entry = {
    kind,
    version: '1',
    status: 'active',
    definition,
    definition_digest: '',
  };
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

function compilerRequirement(requireNamedHuman) {
  return {
    '@version': 'AEB-REQUIREMENT-v1',
    all_of: [
      'machine-policy-input',
      ...(requireNamedHuman ? ['named-human-authorization'] : []),
    ],
    terms: [{ type: 'one-time-consumption' }],
  };
}

function compilerMappingProfile() {
  const profile = {
    version: PEP_PROFILE_VERSION,
    definition: {
      source_protocol: PEP_COMPILER_ARTIFACT_PROTOCOL_ID,
      source_observation: 'LOCAL-AUTHZEN-PEP-OBSERVATION-v0.1',
      signed_observation_protocol: PEP_OBSERVATION_PROTOCOL_ID,
      authzen_mapping_profile_digest: PINNED_MAPPING_PROFILE_DIGEST,
      target_action_type: APPROVED.action.action_type,
      projection: 'strict-observation-attestation-envelope-to-full-typed-mcp-action',
    },
    registry_entry_ref: `mapping:${PEP_PROFILE_ID}`,
    mapper_id: PEP_MAPPER_ID,
    resolver: {
      id: PEP_RESOLVER_ID,
      version: '1',
      implementation_digest: digestAeb({
        implementation: PEP_RESOLVER_ID,
        revision: '1',
        input: 'full-typed-mcp-action',
      }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
    profile_digest: '',
  };
  profile.profile_digest = mappingProfileDigest(PEP_PROFILE_ID, profile);
  return profile;
}

function compilerDescriptor(profile) {
  const descriptor = {
    '@version': AEB_NATIVE_DESCRIPTOR_VERSION,
    protocol: { id: PEP_COMPILER_ARTIFACT_PROTOCOL_ID, revision: 'v0.1' },
    source: {
      media_type: 'application/vnd.emilia.authzen-pep-observation-envelope+json',
      schema: { id: 'LOCAL-AUTHZEN-PEP-OBSERVATION-ENVELOPE', revision: 'v0.1' },
    },
    verifier: {
      implementation_id: PEP_VERIFIER_IMPLEMENTATION_ID,
      implementation_revision: PEP_VERIFIER_IMPLEMENTATION_REVISION,
      implementation_digest: digestAeb({
        implementation: PEP_VERIFIER_IMPLEMENTATION_ID,
        revision: PEP_VERIFIER_IMPLEMENTATION_REVISION,
        bridge: 'EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1',
      }),
    },
    adapter: { id: PEP_ADAPTER_ID, revision: PEP_ADAPTER_VERSION },
    mapping_profile: {
      id: PEP_PROFILE_ID,
      revision: profile.version,
      digest: profile.profile_digest,
    },
    target_action_type: APPROVED.action.action_type,
    replay_scope: 'per-relying-party-signed-local-pep-observation',
    descriptor_digest: '',
  };
  descriptor.descriptor_digest = aebNativeDescriptorDigest(PEP_DESCRIPTOR_ID, descriptor);
  return descriptor;
}

function localPepObservation(translated, pdpDecision, profile) {
  const body = {
    '@version': 'LOCAL-AUTHZEN-PEP-OBSERVATION-v0.1',
    authzen_request_digest: digestJson(translated.request),
    authzen_response_digest: digestJson(pdpDecision),
    boolean_decision: pdpDecision.decision,
    full_typed_action_caid: translated.caid,
    full_typed_action_digest: digestJson(translated.source_action),
    authzen_mapping_profile_digest: PINNED_MAPPING_PROFILE_DIGEST,
    aeb_mapping_profile_digest: profile.profile_digest,
    aeb_mapper_id: profile.mapper_id,
    aeb_resolver_digest: profile.resolver.implementation_digest,
    observed_at: STATUS_CHECKED_AT,
  };
  const observationDigest = digestAeb(body);
  return {
    ...body,
    observation_id: `urn:emilia:authzen-local-pep:${observationDigest.slice('sha256:'.length)}`,
  };
}

const OBSERVATION_KEYS = new Set([
  '@version',
  'observation_id',
  'authzen_request_digest',
  'authzen_response_digest',
  'boolean_decision',
  'full_typed_action_caid',
  'full_typed_action_digest',
  'authzen_mapping_profile_digest',
  'aeb_mapping_profile_digest',
  'aeb_mapper_id',
  'aeb_resolver_digest',
  'observed_at',
]);
const ENVELOPE_KEYS = new Set(['observation', 'attestation']);
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

function plainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainRecord(value)
    && Object.keys(value).length === expected.size
    && Object.keys(value).every((key) => expected.has(key));
}

function exactText(value) {
  return typeof value === 'string' && value.length > 0
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function observationIdFor(observation) {
  const { observation_id: _ignored, ...body } = observation;
  const digest = digestAeb(body);
  return `urn:emilia:authzen-local-pep:${digest.slice('sha256:'.length)}`;
}

function observationShapeValid(observation) {
  return exactKeys(observation, OBSERVATION_KEYS)
    && observation['@version'] === 'LOCAL-AUTHZEN-PEP-OBSERVATION-v0.1'
    && exactText(observation.observation_id)
    && DIGEST_PATTERN.test(observation.authzen_request_digest)
    && DIGEST_PATTERN.test(observation.authzen_response_digest)
    && typeof observation.boolean_decision === 'boolean'
    && exactText(observation.full_typed_action_caid)
    && observation.full_typed_action_caid.startsWith('caid:')
    && DIGEST_PATTERN.test(observation.full_typed_action_digest)
    && observation.authzen_mapping_profile_digest === PINNED_MAPPING_PROFILE_DIGEST
    && DIGEST_PATTERN.test(observation.aeb_mapping_profile_digest)
    && exactText(observation.aeb_mapper_id)
    && DIGEST_PATTERN.test(observation.aeb_resolver_digest)
    && Number.isFinite(Date.parse(observation.observed_at));
}

function inspectPepEnvelope(artifact) {
  if (!exactKeys(artifact, ENVELOPE_KEYS)
      || !observationShapeValid(artifact.observation)
      || !plainRecord(artifact.attestation)) {
    return {
      valid: false,
      observation: null,
      attestation: null,
      reasons: ['pep_observation_envelope_malformed'],
    };
  }
  const { observation, attestation } = artifact;
  const reasons = [];
  const observationDigest = digestAeb(observation);
  if (observation.observation_id !== observationIdFor(observation)) {
    reasons.push('pep_observation_id_mismatch');
  }
  if (observation.authzen_response_digest !== digestJson({
    decision: observation.boolean_decision,
  })) {
    reasons.push('pep_observation_authzen_response_mismatch');
  }
  if (attestation.native_artifact_digest !== observationDigest) {
    reasons.push('pep_observation_digest_mismatch');
  }
  if (attestation.native_artifact_ref !== observation.observation_id) {
    reasons.push('pep_observation_reference_mismatch');
  }
  if (attestation.verified_at !== observation.observed_at) {
    reasons.push('pep_observation_time_mismatch');
  }
  if (!plainRecord(attestation.mapping)
      || attestation.mapping.caid !== observation.full_typed_action_caid
      || attestation.mapping.normalized_action_digest !== observation.full_typed_action_digest) {
    reasons.push('pep_observation_action_mismatch');
  }
  if (!plainRecord(attestation.mapping)
      || attestation.mapping.profile_digest !== observation.aeb_mapping_profile_digest
      || attestation.mapping.mapper_id !== observation.aeb_mapper_id
      || attestation.mapping.resolver_digest !== observation.aeb_resolver_digest) {
    reasons.push('pep_observation_mapping_mismatch');
  }
  return {
    valid: reasons.length === 0,
    observation,
    attestation,
    reasons: [...new Set(reasons)].sort(),
  };
}

/**
 * Verify the signed local PEP observation and its bytes as one strict native
 * artifact. The generic bridge authenticates the attestation. This wrapper
 * additionally proves that the supplied observation is exactly what the
 * attestation names before allowing the mapper to run.
 */
function createAuthzenPepObservationEnvelopeAdapter(options) {
  const signedBridge = createAebNativeVerificationAttestationAdapter(options);
  return Object.freeze({
    id: options.id,
    version: options.version,
    verifyNative(input) {
      const evidenceDigest = digestAeb(input.artifact);
      const inspected = inspectPepEnvelope(input.artifact);
      const bridgeResult = signedBridge.verifyNative({
        ...input,
        artifact: inspected.attestation,
      });
      if (bridgeResult.native_verification !== 'VERIFIED') {
        return { ...bridgeResult, evidence_digest: evidenceDigest };
      }
      if (!inspected.valid) {
        return {
          ...bridgeResult,
          native_verification: 'FAILED',
          acceptance: 'REJECTED',
          evidence_digest: evidenceDigest,
          reasons: inspected.reasons,
        };
      }
      return { ...bridgeResult, evidence_digest: evidenceDigest };
    },
    mapAction(input) {
      const inspected = inspectPepEnvelope(input.artifact);
      if (input.native.native_verification !== 'VERIFIED' || !inspected.valid) {
        return {
          mapping: 'INDETERMINATE',
          caid: null,
          action_digest: null,
          reasons: inspected.valid ? ['native_verification_required'] : inspected.reasons,
        };
      }
      return signedBridge.mapAction({
        ...input,
        artifact: inspected.attestation,
      });
    },
  });
}

/**
 * Build the pure compiler input for a locally authenticated PEP observation.
 * The signature is made by this reference PEP harness, never by AuthZEN.
 */
export function buildAuthzenNativeCompilerFixture({
  call_fixture = 'benign_call',
  token_subject = 'alice@example.com',
  require_named_human = false,
  artifact_ref = 'urn:emilia:wrapper:authzen-local-pep:v0.1',
  attestation_native_artifact_ref = null,
  attestation_mapping_overrides = {},
} = {}) {
  const call = COAZ_CORPUS.fixtures[call_fixture];
  assert.ok(call, `missing COAZ fixture: ${call_fixture}`);
  const token = { ...COAZ_CORPUS.fixtures.token_claims, sub: token_subject };
  const translated = translateWithCaid(DECLARED_RELEASE_PAYMENT_MAPPING, call, token);
  assert.equal(translated.ok, true, `${call_fixture}: translation must construct`);
  const pdpDecision = toyPdpDecide(translated.request);
  const profile = compilerMappingProfile();
  const descriptor = compilerDescriptor(profile);
  const observation = localPepObservation(translated, pdpDecision, profile);
  const observationDigest = digestAeb(observation);
  const attestation = signAebNativeVerificationAttestation({
    '@version': AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
    protocol_id: PEP_OBSERVATION_PROTOCOL_ID,
    audience: PEP_AUDIENCE,
    native_artifact_ref: attestation_native_artifact_ref ?? observation.observation_id,
    native_artifact_digest: observationDigest,
    evidence_role: 'machine-policy-input',
    subject: { id: 'pdp:authzen:local-toy', kind: 'system' },
    verified_at: STATUS_CHECKED_AT,
    expires_at: STATUS_VALID_UNTIL,
    mapping: {
      profile_digest: observation.aeb_mapping_profile_digest,
      mapper_id: observation.aeb_mapper_id,
      resolver_digest: observation.aeb_resolver_digest,
      caid: observation.full_typed_action_caid,
      normalized_action_digest: observation.full_typed_action_digest,
      ...attestation_mapping_overrides,
    },
  }, { key_id: PEP_VERIFIER_KEY_ID, private_key: PEP_TEST_PRIVATE_KEY });
  const envelope = { observation, attestation };
  const adapter = createAuthzenPepObservationEnvelopeAdapter({
    id: PEP_ADAPTER_ID,
    version: PEP_ADAPTER_VERSION,
  });
  const adapterPin = {
    version: PEP_ADAPTER_VERSION,
    trust_roots: [{ key_id: PEP_VERIFIER_KEY_ID, public_key: PEP_TEST_PUBLIC_KEY }],
    config: {
      audience: PEP_AUDIENCE,
      accepted_protocols: [PEP_OBSERVATION_PROTOCOL_ID],
    },
    max_status_age_sec: 360,
    config_digest: '',
  };
  adapterPin.config_digest = adapterPinDigest(PEP_ADAPTER_ID, adapterPin);
  const requirement = compilerRequirement(require_named_human);
  const entries = {
    [profile.registry_entry_ref]: registryEntry(
      profile.registry_entry_ref,
      'mapping-profile',
      { profile_digest: profile.profile_digest },
    ),
    'role:machine-policy-input': registryEntry(
      'role:machine-policy-input',
      'evidence-role',
      { role: 'machine-policy-input', subject_kinds: ['system'] },
    ),
    'role:named-human-authorization': registryEntry(
      'role:named-human-authorization',
      'evidence-role',
      { role: 'named-human-authorization', subject_kinds: ['human'] },
    ),
  };
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:authzen-coaz-mcp-aeb-v0.1',
    epoch: 1,
    entries,
    registry_digest: '',
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const requirementRef = require_named_human
    ? 'requirement:authzen-machine-policy-plus-named-human'
    : 'requirement:authzen-machine-policy';
  const pins = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: PEP_AUDIENCE,
    evaluator_keys: {},
    registry,
    accepted_mappers: [profile.mapper_id],
    adapters: { [PEP_ADAPTER_ID]: adapterPin },
    profiles: { [PEP_PROFILE_ID]: profile },
    requirements: { [requirementRef]: requirement },
  };
  const input = {
    pins,
    adapters: { [PEP_ADAPTER_ID]: adapter },
    native_descriptors: {
      pins: { [PEP_DESCRIPTOR_ID]: descriptor.descriptor_digest },
      registry: { [PEP_DESCRIPTOR_ID]: descriptor },
    },
    native_legs: [{
      native_descriptor_id: PEP_DESCRIPTOR_ID,
      adapter_id: PEP_ADAPTER_ID,
      profile_id: PEP_PROFILE_ID,
      artifact_ref,
      artifact: envelope,
      status: {
        checked_at: STATUS_CHECKED_AT,
        expires_at: STATUS_VALID_UNTIL,
        revocation_checked: true,
        revoked: false,
        consumed: false,
      },
    }],
    expected_action: { caid: APPROVED.caid, value: APPROVED.action },
    requirement: { ref: requirementRef, definition: requirement },
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    evaluated_at: EVALUATED_AT,
    local_policy_input: {
      policy_id: 'policy:local-authzen-access-evaluation',
      policy_version: 'AuthZEN-Authorization-API-1.0',
      decision: pdpDecision.decision ? 'ALLOW' : 'DENY',
      reasons: pdpDecision.decision ? [] : ['authzen_boolean_deny'],
    },
  };
  return { input, envelope, observation, attestation, translated, pdpDecision };
}

function machinePolicyRequirement() {
  return {
    role: 'machine-policy-input',
    principal_kind: 'SYSTEM',
    minimum: 1,
    distinct_principals: false,
    exclude_initiator: false,
    exclude_executor: false,
  };
}

function humanRequirement() {
  return {
    role: 'named-human-authorization',
    principal_kind: 'HUMAN',
    minimum: 1,
    distinct_principals: true,
    exclude_initiator: true,
    exclude_executor: true,
  };
}

function priorOperation(operation) {
  return {
    operation_id: operation.operation_id,
    caid: operation.caid,
    normalized_action_digest: operation.normalized_action_digest,
    custody: 'INVOKING',
    provider_outcome: 'INDETERMINATE',
    effect_relation: 'INDETERMINATE',
  };
}

function modeForScenario(scenario) {
  if (scenario === 'ADMISSION') return 'ADMISSION';
  if (scenario === 'TIMEOUT_AFTER_DISPATCH') return 'INVOCATION_OBSERVATION';
  if (scenario === 'RETRY') return 'RETRY';
  if (scenario === 'RECONCILE_EXACT' || scenario === 'RECONCILE_MISMATCH') {
    return 'RECONCILIATION';
  }
  throw new TypeError(`unsupported scenario: ${scenario}`);
}

function providerEntryState(scenario, aebDecision) {
  if (scenario === 'TIMEOUT_AFTER_DISPATCH') return 'DISPATCHED_OUTCOME_UNKNOWN';
  if (scenario === 'RETRY') return 'REENTRY_REFUSED';
  if (scenario === 'RECONCILE_EXACT') return 'NO_REEXECUTION_RECONCILED';
  if (scenario === 'RECONCILE_MISMATCH') {
    return 'NO_REEXECUTION_RECONCILIATION_REFUSED';
  }
  return aebDecision === 'ADMIT' ? 'AUTHORIZED_NOT_OBSERVED' : 'REFUSED_BEFORE_ENTRY';
}

function buildAebCase(entry, localPolicyDecision, compilerReport) {
  assert.equal(compilerReport['@version'], AEB_NATIVE_COMPILER_VERSION);
  assert.equal(compilerReport.legs.length, 1, 'AuthZEN compiler bridge must produce one leg');
  const compiledLeg = compilerReport.legs[0];
  assert.equal(
    compiledLeg.native_result.verification,
    'VERIFIED',
    `${entry.id}: local PEP attestation must verify before lifecycle evaluation`,
  );
  assert.equal(
    compiledLeg.native_result.acceptance,
    'ACCEPTED',
    `${entry.id}: local PEP attestation must be accepted under relying-party pins`,
  );
  assert.equal(typeof compiledLeg.action.caid, 'string', `${entry.id}: compiled CAID required`);
  assert.equal(
    typeof compiledLeg.action.normalized_action_digest,
    'string',
    `${entry.id}: compiled action digest required`,
  );
  assert.equal(compiledLeg.evidence.subject?.kind, 'system');
  assert.equal(
    compilerReport.axes.policy_input.result,
    localPolicyDecision ? 'ALLOW' : 'DENY',
    `${entry.id}: policy input must match the verified local PEP observation`,
  );
  assert.equal(compilerReport.axes.local_authorization.result, 'NOT_EVALUATED');
  assert.equal(compilerReport.claims.local_authorization_established, false);
  const operation = {
    operation_id: `authzen-aeb:${entry.id}`,
    provider_id: PROVIDER_ID,
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    caid: APPROVED.caid,
    normalized_action_digest: APPROVED.normalized_action_digest,
    requirements: [
      machinePolicyRequirement(),
      ...(entry.require_named_human ? [humanRequirement()] : []),
    ],
  };

  const input = {
    '@version': AEB_CONSEQUENCE_CASE_VERSION,
    id: entry.id,
    mode: modeForScenario(entry.scenario),
    evaluated_at: EVALUATED_AT,
    operation,
    evidence: [
      {
        wrapper_digest: compiledLeg.artifact_digest,
        native_replay_unit: compiledLeg.replay_unit,
        native_verification: compiledLeg.native_result.verification,
        mapped_caid: compiledLeg.action.caid,
        mapped_action_digest: compiledLeg.action.normalized_action_digest,
        role: compiledLeg.evidence.role,
        principal_kind: 'SYSTEM',
        principal_id: compiledLeg.evidence.subject.id,
        status: {
          verdict: 'CURRENT',
          authority_pinned: true,
          checked_at: STATUS_CHECKED_AT,
          valid_until: STATUS_VALID_UNTIL,
        },
      },
    ],
    local_policy: localPolicyDecision ? 'PERMIT' : 'DENY',
    reservation: {
      atomicity: 'local_atomic',
      prior_operations: [],
      consumed_native_replay_units: [],
    },
    observation: null,
    reconciliation: null,
  };

  if (entry.scenario !== 'ADMISSION') {
    input.reservation.prior_operations = [priorOperation(operation)];
  }
  if (entry.scenario === 'TIMEOUT_AFTER_DISPATCH') {
    input.observation = {
      source: 'TIMEOUT_AFTER_DISPATCH',
      provider_outcome: 'INDETERMINATE',
      effect_relation: 'INDETERMINATE',
    };
  }
  if (entry.scenario === 'RECONCILE_EXACT') {
    input.reconciliation = {
      authenticated: true,
      provider_id: operation.provider_id,
      operation_id: operation.operation_id,
      caid: operation.caid,
      normalized_action_digest: operation.normalized_action_digest,
      provider_outcome: 'COMMITTED',
      effect_relation: 'OBSERVED_AS_REQUESTED',
    };
  }
  if (entry.scenario === 'RECONCILE_MISMATCH') {
    input.reconciliation = {
      authenticated: true,
      provider_id: 'provider:payments-other',
      operation_id: operation.operation_id,
      caid: SUBSTITUTED.caid,
      normalized_action_digest: SUBSTITUTED.normalized_action_digest,
      provider_outcome: 'COMMITTED',
      effect_relation: 'OBSERVED_AS_REQUESTED',
    };
  }

  return parseAebConsequenceCase(input);
}

function projectObservation(observation) {
  const aeb = observation.aeb;
  return {
    preflight: observation.preflight,
    translation: observation.translation,
    pdp_decision: observation.pdp_decision,
    authzen_role: 'MACHINE_POLICY_INPUT',
    material_action: observation.material_action,
    native_verification: aeb?.verification ?? null,
    rp_acceptance: aeb?.acceptance ?? null,
    action_match: aeb?.action_match ?? null,
    evidence_satisfaction: aeb?.satisfaction ?? null,
    local_authorization: aeb?.authorization ?? null,
    reservation: aeb?.reservation ?? null,
    custody: aeb?.custody ?? null,
    provider_outcome: aeb?.provider_outcome ?? null,
    effect_relation: aeb?.effect_relation ?? null,
    retry: aeb?.retry ?? null,
    reconciliation: aeb?.reconciliation ?? null,
    aeb_decision: aeb?.decision ?? null,
    reasons: observation.reasons,
    provider_entry: observation.provider_entry,
    named_human_authorization_proven: false,
    execution_proven_by_authzen: false,
  };
}

function evaluateCase(entry) {
  const suppliedPin = entry.supplied_mapping_profile_digest
    ?? VECTORS.pinned_mapping_profile_digest;
  if (suppliedPin !== PINNED_MAPPING_PROFILE_DIGEST) {
    const observation = {
      preflight: 'REFUSE_MAPPING_PROFILE_PIN_MISMATCH',
      translation: 'NOT_ATTEMPTED',
      pdp_decision: null,
      material_action: null,
      material_reason: null,
      request_digest: null,
      local_pep_observation_digest: null,
      policy_input_matches_verified_observation: null,
      native_compiler: null,
      aeb_input_digest: null,
      aeb: null,
      reasons: ['mapping_profile_pin_mismatch'],
      provider_entry: 'REFUSED_BEFORE_ENTRY',
    };
    const projected = projectObservation(observation);
    return {
      id: entry.id,
      description: entry.description,
      passed: sameJson(projected, entry.expected),
      expected: entry.expected,
      observed: projected,
      details: observation,
    };
  }

  const fixture = buildAuthzenNativeCompilerFixture({
    call_fixture: entry.call_fixture,
    token_subject: entry.token_subject,
    require_named_human: entry.require_named_human,
    artifact_ref: `urn:emilia:wrapper:authzen-local-pep:${entry.id}`,
  });
  const {
    input: compilerInput,
    observation: localObservation,
    translated,
    pdpDecision,
  } = fixture;
  const materialCheck = relyingCheck({
    observedAction: translated.source_action,
    presentedCaid: translated.request.context.caid,
    approvedAction: APPROVED.action,
  });
  const compiler = compileAebNativeEvidence(compilerInput);
  const verifiedPolicyDecision = localObservation.boolean_decision;
  const policyInputMatchesVerifiedObservation = compiler.axes.policy_input.result
    === (verifiedPolicyDecision ? 'ALLOW' : 'DENY');
  assert.equal(
    policyInputMatchesVerifiedObservation,
    true,
    `${entry.id}: compiler policy input diverged from the verified local observation`,
  );
  const aebInput = buildAebCase(entry, verifiedPolicyDecision, compiler);
  const aeb = evaluateAebConsequenceCase(aebInput);
  const observation = {
    preflight: 'PASS',
    translation: 'CONSTRUCTED',
    pdp_decision: pdpDecision.decision ? 'ALLOW' : 'DENY',
    material_action: materialCheck.allowed ? 'MATCH' : 'MISMATCH',
    material_reason: materialCheck.reason,
    request_digest: digestJson(translated.request),
    local_pep_observation_digest: digestAeb(localObservation),
    policy_input_matches_verified_observation: policyInputMatchesVerifiedObservation,
    local_pep_attestation: {
      signer: PEP_VERIFIER_KEY_ID,
      signer_scope: 'LOCAL_PEP_TEST_HARNESS',
      authzen_signature_claimed: false,
      envelope_digest: compiler.legs[0].artifact_digest,
    },
    native_compiler: compiler,
    aeb_input_digest: digestJson(aebInput),
    aeb,
    reasons: aeb.reasons,
    provider_entry: providerEntryState(entry.scenario, aeb.decision),
  };
  const projected = projectObservation(observation);
  return {
    id: entry.id,
    description: entry.description,
    passed: sameJson(projected, entry.expected),
    expected: entry.expected,
    observed: projected,
    details: observation,
  };
}

export function verifySourceLock() {
  const failures = [];
  for (const file of SOURCE_LOCK.local_files) {
    const actual = sha256Bytes(readFileSync(resolve(REPO_ROOT, file.path))).slice('sha256:'.length);
    if (actual !== file.sha256) {
      failures.push({ path: file.path, expected: file.sha256, actual });
    }
  }
  const inherited = SOURCE_LOCK.inherits;
  const inheritedActual = sha256Bytes(
    readFileSync(resolve(REPO_ROOT, inherited.path)),
  ).slice('sha256:'.length);
  if (inheritedActual !== inherited.sha256) {
    failures.push({
      path: inherited.path,
      expected: inherited.sha256,
      actual: inheritedActual,
    });
  }
  return { valid: failures.length === 0, failures };
}

export function runSuite() {
  const sourceVerification = verifySourceLock();
  assert.equal(
    sourceVerification.valid,
    true,
    `source lock failed: ${JSON.stringify(sourceVerification.failures)}`,
  );
  const cases = VECTORS.cases.map(evaluateCase);
  const passed = cases.filter((entry) => entry.passed).length;
  const body = {
    '@version': REPORT_VERSION,
    profile: PROFILE,
    executed_at: EVALUATED_AT,
    implementation: {
      owner: 'EMILIA Protocol',
      revision: 'v0.1',
      independent_implementation: false,
      production_mediation: false,
    },
    source_pins: {
      source_lock_digest: sha256Bytes(readFileSync(SOURCE_LOCK_PATH)),
      inherited_profile: COAZ_TRANSLATION_PROFILE,
      authzen_repository_commit: SOURCE_LOCK.upstream_repository.commit,
      authzen_authorization_api_sha256: SOURCE_LOCK.authzen_base.sha256,
      mapping_profile_digest: PINNED_MAPPING_PROFILE_DIGEST,
      native_compiler_version: AEB_NATIVE_COMPILER_VERSION,
      native_compiler_sha256: SOURCE_LOCK.native_compiler.sha256,
      native_attestation_bridge_version: AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
      native_attestation_bridge_sha256: SOURCE_LOCK.native_attestation_bridge.sha256,
      aeb_kernel_sha256: SOURCE_LOCK.aeb_kernel.sha256,
    },
    claim_scope: {
      authzen_result_role: 'LOCAL_MACHINE_POLICY_INPUT',
      aeb_atomicity: AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
      guarantees: [
        'signed_local_pep_observation_compiled_under_relying_party_pins',
        'exact_action_checked_before_admission',
        'compiler_lifecycle_axes_remain_unestablished',
        'local_atomic_reservation_before_provider_entry',
        'blind_retry_refused_while_indeterminate',
        'authenticated_exact_binding_required_for_reconciliation',
      ],
      exclusions: [
        'authzen_signed_receipt',
        'authzen_signature_on_local_pep_observation',
        'named_human_authorization_from_authzen_allow',
        'execution_proof_from_authzen_allow',
        'authorization_api_replay_semantics',
        'compiler_report_as_credential',
        'compiler_reservation_or_provider_entry',
        'verifier_runtime_measurement',
        'remote_or_federated_atomicity',
        'provider_or_effect_truth_before_reconciliation',
        'independent_implementation',
        'production_mediation',
        'openid_working_group_acceptance',
        'ietf_adoption',
      ],
    },
    summary: {
      total: cases.length,
      passed,
      failed: cases.length - passed,
    },
    cases,
  };
  return Object.freeze({ ...body, report_digest: digestJson(body) });
}

function parseArgs(argv) {
  const options = { check: false, emit: false, output: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--check') options.check = true;
    else if (arg === '--emit') options.emit = true;
    else if (arg === '--output') {
      options.output = argv[index + 1];
      index += 1;
    } else {
      throw new TypeError(`unknown argument: ${arg}`);
    }
  }
  if (options.emit && !options.output) {
    throw new TypeError('--emit requires --output');
  }
  return options;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const options = parseArgs(process.argv.slice(2));
  const report = runSuite();
  if (options.check) {
    const reference = JSON.parse(readFileSync(REFERENCE_PATH, 'utf8'));
    assert.deepEqual(report, reference, 'deterministic report differs from reference');
    assert.equal(report.summary.failed, 0, JSON.stringify(report.cases.filter((entry) => !entry.passed)));
    process.stdout.write(
      `${PROFILE}: ${report.summary.passed}/${report.summary.total} cases passed; reference matched\n`,
    );
  } else if (options.emit) {
    writeFileSync(resolve(options.output), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  } else {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}
