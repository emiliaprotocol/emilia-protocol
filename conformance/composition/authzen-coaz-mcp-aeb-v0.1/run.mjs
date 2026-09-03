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
  AEB_EVALUATION_VERSION,
  aebNativeReplayKeys,
  adapterPinDigest,
  createAebNativeVerificationAttestationAdapter,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  signAebNativeVerificationAttestation,
  unifiedRegistryDigest,
} from '../../../packages/verify/dist/aeb-adapter-contract.js';

export const PROFILE = 'AUTHZEN-COAZ-MCP-AEB-CONSEQUENCE-v0.1';
export const REPORT_VERSION = 'AUTHZEN-COAZ-MCP-AEB-REPORT-v0.1';
export const PREFLIGHT_VERSION = 'AUTHZEN-LOCAL-PEP-PREFLIGHT-v0.1';

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
const PEP_ARTIFACT_PROTOCOL_ID = 'emilia-authzen-local-pep-envelope';
const PEP_AUDIENCE = 'rp:emilia:authzen-coaz-mcp-aeb-v0.1';
const PEP_PROFILE_ID = 'profile:authzen-coaz-mcp-release-payment-v0.1';
const PEP_PROFILE_VERSION = 'AUTHZEN-COAZ-MCP-AEB-MAPPING-v0.1';
const PEP_MAPPER_ID = 'mapper:emilia:authzen-coaz-mcp:v0.1';
const PEP_RESOLVER_ID = 'resolver:emilia:typed-mcp-action:v0.1';
const PEP_VERIFIER_KEY_ID = 'test-verifier:authzen-local-pep:v0.1';
export const AUTHZEN_PEP_ADAPTER_ID = PEP_ADAPTER_ID;
export const AUTHZEN_PEP_PROFILE_ID = PEP_PROFILE_ID;

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

function preflightRequirement(requireNamedHuman) {
  return {
    '@version': 'AEB-REQUIREMENT-v1',
    all_of: [
      'machine-policy-input',
      ...(requireNamedHuman ? ['named-human-authorization'] : []),
    ],
    terms: [{ type: 'one-time-consumption' }],
  };
}

function preflightMappingProfile() {
  const profile = {
    version: PEP_PROFILE_VERSION,
    definition: {
      source_protocol: PEP_ARTIFACT_PROTOCOL_ID,
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

function freezeSnapshot(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeSnapshot(child);
    Object.freeze(value);
  }
  return value;
}

function snapshotPreflightInput(input) {
  if (!plainRecord(input)) return null;
  const { legs, config, expected_action, ...rest } = input;
  return {
    ...rest,
    // Snapshot each supplied value once. Both the published evaluator and
    // local policy projection consume these detached, immutable bytes.
    legs: freezeSnapshot(structuredClone(legs)),
    config: freezeSnapshot(structuredClone(config)),
    expected_action: freezeSnapshot(structuredClone(expected_action)),
  };
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
export function createAuthzenPepObservationEnvelopeAdapter(options) {
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
 * Build published evidence-evaluator input for a local PEP preflight.
 * The signature is made by this reference PEP harness, never by AuthZEN.
 */
export function buildAuthzenPreflightFixture({
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
  const profile = preflightMappingProfile();
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
  const requirement = preflightRequirement(require_named_human);
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
    config: pins,
    adapters: { [PEP_ADAPTER_ID]: adapter },
    operation_id: 'authzen-local-pep-preflight',
    consumption_nonce: 'authzen-local-pep-preflight:v0.1',
    legs: [{
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
    expected_action: APPROVED.action,
    caid: APPROVED.caid,
    requirement_ref: requirementRef,
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    evaluated_at: EVALUATED_AT,
  };
  return { input, envelope, observation, attestation, translated, pdpDecision };
}

/**
 * Local preflight only. Preserve the evaluator's unsigned-record refusal;
 * this result is neither a portable credential nor authorization to execute.
 * The policy Boolean is read only from the strictly bound, verified envelope.
 */
export function evaluateAuthzenPreflight(input) {
  let snapshot;
  try {
    snapshot = snapshotPreflightInput(input);
  } catch {
    // Non-cloneable inputs cannot be local observation evidence.
    snapshot = null;
  }
  const evaluation = evaluateAebEvidence(snapshot);
  const leg = evaluation.record.legs[0];
  const envelope = snapshot?.legs?.[0]?.artifact;
  const inspected = inspectPepEnvelope(envelope);
  const policyVerified = evaluation.record.legs.length === 1
    // The published evaluator preserves per-leg verification diagnostics
    // even when the RP configuration is invalid. Do not promote those
    // diagnostics into a policy input under an unaccepted configuration.
    && !evaluation.reasons.includes('cannot_evaluate_unpinned_requirement')
    && leg.native_verification === 'VERIFIED'
    && leg.acceptance === 'ACCEPTED'
    && inspected.valid
    && leg.evidence_digest === digestAeb(envelope);
  return {
    '@version': PREFLIGHT_VERSION,
    evaluation,
    native_replay_keys: aebNativeReplayKeys(evaluation.record),
    policy_input: policyVerified
      ? (inspected.observation.boolean_decision ? 'ALLOW' : 'DENY')
      : 'INDETERMINATE',
    local_authorization: 'NOT_EVALUATED',
    lifecycle: {
      reservation: 'NOT_EVALUATED',
      consumption: 'NOT_EVALUATED',
      provider_entry: 'NOT_ESTABLISHED',
      provider_outcome: 'NOT_ESTABLISHED',
      observed_effect: 'NOT_ESTABLISHED',
      retry: 'NOT_EVALUATED',
      reconciliation: 'NOT_EVALUATED',
    },
    portable_credential: false,
    local_authorization_established: false,
  };
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

function buildAebCase(entry, localPolicyDecision, preflight) {
  assert.equal(preflight['@version'], PREFLIGHT_VERSION);
  assert.equal(preflight.evaluation.record.legs.length, 1, 'AuthZEN preflight must produce one leg');
  assert.equal(preflight.evaluation.valid, false, 'unsigned local preflight is not a credential');
  assert.ok(preflight.evaluation.reasons.includes('evaluation_signature_required'));
  const evaluatedLeg = preflight.evaluation.record.legs[0];
  assert.equal(
    evaluatedLeg.native_verification,
    'VERIFIED',
    `${entry.id}: local PEP attestation must verify before lifecycle evaluation`,
  );
  assert.equal(
    evaluatedLeg.acceptance,
    'ACCEPTED',
    `${entry.id}: local PEP attestation must be accepted under relying-party pins`,
  );
  assert.equal(typeof evaluatedLeg.caid, 'string', `${entry.id}: evaluated CAID required`);
  assert.equal(
    typeof evaluatedLeg.action_digest,
    'string',
    `${entry.id}: evaluated action digest required`,
  );
  assert.equal(evaluatedLeg.subject?.kind, 'system');
  assert.equal(
    preflight.policy_input,
    localPolicyDecision ? 'ALLOW' : 'DENY',
    `${entry.id}: policy input must match the verified local PEP observation`,
  );
  assert.equal(preflight.local_authorization, 'NOT_EVALUATED');
  assert.equal(preflight.local_authorization_established, false);
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
        wrapper_digest: evaluatedLeg.evidence_digest,
        native_replay_unit: evaluatedLeg.replay_unit,
        native_verification: evaluatedLeg.native_verification,
        mapped_caid: evaluatedLeg.caid,
        mapped_action_digest: evaluatedLeg.action_digest,
        role: evaluatedLeg.evidence_role,
        principal_kind: 'SYSTEM',
        principal_id: evaluatedLeg.subject.id,
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
      local_pep_preflight: null,
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

  const fixture = buildAuthzenPreflightFixture({
    call_fixture: entry.call_fixture,
    token_subject: entry.token_subject,
    require_named_human: entry.require_named_human,
    artifact_ref: `urn:emilia:wrapper:authzen-local-pep:${entry.id}`,
  });
  const {
    input: preflightInput,
    observation: localObservation,
    translated,
    pdpDecision,
  } = fixture;
  const materialCheck = relyingCheck({
    observedAction: translated.source_action,
    presentedCaid: translated.request.context.caid,
    approvedAction: APPROVED.action,
  });
  const preflight = evaluateAuthzenPreflight(preflightInput);
  const verifiedPolicyDecision = localObservation.boolean_decision;
  const policyInputMatchesVerifiedObservation = preflight.policy_input
    === (verifiedPolicyDecision ? 'ALLOW' : 'DENY');
  assert.equal(
    policyInputMatchesVerifiedObservation,
    true,
    `${entry.id}: preflight policy input diverged from the verified local observation`,
  );
  const aebInput = buildAebCase(entry, verifiedPolicyDecision, preflight);
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
      envelope_digest: preflight.evaluation.record.legs[0].evidence_digest,
    },
    local_pep_preflight: preflight,
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
      evidence_evaluator_version: AEB_EVALUATION_VERSION,
      evidence_evaluator_sha256: SOURCE_LOCK.evidence_evaluator.sha256,
      native_attestation_bridge_version: AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
      native_attestation_bridge_sha256: SOURCE_LOCK.native_attestation_bridge.sha256,
      aeb_kernel_sha256: SOURCE_LOCK.aeb_kernel.sha256,
    },
    claim_scope: {
      authzen_result_role: 'LOCAL_MACHINE_POLICY_INPUT',
      aeb_atomicity: AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
      lifecycle_evidence: 'PURE_STATE_MODEL_WITH_SUPPLIED_AUTHENTICATION_FACTS',
      guarantees: [
        'signed_local_pep_observation_evaluated_under_relying_party_pins',
        'exact_action_checked_before_admission',
        'preflight_lifecycle_axes_remain_unestablished',
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
        'unsigned_evaluation_as_credential',
        'preflight_reservation_or_provider_entry',
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
