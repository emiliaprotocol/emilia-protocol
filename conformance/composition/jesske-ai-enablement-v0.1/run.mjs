// SPDX-License-Identifier: Apache-2.0
/**
 * Runnable, format-neutral Jesske AI enablement -00 authorization-evidence
 * carrier composition. The interface carries opaque bytes; the relying party
 * alone pins and invokes this illustrative verifier profile.
 */
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeCaid } from '../../../packages/verify/vendor/caid.mjs';
import {
  InMemoryAebConsumptionStore,
  adapterPinDigest,
  authorizeAebExecution,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  verifyAebEvaluation,
} from '../../../packages/verify/aeb-adapter-contract.js';
import { canonicalizeStrictJson } from '../../../packages/verify/strict-json.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = JSON.parse(readFileSync(resolve(HERE, 'vectors.json'), 'utf8'));

const ADAPTER_ID = 'jesske-authorization-evidence';
const ADAPTER_VERSION = 'JESSKE-AUTHORIZATION-EVIDENCE-ADAPTER-v0.1';
const PROFILE_ID = 'jesske:call-recording-start';
const PROFILE_VERSION = 'JESSKE-CALL-RECORDING-CAID-MAPPING-v0.1';
const MAPPER_ID = 'mapper:jesske-call-recording-start-v0.1';
const ROLE = 'call-recording-authorization';
const REQUIREMENT_ID = 'requirement:jesske-call-recording-authorization';
const RP_ID = 'rp:multimedia-ai-gateway';
const AUTHORIZATION_KEY_ID = 'authorization-fixture-1';
const EVALUATOR_KEY_ID = 'evaluator:jesske-fixture-1';
const EVIDENCE_PROFILE = 'RP-CALL-RECORDING-AUTHORIZATION-v0.1';
const COMPACT_TYPE = 'authorization-evidence+jws';

export const CARRIER_CONTRACT = Object.freeze({
  member: 'authorization_evidence',
  location: 'request metadata',
  value_semantics: 'opaque',
  interface_evidence_schema: null,
  verifier_selection: 'relying-party-pinned',
});

const ACTION_DEFINITION = Object.freeze({
  action_type: 'call.recording.start.1',
  required_fields: [
    { name: 'action_type', type: 'string' },
    { name: 'call_id', type: 'string' },
    { name: 'participants', type: 'array' },
    { name: 'purpose', type: 'string' },
    { name: 'destination', type: 'string' },
    { name: 'time_window', type: 'object' },
  ],
  optional_fields: [],
});

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function exactText(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 2048
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function instant(value) {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return NaN;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return NaN;
  const canonical = new Date(milliseconds).toISOString();
  return canonical.slice(0, 19) === value.slice(0, 19) ? milliseconds : NaN;
}

function privateKey(hex) {
  return crypto.createPrivateKey({ key: Buffer.from(hex, 'hex'), format: 'der', type: 'pkcs8' });
}

function publicSpki(key) {
  return crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
}

function statusDigest(status) {
  return digestAeb({
    checked_at: status.checked_at,
    expires_at: status.expires_at,
    revocation_checked: status.revocation_checked,
    revoked: status.revoked,
    consumed: status.consumed,
    unavailable: status.unavailable === true,
  });
}

function actionShape(action) {
  if (!exactKeys(action, ['action_type', 'call_id', 'participants', 'purpose', 'destination', 'time_window'])
      || action.action_type !== ACTION_DEFINITION.action_type
      || !exactText(action.call_id) || !exactText(action.purpose) || !exactText(action.destination)
      || !Array.isArray(action.participants) || action.participants.length < 2
      || action.participants.some((participant) => !exactText(participant))
      || new Set(action.participants).size !== action.participants.length
      || canonicalizeStrictJson(action.participants) !== canonicalizeStrictJson([...action.participants].sort())
      || !exactKeys(action.time_window, ['start', 'end'])) return false;
  const start = instant(action.time_window.start);
  const end = instant(action.time_window.end);
  return Number.isFinite(start) && Number.isFinite(end) && start < end;
}

function claimShape(claim) {
  if (!exactKeys(claim, [
    '@version', 'evidence_id', 'issuer', 'audience', 'subject', 'issued_at',
    'valid_from', 'valid_until', 'action', 'caid', 'action_digest',
  ]) || claim['@version'] !== EVIDENCE_PROFILE || !exactText(claim.evidence_id)
      || !exactText(claim.issuer) || !exactText(claim.audience)
      || !exactKeys(claim.subject, ['id', 'kind']) || !exactText(claim.subject.id)
      || claim.subject.kind !== 'organization' || !actionShape(claim.action)
      || !Number.isFinite(instant(claim.issued_at)) || !Number.isFinite(instant(claim.valid_from))
      || !Number.isFinite(instant(claim.valid_until))) return false;
  const computed = computeCaid(claim.action, { suite: 'jcs-sha256', definitions: [ACTION_DEFINITION] });
  return typeof computed.caid === 'string' && claim.caid === computed.caid
    && claim.action_digest === digestAeb(claim.action)
    && instant(claim.issued_at) <= instant(claim.valid_from)
    && instant(claim.valid_from) < instant(claim.valid_until);
}

function encodePart(value) {
  return Buffer.from(canonicalizeStrictJson(value), 'utf8').toString('base64url');
}

function decodePart(value) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) return null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = JSON.parse(text);
    return canonicalizeStrictJson(parsed) === text ? parsed : null;
  } catch {
    return null;
  }
}

function mintEvidence(unsignedClaim, signer) {
  const computed = computeCaid(unsignedClaim.action, {
    suite: 'jcs-sha256', definitions: [ACTION_DEFINITION],
  });
  if (typeof computed.caid !== 'string') throw new TypeError('fixture action does not produce a CAID');
  const claim = {
    ...structuredClone(unsignedClaim),
    caid: computed.caid,
    action_digest: digestAeb(unsignedClaim.action),
  };
  const header = { alg: 'EdDSA', kid: AUTHORIZATION_KEY_ID, typ: COMPACT_TYPE };
  const signingInput = `${encodePart(header)}.${encodePart(claim)}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), signer).toString('base64url');
  return `${signingInput}.${signature}`;
}

function parseEvidence(artifact) {
  if (typeof artifact !== 'string') return { ok: false, reason: 'authorization_evidence_missing' };
  const parts = artifact.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'authorization_evidence_malformed' };
  const header = decodePart(parts[0]);
  const claim = decodePart(parts[1]);
  const signature = Buffer.from(parts[2], 'base64url');
  if (!exactKeys(header, ['alg', 'kid', 'typ']) || header.alg !== 'EdDSA'
      || header.kid !== AUTHORIZATION_KEY_ID || header.typ !== COMPACT_TYPE
      || !claimShape(claim) || signature.length !== 64
      || signature.toString('base64url') !== parts[2]) {
    return { ok: false, reason: 'authorization_evidence_malformed' };
  }
  return { ok: true, header, claim, signature, signing_input: `${parts[0]}.${parts[1]}` };
}

function makeAdapter() {
  return Object.freeze({
    id: ADAPTER_ID,
    version: ADAPTER_VERSION,
    verifyNative(input) {
      const base = {
        evidence_digest: digestAeb(input.artifact),
        status_digest: statusDigest(input.status),
        evidence_role: ROLE,
        subject: { id: 'organization:unknown', kind: 'organization' },
        replay_unit: digestAeb({ profile: EVIDENCE_PROFILE, artifact: input.artifact }),
      };
      const parsed = parseEvidence(input.artifact);
      if (!parsed.ok) {
        return {
          ...base, native_verification: 'FAILED', acceptance: 'REJECTED', reasons: [parsed.reason],
        };
      }
      base.subject = parsed.claim.subject;
      base.replay_unit = digestAeb({
        profile: EVIDENCE_PROFILE,
        issuer: parsed.claim.issuer,
        evidence_id: parsed.claim.evidence_id,
        key_id: parsed.header.kid,
      });
      const root = input.trust_roots.find((candidate) => (
        candidate.issuer === parsed.claim.issuer && candidate.key_id === parsed.header.kid
      ));
      let signatureValid = false;
      try {
        signatureValid = Boolean(root) && crypto.verify(
          null,
          Buffer.from(parsed.signing_input, 'ascii'),
          crypto.createPublicKey({
            key: Buffer.from(root.public_key, 'base64url'), format: 'der', type: 'spki',
          }),
          parsed.signature,
        );
      } catch {
        signatureValid = false;
      }
      if (!signatureValid) {
        return {
          ...base,
          subject: parsed.claim.subject,
          replay_unit: base.replay_unit,
          native_verification: 'FAILED',
          acceptance: 'REJECTED',
          reasons: ['authorization_evidence_signature_invalid'],
        };
      }
      const reasons = [];
      const now = instant(input.now);
      if (parsed.claim.issuer !== input.adapter_config.issuer
          || parsed.claim.audience !== input.adapter_config.audience) {
        reasons.push('authorization_evidence_scope_mismatch');
      }
      if (now < instant(parsed.claim.valid_from) || now >= instant(parsed.claim.valid_until)) {
        reasons.push('authorization_evidence_outside_validity');
      }
      if (now < instant(parsed.claim.action.time_window.start)
          || now >= instant(parsed.claim.action.time_window.end)) {
        reasons.push('outside_action_window');
      }
      return {
        ...base,
        subject: parsed.claim.subject,
        replay_unit: base.replay_unit,
        native_verification: 'VERIFIED',
        acceptance: reasons.length === 0 ? 'ACCEPTED' : 'REJECTED',
        reasons,
      };
    },
    mapAction(input) {
      if (input.native.native_verification !== 'VERIFIED') {
        return {
          mapping: 'INDETERMINATE', caid: null, action_digest: null,
          reasons: ['native_verification_required'],
        };
      }
      const parsed = parseEvidence(input.artifact);
      if (!parsed.ok || input.profile.mapper_id !== MAPPER_ID
          || input.profile.version !== PROFILE_VERSION) {
        return {
          mapping: 'INDETERMINATE', caid: null, action_digest: null,
          reasons: ['mapping_profile_mismatch'],
        };
      }
      return {
        mapping: 'MATCH',
        caid: parsed.claim.caid,
        action_digest: parsed.claim.action_digest,
        reasons: [],
      };
    },
  });
}

function registryEntry(id, kind, version, definition) {
  const entry = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

function setup() {
  const authorizationPrivateKey = privateKey(CORPUS.fixtures.authorization_private_key_pkcs8_hex);
  const evaluatorPrivateKey = privateKey(CORPUS.fixtures.evaluator_private_key_pkcs8_hex);
  const authorizationEvidence = mintEvidence(CORPUS.fixtures.authorization_claim, authorizationPrivateKey);
  const adapter = makeAdapter();
  const profile = {
    version: PROFILE_VERSION,
    definition: {
      '@version': PROFILE_VERSION,
      source_protocol: CORPUS.source.revision,
      source_member: CARRIER_CONTRACT.member,
      projection: 'jesske-call-recording-request-metadata-v0.1',
      suite: 'jcs-sha256',
      definitions: [ACTION_DEFINITION],
    },
    registry_entry_ref: 'mapping:jesske-call-recording-start',
    mapper_id: MAPPER_ID,
    resolver: {
      id: MAPPER_ID,
      version: '0.1',
      implementation_digest: digestAeb({ implementation: MAPPER_ID, version: '0.1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'request_id', 'user_metadata', 'payload', 'authorization_evidence',
      ],
    },
  };
  profile.profile_digest = mappingProfileDigest(PROFILE_ID, profile);
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:jesske-ai-enablement-v0.1',
    epoch: 1,
    entries: {
      [profile.registry_entry_ref]: registryEntry(
        profile.registry_entry_ref,
        'mapping-profile',
        '0.1',
        { profile_digest: profile.profile_digest },
      ),
      [`role:${ROLE}`]: registryEntry(
        `role:${ROLE}`,
        'evidence-role',
        '0.1',
        { role: ROLE, subject_kinds: ['organization'] },
      ),
    },
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const trustRoots = [{
    issuer: CORPUS.fixtures.authorization_claim.issuer,
    key_id: AUTHORIZATION_KEY_ID,
    algorithm: 'Ed25519',
    public_key: publicSpki(authorizationPrivateKey),
  }];
  const adapterConfig = {
    profile: EVIDENCE_PROFILE,
    evidence_role: ROLE,
    issuer: CORPUS.fixtures.authorization_claim.issuer,
    audience: CORPUS.fixtures.authorization_claim.audience,
    action_type: ACTION_DEFINITION.action_type,
  };
  const adapterPin = {
    version: adapter.version,
    trust_roots: trustRoots,
    config: adapterConfig,
    max_status_age_sec: 900,
  };
  adapterPin.config_digest = adapterPinDigest(adapter.id, adapterPin);
  const config = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: RP_ID,
    evaluator_keys: {
      [EVALUATOR_KEY_ID]: { public_key: publicSpki(evaluatorPrivateKey) },
    },
    registry,
    accepted_mappers: [MAPPER_ID],
    adapters: { [adapter.id]: adapterPin },
    profiles: { [PROFILE_ID]: profile },
    requirements: {
      [REQUIREMENT_ID]: {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: [ROLE],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  return {
    adapter, authorizationEvidence, config, evaluatorPrivateKey,
    store: new InMemoryAebConsumptionStore(),
  };
}

function projectAction(request) {
  const metadata = request.metadata;
  if (metadata?.task_type !== 'call.recording.start') {
    throw new TypeError('unsupported Jesske task type');
  }
  const action = {
    action_type: ACTION_DEFINITION.action_type,
    call_id: metadata.call_id,
    participants: Array.isArray(metadata.participants)
      ? [...metadata.participants].sort()
      : metadata.participants,
    purpose: metadata.purpose,
    destination: metadata.destination,
    time_window: structuredClone(metadata.time_window),
  };
  if (!actionShape(action)) throw new TypeError('invalid call.recording.start action');
  return action;
}

function applyMutations(source, mutations) {
  const result = structuredClone(source);
  for (const mutation of mutations) {
    let parent = result;
    for (const segment of mutation.path.slice(0, -1)) parent = parent[segment];
    const key = mutation.path.at(-1);
    if (mutation.op === 'replace') parent[key] = structuredClone(mutation.value);
    else if (mutation.op === 'remove') delete parent[key];
    else throw new TypeError(`unsupported mutation ${mutation.op}`);
  }
  return result;
}

function evidenceStatus() {
  return {
    checked_at: '2026-08-16T17:59:30Z',
    expires_at: '2026-08-16T18:10:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
}

function materializeRequest(entry, authorizationEvidence) {
  const request = structuredClone(CORPUS.fixtures.request);
  request.metadata.authorization_evidence = authorizationEvidence;
  return applyMutations(request, entry.mutations);
}

function classifyReason(leg, decision) {
  if (leg.reasons.includes('authorization_evidence_missing')) return 'authorization_evidence_missing';
  if (leg.reasons.includes('outside_action_window')) return 'outside_action_window';
  if (leg.mapping === 'MISMATCH') return 'exact_action_mismatch';
  return decision.reason;
}

function runCase(entry, fixture) {
  const request = materializeRequest(entry, fixture.authorizationEvidence);
  const expectedAction = projectAction(request);
  const computed = computeCaid(expectedAction, {
    suite: 'jcs-sha256', definitions: [ACTION_DEFINITION],
  });
  if (typeof computed.caid !== 'string') throw new TypeError('request action does not produce a CAID');
  const artifactRef = `jesske:${request.request_id}:authorization-evidence`;
  const artifact = request.metadata.authorization_evidence ?? null;
  const status = evidenceStatus();
  const evaluation = evaluateAebEvidence({
    config: fixture.config,
    adapters: { [fixture.adapter.id]: fixture.adapter },
    operation_id: request.request_id,
    consumption_nonce: `nonce:${request.request_id}`,
    initiator_id: 'workload:multimedia-framework',
    executor_id: 'workload:ai-enablement-gateway',
    requirement_ref: REQUIREMENT_ID,
    caid: computed.caid,
    expected_action: expectedAction,
    legs: [{
      adapter_id: fixture.adapter.id,
      profile_id: PROFILE_ID,
      artifact_ref: artifactRef,
      artifact,
      status,
    }],
    evaluated_at: entry.now,
    signer: { key_id: EVALUATOR_KEY_ID, private_key: fixture.evaluatorPrivateKey },
  });
  const verification = verifyAebEvaluation(evaluation.record, {
    mode: 'execution',
    config: fixture.config,
    adapters: { [fixture.adapter.id]: fixture.adapter },
    artifacts: { [artifactRef]: artifact },
    current_statuses: { [artifactRef]: status },
    expected_action: expectedAction,
    now: entry.now,
  });
  const locallyAuthorized = verification.valid && verification.execution_authorizing
    && evaluation.record.verdict === 'SATISFIED';
  const decision = authorizeAebExecution(evaluation.record, {
    verification,
    local_authorization: locallyAuthorized,
    store: fixture.store,
  });
  const leg = evaluation.record.legs[0];
  const observed = {
    native_verification: leg.native_verification,
    acceptance: leg.acceptance,
    action_match: leg.mapping,
    evidence_satisfaction: evaluation.record.verdict,
    local_authorization: locallyAuthorized ? 'AUTHORIZED' : 'NOT_AUTHORIZED',
    admission: decision.allowed ? 'RESERVED' : 'REFUSED',
    reason: classifyReason(leg, decision),
  };
  return {
    id: entry.id,
    passed: canonicalizeStrictJson(observed) === canonicalizeStrictJson(entry.expected),
    caid: computed.caid,
    observed,
    expected: entry.expected,
  };
}

export function runSuite() {
  const fixture = setup();
  const cases = CORPUS.cases.map((entry) => runCase(entry, fixture));
  return {
    '@version': CORPUS['@version'],
    source: CORPUS.source,
    composition: {
      interface_member: CARRIER_CONTRACT.member,
      interface_value_semantics: CARRIER_CONTRACT.value_semantics,
      rp_evidence_profile: EVIDENCE_PROFILE,
      action_type: ACTION_DEFINITION.action_type,
      caid_suite: 'jcs-sha256',
      evidence_boundary: 'AEB-ADAPTER-v1',
      admission_store: 'InMemoryAebConsumptionStore',
      jesske_depends_on_emilia: false,
    },
    cases,
    summary: {
      passed: cases.filter((entry) => entry.passed).length,
      total: cases.length,
    },
    passed: cases.every((entry) => entry.passed),
    scope_limits: CORPUS.scope_limits,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = runSuite();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}
