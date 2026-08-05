// SPDX-License-Identifier: Apache-2.0
/**
 * Candidate CAID -> AEC -> AEB -> Agent Action Capsule composition vector.
 *
 * This runner exercises EMILIA's real CAID reference implementation, AEC
 * verifier, and governed AEB consequence kernel. It also supplies an
 * independent, deliberately bounded Class-1 Capsule verifier for the exact
 * fixture profile in this directory. It does not claim general Capsule
 * conformance or a second independent implementation.
 *
 * Run:
 *   node examples/composition/caid-aec-aeb-capsule-v1/run.mjs
 *   node examples/composition/caid-aec-aeb-capsule-v1/run.mjs --emit
 */

import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeCaid, verifyCaid } from '../../../caid/impl/js/caid.mjs';
import {
  AEC_VERSION,
  actionDigest,
  verifyAuthorizationChain,
} from '../../../packages/verify/evidence-chain.js';
import {
  AEB_CONSEQUENCE_CASE_VERSION,
  digestAebConsequenceCase,
  evaluateAebConsequenceCase,
} from '../../../packages/verify/aeb-consequence-conformance.js';
import {
  actionStateCapsuleId,
  createActionStateSignedStatement,
  verifyActionStateSignedStatement,
} from '../../../lib/grace/mobile-grid.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const FIXED_AT = '2026-08-04T20:00:00Z';
const CAPSULE_SPEC = 'draft-mih-scitt-agent-action-capsule-02';
const CAPSULE_FORMAT = '2';
const CAPSULE_KEY_ID = 'emilia-composition-vector-capsule-key';
const SUITE_VERSION = 'EP-CAID-AEC-AEB-CAPSULE-COMPOSITION-v1';
const RESULT_VERSION = 'EP-ACCOUNTABILITY-ATTEMPT-RESULT-v1';

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type RecordValue = Record<string, any>;

function isRecord(value: unknown): value is RecordValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sortJson(value: any): Json {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isRecord(value)) return value as Json;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortJson(value[key])]),
  ) as Json;
}

function canonical(value: any): string {
  return JSON.stringify(sortJson(value));
}

function sha256(value: string | Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function fileDigest(path: string): string {
  return sha256(readFileSync(resolve(ROOT, path)));
}

function digestLabel(label: string): string {
  return sha256(`EMILIA-COMPOSITION-V1\0${label}`);
}

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const CAPSULE_SEED = crypto.createHash('sha256')
  .update('ep:caid-aec-aeb-capsule:v1:capsule-key')
  .digest();
const CAPSULE_PRIVATE_KEY = crypto.createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519_PREFIX, CAPSULE_SEED]),
  format: 'der',
  type: 'pkcs8',
});
const CAPSULE_PUBLIC_KEY = crypto.createPublicKey(CAPSULE_PRIVATE_KEY as any);
const CAPSULE_PUBLIC_SPKI_B64U = CAPSULE_PUBLIC_KEY
  .export({ type: 'spki', format: 'der' })
  .toString('base64url');

function actionDefinitions(): any[] {
  const registry = JSON.parse(readFileSync(resolve(ROOT, 'caid/registry/action-types.json'), 'utf8'));
  if (!Array.isArray(registry.types)) throw new Error('CAID action registry has no types array');
  return registry.types;
}

const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  amount: '250000.00',
  currency: 'USD',
  beneficiary_account: `sha256:${'42'.repeat(32)}`,
  payment_instruction_id: 'payment:acme:2026-08-04:0001',
  memo: 'Approved supplier settlement',
});

const OTHER_ACTION = Object.freeze({
  ...ACTION,
  amount: '999999.00',
  payment_instruction_id: 'payment:other:2026-08-04:9999',
});

function computeAction(action: RecordValue): { caid: string; digest: string } {
  const computed = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: actionDefinitions(),
  });
  if (!('caid' in computed) || typeof computed.caid !== 'string'
      || typeof computed.digest !== 'string') {
    const reasons = 'refusals' in computed ? computed.refusals.join(',') : 'unknown';
    throw new Error(`CAID computation refused: ${reasons}`);
  }
  return { caid: computed.caid, digest: computed.digest };
}

const PRIMARY = computeAction(ACTION);
const OTHER = computeAction(OTHER_ACTION);

function nativeEvidence(
  id: string,
  actionDigestValue = PRIMARY.digest,
  acceptance: 'CURRENT' | 'STALE' = 'CURRENT',
): RecordValue[] {
  return [
    {
      type: 'human_authorization',
      evidence: {
        evidence_id: `human:${id}`,
        signature_valid: true,
        acceptance,
        action_digest: actionDigestValue,
        principal_id: 'human:jane.doe',
      },
    },
    {
      type: 'machine_policy',
      evidence: {
        evidence_id: `policy:${id}`,
        signature_valid: true,
        acceptance: 'CURRENT',
        action_digest: PRIMARY.digest,
        principal_id: 'organization:treasury-policy',
      },
    },
  ];
}

function aebEvidence(
  id: string,
  options: {
    humanCaid?: string;
    humanActionDigest?: string;
    humanValidUntil?: string;
  } = {},
): RecordValue[] {
  return [
    {
      wrapper_digest: digestLabel(`${id}:human:wrapper`),
      native_replay_unit: digestLabel(`${id}:human:replay`),
      native_verification: 'VERIFIED',
      mapped_caid: options.humanCaid ?? PRIMARY.caid,
      mapped_action_digest: options.humanActionDigest ?? PRIMARY.digest,
      role: 'human-authorization',
      principal_kind: 'HUMAN',
      principal_id: 'human:jane.doe',
      status: {
        verdict: 'CURRENT',
        authority_pinned: true,
        checked_at: '2026-08-04T19:59:00Z',
        valid_until: options.humanValidUntil ?? '2026-08-04T21:00:00Z',
      },
    },
    {
      wrapper_digest: digestLabel(`${id}:policy:wrapper`),
      native_replay_unit: digestLabel(`${id}:policy:replay`),
      native_verification: 'VERIFIED',
      mapped_caid: PRIMARY.caid,
      mapped_action_digest: PRIMARY.digest,
      role: 'machine-policy',
      principal_kind: 'ORGANIZATION',
      principal_id: 'organization:treasury-policy',
      status: {
        verdict: 'CURRENT',
        authority_pinned: true,
        checked_at: '2026-08-04T19:59:00Z',
        valid_until: '2026-08-04T21:00:00Z',
      },
    },
  ];
}

function operation(id: string): RecordValue {
  return {
    operation_id: `operation:${id}`,
    provider_id: 'provider:payments',
    initiator_id: 'agent:treasury-bot',
    executor_id: 'executor:payment-rail',
    caid: PRIMARY.caid,
    normalized_action_digest: PRIMARY.digest,
    requirements: [
      {
        role: 'human-authorization',
        principal_kind: 'HUMAN',
        minimum: 1,
        distinct_principals: true,
        exclude_initiator: true,
        exclude_executor: true,
      },
      {
        role: 'machine-policy',
        principal_kind: 'ORGANIZATION',
        minimum: 1,
        distinct_principals: true,
        exclude_initiator: true,
        exclude_executor: true,
      },
    ],
  };
}

function prior(
  id: string,
  custody: 'INVOKING' | 'TERMINAL' = 'INVOKING',
  providerOutcome = 'INDETERMINATE',
  effectRelation = 'INDETERMINATE',
): RecordValue {
  return {
    operation_id: `operation:${id}`,
    caid: PRIMARY.caid,
    normalized_action_digest: PRIMARY.digest,
    custody,
    provider_outcome: providerOutcome,
    effect_relation: effectRelation,
  };
}

function aebCase(
  id: string,
  overrides: RecordValue = {},
): RecordValue {
  return {
    '@version': AEB_CONSEQUENCE_CASE_VERSION,
    id,
    mode: overrides.mode ?? 'ADMISSION',
    evaluated_at: FIXED_AT,
    operation: operation(id),
    evidence: overrides.evidence ?? aebEvidence(id),
    local_policy: overrides.local_policy ?? 'PERMIT',
    reservation: overrides.reservation ?? {
      atomicity: 'local_atomic',
      prior_operations: [],
      consumed_native_replay_units: [],
    },
    observation: overrides.observation ?? null,
    reconciliation: overrides.reconciliation ?? null,
  };
}

function effectFor(kind: string): RecordValue {
  const base = {
    type: 'ai.emiliaprotocol.payment_release',
    external_ref: ACTION.payment_instruction_id,
    irreversibility_class: 'one_way_consequential',
  };
  if (kind === 'confirmed') {
    return {
      ...base,
      status: 'confirmed',
      request_digest: digestLabel('provider:request').slice(7),
      response_digest: digestLabel('provider:response').slice(7),
      effect_attestation: 'gate_executed',
    };
  }
  if (kind === 'dispatched') {
    return {
      ...base,
      status: 'dispatched',
      request_digest: digestLabel('provider:request').slice(7),
      effect_attestation: 'runtime_claimed',
    };
  }
  return { ...base, status: 'planned' };
}

function capsuleDisposition(kind: string, reasonCode: string | null): RecordValue {
  if (kind === 'confirmed') {
    return {
      decision: 'accept',
      approver: 'human',
      human_disposed: true,
      authority: `ep-caid:${PRIMARY.caid}`,
      verdict_class: 'executed',
    };
  }
  const verdict = kind === 'dispatched' ? 'timeout'
    : reasonCode === 'timeout_before_dispatch' ? 'timeout'
      : reasonCode === 'already_consumed' ? 'blocked'
        : 'denied';
  return {
    decision: 'reject',
    approver: 'policy',
    human_disposed: false,
    authority: `ep-caid:${PRIMARY.caid}`,
    verdict_class: verdict,
    reason_digest: digestLabel(`capsule:reason:${reasonCode ?? 'refused'}`).slice(7),
  };
}

function buildCapsule(id: string, kind: string, reasonCode: string | null): RecordValue {
  const effect = effectFor(kind);
  const effectMode = kind === 'confirmed' ? 'confirmed'
    : kind === 'dispatched' ? 'dispatched_unconfirmed'
      : 'not_applicable';
  const capsuleWithoutId = {
    spec_version: CAPSULE_SPEC,
    format_version: CAPSULE_FORMAT,
    action_id: `operation:${id}`,
    action_type: 'decide',
    operator: 'organization:example-treasury',
    developer: 'agent:treasury-bot:v1',
    timestamp: FIXED_AT,
    domain: 'action',
    provenance: 'gate',
    effect,
    assurance: {
      attestation_mode: 'self_attested',
      effect_mode: effectMode,
      ledger_mode: 'standalone',
    },
    disposition: capsuleDisposition(kind, reasonCode),
    constraints: [
      {
        id: 'ai.emiliaprotocol.exact_action',
        result: reasonCode === 'different_action_splice' ? 'fail' : 'pass',
        severity: 'critical',
        blocking: true,
        evidence_digest: PRIMARY.digest.slice(7),
      },
      {
        id: 'ai.emiliaprotocol.admission',
        result: kind === 'confirmed' || kind === 'dispatched' ? 'pass' : 'fail',
        severity: 'critical',
        blocking: true,
        evidence_digest: digestLabel(`admission:${id}`).slice(7),
      },
    ],
  };
  const capsuleId = actionStateCapsuleId(capsuleWithoutId);
  if (!capsuleId) throw new Error(`could not compute Capsule id for ${id}`);
  return {
    spec_version: capsuleWithoutId.spec_version,
    format_version: capsuleWithoutId.format_version,
    capsule_id: capsuleId,
    ...Object.fromEntries(
      Object.entries(capsuleWithoutId)
        .filter(([key]) => !['spec_version', 'format_version'].includes(key)),
    ),
  };
}

const KNOWN_NEVER_DISPATCH = new Set([
  'blocked', 'hitl_dispatched', 'denied', 'engine_failure', 'deferred',
  'needs_decision', 'expired', 'escalated', 'resolved',
]);
const KNOWN_EFFECT_STATUSES = new Set(['planned', 'dispatched', 'confirmed', 'failed', 'reverted']);
const KNOWN_DECISIONS = new Set(['accept', 'reject', 'needs_input', 'deferred']);
const KNOWN_APPROVERS = new Set(['human', 'policy']);
const KNOWN_ATTESTATIONS = new Set(['gate_executed', 'runtime_claimed']);
const KNOWN_IRREVERSIBILITY = new Set([
  'two_way', 'one_way_recoverable', 'one_way_consequential', 'one_way_terminal',
]);

function hasFloat(value: any): boolean {
  if (typeof value === 'number') return !Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.some(hasFloat);
  if (isRecord(value)) return Object.values(value).some(hasFloat);
  return false;
}

function class1Finding(id: string, ok: boolean, detail: string): RecordValue {
  return { id, status: ok ? 'PASS' : 'FAIL', detail };
}

/**
 * Bounded independent Class-1 verifier for these fixtures. This verifies the
 * public -00 invariants exercised here; it is not a claim of general Capsule
 * conformance and it never evaluates Class 2 without the private manifest.
 */
export function verifyCapsuleClass1Candidate(statement: RecordValue): RecordValue {
  const substrate = verifyActionStateSignedStatement(statement, {
    publicKeySpkiB64u: CAPSULE_PUBLIC_SPKI_B64U,
    keyId: CAPSULE_KEY_ID,
  });
  const capsule = substrate.capsule;
  const effect = capsule?.effect;
  const assurance = capsule?.assurance;
  const disposition = capsule?.disposition;
  const requiredShape = isRecord(capsule)
    && capsule.spec_version === CAPSULE_SPEC
    && capsule.format_version === CAPSULE_FORMAT
    && typeof capsule.capsule_id === 'string' && /^[0-9a-f]{64}$/.test(capsule.capsule_id)
    && typeof capsule.action_id === 'string'
    && ['fyi', 'decide'].includes(capsule.action_type)
    && typeof capsule.operator === 'string'
    && typeof capsule.developer === 'string'
    && typeof capsule.timestamp === 'string' && Number.isFinite(Date.parse(capsule.timestamp))
    && isRecord(effect) && KNOWN_EFFECT_STATUSES.has(effect.status)
    && isRecord(assurance) && isRecord(disposition)
    && !hasFloat(capsule);
  const capsuleIdOk = requiredShape && actionStateCapsuleId(capsule) === capsule.capsule_id;
  const confirmedBinding = effect?.status !== 'confirmed'
    || (typeof effect.response_digest === 'string' && /^[0-9a-f]{64}$/.test(effect.response_digest));
  const derivedEffectMode = effect?.status === 'confirmed' ? 'confirmed'
    : ['dispatched', 'failed', 'reverted'].includes(effect?.status)
      ? 'dispatched_unconfirmed'
      : 'not_applicable';
  const verdictEffectOk = !KNOWN_NEVER_DISPATCH.has(disposition?.verdict_class)
    || derivedEffectMode === 'not_applicable';
  const attestationRequired = derivedEffectMode !== 'not_applicable';
  const attestationOk = attestationRequired
    ? typeof effect?.effect_attestation === 'string'
    : effect?.effect_attestation === undefined;
  const chainOk = capsule?.chain === undefined && assurance?.ledger_mode === 'standalone';
  const assuranceOk = assurance?.attestation_mode === 'self_attested'
    && assurance?.effect_mode === derivedEffectMode
    && assurance?.ledger_mode === 'standalone';
  const dispositionOk = KNOWN_DECISIONS.has(disposition?.decision)
    && KNOWN_APPROVERS.has(disposition?.approver)
    && typeof disposition?.human_disposed === 'boolean'
    && (disposition.human_disposed !== true || disposition.approver === 'human');
  const registryInformational = [
    KNOWN_ATTESTATIONS.has(effect?.effect_attestation) || effect?.effect_attestation === undefined,
    KNOWN_IRREVERSIBILITY.has(effect?.irreversibility_class),
  ];
  const findings = [
    class1Finding('class1.substrate', substrate.valid === true, 'COSE_Sign1 and protected claims'),
    class1Finding('class1.structure', requiredShape, 'required fields, types, and integer-only JSON numbers'),
    class1Finding('class1.capsule_id', capsuleIdOk, 'recomputed normalized Capsule content address'),
    class1Finding('class1.confirmed_effect', confirmedBinding, 'confirmed requires response_digest'),
    class1Finding('class1.verdict_effect', verdictEffectOk, 'non-dispatch verdicts require not_applicable'),
    class1Finding('class1.effect_attestation', attestationOk, 'attestation matrix including planned carve'),
    class1Finding('class1.chain', chainOk, 'standalone fixture carries no unresolved parent'),
    class1Finding('class1.assurance', assuranceOk, 'assurance modes rederived from verified bytes'),
    class1Finding('class1.disposition_honesty', dispositionOk, 'human_disposed is consistent with approver'),
  ];
  if (registryInformational.some((known) => !known)) {
    findings.push({
      id: 'class1.registry',
      status: 'INFO',
      detail: 'unknown registry values remain informational and do not grade up',
    });
  } else {
    findings.push(class1Finding('class1.registry', true, 'fixture registry values are recognized'));
  }
  return {
    profile: CAPSULE_SPEC,
    class: 'CLASS_1_CANDIDATE',
    ok: findings.every((finding) => finding.status !== 'FAIL'),
    findings,
    capsule_id: capsule?.capsule_id ?? null,
    statement_digest: statement?.statement_digest ?? null,
    class_2: {
      status: 'NOT_EVALUATED',
      reason: 'constraint_manifest_and_private_evidence_not_supplied',
    },
    nonclaim: 'Bounded independent fixture verifier; not general Capsule conformance.',
  };
}

interface CaseDefinition {
  id: string;
  title: string;
  native: RecordValue[];
  aeb: RecordValue;
  required_bindings: string[];
  capsule_kind: 'confirmed' | 'dispatched' | 'planned';
  reason_code: string | null;
  extra_reason_codes?: string[];
  expected: RecordValue;
}

function expected(
  actionLinkage: string,
  evidenceSatisfaction: string,
  decision: string,
  admission: string,
  outcome: string,
  verifierStatus = 'PASS',
  reasonCodes: string[] = [],
): RecordValue {
  return {
    action_linkage: actionLinkage,
    principal_linkage: 'RESOLVED',
    evidence_satisfaction: evidenceSatisfaction,
    decision,
    admission,
    outcome,
    verifier_status: verifierStatus,
    reason_codes_include: reasonCodes,
  };
}

export function buildCases(): CaseDefinition[] {
  return [
    {
      id: 'positive_observed',
      title: 'Exact action admitted once and independently observed as requested',
      native: nativeEvidence('positive_observed'),
      aeb: aebCase('positive_observed', {
        mode: 'INVOCATION_OBSERVATION',
        reservation: {
          atomicity: 'local_atomic',
          prior_operations: [prior('positive_observed')],
          consumed_native_replay_units: [],
        },
        observation: {
          source: 'PROVIDER_EVIDENCE',
          provider_outcome: 'COMMITTED',
          effect_relation: 'OBSERVED_AS_REQUESTED',
        },
      }),
      required_bindings: ['capsule.class1'],
      capsule_kind: 'confirmed',
      reason_code: null,
      expected: expected('MATCH', 'SATISFIED', 'AUTHORIZED', 'CONSUMED', 'OBSERVED_AS_REQUESTED'),
    },
    {
      id: 'different_action_splice',
      title: 'Human evidence for a different payment is refused before admission',
      native: nativeEvidence('different_action_splice', OTHER.digest),
      aeb: aebCase('different_action_splice', {
        evidence: aebEvidence('different_action_splice', {
          humanCaid: OTHER.caid,
          humanActionDigest: OTHER.digest,
        }),
      }),
      required_bindings: ['capsule.class1'],
      capsule_kind: 'planned',
      reason_code: 'different_action_splice',
      expected: expected('MISMATCH', 'UNSATISFIED', 'NOT_AUTHORIZED', 'REFUSED', 'NONE', 'PASS', ['exact_action_mismatch']),
    },
    {
      id: 'stale_evidence',
      title: 'Cryptographically valid but stale authority cannot satisfy AEC',
      native: nativeEvidence('stale_evidence', PRIMARY.digest, 'STALE'),
      aeb: aebCase('stale_evidence', {
        evidence: aebEvidence('stale_evidence', { humanValidUntil: '2026-08-04T20:00:00Z' }),
      }),
      required_bindings: ['capsule.class1'],
      capsule_kind: 'planned',
      reason_code: 'stale_evidence',
      expected: expected('MATCH', 'UNSATISFIED', 'NOT_AUTHORIZED', 'REFUSED', 'NONE', 'PASS', ['evidence_stale']),
    },
    {
      id: 'already_consumed_replay',
      title: 'A second attempt is refused even though evidence remains valid',
      native: nativeEvidence('already_consumed_replay'),
      aeb: aebCase('already_consumed_replay', {
        reservation: {
          atomicity: 'local_atomic',
          prior_operations: [prior(
            'already_consumed_replay',
            'TERMINAL',
            'COMMITTED',
            'OBSERVED_AS_REQUESTED',
          )],
          consumed_native_replay_units: [],
        },
      }),
      required_bindings: ['capsule.class1'],
      capsule_kind: 'planned',
      reason_code: 'already_consumed',
      expected: expected('MATCH', 'SATISFIED', 'AUTHORIZED', 'REFUSED_ALREADY_CONSUMED', 'NONE', 'PASS', ['operation_replay']),
    },
    {
      id: 'timeout_before_dispatch',
      title: 'A pre-dispatch timeout produces no invocation and no outcome',
      native: nativeEvidence('timeout_before_dispatch'),
      aeb: aebCase('timeout_before_dispatch', { local_policy: 'DENY' }),
      required_bindings: ['capsule.class1'],
      capsule_kind: 'planned',
      reason_code: 'timeout_before_dispatch',
      extra_reason_codes: ['timeout_before_dispatch'],
      expected: expected('MATCH', 'SATISFIED', 'NOT_AUTHORIZED', 'REFUSED_TIMEOUT_BEFORE_DISPATCH', 'NONE', 'PASS', ['timeout_before_dispatch']),
    },
    {
      id: 'timeout_after_dispatch',
      title: 'A post-dispatch timeout is indeterminate and forbids blind retry',
      native: nativeEvidence('timeout_after_dispatch'),
      aeb: aebCase('timeout_after_dispatch', {
        mode: 'INVOCATION_OBSERVATION',
        reservation: {
          atomicity: 'local_atomic',
          prior_operations: [prior('timeout_after_dispatch')],
          consumed_native_replay_units: [],
        },
        observation: {
          source: 'TIMEOUT_AFTER_DISPATCH',
          provider_outcome: 'INDETERMINATE',
          effect_relation: 'INDETERMINATE',
        },
      }),
      required_bindings: ['capsule.class1'],
      capsule_kind: 'dispatched',
      reason_code: 'timeout_after_dispatch',
      expected: expected('MATCH', 'SATISFIED', 'AUTHORIZED', 'CONSUMED', 'INDETERMINATE', 'PASS', ['timeout_after_dispatch']),
    },
    {
      id: 'independent_observer_contradiction',
      title: 'Capsule runtime claim is preserved while an independent observer records divergence',
      native: nativeEvidence('independent_observer_contradiction'),
      aeb: aebCase('independent_observer_contradiction', {
        mode: 'INVOCATION_OBSERVATION',
        reservation: {
          atomicity: 'local_atomic',
          prior_operations: [prior('independent_observer_contradiction')],
          consumed_native_replay_units: [],
        },
        observation: {
          source: 'PROVIDER_EVIDENCE',
          provider_outcome: 'COMMITTED',
          effect_relation: 'DIVERGED',
        },
      }),
      required_bindings: ['capsule.class1'],
      capsule_kind: 'confirmed',
      reason_code: null,
      extra_reason_codes: ['independent_observer_contradiction'],
      expected: expected('MATCH', 'SATISFIED', 'AUTHORIZED', 'CONSUMED', 'DIVERGENT', 'PASS', ['provider_committed_effect_diverged', 'independent_observer_contradiction']),
    },
    {
      id: 'unsupported_required_binding',
      title: 'An unknown required binding returns a structured refusal, never pass or crash',
      native: nativeEvidence('unsupported_required_binding'),
      aeb: aebCase('unsupported_required_binding'),
      required_bindings: ['capsule.class1', 'capsule.class3'],
      capsule_kind: 'planned',
      reason_code: 'unsupported_required_binding',
      expected: expected('MATCH', 'INDETERMINATE', 'INDETERMINATE', 'REFUSED', 'NONE', 'REFUSED', ['unsupported_required_binding:capsule.class3']),
    },
  ];
}

function evaluateAec(item: CaseDefinition): RecordValue {
  const chain = {
    '@version': AEC_VERSION,
    action: ACTION,
    action_digest: PRIMARY.digest,
    requirement: 'human_authorization AND machine_policy',
    components: item.native,
  };
  const verifier = (evidence: RecordValue): RecordValue => ({
    valid: evidence?.signature_valid === true && evidence?.acceptance === 'CURRENT',
    action_digest: evidence?.action_digest ?? null,
    detail: {
      principal_id: evidence?.principal_id ?? null,
      native_signature: evidence?.signature_valid === true ? 'VERIFIED' : 'FAILED',
      profile_acceptance: evidence?.acceptance ?? 'UNKNOWN',
    },
  });
  return verifyAuthorizationChain(chain, {
    requirement: 'human_authorization AND machine_policy',
    expectedActionDigest: PRIMARY.digest,
    verifiers: {
      human_authorization: verifier,
      machine_policy: verifier,
    },
  });
}

function mapAdmission(item: CaseDefinition, aeb: RecordValue): string {
  if (item.id === 'already_consumed_replay') return 'REFUSED_ALREADY_CONSUMED';
  if (item.id === 'timeout_before_dispatch') return 'REFUSED_TIMEOUT_BEFORE_DISPATCH';
  if (aeb.reservation === 'CONSUMED') return 'CONSUMED';
  if (aeb.decision === 'ADMIT') return 'ADMITTED';
  return 'REFUSED';
}

function mapOutcome(admission: string, aeb: RecordValue): string {
  // An outcome belongs to this attempt, not to a prior attempt that caused a
  // replay refusal. Nothing refused before dispatch may inherit an outcome.
  if (admission.startsWith('REFUSED')) return 'NONE';
  if (aeb.effect_relation === 'DIVERGED') return 'DIVERGENT';
  if (aeb.decision === 'INDETERMINATE' || aeb.effect_relation === 'INDETERMINATE') {
    return 'INDETERMINATE';
  }
  if (aeb.effect_relation === 'OBSERVED_AS_REQUESTED') return 'OBSERVED_AS_REQUESTED';
  return 'NONE';
}

function structuredRefusal(
  item: CaseDefinition,
  nativeResults: RecordValue[],
  capsuleResult: RecordValue,
  unsupported: string,
): RecordValue {
  return {
    '@version': RESULT_VERSION,
    attempt_id: item.id,
    native_results: [...nativeResults, capsuleResult],
    action_linkage: 'MATCH',
    principal_linkage: 'RESOLVED',
    evidence_satisfaction: 'INDETERMINATE',
    decision: 'INDETERMINATE',
    admission: 'REFUSED',
    outcome: 'NONE',
    reason_codes: [`unsupported_required_binding:${unsupported}`],
    verifier: { status: 'REFUSED', crashed: false },
  };
}

export function evaluateCase(item: CaseDefinition): RecordValue {
  try {
    const computed = computeAction(ACTION);
    const caidVerification = verifyCaid(ACTION, computed.caid, {
      definitions: actionDefinitions(),
    });
    const aec = evaluateAec(item);
    const capsule = buildCapsule(item.id, item.capsule_kind, item.reason_code);
    const statement = createActionStateSignedStatement(capsule, {
      privateKey: CAPSULE_PRIVATE_KEY,
      keyId: CAPSULE_KEY_ID,
    });
    const capsuleClass1 = verifyCapsuleClass1Candidate(statement);
    const nativeResults = [
      {
        profile: 'CAID',
        status: caidVerification.valid ? 'VERIFIED' : 'FAILED',
        caid: computed.caid,
        action_digest: computed.digest,
        reasons: caidVerification.reasons,
      },
      ...item.native.map((component) => ({
        profile: component.type,
        status: component.evidence.signature_valid ? 'VERIFIED' : 'FAILED',
        profile_acceptance: component.evidence.acceptance,
        action_digest: component.evidence.action_digest,
        principal_id: component.evidence.principal_id,
      })),
      {
        profile: 'AEC',
        status: aec.satisfied ? 'SATISFIED' : 'UNSATISFIED',
        action_digest: aec.action_digest,
        expected_action_bound: aec.expected_action_bound,
        reasons: aec.reasons,
      },
    ];
    const capsuleResult = {
      profile: CAPSULE_SPEC,
      status: capsuleClass1.ok ? 'VERIFIED' : 'FAILED',
      class_1: capsuleClass1,
      class_2: capsuleClass1.class_2,
      signed_statement: statement,
    };
    const unsupported = item.required_bindings.find(
      (binding) => !['capsule.class1', 'capsule.class2'].includes(binding),
    );
    if (unsupported) return structuredRefusal(item, nativeResults, capsuleResult, unsupported);

    const aeb = evaluateAebConsequenceCase(item.aeb);
    const actionLinkage = aeb.action_match === 'MATCH' && aec.expected_action_bound
      ? 'MATCH' : aeb.action_match;
    const evidenceSatisfaction = aec.satisfied ? 'SATISFIED' : 'UNSATISFIED';
    const decision = !aec.satisfied || item.id === 'timeout_before_dispatch'
      ? 'NOT_AUTHORIZED'
      : aeb.authorization;
    const admission = mapAdmission(item, aeb);
    const reasonCodes = [...new Set([
      ...aeb.reasons,
      ...(item.extra_reason_codes ?? []),
    ])].sort();
    return {
      '@version': RESULT_VERSION,
      attempt_id: item.id,
      native_results: [
        ...nativeResults,
        { profile: 'AEB', status: aeb.decision, case_digest: digestAebConsequenceCase(item.aeb), result: aeb },
        capsuleResult,
      ],
      action_linkage: actionLinkage,
      principal_linkage: 'RESOLVED',
      evidence_satisfaction: evidenceSatisfaction,
      decision,
      admission,
      outcome: mapOutcome(admission, aeb),
      reason_codes: reasonCodes,
      verifier: { status: 'PASS', crashed: false },
    };
  } catch (error) {
    return {
      '@version': RESULT_VERSION,
      attempt_id: item.id,
      native_results: [],
      action_linkage: 'INDETERMINATE',
      principal_linkage: 'INDETERMINATE',
      evidence_satisfaction: 'INDETERMINATE',
      decision: 'INDETERMINATE',
      admission: 'REFUSED',
      outcome: 'NONE',
      reason_codes: ['composition_verifier_internal_error'],
      verifier: {
        status: 'ERROR',
        crashed: false,
        detail: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

function actualSummary(result: RecordValue): RecordValue {
  return {
    action_linkage: result.action_linkage,
    principal_linkage: result.principal_linkage,
    evidence_satisfaction: result.evidence_satisfaction,
    decision: result.decision,
    admission: result.admission,
    outcome: result.outcome,
    verifier_status: result.verifier?.status,
  };
}

function verifyExpected(item: CaseDefinition, result: RecordValue): RecordValue {
  const expectedAxes = { ...item.expected };
  delete expectedAxes.reason_codes_include;
  const axesMatch = canonical(actualSummary(result)) === canonical(expectedAxes);
  const expectedReasons = item.expected.reason_codes_include ?? [];
  const reasonsMatch = expectedReasons.every((reason: string) => result.reason_codes.includes(reason));
  const noCrash = result.verifier?.crashed === false && result.verifier?.status !== 'ERROR';
  return {
    id: item.id,
    passed: axesMatch && reasonsMatch && noCrash,
    axes_match: axesMatch,
    reasons_match: reasonsMatch,
    no_crash: noCrash,
    expected: item.expected,
    actual: actualSummary(result),
    reason_codes: result.reason_codes,
  };
}

function sourceManifest(): RecordValue {
  const implementationSources = [
    'caid/registry/action-types.json',
    'packages/verify/evidence-chain.js',
    'packages/verify/aeb-consequence-conformance.js',
    'lib/grace/mobile-grid.js',
    'examples/composition/caid-aec-aeb-capsule-v1/run.mts',
  ].map((path) => ({ path, sha256: fileDigest(path) }));
  return {
    '@version': 'EP-COMPOSITION-VECTOR-MANIFEST-v1',
    suite: SUITE_VERSION,
    status: 'candidate-emilia-owned-composition-vector',
    source_tree_parent: '4b159115bae7aa4273783c9340f9729a08377992',
    generated_at: FIXED_AT,
    drafts: [
      {
        role: 'CAID',
        revision: 'draft-schrock-canonical-action-identifier-01',
        url: 'https://www.ietf.org/archive/id/draft-schrock-canonical-action-identifier-01.txt',
        sha256: 'sha256:067fe16bcb6026794306c916d92ca5f9229aba2d2ff9e678a1f380e0315bb73d',
      },
      {
        role: 'AEC',
        revision: 'draft-schrock-ep-authorization-evidence-chain-05',
        url: 'https://www.ietf.org/archive/id/draft-schrock-ep-authorization-evidence-chain-05.txt',
        sha256: 'sha256:ea906a245e5e193d6edf3ae52e77810ea1ffa6d06bdfd3ab962be602d91662b7',
      },
      {
        role: 'AEB',
        revision: 'draft-schrock-action-evidence-boundary-03',
        url: 'https://www.ietf.org/archive/id/draft-schrock-action-evidence-boundary-03.txt',
        sha256: 'sha256:f25af52c9f88f82777f26accdb9205ba242219d66f2ac16e5bfc8d276b441fde',
      },
      {
        role: 'Capsule WHAT',
        revision: CAPSULE_SPEC,
        url: 'https://www.ietf.org/archive/id/draft-mih-scitt-agent-action-capsule-02.txt',
        sha256: 'sha256:493428486c85e03624bc1d90e8265b072b98265b93b7bd50d55824688a1802d8',
      },
      {
        role: 'Composition',
        revision: 'draft-mih-sato-agent-accountability-composition-00',
        url: 'https://www.ietf.org/archive/id/draft-mih-sato-agent-accountability-composition-00.txt',
        sha256: 'sha256:3649831a2908fdee5cf11015965d24711f67e89bffdce193220d2bd50925919f',
      },
    ],
    implementation_sources: implementationSources,
    capsule_verifier_scope: {
      class_1: 'independent candidate verifier bounded to these fixtures',
      class_2: 'not evaluated without producer manifest and private evidence',
      general_conformance_claim: false,
    },
    freeze_rule: 'candidate freezes only after a second independent implementation reproduces the exact bundle',
  };
}

export function runSuite(): RecordValue {
  const cases = buildCases();
  const results = cases.map((item) => evaluateCase(item));
  const checks = cases.map((item, index) => verifyExpected(item, results[index]));
  const manifest = sourceManifest();
  const manifestDigest = sha256(canonical(manifest));
  const bundle = {
    '@version': SUITE_VERSION,
    manifest_digest: manifestDigest,
    action: ACTION,
    caid: PRIMARY.caid,
    action_digest: PRIMARY.digest,
    capsule_public_key_spki_b64u: CAPSULE_PUBLIC_SPKI_B64U,
    capsule_key_id: CAPSULE_KEY_ID,
    cases: cases.map((item) => ({
      id: item.id,
      title: item.title,
      native_evidence: item.native,
      aeb_case: item.aeb,
      required_bindings: item.required_bindings,
      capsule_kind: item.capsule_kind,
      expected: item.expected,
    })),
  };
  const report = {
    '@version': 'EP-COMPOSITION-VECTOR-RUN-REPORT-v1',
    implementation: 'emilia-js-candidate',
    implementation_owner: 'EMILIA Protocol',
    generated_at: FIXED_AT,
    manifest_digest: manifestDigest,
    bundle_digest: sha256(canonical(bundle)),
    passed: checks.every((check) => check.passed),
    case_count: checks.length,
    checks,
    results,
    independence: {
      same_team: true,
      external_confirmation: false,
      claim: 'candidate vector execution, not independent interoperability',
    },
  };
  return { manifest, bundle, report };
}

function emitArtifacts(run: RecordValue): void {
  const files: Array<[string, RecordValue]> = [
    ['manifest.json', run.manifest],
    ['bundle.json', run.bundle],
    ['report.emilia-js.json', run.report],
    ['external-report.template.json', {
      '@version': 'EP-COMPOSITION-VECTOR-EXTERNAL-REPORT-v1',
      status: 'AWAITING_INDEPENDENT_RUN',
      implementation: null,
      implementation_owner: null,
      manifest_digest: run.report.manifest_digest,
      bundle_digest: run.report.bundle_digest,
      capsule_profile: CAPSULE_SPEC,
      class_1: null,
      class_2: null,
      per_case_results: null,
      signed_by: null,
      generated_at: null,
    }],
  ];
  for (const [name, value] of files) {
    writeFileSync(resolve(HERE, name), `${JSON.stringify(value, null, 2)}\n`);
  }
  const checksums = files
    .map(([name]) => `${fileDigest(relative(ROOT, resolve(HERE, name))).slice(7)}  ${name}`)
    .join('\n');
  writeFileSync(resolve(HERE, 'CHECKSUMS.sha256'), `${checksums}\n`);
}

function main(): void {
  const run = runSuite();
  for (const check of run.report.checks) {
    process.stdout.write(`${check.passed ? 'PASS' : 'FAIL'} ${check.id}\n`);
  }
  process.stdout.write(
    `${run.report.passed ? 'COMPOSITION VECTOR PASS' : 'COMPOSITION VECTOR FAIL'} — `
    + `${run.report.case_count} attempt-scoped cases, no verifier crashes\n`,
  );
  if (process.argv.includes('--emit')) {
    emitArtifacts(run);
    process.stdout.write(`wrote frozen candidate artifacts under ${relative(ROOT, HERE)}\n`);
  }
  if (!run.report.passed) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) main();
