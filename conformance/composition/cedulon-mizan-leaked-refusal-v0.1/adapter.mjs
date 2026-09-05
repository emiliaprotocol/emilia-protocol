// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA-side projection of Cedulon's pinned Mizan `leaked-refusal` fixture.
 *
 * The three upstream files are unsigned raw source bytes. This adapter first
 * checks their exact SHA-256 commitments, then projects the refusal and sent
 * row into separately generated, fixture-only EMILIA Trust Receipt and
 * Outcome Observation inputs. That is an adapter test, not native-format
 * interoperability and not proof of which component allowed the send.
 */
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  actionHash,
  buildReceiptAnchorV2,
  canonicalize,
  contextDigest,
} from '../../../packages/issue/index.js';
import {
  buildOutcomeObservation,
  trustReceiptDigest,
  verifyOutcomeBindingSet,
} from '../../../packages/verify/index.js';
import { predictedEffectsDigest } from '../../../packages/verify/effect-predicates.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(HERE, 'fixtures');
const SOURCE_LOCK = JSON.parse(readFileSync(join(HERE, 'source-lock.json'), 'utf8'));
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const SHA256_HEX = /^[0-9a-f]{64}$/;
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export const PROFILE = 'EMILIA-CEDULON-MIZAN-LEAKED-REFUSAL-v0.1';
export const REPORT_VERSION = 'EMILIA-CEDULON-MIZAN-LEAKED-REFUSAL-REPORT-v0.1';
export const SOURCE_COMMIT = SOURCE_LOCK.commit;
export const SOURCE_LOCK_DIGEST = canonicalDigest(SOURCE_LOCK);

const FILES = Object.freeze({
  policy: 'policy.txt',
  decisions: 'decisions.jsonl',
  sent: 'sent.jsonl',
});

const FIXTURE_APPROVER_ID = 'ep:approver:fixture:cedulon-mizan';
const FIXTURE_APPROVER_KEY_ID = 'ep:key:fixture:cedulon-mizan#1';
const FIXTURE_LOG_KEY_ID = 'ep:log:fixture:cedulon-mizan#1';
const FIXTURE_SOURCE_ID = 'ep:outcome-source:fixture:cedulon-mizan-sent-log';
const FIXTURE_SOURCE_CLASS = 'cedulon.mizan.sent-log';
const FIXTURE_OPERATION_ID = 'ep:operation:fixture:cedulon-mizan:leak-1';

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha256Text(text) {
  return sha256Hex(Buffer.from(text, 'utf8'));
}

function canonicalDigest(value) {
  return `sha256:${sha256Text(canonicalize(value))}`;
}

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === expected.length
    && expected.every((key) => Object.hasOwn(value, key));
}

function parseJsonl(bytes, name) {
  let text;
  try {
    text = UTF8.decode(bytes);
  } catch {
    throw new Error(`source_utf8_invalid:${name}`);
  }
  if (!text.endsWith('\n') || text.includes('\r')) {
    throw new Error(`source_jsonl_framing_invalid:${name}`);
  }
  const rows = text.slice(0, -1).split('\n');
  if (rows.length === 0 || rows.some((row) => row.length === 0)) {
    throw new Error(`source_jsonl_framing_invalid:${name}`);
  }
  try {
    return rows.map((row) => JSON.parse(row));
  } catch {
    throw new Error(`source_json_invalid:${name}`);
  }
}

function checkedBytes(name, supplied) {
  const expected = SOURCE_LOCK.files[name];
  const bytes = supplied === undefined
    ? readFileSync(join(FIXTURE_DIR, FILES[name]))
    : Buffer.from(supplied);
  const actual = sha256Hex(bytes);
  if (bytes.length !== expected.bytes || actual !== expected.sha256) {
    throw new Error(`source_digest_mismatch:${name}`);
  }
  return bytes;
}

/**
 * Load and authenticate the exact raw fixture before parsing either JSONL.
 *
 * @param {{raw?: {policy?: Uint8Array, decisions?: Uint8Array, sent?: Uint8Array}}} [options]
 */
export function loadPinnedFixture({ raw } = {}) {
  const sourceRaw = {
    policy: checkedBytes('policy', raw?.policy),
    decisions: checkedBytes('decisions', raw?.decisions),
    sent: checkedBytes('sent', raw?.sent),
  };
  const policyText = UTF8.decode(sourceRaw.policy);
  const decisions = parseJsonl(sourceRaw.decisions, 'decisions');
  const sent = parseJsonl(sourceRaw.sent, 'sent');
  return {
    commit: SOURCE_COMMIT,
    raw: sourceRaw,
    policy_text: policyText,
    decisions,
    sent,
    digests: Object.fromEntries(
      Object.entries(sourceRaw).map(([name, bytes]) => [name, sha256Hex(bytes)]),
    ),
  };
}

function strictInstant(milliseconds, field) {
  if (!Number.isSafeInteger(milliseconds)) throw new Error(`source_${field}_invalid`);
  const value = new Date(milliseconds);
  if (!Number.isFinite(value.getTime())) throw new Error(`source_${field}_invalid`);
  return value.toISOString();
}

/**
 * Pure mapping seam. It mirrors the pinned upstream adapter's three relevant
 * choices: silent -> deny, both sides use id as ref, and the IG effect class
 * is the fixed literal `ig-dm-reply`.
 */
export function projectLeakedRefusal({ decision, sent, policyDigest }) {
  if (!exactKeys(decision, ['id', 'receivedAt', 'from', 'text', 'verdict', 'reason'])
      || typeof decision.id !== 'string' || !decision.id
      || typeof decision.from !== 'string' || !decision.from
      || typeof decision.text !== 'string'
      || decision.verdict !== 'silent'
      || typeof decision.reason !== 'string' || !decision.reason) {
    throw new Error('source_decision_invalid');
  }
  if (!exactKeys(sent, ['id', 'sentAt', 'to', 'text'])
      || typeof sent.id !== 'string' || !sent.id
      || typeof sent.to !== 'string' || !sent.to
      || typeof sent.text !== 'string') {
    throw new Error('source_sent_invalid');
  }
  if (decision.id !== sent.id) throw new Error('source_ref_mismatch');
  if (!SHA256_HEX.test(policyDigest)) throw new Error('source_policy_digest_invalid');
  if (!Number.isSafeInteger(decision.receivedAt)
      || !Number.isSafeInteger(sent.sentAt)
      || sent.sentAt < decision.receivedAt) {
    throw new Error('source_time_order_invalid');
  }
  const target = `cedulon:mizan-ig:ref:${decision.id}`;
  const effectClass = 'ig-dm-reply';
  return {
    refusal: {
      source_verdict: 'silent',
      decision: 'deny',
      ref: decision.id,
      reason_code: decision.reason,
      request_hash: sha256Text(decision.text),
      policy_hash: policyDigest,
      effect_hash: null,
      effect_class: effectClass,
      decided_at: strictInstant(decision.receivedAt, 'receivedAt'),
    },
    predicted_effect: {
      effect_type: effectClass,
      target,
      required_source_role: 'system_of_record',
      required_source_class: FIXTURE_SOURCE_CLASS,
      predicate: { op: 'absent' },
    },
    observed_effect: {
      effect_type: effectClass,
      target,
      value: sha256Text(sent.text),
    },
    observed_at: strictInstant(sent.sentAt, 'sentAt'),
    source_actor: sent.to,
  };
}

function privateKeyFromLabel(label) {
  const seed = crypto.createHash('sha256').update(label, 'utf8').digest();
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

function publicKeyB64u(privateKey) {
  return crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
}

function fixedNonce(label) {
  return crypto.createHash('sha256').update(label, 'utf8').digest().subarray(0, 16).toString('base64url');
}

const APPROVER_PRIVATE_KEY = privateKeyFromLabel(`${PROFILE}:approver`);
const LOG_PRIVATE_KEY = privateKeyFromLabel(`${PROFILE}:log`);
const SOURCE_PRIVATE_KEY = privateKeyFromLabel(`${PROFILE}:source`);
const APPROVER_PUBLIC_KEY = publicKeyB64u(APPROVER_PRIVATE_KEY);
const LOG_PUBLIC_KEY = publicKeyB64u(LOG_PRIVATE_KEY);
const SOURCE_PUBLIC_KEY = publicKeyB64u(SOURCE_PRIVATE_KEY);

async function buildFixtureTrustReceipt(fixture, projection) {
  const issuedAt = projection.refusal.decided_at;
  const expiresAt = new Date(Date.parse(issuedAt) + 3_600_000).toISOString();
  const action = {
    ep_version: '1.0',
    action_type: 'interop.cedulon-mizan.reconcile-refusal-effect',
    target: {
      system: 'cedulon:mizan-ig:pinned-fixture',
      resource: `decision/${projection.refusal.ref}`,
    },
    parameters: {
      source_repository: SOURCE_LOCK.repository,
      source_commit: SOURCE_COMMIT,
      source_fixture: SOURCE_LOCK.fixture,
      source_lock_digest: SOURCE_LOCK_DIGEST,
      source_policy_sha256: fixture.digests.policy,
      source_decisions_sha256: fixture.digests.decisions,
      source_sent_sha256: fixture.digests.sent,
      source_mapping_sha256: SOURCE_LOCK.upstream_mapping.sha256,
      source_decision_profile_sha256: SOURCE_LOCK.decision_profile.sha256,
      mapped_decision: projection.refusal.decision,
      source_verdict: projection.refusal.source_verdict,
      reason_code: projection.refusal.reason_code,
    },
    initiator: 'ep:entity:fixture:cedulon-mizan-adapter',
    policy_id: 'ep:policy:fixture:cedulon-mizan-leaked-refusal@v0.1',
    requested_at: issuedAt,
    predicted_effects: [projection.predicted_effect],
    predicted_effects_digest: predictedEffectsDigest([projection.predicted_effect]),
  };
  const action_hash = actionHash(action);
  const context = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash,
    policy_id: action.policy_id,
    policy_hash: `sha256:${fixture.digests.policy}`,
    initiator: action.initiator,
    approver: FIXTURE_APPROVER_ID,
    approver_index: 1,
    required_approvals: 1,
    nonce: fixedNonce(`${PROFILE}:context:${projection.refusal.ref}`),
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  const contextHash = contextDigest(context);
  const signoff = {
    context_hash: `sha256:${contextHash.toString('hex')}`,
    key_class: 'B',
    approver_key_id: FIXTURE_APPROVER_KEY_ID,
    signed_at: issuedAt,
    signature: crypto.sign(null, contextHash, APPROVER_PRIVATE_KEY).toString('base64url'),
  };
  const receipt = {
    receipt_id: `ep:receipt:fixture:cedulon-mizan:${projection.refusal.ref}`,
    action,
    action_hash,
    contexts: [context],
    signoffs: [signoff],
    consumption: {
      nonce: fixedNonce(`${PROFILE}:consumption:${projection.refusal.ref}`),
      state: 'COMMITTED',
      committed_at: issuedAt,
    },
  };
  const anchor = buildReceiptAnchorV2(receipt);
  const checkpoint = {
    tree_size: 1,
    root_hash: `sha256:${anchor.merkle_root}`,
    log_key_id: FIXTURE_LOG_KEY_ID,
    merkle_alg: anchor.alg,
  };
  const checkpointDigest = crypto.createHash('sha256')
    .update(canonicalize(checkpoint), 'utf8').digest();
  const log_signature = crypto.sign(null, checkpointDigest, LOG_PRIVATE_KEY).toString('base64url');
  return {
    ...receipt,
    log_proof: {
      alg: anchor.alg,
      leaf_hash: `sha256:${anchor.leaf_hash}`,
      leaf_index: 0,
      inclusion_path: anchor.merkle_proof,
      checkpoint: { ...checkpoint, log_signature },
    },
  };
}

/** Build the separate EMILIA-native fixture artifacts and public verifier pins. */
export async function buildNativeInputs() {
  const fixture = loadPinnedFixture();
  if (fixture.decisions.length !== 1 || fixture.sent.length !== 1) {
    throw new Error('source_population_not_singleton');
  }
  const projection = projectLeakedRefusal({
    decision: fixture.decisions[0],
    sent: fixture.sent[0],
    policyDigest: fixture.digests.policy,
  });
  const receipt = await buildFixtureTrustReceipt(fixture, projection);
  const attestedAt = new Date(Date.parse(projection.observed_at) + 1_000).toISOString();
  const verifierNow = new Date(Date.parse(projection.observed_at) + 5_000).toISOString();
  const observation = buildOutcomeObservation({
    receipt_id: receipt.receipt_id,
    receipt_digest: trustReceiptDigest(receipt),
    action_hash: receipt.action_hash,
    consumption_nonce: receipt.consumption.nonce,
    operation_id: FIXTURE_OPERATION_ID,
    source: {
      role: 'system_of_record',
      source_id: FIXTURE_SOURCE_ID,
      source_class: FIXTURE_SOURCE_CLASS,
    },
    observed_from: projection.observed_at,
    observed_until: projection.observed_at,
    attested_at: attestedAt,
    observed_effects: [projection.observed_effect],
    signer: { privateKey: SOURCE_PRIVATE_KEY },
  });
  const verifier_options = {
    receiptOptions: {
      approverKeys: {
        [FIXTURE_APPROVER_KEY_ID]: {
          approver_id: FIXTURE_APPROVER_ID,
          public_key: APPROVER_PUBLIC_KEY,
          key_class: 'B',
          valid_from: '2023-01-01T00:00:00.000Z',
          valid_to: '2024-01-01T00:00:00.000Z',
        },
      },
      logPublicKey: LOG_PUBLIC_KEY,
      verificationMode: 'historical',
      now: verifierNow,
    },
    sourceKeys: {
      [FIXTURE_SOURCE_ID]: {
        public_key: SOURCE_PUBLIC_KEY,
        role: 'system_of_record',
        source_class: FIXTURE_SOURCE_CLASS,
        control_domain_id: 'fixture:cedulon-mizan',
        status: 'active',
        valid_from: '2023-01-01T00:00:00.000Z',
        valid_to: '2024-01-01T00:00:00.000Z',
      },
    },
    sourceRequirements: [{
      role: 'system_of_record',
      source_class: FIXTURE_SOURCE_CLASS,
      min_distinct_sources: 1,
      distinct_by: ['key'],
      source_ids: [FIXTURE_SOURCE_ID],
    }],
    observationWindows: [{
      role: 'system_of_record',
      source_class: FIXTURE_SOURCE_CLASS,
      relation: 'exact',
      not_before: projection.observed_at,
      not_after: projection.observed_at,
      max_attestation_delay_ms: 1_000,
    }],
    now: verifierNow,
    expectedReceiptId: receipt.receipt_id,
    expectedReceiptDigest: trustReceiptDigest(receipt),
    expectedActionHash: receipt.action_hash,
    expectedConsumptionNonce: receipt.consumption.nonce,
    expectedOperationId: FIXTURE_OPERATION_ID,
  };
  return {
    fixture,
    projection,
    receipt,
    observations: [observation],
    verifier_options,
  };
}

function reportCore(native, outcomeBinding) {
  return {
    '@version': REPORT_VERSION,
    profile: PROFILE,
    source: {
      repository: SOURCE_LOCK.repository,
      commit: SOURCE_COMMIT,
      fixture: SOURCE_LOCK.fixture,
      source_lock_digest: SOURCE_LOCK_DIGEST,
      files: Object.fromEntries(
        Object.entries(SOURCE_LOCK.files).map(([name, entry]) => [name, {
          path: entry.path,
          bytes: entry.bytes,
          sha256: entry.sha256,
        }]),
      ),
      upstream_mapping: {
        path: SOURCE_LOCK.upstream_mapping.path,
        sha256: SOURCE_LOCK.upstream_mapping.sha256,
      },
      decision_profile: {
        path: SOURCE_LOCK.decision_profile.path,
        sha256: SOURCE_LOCK.decision_profile.sha256,
      },
      signed_by_upstream: false,
    },
    mapping: {
      kind: 'pinned-adapter-projection',
      source_decision: native.projection.refusal,
      predicted_effect: native.projection.predicted_effect,
      observed_effect: native.projection.observed_effect,
      rule: 'silent maps to deny; deny maps to an absent predicate; id maps to target cedulon:mizan-ig:ref:<id>; the sent row maps to an observed effect using the pinned IG effect class and SHA-256 text hash',
    },
    native_inputs: {
      receipt: native.receipt,
      observations: native.observations,
      verifier_options: native.verifier_options,
      receipt_digest: trustReceiptDigest(native.receipt),
      observation_digests: native.observations.map(canonicalDigest),
      fixture_only_keys: true,
    },
    outcome_binding: outcomeBinding,
    claim_boundary: {
      shared_raw_fixture: true,
      native_format_interoperability: false,
      upstream_logs_signed: false,
      independent_observation: false,
      fixture_keys_secret: false,
      real_identity_proven: false,
      temporal_precommitment_proven: false,
      authorization_of_original_send: false,
      failure_location_proven: false,
      statement: 'The same pinned raw decision and sent-log bytes are projected through an EMILIA-owned adapter into fixture-only signed native inputs. The deterministic keys are public test material, and the timestamps are derived after the fact from the fixture. The run detects a divergent observed effect against the mapped absence predicate. It does not make Cedulon records valid EMILIA artifacts, prove a real approver or source identity, establish temporal precommitment, prove that the raw logs are authentic or complete, identify where enforcement failed, or authorize the original send.',
    },
  };
}

/** Authenticate, project, sign, and run the full current Outcome Binding reader. */
export async function runPinnedFixture() {
  const native = await buildNativeInputs();
  const outcomeBinding = verifyOutcomeBindingSet(
    native.receipt,
    native.observations,
    native.verifier_options,
  );
  const core = reportCore(native, outcomeBinding);
  return { ...core, report_digest: canonicalDigest(core) };
}

export function verifyReportDigest(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)
      || typeof report.report_digest !== 'string'
      || !/^sha256:[0-9a-f]{64}$/.test(report.report_digest)) return false;
  const { report_digest, ...core } = report;
  const expected = canonicalDigest(core);
  return crypto.timingSafeEqual(
    Buffer.from(report_digest.slice(7), 'hex'),
    Buffer.from(expected.slice(7), 'hex'),
  );
}
