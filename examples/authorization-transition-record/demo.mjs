#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EP evidence behind draft-kuehlewind-audit-architecture-00 Section 7.4.
 *
 * The audit architecture owns the Authorization Transition Record, its state
 * model, store, correlation, and transparency registration. This example fills
 * one narrow evidence slot: a user_approval trigger references an EP receipt by
 * digest, so an auditor can verify the responsible actor and exact action
 * independently of the service that recorded the transition.
 */
import crypto from 'node:crypto';
import {
  actionHash,
  canonicalize,
  generateIssuerKeyBundle,
  issueFromKeyBundle,
  publicKeyToSpkiB64u,
} from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';

export const LAB_VERSION = 'EP-AUTHORIZATION-TRANSITION-RECORD-LAB-v1';
export const SOURCE_DRAFT = 'draft-kuehlewind-audit-architecture-00';

export const EXACT_ACTION = Object.freeze({
  ep_version: '1.0',
  action_type: 'calendar.event.create',
  target: Object.freeze({ system: 'calendar.service', resource: 'calendars/user-123' }),
  parameters: Object.freeze({
    title: 'Project review',
    starts_at: '2026-07-20T16:00:00Z',
    duration_minutes: 30,
    invitees: Object.freeze(['colleague@example.net']),
  }),
  initiator: 'agent:calendar-assistant:42',
  policy_id: 'policy:calendar-step-up@3',
  requested_at: '2026-07-16T18:00:00Z',
});

const AUDIT_SERVICE_KEY_ID = 'audit.example#record-1';
const sha256Hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const clone = (value) => structuredClone(value);

function evidenceReference(receipt) {
  return `urn:ep:receipt:sha256:${sha256Hex(Buffer.from(canonicalize(receipt), 'utf8'))}`;
}

function signTransitionRecord(record, privateKey, keyId = AUDIT_SERVICE_KEY_ID) {
  return {
    record: clone(record),
    signature: {
      algorithm: 'Ed25519',
      kid: keyId,
      value: crypto.sign(null, Buffer.from(canonicalize(record), 'utf8'), privateKey).toString('base64url'),
    },
  };
}

function refusal(checks, reason) {
  return { accepted: false, checks, reason };
}

/**
 * Verify the record/evidence join without deciding whether the new state is lawful.
 *
 * @param {{
 *   signedRecord?: any,
 *   expectedAction?: any,
 *   artifactStore?: Map<string, any>,
 *   trust?: any,
 * }} [input]
 */
export function verifyAuthorizationTransition({
  signedRecord,
  expectedAction,
  artifactStore,
  trust,
} = {}) {
  const checks = {
    record_signature: false,
    record_shape: false,
    evidence_reference: false,
    receipt: false,
    actor_binding: false,
    action_binding: false,
  };
  try {
    if (!signedRecord?.record || signedRecord?.signature?.algorithm !== 'Ed25519') {
      return refusal(checks, 'malformed_signed_transition_record');
    }
    const auditKey = trust?.auditServiceKeys?.[signedRecord.signature.kid];
    if (typeof auditKey !== 'string') return refusal(checks, 'audit_service_key_not_pinned');
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(auditKey, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    checks.record_signature = crypto.verify(
      null,
      Buffer.from(canonicalize(signedRecord.record), 'utf8'),
      publicKey,
      Buffer.from(signedRecord.signature.value || '', 'base64url'),
    );
    if (!checks.record_signature) return refusal(checks, 'transition_record_signature_invalid');

    const record = signedRecord.record;
    checks.record_shape = record.type === 'authorization_transition'
      && record.trigger?.type === 'user_approval'
      && record.actor?.type === 'user'
      && record.previous_state && typeof record.previous_state === 'object'
      && record.new_state && typeof record.new_state === 'object';
    if (!checks.record_shape) return refusal(checks, 'transition_record_shape_invalid');

    const reference = record.trigger.evidence_ref;
    if (typeof reference !== 'string' || !reference.startsWith('urn:ep:receipt:sha256:')) {
      return refusal(checks, 'unsupported_trigger_evidence_reference');
    }
    const receipt = artifactStore instanceof Map ? artifactStore.get(reference) : undefined;
    checks.evidence_reference = Boolean(receipt) && evidenceReference(receipt) === reference;
    if (!checks.evidence_reference) return refusal(checks, 'trigger_evidence_digest_mismatch');

    const report = verifyTrustReceipt(receipt, {
      approverKeys: trust?.approverKeys,
      logPublicKey: trust?.logPublicKey,
    });
    checks.receipt = report.valid;
    if (!checks.receipt) return refusal(checks, `receipt_refused:${report.errors[0] || 'invalid'}`);

    const approvers = new Set(receipt.contexts.map((context) => context.approver));
    checks.actor_binding = approvers.size === 1 && approvers.has(record.actor.id);
    if (!checks.actor_binding) return refusal(checks, 'responsible_actor_does_not_match_receipt_approver');

    const expectedHash = actionHash(expectedAction);
    checks.action_binding = record.trigger.action_hash === receipt.action_hash
      && receipt.action_hash === expectedHash;
    if (!checks.action_binding) return refusal(checks, 'trigger_does_not_bind_expected_action');

    return {
      accepted: true,
      checks,
      reason: null,
      event_id: record.event_id,
      receipt_id: receipt.receipt_id,
    };
  } catch (error) {
    return refusal(checks, `verification_error:${error instanceof Error ? error.message : 'unknown'}`);
  }
}

export async function runAuthorizationTransitionLab() {
  const now = new Date();
  const approverId = 'ep:approver:user-123';
  const keys = generateIssuerKeyBundle({
    approverId,
    approverKeyId: 'ep:key:user-123#1',
    logKeyId: 'ep:log:user-example#1',
    validFrom: new Date(now.getTime() - 86_400_000).toISOString(),
    validTo: new Date(now.getTime() + 86_400_000).toISOString(),
  });
  const issuedAt = new Date(now.getTime() - 10_000).toISOString();
  const { receipt, verification } = await issueFromKeyBundle({
    keys,
    action: EXACT_ACTION,
    policyHash: 'sha256:fa326f41be2370827a2a85eefb37bb6f0b0f037283c47b5c16fc485c1b4177b8',
    receiptId: 'ep:receipt:authorization-transition-example',
    issuedAt,
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
  });
  const reference = evidenceReference(receipt);
  const auditService = crypto.generateKeyPairSync('ed25519');
  const record = {
    event_id: 'auth-001',
    trace_id: 'trace-abc',
    parent_id: 'int-002',
    timestamp: now.toISOString(),
    type: 'authorization_transition',
    previous_state: { scope: ['calendar.read'] },
    new_state: { scope: ['calendar.read', 'calendar.write'] },
    trigger: {
      type: 'user_approval',
      action_hash: receipt.action_hash,
      evidence_ref: reference,
    },
    actor: { type: 'user', id: approverId },
  };
  const signedRecord = signTransitionRecord(record, auditService.privateKey);
  const artifactStore = new Map([[reference, receipt]]);
  const trust = {
    auditServiceKeys: {
      [AUDIT_SERVICE_KEY_ID]: publicKeyToSpkiB64u(auditService.publicKey),
    },
    approverKeys: verification.approver_keys,
    logPublicKey: verification.log_public_key,
  };
  const verify = (overrides = {}) => verifyAuthorizationTransition({
    signedRecord,
    expectedAction: EXACT_ACTION,
    artifactStore,
    trust,
    ...overrides,
  });

  const cases = [{ id: 'accept-user-approval-transition', expected: 'accept', result: verify() }];

  const wrongAction = {
    ...EXACT_ACTION,
    parameters: { ...EXACT_ACTION.parameters, invitees: ['attacker@example.net'] },
  };
  cases.push({ id: 'refuse-executed-action-substitution', expected: 'refuse', result: verify({ expectedAction: wrongAction }) });

  const actorMismatch = signTransitionRecord({
    ...record,
    actor: { type: 'user', id: 'ep:approver:someone-else' },
  }, auditService.privateKey);
  cases.push({ id: 'refuse-responsible-actor-substitution', expected: 'refuse', result: verify({ signedRecord: actorMismatch }) });

  const mutatedReceipt = clone(receipt);
  mutatedReceipt.action.parameters.title = 'Transfer funds';
  cases.push({
    id: 'refuse-receipt-substitution-under-stable-reference',
    expected: 'refuse',
    result: verify({ artifactStore: new Map([[reference, mutatedReceipt]]) }),
  });

  const tamperedRecord = clone(signedRecord);
  tamperedRecord.record.new_state.scope.push('mail.send');
  cases.push({ id: 'refuse-transition-record-tamper', expected: 'refuse', result: verify({ signedRecord: tamperedRecord }) });

  const untrustedAuditService = crypto.generateKeyPairSync('ed25519');
  const recordFromUntrustedService = signTransitionRecord(
    record,
    untrustedAuditService.privateKey,
    'audit.untrusted.example#1',
  );
  cases.push({ id: 'refuse-untrusted-audit-service', expected: 'refuse', result: verify({ signedRecord: recordFromUntrustedService }) });

  return {
    '@version': LAB_VERSION,
    source_draft: SOURCE_DRAFT,
    boundary: 'The audit architecture owns state and records; EP supplies separately verifiable triggering evidence for user_approval.',
    cases,
  };
}

function print(result) {
  const green = (value) => `\x1b[32m${value}\x1b[0m`;
  const red = (value) => `\x1b[31m${value}\x1b[0m`;
  console.log('='.repeat(78));
  console.log(' Authorization Transition Record + EP triggering evidence');
  console.log(` ${result.source_draft} Section 7.4 / WI-8`);
  console.log('='.repeat(78));
  for (const testCase of result.cases) {
    const actual = testCase.result.accepted ? 'accept' : 'refuse';
    const ok = actual === testCase.expected;
    console.log(` ${ok ? green('PASS') : red('FAIL')}  ${testCase.id}`);
    console.log(`       expected=${testCase.expected} actual=${actual} reason=${testCase.result.reason || 'none'}`);
  }
  console.log('-'.repeat(78));
  console.log(' The record says authorization changed. The receipt proves which pinned');
  console.log(' approver authorized which exact action. State semantics stay with WI-8.');
  console.log('='.repeat(78));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await runAuthorizationTransitionLab();
  print(result);
  process.exitCode = result.cases.every(
    (testCase) => testCase.result.accepted === (testCase.expected === 'accept'),
  ) ? 0 : 1;
}
