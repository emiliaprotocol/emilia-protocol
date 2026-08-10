// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  A2A_ACTION_MEDIA_TYPE,
  A2A_PROTOCOL_VERSION,
  A2A_RECEIPT_BINDING_VERSION,
  A2A_RECEIPT_EXTENSION_NAME,
  A2A_RECEIPT_EXTENSION_URI,
  A2A_RECEIPT_PRESENTATION_VERSION,
  createA2AReceiptPresentation,
  verifyA2AReceiptPresentation,
} from './a2a-receipt-binding.js';
import { digestAeb } from './aeb-adapter-contract.js';
import { verifyReceipt } from './index.js';
import { canonicalizeStrictJson } from './strict-json.js';

const NOW = '2026-08-06T18:00:00.000Z';
const CAID = 'caid:1:payment.release.1:jcs-sha256:nOa-Aijv3apQja9bcRiASEtVOJkheGykD9gz2whCYuw';
const TRACE_EXTENSION = 'https://example.com/extensions/tracing/v1';

const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  amount: '184.00',
  currency: 'USD',
  beneficiary_account: 'sha256:74ebd63b55d825ab575d801a4c902f9d2304e83b805bb3dd740b6716c3ae8ea6',
  payment_instruction_id: 'pi-bindings-001',
});

function spki(key: crypto.KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function makeReceipt(issuer: crypto.KeyPairKeyObjectResult) {
  const payload = {
    receipt_id: 'receipt:a2a:1',
    issuer: 'ep:test',
    created_at: '2026-08-06T17:59:00.000Z',
    action: ACTION,
    action_hash: digestAeb(ACTION),
    caid: CAID,
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: crypto.sign(
        null,
        Buffer.from(canonicalizeStrictJson(payload), 'utf8'),
        issuer.privateKey,
      ).toString('base64url'),
    },
  };
}

function fixture() {
  const binder = crypto.generateKeyPairSync('ed25519');
  const issuer = crypto.generateKeyPairSync('ed25519');
  const agentCard = {
    name: 'Payment executor',
    description: 'Executes approved payment actions',
    supportedInterfaces: [{
      url: 'https://executor.example/a2a/v1',
      protocolBinding: 'HTTP+JSON',
      protocolVersion: A2A_PROTOCOL_VERSION,
    }],
    version: '1.0.0',
    capabilities: { extensions: [{ uri: A2A_RECEIPT_EXTENSION_URI, required: true }] },
    defaultInputModes: ['application/json'],
    defaultOutputModes: ['application/json'],
    skills: [],
  };
  const initiatingMessage = {
    messageId: 'msg-init-0001',
    role: 'ROLE_USER',
    parts: [{ data: ACTION, mediaType: A2A_ACTION_MEDIA_TYPE }],
  };
  const task = {
    id: 'task-server-0001',
    contextId: 'context-server-0001',
    status: { state: 'TASK_STATE_AUTH_REQUIRED', timestamp: '2026-08-06T17:58:30.000Z' },
  };
  const proofMessage = {
    messageId: 'msg-proof-0001',
    taskId: task.id,
    contextId: task.contextId,
    role: 'ROLE_USER',
    parts: [{ text: 'Authorization receipt attached.' }],
    extensions: [TRACE_EXTENSION],
    metadata: { [TRACE_EXTENSION]: { traceId: 'trace-0001' } },
    referenceTaskIds: ['task-prior-0001'],
  };
  const receipt = makeReceipt(issuer);
  const created = createA2AReceiptPresentation({
    protocol_version: A2A_PROTOCOL_VERSION,
    target_interface_url: 'https://executor.example/a2a/v1',
    agent_card: agentCard,
    task,
    initiating_message: initiatingMessage,
    proof_message: proofMessage,
    base_receipt: receipt,
    receipt_binding: { caid: CAID, action_digest: digestAeb(ACTION) },
    issued_at: '2026-08-06T17:59:30.000Z',
    expires_at: '2026-08-06T18:05:00.000Z',
    signer: { key_id: 'binder:test', private_key: binder.privateKey },
  });
  const verification = (overrides: Record<string, unknown> = {}) => ({
    protocol_version: A2A_PROTOCOL_VERSION,
    target_interface_url: 'https://executor.example/a2a/v1',
    agent_card: agentCard,
    task,
    initiating_message: initiatingMessage,
    presentation_message: created.message,
    negotiated_extensions: [A2A_RECEIPT_EXTENSION_URI],
    trust_roots: [{ key_id: 'binder:test', public_key: spki(binder.publicKey) }],
    expected_action: ACTION,
    expected_caid: CAID,
    now: NOW,
    verify_receipt(candidate: unknown) {
      const result = verifyReceipt(candidate, spki(issuer.publicKey));
      const payload = (candidate as any)?.payload;
      return {
        valid: result.valid,
        action_digest: payload?.action_hash,
        caid: payload?.caid,
      };
    },
    ...overrides,
  });
  return { agentCard, binder, created, initiatingMessage, issuer, proofMessage, receipt, task, verification };
}

test('binds a verified receipt to the server-issued A2A v1.0 task and both messages', () => {
  const f = fixture();
  const result = verifyA2AReceiptPresentation(f.verification());

  assert.equal(result.valid, true, JSON.stringify(result.reasons));
  assert.deepEqual(result.reasons, []);
  assert.equal(result.checks.receipt, true);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.initiating_message, true);
  assert.equal(result.checks.presentation_message, true);
  assert.equal(result.decision_scope.receipt_verified, true);
  assert.equal(result.decision_scope.authorization_granted, false);
  assert.equal(result.decision_scope.execution_proven, false);

  assert.equal(f.initiatingMessage.taskId, undefined);
  assert.equal(f.created.artifact.task_id, f.task.id);
  assert.equal(f.created.artifact.context_id, f.task.contextId);
  assert.equal(f.created.artifact.initiating_message_id, f.initiatingMessage.messageId);
  assert.equal(f.created.artifact.proof_message_id, f.proofMessage.messageId);
  assert.equal(f.created.artifact['@version'], A2A_RECEIPT_BINDING_VERSION);
  assert.equal(f.created.companion.entries[0].name, A2A_RECEIPT_EXTENSION_NAME);
  assert.equal(f.created.companion.entries[0].operation_id, f.task.id);
  assert.equal(f.created.companion.entries[0].consequence_digest, null);

  const payload = f.created.message.metadata[A2A_RECEIPT_EXTENSION_URI];
  assert.equal(payload['@version'], A2A_RECEIPT_PRESENTATION_VERSION);
  assert.deepEqual(payload.action, ACTION);
  assert.equal(f.created.message.extensions.filter((uri) => uri === A2A_RECEIPT_EXTENSION_URI).length, 1);
  assert.deepEqual(f.created.message.metadata[TRACE_EXTENSION], { traceId: 'trace-0001' });
});

test('refuses task, context, message, target, negotiation, and protocol substitution', () => {
  const f = fixture();
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ['task', { task: { ...f.task, id: 'task-server-0002' } }, 'task_binding_mismatch'],
    ['context', { task: { ...f.task, contextId: 'context-server-0002' } }, 'context_binding_mismatch'],
    ['target', { target_interface_url: 'https://other.example/a2a/v1' }, 'target_binding_mismatch'],
    ['negotiation', { negotiated_extensions: [] }, 'extension_not_negotiated'],
    ['lookalike negotiation', { negotiated_extensions: [`${A2A_RECEIPT_EXTENSION_URI}.attacker.example`] }, 'extension_not_negotiated'],
    ['version', { protocol_version: '0.3' }, 'protocol_version_mismatch'],
  ];
  for (const [label, override, reason] of cases) {
    const result = verifyA2AReceiptPresentation(f.verification(override));
    assert.equal(result.valid, false, label);
    assert.ok(result.reasons.includes(reason), `${label}: ${JSON.stringify(result.reasons)}`);
  }

  const unsupportedCard = structuredClone(f.agentCard);
  unsupportedCard.capabilities.extensions = [];
  const unsupportedResult = verifyA2AReceiptPresentation(f.verification({ agent_card: unsupportedCard }));
  assert.equal(unsupportedResult.valid, false);
  assert.ok(unsupportedResult.reasons.includes('target_binding_mismatch'));
  assert.throws(() => createA2AReceiptPresentation({
    protocol_version: A2A_PROTOCOL_VERSION,
    target_interface_url: 'https://executor.example/a2a/v1',
    agent_card: unsupportedCard,
    task: f.task,
    initiating_message: f.initiatingMessage,
    proof_message: f.proofMessage,
    base_receipt: f.receipt,
    receipt_binding: { caid: CAID, action_digest: digestAeb(ACTION) },
    issued_at: '2026-08-06T17:59:30.000Z',
    expires_at: '2026-08-06T18:05:00.000Z',
    signer: { key_id: 'binder:test', private_key: f.binder.privateKey },
  }), /Agent Card.*extension/);

  const changedMessage = structuredClone(f.created.message);
  changedMessage.messageId = 'msg-proof-0002';
  const messageResult = verifyA2AReceiptPresentation(f.verification({ presentation_message: changedMessage }));
  assert.equal(messageResult.valid, false);
  assert.ok(messageResult.reasons.includes('proof_message_id_mismatch'));
});

test('refuses action, receipt, original-message, or non-EMILIA metadata substitution', () => {
  const f = fixture();

  const changedAction = { ...ACTION, amount: '185.00' };
  const actionResult = verifyA2AReceiptPresentation(f.verification({ expected_action: changedAction }));
  assert.equal(actionResult.valid, false);
  assert.ok(actionResult.reasons.includes('base_action_digest_mismatch'));

  const changedOrigin = structuredClone(f.initiatingMessage);
  changedOrigin.parts[0].data.amount = '185.00';
  const originResult = verifyA2AReceiptPresentation(f.verification({ initiating_message: changedOrigin }));
  assert.equal(originResult.valid, false);
  assert.ok(originResult.reasons.includes('initiating_message_digest_mismatch'));

  const changedPresentation = structuredClone(f.created.message);
  changedPresentation.metadata[TRACE_EXTENSION].traceId = 'trace-0002';
  const presentationResult = verifyA2AReceiptPresentation(f.verification({ presentation_message: changedPresentation }));
  assert.equal(presentationResult.valid, false);
  assert.ok(presentationResult.reasons.includes('proof_message_digest_mismatch'));

  const changedReceipt = structuredClone(f.created.message);
  changedReceipt.metadata[A2A_RECEIPT_EXTENSION_URI].receipt.payload.receipt_id = 'receipt:a2a:other';
  const receiptResult = verifyA2AReceiptPresentation(f.verification({ presentation_message: changedReceipt }));
  assert.equal(receiptResult.valid, false);
  assert.ok(receiptResult.reasons.includes('base_receipt_digest_mismatch'));
  assert.ok(receiptResult.reasons.includes('receipt_verification_failed'));
});

test('refuses unsigned A2A objects, a missing receipt verifier, and forged binders', () => {
  const f = fixture();
  const rawTaskResult = verifyA2AReceiptPresentation(f.verification({ presentation_message: f.task }));
  assert.equal(rawTaskResult.valid, false);
  assert.ok(rawTaskResult.reasons.includes('presentation_malformed'));

  const noVerifier = f.verification();
  delete (noVerifier as any).verify_receipt;
  const noVerifierResult = verifyA2AReceiptPresentation(noVerifier as any);
  assert.equal(noVerifierResult.valid, false);
  assert.ok(noVerifierResult.reasons.includes('receipt_verifier_required'));

  const launderingResult = verifyA2AReceiptPresentation(f.verification({
    verify_receipt: () => ({
      valid: true,
      action_digest: digestAeb({ ...ACTION, amount: '999.00' }),
      caid: CAID,
    }),
  }));
  assert.equal(launderingResult.valid, false);
  assert.ok(launderingResult.reasons.includes('receipt_verification_failed'));

  const forged = structuredClone(f.created.message);
  forged.metadata[A2A_RECEIPT_EXTENSION_URI].binding_artifact.task_id = 'task-server-0002';
  const forgedResult = verifyA2AReceiptPresentation(f.verification({ presentation_message: forged }));
  assert.equal(forgedResult.valid, false);
  assert.ok(forgedResult.reasons.includes('binding_signature_invalid'));
});

test('fails closed on validity boundaries and hostile non-JSON inputs', () => {
  const f = fixture();
  assert.equal(verifyA2AReceiptPresentation(f.verification({ now: '2026-08-06T17:59:29.999Z' })).valid, false);
  assert.equal(verifyA2AReceiptPresentation(f.verification({ now: '2026-08-06T18:05:00.000Z' })).valid, false);

  let getterRan = false;
  const hostileMessage: any = { ...f.proofMessage };
  Object.defineProperty(hostileMessage, 'metadata', {
    enumerable: true,
    get() {
      getterRan = true;
      return {};
    },
  });
  assert.throws(() => createA2AReceiptPresentation({
    protocol_version: A2A_PROTOCOL_VERSION,
    target_interface_url: 'https://executor.example/a2a/v1',
    agent_card: f.agentCard,
    task: f.task,
    initiating_message: f.initiatingMessage,
    proof_message: hostileMessage,
    base_receipt: f.receipt,
    receipt_binding: { caid: CAID, action_digest: digestAeb(ACTION) },
    issued_at: '2026-08-06T17:59:30.000Z',
    expires_at: '2026-08-06T18:05:00.000Z',
    signer: { key_id: 'binder:test', private_key: f.binder.privateKey },
  }), /strict canonical JSON|closed A2A Message/);
  assert.equal(getterRan, false);
});

test('refuses an INPUT_REQUIRED Task substituted for the A2A authorization interruption', () => {
  const f = fixture();
  // A2A v1.0 delegates authorization to the client through TASK_STATE_AUTH_REQUIRED.
  // A generic input-required Task is not an authorization interruption and MUST NOT
  // be accepted in its place, otherwise an agent could downgrade the authorization
  // step to an ordinary input prompt while still presenting a bound receipt.
  for (const state of ['TASK_STATE_INPUT_REQUIRED', 'TASK_STATE_SUBMITTED', 'TASK_STATE_WORKING', 'TASK_STATE_COMPLETED']) {
    const substituted = { ...f.task, status: { ...f.task.status, state } };
    assert.throws(() => createA2AReceiptPresentation({
      protocol_version: A2A_PROTOCOL_VERSION,
      target_interface_url: 'https://executor.example/a2a/v1',
      agent_card: f.agentCard,
      task: substituted,
      initiating_message: f.initiatingMessage,
      proof_message: f.proofMessage,
      base_receipt: f.receipt,
      receipt_binding: { caid: CAID, action_digest: digestAeb(ACTION) },
      issued_at: '2026-08-06T17:59:30.000Z',
      expires_at: '2026-08-06T18:05:00.000Z',
      signer: { key_id: 'binder:test', private_key: f.binder.privateKey },
    }), /closed A2A auth-required Task required/, `state ${state} must be refused`);
  }
});
