// SPDX-License-Identifier: Apache-2.0

import {
  createHash,
  generateKeyPairSync,
  sign,
} from 'node:crypto';

import {
  canonicalize,
  createGate,
  createMemoryCapabilityStore,
  executeWithCapability,
  mintDeviceSignoff,
  mintCapabilityReceipt,
} from '../../packages/gate/index.js';

import {
  createSignedMockProvider,
} from './provider.mjs';
import {
  createReconciliationLedger,
  reconcileIndeterminateEffect,
} from './reconciliation.mjs';

const NOW = Date.parse('2026-07-19T04:00:00.000Z');
const OPERATION_ID = 'payment-release:invoice-8841';
const SELECTOR = {
  protocol: 'demo',
  tool: 'release_payment',
};
const ACTION = Object.freeze({
  action_type: 'payment.release',
  amount: 25_000,
  currency: 'USD',
  destination: 'acct:contractor:1842',
  payment_instruction_id: 'invoice-8841',
});
const MANIFEST = Object.freeze({
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: [{
    id: 'demo-payment-release',
    action_type: ACTION.action_type,
    receipt_required: true,
    risk: 'critical',
    assurance_class: 'class_a',
    match: SELECTOR,
    execution_binding: {
      required_fields: [
        'action_type',
        'amount',
        'currency',
        'destination',
        'payment_instruction_id',
      ],
    },
  }],
});

function publicKeyB64u(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function mintBaseReceipt(privateKey, publicKey) {
  const actionHash = createHash('sha256')
    .update(canonicalize({ action_type: ACTION.action_type }), 'utf8')
    .digest('hex');
  const approval = mintDeviceSignoff({
    actionHash,
    approver: 'ep:approver:demo-cfo',
    issuedAtMs: NOW,
  });
  const payload = {
    receipt_id: 'ep:receipt:indeterminate-demo',
    created_at: new Date(NOW - 1_000).toISOString(),
    subject: 'agent:accounts-payable',
    issuer: 'ep:org:demo',
    claim: {
      ...ACTION,
      outcome: 'allow_with_signoff',
    },
    signoff: approval.signoff,
    approver_public_key: approval.approver_public_key,
  };
  return {
    approver: {
      approver_id: approval.signoff.context.approver,
      public_key: approval.approver_public_key,
      key_class: 'A',
    },
    receipt: {
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: {
        algorithm: 'Ed25519',
        value: sign(
          null,
          Buffer.from(canonicalize(payload), 'utf8'),
          privateKey,
        ).toString('base64url'),
      },
      public_key: publicKeyB64u(publicKey),
    },
  };
}

export function createIndeterminateEffectHarness() {
  const issuer = generateKeyPairSync('ed25519');
  const issuerPublicKey = publicKeyB64u(issuer.publicKey);
  const signedApproval = mintBaseReceipt(issuer.privateKey, issuer.publicKey);
  const baseReceipt = signedApproval.receipt;
  const gate = createGate({
    manifest: MANIFEST,
    trustedKeys: [issuerPublicKey],
    approverKeys: {
      'ep:key:demo-cfo': signedApproval.approver,
    },
    rpId: 'emiliaprotocol.ai',
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
    allowEphemeralStore: true,
    now: () => NOW,
  });
  const minted = mintCapabilityReceipt(baseReceipt, {
    issuerPrivateKey: issuer.privateKey,
    budget: { amount: 100_000, currency: 'USD' },
    expiry: new Date(NOW + 60_000).toISOString(),
    capabilityId: 'ep:capability:invoice-8841',
  });
  const capabilityStore = createMemoryCapabilityStore();
  if (!capabilityStore.registerCapability(minted.capabilityReceipt)) {
    throw new Error('failed to register capability receipt');
  }

  const provider = createSignedMockProvider();
  const reconciliationLedger = createReconciliationLedger();
  const execute = () => executeWithCapability({
    capabilityReceipt: minted.capabilityReceipt,
    secret: minted.secret,
    action: ACTION,
    store: capabilityStore,
    gate,
    selector: SELECTOR,
    observedAction: ACTION,
    trustedIssuerKeys: [issuerPublicKey],
    operationId: OPERATION_ID,
    now: () => NOW,
    executeAction: (action, context) => provider.execute(action, context),
  });

  return Object.freeze({
    action: ACTION,
    operationId: OPERATION_ID,
    provider,
    reconciliationLedger,
    attempt: execute,
    retry: execute,
    reconcile(providerEvidence = provider.getSignedEvidence(OPERATION_ID)) {
      return reconcileIndeterminateEffect({
        capabilityStore,
        capabilityId: minted.capabilityReceipt.capability.id,
        operationId: OPERATION_ID,
        action: ACTION,
        providerEvidence,
        pinnedProviderKey: provider.pinnedPublicKey,
        expectedProviderId: provider.providerId,
        ledger: reconciliationLedger,
      });
    },
    get capabilityOperation() {
      return capabilityStore.getOperation(OPERATION_ID);
    },
  });
}

export async function runIndeterminateEffectDemo() {
  const harness = createIndeterminateEffectHarness();
  const first = await harness.attempt();
  const retry = await harness.retry();
  const providerEvidence = harness.provider.getSignedEvidence(harness.operationId);
  const reconciliation = await harness.reconcile(providerEvidence);
  const operation = harness.capabilityOperation;

  return Object.freeze({
    first_attempt: {
      ok: first.ok,
      reason: first.reason,
      operation_id: first.operation_id,
      authorization: {
        allow: first.authorization?.allow === true,
        execution_binding_ok:
          first.authorization?.evidence?.execution_binding?.ok === true,
      },
    },
    capability_operation: {
      status: operation.status,
      outcome: operation.outcome,
      amount: operation.amount,
      currency: operation.currency,
    },
    retry: {
      ok: retry.ok,
      reason: retry.reason,
    },
    provider: {
      provider_id: harness.provider.providerId,
      execution_attempts: harness.provider.executionAttempts,
      committed_effects: harness.provider.committedEffects,
      action_digest: harness.provider.actionDigest,
    },
    reconciliation,
  });
}
