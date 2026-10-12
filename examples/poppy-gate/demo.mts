// SPDX-License-Identifier: Apache-2.0
// Offline integration with synthetic session/credential keys and a mock provider.
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { canonicalizeStrictJson } from '../../packages/verify/dist/strict-json.js';
import { createEg1Harness, createGate } from '../../packages/gate/dist/index.js';
import { buildPoppyAction, createPoppyApprovalVerifier } from './evidence.mjs';
import { createSyntheticPoppyApprovalFixture, syntheticPoppyOperation } from './approval-fixture.mjs';
import { createDemoSessionAuth } from './demo-auth.mjs';
import { createMemoryPoppyOperationStore, createPoppyOperationsAdapter,
  poppyActionDigest, POPPY_APPROVAL_EXTENSION } from './operations.mjs';

type Value = Record<string, any>;
const AT = Date.parse('2026-10-12T18:00:30Z');
const ISSUER = 'https://shop.example';
const ENDPOINT = 'https://api.shop.example/poppy/operations';
const selector = { protocol: 'poppy', tool: 'confirm_refund' };
function identityFence(owner: Value): string {
  return poppyActionDigest(owner.accountId === null
    ? { clientId: owner.clientId, userId: owner.userId, sessionId: owner.sessionId, accountId: null }
    : { clientId: owner.clientId, userId: owner.userId, accountId: owner.accountId });
}

async function harness({ strong = true, responseLoss = false, missingGateReceipt = false }: {
  strong?: boolean; responseLoss?: boolean; missingGateReceipt?: boolean;
} = {}) {
  const approval = await createSyntheticPoppyApprovalFixture({
    operation: { ...syntheticPoppyOperation(), user_approval_required: strong },
  });
  const owner = { ...approval.owner, scopes: ['poppy:write'], extensions: {
    operations: { version: '1' }, [POPPY_APPROVAL_EXTENSION]: { version: '1' },
  } };
  const auth = createDemoSessionAuth({ companyIssuer: ISSUER, endpoint: ENDPOINT, owner, now: () => AT });
  const expectedAction = buildPoppyAction(approval.operation, approval.owner, ISSUER);
  const gateFixture = createEg1Harness({ action: expectedAction, now: () => AT, idPrefix: 'poppy-demo' });
  const gate = createGate({
    manifest: { '@version': 'EP-ACTION-RISK-MANIFEST-v0.1', actions: [{
      id: 'poppy-refund-confirmation', action_type: expectedAction.action_type,
      receipt_required: true, risk: 'high', assurance_class: strong ? 'class_a' : 'software', match: selector,
      execution_binding: { required_fields: Object.keys(expectedAction) },
    }] },
    trustedKeys: [gateFixture.publicKey], approverKeys: gateFixture.approverKeys,
    rpId: gateFixture.rpId, allowedOrigins: gateFixture.allowedOrigins,
    allowEphemeralStore: true, now: () => AT,
  });
  const verifier = createPoppyApprovalVerifier({ ...approval.config, now: () => AT });
  const providerKeys = generateKeyPairSync('ed25519');
  const providerEvidence = new Map<string, Value>();
  let providerAttempts = 0;
  const adapter = createPoppyOperationsAdapter({ companyIssuer: ISSUER, endpoint: ENDPOINT,
    authenticateRequest: auth.authenticateRequest, store: createMemoryPoppyOperationStore(),
    gate, selector, requiredScopes: ['poppy:write'], allowEphemeralStore: true, now: () => AT,
    resolveAction: (operation, operationOwner) => buildPoppyAction(operation, operationOwner, ISSUER),
    requireApprovalEvidence: strong, verifyApprovalEvidence: input => verifier.verify(input),
    // The company supplies a native Gate record separately. An EP Trust Receipt
    // is never cast into this authority record. Each record is verified by its
    // own native verifier and bound to the same executor-owned action.
    resolveGateReceipt: ({ observedAction }) => missingGateReceipt ? null : gateFixture.mint({
      outcome: strong ? 'allow_with_signoff' : 'allow', extra: { canonical_action: observedAction },
    }),
    executeAction: async ({ operation, owner: operationOwner, observedAction }) => {
      providerAttempts++;
      const statement = { companyIssuer: ISSUER, operation_id: operation.operation_id,
        revision: operation.revision, action_digest: poppyActionDigest(observedAction),
        ownerFence: identityFence(operationOwner), observedAction, state: 'succeeded',
        summary: 'The mock provider accepted the refund.', data: { provider_reference: 'mock-refund-100' } };
      providerEvidence.set(operation.operation_id, { statement, signature: sign(null,
        Buffer.from(canonicalizeStrictJson(statement)), providerKeys.privateKey).toString('base64url') });
      if (responseLoss) throw new Error('Simulated response lost after provider commitment.');
      return { state: statement.state, summary: statement.summary, data: statement.data };
    },
    verifyProviderOutcome: async ({ evidence }) => {
      const valid = evidence?.statement && typeof evidence?.signature === 'string'
        && verify(null, Buffer.from(canonicalizeStrictJson(evidence.statement)), providerKeys.publicKey,
          Buffer.from(evidence.signature, 'base64url'));
      return valid ? { ...evidence.statement, valid: true } : { valid: false };
    },
  });
  const operation = await adapter.propose({ request: auth.request({ url: ENDPOINT, method: 'POST' }),
    actionKey: 'refund:order-100', ...approval.operation });
  const body = (evidence = approval.evidence, approved_by = 'user'): Value => ({ revision: 1, approved_by,
    ...(strong ? { extensions: { [POPPY_APPROVAL_EXTENSION]: { version: '1', evidence } } } : {}) });
  const confirm = (value: Value = body()) => adapter.handle(auth.request({
    url: `${ENDPOINT}/${operation.operation_id}/confirm`, method: 'POST', body: value,
  }));
  const read = () => adapter.handle(auth.request({ url: `${ENDPOINT}/${operation.operation_id}`, method: 'GET' }));
  return { adapter, auth, approval, operation, body, confirm, read,
    providerAttempts: () => providerAttempts,
    reconcile: () => adapter.reconcile({ operation_id: operation.operation_id, revision: 1,
      action_digest: poppyActionDigest(expectedAction), evidence: providerEvidence.get(operation.operation_id) }),
  };
}

export async function runPoppyGateDemo(): Promise<Value> {
  const cases: Value[] = [];
  {
    const h = await harness(); const result = await h.confirm({ revision: 1, approved_by: 'user' });
    cases.push({ id: 'false_approval', pass: result.status === 403 && h.providerAttempts() === 0,
      status: result.status, refusal: result.body.error, provider_attempts: h.providerAttempts() });
  }
  {
    const h = await harness(); const changed = await h.adapter.revise({ request: h.auth.request({ url: ENDPOINT, method: 'POST' }),
      operation_id: h.operation.operation_id, revision: 1, summary: 'Refund $500.00 USD instead.',
      terms: { ...h.operation.terms, amount: '500.00' }, expires_at: h.operation.expires_at, user_approval_required: true });
    const result = await h.confirm();
    cases.push({ id: 'changed_revision', pass: changed.revision === 2 && result.status === 409 && h.providerAttempts() === 0,
      status: result.status, refusal: result.body.error, provider_attempts: h.providerAttempts() });
  }
  {
    const h = await harness(); const altered = structuredClone(h.approval.evidence);
    altered.components[0].evidence.signoffs[0].webauthn.signature = Buffer.alloc(64).toString('base64url');
    const result = await h.confirm(h.body(altered));
    cases.push({ id: 'tampered_evidence', pass: result.status === 403 && h.providerAttempts() === 0,
      status: result.status, refusal: result.body.error, provider_attempts: h.providerAttempts() });
  }
  {
    const h = await harness(); const result = await h.confirm();
    cases.push({ id: 'approved_operation', pass: result.body.state === 'succeeded' && h.providerAttempts() === 1,
      status: result.status, state: result.body.state, provider_attempts: h.providerAttempts() });
  }
  {
    const h = await harness(); const results = await Promise.all(Array.from({ length: 12 }, () => h.confirm()));
    const read = await h.read();
    cases.push({ id: 'concurrent_confirmation', pass: results.every(r => r.status === 200)
      && read.body.state === 'succeeded' && h.providerAttempts() === 1,
      confirmations: results.length, state: read.body.state, provider_attempts: h.providerAttempts() });
  }
  {
    const h = await harness({ responseLoss: true }); const first = await h.confirm();
    await h.confirm(); const reconciled = await h.reconcile(); await h.confirm();
    cases.push({ id: 'response_loss_and_reconciliation', pass: first.body.state === 'in_progress'
      && reconciled.state === 'succeeded' && h.providerAttempts() === 1,
      before_reconciliation: first.body.state, after_reconciliation: reconciled.state,
      provider_attempts: h.providerAttempts() });
  }
  {
    const h = await harness({ strong: false }); const result = await h.confirm(h.body(undefined, 'standing_permission'));
    cases.push({ id: 'native_standing_permission', pass: result.body.state === 'succeeded' && h.providerAttempts() === 1,
      state: result.body.state, fresh_user_profile_required: false, provider_attempts: h.providerAttempts() });
  }
  return { candidate: 'poppy-operations-with-emilia-gate', source_draft: 'Poppy 0.1 / Operations 1 (October 9, 2026)',
    scope: 'synthetic_local_reference', independent_interoperability: false,
    assumptions: ['synthetic local session authority', 'software-emulated credential assertions',
      'test-only operation and Gate stores', 'mock provider with a pinned synthetic outcome key'],
    passed: cases.every(row => row.pass), cases };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = await runPoppyGateDemo();
  console.log(JSON.stringify(report, null, 2));
  if (!report.passed) process.exitCode = 1;
}
