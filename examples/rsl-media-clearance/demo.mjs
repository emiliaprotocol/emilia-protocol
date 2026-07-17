// SPDX-License-Identifier: Apache-2.0
/**
 * Runnable declaration-to-proof reference flow.
 *
 * Run:
 *   node examples/rsl-media-clearance/demo.mjs
 *
 * This is an independent compatibility prototype, not an RSL Media
 * implementation, partnership, endorsement, or production clearance service.
 */
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import {
  buildConsentGrant,
  verifyReceiptUnderGrant,
} from '../../packages/verify/consent-grant.js';
import {
  formatLogKeyId,
  generateEd25519KeyPair,
  issueAuthorizationReceipt,
  policyHash,
  publicKeyToSpkiB64u,
} from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';
import {
  createDurableConsumptionStore,
  createMemoryBackend,
} from '../../packages/gate/store.js';
import {
  buildRslMediaAction,
  buildRslMediaGrantSpec,
  RSL_MEDIA_NORMALIZED_VERSION,
  rslMediaConstraintsCover,
  rslMediaDeclarationCoversGrant,
} from './profile.mjs';

export const RSL_CLEARANCE_DEMO_VERSION = 'EP-RSL-MEDIA-CLEARANCE-DEMO-v1';

const HERE = dirname(fileURLToPath(import.meta.url));
const RP_ID = 'clearance.example';
const ORIGIN = `https://${RP_ID}`;
const TIMES = Object.freeze({
  evaluated: '2026-07-17T15:00:00Z',
  approved: '2026-07-17T15:00:20Z',
  expires: '2026-07-17T15:10:00Z',
  currentThrough: '2026-07-17T16:00:00Z',
});

const POLICY = Object.freeze({
  policy_id: 'urn:example:policy:rsl-media-clearance:v1',
  rule: 'require active trusted declaration, signed standing grant, and fresh Class-A exact-use approval',
  profile: 'EP-RSL-MEDIA-CLEARANCE-REFERENCE-v1',
});

const REQUEST = Object.freeze({
  purpose: 'documentary-promotion',
  media_type: 'video',
  territory: 'EU',
  campaign_id: 'documentary-2026',
  output_description_digest:
    'sha256:84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bed297302e99c2',
});

function clone(value) {
  return structuredClone(value);
}

function sha256(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function createVirtualClassAApprover() {
  const approverId = 'urn:example:person:rights-holder';
  const approverKeyId = 'urn:example:key:rights-holder-passkey:1';
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const log = generateEd25519KeyPair();
  return {
    approverId,
    approverKeyId,
    signer: {
      approverKeyId,
      keyClass: 'A',
      signedAt: TIMES.approved,
      signWebAuthn: (digest) => {
        const clientData = Buffer.from(JSON.stringify({
          type: 'webauthn.get',
          challenge: digest.toString('base64url'),
          origin: ORIGIN,
        }), 'utf8');
        const authenticatorData = Buffer.concat([
          crypto.createHash('sha256').update(RP_ID).digest(),
          Buffer.from([0x05]), // user present + user verified
          Buffer.from([0, 0, 0, 1]),
        ]);
        const signedData = Buffer.concat([
          authenticatorData,
          crypto.createHash('sha256').update(clientData).digest(),
        ]);
        return {
          authenticator_data: authenticatorData.toString('base64url'),
          client_data_json: clientData.toString('base64url'),
          signature: crypto.sign('sha256', signedData, privateKey).toString('base64url'),
        };
      },
    },
    log,
    verification: {
      approverKeys: {
        [approverKeyId]: {
          approver_id: approverId,
          public_key: publicKeyToSpkiB64u(publicKey),
          key_class: 'A',
          valid_from: '2026-01-01T00:00:00Z',
          valid_to: '2027-01-01T00:00:00Z',
        },
      },
      logPublicKey: log.publicKeyB64u,
      rpId: RP_ID,
    },
  };
}

async function issueExactUseReceipt(action, authority, receiptId) {
  return issueAuthorizationReceipt({
    receiptId,
    action,
    policyHash: policyHash(POLICY),
    approvers: [authority.approverId],
    requiredApprovals: 1,
    issuedAt: TIMES.approved,
    expiresAt: TIMES.expires,
    committedAt: TIMES.approved,
    signers: [authority.signer],
    log: {
      privateKeyB64u: authority.log.privateKeyB64u,
      logKeyId: formatLogKeyId('rsl-media-clearance'),
    },
  });
}

function verifyClearance(receipt, grant, authority, pinnedPrincipalKey, evaluation) {
  const receiptVerification = verifyTrustReceipt(receipt, {
    approverKeys: authority.verification.approverKeys,
    logPublicKey: authority.verification.logPublicKey,
    rpId: authority.verification.rpId,
    expectedPolicyHash: policyHash(POLICY),
    strict: true,
  });
  const grantComposition = verifyReceiptUnderGrant(receipt, grant, {
    now: TIMES.evaluated,
    pinnedPrincipalKey,
    constraintsCover: rslMediaConstraintsCover,
  });
  const declarationBinding = rslMediaDeclarationCoversGrant(evaluation, grant, {
    now: TIMES.approved,
  });
  return {
    accepted: receiptVerification.valid === true
      && grantComposition.ok === true
      && declarationBinding.valid === true,
    receipt: receiptVerification,
    grant: grantComposition,
    declaration: declarationBinding,
  };
}

async function executeOnce({ verification, receipt, store, effect }) {
  if (verification.accepted !== true) {
    return { executed: false, verdict: 'refuse', reason: 'clearance_evidence_invalid' };
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(String(receipt.action_hash ?? ''))) {
    return { executed: false, verdict: 'refuse', reason: 'action_digest_invalid' };
  }
  // Consume the action, not the receipt identifier. Two independently issued
  // receipts for the same exact action must not each authorize an effect.
  const key = `rsl-media-clearance:${receipt.action_hash}`;
  let fresh;
  try {
    fresh = await store.reserve(key);
  } catch {
    return { executed: false, verdict: 'refuse', reason: 'consumption_store_unavailable' };
  }
  if (fresh !== true) {
    return { executed: false, verdict: 'refuse', reason: 'clearance_replay_refused' };
  }
  try {
    const result = await effect();
    await store.commit(key);
    return { executed: true, verdict: 'execute', reason: null, result };
  } catch (error) {
    // Once an external effect was attempted, an error is indeterminate. Burn
    // the approval rather than reopening it for a potentially duplicate use.
    try { await store.commit(key); } catch { /* reservation remains fail-closed */ }
    throw error;
  }
}

export async function runRslMediaClearanceDemo() {
  const declarationBytes = await fs.readFile(join(HERE, 'fixtures', 'conditional-identity-declaration.xml'));
  const evaluation = {
    profile: RSL_MEDIA_NORMALIZED_VERSION,
    source_standard: 'RSL-MEDIA-SPEC-1.0-DRAFT',
    source_document_digest: sha256(declarationBytes),
    source_uri: 'https://registry.example/identity/RSL-0000-0042-7',
    isrd: 'RSL-0000-0042-7',
    registry: 'https://registry.example',
    registry_id: 'PERSON-42',
    subject: 'identity',
    subject_is_minor: false,
    status: 'active',
    operative: true,
    trusted_source: true,
    conflict_free: true,
    usage_token: 'media:ai-generate',
    usage_decision: 'clearance_required',
    clearance_server: 'https://clearance.example/rsl',
    evaluated_at: TIMES.evaluated,
    current_through: TIMES.currentThrough,
    allowed_terms: {
      purposes: ['documentary-promotion'],
      media_types: ['video'],
      territories: ['EU'],
    },
  };

  const principal = crypto.generateKeyPairSync('ed25519');
  const pinnedPrincipalKey = principal.publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
  const grantSpec = buildRslMediaGrantSpec({
    evaluation,
    request: REQUEST,
    principal: 'urn:example:person:rights-holder',
    grantId: 'urn:example:grant:rsl-media:documentary-2026',
    issuedAt: TIMES.evaluated,
    expiresAt: TIMES.expires,
  });
  const grant = buildConsentGrant(grantSpec, principal.privateKey);
  const action = buildRslMediaAction({
    evaluation,
    request: REQUEST,
    grantHash: grant.grant_hash,
    initiator: 'urn:example:agent:campaign-editor',
    policyId: POLICY.policy_id,
    requestedAt: TIMES.evaluated,
  });
  const authority = createVirtualClassAApprover();
  const receipt = await issueExactUseReceipt(
    action,
    authority,
    'urn:example:receipt:rsl-media:documentary-2026:1',
  );
  const verification = verifyClearance(
    receipt,
    grant,
    authority,
    pinnedPrincipalKey,
    evaluation,
  );
  const store = createDurableConsumptionStore(createMemoryBackend());
  let executorCalls = 0;
  const execute = () => {
    executorCalls += 1;
    return { render_job_id: 'render-0042', status: 'accepted' };
  };
  const first = await executeOnce({ verification, receipt, store, effect: execute });
  const replay = await executeOnce({ verification, receipt, store, effect: execute });
  const independentlyIssuedDuplicate = await issueExactUseReceipt(
    action,
    authority,
    'urn:example:receipt:rsl-media:documentary-2026:duplicate',
  );
  const independentlyIssuedDuplicateVerification = verifyClearance(
    independentlyIssuedDuplicate,
    grant,
    authority,
    pinnedPrincipalKey,
    evaluation,
  );
  const duplicateAction = await executeOnce({
    verification: independentlyIssuedDuplicateVerification,
    receipt: independentlyIssuedDuplicate,
    store,
    effect: execute,
  });

  const tampered = clone(receipt);
  tampered.action.rsl_media.campaign_id = 'unauthorized-campaign';
  const tamperedVerification = verifyClearance(
    tampered,
    grant,
    authority,
    pinnedPrincipalKey,
    evaluation,
  );

  const outOfScopeAction = clone(action);
  outOfScopeAction.rsl_media.territory = 'US';
  const outOfScopeReceipt = await issueExactUseReceipt(
    outOfScopeAction,
    authority,
    'urn:example:receipt:rsl-media:documentary-2026:2',
  );
  const outOfScopeVerification = verifyClearance(
    outOfScopeReceipt,
    grant,
    authority,
    pinnedPrincipalKey,
    evaluation,
  );

  const prohibitedEvaluation = {
    ...evaluation,
    usage_decision: 'prohibited',
  };
  const prohibitedVerification = verifyClearance(
    receipt,
    grant,
    authority,
    pinnedPrincipalKey,
    prohibitedEvaluation,
  );
  const absentVerification = verifyClearance(
    receipt,
    grant,
    authority,
    pinnedPrincipalKey,
    null,
  );
  const staleEvaluation = {
    ...evaluation,
    current_through: '2026-07-17T14:59:59Z',
  };
  const staleVerification = verifyClearance(
    receipt,
    grant,
    authority,
    pinnedPrincipalKey,
    staleEvaluation,
  );
  const changedDeclarationVerification = verifyClearance(
    receipt,
    grant,
    authority,
    pinnedPrincipalKey,
    {
      ...evaluation,
      source_document_digest:
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    },
  );

  const concurrentStore = createDurableConsumptionStore(createMemoryBackend());
  let concurrentExecutorCalls = 0;
  const concurrentEffect = () => {
    concurrentExecutorCalls += 1;
    return { status: 'accepted' };
  };
  const concurrentResults = await Promise.all([
    executeOnce({
      verification,
      receipt,
      store: concurrentStore,
      effect: concurrentEffect,
    }),
    executeOnce({
      verification: independentlyIssuedDuplicateVerification,
      receipt: independentlyIssuedDuplicate,
      store: concurrentStore,
      effect: concurrentEffect,
    }),
  ]);
  const concurrentRefused = concurrentResults.filter((item) => item.executed === false);

  return {
    '@version': RSL_CLEARANCE_DEMO_VERSION,
    notice: [
      'Independent compatibility prototype; not endorsed by RSL Media.',
      'RSL-MEDIA 1.0 is a draft that says it must not be used for production.',
      'The XML is synthetic and is evaluated outside this module; no RSL conformance is claimed.',
      'The virtual WebAuthn authenticator proves protocol behavior, not a real mobile ceremony.',
      'The evidence does not establish rights ownership, legal permission, human comprehension, or output safety.',
    ],
    artifacts: {
      declaration_digest: evaluation.source_document_digest,
      isrd: evaluation.isrd,
      grant_hash: grant.grant_hash,
      action_hash: receipt.action_hash,
      receipt_id: receipt.receipt_id,
    },
    cases: [
      {
        id: 'exact-use-executes-once',
        verdict: first.verdict,
        reason: first.reason,
        receipt_valid: verification.receipt.valid,
        grant_composition_valid: verification.grant.ok,
        declaration_binding_valid: verification.declaration.valid,
      },
      {
        id: 'replay-refused',
        verdict: replay.verdict,
        reason: replay.reason,
      },
      {
        id: 'independently-issued-same-action-refused',
        verdict: duplicateAction.verdict,
        reason: duplicateAction.reason,
      },
      {
        id: 'concurrent-independent-receipts-admit-one',
        verdict: concurrentRefused.length === 1 && concurrentExecutorCalls === 1 ? 'refuse' : 'execute',
        reason: concurrentRefused[0]?.reason ?? 'concurrency_invariant_failed',
        executed_count: concurrentExecutorCalls,
        refused_count: concurrentRefused.length,
      },
      {
        id: 'mutated-signed-action-refused',
        verdict: tamperedVerification.accepted ? 'execute' : 'refuse',
        reason: tamperedVerification.receipt.errors[0] ?? tamperedVerification.grant.reason,
      },
      {
        id: 'valid-signature-outside-grant-terms-refused',
        verdict: outOfScopeVerification.accepted ? 'execute' : 'refuse',
        reason: outOfScopeVerification.grant.reason,
        receipt_valid: outOfScopeVerification.receipt.valid,
      },
      {
        id: 'prohibited-declaration-refused',
        verdict: prohibitedVerification.accepted ? 'execute' : 'refuse',
        reason: prohibitedVerification.declaration.verdict,
      },
      {
        id: 'absent-declaration-refused',
        verdict: absentVerification.accepted ? 'execute' : 'refuse',
        reason: absentVerification.declaration.verdict,
      },
      {
        id: 'stale-declaration-refused',
        verdict: staleVerification.accepted ? 'execute' : 'refuse',
        reason: staleVerification.declaration.verdict,
      },
      {
        id: 'changed-declaration-refused',
        verdict: changedDeclarationVerification.accepted ? 'execute' : 'refuse',
        reason: changedDeclarationVerification.declaration.verdict,
      },
    ],
    executor_call_count: executorCalls,
    concurrent_executor_call_count: concurrentExecutorCalls,
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const result = await runRslMediaClearanceDemo();
  console.log('RSL-MEDIA declaration -> EMILIA exact-use clearance');
  for (const item of result.cases) {
    console.log(`${item.verdict === 'execute' ? 'EXECUTE' : 'REFUSE '}  ${item.id}`
      + `${item.reason ? ` (${item.reason})` : ''}`);
  }
  console.log(`executor calls: ${result.executor_call_count}`);
  console.log('\nScope notice:');
  for (const line of result.notice) console.log(`- ${line}`);
}
