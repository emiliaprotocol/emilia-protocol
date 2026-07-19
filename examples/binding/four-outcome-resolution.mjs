#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Runnable composition of a transient Morrison binding-moment envelope with a
// durable EP-RESOLUTION-v1 record. The generated P-256 key emulates a WebAuthn
// authenticator for this local demonstration; it is not a hardware attestation.

import crypto from 'node:crypto';
import {
  RESOLUTION_CONTEXT_TYPE,
  RESOLUTION_VERSION,
  computeBindingMomentHash,
  computeResolutionChallenge,
  computeResolutionResponseHash,
  verifyResolutionReceipt,
} from '../../packages/verify/resolution.js';

const RP_ID = 'emiliaprotocol.ai';
const PRINCIPAL = 'ep:principal:jchen';
const KEY_ID = 'ep:key:jchen#resolution-demo';
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;
const NONCE = 'resolution-demo-001';
const INITIATOR = 'spiffe://operator.example/agent/7';

const bindingMoment = {
  synopsis: 'Release the staged disbursement after the second review.',
  findings: ['The payee and amount match the approved invoice.'],
  recommendations: ['Release the payment.', 'Hold for another review.'],
  offer: 'Ask for the invoice or account-change history.',
  question: {
    stem: 'Should the staged disbursement be released?',
    options: [
      { label: 'Release', reasoning: 'The verification checks passed.' },
      { label: 'Hold', reasoning: 'A further review can still be requested.' },
    ],
    recommended_idx: 0,
    hatches: { free_text: true, dialogue: true },
  },
};

const successorMoment = {
  ...bindingMoment,
  synopsis: 'Release half of the disbursement and hold the remainder.',
  question: { ...bindingMoment.question, stem: 'Should half of the disbursement be released?' },
};

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pinnedPublicKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function mint(resolution) {
  const context = {
    ep_version: '1.0',
    context_type: RESOLUTION_CONTEXT_TYPE,
    envelope_hash: computeBindingMomentHash(bindingMoment),
    action_hash: ACTION_HASH,
    principal: PRINCIPAL,
    principal_key_id: KEY_ID,
    initiator: INITIATOR,
    nonce: NONCE,
    issued_at: '2026-07-14T05:25:00Z',
    expires_at: '2026-07-14T05:35:00Z',
    resolution,
  };
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: computeResolutionChallenge(context),
    origin: 'https://www.emiliaprotocol.ai',
  }));
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID).digest(),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signedBytes = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientData).digest(),
  ]);
  return {
    profile: RESOLUTION_VERSION,
    signoff: {
      '@type': 'ep.signoff',
      context,
      webauthn: {
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: crypto.sign('sha256', signedBytes, privateKey).toString('base64url'),
      },
    },
  };
}

const verifyOpts = {
  bindingMoment,
  expectedActionHash: ACTION_HASH,
  expectedSelectedOption: 0,
  expectedNonce: NONCE,
  expectedInitiator: INITIATOR,
  evaluationTime: '2026-07-14T05:30:00Z',
  rpId: RP_ID,
  allowedOrigins: ['https://www.emiliaprotocol.ai'],
  principalKeys: { [KEY_ID]: { principal: PRINCIPAL, public_key: pinnedPublicKey } },
};

const receipts = {
  approved: mint({ outcome: 'approved', selected_option: 0 }),
  declined: mint({ outcome: 'declined' }),
  amended: mint({
    outcome: 'amended',
    response_hash: computeResolutionResponseHash('Release only half.'),
    successor_envelope_hash: computeBindingMomentHash(successorMoment),
  }),
  rejected: mint({
    outcome: 'rejected',
    objection_hash: computeResolutionResponseHash('The payee identity is unresolved.'),
  }),
};

console.log('EP-RESOLUTION-v1: envelope -> durable four-outcome record');
for (const [name, receipt] of Object.entries(receipts)) {
  const result = verifyResolutionReceipt(receipt, verifyOpts);
  const expectedAuthority = name === 'approved';
  if (!result.valid || result.authorizes_action !== expectedAuthority) {
    throw new Error(`${name} produced an unexpected verdict: ${JSON.stringify(result)}`);
  }
  console.log(`${name.padEnd(8)} valid=${result.valid} authorizes_action=${result.authorizes_action} requires_successor=${result.requires_successor}`);
}

const noOptionMap = verifyResolutionReceipt(receipts.approved, {
  ...verifyOpts,
  expectedSelectedOption: undefined,
});
if (!noOptionMap.valid || noOptionMap.authorizes_action) {
  throw new Error('an unpinned option-to-action mapping authorized execution');
}
console.log('no-map   valid=true authorizes_action=false');

const relabeled = structuredClone(receipts.declined);
relabeled.signoff.context.resolution = { outcome: 'approved', selected_option: 0 };
const attack = verifyResolutionReceipt(relabeled, verifyOpts);
if (attack.valid || attack.authorizes_action) throw new Error('outcome relabeling was accepted');
console.log(`relabel  refused=${!attack.valid} reason=${attack.reason}`);

console.log('OK: four meanings preserved; only a pinned, authentic approval authorizes.');
