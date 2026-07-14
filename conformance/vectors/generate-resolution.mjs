// SPDX-License-Identifier: Apache-2.0
// Generate EP-RESOLUTION-v1 cross-language vectors with a fixed P-256 test key.
// The key is public test material only. Run: node generate-resolution.mjs

import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { canonicalize } from '../../packages/issue/index.js';
import {
  RESOLUTION_CONTEXT_TYPE,
  RESOLUTION_VERSION,
  computeBindingMomentHash,
  computeResolutionResponseHash,
} from '../../packages/verify/resolution.js';

const TEST_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSjVayBMRRDKrRITX
WdPo+H/5oIqu2VUMEkc7PIt5MOehRANCAATbrq46hGNCM0BGVFEUCThNq5j4EPAy
7MoVtW6QpL5GkZcLCA98W74O8i3o/V31OFBPLyo3dYmk8y57UJeWw1wP
-----END PRIVATE KEY-----`;
const PRIVATE_KEY = crypto.createPrivateKey(TEST_PRIVATE_KEY);
const PUBLIC_KEY = crypto.createPublicKey(PRIVATE_KEY)
  .export({ type: 'spki', format: 'der' }).toString('base64url');

const RP_ID = 'emiliaprotocol.ai';
const PRINCIPAL = 'ep:principal:jchen';
const KEY_ID = 'ep:key:jchen#resolution-1';
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;
const NONCE = 'res_8c0f0e9e7f8a4c9aa3c7';
const INITIATOR = 'spiffe://operator.example/agent/7';
const EVALUATION_TIME = '2026-07-14T05:30:00.000Z';

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
  synopsis: 'Release half of the staged disbursement and hold the remainder.',
  question: {
    ...bindingMoment.question,
    stem: 'Should half of the staged disbursement be released?',
  },
};

function makeReceipt(resolution, {
  contextOverrides = {},
  sourceBindingMoment = bindingMoment,
  signedRpId = RP_ID,
  signedOrigin = 'https://www.emiliaprotocol.ai',
  flags = 0x05,
  tamperAfterSign = null,
} = {}) {
  const context = {
    ep_version: '1.0',
    context_type: RESOLUTION_CONTEXT_TYPE,
    envelope_hash: computeBindingMomentHash(sourceBindingMoment),
    action_hash: ACTION_HASH,
    principal: PRINCIPAL,
    principal_key_id: KEY_ID,
    initiator: INITIATOR,
    nonce: NONCE,
    issued_at: '2026-07-14T05:25:00.000Z',
    expires_at: '2026-07-14T05:35:00.000Z',
    resolution,
    ...contextOverrides,
  };
  const challenge = crypto.createHash('sha256').update(canonicalize(context), 'utf8').digest('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge, origin: signedOrigin,
  }), 'utf8');
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(signedRpId, 'utf8').digest(),
    Buffer.from([flags]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signed, PRIVATE_KEY).toString('base64url');
  const deliveredContext = tamperAfterSign ? { ...context, ...tamperAfterSign } : context;
  return {
    profile: RESOLUTION_VERSION,
    signoff: {
      '@type': 'ep.signoff',
      context: deliveredContext,
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature,
      },
    },
  };
}

const defaultVerification = {
  binding_moment: bindingMoment,
  expected_action_hash: ACTION_HASH,
  expected_selected_option: 0,
  expected_nonce: NONCE,
  expected_initiator: INITIATOR,
  evaluation_time: EVALUATION_TIME,
  rp_id: RP_ID,
  allowed_origins: ['https://www.emiliaprotocol.ai'],
  principal_keys: { [KEY_ID]: { principal: PRINCIPAL, public_key: PUBLIC_KEY } },
};

const vectors = [];
function add(id, description, failureClass, valid, receipt, verification = {}, mode = 'receipt') {
  vectors.push({
    id,
    description,
    failure_class: failureClass,
    expect: { valid },
    [mode === 'authorization' ? 'resolution_authorization' : 'resolution_receipt']: receipt,
    ...defaultVerification,
    ...verification,
  });
}

const approved = makeReceipt({ outcome: 'approved', selected_option: 0 });
const declined = makeReceipt({ outcome: 'declined' });
const amended = makeReceipt({
  outcome: 'amended',
  response_hash: computeResolutionResponseHash('Release only half.'),
  successor_envelope_hash: computeBindingMomentHash(successorMoment),
});
const rejected = makeReceipt({
  outcome: 'rejected',
  objection_hash: computeResolutionResponseHash('The payee identity is unresolved.'),
});

add('accept_approved', 'A pinned Class-A principal approved one exact option for the exact action.', 'accept', true, approved);
add('accept_declined', 'The question was well formed and the principal answered no.', 'accept', true, declined);
add('accept_amended', 'The question stands but the answer space was amended; the response and successor are digest-bound.', 'accept', true, amended);
add('accept_rejected', 'The principal rejected the question itself and reopened deliberation.', 'accept', true, rejected);

add('refuse_declined_as_authorization', 'A valid decline is evidence but never authority for the action.', 'outcome-class', false, declined, {}, 'authorization');
add('refuse_amended_as_authorization', 'A valid amendment cannot authorize the original action.', 'outcome-class', false, amended, {}, 'authorization');
add('refuse_rejected_as_authorization', 'A valid rejection cannot authorize the original action.', 'outcome-class', false, rejected, {}, 'authorization');
add('refuse_approved_without_option_binding', 'A valid approval is evidence but not authority until the relying party pins which option denotes this action.', 'option-action-binding', false, approved,
  { expected_selected_option: undefined }, 'authorization');
add('refuse_approved_wrong_option_binding', 'An approval for one envelope option cannot authorize the action mapped to another option.', 'option-action-binding', false, approved,
  { expected_selected_option: 1 }, 'authorization');
add('refuse_approved_without_nonce_pin', 'An authentic approval is not executable authority without a relying-party-pinned ceremony nonce.', 'replay-context', false, approved,
  { expected_nonce: undefined }, 'authorization');
add('refuse_approved_without_initiator_pin', 'An authentic approval is not executable authority without a relying-party-pinned initiator.', 'initiator-binding', false, approved,
  { expected_initiator: undefined }, 'authorization');
add('refuse_approved_without_evaluation_time', 'An authentic approval is not executable authority without a relying-party evaluation time inside the signed window.', 'lifecycle', false, approved,
  { evaluation_time: undefined }, 'authorization');

add('reject_outcome_relabel', 'A signed decline relabeled approved after the ceremony breaks the challenge binding.', 'cryptographic-binding', false,
  makeReceipt({ outcome: 'declined' }, { tamperAfterSign: { resolution: { outcome: 'approved', selected_option: 0 } } }));
const substitutedMoment = structuredClone(bindingMoment);
substitutedMoment.question.stem = 'Should a different transfer be released?';
add('reject_envelope_substitution', 'The receipt is presented with a different source envelope.', 'envelope-binding', false, approved,
  { binding_moment: substitutedMoment });
add('reject_action_substitution', 'The relying party expects a different action digest.', 'action-binding', false, approved,
  { expected_action_hash: `sha256:${'b'.repeat(64)}` });
add('reject_unpinned_principal_key', 'No role-pinned principal key is supplied.', 'authority', false, approved,
  { principal_keys: {} });
add('reject_cross_principal_key', 'The same SPKI pinned to another principal cannot establish this principal.', 'authority', false, approved,
  { principal_keys: { [KEY_ID]: { principal: 'ep:principal:mallory', public_key: PUBLIC_KEY } } });
add('reject_wrong_rp', 'The relying party expects a different WebAuthn RP ID.', 'audience', false, approved,
  { rp_id: 'other.example' });
add('reject_wrong_origin', 'A valid signature from an origin outside the relying-party allowlist is refused.', 'audience', false,
  makeReceipt({ outcome: 'approved', selected_option: 0 }, { signedOrigin: 'https://attacker.example' }));
add('reject_expired_ceremony', 'Evaluation time is outside the signed ceremony window.', 'lifecycle', false, approved,
  { evaluation_time: '2026-07-14T06:00:00.000Z' });
add('reject_impossible_calendar_date', 'February 30 is not an RFC 3339 instant and must not normalize to March.', 'lifecycle', false,
  makeReceipt({ outcome: 'approved', selected_option: 0 }, {
    contextOverrides: { issued_at: '2026-02-30T05:25:00.000Z', expires_at: '2026-03-03T05:35:00.000Z' },
  }), { evaluation_time: '2026-03-01T05:30:00.000Z' });
add('reject_nonce_mismatch', 'The relying party expected a different single-ceremony nonce.', 'replay-context', false, approved,
  { expected_nonce: 'res_other' });
add('reject_initiator_mismatch', 'The artifact is replayed under a different initiating agent.', 'initiator-binding', false, approved,
  { expected_initiator: 'spiffe://operator.example/agent/other' });

const malformedMoment = structuredClone(bindingMoment);
delete malformedMoment.question.hatches.dialogue;
add('reject_malformed_binding_moment', 'A source envelope that violates the binding-moment grammar cannot gain authority through a valid signature.', 'envelope-grammar', false,
  makeReceipt({ outcome: 'rejected' }, { sourceBindingMoment: malformedMoment }),
  { binding_moment: malformedMoment });
const unsafeMoment = structuredClone(bindingMoment);
unsafeMoment.question.recommended_idx = 9007199254740992;
add('reject_noncanonical_binding_moment', 'A binding moment outside the cross-language safe-integer profile is refused before hashing.', 'canonicalization', false,
  makeReceipt({ outcome: 'rejected' }, { contextOverrides: { envelope_hash: `sha256:${'c'.repeat(64)}` } }),
  { binding_moment: unsafeMoment });

add('reject_approved_without_selection', 'Approved must identify one option from the envelope.', 'outcome-grammar', false,
  makeReceipt({ outcome: 'approved' }));
add('reject_approved_selection_out_of_range', 'Approved cannot select an option absent from the envelope.', 'outcome-grammar', false,
  makeReceipt({ outcome: 'approved', selected_option: 9 }));
add('reject_amended_without_response', 'Amended must bind the principal-authored answer.', 'outcome-grammar', false,
  makeReceipt({ outcome: 'amended' }));
add('reject_decline_with_successor', 'Declined cannot smuggle a successor pointer; the original question was accepted as posed.', 'outcome-grammar', false,
  makeReceipt({ outcome: 'declined', successor_envelope_hash: computeBindingMomentHash(successorMoment) }));
add('reject_self_successor', 'A rejected or amended envelope cannot name itself as its successor.', 'continuation-binding', false,
  makeReceipt({ outcome: 'rejected', successor_envelope_hash: computeBindingMomentHash(bindingMoment) }));
add('reject_unknown_outcome', 'An unregistered fifth outcome fails closed.', 'outcome-grammar', false,
  makeReceipt({ outcome: 'deferred' }));
add('reject_malformed_receipt', 'Hostile empty input refuses instead of throwing.', 'structural', false, {});

const output = {
  suite: 'EP-RESOLUTION-v1',
  profile: 'Four-outcome device-signed resolution of draft-morrison-binding-moment-envelope',
  vectors_version: '1.0.0',
  description: 'Shared vectors for approved, declined, amended, and rejected resolution receipts, including the rule that only approved can authorize the original action.',
  scope_note: 'The source binding_moment, exact expected action digest, expected RP ID, and role-pinned principal key are verifier inputs. A valid receipt proves the presented resolution under those inputs. It does not prove the envelope briefing was truthful, the decision was wise, or an approved receipt was consumed exactly once; consumption remains a stateful enforcement property.',
  count: vectors.length,
  vectors,
};

writeFileSync(new URL('./resolution.v1.json', import.meta.url), `${JSON.stringify(output, null, 2)}\n`);
console.log(`wrote resolution.v1.json -- ${vectors.length} vectors`);
