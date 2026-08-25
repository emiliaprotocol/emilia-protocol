// SPDX-License-Identifier: Apache-2.0
/**
 * EP <-> Agent Action Capsule seam vector v2.
 *
 * Unlike the immutable legacy v1 artifact, every v2 COSE object is built by
 * `buildEpScittSignedStatement` and accepted by the shipped fail-closed
 * `verifyEpScittSignedStatement` implementation. The vector keeps the exact
 * statement entry, signature input, and verified EP receipt payload identities
 * separate. A digest is a binding value, never authority by itself.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildEpScittSignedStatement,
  canonicalize,
  receiptActionCaid,
  verifyEpScittSignedStatement,
} from '../../packages/verify/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = resolve(HERE, 'capsule-seam-vector-v2.json');
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export const VECTOR_VERSION = 'EP<->Capsule seam vector v2';
export const PROFILE = 'EP-CAPSULE-SEAM-v2';
export const STATEMENT_ISS = 'ep:issuer:capsule-seam-v2-statement';
export const RECEIPT_ISS = 'ep:issuer:capsule-seam-v2-receipt';
export const STATEMENT_KID = 'ep:key:capsule-seam-v2-statement#1';

type PlainObject = Record<string, any>;

function must<T>(result: { ok: boolean; value?: T; reason?: string }, label: string): T {
  assert.equal(result.ok, true, `${label}: ${result.reason}`);
  return result.value as T;
}

function fixedEd25519(label: string) {
  const seed = crypto.createHash('sha256').update(label, 'utf8').digest();
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    privateKey,
    publicKeyBase64url:
      publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

const receiptIssuer = fixedEd25519('ep:capsule-seam-vector:v2:receipt-issuer');
const statementIssuer = fixedEd25519('ep:capsule-seam-vector:v2:statement-issuer');
const otherReceiptIssuer = fixedEd25519('ep:capsule-seam-vector:v2:other-receipt-issuer');

export const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  payment_instruction_id: 'wire:vendor-acme-250000',
  target: 'wire:vendor-acme-250000',
  amount: '250000.00',
  currency: 'USD',
  beneficiary_account:
    'sha256:12f641b8c481e23c00148de1bb73989601dfa6a5562f72b5e358fcda6e8eb674',
});

const ACTION_IDENTITY = must<{ caid: string; digest: string }>(
  receiptActionCaid(ACTION),
  'action identity',
);

export const ACTION_CAID = ACTION_IDENTITY.caid;
export const SUBJECT_DIGEST = ACTION_IDENTITY.digest;

function makeReceipt(
  receiptId: string,
  decision: PlainObject,
  signer = receiptIssuer,
) {
  const payload = {
    receipt_id: receiptId,
    issuer: RECEIPT_ISS,
    issued_at: '2026-08-25T00:00:00Z',
    quorum_threshold: 1,
    action: ACTION,
    context: {
      organization: 'capsule_seam_conformance',
      subject: 'agent:autonomous:treasury-bot',
      subject_digest: SUBJECT_DIGEST,
      authority_decision: decision,
    },
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalize(payload), 'utf8'),
    signer.privateKey,
  );
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: signature.toString('base64url'),
    },
  };
}

function buildFixture(receipt: ReturnType<typeof makeReceipt>) {
  const built = must<{
    statement: Uint8Array;
    payload: Uint8Array;
    iss: string;
    sub: string;
  }>(buildEpScittSignedStatement(receipt, {
    statementPrivateKey: statementIssuer.privateKey,
    kid: STATEMENT_KID,
    iss: STATEMENT_ISS,
  }), 'EP Signed Statement');
  const pins = {
    statementPublicKeyBase64url: statementIssuer.publicKeyBase64url,
    receiptIssuerPublicKeyBase64url: receiptIssuer.publicKeyBase64url,
    expectedKid: STATEMENT_KID,
    expectedIss: STATEMENT_ISS,
    expectedSub: ACTION_CAID,
  };
  const verified = verifyEpScittSignedStatement(built.statement, pins);
  assert.equal(verified.valid, true, verified.reason ?? 'profile verification refused');
  assert.ok(verified.identity, 'verified statement must expose identity layers');
  return {
    receipt,
    receipt_document_canonical: Buffer.from(built.payload).toString('utf8'),
    statement_cose_sign1_b64: Buffer.from(built.statement).toString('base64'),
    authorization_payload_digest: verified.identity.authorization_payload_digest,
    signing_input_digest: verified.identity.signing_input_digest,
    statement_entry_digest: verified.identity.statement_entry_digest,
    statement_payload_digest: verified.identity.statement_payload_digest,
    authority_reference_digest: verified.identity.authorization_payload_digest,
    iss: verified.iss as string,
    sub: verified.sub as string,
    kid: verified.kid as string,
    verification: {
      valid: verified.valid,
      registered: verified.registered,
      checks: verified.checks,
    },
    statement: built.statement,
    pins,
  };
}

export const approved = buildFixture(makeReceipt(
  'ep:receipt:capsule-seam-v2-approved-0001',
  {
    outcome: 'allow_with_signoff',
    approver: 'jane.doe@yourco.example',
    assurance: 'class_a',
  },
));

export const denied = buildFixture(makeReceipt(
  'ep:receipt:capsule-seam-v2-denied-0001',
  {
    outcome: 'deny',
    approver: null,
    reason: 'no_human_authorizer',
  },
));

export type CapsuleBindingInput = {
  action: PlainObject;
  authority_reference_digest?: string;
  expected_outcome?: string;
};

export function verifyCapsuleBinding(
  fixture: typeof approved,
  input: CapsuleBindingInput,
): { accepted: boolean; reason: string } {
  const verified = verifyEpScittSignedStatement(fixture.statement, fixture.pins);
  if (!verified.valid || !verified.identity || !verified.receipt) {
    return { accepted: false, reason: verified.reason ?? 'statement_invalid' };
  }
  const presented = receiptActionCaid(input.action);
  if (!presented.ok || presented.value.caid !== verified.sub) {
    return { accepted: false, reason: 'who_subject_mismatch' };
  }
  if (typeof input.authority_reference_digest !== 'string') {
    return { accepted: false, reason: 'who_required_but_absent' };
  }
  if (input.authority_reference_digest
      !== verified.identity.authorization_payload_digest) {
    return { accepted: false, reason: 'authority_reference_mismatch' };
  }
  const decision = (verified.receipt as PlainObject)?.payload?.context?.authority_decision;
  if (typeof input.expected_outcome === 'string'
      && decision?.outcome !== input.expected_outcome) {
    return { accepted: false, reason: 'disposition_contradicts_receipt' };
  }
  return { accepted: true, reason: 'verified_binding' };
}

function verifyReceiptActionBinding(
  fixture: typeof approved,
  action: PlainObject,
): { accepted: boolean; reason: string } {
  const verified = verifyEpScittSignedStatement(fixture.statement, fixture.pins);
  if (!verified.valid) return { accepted: false, reason: verified.reason ?? 'statement_invalid' };
  const presented = receiptActionCaid(action);
  if (!presented.ok || presented.value.caid !== verified.sub) {
    return { accepted: false, reason: 'receipt_action_bound' };
  }
  return { accepted: true, reason: 'verified_action_binding' };
}

function negativeCases() {
  const actionB = {
    ...ACTION,
    payment_instruction_id: 'wire:vendor-acme-999999',
    target: 'wire:vendor-acme-999999',
    amount: '999999.00',
  };
  const wrongAction = verifyCapsuleBinding(approved, {
    action: actionB,
    authority_reference_digest: approved.authority_reference_digest,
    expected_outcome: 'allow_with_signoff',
  });
  const contradiction = verifyCapsuleBinding(denied, {
    action: ACTION,
    authority_reference_digest: denied.authority_reference_digest,
    expected_outcome: 'allow_with_signoff',
  });
  const missingWho = verifyCapsuleBinding(approved, {
    action: ACTION,
    expected_outcome: 'allow_with_signoff',
  });
  const replay = verifyReceiptActionBinding(approved, actionB);

  const forgedReceipt = makeReceipt(
    'ep:receipt:capsule-seam-v2-forged-0001',
    {
      outcome: 'allow_with_signoff',
      approver: 'mallory@example.invalid',
      assurance: 'untrusted',
    },
    otherReceiptIssuer,
  );
  const forgedBuilt = must<{ statement: Uint8Array }>(buildEpScittSignedStatement(forgedReceipt, {
    statementPrivateKey: statementIssuer.privateKey,
    kid: STATEMENT_KID,
    iss: STATEMENT_ISS,
  }), 'forged receipt statement');
  const untrusted = verifyEpScittSignedStatement(forgedBuilt.statement, approved.pins);

  return [
    {
      id: 'wrong_action',
      must: 'reject',
      expected_reason: 'who_subject_mismatch',
      observed_reason: wrongAction.reason,
      enforced: wrongAction.accepted === false && wrongAction.reason === 'who_subject_mismatch',
    },
    {
      id: 'approval_contradiction',
      must: 'reject',
      expected_reason: 'disposition_contradicts_receipt',
      observed_reason: contradiction.reason,
      enforced: contradiction.accepted === false
        && contradiction.reason === 'disposition_contradicts_receipt',
    },
    {
      id: 'untrusted_receipt_issuer',
      must: 'reject',
      expected_reason: 'receipt_invalid',
      observed_reason: untrusted.reason ?? 'missing',
      enforced: untrusted.valid === false && untrusted.reason === 'receipt_invalid',
    },
    {
      id: 'replay_across_subject',
      must: 'reject',
      expected_reason: 'receipt_action_bound',
      observed_reason: replay.reason,
      enforced: replay.accepted === false && replay.reason === 'receipt_action_bound',
    },
    {
      id: 'missing_who_when_required',
      must: 'policy_reject',
      expected_reason: 'who_required_but_absent',
      observed_reason: missingWho.reason,
      enforced: missingWho.accepted === false && missingWho.reason === 'who_required_but_absent',
    },
  ];
}

function portableFixture(fixture: typeof approved) {
  const { statement: _statement, pins: _pins, ...portable } = fixture;
  return portable;
}

export function vectorJson() {
  const negatives = negativeCases();
  assert.equal(negatives.every((entry) => entry.enforced), true,
    JSON.stringify(negatives, null, 2));
  return {
    vector: VECTOR_VERSION,
    profile: PROFILE,
    spec: 'docs/EP-CAPSULE-SEAM.md',
    compatibility: {
      predecessor: 'examples/scitt/capsule-seam-vector.json',
      rule: 'v1 remains immutable; v2 is a new profile-valid artifact and does not rewrite v1 bytes',
    },
    canonicalization: 'RFC 8785 JCS over the EP I-JSON subset; SHA-256 digests use the sha256:hex form',
    issuer: {
      statement_issuer: STATEMENT_ISS,
      statement_kid: STATEMENT_KID,
      statement_public_key_spki_base64url: statementIssuer.publicKeyBase64url,
      receipt_issuer: RECEIPT_ISS,
      receipt_issuer_public_key_spki_base64url: receiptIssuer.publicKeyBase64url,
      note: 'fixed conformance keys only; never production issuer keys',
    },
    action: ACTION,
    action_caid: ACTION_CAID,
    subject_digest: SUBJECT_DIGEST,
    authority_reference: {
      field: 'authorization_payload_digest',
      rule: 'Resolve the statement, run the complete pinned EP verifier, and only then compare SHA-256(JCS(receipt.payload)); statement-entry and signing-input digests cannot substitute',
      approved: approved.authority_reference_digest,
      denied: denied.authority_reference_digest,
    },
    approved: portableFixture(approved),
    denied: portableFixture(denied),
    must_reject: negatives,
    claim_boundary: [
      'A locally verified Signed Statement is not a registered or transparent statement.',
      'A digest binds bytes or canonical content; it does not independently establish authorization.',
      'The decision field is signed application evidence. Gate and relying-party policy still decide whether an action may execute.',
    ],
  };
}

function main() {
  const vector = vectorJson();
  if (process.argv.includes('--emit')) {
    writeFileSync(VECTOR_PATH, `${JSON.stringify(vector, null, 2)}\n`, 'utf8');
  }
  if (process.argv.includes('--check')) {
    const frozen = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
    assert.deepEqual(vector, frozen,
      'capsule seam v2 vector drifted; inspect and re-pin deliberately with --emit');
  }
  process.stdout.write(`${JSON.stringify({
    vector: vector.vector,
    profile: vector.profile,
    approved_profile_valid: approved.verification.valid,
    denied_profile_valid: denied.verification.valid,
    registered: false,
    negative_cases_enforced: vector.must_reject.length,
  }, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
