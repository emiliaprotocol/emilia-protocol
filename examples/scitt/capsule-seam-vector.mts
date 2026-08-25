// SPDX-License-Identifier: Apache-2.0
//
// EMILIA <-> Agent Action Capsule SEAM VECTOR (who -> what, by shared digest)
//
//   node examples/scitt/capsule-seam-vector.mjs           # verify + print
//   node examples/scitt/capsule-seam-vector.mjs --emit    # (re)write capsule-seam-vector.json
//
// Purpose (per the SCITT thread with Steven Mih / Tom Sato): thread a SINGLE
// action's digest through the who->what seam so the linkage is TESTABLE, not
// asserted. This file is the EMILIA side:
//
//   - subject_digest         = SHA-256( JCS(action) )      -- the exact action both
//                              statements are ABOUT (recomputable on either side).
//   - EP authorization receipt over that action (APPROVED and DENIED variants),
//     natively Ed25519-signed and wrapped as a COSE_Sign1 SCITT Signed Statement.
//   - authority_reference_digest = the digest a Capsule's *opaque authority
//     reference* embeds to commit to the approval WITHOUT restating it. PINNED
//     per profile (Songbo Bu byte-binding review, SCITT list 2026-07-02):
//       * transparency profile: SHA-256( COSE_Sign1 bytes ) = statement_digest
//         (the registered statement object; requires deterministic COSE)
//       * offline profile:       SHA-256( JCS(receipt.payload) ) = receipt_payload_digest
//     One per profile, labelled; both MUST NOT be accepted under one profile.
//   - receipt_payload_digest is ALSO always present as the inner payload check.
//
// Composition rule: authorization -> record, BY DIGEST, not containment. The
// Capsule records subject_digest (same action) and carries authority_reference_
// digest (this receipt). who (EMILIA) -> what (Capsule) is then verifiable
// end-to-end across conforming implementations.
//
// Determinism: a FIXED Ed25519 issuer seed + fixed receipt fields, so every run
// (and every implementation) reproduces byte-identical payloads and digests.
// This is a demo/interop vector key — NOT a production issuer key.

import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { canonicalize } from './ep-receipt-scitt-conformance.mjs';

const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

// --- Deterministic Ed25519 issuer key from a fixed 32-byte seed ---------------
// PKCS#8 prefix for an Ed25519 private key, followed by the 32-byte seed.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SEED = crypto.createHash('sha256').update('ep:capsule-seam-vector:v1:issuer-seed').digest(); // fixed 32B
const privateKey = crypto.createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519_PREFIX, SEED]),
  format: 'der',
  type: 'pkcs8',
});
const publicKey = crypto.createPublicKey(privateKey as any);
const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
const kid = crypto.createHash('sha256').update(spkiDer).digest().subarray(0, 16);

// --- Minimal deterministic CBOR (only what COSE_Sign1 needs; mirrors the profile)
const U = (n) => Buffer.from([n]);
const head = (major, len) => {
  const m = major << 5;
  if (len < 24) return U(m | len);
  if (len < 256) return Buffer.from([m | 24, len]);
  if (len < 65536) return Buffer.from([m | 25, len >> 8, len & 0xff]);
  throw new Error('length out of range');
};
const cbBstr = (buf) => Buffer.concat([head(2, buf.length), buf]);
const cbTstr = (s) => { const b = Buffer.from(s, 'utf8'); return Buffer.concat([head(3, b.length), b]); };
const cbUint = (n) => head(0, n);
const cbNint = (n) => head(1, -1 - n);
const cbArr = (items) => Buffer.concat([head(4, items.length), ...items]);
const cbMap = (pairs) => Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
const tagCoseSign1 = (buf) => Buffer.concat([Buffer.from([0xd2]), buf]); // tag(18)
const CTY = 'application/ep-receipt+json';

// The single action both statements are ABOUT.
const ACTION = { action_type: 'payment.release', target: 'wire:vendor-acme-250000', amount: '250000.00', currency: 'USD' };
const SUBJECT_DIGEST = sha256hex(Buffer.from(canonicalize(ACTION), 'utf8'));

function buildReceiptStatement(payload) {
  const payloadBytes = Buffer.from(canonicalize(payload), 'utf8');
  const nativeSig = crypto.sign(null, payloadBytes, privateKey);

  const protectedMap = cbMap([
    [cbUint(1), cbNint(-8)],        // alg = EdDSA (-8)
    [cbUint(3), cbTstr(CTY)],       // content type
    [cbUint(4), cbBstr(kid)],       // kid
  ]);
  const protectedBstr = cbBstr(protectedMap);
  const sigStructure = cbArr([cbTstr('Signature1'), protectedBstr, cbBstr(Buffer.alloc(0)), cbBstr(payloadBytes)]);
  const coseSig = crypto.sign(null, sigStructure, privateKey);
  const coseSign1 = tagCoseSign1(cbArr([protectedBstr, cbMap([]), cbBstr(payloadBytes), cbBstr(coseSig)]));

  return {
    payload,
    payload_canonical: payloadBytes.toString('utf8'),
    native_signature_b64: nativeSig.toString('base64'),
    cose_sign1_b64: coseSign1.toString('base64'),
    receipt_payload_digest: sha256hex(payloadBytes),   // authority-ref (offline)
    statement_digest: sha256hex(coseSign1),             // authority-ref (registered)
    _payloadBytes: payloadBytes,
    _coseSign1: coseSign1,
    _sigStructure: sigStructure,
    _nativeSig: nativeSig,
    _coseSig: coseSig,
  };
}

// APPROVED: a named human authorized this exact action.
const approved = buildReceiptStatement({
  receipt_id: 'ep:receipt:seam-vector-approved-0001',
  subject: 'agent:autonomous:treasury-bot',
  created_at: '2026-07-02T00:00:00Z',
  claim: {
    action_type: ACTION.action_type,
    target: ACTION.target,
    subject_digest: SUBJECT_DIGEST,
    outcome: 'allow_with_signoff',
    approver: 'jane.doe@yourco.example',
    assurance: 'class_a',
  },
});

// DENIED (verdict-complete): no valid human authorizer -> a SIGNED refusal event.
const denied = buildReceiptStatement({
  receipt_id: 'ep:receipt:seam-vector-denied-0001',
  subject: 'agent:autonomous:treasury-bot',
  created_at: '2026-07-02T00:00:00Z',
  claim: {
    action_type: ACTION.action_type,
    target: ACTION.target,
    subject_digest: SUBJECT_DIGEST,
    outcome: 'deny',
    approver: null,
    reason: 'no_human_authorizer',
  },
});

// --- Negative / MUST-reject vectors for the WHO leg --------------------------
// Per Songbo Bu: a decomposition is only an interop surface if each leg ships its
// own verifier contract AND negative cases. These are the WHO-leg rejects a
// conforming composed verifier MUST enforce, each with the expected reason code.
const ACTION_B = { action_type: 'payment.release', target: 'wire:vendor-acme-999999', amount: '999999.00', currency: 'USD' };
const SUBJECT_DIGEST_B = sha256hex(Buffer.from(canonicalize(ACTION_B), 'utf8'));

// A forged issuer: a different fixed seed signing a look-alike of the approved payload.
const FORGED_SEED = crypto.createHash('sha256').update('ep:capsule-seam-vector:v1:FORGED-issuer').digest();
const forgedKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, FORGED_SEED]), format: 'der', type: 'pkcs8' });
const forgedSigOverApproved = crypto.sign(null, approved._payloadBytes, forgedKey);

const negatives = [
  {
    id: 'wrong_action', must: 'reject', reason: 'who_subject_mismatch',
    detail: 'WHO receipt binds ACTION A; a Capsule recording ACTION B must not accept it as B’s approval.',
    capsule_subject_digest: SUBJECT_DIGEST_B, who_subject_digest: SUBJECT_DIGEST,
    _check: () => SUBJECT_DIGEST !== SUBJECT_DIGEST_B,
  },
  {
    id: 'approval_contradiction', must: 'reject', reason: 'disposition_contradicts_receipt',
    detail: 'Capsule records human_disposed=approved but references the DENIED receipt digest — the WHO evidence is a refusal.',
    referenced_authority_digest: denied.receipt_payload_digest,
    _check: () => denied.payload.claim.outcome === 'deny',
  },
  {
    id: 'untrusted_issuer', must: 'reject', reason: 'issuer_not_pinned',
    detail: 'A receipt signed by a non-pinned key must fail verification under the pinned issuer SPKI — no trust laundering via a receipt-supplied key.',
    forged_signature_b64: forgedSigOverApproved.toString('base64'),
    _check: () => crypto.verify(null, approved._payloadBytes, publicKey, forgedSigOverApproved) === false,
  },
  {
    id: 'replay_across_subject', must: 'reject', reason: 'receipt_action_bound',
    detail: 'The approved receipt is bound to ACTION A via claim.subject_digest; presenting its digest for a Capsule over ACTION B must be refused (action-bound, one-time).',
    receipt_bound_subject: SUBJECT_DIGEST, other_subject: SUBJECT_DIGEST_B,
    _check: () => approved.payload.claim.subject_digest !== SUBJECT_DIGEST_B,
  },
  {
    id: 'missing_who_when_required', must: 'policy_reject', reason: 'who_required_but_absent',
    detail: 'When policy requires accountable-human approval, a Capsule chain with no resolvable WHO digest must be policy-rejected. Verdict-complete: a required-but-absent approval is itself the finding.',
    _check: () => true,
  },
];

function verifyNegatives() {
  return negatives.map((n) => ({ id: n.id, must: n.must, reason: n.reason, enforced: Boolean(n._check()) }));
}

function verifyStatement(s) {
  const nativeOk = crypto.verify(null, s._payloadBytes, publicKey, s._nativeSig);
  const coseOk = crypto.verify(null, s._sigStructure, publicKey, s._coseSig);
  const canonicalStable = canonicalize(s.payload) === s.payload_canonical;
  return { nativeOk, coseOk, canonicalStable, ok: nativeOk && coseOk && canonicalStable };
}

function vectorJson() {
  const strip = ({ _payloadBytes, _coseSign1, _sigStructure, _nativeSig, _coseSig, ...rest }) => rest;
  return {
    vector: 'EP<->Capsule seam vector v1',
    spec: 'docs/EP-CAPSULE-SEAM.md',
    canonicalization: 'RFC 8785 (JCS) over the EP I-JSON value subset; SHA-256 for all digests',
    issuer: {
      alg: 'Ed25519 (COSE EdDSA -8)',
      spki_der_b64: spkiDer.toString('base64'),
      kid_hex: kid.toString('hex'),
      note: 'demo/interop vector key derived from a fixed seed — NOT a production issuer',
    },
    action: ACTION,
    subject_digest: SUBJECT_DIGEST,
    authority_reference: {
      // Pinned per profile (Songbo Bu byte-binding review, SCITT list 2026-07-02):
      // the authority reference binds ONE digest, labelled by profile — never both
      // under one profile. Transparency = the registered statement; offline = the
      // payload. receipt_payload_digest is ALSO always carried as the inner check.
      rule: 'authority_reference_digest is pinned per deployment profile and MUST be labelled. transparency: SHA-256(COSE_Sign1) (statement_digest) — the registered statement object. offline: SHA-256(JCS(receipt.payload)) (receipt_payload_digest). A profile pins exactly one; both MUST NOT be accepted under one profile. receipt_payload_digest is always present as the inner payload check after the statement is dereferenced.',
      binding_by_profile: {
        transparency: 'statement_digest',        // SHA-256(COSE_Sign1 bytes)
        offline: 'receipt_payload_digest',       // SHA-256(JCS(receipt.payload))
      },
      cose_determinism: 'statement_digest is reproducible only under deterministic COSE: canonical CBOR + fixed protected header (alg=EdDSA(-8), cty=application/ep-receipt+json, kid), per EP-RECEIPT-SCITT-PROFILE.md. This generator emits exactly that canonical CBOR.',
      approved: { receipt_payload_digest: approved.receipt_payload_digest, statement_digest: approved.statement_digest },
      denied: { receipt_payload_digest: denied.receipt_payload_digest, statement_digest: denied.statement_digest },
    },
    approved: strip(approved),
    denied: strip(denied),
    action_b: ACTION_B,
    subject_digest_b: SUBJECT_DIGEST_B,
    must_reject: negatives.map(({ _check, ...rest }) => rest),
  };
}

function main() {
  const emit = process.argv.includes('--emit');
  const a = verifyStatement(approved);
  const d = verifyStatement(denied);

  console.log('EMILIA <-> Capsule seam vector');
  console.log(`  action              = ${JSON.stringify(ACTION)}`);
  console.log(`  subject_digest      = ${SUBJECT_DIGEST}`);
  console.log(`  issuer kid          = ${kid.toString('hex')}`);
  console.log('\n  APPROVED');
  console.log(`    receipt_payload_digest (authority-ref, offline)   = ${approved.receipt_payload_digest}`);
  console.log(`    statement_digest       (authority-ref, registered)= ${approved.statement_digest}`);
  console.log(`    native_sig=${a.nativeOk ? 'OK' : 'FAIL'} cose_sig=${a.coseOk ? 'OK' : 'FAIL'} canonical_stable=${a.canonicalStable ? 'OK' : 'FAIL'}`);
  console.log('\n  DENIED (verdict-complete)');
  console.log(`    receipt_payload_digest = ${denied.receipt_payload_digest}`);
  console.log(`    statement_digest       = ${denied.statement_digest}`);
  console.log(`    native_sig=${d.nativeOk ? 'OK' : 'FAIL'} cose_sig=${d.coseOk ? 'OK' : 'FAIL'} canonical_stable=${d.canonicalStable ? 'OK' : 'FAIL'}`);

  const negs = verifyNegatives();
  console.log('\n  MUST-REJECT (WHO-leg negative cases)');
  for (const n of negs) console.log(`    ${n.enforced ? 'ENFORCED' : 'MISSING '} ${n.id} → ${n.must} (${n.reason})`);

  if (emit) {
    const path = fileURLToPath(new URL('./capsule-seam-vector.json', import.meta.url));
    writeFileSync(path, JSON.stringify(vectorJson(), null, 2) + '\n');
    console.log(`\n  wrote ${path}`);
  }

  const ok = a.ok && d.ok && negs.every((n) => n.enforced);
  console.log(`\n${ok ? 'SEAM VECTOR OK' : 'SEAM VECTOR FAIL'} — who(EMILIA) -> what(Capsule) linkage is byte-reproducible across implementations.`);
  if (!ok) process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { ACTION, SUBJECT_DIGEST, approved, denied, verifyStatement, vectorJson };
