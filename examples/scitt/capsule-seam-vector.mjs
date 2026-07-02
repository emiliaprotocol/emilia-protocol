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
//     reference* embeds to commit to the approval WITHOUT restating it:
//       * receipt_payload_digest = SHA-256( JCS(receipt.payload) )  (offline)
//       * statement_digest       = SHA-256( COSE_Sign1 bytes )      (when registered)
//
// Composition rule: authorization -> record, BY DIGEST, not containment. The
// Capsule records subject_digest (same action) and carries authority_reference_
// digest (this receipt). who (EMILIA) -> what (Capsule) is then verifiable
// end-to-end across independent implementations.
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
const publicKey = crypto.createPublicKey(privateKey);
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
      rule: 'A Capsule commits to the approval by embedding one of these digests in its opaque authority reference. Recommend statement_digest when the receipt is registered as a SCITT Signed Statement; receipt_payload_digest for offline composition.',
      approved: { receipt_payload_digest: approved.receipt_payload_digest, statement_digest: approved.statement_digest },
      denied: { receipt_payload_digest: denied.receipt_payload_digest, statement_digest: denied.statement_digest },
    },
    approved: strip(approved),
    denied: strip(denied),
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

  if (emit) {
    const path = fileURLToPath(new URL('./capsule-seam-vector.json', import.meta.url));
    writeFileSync(path, JSON.stringify(vectorJson(), null, 2) + '\n');
    console.log(`\n  wrote ${path}`);
  }

  const ok = a.ok && d.ok;
  console.log(`\n${ok ? 'SEAM VECTOR OK' : 'SEAM VECTOR FAIL'} — who(EMILIA) -> what(Capsule) linkage is byte-reproducible across implementations.`);
  if (!ok) process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { ACTION, SUBJECT_DIGEST, approved, denied, verifyStatement, vectorJson };
