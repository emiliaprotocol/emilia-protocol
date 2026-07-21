// SPDX-License-Identifier: Apache-2.0
// Generated from ep-receipt-as-signed-statement.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-RECEIPT-SCITT-PROFILE-v1 — runnable example.
//
// Produces an EMILIA authorization receipt, wraps it as a SCITT Signed Statement
// (a COSE_Sign1, RFC 9052) per docs/EP-RECEIPT-SCITT-PROFILE.md, and prints the
// SCRAPI registration request a Transparency Service would ingest. Zero runtime
// dependencies (node:crypto only) so it runs anywhere with `node`.
//
//   node examples/scitt/ep-receipt-as-signed-statement.mjs
//
// The Ed25519 signature is real and is self-verified below over the exact COSE
// Sig_structure (RFC 9052 §4.4). The CBOR encoder here is minimal and covers
// exactly the COSE_Sign1 shape in the profile; validate against a full COSE
// library (e.g. @auth0/cose) before production use.
import crypto from 'node:crypto';
// --- RFC 8785 (JCS) canonicalization over the EP I-JSON value subset ---------
const canonicalize = (v) => v === null || v === undefined ? JSON.stringify(v)
    : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
        : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
            : JSON.stringify(v);
// --- minimal deterministic CBOR encoder (only the types this profile needs) --
const U = (n) => Buffer.from([n]);
function head(major, len) {
    const m = major << 5;
    if (len < 24)
        return U(m | len);
    if (len < 256)
        return Buffer.from([m | 24, len]);
    if (len < 65536)
        return Buffer.from([m | 25, len >> 8, len & 0xff]);
    throw new Error('length out of range for this minimal encoder');
}
const cbBstr = (buf) => Buffer.concat([head(2, buf.length), buf]);
const cbTstr = (s) => { const b = Buffer.from(s, 'utf8'); return Buffer.concat([head(3, b.length), b]); };
const cbUint = (n) => head(0, n);
const cbNint = (n) => head(1, -1 - n); // negative int: -1-n
const cbArr = (items) => Buffer.concat([head(4, items.length), ...items]);
function cbMap(pairs) {
    return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}
const TAG_COSE_SIGN1 = (buf) => Buffer.concat([Buffer.from([0xd2]), buf]); // tag(18)
// --- 1. Mint an EMILIA authorization receipt (Ed25519 over JCS) ---------------
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const kid = crypto.createHash('sha256').update(spki).digest().subarray(0, 16); // issuer key id
const action = { action_type: 'db.records.delete_all', target: 'customers' };
const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: { action_type: action.action_type, target: action.target, outcome: 'allow_with_signoff', approver: 'jane.doe@yourco.example' },
    // prev: <SHA-256 of the prior hop's canonical receipt> for a lineage chain (omitted: this is hop 0)
};
const payloadBytes = Buffer.from(canonicalize(payload), 'utf8');
const nativeSig = crypto.sign(null, payloadBytes, privateKey); // the native EP-RECEIPT-v1 signature
// --- 2. Build the SCITT Signed Statement (COSE_Sign1) -------------------------
// protected header: { 1: EdDSA(-8), 3: "application/ep-receipt+json", 4: kid }
const protectedMap = cbMap([
    [cbUint(1), cbNint(-8)], // alg = EdDSA (-8)
    [cbUint(3), cbTstr('application/ep-receipt+json')], // content type
    [cbUint(4), cbBstr(kid)], // kid
]);
const protectedBstr = cbBstr(protectedMap); // protected header is a bstr-wrapped map
// Sig_structure = [ "Signature1", protected, external_aad (empty bstr), payload ]  (RFC 9052 §4.4)
const sigStructure = cbArr([cbTstr('Signature1'), protectedBstr, cbBstr(Buffer.alloc(0)), cbBstr(payloadBytes)]);
const coseSig = crypto.sign(null, sigStructure, privateKey);
// COSE_Sign1 = tag(18) [ protected, unprotected({}), payload, signature ]
const coseSign1 = TAG_COSE_SIGN1(cbArr([protectedBstr, cbMap([]), cbBstr(payloadBytes), cbBstr(coseSig)]));
// --- 3. Self-verify the COSE signature over the Sig_structure -----------------
const ok = crypto.verify(null, sigStructure, publicKey, coseSig);
if (!ok) {
    console.error('FATAL: COSE Sig_structure signature did not verify');
    process.exit(1);
}
// --- 4. Emit the artifacts ----------------------------------------------------
console.log('EMILIA authorization receipt (EP-RECEIPT-v1):');
console.log(JSON.stringify({ '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: nativeSig.toString('base64url') }, public_key: spki.toString('base64url') }, null, 2));
console.log('\nSCITT Signed Statement (COSE_Sign1, EP-RECEIPT-SCITT-PROFILE-v1):');
console.log('  alg=EdDSA  cty=application/ep-receipt+json  kid=' + kid.toString('hex'));
console.log('  Sig_structure signature verified offline: ' + ok);
console.log('  COSE_Sign1 (hex): ' + coseSign1.toString('hex'));
console.log('\nSCRAPI registration request (draft-ietf-scitt-scrapi):');
console.log('  POST /entries');
console.log('  Content-Type: application/cose');
console.log('  body: <the COSE_Sign1 bytes above>');
console.log('\nThe Transparency Service responds with a SCITT inclusion Receipt (COSE Merkle proof).');
console.log('Signed Statement + Receipt = Transparent Statement. EMILIA = who authorized; SCITT = proof it was logged.');
