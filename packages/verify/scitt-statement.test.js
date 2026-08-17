// SPDX-License-Identifier: Apache-2.0
// Generated from scitt-statement.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP-SCITT-STATEMENT-v1 suite.
 *
 * Portable node:test program, like the sibling pq-hybrid / a2a-receipt-binding
 * suites. The repository-wide Vitest collector excludes `packages/**`, so run it
 * directly:
 *
 *   npx tsx --test packages/verify/scitt-statement.test.ts
 *
 * The module under test is imported from `src/` rather than from the package
 * index: EP-SCITT-STATEMENT-v1 is not exported from `src/index.ts` yet (that is
 * a separate integration step), and the suite must not depend on it being.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildEpScittSignedStatement, verifyEpScittSignedStatement, describeScittRegistrationRequest, EP_SCITT_STATEMENT_PROFILE, EP_STATEMENT_PAYLOAD_CONTENT_TYPE, SCITT_STATEMENT_MEDIA_TYPE, COSE_HEADER_CWT_CLAIMS, CWT_CLAIM_ISS, CWT_CLAIM_SUB, ISS_MAX_LENGTH, } from './src/scitt-statement.js';
import { COSE_ALG_EDDSA, encodeDeterministicCbor8949, decodeDeterministicCbor8949, receiptActionCaid, } from './src/receipt-cose-encoding.js';
import { canonicalize } from './src/index.js';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const UTF8 = new TextEncoder();
const COSE_SIGN1_TAG_BYTE = 0xd2;
// --- deterministic fixtures --------------------------------------------------
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function ed25519FromSeed(seedHex) {
    const privateKey = crypto.createPrivateKey({
        key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, 'hex')]),
        format: 'der',
        type: 'pkcs8',
    });
    const publicKey = crypto.createPublicKey(privateKey);
    return {
        privateKey,
        publicKey,
        publicKeyBase64url: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    };
}
const STATEMENT_KEY = ed25519FromSeed('11'.repeat(32));
const RECEIPT_ISSUER = ed25519FromSeed('22'.repeat(32));
const OTHER_KEY = ed25519FromSeed('33'.repeat(32));
const ISS = 'ep:issuer:conformance';
const KID = 'ep:key:conformance:scitt-statement#1';
function makeReceipt(overrides = {}) {
    const payload = {
        receipt_id: 'tr_scitt_statement_v1',
        issuer: ISS,
        issued_at: '2026-08-16T00:00:00Z',
        quorum_threshold: 1,
        action: {
            action_type: 'payment.release.1',
            payment_instruction_id: 'pi_scitt_1',
            amount: '40000.00',
            currency: 'USD',
            beneficiary_account: 'sha256:12f641b8c481e23c00148de1bb73989601dfa6a5562f72b5e358fcda6e8eb674',
        },
        context: { organization: 'demo_treasury' },
        ...overrides,
    };
    const signature = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), RECEIPT_ISSUER.privateKey);
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: signature.toString('base64url') },
    };
}
const RECEIPT = makeReceipt();
function build(receipt = RECEIPT) {
    const result = buildEpScittSignedStatement(receipt, {
        statementPrivateKey: STATEMENT_KEY.privateKey,
        kid: KID,
        iss: ISS,
    });
    assert.equal(result.ok, true, `build refused: ${result.reason}`);
    return result.value;
}
const PINS = {
    statementPublicKeyBase64url: STATEMENT_KEY.publicKeyBase64url,
    receiptIssuerPublicKeyBase64url: RECEIPT_ISSUER.publicKeyBase64url,
};
function must(result, what) {
    assert.equal(result.ok, true, `${what}: ${result.reason}`);
    return result.value;
}
/**
 * Assemble a COSE_Sign1 from an arbitrary protected-header map, signing the real
 * RFC 9052 Section 4.4 Sig_structure. The forged statements therefore carry
 * genuinely valid signatures: only a profile rule can refuse them.
 */
function forge(protectedMap, payloadBytes, signingKey = STATEMENT_KEY.privateKey, unprotected = new Map()) {
    const protectedBytes = must(encodeDeterministicCbor8949(protectedMap), 'protected');
    const sigStruct = must(encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(0), payloadBytes]), 'Sig_structure');
    const signature = new Uint8Array(crypto.sign(null, sigStruct, signingKey));
    const body = must(encodeDeterministicCbor8949([protectedBytes, unprotected, payloadBytes, signature]), 'body');
    const out = new Uint8Array(body.length + 1);
    out[0] = COSE_SIGN1_TAG_BYTE;
    out.set(body, 1);
    return out;
}
function baseProtected() {
    return new Map([
        [1, COSE_ALG_EDDSA],
        [3, EP_STATEMENT_PAYLOAD_CONTENT_TYPE],
        [4, UTF8.encode(KID)],
    ]);
}
function withClaims(sub, iss = ISS) {
    const m = baseProtected();
    m.set(COSE_HEADER_CWT_CLAIMS, new Map([[CWT_CLAIM_ISS, iss], [CWT_CLAIM_SUB, sub]]));
    return m;
}
// ---------------------------------------------------------------------------
// Shape: the RFC 9943 Section 6 requirements are actually in the bytes
// ---------------------------------------------------------------------------
test('profile constant and payload content type', () => {
    assert.equal(EP_SCITT_STATEMENT_PROFILE, 'EP-SCITT-STATEMENT-v1');
    assert.equal(SCITT_STATEMENT_MEDIA_TYPE, 'application/scitt-statement+cose');
    assert.equal(EP_STATEMENT_PAYLOAD_CONTENT_TYPE, 'application/emilia-receipt+json');
});
test('statement is a tag-18 COSE_Sign1 with an empty unprotected bucket', () => {
    const built = build();
    assert.equal(built.statement[0], COSE_SIGN1_TAG_BYTE);
    const decoded = must(decodeDeterministicCbor8949(built.statement.subarray(1), { textKeysOnly: false }), 'decode');
    assert.equal(Array.isArray(decoded), true);
    const arr = decoded;
    assert.equal(arr.length, 4);
    assert.equal(arr[1] instanceof Map, true);
    // RFC 9943 Section 6.3: the unprotected header must be an empty map before the
    // statement can be included in a Statement Sequence.
    assert.equal(arr[1].size, 0);
    // Attached payload, not detached: the receipt's own signature covers it.
    assert.equal(arr[2] instanceof Uint8Array, true);
    assert.deepEqual(Buffer.from(arr[2]), Buffer.from(built.payload));
});
test('protected header carries exactly alg, content type, kid and CWT Claims', () => {
    const built = build();
    const headers = must(decodeDeterministicCbor8949(built.protectedHeaderBytes, { textKeysOnly: false }), 'headers');
    assert.deepEqual([...headers.keys()].sort((a, b) => a - b), [1, 3, 4, 15]);
    assert.equal(headers.get(1), COSE_ALG_EDDSA);
    assert.equal(headers.get(3), EP_STATEMENT_PAYLOAD_CONTENT_TYPE);
    assert.equal(Buffer.from(headers.get(4)).toString('utf8'), KID);
    // RFC 9943 Section 6: the CWT Claims value MUST include the Issuer Claim
    // (label 1) and the Subject Claim (label 2).
    const cwt = headers.get(COSE_HEADER_CWT_CLAIMS);
    assert.equal(cwt instanceof Map, true);
    assert.equal(cwt.get(CWT_CLAIM_ISS), ISS);
    assert.equal(cwt.get(CWT_CLAIM_SUB), built.sub);
});
test('sub is the action CAID, recomputable from the payload', () => {
    const built = build();
    const caid = must(receiptActionCaid(RECEIPT.payload.action), 'caid');
    assert.equal(built.sub, caid.caid);
    assert.match(built.sub, /^caid:1:payment\.release\.1:jcs-sha256:[A-Za-z0-9_-]+$/);
});
test('the payload IS the receipt canonical JSON, byte for byte', () => {
    const built = build();
    assert.equal(Buffer.from(built.payload).toString('utf8'), canonicalize(RECEIPT));
});
// ---------------------------------------------------------------------------
// Verify: the happy path, and the two signature legs kept separate
// ---------------------------------------------------------------------------
test('a conforming statement verifies with every check green', () => {
    const built = build();
    const result = verifyEpScittSignedStatement(built.statement, PINS);
    assert.equal(result.valid, true, result.reason);
    assert.deepEqual(result.checks, {
        deterministic_encoding: true,
        cose_structure: true,
        cwt_claims: true,
        statement_signature: true,
        payload_canonical: true,
        receipt_signature: true,
        sub_binding: true,
    });
    assert.equal(result.iss, ISS);
    assert.equal(result.sub, built.sub);
    assert.equal(result.kid, KID);
    assert.equal(result.payloadSha256, built.payloadSha256);
});
test('VERIFIED is never REGISTERED: the result always reports registered false', () => {
    const built = build();
    const ok = verifyEpScittSignedStatement(built.statement, PINS);
    const bad = verifyEpScittSignedStatement(new Uint8Array([1, 2, 3]), PINS);
    assert.equal(ok.valid, true);
    assert.equal(ok.registered, false);
    assert.equal(bad.valid, false);
    assert.equal(bad.registered, false);
});
test('statement signature and receipt signature are independent checks', () => {
    const built = build();
    // Wrong STATEMENT key: the receipt is untouched, but the statement leg fails
    // and the verifier stops there rather than reporting a receipt problem.
    const wrongStatementKey = verifyEpScittSignedStatement(built.statement, {
        ...PINS,
        statementPublicKeyBase64url: OTHER_KEY.publicKeyBase64url,
    });
    assert.equal(wrongStatementKey.valid, false);
    assert.equal(wrongStatementKey.reason, 'statement_signature_invalid');
    assert.equal(wrongStatementKey.checks.statement_signature, false);
    assert.equal(wrongStatementKey.checks.receipt_signature, false);
    // Wrong RECEIPT-ISSUER key: the statement leg is green, the receipt leg is
    // not. A relying party can tell exactly which attestation failed.
    const wrongReceiptKey = verifyEpScittSignedStatement(built.statement, {
        ...PINS,
        receiptIssuerPublicKeyBase64url: OTHER_KEY.publicKeyBase64url,
    });
    assert.equal(wrongReceiptKey.valid, false);
    assert.equal(wrongReceiptKey.reason, 'receipt_invalid');
    assert.equal(wrongReceiptKey.checks.statement_signature, true);
    assert.equal(wrongReceiptKey.checks.payload_canonical, true);
    assert.equal(wrongReceiptKey.checks.receipt_signature, false);
});
test('a valid statement over a receipt with a broken own-signature is refused', () => {
    // The statement signer is honest; the receipt inside it is not. Only the
    // second leg catches this.
    const broken = JSON.parse(JSON.stringify(RECEIPT));
    broken.signature.value = Buffer.from(broken.signature.value, 'base64url');
    broken.signature.value[0] ^= 0x01;
    broken.signature.value = Buffer.from(broken.signature.value).toString('base64url');
    const built = build(broken);
    const result = verifyEpScittSignedStatement(built.statement, PINS);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'receipt_invalid');
    assert.equal(result.checks.statement_signature, true);
});
// ---------------------------------------------------------------------------
// Named refusals: header rules
// ---------------------------------------------------------------------------
test('missing CWT Claims header is refused (RFC 9943 Section 6 makes it mandatory)', () => {
    const built = build();
    const statement = forge(baseProtected(), built.payload);
    const result = verifyEpScittSignedStatement(statement, PINS);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'cwt_claims_missing');
    assert.equal(result.checks.cwt_claims, false);
});
test('CWT Claims present but not a map is refused', () => {
    const built = build();
    const m = baseProtected();
    m.set(COSE_HEADER_CWT_CLAIMS, 'ep:issuer:conformance');
    const result = verifyEpScittSignedStatement(forge(m, built.payload), PINS);
    assert.equal(result.reason, 'cwt_claims_malformed');
});
test('CWT Claims missing iss or sub is refused with the specific reason', () => {
    const built = build();
    const noIss = baseProtected();
    noIss.set(COSE_HEADER_CWT_CLAIMS, new Map([[CWT_CLAIM_SUB, built.sub]]));
    assert.equal(verifyEpScittSignedStatement(forge(noIss, built.payload), PINS).reason, 'iss_missing');
    const noSub = baseProtected();
    noSub.set(COSE_HEADER_CWT_CLAIMS, new Map([[CWT_CLAIM_ISS, ISS]]));
    assert.equal(verifyEpScittSignedStatement(forge(noSub, built.payload), PINS).reason, 'sub_missing');
});
test('an unexpected claim inside CWT Claims is refused, not ignored', () => {
    const built = build();
    const m = withClaims(built.sub);
    m.get(COSE_HEADER_CWT_CLAIMS).set(6, 1755302400); // iat
    const result = verifyEpScittSignedStatement(forge(m, built.payload), PINS);
    assert.equal(result.reason, 'unexpected_cwt_claim');
});
test('an unexpected protected label is refused, not ignored', () => {
    const built = build();
    const m = withClaims(built.sub);
    m.set('ep.caid', built.sub);
    const result = verifyEpScittSignedStatement(forge(m, built.payload), PINS);
    assert.equal(result.reason, 'unexpected_protected_header');
});
test('crit is refused: this profile marks nothing critical', () => {
    const built = build();
    const m = withClaims(built.sub);
    m.set(2, [15]);
    assert.equal(verifyEpScittSignedStatement(forge(m, built.payload), PINS).reason, 'crit_unsupported');
});
test('alg confusion is refused on the signed header before any signature work', () => {
    const built = build();
    const m = withClaims(built.sub);
    m.set(1, -7); // ES256 declared, real Ed25519 signature attached
    const result = verifyEpScittSignedStatement(forge(m, built.payload), PINS);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'unsupported_statement_alg');
    assert.equal(result.checks.statement_signature, false);
});
test('content type mismatch is refused', () => {
    const built = build();
    const m = withClaims(built.sub);
    m.set(3, 'application/json');
    assert.equal(verifyEpScittSignedStatement(forge(m, built.payload), PINS).reason, 'content_type_mismatch');
});
test('kid is mandatory and honours a caller pin', () => {
    const built = build();
    const noKid = withClaims(built.sub);
    noKid.delete(4);
    assert.equal(verifyEpScittSignedStatement(forge(noKid, built.payload), PINS).reason, 'kid_missing');
    const pinned = verifyEpScittSignedStatement(built.statement, { ...PINS, expectedKid: 'ep:key:other#9' });
    assert.equal(pinned.reason, 'kid_mismatch');
    assert.equal(verifyEpScittSignedStatement(built.statement, { ...PINS, expectedKid: KID }).valid, true);
});
test('content in the unprotected bucket is refused', () => {
    const built = build();
    // Label 394 is where RFC 9943 Section 7 puts Receipts. A Signed Statement
    // carrying one is a TRANSPARENT Statement, a different artifact. Refusing here
    // stops the two from being silently interchanged.
    const statement = forge(withClaims(built.sub), built.payload, STATEMENT_KEY.privateKey, new Map([[394, [new Uint8Array([0xd2])]]]));
    const result = verifyEpScittSignedStatement(statement, PINS);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'unprotected_headers_present');
});
// ---------------------------------------------------------------------------
// Named refusals: claim binding
// ---------------------------------------------------------------------------
test('a sub naming a different action is refused (sub is recomputed, not trusted)', () => {
    const built = build();
    const other = must(receiptActionCaid({ action_type: 'payment.release.1', payment_instruction_id: 'pi_other' }), 'other caid').caid;
    const result = verifyEpScittSignedStatement(forge(withClaims(other), built.payload), PINS);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'sub_not_bound_to_payload');
    assert.equal(result.checks.receipt_signature, true);
    assert.equal(result.checks.sub_binding, false);
});
test('a malformed sub or iss is refused before any binding work', () => {
    const built = build();
    assert.equal(verifyEpScittSignedStatement(forge(withClaims('not-a-caid'), built.payload), PINS).reason, 'sub_malformed');
    assert.equal(verifyEpScittSignedStatement(forge(withClaims(built.sub, 'no-scheme'), built.payload), PINS).reason, 'iss_malformed');
    assert.equal(verifyEpScittSignedStatement(forge(withClaims(built.sub, 42), built.payload), PINS).reason, 'iss_malformed');
});
test('caller pins on iss and sub are enforced', () => {
    const built = build();
    assert.equal(verifyEpScittSignedStatement(built.statement, { ...PINS, expectedIss: 'ep:issuer:other' }).reason, 'iss_mismatch');
    assert.equal(verifyEpScittSignedStatement(built.statement, { ...PINS, expectedSub: 'caid:1:a.b.1:jcs-sha256:AA' }).reason, 'sub_mismatch');
    assert.equal(verifyEpScittSignedStatement(built.statement, { ...PINS, expectedIss: ISS, expectedSub: built.sub }).valid, true);
});
test('a tampered payload breaks the statement signature first', () => {
    const built = build();
    const tampered = new Uint8Array(built.statement);
    // Flip a byte inside the payload region; the statement signature covers it.
    const marker = Buffer.from(built.statement).indexOf(Buffer.from('demo_treasury', 'utf8'));
    assert.ok(marker > 0, 'payload marker present');
    tampered[marker] ^= 0x01;
    const result = verifyEpScittSignedStatement(tampered, PINS);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'statement_signature_invalid');
});
test('a non-canonical JSON payload is refused', () => {
    const built = build();
    // Same receipt, but serialized with whitespace: semantically equal, not
    // canonical. The receipt signature covers the CANONICAL bytes only.
    const loose = UTF8.encode(JSON.stringify(RECEIPT, null, 1));
    const statement = forge(withClaims(built.sub), loose);
    const result = verifyEpScittSignedStatement(statement, PINS);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'payload_not_canonical_json');
});
// ---------------------------------------------------------------------------
// Build-side refusals
// ---------------------------------------------------------------------------
test('build refuses bad inputs with named reasons and never throws', () => {
    const good = { statementPrivateKey: STATEMENT_KEY.privateKey, kid: KID, iss: ISS };
    const cases = [
        [null, good, 'invalid_receipt_document'],
        [{ payload: 'not-an-object' }, good, 'invalid_receipt_document'],
        [RECEIPT, { ...good, kid: '' }, 'invalid_kid'],
        [RECEIPT, { ...good, iss: 'no-scheme' }, 'invalid_iss'],
        [RECEIPT, { ...good, iss: '' }, 'invalid_iss'],
        [RECEIPT, { ...good, iss: 'ep:issuer:' + 'x'.repeat(ISS_MAX_LENGTH) }, 'invalid_iss'],
        [RECEIPT, { ...good, statementPrivateKey: OTHER_KEY.publicKey }, 'invalid_signing_key'],
        [{ payload: { action: { action_type: 'no-version' } } }, good, 'invalid_action_type'],
        [{ payload: {} }, good, 'invalid_action_object'],
    ];
    for (const [receipt, opts, reason] of cases) {
        const result = buildEpScittSignedStatement(receipt, opts);
        assert.equal(result.ok, false, `expected refusal ${reason}`);
        assert.equal(result.reason, reason);
    }
});
test('verify refuses hostile bytes with a reason instead of throwing', () => {
    const built = build();
    const hostile = [
        new Uint8Array(0),
        new Uint8Array([0xd2]),
        new Uint8Array([0xd2, 0xff]),
        new Uint8Array([0x84, 0x40, 0xa0, 0x40, 0x40]), // untagged COSE_Sign1
        built.statement.subarray(0, built.statement.length - 1), // truncated
    ];
    for (const bytes of hostile) {
        const result = verifyEpScittSignedStatement(bytes, PINS);
        assert.equal(result.valid, false);
        assert.equal(typeof result.reason, 'string');
        assert.equal(result.registered, false);
    }
    // A deterministic sweep of single-byte corruptions: every one refuses with a
    // named reason, none throws, none verifies.
    for (let i = 0; i < built.statement.length; i += 7) {
        const corrupt = new Uint8Array(built.statement);
        corrupt[i] ^= 0x80;
        const result = verifyEpScittSignedStatement(corrupt, PINS);
        if (result.valid)
            assert.fail(`corruption at byte ${i} verified`);
        assert.equal(typeof result.reason, 'string');
    }
    // Bad pinned keys refuse rather than throw.
    for (const key of ['', 'not base64url!!', 'AAAA']) {
        const result = verifyEpScittSignedStatement(built.statement, {
            ...PINS,
            statementPublicKeyBase64url: key,
        });
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'invalid_public_key');
    }
});
// ---------------------------------------------------------------------------
// Registration request description: built, never sent
// ---------------------------------------------------------------------------
test('registration request is described, not performed', () => {
    const built = build();
    const request = must(describeScittRegistrationRequest(built.statement, 'https://example.invalid/entries'), 'describe');
    assert.equal(request.method, 'POST');
    assert.equal(request.url, 'https://example.invalid/entries');
    assert.equal(request.headers['Content-Type'], SCITT_STATEMENT_MEDIA_TYPE);
    assert.equal(request.bodyBytes, built.statement.length);
    assert.equal(request.bodySha256, crypto.createHash('sha256').update(built.statement).digest('hex'));
    // Non-https and non-string endpoints refuse.
    assert.equal(describeScittRegistrationRequest(built.statement, 'http://x/y').ok, false);
    assert.equal(describeScittRegistrationRequest(built.statement, '').ok, false);
});
// ---------------------------------------------------------------------------
// The checked-in conformance vectors still behave exactly as declared
// ---------------------------------------------------------------------------
test('conformance/scitt-statement/vectors.json replays exactly', () => {
    const file = path.join(ROOT, 'conformance/scitt-statement/vectors.json');
    const suite = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(suite['@version'], 'EP-SCITT-STATEMENT-CONFORMANCE-v1');
    assert.equal(suite.profile, EP_SCITT_STATEMENT_PROFILE);
    assert.equal(suite.vectors.length, 5);
    const pins = {
        statementPublicKeyBase64url: suite.keys.statement_public_key_spki_base64url,
        receiptIssuerPublicKeyBase64url: suite.keys.receipt_issuer_public_key_spki_base64url,
    };
    for (const vector of suite.vectors) {
        const bytes = Uint8Array.from(Buffer.from(vector.statement_hex, 'hex'));
        const result = verifyEpScittSignedStatement(bytes, pins);
        assert.equal(result.valid, vector.expect.valid, `${vector.id}: ${result.reason}`);
        assert.equal(result.registered, false, `${vector.id}: registered must always be false`);
        if (vector.expect.reason)
            assert.equal(result.reason, vector.expect.reason, vector.id);
        if (vector.expect.iss)
            assert.equal(result.iss, vector.expect.iss, vector.id);
        if (vector.expect.sub)
            assert.equal(result.sub, vector.expect.sub, vector.id);
        for (const [name, want] of Object.entries(vector.expect.checks ?? {})) {
            assert.equal(result.checks[name], want, `${vector.id}: check ${name}`);
        }
    }
    // The pinned receipt and its canonical form are self-consistent, and the
    // pinned sub really is that receipt's action CAID.
    assert.equal(canonicalize(suite.receipt), suite.receipt_canonical_json);
    const caid = must(receiptActionCaid(suite.receipt.payload.action), 'caid');
    assert.equal(suite.expected.sub, caid.caid);
    assert.equal(suite.expected.payload_sha256, crypto.createHash('sha256').update(Buffer.from(suite.receipt_canonical_json, 'utf8')).digest('hex'));
});
