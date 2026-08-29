// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * SCITT Signed Statement identity separation.
 *
 * Reproduces one RFC 9943-shaped P-256 signing input with two mathematically
 * equivalent, independently valid ECDSA signatures, then separately verifies
 * an EP-SCITT-STATEMENT-v1 fixture with the shipped fail-closed verifier. The
 * profile keeps exact envelope, signed input, and EP authorization identity
 * separate without treating generic ES256 evidence as EP profile evidence.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildEpScittSignedStatement, deriveScittStatementIdentityLayers, verifyEpScittSignedStatement, } from '../../../packages/verify/scitt-statement.js';
import { encodeDeterministicCbor8949, } from '../../../packages/verify/dist/receipt-cose-encoding.js';
import { canonicalize } from '../../../packages/verify/index.js';
export const PROFILE = 'EP-SCITT-STATEMENT-IDENTITY-v0.1';
const REPORT_VERSION = 'EP-SCITT-STATEMENT-IDENTITY-REFERENCE-REPORT-v1';
const COSE_SIGN1_TAG = 0xd2;
const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');
const VECTORS_PATH = resolve(HERE, 'vectors.reference.json');
const UTF8 = new TextEncoder();
function readPinnedP256Vector() {
    const vector = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));
    assert.equal(vector['@version'], 'EP-SCITT-STATEMENT-IDENTITY-VECTORS-v1');
    assert.equal(vector.profile, PROFILE);
    return vector;
}
function must(result, label) {
    assert.equal(result.ok, true, `${label}: ${result.reason}`);
    return result.value;
}
function taggedCoseSign1(protectedBytes, payload, signature) {
    const body = must(encodeDeterministicCbor8949([protectedBytes, new Map(), payload, signature]), 'COSE_Sign1 body');
    const statement = new Uint8Array(body.length + 1);
    statement[0] = COSE_SIGN1_TAG;
    statement.set(body, 1);
    return statement;
}
function sigStructure(protectedBytes, payload) {
    return must(encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(), payload]), 'Sig_structure');
}
function identity(statement) {
    return must(deriveScittStatementIdentityLayers(statement), 'statement identity');
}
function classifyPair(a, b) {
    const left = identity(a);
    const right = identity(b);
    if (left.signing_input_digest === right.signing_input_digest
        && left.statement_entry_digest !== right.statement_entry_digest) {
        return 'same_signing_input_different_envelope';
    }
    if (left.signing_input_digest !== right.signing_input_digest)
        return 'different_signing_input';
    return 'same_envelope';
}
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function ed25519FromSeed(seedByte) {
    const privateKey = crypto.createPrivateKey({
        key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seedByte.repeat(32), 'hex')]),
        format: 'der',
        type: 'pkcs8',
    });
    const publicKey = crypto.createPublicKey(privateKey);
    return {
        privateKey,
        publicKeyBase64url: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
function buildEpFixture() {
    const receiptIssuer = ed25519FromSeed('22');
    const statementIssuer = ed25519FromSeed('11');
    const payload = {
        receipt_id: 'tr_scitt_identity_v01',
        issuer: 'ep:issuer:scitt-identity-conformance',
        issued_at: '2026-08-24T00:00:00Z',
        quorum_threshold: 1,
        action: {
            action_type: 'payment.release.1',
            payment_instruction_id: 'pi_scitt_identity_1',
            amount: '1250.00',
            currency: 'USD',
            beneficiary_account: 'sha256:12f641b8c481e23c00148de1bb73989601dfa6a5562f72b5e358fcda6e8eb674',
        },
        context: { organization: 'scitt_identity_conformance' },
    };
    const receiptSignature = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), receiptIssuer.privateKey);
    const receipt = {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: receiptSignature.toString('base64url') },
    };
    const built = must(buildEpScittSignedStatement(receipt, {
        statementPrivateKey: statementIssuer.privateKey,
        kid: 'ep:key:scitt-identity-conformance#1',
        iss: 'ep:issuer:scitt-identity-conformance',
    }), 'EP Signed Statement');
    const verified = verifyEpScittSignedStatement(built.statement, {
        statementPublicKeyBase64url: statementIssuer.publicKeyBase64url,
        receiptIssuerPublicKeyBase64url: receiptIssuer.publicKeyBase64url,
    });
    return {
        payload,
        built,
        verified,
        pins: {
            statementPublicKeyBase64url: statementIssuer.publicKeyBase64url,
            receiptIssuerPublicKeyBase64url: receiptIssuer.publicKeyBase64url,
        },
    };
}
export function runProfile() {
    const vector = readPinnedP256Vector();
    const P256_PUBLIC_JWK = Object.freeze(vector.fixture.public_jwk);
    const P256_SIGNATURE_A = Buffer.from(vector.fixture.signature_a_base64url, 'base64url');
    const P256_SIGNATURE_B = Buffer.from(vector.fixture.signature_b_base64url, 'base64url');
    const p256CwtClaims = new Map([
        [1, 'https://issuer.example/scitt'],
        [2, 'urn:example:scitt-identity-p256:1'],
    ]);
    const p256Protected = new Map([
        [1, -7],
        [3, 'application/example+json'],
        [4, UTF8.encode('scitt-identity-p256-1')],
        [15, p256CwtClaims],
    ]);
    const protectedBytes = must(encodeDeterministicCbor8949(p256Protected), 'P-256 protected header');
    assert.equal(Buffer.from(protectedBytes).toString('base64url'), vector.fixture.protected_bstr_base64url, 'pinned protected header drifted');
    const payload = Buffer.from(vector.fixture.payload_bstr_base64url, 'base64url');
    const signingInput = sigStructure(protectedBytes, payload);
    assert.equal(Buffer.from(signingInput).toString('base64url'), vector.fixture.sig_structure_base64url, 'pinned Sig_structure drifted');
    const publicKey = crypto.createPublicKey({ key: P256_PUBLIC_JWK, format: 'jwk' });
    const statementA = taggedCoseSign1(protectedBytes, payload, P256_SIGNATURE_A);
    const statementB = taggedCoseSign1(protectedBytes, payload, P256_SIGNATURE_B);
    assert.equal(Buffer.from(statementA).toString('base64url'), vector.fixture.cose_sign1_a_base64url, 'pinned COSE_Sign1 A drifted');
    assert.equal(Buffer.from(statementB).toString('base64url'), vector.fixture.cose_sign1_b_base64url, 'pinned COSE_Sign1 B drifted');
    const identityA = identity(statementA);
    const identityB = identity(statementB);
    const verifiesA = crypto.verify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_A);
    const verifiesB = crypto.verify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_B);
    assert.equal(verifiesA, vector.expected.signature_a_valid);
    assert.equal(verifiesB, vector.expected.signature_b_valid);
    assert.equal(identityA.statement_entry_digest, vector.expected.statement_entry_digest_a);
    assert.equal(identityB.statement_entry_digest, vector.expected.statement_entry_digest_b);
    assert.equal(identityA.signing_input_digest, vector.expected.signing_input_digest);
    assert.equal(classifyPair(statementA, statementB), vector.expected.classification);
    const changedPayload = UTF8.encode('{"claim":"substituted payload","sequence":1}');
    const payloadTwin = taggedCoseSign1(protectedBytes, changedPayload, P256_SIGNATURE_A);
    const changedProtected = must(encodeDeterministicCbor8949(new Map([
        [1, -7],
        [3, 'application/example+json'],
        [4, UTF8.encode('substituted-key-id')],
    ])), 'substituted protected header');
    const protectedTwin = taggedCoseSign1(changedProtected, payload, P256_SIGNATURE_A);
    const malformed = deriveScittStatementIdentityLayers(new Uint8Array([0xd2, 0x01]));
    const ep = buildEpFixture();
    const p256EpProfileAttempt = verifyEpScittSignedStatement(statementA, {
        statementPublicKeyBase64url: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        receiptIssuerPublicKeyBase64url: ep.pins.receiptIssuerPublicKeyBase64url,
    });
    const cases = [
        {
            id: 'P256-SIGNATURE-A-VERIFIES', category: 'positive', passed: verifiesA,
            expected: 'the first static P-256 signature verifies over the pinned Sig_structure',
            observed: { verified: verifiesA },
        },
        {
            id: 'P256-SIGNATURE-B-VERIFIES', category: 'positive', passed: verifiesB,
            expected: 'the mathematically equivalent P-256 signature verifies over the same Sig_structure',
            observed: { verified: verifiesB },
        },
        {
            id: 'P256-RFC9943-CWT-CLAIMS-PRESENT', category: 'positive',
            passed: p256Protected.has(15)
                && p256CwtClaims.has(1)
                && p256CwtClaims.has(2),
            expected: 'the generic ES256 Signed Statement carries protected CWT iss and sub claims',
            observed: {
                cwt_header_label: 15,
                iss: String(p256CwtClaims.get(1)),
                sub: String(p256CwtClaims.get(2)),
            },
        },
        {
            id: 'P256-PAIR-IS-NOT-EP-PROFILE', category: 'boundary',
            passed: p256EpProfileAttempt.valid === false
                && p256EpProfileAttempt.reason === 'unsupported_statement_alg',
            expected: 'the shipped EP verifier refuses generic ES256 rather than laundering it into EP profile evidence',
            observed: {
                ep_profile_valid: p256EpProfileAttempt.valid,
                refusal: p256EpProfileAttempt.reason ?? 'missing',
            },
        },
        {
            id: 'EXACT-ENTRY-IDENTITY-SEPARATES-ENVELOPES', category: 'boundary',
            passed: identityA.statement_entry_digest !== identityB.statement_entry_digest,
            expected: 'two valid envelope encodings produce different exact entry digests',
            observed: {
                entry_a: identityA.statement_entry_digest,
                entry_b: identityB.statement_entry_digest,
            },
        },
        {
            id: 'SIGNING-INPUT-IDENTITY-IS-STABLE', category: 'boundary',
            passed: identityA.signing_input_digest === identityB.signing_input_digest,
            expected: 'signature-only re-encoding preserves the signing-input digest',
            observed: { signing_input_digest: identityA.signing_input_digest },
        },
        {
            id: 'PAYLOAD-SUBSTITUTION-CHANGES-SIGNING-INPUT', category: 'hostile',
            passed: identityA.signing_input_digest !== identity(payloadTwin).signing_input_digest
                && crypto.verify('sha256', sigStructure(protectedBytes, changedPayload), { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_A) === false,
            expected: 'a payload substitution changes the signing input and invalidates the old signature',
            observed: { refusal: 'different_signing_input' },
        },
        {
            id: 'PROTECTED-HEADER-SUBSTITUTION-CHANGES-SIGNING-INPUT', category: 'hostile',
            passed: identityA.signing_input_digest !== identity(protectedTwin).signing_input_digest
                && crypto.verify('sha256', sigStructure(changedProtected, payload), { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_A) === false,
            expected: 'a protected-header substitution changes the signing input and invalidates the old signature',
            observed: { refusal: 'different_signing_input' },
        },
        {
            id: 'FALSE-TAMPERING-REASON-REFUSED', category: 'boundary',
            passed: classifyPair(statementA, statementB) === 'same_signing_input_different_envelope',
            expected: 'a valid signature-only difference is classified as a distinct envelope, not payload tampering',
            observed: { classification: classifyPair(statementA, statementB) },
        },
        {
            id: 'MALFORMED-COSE-REFUSED', category: 'hostile',
            passed: malformed.ok === false && malformed.reason === 'cose_structure_invalid',
            expected: 'malformed tagged input refuses with a named reason',
            observed: { reason: malformed.ok ? 'accepted' : malformed.reason },
        },
        {
            id: 'EP-AUTHORIZATION-PAYLOAD-IDENTITY-VERIFIES', category: 'positive',
            passed: ep.verified.valid === true
                && ep.verified.identity?.authorization_payload_digest
                    === `sha256:${crypto.hash('sha256', canonicalize(ep.payload), 'hex')}`,
            expected: 'the verified EP statement reports the canonical authorization payload digest',
            observed: {
                verified: ep.verified.valid,
                authorization_payload_digest: ep.verified.identity?.authorization_payload_digest ?? 'missing',
            },
        },
        {
            id: 'ENTRY-DIGEST-CANNOT-SUBSTITUTE-FOR-AUTHORIZATION', category: 'boundary',
            passed: ep.verified.identity?.statement_entry_digest
                !== ep.verified.identity?.authorization_payload_digest,
            expected: 'exact log-entry identity remains distinct from EP authorization identity',
            observed: {
                statement_entry_digest: ep.verified.identity?.statement_entry_digest ?? 'missing',
                authorization_payload_digest: ep.verified.identity?.authorization_payload_digest ?? 'missing',
            },
        },
    ];
    const passed = cases.every((entry) => entry.passed);
    const reportCore = {
        '@version': REPORT_VERSION,
        profile: PROFILE,
        passed,
        cases,
        summary: { total: cases.length, passed: cases.filter((entry) => entry.passed).length },
        claim_boundary: [
            'The P-256 pair is a generic RFC 9943 Signed Statement fixture, not an EP-SCITT-STATEMENT-v1 fixture; its algorithm-level verification cannot establish EP authorization.',
            'The exact COSE_Sign1 envelope digest identifies one envelope or registration entry.',
            'The Sig_structure digest identifies the bytes presented to the signature algorithm.',
            'The EP authorization payload digest identifies the canonical authorization claim under separately pinned issuer and profile checks.',
            'None of these digests alone proves authorization, transparency registration, or source-population completeness.',
        ],
    };
    return {
        ...reportCore,
        results_digest: `sha256:${crypto.hash('sha256', JSON.stringify(reportCore), 'hex')}`,
    };
}
export function buildReferenceReport() {
    return runProfile();
}
function main() {
    const report = runProfile();
    const args = new Set(process.argv.slice(2));
    if (args.has('--write')) {
        writeFileSync(REFERENCE_PATH, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    }
    if (args.has('--check')) {
        const reference = JSON.parse(readFileSync(REFERENCE_PATH, 'utf8'));
        assert.deepEqual(report, reference, 'reference report drifted; review and re-pin deliberately');
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.passed)
        process.exitCode = 1;
}
if (process.argv[1]
    && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
    main();
}
