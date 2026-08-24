// SPDX-License-Identifier: Apache-2.0
/**
 * SCITT Signed Statement identity separation.
 *
 * Reproduces one P-256 signing input with two mathematically equivalent,
 * independently valid ECDSA signatures. The profile keeps three identities
 * separate: exact envelope entry, signed input, and EP authorization payload.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildEpScittSignedStatement,
  deriveScittStatementIdentityLayers,
  verifyEpScittSignedStatement,
} from '../../../packages/verify/scitt-statement.js';
import {
  encodeDeterministicCbor8949,
} from '../../../packages/verify/dist/receipt-cose-encoding.js';
import { canonicalize } from '../../../packages/verify/index.js';

export const PROFILE = 'EP-SCITT-STATEMENT-IDENTITY-v0.1';
const REPORT_VERSION = 'EP-SCITT-STATEMENT-IDENTITY-REFERENCE-REPORT-v1';
const COSE_SIGN1_TAG = 0xd2;
const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');
const UTF8 = new TextEncoder();

const P256_PUBLIC_JWK = Object.freeze({
  kty: 'EC',
  x: 'ukQY2N41rXeZh4X86CJQMrUuJulujnV2SY7Gr6dtvuM',
  y: 'MegNL7yc2_EHydyOVuNIwJoYX4Fva686EseQr475p0E',
  crv: 'P-256',
});
const P256_SIGNATURE_A = Buffer.from(
  'YtBJi0iCj0mpfA7XdmW1viyF3F2efFAVIphq9ZLEGBzuXTcgQSSYPHKBCfHUQvgBXzGQ0AdO2kLhgtSNnr1hYA',
  'base64url',
);
const P256_SIGNATURE_B = Buffer.from(
  'YtBJi0iCj0mpfA7XdmW1viyF3F2efFAVIphq9ZLEGBwRosjevttnxI1-9g4rvQf-XbVp3Z_IxEISNvY1XaXD8Q',
  'base64url',
);

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type CaseResult = {
  id: string;
  category: 'positive' | 'hostile' | 'boundary';
  passed: boolean;
  expected: string;
  observed: Record<string, Json>;
};

function must<T>(result: { ok: boolean; value?: T; reason?: string }, label: string): T {
  assert.equal(result.ok, true, `${label}: ${result.reason}`);
  return result.value as T;
}

function taggedCoseSign1(
  protectedBytes: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  const body = must<Uint8Array>(
    encodeDeterministicCbor8949([protectedBytes, new Map(), payload, signature]),
    'COSE_Sign1 body',
  );
  const statement = new Uint8Array(body.length + 1);
  statement[0] = COSE_SIGN1_TAG;
  statement.set(body, 1);
  return statement;
}

function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  return must(
    encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(), payload]),
    'Sig_structure',
  );
}

function identity(statement: Uint8Array) {
  return must(deriveScittStatementIdentityLayers(statement), 'statement identity');
}

function classifyPair(a: Uint8Array, b: Uint8Array): string {
  const left = identity(a);
  const right = identity(b);
  if (left.signing_input_digest === right.signing_input_digest
      && left.statement_entry_digest !== right.statement_entry_digest) {
    return 'same_signing_input_different_envelope';
  }
  if (left.signing_input_digest !== right.signing_input_digest) return 'different_signing_input';
  return 'same_envelope';
}

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function ed25519FromSeed(seedByte: string) {
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
  const receiptSignature = crypto.sign(
    null,
    Buffer.from(canonicalize(payload), 'utf8'),
    receiptIssuer.privateKey,
  );
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
  return { payload, built, verified };
}

export function runProfile() {
  const protectedBytes = must<Uint8Array>(encodeDeterministicCbor8949(new Map<unknown, unknown>([
    [1, -7],
    [3, 'application/example+json'],
    [4, UTF8.encode('scitt-identity-p256-1')],
  ])), 'P-256 protected header');
  const payload = UTF8.encode('{"claim":"one signing input, two valid envelopes","sequence":1}');
  const signingInput = sigStructure(protectedBytes, payload);
  const publicKey = crypto.createPublicKey({ key: P256_PUBLIC_JWK, format: 'jwk' });
  const statementA = taggedCoseSign1(protectedBytes, payload, P256_SIGNATURE_A);
  const statementB = taggedCoseSign1(protectedBytes, payload, P256_SIGNATURE_B);
  const identityA = identity(statementA);
  const identityB = identity(statementB);
  const verifiesA = crypto.verify(
    'sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_A,
  );
  const verifiesB = crypto.verify(
    'sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_B,
  );

  const changedPayload = UTF8.encode('{"claim":"substituted payload","sequence":1}');
  const payloadTwin = taggedCoseSign1(protectedBytes, changedPayload, P256_SIGNATURE_A);
  const changedProtected = must<Uint8Array>(encodeDeterministicCbor8949(new Map<unknown, unknown>([
    [1, -7],
    [3, 'application/example+json'],
    [4, UTF8.encode('substituted-key-id')],
  ])), 'substituted protected header');
  const protectedTwin = taggedCoseSign1(changedProtected, payload, P256_SIGNATURE_A);
  const malformed = deriveScittStatementIdentityLayers(new Uint8Array([0xd2, 0x01]));
  const ep = buildEpFixture();

  const cases: CaseResult[] = [
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
        && crypto.verify(
          'sha256', sigStructure(protectedBytes, changedPayload),
          { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_A,
        ) === false,
      expected: 'a payload substitution changes the signing input and invalidates the old signature',
      observed: { refusal: 'different_signing_input' },
    },
    {
      id: 'PROTECTED-HEADER-SUBSTITUTION-CHANGES-SIGNING-INPUT', category: 'hostile',
      passed: identityA.signing_input_digest !== identity(protectedTwin).signing_input_digest
        && crypto.verify(
          'sha256', sigStructure(changedProtected, payload),
          { key: publicKey, dsaEncoding: 'ieee-p1363' }, P256_SIGNATURE_A,
        ) === false,
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
        authorization_payload_digest:
          ep.verified.identity?.authorization_payload_digest ?? 'missing',
      },
    },
    {
      id: 'ENTRY-DIGEST-CANNOT-SUBSTITUTE-FOR-AUTHORIZATION', category: 'boundary',
      passed: ep.verified.identity?.statement_entry_digest
        !== ep.verified.identity?.authorization_payload_digest,
      expected: 'exact log-entry identity remains distinct from EP authorization identity',
      observed: {
        statement_entry_digest: ep.verified.identity?.statement_entry_digest ?? 'missing',
        authorization_payload_digest:
          ep.verified.identity?.authorization_payload_digest ?? 'missing',
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
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
