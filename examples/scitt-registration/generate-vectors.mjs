// SPDX-License-Identifier: Apache-2.0
//
// Generator for conformance/scitt-statement/vectors.json.
//
//   npx tsx examples/scitt-registration/generate-vectors.mjs          # print
//   npx tsx examples/scitt-registration/generate-vectors.mjs --write  # write
//
// Everything here is deterministic: fixed Ed25519 seeds, a fixed receipt, and
// deterministic CBOR (RFC 8949 Section 4.2.1). Re-running produces byte-identical
// output, so a diff in vectors.json means a behavior change, not noise.
//
// The four negative vectors are FORGED at the CBOR layer on purpose. Building
// them through the normal API would only prove the API refuses to emit them; a
// hostile party has no such constraint, so the vectors are constructed the way
// an attacker would construct them and then handed to the verifier.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildEpScittSignedStatement,
  verifyEpScittSignedStatement,
  EP_SCITT_STATEMENT_PROFILE,
  EP_STATEMENT_PAYLOAD_CONTENT_TYPE,
  COSE_HEADER_CWT_CLAIMS,
  CWT_CLAIM_ISS,
  CWT_CLAIM_SUB,
} from '../../packages/verify/scitt-statement.js';
import {
  encodeDeterministicCbor8949,
  receiptActionCaid,
  COSE_ALG_EDDSA,
} from '../../packages/verify/dist/receipt-cose-encoding.js';
import { canonicalize } from '../../packages/verify/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT = path.join(ROOT, 'conformance/scitt-statement/vectors.json');

const COSE_SIGN1_TAG_BYTE = 0xd2;
const UTF8 = new TextEncoder();

// --- deterministic Ed25519 keys from fixed seeds -----------------------------

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function ed25519FromSeed(seedHex) {
  const seed = Buffer.from(seedHex, 'hex');
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
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

// Test-only seeds. Fixed and public on purpose; they secure nothing.
export const STATEMENT_SEED = '11'.repeat(32);
export const RECEIPT_ISSUER_SEED = '22'.repeat(32);

export const ISS = 'ep:issuer:conformance';
export const KID = 'ep:key:conformance:scitt-statement#1';

// --- the fixture receipt (EP-RECEIPT-v1) -------------------------------------

export function buildFixtureReceipt(receiptIssuer) {
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
  };
  const canonical = canonicalize(payload);
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), receiptIssuer.privateKey);
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signature.toString('base64url') },
  };
}

// --- forging helpers ---------------------------------------------------------

function must(result, what) {
  if (!result.ok) throw new Error(`${what}: ${result.reason}`);
  return result.value;
}

/**
 * Assemble a COSE_Sign1 from an arbitrary protected-header map, signing over the
 * RFC 9052 Section 4.4 Sig_structure so the signature is genuinely valid for
 * whatever headers are supplied. That is what makes these vectors adversarial:
 * only the profile rule catches them, never a broken signature.
 */
function forgeStatement(protectedMap, payloadBytes, signingKey, { unprotected = new Map() } = {}) {
  const protectedBytes = must(encodeDeterministicCbor8949(protectedMap), 'protected header');
  const sigStruct = must(
    encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(0), payloadBytes]),
    'Sig_structure',
  );
  const signature = new Uint8Array(crypto.sign(null, sigStruct, signingKey));
  const body = must(
    encodeDeterministicCbor8949([protectedBytes, unprotected, payloadBytes, signature]),
    'COSE_Sign1 body',
  );
  const out = new Uint8Array(body.length + 1);
  out[0] = COSE_SIGN1_TAG_BYTE;
  out.set(body, 1);
  return out;
}

const hex = (bytes) => Buffer.from(bytes).toString('hex');

// --- build the suite ---------------------------------------------------------

export function buildVectorSuite() {
  const statementKey = ed25519FromSeed(STATEMENT_SEED);
  const receiptIssuer = ed25519FromSeed(RECEIPT_ISSUER_SEED);
  const receipt = buildFixtureReceipt(receiptIssuer);

  const built = must(
    buildEpScittSignedStatement(receipt, {
      statementPrivateKey: statementKey.privateKey,
      kid: KID,
      iss: ISS,
    }),
    'build signed statement',
  );

  const payloadBytes = built.payload;

  // A CAID for a DIFFERENT action, so `sub` is well-formed and self-consistent
  // but does not describe the carried payload.
  const otherCaid = must(
    receiptActionCaid({ action_type: 'payment.release.1', payment_instruction_id: 'pi_other' }),
    'other caid',
  ).caid;

  /** @returns {Map<unknown, unknown>} */
  const baseProtected = () => new Map(/** @type {Array<[unknown, unknown]>} */ ([
    [1, COSE_ALG_EDDSA],
    [3, EP_STATEMENT_PAYLOAD_CONTENT_TYPE],
    [4, UTF8.encode(KID)],
  ]));

  /** @returns {Map<unknown, unknown>} */
  const withClaims = (sub, iss = ISS) => {
    const m = baseProtected();
    m.set(COSE_HEADER_CWT_CLAIMS, new Map(/** @type {Array<[unknown, unknown]>} */ (
      [[CWT_CLAIM_ISS, iss], [CWT_CLAIM_SUB, sub]]
    )));
    return m;
  };

  // 1. valid
  const valid = built.statement;

  // 2. missing CWT claims: RFC 9943 Section 6 makes label 15 mandatory. This is
  //    exactly the shape of the sibling EP-COSE-ENCODING-v0.1 transport
  //    envelope, which is why that envelope is not a Signed Statement.
  const missingClaims = forgeStatement(baseProtected(), payloadBytes, statementKey.privateKey);

  // 3. wrong sub: well-formed CAID for a different action.
  const wrongSub = forgeStatement(withClaims(otherCaid), payloadBytes, statementKey.privateKey);

  // 4. tampered payload: the receipt's approver field is edited and the
  //    statement is re-signed by the statement key. The statement signature is
  //    valid; the RECEIPT signature is not.
  const tampered = JSON.parse(Buffer.from(payloadBytes).toString('utf8'));
  tampered.payload.context.organization = 'attacker_treasury';
  const tamperedBytes = UTF8.encode(canonicalize(tampered));
  const tamperedCaid = must(receiptActionCaid(tampered.payload.action), 'tampered caid').caid;
  const tamperedStatement = forgeStatement(
    withClaims(tamperedCaid),
    tamperedBytes,
    statementKey.privateKey,
  );

  // 5. alg confusion: the signed `alg` says ES256 (-7) while the signature is a
  //    real Ed25519 signature made by the statement key. A verifier that
  //    dispatched on the key type instead of the signed header would accept it.
  const algConfusion = forgeStatement(
    (() => { const m = withClaims(built.sub); m.set(1, -7); return m; })(),
    payloadBytes,
    statementKey.privateKey,
  );

  const cases = [
    {
      id: 'valid-signed-statement',
      description:
        'Conforming EP-SCITT-STATEMENT-v1 Signed Statement: protected header carries alg, content type, kid, and the RFC 9597 label-15 CWT Claims map with iss and sub.',
      statement_hex: hex(valid),
      expect: {
        valid: true,
        registered: false,
        iss: built.iss,
        sub: built.sub,
        checks: {
          deterministic_encoding: true,
          cose_structure: true,
          cwt_claims: true,
          statement_signature: true,
          payload_canonical: true,
          receipt_signature: true,
          sub_binding: true,
        },
      },
    },
    {
      id: 'missing-cwt-claims',
      description:
        'Protected header omits the CWT Claims header parameter (label 15). RFC 9943 Section 6 makes it mandatory for a Signed Statement.',
      statement_hex: hex(missingClaims),
      expect: { valid: false, reason: 'cwt_claims_missing', registered: false },
    },
    {
      id: 'wrong-sub',
      description:
        'CWT sub is a well-formed CAID for a DIFFERENT action object, so it does not recompute from the carried payload.',
      statement_hex: hex(wrongSub),
      expect: { valid: false, reason: 'sub_not_bound_to_payload', registered: false },
    },
    {
      id: 'tampered-payload',
      description:
        'Receipt payload edited after issuance and the statement re-signed by the statement key. The statement signature verifies; the receipt signature does not. The two checks are reported separately.',
      statement_hex: hex(tamperedStatement),
      expect: {
        valid: false,
        reason: 'receipt_invalid',
        registered: false,
        checks: { statement_signature: true, receipt_signature: false },
      },
    },
    {
      id: 'alg-confusion',
      description:
        'Signed alg says ES256 (-7) while the signature is a real Ed25519 signature by the pinned statement key. Refused on the signed header before any signature work.',
      statement_hex: hex(algConfusion),
      expect: { valid: false, reason: 'unsupported_statement_alg', registered: false },
    },
  ];

  return {
    '@version': 'EP-SCITT-STATEMENT-CONFORMANCE-v1',
    profile: EP_SCITT_STATEMENT_PROFILE,
    specifications: {
      signed_statement: 'RFC 9943 Section 6 and Section 6.1 Figure 3',
      cwt_claims_header: 'RFC 9597 Section 2 (label 15)',
      cose_sign1: 'RFC 9052 Sections 3, 4.2 and 4.4',
      deterministic_encoding: 'RFC 8949 Section 4.2.1',
    },
    claim_boundary: {
      proves:
        'These bytes are a COSE_Sign1 whose protected header satisfies the RFC 9943 Section 6 Signed Statement requirements, and the accept/refuse decision for each vector under the pinned keys.',
      does_not_prove:
        'Registration. No Transparency Service has accepted any statement in this file. VERIFIED (signatures check out) is not REGISTERED (accepted into a verifiable data structure with a Receipt returned) and is not ACCEPTED (trusted under a pinned root).',
    },
    keys: {
      statement_public_key_spki_base64url: statementKey.publicKeyBase64url,
      receipt_issuer_public_key_spki_base64url: receiptIssuer.publicKeyBase64url,
      _note: 'Ed25519 keys derived from the fixed public seeds in examples/scitt-registration/generate-vectors.mjs. Test material only.',
    },
    receipt,
    receipt_canonical_json: canonicalize(receipt),
    expected: {
      iss: built.iss,
      sub: built.sub,
      caid: built.caid,
      kid: KID,
      payload_sha256: built.payloadSha256,
      payload_bytes: built.payload.length,
      protected_header_hex: hex(built.protectedHeaderBytes),
    },
    vectors: cases,
  };
}

// --- self-check + emit -------------------------------------------------------

export function selfCheck(suite) {
  const failures = [];
  for (const vector of suite.vectors) {
    const result = verifyEpScittSignedStatement(
      Uint8Array.from(Buffer.from(vector.statement_hex, 'hex')),
      {
        statementPublicKeyBase64url: suite.keys.statement_public_key_spki_base64url,
        receiptIssuerPublicKeyBase64url: suite.keys.receipt_issuer_public_key_spki_base64url,
      },
    );
    if (result.valid !== vector.expect.valid) {
      failures.push(`${vector.id}: valid=${result.valid} expected ${vector.expect.valid} (${result.reason ?? ''})`);
      continue;
    }
    if (vector.expect.reason && result.reason !== vector.expect.reason) {
      failures.push(`${vector.id}: reason=${result.reason} expected ${vector.expect.reason}`);
    }
    for (const [name, want] of Object.entries(vector.expect.checks ?? {})) {
      if (result.checks[name] !== want) {
        failures.push(`${vector.id}: check ${name}=${result.checks[name]} expected ${want}`);
      }
    }
  }
  return failures;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const suite = buildVectorSuite();
  const failures = selfCheck(suite);
  if (failures.length) {
    console.error('SELF-CHECK FAILED');
    for (const f of failures) console.error('  ' + f);
    process.exit(1);
  }
  const json = JSON.stringify(suite, null, 2) + '\n';
  if (process.argv.includes('--write')) {
    fs.mkdirSync(path.dirname(OUT), { recursive: true });
    fs.writeFileSync(OUT, json);
    console.log(`self-check PASS (${suite.vectors.length} vectors); wrote ${path.relative(ROOT, OUT)}`);
  } else {
    console.log(json);
  }
}
