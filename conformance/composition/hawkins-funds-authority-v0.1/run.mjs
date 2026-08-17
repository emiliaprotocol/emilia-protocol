// SPDX-License-Identifier: Apache-2.0
/**
 * Funds-authority profile for Check 8 of
 * draft-hawkins-scitt-attested-agent-payment-01, as a runnable composition
 * vector.
 *
 * Check 8 (Section 4 of that draft) requires a Payment Executor to establish,
 * "by a rail- or deployment-defined procedure, that the scope's Issuer may
 * authorize spending from the account the payment draws on", and it states
 * that the draft "does not define the funds-authority procedure" but that a
 * conforming executor MUST have one, "and its absence is failure of this
 * check, not a permission".
 *
 * This vector instantiates that deliberately unfilled slot with an EMILIA
 * authorization receipt: a human principal's EP-RECEIPT-v1 whose exact action
 * material names the Issuer identity, the account, and the scope digest of
 * the Authorization Scope being issued. The executor verifies that receipt
 * OFFLINE, under keys it pinned out of band for the account's principal,
 * before treating the funds-authority clause of Check 8 as established.
 *
 * Composition rule (the repo's standing seam discipline): the two legs stay
 * in their own trust boundaries and join by the scope digest.
 *
 *   Hawkins leg   the Authorization Scope is a CBOR map in the deterministic
 *                 encoding of RFC 8949 Section 4.2.1; the scope digest is
 *                 SHA-256 over exactly those bytes. Encoded here with the
 *                 repo's real deterministic encoder
 *                 (packages/verify receipt-cose-encoding), not a new one.
 *   EMILIA leg    the funds-authority receipt is verified by the repo's real
 *                 offline receipt verifier (packages/verify verifyReceipt),
 *                 with expiry read from the receipt payload and revocation
 *                 checked against presented EP-REVOCATION-v1 statements under
 *                 pinned revoker keys.
 *
 * Neither leg ingests the other's evidence: the EP verifier never parses the
 * scope, and the scope encoding never embeds the receipt. Equality of the
 * scope digest string is the entire join.
 *
 * Claim boundary: this is OUR proposed instantiation of a slot the Hawkins
 * draft leaves rail- or deployment-defined. That draft does not reference
 * EMILIA, and nothing here claims endorsement, adoption, or that this is the
 * procedure his rail uses. Scope of this vector: the funds-authority clause
 * of Check 8 only. Receipt availability from the Transparency Service (the
 * other clause of Check 8) and Checks 1-7 and 9 are out of scope here.
 *
 * Determinism: fixed Ed25519 seeds, fixed timestamps, fixed fixture bytes.
 * Every conforming run produces the identical report digest.
 *
 *   node conformance/composition/hawkins-funds-authority-v0.1/run.mjs
 *   node conformance/composition/hawkins-funds-authority-v0.1/run.mjs --emit
 *   node conformance/composition/hawkins-funds-authority-v0.1/run.mjs --check
 */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  encodeDeterministicCbor8949,
  receiptActionCaid,
} from '../../../packages/verify/dist/receipt-cose-encoding.js';
import {
  canonicalize,
  isRevoked,
  verifyReceipt,
  REVOCATION_VERSION,
} from '../../../packages/verify/dist/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));

export const PROFILE = 'EP-HAWKINS-FUNDS-AUTHORITY-PROFILE-v0.1';
export const PINNED_DRAFT = 'draft-hawkins-scitt-attested-agent-payment-01';
export const PINNED_DRAFT_SHA256 = '9e6deb7c735a5f776809e3e1431c7e67e1ecc664ab2c0a94895d51778f4080a7';

/** Fixed decision time for every check in this vector. */
const NOW = '2026-08-16T12:00:00.000Z';
/** Section 3: "expiry" is epoch seconds, a CBOR unsigned integer. */
const SCOPE_EXPIRY_EPOCH_SECONDS = 1787270400; // 2026-08-21T00:00:00Z

const FUNDS_AUTHORITY_ACTION_TYPE = 'payment.scope-issuance.authorize.1';
const ACCOUNT_REF = 'acct:rail-fixture:treasury-operating-001';
const SCOPE_ISSUER_ID = 'issuer:treasury-ops:scope-issuer-01';
const PRINCIPAL_ID = 'user:treasury-controller-01';
const REVOKER_ID = 'revoker:treasury-controller-01';

// --- Fixed Ed25519 keys (fixture-only; never deployment credentials) --------
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function seededKey(label) {
  const seed = crypto.createHash('sha256').update(label, 'utf8').digest();
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey,
    publicKey,
    spkiDer,
    spkiB64u: Buffer.from(spkiDer).toString('base64url'),
  };
}

/** The account principal whose key the executor pinned out of band. */
const PRINCIPAL_KEY = seededKey('ep:hawkins-funds-authority:v0.1:principal');
/** A structurally identical signer the executor did NOT pin. */
const ROGUE_KEY = seededKey('ep:hawkins-funds-authority:v0.1:rogue');
/** The pinned revoker for the account's principal. */
const REVOKER_KEY = seededKey('ep:hawkins-funds-authority:v0.1:revoker');
/** The Attested Payment Key named by the scope's "apk" member. */
const APK_KEY = seededKey('ep:hawkins-funds-authority:v0.1:apk');

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

/** Encode with the repo's deterministic RFC 8949 4.2.1 encoder or throw. */
function mustEncode(value) {
  const result = encodeDeterministicCbor8949(value);
  if (!result.ok) throw new Error(`deterministic CBOR refusal: ${result.reason}`);
  return result.value;
}

// --- Hawkins leg: the Authorization Scope (Section 3 CDDL) ------------------

/**
 * RFC 9679 COSE Key Thumbprint of the APK, SHA-256 over the
 * required-parameter COSE_Key, as the "apk" member requires. For an Ed25519
 * key the required parameters are kty(1)=OKP(1), crv(-1)=Ed25519(6), and
 * x(-2)=the raw public key bytes; the deterministic encoding is produced by
 * the same encoder the scope uses.
 */
function apkThumbprint(spkiDer) {
  const rawX = new Uint8Array(spkiDer.subarray(spkiDer.length - 32));
  const coseKey = new Map(/** @type {Array<[number, number | Uint8Array]>} */ ([
    [1, 1],
    [-1, 6],
    [-2, rawX],
  ]));
  return new Uint8Array(crypto.createHash('sha256').update(mustEncode(coseKey)).digest());
}

/**
 * Authorization Scope per the pinned draft's Section 3 CDDL:
 *   apk (bstr), code {alg, artifact, digest(bstr)}, limits {currency, scale,
 *   per_payment, aggregate, window}, expiry (uint epoch seconds), rails,
 *   payees, executor (required here because limits carries an aggregate
 *   bound). Amounts are integer counts of the smallest unit with the scale
 *   declared, per Section 3.
 */
function buildScope({ payee }) {
  return {
    apk: apkThumbprint(APK_KEY.spkiDer),
    code: {
      alg: 'sha-256',
      artifact: 'cvm-launch-measurement',
      digest: new Uint8Array(
        crypto.createHash('sha256').update('ep:hawkins-funds-authority:v0.1:endorsed-code', 'utf8').digest(),
      ),
    },
    limits: {
      currency: 'USD',
      scale: 2,
      per_payment: 500000,
      aggregate: 2000000,
      window: 86400,
    },
    expiry: SCOPE_EXPIRY_EPOCH_SECONDS,
    rails: ['rail:fixture-testnet'],
    payees: [payee],
    executor: 'executor:rail-fixture:settlement-01',
  };
}

/** Scope digest: SHA-256 over exactly the deterministic encoding bytes. */
export function scopeDigestOf(scope) {
  const bytes = mustEncode(scope);
  return { bytes, digest: `sha256:${sha256Hex(bytes)}` };
}

export const SCOPE_A = buildScope({ payee: 'payee:vendor-acme' });
export const SCOPE_B = buildScope({ payee: 'payee:vendor-other' });

// --- EMILIA leg: the funds-authority receipt --------------------------------

/**
 * Mint the principal's funds-authority receipt. The exact action material
 * names the scope issuance: issuer identity, account, and the scope digest.
 * The scope digest IS the action material that joins the two legs.
 */
function mintFundsAuthorityReceipt({
  receiptId,
  scopeDigest,
  key = PRINCIPAL_KEY,
  createdAt = '2026-08-16T11:00:00.000Z',
  expiresAt = '2026-08-17T11:00:00.000Z',
}) {
  const action = {
    action_type: FUNDS_AUTHORITY_ACTION_TYPE,
    account: ACCOUNT_REF,
    issuer: SCOPE_ISSUER_ID,
    scope_digest: scopeDigest,
  };
  const caidResult = receiptActionCaid(action);
  if (!caidResult.ok) throw new Error(`CAID refusal: ${caidResult.reason}`);
  const payload = {
    receipt_id: receiptId,
    created_at: createdAt,
    expires_at: expiresAt,
    principal: PRINCIPAL_ID,
    action,
    caid: caidResult.value.caid,
    action_digest: caidResult.value.digest,
  };
  const signature = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), key.privateKey);
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signature.toString('base64url') },
  };
}

/** EP-REVOCATION-v1 statement for a funds-authority receipt, revoker-signed. */
function mintRevocationStatement(receipt) {
  const actionHash = sha256Hex(Buffer.from(canonicalize(receipt.payload.action), 'utf8'));
  const unsigned = {
    '@version': REVOCATION_VERSION,
    target_type: 'receipt',
    target_id: receipt.payload.receipt_id,
    action_hash: `sha256:${actionHash}`,
    revoker_id: REVOKER_ID,
    revoked_at: '2026-08-16T11:30:00.000Z',
    reason: 'principal withdrew funds authority for this scope issuance',
  };
  const signedPayload = Buffer.from(canonicalize({
    '@version': REVOCATION_VERSION,
    action_hash: unsigned.action_hash,
    reason: unsigned.reason,
    revoked_at: unsigned.revoked_at,
    revoker_id: unsigned.revoker_id,
    target_id: unsigned.target_id,
    target_type: unsigned.target_type,
  }), 'utf8');
  return {
    ...unsigned,
    proof: {
      algorithm: 'Ed25519',
      revoker_key_id: `ep:revoker-key:sha256:${sha256Hex(REVOKER_KEY.spkiDer)}`,
      signature_b64u: crypto.sign(null, signedPayload, REVOKER_KEY.privateKey).toString('base64url'),
      public_key: REVOKER_KEY.spkiB64u,
    },
  };
}

// --- The executor's funds-authority procedure -------------------------------

/**
 * What the executor pinned out of band, per account: the Ed25519 key of the
 * principal who may grant funds authority on that account, the revoker keys
 * for that principal, and the Issuer identity expected to appear as the
 * Signed Statement's "iss" for scopes drawing on the account.
 */
export const EXECUTOR_PINS = Object.freeze({
  accounts: Object.freeze({
    [ACCOUNT_REF]: Object.freeze({
      principal_public_key: PRINCIPAL_KEY.spkiB64u,
      scope_issuer_id: SCOPE_ISSUER_ID,
      revoker_keys: Object.freeze({
        [REVOKER_ID]: Object.freeze({ public_key: REVOKER_KEY.spkiB64u }),
      }),
    }),
  }),
});

/**
 * The rail-defined funds-authority procedure this profile proposes for the
 * funds-authority clause of Check 8. Fail-closed: every path that does not
 * end in an established grant returns a named refusal, and absence of a
 * presentable receipt is a refusal, never a pass.
 *
 * @param {object} input
 * @param {string} input.scopeDigest   digest of the scope the instruction selected
 * @param {string} input.accountRef    the account the payment draws on
 * @param {object|null} input.presentation  { receipt, revocation_statements } or null
 * @param {object} input.pins          executor pin set (EXECUTOR_PINS shape)
 * @param {string} input.now           decision time, RFC 3339
 */
export function establishFundsAuthority({ scopeDigest, accountRef, presentation, pins, now }) {
  const refuse = (refusal, detail) => ({
    check8_funds_authority: 'refused',
    refusal,
    detail: detail ?? null,
    scope_digest: scopeDigest,
    account: accountRef,
  });

  const accountPins = pins?.accounts?.[accountRef];
  if (!accountPins || typeof accountPins.principal_public_key !== 'string') {
    // No procedure configured for this account. Absence of a procedure is
    // failure of the check, not a permission (Section 4, Check 8).
    return refuse('funds_authority_unavailable', 'no funds-authority procedure pinned for this account');
  }
  const receipt = presentation?.receipt ?? null;
  if (!receipt) {
    return refuse('funds_authority_unavailable', 'no funds-authority receipt presented');
  }

  const verification = verifyReceipt(receipt, accountPins.principal_public_key);
  if (!verification.valid) {
    if (verification.checks?.version === true && verification.checks?.signature === false) {
      return refuse('funds_authority_signer_not_pinned',
        'receipt signature does not verify under the key pinned for the account principal');
    }
    return refuse('funds_authority_receipt_invalid', verification.error ?? 'receipt verification failed');
  }

  const payload = receipt.payload;
  const action = payload?.action;
  const caidResult = receiptActionCaid(action);
  if (!caidResult.ok
      || action?.action_type !== FUNDS_AUTHORITY_ACTION_TYPE
      || payload?.caid !== caidResult.value.caid
      || payload?.action_digest !== caidResult.value.digest) {
    return refuse('funds_authority_action_invalid',
      'receipt action is not a well-formed funds-authority grant with a matching CAID');
  }
  if (action.account !== accountRef) {
    return refuse('funds_authority_account_mismatch',
      'receipt grants authority over a different account than the payment draws on');
  }
  if (action.issuer !== accountPins.scope_issuer_id) {
    return refuse('funds_authority_issuer_mismatch',
      'receipt authorizes a different Issuer than the one pinned for this account');
  }
  if (action.scope_digest !== scopeDigest) {
    return refuse('funds_authority_scope_mismatch',
      'receipt authorizes issuance of a different Authorization Scope (join digest differs)');
  }

  const nowMs = Date.parse(now);
  const expiresMs = Date.parse(String(payload.expires_at ?? ''));
  if (!Number.isFinite(expiresMs) || !Number.isFinite(nowMs) || expiresMs <= nowMs) {
    return refuse('funds_authority_receipt_expired',
      'receipt expiry has passed at the executor decision time');
  }

  const statements = Array.isArray(presentation?.revocation_statements)
    ? presentation.revocation_statements
    : [];
  const revoked = isRevoked(
    {
      target_type: 'receipt',
      target_id: payload.receipt_id,
      action_hash: `sha256:${sha256Hex(Buffer.from(canonicalize(action), 'utf8'))}`,
    },
    statements,
    { revokerKeys: accountPins.revoker_keys, now },
  );
  if (revoked) {
    return refuse('funds_authority_receipt_revoked',
      'an authentic pinned-revoker statement revokes this exact receipt');
  }

  return {
    check8_funds_authority: 'established',
    refusal: null,
    detail: null,
    scope_digest: scopeDigest,
    account: accountRef,
    evidence: {
      receipt_id: payload.receipt_id,
      principal: payload.principal,
      caid: payload.caid,
      receipt_checks: verification.checks,
    },
  };
}

// --- Cases ------------------------------------------------------------------

export function runProfile() {
  const scopeA = scopeDigestOf(SCOPE_A);
  const scopeB = scopeDigestOf(SCOPE_B);

  const happyReceipt = mintFundsAuthorityReceipt({
    receiptId: 'receipt:hawkins-funds-authority:happy',
    scopeDigest: scopeA.digest,
  });
  const wrongScopeReceipt = mintFundsAuthorityReceipt({
    receiptId: 'receipt:hawkins-funds-authority:other-scope',
    scopeDigest: scopeB.digest,
  });
  const expiredReceipt = mintFundsAuthorityReceipt({
    receiptId: 'receipt:hawkins-funds-authority:expired',
    scopeDigest: scopeA.digest,
    createdAt: '2026-08-10T11:00:00.000Z',
    expiresAt: '2026-08-11T11:00:00.000Z',
  });
  const revokedReceipt = mintFundsAuthorityReceipt({
    receiptId: 'receipt:hawkins-funds-authority:revoked',
    scopeDigest: scopeA.digest,
  });
  const revocationStatement = mintRevocationStatement(revokedReceipt);
  const rogueReceipt = mintFundsAuthorityReceipt({
    receiptId: 'receipt:hawkins-funds-authority:rogue-signer',
    scopeDigest: scopeA.digest,
    key: ROGUE_KEY,
  });

  const evaluate = (presentation) => establishFundsAuthority({
    scopeDigest: scopeA.digest,
    accountRef: ACCOUNT_REF,
    presentation,
    pins: EXECUTOR_PINS,
    now: NOW,
  });

  const cases = [
    {
      id: 'funds-authority-established',
      title: 'The principal receipt names this exact scope digest; the funds-authority clause of Check 8 is established',
      expected: { check8_funds_authority: 'established', refusal: null },
      outcome: evaluate({ receipt: happyReceipt, revocation_statements: [] }),
    },
    {
      id: 'different-scope-digest-refused',
      title: 'A valid receipt for a DIFFERENT scope digest does not carry authority for this scope',
      expected: { check8_funds_authority: 'refused', refusal: 'funds_authority_scope_mismatch' },
      outcome: evaluate({ receipt: wrongScopeReceipt, revocation_statements: [] }),
    },
    {
      id: 'no-receipt-fails-closed',
      title: 'No funds-authority receipt available: the check fails closed, never a pass',
      expected: { check8_funds_authority: 'refused', refusal: 'funds_authority_unavailable' },
      outcome: evaluate(null),
    },
    {
      id: 'expired-receipt-refused',
      title: 'An expired receipt confers nothing at the executor decision time',
      expected: { check8_funds_authority: 'refused', refusal: 'funds_authority_receipt_expired' },
      outcome: evaluate({ receipt: expiredReceipt, revocation_statements: [] }),
    },
    {
      id: 'revoked-receipt-refused',
      title: 'An authentic pinned-revoker EP-REVOCATION-v1 statement revokes the exact receipt',
      expected: { check8_funds_authority: 'refused', refusal: 'funds_authority_receipt_revoked' },
      outcome: evaluate({ receipt: revokedReceipt, revocation_statements: [revocationStatement] }),
    },
    {
      id: 'unpinned-signer-refused',
      title: 'A receipt signed by a key not pinned for the account principal is refused',
      expected: { check8_funds_authority: 'refused', refusal: 'funds_authority_signer_not_pinned' },
      outcome: evaluate({ receipt: rogueReceipt, revocation_statements: [] }),
    },
  ].map((entry) => ({
    ...entry,
    passed: entry.outcome.check8_funds_authority === entry.expected.check8_funds_authority
      && entry.outcome.refusal === entry.expected.refusal,
  }));

  const body = {
    '@version': 'HAWKINS-FUNDS-AUTHORITY-REPORT-v0.1',
    profile: PROFILE,
    reference: `${PINNED_DRAFT}, Section 4, Check 8 (funds-authority clause); Section 3 (Authorization Scope CDDL)`,
    pinned_draft: {
      name: PINNED_DRAFT,
      url: `https://www.ietf.org/archive/id/${PINNED_DRAFT}.txt`,
      sha256: PINNED_DRAFT_SHA256,
    },
    claim_boundary: {
      instantiation: 'This profile is EMILIA\'s proposed instantiation of the funds-authority procedure that the pinned draft deliberately leaves rail- or deployment-defined. The draft does not reference EMILIA, and no endorsement or adoption is claimed.',
      scope: 'Only the funds-authority clause of Check 8 is instantiated. Receipt availability from the Transparency Service, and Checks 1 through 7 and 9, are out of scope for this vector.',
      composition: 'The Hawkins scope leg and the EMILIA receipt leg stay in their own trust boundaries and join by the scope digest; neither verifier ingests the other\'s evidence.',
    },
    decision_time: NOW,
    scope_model: {
      encoding: 'rfc8949-4.2.1-deterministic (packages/verify encodeDeterministicCbor8949)',
      apk_thumbprint: 'RFC 9679 COSE Key Thumbprint, SHA-256, required-parameter OKP COSE_Key',
      scope_a: {
        payee: 'payee:vendor-acme',
        bytes_hex: Buffer.from(scopeA.bytes).toString('hex'),
        scope_digest: scopeA.digest,
      },
      scope_b: {
        payee: 'payee:vendor-other',
        bytes_hex: Buffer.from(scopeB.bytes).toString('hex'),
        scope_digest: scopeB.digest,
      },
    },
    receipt_model: {
      version: 'EP-RECEIPT-v1',
      verifier: 'packages/verify verifyReceipt (offline, pinned Ed25519 key per account principal)',
      action_type: FUNDS_AUTHORITY_ACTION_TYPE,
      action_material: ['action_type', 'account', 'issuer', 'scope_digest'],
      caid: 'packages/verify receiptActionCaid (jcs-sha256)',
      revocation: 'packages/verify EP-REVOCATION-v1 isRevoked under pinned revoker keys',
    },
    cases: cases.map((entry) => ({
      id: entry.id,
      title: entry.title,
      expected: entry.expected,
      outcome: {
        check8_funds_authority: entry.outcome.check8_funds_authority,
        refusal: entry.outcome.refusal,
        detail: entry.outcome.detail,
      },
      passed: entry.passed,
    })),
    passed: cases.every((entry) => entry.passed),
  };
  const reportDigest = `sha256:${sha256Hex(Buffer.from(canonicalize(body), 'utf8'))}`;
  return { ...body, report_digest: reportDigest, case_details: cases };
}

function parseArgs(argv) {
  const args = { check: false, emit: false };
  for (const arg of argv) {
    if (arg === '--check') args.check = true;
    else if (arg === '--emit') args.emit = true;
    else throw new TypeError(`unknown argument: ${arg}`);
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const { case_details, ...report } = runProfile();
  if (args.emit) {
    writeFileSync(resolve(HERE, 'report.reference.json'), `${JSON.stringify(report, null, 2)}\n`);
  }
  if (args.check) {
    const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
    if (canonicalize(reference) !== canonicalize(report)) {
      throw new Error('funds-authority reference report is stale');
    }
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
