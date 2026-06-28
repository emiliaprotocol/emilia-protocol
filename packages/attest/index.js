// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/attest — verify an agent identity, then sign a work product
 * as an offline-verifiable EP-RECEIPT-v1.
 *
 * This is the standardized, drop-in version of the "Identity Manager" pattern
 * (hash an identity → compare to a known-good → sign the work): the same idea,
 * but the thing it signs is an EP receipt anyone can re-derive offline with
 * @emilia-protocol/verify — re-hash the identity file, re-hash the work file,
 * check the Ed25519 signature, check the EP-MERKLE-v2 anchor. No server, no
 * trust in the issuer.
 *
 * Two calls:
 *   verifyIdentity()  — SHA-256 an agent's identity bytes, constant-time compare
 *                       to a known-good hash (e.g. from a Keeper vault).
 *   signWorkReceipt() — bind the verified identity + the work-product hash into a
 *                       receipt. Fail-closed: refuses to sign if identity != known-good.
 *
 * Zero runtime deps beyond node:crypto and the sibling issuer/verifier packages.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import {
  canonicalize,
  buildReceiptAnchorV2,
  publicKeyToSpkiB64u,
  privateKeyFromPkcs8B64u,
} from '../issue/index.js';

export const ATTEST_VERSION = 'EP-ATTEST-v1';

function toBuf(input) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  return Buffer.from(String(input), 'utf8');
}

/** SHA-256 of arbitrary bytes (Buffer | Uint8Array | string) -> hex. */
export function sha256Hex(input) {
  return crypto.createHash('sha256').update(toBuf(input)).digest('hex');
}

/** Constant-time hex-string comparison. */
function hexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

/**
 * Verify an agent identity against a known-good SHA-256.
 * @param {{ identity: Buffer|Uint8Array|string, knownGoodHash: string }} args
 * @returns {{ verified: boolean, computedHash: string }}
 */
export function verifyIdentity({ identity, knownGoodHash } = {}) {
  const computedHash = sha256Hex(identity);
  return { verified: hexEqual(computedHash, String(knownGoodHash || '')), computedHash };
}

/**
 * Sign a work product as an EP-RECEIPT-v1, bound to a verified identity.
 * Fail-closed: throws if the identity does not match knownGoodHash.
 *
 * @param {object} args
 * @param {Buffer|Uint8Array|string} args.identity        identity-file bytes
 * @param {string} args.knownGoodHash                     SHA-256 hex (e.g. from Keeper)
 * @param {Buffer|Uint8Array|string} args.work            the work-product bytes
 * @param {crypto.KeyObject|string} args.signerPrivateKey Ed25519 key (KeyObject or b64u PKCS#8)
 * @param {string} args.subject                           identity id (e.g. ep:approver:cfo)
 * @param {string} args.issuedAt                          ISO-8601 (caller-supplied — no Date.now lock-in)
 * @param {string} [args.workName]
 * @param {string} [args.receiptId]
 * @param {boolean} [args.anchor=false]                   attach an EP-MERKLE-v2 anchor
 * @param {string[]} [args.priorLeaves]                   existing v2 leaves for a real inclusion proof
 * @returns {{ document: object, public_key: string }}   EP-RECEIPT-v1 + the signer SPKI (b64u)
 */
export function signWorkReceipt({
  identity,
  knownGoodHash,
  work,
  signerPrivateKey,
  subject,
  issuedAt,
  workName = null,
  receiptId,
  anchor = false,
  priorLeaves = [],
} = {}) {
  const idCheck = verifyIdentity({ identity, knownGoodHash });
  if (!idCheck.verified) {
    throw new Error('attest: identity does not match the known-good hash — refusing to sign (fail-closed)');
  }
  if (!subject) throw new Error('attest: subject (identity id) is required');
  if (!issuedAt) throw new Error('attest: issuedAt (ISO-8601) is required');

  const privateKey = typeof signerPrivateKey === 'string'
    ? privateKeyFromPkcs8B64u(signerPrivateKey)
    : signerPrivateKey;
  if (!privateKey) throw new Error('attest: signerPrivateKey is required');
  const publicKey = crypto.createPublicKey(privateKey);

  const payload = {
    receipt_id: receiptId || `att_${crypto.randomBytes(12).toString('hex')}`,
    subject,
    // The verified agent identity (its file hash) — re-derivable by re-hashing
    // the same identity file. This is the "who" the work is bound to.
    identity: { algorithm: 'SHA-256', hash: idCheck.computedHash, verified: true },
    // The work product, by hash — re-derivable by re-hashing the artifact.
    work: { algorithm: 'SHA-256', hash: sha256Hex(work), ...(workName ? { name: workName } : {}) },
    claim: { action_type: 'work.signed', outcome: 'attested' },
    issued_at: issuedAt,
  };

  const signature = crypto
    .sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey)
    .toString('base64url');

  const document = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signature },
    ...(anchor ? { anchor: buildReceiptAnchorV2(payload, priorLeaves) } : {}),
  };

  return { document, public_key: publicKeyToSpkiB64u(publicKey) };
}
