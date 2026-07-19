// SPDX-License-Identifier: Apache-2.0
/**
 * EP-EXTERNAL-VERIFICATION-STATEMENT-v1.
 *
 * A signed statement a NON-EMILIA verifier can issue after it re-performs an
 * evidence log, replays an admissibility profile, or runs a conformance harness.
 * This is the missing adoption rail between "our verifier works" and "an
 * outside party says exactly what they checked."
 *
 * Scope is intentionally narrow:
 *   - the statement signs a procedure, inputs, result, and limitations;
 *   - it does NOT authorize an action;
 *   - it does NOT certify business correctness;
 *   - acceptance is by a relying party pinning the external verifier key.
 */
import crypto from 'node:crypto';
// In-package canonicalize (byte-identical to lib/canonical-json.js): reports must
// never import outside the package root or the published tarball cannot resolve it.
import { canonicalize } from '../execution-binding.js';

export const EXTERNAL_VERIFICATION_STATEMENT_VERSION = 'EP-EXTERNAL-VERIFICATION-STATEMENT-v1';
export const EXTERNAL_VERIFICATION_DOMAIN = 'EP-EXTERNAL-VERIFICATION-STATEMENT-v1\0';

const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;

function sha256hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function publicKeyToB64u(key) {
  return crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
}

function keyIdFor(publicKeyB64u) {
  return `ep:external-verifier-key:sha256:${sha256hex(Buffer.from(publicKeyB64u, 'base64url')).slice(0, 16)}`;
}

function signingBytes(unsignedStatement) {
  return Buffer.from(EXTERNAL_VERIFICATION_DOMAIN + canonicalize(unsignedStatement), 'utf8');
}

function unsigned(statement) {
  if (!statement || typeof statement !== 'object' || Array.isArray(statement)) {
    throw new Error('statement must be an object');
  }
  const { signature: _signature, ...body } = statement;
  return body;
}

/** Digest of the signed statement body, excluding the signature envelope. */
export function externalVerificationDigest(statement) {
  return `sha256:${sha256hex(signingBytes(unsigned(statement)))}`;
}

function normalizeChecks(checks) {
  if (!Array.isArray(checks)) return [];
  return checks.map((c) => ({
    id: String(c?.id ?? ''),
    ok: c?.ok === true,
    ...(c?.detail !== undefined ? { detail: c.detail } : {}),
  })).filter((c) => c.id);
}

/**
 * Build and sign an external-verifier statement.
 *
 * @param {object} args
 * @param {object} args.verifier {id, name?, organization?}
 * @param {object} args.subject  what was checked, e.g. {kind:'evidence_log', head:'sha256:...'}
 * @param {object} args.procedure {id, version?, tool?, command?}
 * @param {object} args.result {status, checks?, artifact_digest?}
 * @param {object} [args.inputs] stable digests/ids the procedure consumed
 * @param {string[]} [args.limitations] honest non-claims
 * @param {string|number} [args.generated_at] ISO or epoch millis
 * @param {crypto.KeyObject} privateKey Ed25519 private key
 */
export function signExternalVerificationStatement(args, privateKey) {
  if (!privateKey) throw new Error('privateKey is required');
  const generatedAt = args?.generated_at !== undefined
    ? new Date(args.generated_at).toISOString()
    : new Date().toISOString();
  const publicKey = publicKeyToB64u(privateKey);
  const body = {
    '@version': EXTERNAL_VERIFICATION_STATEMENT_VERSION,
    generated_at: generatedAt,
    verifier: {
      id: args?.verifier?.id ?? keyIdFor(publicKey),
      ...(args?.verifier?.name ? { name: args.verifier.name } : {}),
      ...(args?.verifier?.organization ? { organization: args.verifier.organization } : {}),
    },
    subject: args?.subject ?? {},
    procedure: args?.procedure ?? {},
    inputs: args?.inputs ?? {},
    result: {
      status: String(args?.result?.status ?? 'unknown'),
      checks: normalizeChecks(args?.result?.checks),
      ...(args?.result?.artifact_digest ? { artifact_digest: args.result.artifact_digest } : {}),
    },
    limitations: Array.isArray(args?.limitations) && args.limitations.length
      ? args.limitations.map(String)
      : [
        'This statement records the external verifier procedure and result; it does not authorize the action.',
        'It does not certify business correctness, legal compliance, or human wisdom.',
        'Acceptance depends on the relying party pinning the verifier key out of band.',
        'The statement carries no expiry and no consumer binding; it is replayable verbatim, and generated_at is asserted by the signer, not verified.',
      ],
  };

  const digest = externalVerificationDigest(body);
  const sig = crypto.sign(null, signingBytes(body), privateKey).toString('base64url');
  return Object.freeze({
    ...body,
    signature: {
      algorithm: 'Ed25519',
      key_id: keyIdFor(publicKey),
      public_key: publicKey,
      statement_digest: digest,
      signature_b64u: sig,
    },
  });
}

/**
 * Verify a signed external-verifier statement against pinned verifier keys.
 *
 * @param {object} statement
 * @param {{pinnedVerifierKeys?:Array<{verifier_id?:string,key_id?:string,public_key:string}>}} [opts]
 * @returns {{verified:boolean, accepted:boolean, checks:object, reason?:string, statement_digest?:string, verifier_id?:string, key_id?:string}}
 */
export function verifyExternalVerificationStatement(statement, opts = {}) {
  const fail = (reason, extra = {}) => ({
    verified: false,
    accepted: false,
    checks: {
      version: statement?.['@version'] === EXTERNAL_VERIFICATION_STATEMENT_VERSION,
      signature: false,
      pinned_verifier_key: false,
      statement_digest: false,
    },
    reason,
    ...extra,
  });

  if (statement?.['@version'] !== EXTERNAL_VERIFICATION_STATEMENT_VERSION) {
    return fail('unsupported_version');
  }
  const sig = statement.signature;
  if (!sig || sig.algorithm !== 'Ed25519' || typeof sig.public_key !== 'string' || typeof sig.signature_b64u !== 'string') {
    return fail('signature_missing_or_malformed');
  }
  if (typeof sig.statement_digest !== 'string' || !SHA256_RE.test(sig.statement_digest)) {
    return fail('statement_digest_missing_or_malformed');
  }

  let digest;
  try {
    digest = externalVerificationDigest(statement);
  } catch {
    return fail('statement_uncanonicalizable');
  }
  if (digest !== sig.statement_digest) {
    return fail('statement_digest_mismatch', { statement_digest: digest });
  }

  const pinned = Array.isArray(opts.pinnedVerifierKeys) ? opts.pinnedVerifierKeys : [];
  const verifierId = statement.verifier?.id ?? null;
  // key_id is always DERIVED from the carried public key. The envelope's key_id is
  // outside the signed bytes, so it is attacker-malleable; if present it must match
  // the derived value or the statement is refused.
  const keyId = keyIdFor(sig.public_key);
  if (sig.key_id !== undefined && sig.key_id !== keyId) {
    return fail('key_id_mismatch', { statement_digest: digest });
  }
  // A pin grants an identity, not just a key: every usable pin entry must name the
  // verifier_id it vouches for. A pin that matches the key but omits verifier_id
  // (or names a different one) never binds the statement's claimed identity.
  const keyMatched = pinned.filter((k) => k?.public_key === sig.public_key
    && (k.key_id === undefined || k.key_id === keyId));
  const pin = keyMatched.find((k) => typeof k.verifier_id === 'string' && k.verifier_id === verifierId);
  if (!pin) {
    return {
      verified: false,
      accepted: false,
      checks: { version: true, signature: false, pinned_verifier_key: false, statement_digest: true },
      reason: keyMatched.length ? 'pin_missing_or_mismatched_verifier_id' : 'verifier_key_not_pinned',
      statement_digest: digest,
    };
  }

  let ok = false;
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(sig.public_key, 'base64url'), type: 'spki', format: 'der' });
    ok = crypto.verify(null, signingBytes(unsigned(statement)), publicKey, Buffer.from(sig.signature_b64u, 'base64url'));
  } catch {
    ok = false;
  }
  if (!ok) {
    return {
      verified: false,
      accepted: false,
      checks: { version: true, signature: false, pinned_verifier_key: true, statement_digest: true },
      reason: 'signature_invalid',
      statement_digest: digest,
    };
  }

  return {
    verified: true,
    accepted: true,
    checks: { version: true, signature: true, pinned_verifier_key: true, statement_digest: true },
    verifier_id: verifierId,
    key_id: keyId,
    statement_digest: digest,
  };
}

export default {
  EXTERNAL_VERIFICATION_STATEMENT_VERSION,
  EXTERNAL_VERIFICATION_DOMAIN,
  externalVerificationDigest,
  signExternalVerificationStatement,
  verifyExternalVerificationStatement,
};
