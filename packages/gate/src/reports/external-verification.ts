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
// A genuine declared dependency of @emilia-protocol/gate (see package.json),
// unlike a workspace-relative "../../verify/..." path -- this resolves fine in
// the published tarball, same as any other npm dependency.
import {
  signAgileSet,
  verifyAgileSignatureSet,
  type AgileSigningKey,
  type AgileSignature,
} from '@emilia-protocol/verify/pq-signature-agility';

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
 */
export function verifyExternalVerificationStatement(statement, opts: {
  pinnedVerifierKeys?: Array<{ verifier_id?: string; key_id?: string; public_key: string }>;
} = {}): {
  verified: boolean;
  accepted: boolean;
  checks: Record<string, boolean>;
  reason?: string;
  statement_digest?: string;
  verifier_id?: string;
  key_id?: string;
} {
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

// ===========================================================================
// EP-EXTERNAL-VERIFICATION-STATEMENT-v2 -- hybrid (Ed25519 + ML-DSA-65)
// ===========================================================================
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the external-verifier statement.
 *
 * 1. VERSION BUMP. `signature: {algorithm, key_id, public_key,
 *    statement_digest, signature_b64u}` becomes `signature: {profile,
 *    required_algorithms, key_id, public_key, pq_key_id, pq_public_key,
 *    statement_digest, signatures}`, a shape change, so this is a new
 *    `@version` (-v1 -> -v2). verifyExternalVerificationStatement above is
 *    UNCHANGED and refuses a v2 statement at `unsupported_version` before it
 *    ever inspects `signature`.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1
 *    AgileSignature array, one entry per required algorithm.
 * 3. ANTI-STRIPPING. `required_algorithms` is a field of the STATEMENT BODY
 *    (inside `unsigned(statement)`, alongside subject/procedure/result), so
 *    it is covered by BOTH signatures via the existing signingBytes()/
 *    externalVerificationDigest() machinery -- no new signing-bytes function
 *    is needed, because that machinery already signs "the statement minus
 *    `signature`" for whatever shape is presented. Narrowing
 *    required_algorithms after minting changes the signed bytes, so the
 *    surviving Ed25519 signature no longer verifies.
 * 4. V1 COMPATIBILITY. verifyExternalVerificationStatement stays synchronous
 *    and untouched. verifyExternalVerificationStatementV2 is a SEPARATE async
 *    entry point; verifyExternalVerificationStatementAnyVersion routes on
 *    `@version`.
 * 5. NAMED REFUSALS. Every failure path returns `{verified:false,
 *    accepted:false, reason}`; nothing throws. An absent ML-DSA backend
 *    surfaces through the agility module's own `pq_backend_unavailable`,
 *    never a silent pass on the Ed25519 leg alone.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: this statement signs a procedure,
 * inputs, result, and limitations. It does not authorize an action and does
 * not certify business correctness under either version. The ML-DSA-65
 * backend remains @noble/post-quantum's pure-JS FIPS 204 implementation, not
 * independently audited and not a FIPS validated module; issuing or
 * verifying under this profile is not a certification claim.
 */
export const EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION = 'EP-EXTERNAL-VERIFICATION-STATEMENT-v2';
export const EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

function algorithmSetMatchesRegisteredV2(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS[i]);
}

function pqKeyIdFor(pqPublicKeyRawB64u: string): string {
  return `ep:external-verifier-key:ml-dsa-65:sha256:${sha256hex(Buffer.from(pqPublicKeyRawB64u, 'base64url')).slice(0, 16)}`;
}

/**
 * Build and sign a hybrid external-verifier statement. Throws on invalid
 * input or an unavailable ML-DSA backend -- issuer-side misuse is a
 * programming error, and a statement missing the PQ leg must never be minted.
 *
 * Unlike the classical signer (which derives its own public key from
 * `privateKey`), ML-DSA-65 has no public-key-from-secret-key derivation this
 * module performs, so the caller supplies `keys.pq.publicKeyB64u` explicitly
 * (raw 1952-byte ML-DSA-65 public key, base64url) -- the same convention
 * `PqCustodySigner` uses in lib/key-custody.ts.
 */
export async function signExternalVerificationStatementV2(
  args: Parameters<typeof signExternalVerificationStatement>[0],
  keys: {
    ed: { privateKey: crypto.KeyObject };
    pq: { secretKey: Uint8Array | string; publicKeyB64u: string };
  },
) {
  if (!keys?.ed?.privateKey || !keys?.pq?.secretKey || !keys?.pq?.publicKeyB64u) {
    throw new Error('external verification statement v2: keys.ed.privateKey, keys.pq.secretKey, and keys.pq.publicKeyB64u are all required');
  }
  const generatedAt = args?.generated_at !== undefined
    ? new Date(args.generated_at).toISOString()
    : new Date().toISOString();
  const edPublicKey = publicKeyToB64u(keys.ed.privateKey);
  const pqPublicKey = keys.pq.publicKeyB64u;
  const requiredAlgorithms = [...EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS];
  const body = {
    '@version': EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION,
    generated_at: generatedAt,
    verifier: {
      id: args?.verifier?.id ?? keyIdFor(edPublicKey),
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
        'Acceptance depends on the relying party pinning BOTH the Ed25519 and ML-DSA-65 verifier keys out of band.',
        'The statement carries no expiry and no consumer binding; it is replayable verbatim, and generated_at is asserted by the signer, not verified.',
      ],
    required_algorithms: requiredAlgorithms,
  };

  const digest = externalVerificationDigest(body);
  const bytes = signingBytes(body);
  const signingKeys: AgileSigningKey[] = [
    { alg: 'Ed25519', private_key: keys.ed.privateKey },
    { alg: 'ML-DSA-65', private_key: keys.pq.secretKey },
  ];
  const signatures = await signAgileSet(new Uint8Array(bytes), signingKeys);

  return Object.freeze({
    ...body,
    signature: {
      profile: EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      key_id: keyIdFor(edPublicKey),
      public_key: edPublicKey,
      pq_key_id: pqKeyIdFor(pqPublicKey),
      pq_public_key: pqPublicKey,
      statement_digest: digest,
      signatures,
    },
  });
}

/**
 * Verify a hybrid external-verifier statement against pinned verifier keys.
 * NEVER throws. Every failure returns `{verified:false, accepted:false,
 * reason}`, mirroring verifyExternalVerificationStatement's v1 contract.
 *
 * @param pinnedVerifierKeys entries now carry BOTH halves:
 *   {verifier_id, key_id?, public_key, pq_key_id?, pq_public_key}. A pin that
 *   matches the classical key but has no pq_public_key does not accept a v2
 *   statement from that verifier -- identified but not trusted for a leg that
 *   was never pinned.
 */
export async function verifyExternalVerificationStatementV2(statement, opts: {
  pinnedVerifierKeys?: Array<{
    verifier_id?: string; key_id?: string; public_key: string;
    pq_key_id?: string; pq_public_key?: string;
  }>;
} = {}): Promise<{
  verified: boolean;
  accepted: boolean;
  checks: Record<string, boolean>;
  reason?: string;
  statement_digest?: string;
  verifier_id?: string;
  key_id?: string;
  pq_key_id?: string;
}> {
  const fail = (reason: string, extra: Record<string, unknown> = {}) => ({
    verified: false,
    accepted: false,
    checks: {
      version: statement?.['@version'] === EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION,
      algorithm_set: false,
      signature: false,
      pinned_verifier_key: false,
      statement_digest: false,
    },
    reason,
    ...extra,
  });

  if (statement?.['@version'] !== EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION) {
    return fail('unsupported_version');
  }
  if (!algorithmSetMatchesRegisteredV2(statement.required_algorithms)) {
    return fail('unsupported_algorithm_set');
  }
  const sig = statement.signature;
  if (!sig || sig.profile !== EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION
      || typeof sig.public_key !== 'string' || typeof sig.pq_public_key !== 'string'
      || !algorithmSetMatchesRegisteredV2(sig.required_algorithms) || !Array.isArray(sig.signatures)) {
    return fail('signature_missing_or_malformed');
  }
  if (typeof sig.statement_digest !== 'string' || !SHA256_RE.test(sig.statement_digest)) {
    return fail('statement_digest_missing_or_malformed');
  }

  let digest: string;
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
  const keyId = keyIdFor(sig.public_key);
  const pqKeyId = pqKeyIdFor(sig.pq_public_key);
  if (sig.key_id !== undefined && sig.key_id !== keyId) {
    return fail('key_id_mismatch', { statement_digest: digest });
  }
  if (sig.pq_key_id !== undefined && sig.pq_key_id !== pqKeyId) {
    return fail('pq_key_id_mismatch', { statement_digest: digest });
  }
  // A pin grants an identity for BOTH halves, not just the classical key: an
  // entry matching public_key but missing (or mismatching) pq_public_key does
  // not vouch for a v2 statement from this verifier.
  const keyMatched = pinned.filter((k) => k?.public_key === sig.public_key
    && k?.pq_public_key === sig.pq_public_key
    && (k.key_id === undefined || k.key_id === keyId)
    && (k.pq_key_id === undefined || k.pq_key_id === pqKeyId));
  const pin = keyMatched.find((k) => typeof k.verifier_id === 'string' && k.verifier_id === verifierId);
  if (!pin) {
    return {
      verified: false,
      accepted: false,
      checks: {
        version: true, algorithm_set: true, signature: false,
        pinned_verifier_key: false, statement_digest: true,
      },
      reason: keyMatched.length ? 'pin_missing_or_mismatched_verifier_id' : 'verifier_key_not_pinned',
      statement_digest: digest,
    };
  }

  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(signingBytes(unsigned(statement))),
      sig.signatures as AgileSignature[],
      [
        { alg: 'Ed25519', public_key: sig.public_key },
        { alg: 'ML-DSA-65', public_key: sig.pq_public_key },
      ],
      { policy: 'hybrid_all', requiredAlgorithms: [...EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS] },
    );
  } catch { setResult = null; } // verifyAgileSignatureSet never throws; a thrown backend is still a refusal.
  if (setResult?.verified !== true) {
    return {
      verified: false,
      accepted: false,
      checks: {
        version: true, algorithm_set: true, signature: false,
        pinned_verifier_key: true, statement_digest: true,
      },
      reason: String(setResult?.reason ?? 'signature_set_unverified'),
      statement_digest: digest,
    };
  }

  return {
    verified: true,
    accepted: true,
    checks: {
      version: true, algorithm_set: true, signature: true,
      pinned_verifier_key: true, statement_digest: true,
    },
    verifier_id: verifierId,
    key_id: keyId,
    pq_key_id: pqKeyId,
    statement_digest: digest,
  };
}

/**
 * Route a statement of EITHER version to its verifier. A v1 statement keeps
 * the exact v1 verdict (wrapped in a resolved Promise for a uniform async
 * surface); a v2 statement gets the hybrid check.
 */
export async function verifyExternalVerificationStatementAnyVersion(statement, opts: {
  pinnedVerifierKeys?: Array<{
    verifier_id?: string; key_id?: string; public_key: string;
    pq_key_id?: string; pq_public_key?: string;
  }>;
} = {}) {
  if (statement?.['@version'] === EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION) {
    return verifyExternalVerificationStatementV2(statement, opts);
  }
  return verifyExternalVerificationStatement(statement, opts as any);
}

export default {
  EXTERNAL_VERIFICATION_STATEMENT_VERSION,
  EXTERNAL_VERIFICATION_DOMAIN,
  externalVerificationDigest,
  signExternalVerificationStatement,
  verifyExternalVerificationStatement,
  EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION,
  EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS,
  signExternalVerificationStatementV2,
  verifyExternalVerificationStatementV2,
  verifyExternalVerificationStatementAnyVersion,
};
