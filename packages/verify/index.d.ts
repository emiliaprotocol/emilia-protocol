/**
 * @emilia-protocol/verify — TypeScript definitions
 * @license Apache-2.0
 */

export interface ReceiptVerificationResult {
  valid: boolean;
  checks: {
    version: boolean;
    signature: boolean;
    anchor: boolean | null;
  };
  error?: string;
}

export interface ProofVerificationResult {
  valid: boolean;
  claim: Record<string, unknown> | null;
  error?: string;
}

export interface BundleVerificationResult {
  valid: boolean;
  total: number;
  verified: number;
  failed: string[];
}

/**
 * Verify an EP receipt document (EP-RECEIPT-v1).
 * Zero dependencies — uses only Node.js crypto.
 */
export function verifyReceipt(
  doc: Record<string, unknown>,
  publicKeyBase64url: string
): ReceiptVerificationResult;

/**
 * Verify a Merkle inclusion proof against an expected root.
 */
export function verifyMerkleAnchor(
  leafHash: string,
  proof: Array<{ hash: string; position: 'left' | 'right' }>,
  expectedRoot: string
): boolean;

/**
 * Verify an EP commitment proof (EP-PROOF-v1).
 */
export function verifyCommitmentProof(
  proof: Record<string, unknown>,
  publicKeyBase64url: string
): ProofVerificationResult;

/**
 * Verify a bundle of EP receipts (EP-BUNDLE-v1).
 */
export function verifyReceiptBundle(
  bundle: Record<string, unknown>,
  publicKeyBase64url: string
): BundleVerificationResult;

export interface WebAuthnSignoffChecks {
  challenge_binding: boolean;
  client_data_type: boolean;
  user_present: boolean;
  user_verified: boolean;
  rp_id_hash: boolean | null;
  signature: boolean;
}

export interface WebAuthnSignoffResult {
  valid: boolean;
  checks: WebAuthnSignoffChecks;
  error?: string;
}

/**
 * Verify a Class A (approver-held key, WebAuthn) signoff fully offline.
 * Proves the device signed SHA-256(JCS(context)) with user verification,
 * against the approver's enrolled P-256 key. Pure math — no network.
 */
export function verifyWebAuthnSignoff(
  signoff: {
    context: Record<string, unknown>;
    webauthn: {
      authenticator_data: string;
      client_data_json: string;
      signature: string;
    };
  },
  approverPublicKeySpkiB64u: string,
  opts?: { rpId?: string }
): WebAuthnSignoffResult;

// ── Federation (PIP-006) ────────────────────────────────────────────────────

export interface OperatorKeyCandidate {
  public_key: string;
  status: 'current' | 'historical';
  algorithm: string;
  retired_at?: string;
}

export interface FederatedVerificationResult {
  accepted: boolean;
  verified: boolean;
  revoked: boolean;
  signer: string | null;
  keyMatched: 'current' | 'historical' | null;
  checks: {
    version: boolean;
    signer_present: boolean;
    signature: boolean;
    not_revoked: boolean;
  };
  error?: string;
}

/**
 * Resolve the candidate verification keys an operator advertises for a signer
 * from its parsed /.well-known/ep-keys.json (current first, then historical).
 */
export function resolveOperatorKeys(
  discoveryDoc: Record<string, unknown>,
  signerId: string
): OperatorKeyCandidate[];

/**
 * Verify a federated EP-RECEIPT-v1 fully offline (PIP-006 Operator-B semantics):
 * resolve the issuing operator's key from the supplied discovery doc, verify the
 * Ed25519 signature (trying historical keys for rotation safety), and check the
 * operator's revocation set. `accepted` is verified-and-not-revoked; local trust
 * policy remains the caller's.
 */
export function verifyFederatedReceiptOffline(
  receipt: Record<string, unknown>,
  discoveryDoc: Record<string, unknown>,
  opts?: { revokedReceiptIds?: Set<string> | string[]; expectedSigner?: string }
): FederatedVerificationResult;

/**
 * Verify a federated receipt against a live operator, fetching its ep-keys.json
 * (from `signature.key_discovery`) and revocation surface. Injectable fetch.
 */
export function verifyFederatedReceipt(
  receipt: Record<string, unknown>,
  opts?: {
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    keyDiscoveryUrl?: string;
    verifyUrlBase?: string;
    expectedSigner?: string;
  }
): Promise<FederatedVerificationResult & { fetched: Record<string, unknown>; revocation_confirmed?: boolean }>;
