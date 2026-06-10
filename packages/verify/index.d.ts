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
