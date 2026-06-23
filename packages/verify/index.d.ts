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

export interface CommitmentProofVerificationOptions {
  /**
   * Opt into structure/expiry-only checks. Default verification requires both
   * a commitment proof signature and the entity public key.
   */
  allowUnsigned?: boolean;
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
  publicKeyBase64url?: string | null,
  options?: CommitmentProofVerificationOptions
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

// ── Trust Receipt — full offline verification (I-D Section 6.3) ─────────────

export interface ApproverKeyEntry {
  public_key: string;
  key_class?: 'A' | 'B' | 'C';
  valid_from?: string;
  valid_to?: string;
}

export interface TrustReceiptChecks {
  action_hash: boolean;
  context_commitments: boolean;
  signoff_signatures: boolean;
  sod: boolean;
  inclusion: boolean;
  checkpoint_signature: boolean;
  windows: boolean;
}

export type TrustReceiptStrictCheckName =
  | 'pinned_keys'
  | 'rp_id'
  | 'user_presence'
  | 'user_verification'
  | 'key_windows'
  | 'policy_hash'
  | 'no_unsigned';

export type TrustReceiptStrictChecks = Partial<Record<TrustReceiptStrictCheckName, boolean>>;

export interface TrustReceiptStrictReport {
  /** True only when `verifyTrustReceipt(..., { strict: true })` is requested. */
  enabled: boolean;
  /** Conjunction of all strict checks when enabled; true when disabled. */
  valid: boolean;
  /** Empty when disabled; otherwise one boolean per strict check. */
  checks: TrustReceiptStrictChecks;
  errors: string[];
}

/**
 * PIP-007 §2 ADVISORY attestation report. Never affects `valid` or `checks`.
 *   - present:    a context carries an initiator_attestation.
 *   - consistent: present in every context with an identical canonical form
 *     (PIP-007 §1; MUST be flagged on mismatch).
 *   - issues:     SHOULD-flagged §1 malformations (unknown members, over-cap
 *     statement, `policy_rule` without `policy_basis`, bad enum) and the
 *     cross-context-identity violations.
 */
export interface AttestationReport {
  present: boolean;
  consistent: boolean;
  issues: string[];
}

export interface TrustReceiptResult {
  valid: boolean;
  checks: TrustReceiptChecks;
  errors: string[];
  /** PIP-007 §2 advisory report — independent of `valid` and `checks`. */
  attestation: AttestationReport;
  /** Optional deployment-grade gate; affects `valid` only when enabled. */
  strict: TrustReceiptStrictReport;
}

export interface TrustReceiptVerificationOptions {
  approverKeys: Record<string, ApproverKeyEntry>;
  logPublicKey: string;
  /** Opt into deployment-grade verification beyond the frozen Section 6.3 checks. */
  strict?: boolean;
  /** Expected WebAuthn RP ID for Class-A signoffs in strict mode. */
  rpId?: string;
  /** Expected policy hash all contexts must carry in strict mode. */
  expectedPolicyHash?: string;
}

/**
 * Verify a Trust Receipt (I-D Section 6.2) fully offline — the Section 6.3
 * algorithm: action-hash recomputation, context commitments, signoff
 * signatures against pinned approver keys (incl. Class-A WebAuthn and key
 * validity windows), separation of duties, Merkle inclusion + checkpoint
 * signature against the trusted log key, and temporal windows.
 *
 * Additionally surfaces a PIP-007 §2 ADVISORY `attestation` report when the
 * contexts carry an initiator escalation attestation. The advisory flags
 * cross-context inconsistency and §1 malformations but NEVER changes
 * signature validity or any member of `checks`.
 */
export function verifyTrustReceipt(
  receipt: Record<string, unknown>,
  opts: TrustReceiptVerificationOptions
): TrustReceiptResult;

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

/** EP-QUORUM-v1 multi-party (M-of-N / ordered) approval verification result. */
export interface QuorumResult {
  valid: boolean;
  checks: {
    all_signatures_valid: boolean;
    action_binding: boolean;
    distinct_humans: boolean;
    roles_admitted: boolean;
    threshold_met: boolean;
    order_satisfied: boolean;
    within_window: boolean;
  };
  members: Array<{ approver: string | null; role: string | null; valid: boolean }>;
}

/** Verify an EP-QUORUM-v1 multi-party approval (composes verifyWebAuthnSignoff; fail-closed). */
export function verifyQuorum(quorum: object, opts?: { rpId?: string }): QuorumResult;
