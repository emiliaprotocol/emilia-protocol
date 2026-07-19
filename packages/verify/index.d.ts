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
  opts?: { rpId?: string; allowedOrigins?: string[] }
): WebAuthnSignoffResult;

// ── Trust Receipt — full offline verification (I-D Section 6.3) ─────────────

export interface ApproverKeyEntry {
  /** Principal this pinned key belongs to; must equal the signed context approver. */
  approver_id: string;
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
  /**
   * Present ONLY when `opts.priorCheckpoint` is set (opt-in, fail-closed):
   * true iff the receipt's checkpoint is proven an append-only extension of
   * the caller's pinned prior head via an RFC 6962 consistency proof.
   * Proves consistency between two OBSERVED heads only; it does NOT establish
   * currency or split-view honesty (that needs independent witnesses).
   */
  consistency?: boolean;
  /**
   * Present ONLY when `opts.witnessQuorum` is set (opt-in, fail-closed): true
   * iff >= k distinct pinned witnesses validly cosigned the receipt's
   * checkpoint head. Proves k trusted witnesses saw ONE head (local
   * single-view); it does NOT prove no different head was shown elsewhere.
   */
  witness_quorum?: boolean;
  /**
   * Present ONLY when `opts.timestampProof` is set (opt-in, fail-closed): true
   * iff a pinned TSA's RFC 3161 token verifies over the caller's expectedDigest.
   * Proves the digest existed at gen_time; authentic-as-of-token only.
   */
  timestamp_proof?: boolean;
  /**
   * Present ONLY when `opts.currency` is set (opt-in, fail-closed): true iff
   * currency status is `fresh`. BOTH `stale` and the honest offline default
   * `unknown` fail this gate: offline verification can never prove currency,
   * so opting in requires a supplied recent non-revoking signed head.
   */
  currency?: boolean;
  /**
   * Present ONLY when `opts.consumptionProof` is set (opt-in, fail-closed):
   * true iff the bundle proves a one-time nonce went absent -> present exactly
   * once across two append-only-linked heads. Tree-shaped facts only; the
   * checkpoint signatures and currency of the later head are the caller's job.
   */
  consumption?: boolean;
  /**
   * Present ONLY when `opts.requireInitiatorAttestation` is true (opt-in,
   * fail-closed): true iff action.initiator_software is a structurally valid
   * EP-INITIATOR-ATTESTATION-v1. Says WHICH software asked; does NOT prove the
   * software behaved (labels are self-asserted). Absent or malformed => false.
   */
  initiator_attestation?: boolean;
}

/** EP-WITNESS-v1 quorum report surfaced as result.witness_quorum. */
export interface WitnessQuorumReport {
  ok: boolean;
  met: number;
  required: number;
  witness_ids: string[];
  reasons: string[];
}

/** RFC 3161 timestamp result surfaced as result.timestamp_proof. */
export interface TimestampProofResult {
  verified: boolean;
  tsa_key_id: string | null;
  gen_time: string | null;
  reason?: string;
}

/** EP-CURRENCY-v1 two-axis result surfaced as result.currency. */
export interface CurrencyResult {
  authentic_as_of_commit: boolean;
  currency_at_T: {
    status: 'fresh' | 'stale' | 'unknown';
    evaluated_at: string | null;
    reason: string;
  };
}

/** EP-SMT-CONSUME-v1 result surfaced as result.consumption. */
export interface ConsumptionProofResult {
  valid: boolean;
  checks: { non_inclusion: boolean; inclusion: boolean; consistency: boolean };
  reason: string | null;
}

/** EP-INITIATOR-ATTESTATION-v1 result surfaced as result.initiator_attestation. */
export interface InitiatorAttestationResult {
  ok: boolean;
  normalized: Record<string, unknown> | null;
  errors: string[];
  statement_report: Record<string, unknown> | null;
}

export type TrustReceiptStrictCheckName =
  | 'pinned_keys'
  | 'rp_id'
  | 'origin'
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
  /** Present ONLY when `opts.witnessQuorum` was supplied. */
  witness_quorum?: WitnessQuorumReport;
  /** Present ONLY when `opts.timestampProof` was supplied. */
  timestamp_proof?: TimestampProofResult;
  /** Present ONLY when `opts.currency` was supplied. */
  currency?: CurrencyResult;
  /** Present ONLY when `opts.consumptionProof` was supplied. */
  consumption?: ConsumptionProofResult;
  /** Present ONLY when `opts.requireInitiatorAttestation` was true. */
  initiator_attestation?: InitiatorAttestationResult;
}

export interface TrustReceiptVerificationOptions {
  approverKeys: Record<string, ApproverKeyEntry>;
  logPublicKey: string;
  /** Opt into deployment-grade verification beyond the frozen Section 6.3 checks. */
  strict?: boolean;
  /** Expected WebAuthn RP ID for Class-A signoffs in strict mode. */
  rpId?: string;
  /** Allowed WebAuthn origins for Class-A signoffs. Required in strict mode. */
  allowedOrigins?: string[];
  /** Expected policy hash all contexts must carry in strict mode. */
  expectedPolicyHash?: string;
  /**
   * OPT-IN append-only check: a checkpoint head this verifier previously
   * observed and pinned, plus the RFC 6962 consistency proof from that head
   * to the receipt's checkpoint (hex or "sha256:"-prefixed node hashes over
   * EP-MERKLE-v2 branch hashing). When set, `checks.consistency` is added and
   * fails closed on a malformed pin, missing proof, or invalid proof.
   */
  priorCheckpoint?: { tree_size: number; root_hash: string; consistency_proof: string[] };
  /**
   * OPT-IN (EP-WITNESS-v1): require >= k DISTINCT pinned witnesses to have
   * validly cosigned the receipt's checkpoint head. Adds fail-closed
   * `checks.witness_quorum` and surfaces `result.witness_quorum`. Proves k
   * trusted witnesses saw ONE head (local single-view); does NOT prove no
   * split view elsewhere. Fail-closed: no checkpoint, bad k, or < k distinct
   * valid cosignatures each refuse.
   */
  witnessQuorum?: {
    cosignatures: Array<Record<string, unknown>>;
    pinnedWitnessKeys: Array<{ witness_id: string; public_key: string }>;
    k: number;
  };
  /**
   * OPT-IN (RFC 3161): verify a TSA timestamp token over a caller-chosen
   * `expectedDigest` against a PINNED TSA key. Adds fail-closed
   * `checks.timestamp_proof` and surfaces `result.timestamp_proof`. Proves the
   * digest existed at gen_time; authentic-as-of-token only (nothing about
   * current TSA-cert validity).
   */
  timestampProof?: {
    token: string | Uint8Array;
    expectedDigest: string | Uint8Array;
    pinnedTsaKeys: string | string[] | Record<string, string>;
  };
  /**
   * OPT-IN (EP-CURRENCY-v1): evaluate currency-at-T. Adds `checks.currency`,
   * which passes ONLY on a proven `fresh` status; BOTH `stale` and the honest
   * offline default `unknown` fail this opted-in gate (offline can never prove
   * currency). Surfaces the two-axis `result.currency`. `authentic_as_of_commit`
   * is a SEPARATE axis, passed through verbatim (fail-safe false), and does not
   * influence the gate.
   */
  currency?: {
    now?: number | string | Date;
    maxStalenessSeconds?: number;
    freshHead?: Record<string, unknown>;
    freshHeadRequired?: boolean;
    authentic_as_of_commit?: boolean;
  };
  /**
   * OPT-IN (EP-SMT-CONSUME-v1): a third-party bundle proving a one-time nonce
   * went absent -> present exactly once across two append-only-linked heads.
   * Adds fail-closed `checks.consumption` and surfaces `result.consumption`.
   * Tree-shaped facts only; checkpoint signatures and currency of the later
   * head are the caller's responsibility.
   */
  consumptionProof?: Record<string, unknown>;
  /**
   * OPT-IN (EP-INITIATOR-ATTESTATION-v1): when true, structurally validate the
   * self-asserted initiating-software attestation at
   * receipt.action.initiator_software. Adds fail-closed
   * `checks.initiator_attestation` (absent or malformed => false) and surfaces
   * `result.initiator_attestation`. Says WHICH software asked; does NOT prove
   * the software behaved.
   */
  requireInitiatorAttestation?: boolean;
  /**
   * DORMANT legacy opt-in: verify pre-v2 (sorted-pair, undomain-separated)
   * Merkle inclusion. Never the default and never used by production gates;
   * present only so callers holding pre-v2 proofs can explicitly opt in.
   */
  allowLegacyMerkle?: boolean;
  /** Alias of `allowLegacyMerkle` for the Trust Receipt inclusion path. */
  allowLegacyTrustReceiptMerkle?: boolean;
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

// ── Checkpoint consistency (RFC 6962 §2.1.2 over EP-MERKLE-v2 branches) ─────

export const CONSISTENCY_ALG: 'EP-MERKLE-v2';

/**
 * Verify an RFC 6962 §2.1.2 consistency proof: the size-`newSize` tree (root
 * `newRoot`) is an append-only extension of the size-`oldSize` tree (root
 * `oldRoot`). Fail-closed on malformed inputs. Proves consistency between two
 * OBSERVED heads only; it does NOT establish currency or split-view honesty.
 */
export function verifyCheckpointConsistency(
  oldRoot: string,
  oldSize: number,
  newRoot: string,
  newSize: number,
  proof: string[]
): boolean;

// ── Opt-in transparency/currency knobs (also usable standalone) ────────────

export const WITNESS_VERSION: 'EP-WITNESS-v1';
export const WITNESS_DOMAIN_TAG: string;

/** Verify one EP-WITNESS-v1 cosignature over a checkpoint against a pinned key. */
export function verifyWitnessCosignature(
  checkpoint: Record<string, unknown>,
  cosignature: Record<string, unknown>,
  pinnedWitnessKey: { witness_id: string; public_key: string }
): { verified: boolean; witness_id: string | null; reason?: string };

/** Require >= k DISTINCT pinned witnesses to have validly cosigned one head. */
export function requireWitnessQuorum(
  checkpoint: Record<string, unknown>,
  cosignatures: Array<Record<string, unknown>>,
  pinnedWitnessKeys: Array<{ witness_id: string; public_key: string }>,
  k: number
): WitnessQuorumReport;

/** The exact bytes a witness signs for a checkpoint (log_signature stripped). */
export function witnessSigningDigest(checkpoint: Record<string, unknown>): Uint8Array | null;

export const TIMESTAMP_PROOF_ALG: 'RFC3161';

/** Parse + verify an RFC 3161 TimeStampToken against a PINNED TSA key. */
export function verifyTimestampProof(
  timestampProof: string | Uint8Array,
  expectedDigest: string | Uint8Array,
  pinnedTsaKeys: string | string[] | Record<string, string>
): TimestampProofResult;

export const CURRENCY_VERSION: 'EP-CURRENCY-v1';
export const CURRENCY_STATUS: readonly ['fresh', 'stale', 'unknown'];
export const CURRENCY_REASON: Readonly<Record<string, string>>;

/** Two-axis authenticity-vs-currency evaluation; `unknown` is the honest default. */
export function evaluateCurrency(args: {
  receipt?: Record<string, unknown>;
  authentic_as_of_commit?: boolean;
  now?: number | string | Date;
  maxStalenessSeconds?: number;
  freshHead?: Record<string, unknown>;
  freshHeadRequired?: boolean;
}): CurrencyResult;

export const CONSUMPTION_PROFILE: 'EP-SMT-CONSUME-v1';
export const CONSUMPTION_LEAF_DOMAIN: 'EP-SMT-CONSUME-v1';
export const SMT_DEPTH: number;

/** Verify a third-party consumption bundle (absent -> present exactly once). */
export function verifyConsumptionProof(bundle: Record<string, unknown>): ConsumptionProofResult;

/** Reference/spec sparse-Merkle prover for tests and tooling (NOT a ledger). */
export class ReferenceConsumptionTree {
  constructor(depth?: number);
  insert(nonce: string, value?: string): void;
  root(): string;
  prove(nonce: string): { root: string; siblings: string[]; present: boolean; value?: string };
}

export const INITIATOR_ATTESTATION_VERSION: 'EP-INITIATOR-ATTESTATION-v1';
export const INITIATOR_ATTESTATION_FIELD: 'initiator_software';
export const INITIATOR_STATEMENT_MAX: number;

/** Normalize a digest to bare 64-hex, or '' when malformed. */
export function normalizeDigest(h: unknown): string;

/** Neutralize hostile statement text (escape bidi/control, flag homoglyphs). */
export function neutralizeStatement(statement: unknown): {
  safe: string;
  changed: boolean;
  homoglyph_risk: boolean;
  escaped_codepoints: number[];
  truncated: boolean;
};

/** Fail-closed structural validation of a self-asserted software attestation. */
export function validateInitiatorAttestation(att: unknown): InitiatorAttestationResult;

/** Bind a validated attestation into an action under `initiator_software`. */
export function bindInitiatorAttestation(
  action: Record<string, unknown>,
  att: Record<string, unknown>
): { action: Record<string, unknown>; attestation: Record<string, unknown>; digest_preview: string };

// ── PIP-008: L4 → L7 binding (record relied-on agent identity + freshness) ──

export interface AgentBindingEvaluation {
  present: boolean;
  agent_id?: string;
  delegation?: { scheme: string; ref: string; hash?: string; observed_at?: string } | null;
  evidence_hash?: string | null;
  observed_at?: string | null;
  /** true/false when freshness is evaluated (maxAgeSec set); null otherwise. */
  fresh: boolean | null;
  age_seconds: number | null;
  reason: string;
}

/**
 * Surface the external agent-identity/delegation evidence (L4) a decision
 * relied on and optionally enforce its freshness (PIP-008 §2.1). The context's
 * signature must already be verified. With `maxAgeSec`, freshness is
 * fail-closed (missing/future/over-age observed_at => fresh:false).
 */
export function evaluateAgentBinding(
  context: Record<string, unknown>,
  opts?: { maxAgeSec?: number; at?: string }
): AgentBindingEvaluation;

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
/**
 * A pin binding for a federation issuer. Pins the KEY SOURCE for a signer, not
 * just its id: a receipt-supplied `key_discovery` is honored online only when
 * its origin matches the pinned `keyDiscoveryOrigin`/`key_discovery`, and a
 * matched verifying key is accepted only when it is one of the pinned keys
 * (if any were pinned). Bare-id pins (plain strings) carry no binding.
 */
export interface IssuerPin {
  /** Full expected discovery URL; its origin binds the receipt's key_discovery. */
  key_discovery?: string;
  /** Expected discovery origin (scheme://host[:port]); alternative to key_discovery. */
  keyDiscoveryOrigin?: string;
  /** A single pinned Ed25519 public key (SPKI DER, base64url). */
  publicKey?: string;
  /** Multiple pinned public keys (e.g. across a key rotation). */
  publicKeys?: string[];
}

/** Out-of-band issuer allowlist: bare ids, or a map from signer id → key-source pin. */
export type TrustedIssuers = Set<string> | string[] | Record<string, IssuerPin>;

export function verifyFederatedReceiptOffline(
  receipt: Record<string, unknown>,
  discoveryDoc: Record<string, unknown>,
  opts?: {
    revokedReceiptIds?: Set<string> | string[];
    expectedSigner?: string;
    trustedIssuers?: TrustedIssuers;
  }
): FederatedVerificationResult;

/**
 * Verify a federated receipt against a live operator, fetching its ep-keys.json
 * (from `signature.key_discovery`) and revocation surface. Injectable fetch.
 * To honor a RECEIPT-supplied key_discovery, pin the signer's key source via the
 * object-map form of `trustedIssuers`; a bare-id pin will not fetch it.
 */
export function verifyFederatedReceipt(
  receipt: Record<string, unknown>,
  opts?: {
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    keyDiscoveryUrl?: string;
    verifyUrlBase?: string;
    expectedSigner?: string;
    trustedIssuers?: TrustedIssuers;
    allowInsecureFetch?: boolean;
  }
): Promise<FederatedVerificationResult & {
  fetched: Record<string, unknown>;
  revocation_confirmed?: boolean;
  revocation_status?: 'confirmed_not_revoked' | 'revoked' | 'unavailable';
}>;

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
export function verifyQuorum(quorum: object, opts?: { rpId?: string; allowedOrigins?: string[] }): QuorumResult;

/** AgentROA -01 native verifier. It verifies evidence; it never grants local authority by itself. */
export const AGENTROA_DRAFT: 'draft-nivalto-agentroa-route-authorization-01';
export function verifyAgentROA(
  evidence: Record<string, unknown>,
  context?: Record<string, unknown>
): { valid: boolean; reason: string | null; action_digest?: string; decision?: string };

/** Concrete EMILIA JSON/JCS/Ed25519 profile for the abstract ORPRG -00 model. */
export const ORPRG_JSON_JCS_PROFILE: 'ORPRG-JSON-JCS-ED25519-v1';
export const ORPRG_ACTION_PROFILE: 'ORPRG-JCS-ACTION-v1';
export function computeOrprgActionDigest(action: Record<string, unknown>): string;
export function verifyOrprgJsonJcsPermit(
  input: Record<string, unknown> | string,
  options?: Record<string, unknown>
): { valid: boolean; reason: string | null; action_digest?: string };
export function verifyOrprgJsonJcsPermitAsync(
  input: Record<string, unknown> | string,
  options?: Record<string, unknown>
): Promise<{ valid: boolean; reason: string | null; action_digest?: string }>;
export function createOrprgAecVerifier(
  profile?: Record<string, unknown>
): (evidence: Record<string, unknown>, context?: Record<string, unknown>) => {
  valid: boolean;
  reason: string | null;
  action_digest?: string;
};

export const OUTCOME_ATTESTATION_VERSION: 'EP-OUTCOME-ATTESTATION-v1';
export const OUTCOME_ATTESTATION_DOMAIN: 'EP-OUTCOME-ATTESTATION-v1\0';
export const OUTCOME_BINDING_VERSION: 'EP-OUTCOME-BINDING-v1';
export const OUTCOME_BINDING_OUTCOMES: readonly ['in_bounds', 'divergent', 'incomparable'];
export function observedEffectsDigest(observedEffects: unknown[]): string;
export function trustReceiptDigest(receipt: Record<string, unknown>): string;
export function buildOutcomeAttestation(input: {
  receipt_id: string;
  receipt_digest: string;
  action_hash: string;
  consumption_nonce: string;
  execution_id: string;
  executor_id: string;
  executed_at: string;
  observed_effects: Array<Record<string, unknown>>;
  signer: { privateKey: object; publicKey?: string; key_id?: string };
}): Record<string, unknown>;
export function verifyOutcomeAttestation(
  attestation: Record<string, unknown>,
  opts?: {
    executorKeys?: Record<string, { public_key: string; key_id?: string }>;
    now?: string;
  }
): { valid: boolean; checks: Record<string, boolean>; errors: string[] };
export function verifyOutcomeBinding(
  receipt: Record<string, unknown>,
  attestation: Record<string, unknown>,
  opts?: {
    receiptOptions?: Record<string, unknown>;
    executorKeys?: Record<string, { public_key: string; key_id?: string }>;
    policyPredictedEffects?: Array<Record<string, unknown>>;
    now?: string;
  }
): {
  valid: boolean;
  checks: Record<string, boolean>;
  errors: string[];
  outcome_binding: {
    '@version': 'EP-OUTCOME-BINDING-v1';
    outcome: 'in_bounds' | 'divergent' | 'incomparable';
    evaluations: unknown[];
    reasons: string[];
  };
  result_digest: string;
};

/**
 * Deterministic canonical serialization (RFC 8785 JCS for the value subset EP
 * signs) — the single canonicalization source of truth shared by every offline
 * verifier module so signer and verifier produce byte-identical material.
 */
export function canonicalize(value: unknown): string;

/**
 * True if `value` serializes within the EP canonicalization profile
 * (JSON scalars, arrays, and plain objects of canonicalizable values).
 */
export function isCanonicalizable(value: unknown): boolean;

/** b64u/hex SHA-256 over `canonicalize(context)`; links each ordered signoff to its predecessor. */
export function contextChainHash(context: unknown): string;

export const REVOCATION_VERSION: 'EP-REVOCATION-v1';

/**
 * Verify an EP-REVOCATION-v1 statement against the authorization the relying
 * party holds. Fail-closed: a missing or malformed statement returns valid:false.
 */
export function verifyRevocation(
  target: { target_type: string; target_id: string; action_hash: string },
  statement: object,
  opts?: {
    revokerKeys?: Record<string, { public_key: string; key_id?: string }>;
    maxAgeSeconds?: number;
    now?: number | string | Date;
    [k: string]: unknown;
  }
): { valid: boolean; checks: Record<string, boolean>; errors: string[] };

/** True if any statement in `statements` validly revokes `target`. */
export function isRevoked(target: object, statements: unknown, opts?: object): boolean;

export const PROVENANCE_VERSION: 'EP-PROVENANCE-CHAIN-v1';

/** Verify an EP-PROVENANCE-CHAIN-v1 document fully offline. Fail-closed. */
export function verifyProvenanceOffline(
  doc: unknown,
  opts?: Record<string, unknown>
): {
  valid: boolean;
  checks: Record<string, boolean>;
  errors: string[];
  links: unknown[];
  agent_identity: unknown;
  liability: unknown;
};

export const EVIDENCE_RECORD_VERSION: 'EP-EVIDENCE-RECORD-v1';

/**
 * Verify an EP-EVIDENCE-RECORD-v1 document: a chain of EP-TIME-ATTESTATION-v1
 * renewals proving a protected artifact was continuously, independently
 * time-anchored across algorithm aging. Fail-closed.
 */
export function verifyEvidenceRecord(
  record: Record<string, unknown>,
  opts?: {
    tsaKeys?: Record<string, { public_key: string }>;
    protectedHash?: string;
  }
): {
  valid: boolean;
  checks: Record<string, boolean>;
  errors: string[];
  protected_since?: string;
  last_renewed?: string;
};

export const TIME_ATTESTATION_VERSION: 'EP-TIME-ATTESTATION-v1';

/** EP-TIME-ATTESTATION-v1: independent, pinned, offline-verifiable proof of WHEN (trusted-time anchor). */
export function verifyTimeAttestation(
  att: Record<string, unknown> | null | undefined,
  opts?: {
    pinnedTsaKeys?: string | string[] | Record<string, string>;
    expectedHash?: string | Uint8Array;
    notBefore?: number | string | Date;
    notAfter?: number | string | Date;
    [k: string]: unknown;
  }
): { valid: boolean; checks: Record<string, boolean>; errors: string[] };
