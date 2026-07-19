/**
 * @emilia-protocol/issue — TypeScript definitions
 * @license Apache-2.0
 */

import type { KeyObject } from 'node:crypto';

export interface ActionObject {
  ep_version?: string;
  action_type?: string;
  initiator?: string;
  policy_id?: string;
  [key: string]: unknown;
}

/**
 * PIP-007 §1 initiator escalation attestation. The initiator's own stated
 * reason for escalating to a human. Exactly the three members below, no others.
 */
export type EscalationTrigger =
  | 'irreversibility'
  | 'magnitude'
  | 'uncertainty'
  | 'novelty'
  | 'authority_gap'
  | 'policy_rule';

export interface InitiatorAttestation {
  /** Why the initiator escalated (REQUIRED). */
  escalation_trigger: EscalationTrigger;
  /**
   * Identifier of the policy/rule that fired. REQUIRED whenever a deterministic
   * rule fired, and always when escalation_trigger is `policy_rule`.
   */
  policy_basis?: string;
  /** Short free-text reason for the approver. MUST NOT exceed 280 characters. */
  statement?: string;
}

/** PIP-008: reference to an external delegation receipt/credential (e.g. DRP). */
export interface AgentDelegationRef {
  /** Name of the external standard, e.g. "DRP", "WIMSE". */
  scheme: string;
  /** The external receipt/credential id. */
  ref: string;
  /** Optional content hash of the referenced artifact: "sha256:<64-hex>". */
  hash?: string;
}

/**
 * PIP-008 agent_binding — an identified-never-trusted CLAIM attributing the
 * authorized action to an external agent identity / delegation. EP composes
 * with agent-identity standards rather than minting identity; a verifier treats
 * this as a claim, not proof. Copied verbatim into every context (signature-bound).
 */
export interface AgentBinding {
  /** External agent identity URI / DID / opaque id (REQUIRED). */
  agent_id: string;
  /** Optional reference to the external delegation that authorized the agent. */
  delegation?: AgentDelegationRef;
  /** Short free-text note. MUST NOT exceed 280 characters. */
  statement?: string;
}

export interface AuthorizationContext {
  ep_version: string;
  context_type: string;
  action_hash: string;
  policy_id: string;
  policy_hash: string;
  initiator?: string;
  approver: string;
  approver_index: number;
  required_approvals: number;
  nonce: string;
  issued_at: string;
  expires_at: string;
  prev_receipt_hash?: string;
  /** PIP-007 §1: identical across every context of a receipt when present. */
  initiator_attestation?: InitiatorAttestation;
  /** PIP-008: identical across every context of a receipt when present. */
  agent_binding?: AgentBinding;
}

export interface Signoff {
  context_hash: string;
  key_class: 'A' | 'B' | 'C';
  approver_key_id: string;
  signed_at: string;
  signature: string;
  webauthn?: {
    authenticator_data: string;
    client_data_json: string;
    signature: string;
  };
}

export interface AuthorizationReceipt {
  receipt_id: string;
  action: ActionObject;
  action_hash: string;
  contexts: AuthorizationContext[];
  signoffs: Signoff[];
  consumption: { nonce: string; state: string; committed_at: string };
  log_proof: {
    leaf_index: number;
    inclusion_path: Array<{ hash: string; position: 'left' | 'right' }>;
    checkpoint: { tree_size: number; root_hash: string; log_key_id: string; log_signature: string };
  };
}

export interface Ed25519KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  publicKeyB64u: string;
  privateKeyB64u: string;
}

export interface IssuerKeyBundle {
  '@version': 'EP-ISSUER-KEYS-v1';
  approver: {
    id: string;
    key_id: string;
    key_class: 'B' | 'C';
    private_key: string;
    public_key: string;
    valid_from: string;
    valid_to: string;
  };
  log: { key_id: string; private_key: string; public_key: string };
}

export interface VerificationMaterial {
  '@version': 'EP-AUTHORIZATION-RECEIPT-VERIFICATION-v1';
  approver_keys: Record<string, { approver_id: string; public_key: string; key_class: 'A' | 'B' | 'C'; valid_from?: string; valid_to?: string }>;
  log_public_key: string;
}

export interface Signer {
  approverKeyId: string;
  keyClass?: 'A' | 'B' | 'C';
  signedAt: string;
  sign?: (digest: Buffer) => string | Promise<string>;
  signWebAuthn?: (digest: Buffer) => { authenticator_data: string; client_data_json: string; signature: string };
}

export interface LogConfig {
  privateKey?: KeyObject;
  privateKeyB64u?: string;
  logKeyId: string;
  priorLeaves?: string[];
}

export function canonicalize(value: unknown): string;
export function isCanonicalizable(value: unknown): boolean;
export function actionHash(action: ActionObject): string;
export function policyHash(policy: Record<string, unknown>): string;

/** The six PIP-007 §1 escalation triggers, in spec order. */
export const ESCALATION_TRIGGERS: readonly EscalationTrigger[];
/** PIP-007 §1: the `statement` member's character cap (280). */
export const ATTESTATION_STATEMENT_MAX: number;

/**
 * Validate an initiator_attestation against PIP-007 §1, returning a frozen,
 * canonicalized copy. Throws on any violation (unknown member, bad enum,
 * over-cap statement, or `policy_rule` without `policy_basis`).
 */
export function validateInitiatorAttestation(attestation: InitiatorAttestation): Readonly<InitiatorAttestation>;

export function validateAgentBinding(binding: AgentBinding): Readonly<AgentBinding>;

export function publicKeyToSpkiB64u(publicKey: KeyObject): string;
export function privateKeyToPkcs8B64u(privateKey: KeyObject): string;
export function privateKeyFromPkcs8B64u(privateKeyB64u: string): KeyObject;
export function generateEd25519KeyPair(): Ed25519KeyPair;
export function formatLogKeyId(name: string, generation?: number): string;

export function generateIssuerKeyBundle(args?: {
  approverId?: string;
  approverKeyId?: string;
  logKeyId?: string;
  validFrom?: string;
  validTo?: string;
}): IssuerKeyBundle;

export function buildContexts(args: {
  action: ActionObject;
  policyHash: string;
  approvers: string[];
  requiredApprovals?: number;
  issuedAt: string;
  expiresAt: string;
  prevReceiptHash?: string;
  initiatorAttestation?: InitiatorAttestation;
  agentBinding?: AgentBinding;
}): AuthorizationContext[];

export function contextDigest(context: AuthorizationContext): Buffer;

export function softwareSignerFromPrivateKey(args: {
  privateKey?: KeyObject;
  privateKeyB64u?: string;
  approverKeyId: string;
  signedAt: string;
  keyClass?: 'B' | 'C';
}): Signer;

export function collectSignoffs(contexts: AuthorizationContext[], signers: Signer[]): Promise<Signoff[]>;

export function merkleProof(
  leaves: string[],
  leafIndex: number
): { root: string; path: Array<{ hash: string; position: 'left' | 'right' }> };

export function assembleAuthorizationReceipt(args: {
  receiptId: string;
  action: ActionObject;
  contexts: AuthorizationContext[];
  signoffs: Signoff[];
  committedAt: string;
  log: LogConfig;
}): AuthorizationReceipt;

export function issueAuthorizationReceipt(args: {
  receiptId?: string;
  action: ActionObject;
  policy?: Record<string, unknown>;
  policyHash?: string;
  approvers: string[];
  requiredApprovals?: number;
  issuedAt?: string;
  expiresAt?: string;
  expiresInSeconds?: number;
  prevReceiptHash?: string;
  initiatorAttestation?: InitiatorAttestation;
  agentBinding?: AgentBinding;
  signers: Signer[];
  committedAt?: string;
  log: LogConfig;
}): Promise<AuthorizationReceipt>;

export function issueFromKeyBundle(args: {
  keys: IssuerKeyBundle;
  action: ActionObject;
  policy?: Record<string, unknown>;
  policyHash?: string;
  receiptId?: string;
  issuedAt?: string;
  expiresAt?: string;
  expiresInSeconds?: number;
  initiatorAttestation?: InitiatorAttestation;
  agentBinding?: AgentBinding;
}): Promise<{ receipt: AuthorizationReceipt; verification: VerificationMaterial }>;

export function verificationMaterialFromKeyBundle(keys: IssuerKeyBundle): VerificationMaterial;

// Canonical protocol vocabulary aliases.
export const assembleTrustReceipt: typeof assembleAuthorizationReceipt;
export const issueTrustReceipt: typeof issueAuthorizationReceipt;
