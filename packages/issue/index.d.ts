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
  approver_keys: Record<string, { public_key: string; key_class: 'A' | 'B' | 'C'; valid_from?: string; valid_to?: string }>;
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
export function actionHash(action: ActionObject): string;
export function policyHash(policy: Record<string, unknown>): string;

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
}): Promise<{ receipt: AuthorizationReceipt; verification: VerificationMaterial }>;

export function verificationMaterialFromKeyBundle(keys: IssuerKeyBundle): VerificationMaterial;

// Canonical protocol vocabulary aliases.
export const assembleTrustReceipt: typeof assembleAuthorizationReceipt;
export const issueTrustReceipt: typeof issueAuthorizationReceipt;
