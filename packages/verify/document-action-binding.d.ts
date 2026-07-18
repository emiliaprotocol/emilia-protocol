/// <reference types="node" />

import type { KeyObject } from 'node:crypto';

export const DOCUMENT_ACTION_BINDING_VERSION: 'EP-DOCUMENT-ACTION-BINDING-v1';
export const DOCUMENT_ACTION_BINDING_DOMAIN: 'EP-DOCUMENT-ACTION-BINDING-v1\0';
export const DOCUMENT_ACTION_MATERIAL_TERM_TYPES: readonly [
  'amount',
  'boolean',
  'date',
  'decimal',
  'digest',
  'identifier',
  'integer',
  'string',
  'timestamp',
];

export type CanonicalJsonValue =
  | null
  | boolean
  | string
  | number
  | CanonicalJsonValue[]
  | { [member: string]: CanonicalJsonValue };

export type DocumentActionMaterialTerm =
  | { term_id: string; type: 'amount'; value: string; currency: string }
  | { term_id: string; type: 'boolean'; value: boolean }
  | { term_id: string; type: 'integer'; value: number }
  | {
      term_id: string;
      type: 'date' | 'decimal' | 'digest' | 'identifier' | 'string' | 'timestamp';
      value: string;
    };

export interface DocumentActionParty {
  party_id: string;
  role: string;
}

export interface DocumentActionTemplate {
  action_type: string;
  [member: string]: CanonicalJsonValue;
}

export interface DocumentActionBinding {
  profile: 'EP-DOCUMENT-ACTION-BINDING-v1';
  binding_id: string;
  agreement_id: string;
  mapping_issuer: {
    issuer_id: string;
    key_id: string;
  };
  document: {
    digest: string;
    media_type: string;
    byte_length: number;
  };
  material_terms: DocumentActionMaterialTerm[];
  release_action: {
    digest: string;
    template: DocumentActionTemplate;
  };
  parties: DocumentActionParty[];
  required_parties: DocumentActionParty[];
  validity: {
    not_before: string;
    not_after: string;
  };
  supersedes_digest?: string;
  binding_digest: string;
  issuer_signatures: [{
    algorithm: 'Ed25519';
    signature_b64u: string;
  }];
}

export interface DocumentActionBindingSpec {
  binding_id: string;
  agreement_id: string;
  document: {
    bytes: Uint8Array | ArrayBuffer;
    media_type: string;
  };
  material_terms: DocumentActionMaterialTerm[];
  release_action_template: DocumentActionTemplate;
  parties: DocumentActionParty[];
  required_parties: DocumentActionParty[];
  validity: {
    not_before: string;
    not_after: string;
  };
  supersedes_digest?: string;
}

export interface DocumentActionBindingSigner {
  issuer_id: string;
  key_id: string;
  privateKey: KeyObject | string | Buffer;
}

export interface DocumentActionIssuerKey {
  issuer_id: string;
  public_key: string;
}

export interface DocumentActionBindingVerificationOptions {
  issuerKeys: Record<string, DocumentActionIssuerKey>;
  now?: number | string | Date;
  allowedMediaTypes: string[];
  allowedPartyRoles: string[];
  allowedActionTypes: string[];
  requiredMaterialTermIds?: string[];
  expectedBindingId?: string;
  expectedAgreementId?: string;
  documentBytes?: Uint8Array | ArrayBuffer;
  documentMediaType?: string;
  releaseActionTemplate?: DocumentActionTemplate;
  expectedRequiredParties?: DocumentActionParty[];
  expectedSupersedesDigest?: string | null;
}

export interface DocumentActionBindingVerificationResult {
  /** Mapping authenticity only; never a claim that any party accepted. */
  valid: boolean;
  reason: string;
  binding_id: string | null;
  agreement_id: string | null;
  supersedes_digest: string | null;
  binding_digest: string | null;
  document_digest: string | null;
  action_digest: string | null;
  required_parties: DocumentActionParty[];
}

export function computeDocumentSha256(documentBytes: Uint8Array | ArrayBuffer): string | null;
export function computeReleaseActionDigest(template: DocumentActionTemplate): string | null;
export function computeDocumentActionBindingDigest(binding: object): string | null;
export function signDocumentActionBinding(
  spec: DocumentActionBindingSpec,
  signer: DocumentActionBindingSigner,
): DocumentActionBinding;
export function verifyDocumentActionBinding(
  binding: unknown,
  opts: DocumentActionBindingVerificationOptions,
): DocumentActionBindingVerificationResult;

declare const documentActionBinding: {
  DOCUMENT_ACTION_BINDING_VERSION: typeof DOCUMENT_ACTION_BINDING_VERSION;
  DOCUMENT_ACTION_BINDING_DOMAIN: typeof DOCUMENT_ACTION_BINDING_DOMAIN;
  DOCUMENT_ACTION_MATERIAL_TERM_TYPES: typeof DOCUMENT_ACTION_MATERIAL_TERM_TYPES;
  computeDocumentSha256: typeof computeDocumentSha256;
  computeReleaseActionDigest: typeof computeReleaseActionDigest;
  computeDocumentActionBindingDigest: typeof computeDocumentActionBindingDigest;
  signDocumentActionBinding: typeof signDocumentActionBinding;
  verifyDocumentActionBinding: typeof verifyDocumentActionBinding;
};

export default documentActionBinding;
