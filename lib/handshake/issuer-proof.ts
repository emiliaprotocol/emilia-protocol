// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { canonicalize } from '@/lib/canonical-json.js';

export const HANDSHAKE_ISSUER_PROOF_PROFILE = 'EP-HANDSHAKE-ISSUER-PROOF-v1';

export interface HandshakeIssuerProof {
  profile: typeof HANDSHAKE_ISSUER_PROOF_PROFILE;
  algorithm: 'Ed25519';
  key_id: string;
  signature: string;
}

export interface HandshakeIssuerProofStatementInput {
  handshakeId: string;
  partyRole: string;
  presentationType: string;
  issuerRef: string;
  actorEntityRef: string;
  disclosureMode: string;
  presentationHash: string;
  canonicalClaimsHash: string | null;
}

export interface HandshakeIssuerAuthority {
  key_id: string;
  public_key: string;
  algorithm: string;
}

export function handshakeIssuerProofStatement(input: HandshakeIssuerProofStatementInput) {
  return {
    '@version': HANDSHAKE_ISSUER_PROOF_PROFILE,
    handshake_id: input.handshakeId,
    party_role: input.partyRole,
    presentation_type: input.presentationType,
    issuer_ref: input.issuerRef,
    actor_entity_ref: input.actorEntityRef,
    disclosure_mode: input.disclosureMode,
    presentation_hash: input.presentationHash,
    canonical_claims_hash: input.canonicalClaimsHash,
  };
}

export function handshakeIssuerProofBytes(input: HandshakeIssuerProofStatementInput): Buffer {
  const statement = handshakeIssuerProofStatement(input);
  return Buffer.from(`${HANDSHAKE_ISSUER_PROOF_PROFILE}\0${canonicalize(statement)}`, 'utf8');
}

/** Cross-language hash for the presentation payload. Objects use JCS bytes. */
export function handshakePresentationHash(data: unknown): string {
  const bytes = typeof data === 'string' ? data : canonicalize(data);
  return crypto.createHash('sha256').update(bytes, 'utf8').digest('hex');
}

function strictBase64url(value: string, expectedBytes: number): Buffer | null {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.length !== expectedBytes || decoded.toString('base64url') !== value) return null;
    return decoded;
  } catch {
    return null;
  }
}

/** Verify proof of control of the registry key that issued these exact claims. */
export function verifyHandshakeIssuerProof({
  proof,
  authority,
  statement,
}: {
  proof: HandshakeIssuerProof | null | undefined;
  authority: HandshakeIssuerAuthority;
  statement: HandshakeIssuerProofStatementInput;
}): boolean {
  if (!proof
      || proof.profile !== HANDSHAKE_ISSUER_PROOF_PROFILE
      || proof.algorithm !== 'Ed25519'
      || proof.key_id !== authority.key_id
      || proof.key_id !== statement.issuerRef
      || authority.algorithm !== 'Ed25519') {
    return false;
  }
  const signature = strictBase64url(proof.signature, 64);
  if (!signature || typeof authority.public_key !== 'string') return false;
  try {
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(authority.public_key, 'base64url'),
      type: 'spki',
      format: 'der',
    });
    if (publicKey.asymmetricKeyType !== 'ed25519') return false;
    return crypto.verify(null, handshakeIssuerProofBytes(statement), publicKey, signature);
  } catch {
    return false;
  }
}

export function handshakeIssuerProofDigest(proof: HandshakeIssuerProof): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(proof), 'utf8').digest('hex')}`;
}

/** Digest the exact registry key text used for application-side verification. */
export function handshakeAuthorityKeyDigest(publicKey: string): string {
  if (typeof publicKey !== 'string' || !publicKey) throw new TypeError('authority public key is required');
  return `sha256:${crypto.createHash('sha256').update(publicKey, 'utf8').digest('hex')}`;
}
