/**
 * @emilia-protocol/issue — zero-dependency local issuance of EP authorization
 * receipts (EP-RECEIPT-v1; I-D draft-schrock-ep-authorization-receipts §6.2).
 *
 * The signing-side companion to @emilia-protocol/verify. It assembles and signs
 * the full authorization receipt — canonical Action Object + action hash,
 * per-approver Authorization Contexts, signoffs over the context digests, a
 * consumption record, Merkle log inclusion, and an Ed25519 log-signed
 * checkpoint — using byte-level choices identical to the verifier's reference
 * profile (§6.3), so receipts this module emits verify 7/7 under
 * verifyTrustReceipt() with NO EP backend.
 *
 *   - hashes are "sha256:<hex>"; canonicalization is recursive sorted-key JSON
 *   - a Class B/C signoff signs the raw 32-byte context digest (Ed25519)
 *   - a Class A signoff is a WebAuthn assertion whose challenge is
 *     base64url(context digest) — produced by the hosted ceremony, not here
 *   - the receipt leaf is SHA-256 of the canonical receipt WITHOUT log_proof /
 *     approver_key_proofs; inclusion_path is positioned steps
 *   - the checkpoint signature is Ed25519 over the canonical checkpoint
 *     WITHOUT log_signature
 *
 * Signing is delegated: the issuer never holds approver keys in its core path.
 * Each approver supplies a callback (a local software key for Class B/C here;
 * the WebAuthn ceremony for Class A in production).
 *
 * This file is the single source of truth. lib/trust-receipt/issuer.js
 * re-exports from it so the in-repo issuer and the published package are the
 * same bytes by construction.
 *
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
type AnyRecord = Record<string, any>;
/** Recursive canonical JSON — depth-first key sort at every level (JCS-equivalent). */
export declare function canonicalize(value: any): string;
export declare function isCanonicalizable(value: any): boolean;
/** "sha256:<hex>" action hash of the canonical Action Object (I-D §3). */
export declare function actionHash(action: any): string;
/** "sha256:<hex>" of an evaluated policy document (I-D §4). */
export declare function policyHash(policy: any): string;
/**
 * Export an Ed25519/EC public key to base64url SPKI DER.
 * @param {crypto.KeyObject} publicKey
 */
export declare function publicKeyToSpkiB64u(publicKey: any): string;
/** Export a private key to base64url PKCS#8 DER (portable, JSON-safe). */
export declare function privateKeyToPkcs8B64u(privateKey: any): string;
/** Rehydrate a private key from base64url PKCS#8 DER. */
export declare function privateKeyFromPkcs8B64u(privateKeyB64u: string): any;
/** Generate an Ed25519 keypair and its base64url SPKI/PKCS#8 encodings. */
export declare function generateEd25519KeyPair(): {
    publicKey: crypto.KeyObject;
    privateKey: crypto.KeyObject;
    publicKeyB64u: string;
    privateKeyB64u: string;
};
/**
 * Format a human log name into the canonical log key id, e.g.
 * formatLogKeyId('acme') -> 'ep:log:acme#1'. Pass a generation for rotation.
 */
export declare function formatLogKeyId(name: string, generation?: number): string;
/**
 * Generate a complete local issuer bundle: one Class-B (software) approver key
 * and one Ed25519 log key. This is what `ep-issue keygen` writes. The bundle
 * carries private material — keep it secret; share only the verification block.
 *
 * @param {object} [args]
 * @param {string} [args.approverId]    - approver subject id (ep:approver:…)
 * @param {string} [args.approverKeyId] - approver key id (ep:key:…#1)
 * @param {string} [args.logKeyId]      - log key id (ep:log:<name>#1)
 * @param {string} [args.validFrom]     - approver key validity start (ISO-8601)
 * @param {string} [args.validTo]       - approver key validity end (ISO-8601)
 * @returns {object} EP-ISSUER-KEYS-v1 bundle
 */
export declare function generateIssuerKeyBundle({ approverId, approverKeyId, logKeyId, validFrom, validTo, }?: {
    approverId?: string | undefined;
    approverKeyId?: string | undefined;
    logKeyId?: string | undefined;
    validFrom?: string | undefined;
    validTo?: string | undefined;
}): {
    '@version': string;
    approver: {
        id: string;
        key_id: string;
        key_class: string;
        private_key: string;
        public_key: string;
        valid_from: string;
        valid_to: string;
    };
    log: {
        key_id: string;
        private_key: string;
        public_key: string;
    };
};
/**
 * The six escalation triggers defined by PIP-007 §1. Exactly one is REQUIRED.
 * The first five are substantive reasons; `policy_rule` is the residual used
 * only when no substantive category fits (see the precedence rule).
 */
export declare const ESCALATION_TRIGGERS: readonly string[];
/** PIP-007 §1: the free-text `statement` MUST NOT exceed 280 characters. */
export declare const ATTESTATION_STATEMENT_MAX = 280;
/**
 * Validate an `initiator_attestation` object against PIP-007 §1, returning a
 * frozen copy of the validated object. Throws on any violation — the issuer
 * fails closed, so a malformed attestation never reaches a context.
 *
 * Rules enforced (PIP-007 §1):
 *   - it is a plain object with ONLY the three defined members (reject extras);
 *   - `escalation_trigger` is REQUIRED and one of the six enum values;
 *   - `statement`, if present, is a string at most 280 characters;
 *   - `policy_basis`, if present, is a non-empty string;
 *   - whenever `escalation_trigger` is `policy_rule`, `policy_basis` is REQUIRED
 *     (the always-case of the deterministic-rule precedence rule).
 *
 * Note: the broader "REQUIRED whenever a deterministic rule fired" obligation is
 * a producer responsibility — the issuer cannot see whether a rule fired beyond
 * the `policy_rule` trigger, so it enforces only the unconditional sub-case
 * here. The verifier SHOULD-flags the `policy_rule`-without-`policy_basis` case
 * symmetrically (PIP-007 §2).
 *
 * @param {object} attestation
 * @returns {Readonly<object>} the validated attestation
 */
export declare function validateInitiatorAttestation(attestation: AnyRecord): AnyRecord;
/**
 * Validate an `agent_binding` object against PIP-008, returning a frozen copy.
 *
 * EP COMPOSES with external agent-identity / delegation standards (e.g. IETF
 * WIMSE, the Delegated-Receipt Protocol) rather than rebuilding them. The
 * `agent_binding` is an IDENTIFIED-NEVER-TRUSTED CLAIM, copied verbatim into
 * every context, so the approver's signature over the JCS-canonical context
 * already binds it — no verifier change, no new trust. A verifier treats it as
 * a claim ("this approval was for an action attributed to agent X under
 * delegation Y"), NOT as proof of agent identity. The issuer fails closed.
 *
 * Rules (PIP-008 §1):
 *   - plain object with ONLY agent_id, delegation, statement (reject extras);
 *   - `agent_id` REQUIRED, non-empty string (an external identity URI / DID /
 *     opaque id — EP does not mint or verify it);
 *   - `delegation` OPTIONAL object {scheme, ref, hash?}: `scheme` + `ref` are
 *     non-empty strings naming the external standard (e.g. "DRP") and its
 *     receipt/credential reference; `hash`, if present, is "sha256:<64-hex>";
 *   - `statement` OPTIONAL string, at most 280 characters.
 *
 * @param {object} binding
 * @returns {Readonly<object>} the validated binding
 */
export declare function validateAgentBinding(binding: AnyRecord): AnyRecord;
/**
 * Build one Authorization Context per approver.
 *
 * @param {object} args
 * @param {object} args.action - the Action Object (initiator, policy_id, …)
 * @param {string} args.policyHash - "sha256:<hex>" of the evaluated policy
 * @param {string[]} args.approvers - approver ids, one context each
 * @param {number} [args.requiredApprovals] - defaults to approvers.length
 * @param {string} args.issuedAt - ISO-8601
 * @param {string} args.expiresAt - ISO-8601
 * @param {string} [args.prevReceiptHash] - chains to the log's latest receipt
 * @param {object} [args.initiatorAttestation] - PIP-007 §1 attestation. When
 *   present it is validated and copied verbatim — the IDENTICAL object — into
 *   every context, so its canonical form is identical across all of them.
 * @param {object} [args.agentBinding] - PIP-008 agent attribution claim.
 * @returns {object[]} contexts
 */
export declare function buildContexts({ action, policyHash, approvers, requiredApprovals, issuedAt, expiresAt, prevReceiptHash, initiatorAttestation, agentBinding }: AnyRecord): AnyRecord[];
/** The 32-byte context digest an approver signs. */
export declare function contextDigest(context: AnyRecord): Buffer;
/**
 * Build a Class B/C software signer backed by a local Ed25519 private key. The
 * signer signs the raw 32-byte context digest, the exact bytes the verifier
 * checks (§6.3). Class A (device-bound WebAuthn) is NOT produced here — it
 * requires the hosted ceremony; pass a `signWebAuthn` signer for that.
 *
 * @param {object} args
 * @param {crypto.KeyObject} [args.privateKey] - the Ed25519 private key, OR
 * @param {string} [args.privateKeyB64u]        - base64url PKCS#8 DER of it
 * @param {string} args.approverKeyId           - the approver key id (ep:key:…#1)
 * @param {string} args.signedAt                - ISO-8601 signoff time
 * @param {'A'|'B'|'C'} [args.keyClass='B']
 * @returns {object} a signer for collectSignoffs()
 */
export declare function softwareSignerFromPrivateKey({ privateKey, privateKeyB64u, approverKeyId, signedAt, keyClass }: AnyRecord): AnyRecord;
/**
 * Collect a signoff from each approver's signer.
 *
 * @param {object[]} contexts - from buildContexts (one per signer, same order)
 * @param {Array<{
 *   approverKeyId: string,
 *   keyClass?: 'A'|'B'|'C',
 *   signedAt: string,
 *   sign?: (digest: Buffer) => string|Promise<string>,
 *   signWebAuthn?: (digest: Buffer) => { authenticator_data:string, client_data_json:string, signature:string },
 * }>} signers
 * @returns {Promise<object[]>} signoffs
 */
export declare function collectSignoffs(contexts: AnyRecord[], signers: AnyRecord[]): Promise<AnyRecord[]>;
/**
 * Build a sorted-pair Merkle tree over hex leaves; return the root and the
 * positioned inclusion path for leafIndex (the verifier's verifyMerkleAnchor
 * shape). Duplicates the last leaf when a level has an odd count.
 */
export declare function merkleProof(leaves: string[], leafIndex: number): AnyRecord;
export declare const MERKLE_V2_ALG = "EP-MERKLE-v2";
/**
 * v2 (domain-separated, positional) sibling of merkleProof().
 *
 * CVE-2012-2459 fix: an unpaired node on an odd-count level is PROMOTED to the
 * next level unchanged (never duplicated and re-hashed against itself). Combined
 * with positional, domain-separated hashing this makes the root a UNIQUE
 * commitment to the leaf set — an operator cannot mint two distinct trees with
 * the same root (no equivocation). The verifier's proof-folding is agnostic to
 * promotion (a promoted node contributes no proof step), so verifyMerkleAnchor
 * with {v2:true} reconstructs the identical root.
 */
export declare function merkleProofV2(leaves: string[], leafIndex: number): AnyRecord;
/**
 * Build the canonical EP-MERKLE-v2 anchor for a receipt document payload — the
 * default for all NEW anchored issuance. The returned anchor self-checks under
 * @emilia-protocol/verify's verifyReceipt (it recomputes leaf_hash from
 * doc.payload and rejects a mismatch).
 *
 * @param {object} payload - the EP-RECEIPT-v1 document payload to anchor
 * @param {string[]} [priorLeaves=[]] - existing v2 leaf hashes (hex), oldest first
 * @returns {{alg:'EP-MERKLE-v2', leaf_hash:string, merkle_proof:Array, merkle_root:string}}
 */
export declare function buildReceiptAnchorV2(payload: AnyRecord, priorLeaves?: string[]): AnyRecord;
/**
 * Assemble and log-sign the complete authorization receipt.
 *
 * @param {object} args
 * @param {string} args.receiptId
 * @param {object} args.action
 * @param {object[]} args.contexts
 * @param {object[]} args.signoffs
 * @param {string} args.committedAt - ISO-8601 consumption time
 * @param {object} args.log
 * @param {crypto.KeyObject} [args.log.privateKey] - the log's Ed25519 signing key, OR
 * @param {string} [args.log.privateKeyB64u]        - base64url PKCS#8 DER of it
 * @param {string} args.log.logKeyId - e.g. "ep:log:acme#1"
 * @param {string[]} [args.log.priorLeaves] - existing log leaves (hex), oldest first
 * @returns {object} the §6.2 authorization receipt (verifies under verifyTrustReceipt)
 */
export declare function assembleAuthorizationReceipt({ receiptId, action, contexts, signoffs, committedAt, log }: AnyRecord): AnyRecord;
/**
 * LEGACY (EP-MERKLE-v1) assembler — sorted-pair, undomain-separated, no
 * payload-bound leaf. DEPRECATED and INSECURE (leaf/branch second-preimage +
 * CVE-2012-2459 root equivocation). Retained ONLY to produce compatibility
 * artifacts for the opt-in legacy verification path; NEVER use for new issuance.
 * A receipt from this function verifies under verifyTrustReceipt ONLY when the
 * caller passes { allowLegacyMerkle: true }.
 */
export declare function assembleAuthorizationReceiptLegacyV1({ receiptId, action, contexts, signoffs, committedAt, log }: AnyRecord): AnyRecord;
/**
 * One-call issuance: contexts → signoffs → assembled, log-signed receipt.
 * @param {object} args
 * @param {string} [args.receiptId]
 * @param {object} args.action
 * @param {object} [args.policy]
 * @param {string} [args.policyHash]
 * @param {string[]} args.approvers
 * @param {number} [args.requiredApprovals]
 * @param {string} [args.issuedAt]
 * @param {string} [args.expiresAt]
 * @param {number} [args.expiresInSeconds]
 * @param {string} [args.prevReceiptHash]
 * @param {object} [args.initiatorAttestation]
 * @param {object} [args.agentBinding]
 * @param {Array<object>} args.signers
 * @param {string} [args.committedAt]
 * @param {object} args.log
 */
export declare function issueAuthorizationReceipt({ receiptId, action, policy, policyHash: explicitPolicyHash, approvers, requiredApprovals, issuedAt, expiresAt, expiresInSeconds, prevReceiptHash, initiatorAttestation, agentBinding, signers, committedAt, log, }: AnyRecord): Promise<AnyRecord>;
/**
 * Highest-level convenience: issue a single-approver, Class-B receipt straight
 * from an EP-ISSUER-KEYS-v1 bundle (what `ep-issue keygen` produced). Returns
 * the receipt plus the public verification material a verifier needs.
 *
 * @param {object} args
 * @param {object} args.keys - EP-ISSUER-KEYS-v1 bundle
 * @param {object} args.action - the Action Object
 * @param {object} [args.policy] - the evaluated policy (hashed into the context)
 * @param {string} [args.policyHash] - explicit "sha256:<hex>" policy hash
 * @param {string} [args.receiptId]
 * @param {string} [args.issuedAt]
 * @param {string} [args.expiresAt]
 * @param {number} [args.expiresInSeconds=3600]
 * @param {object} [args.initiatorAttestation] - PIP-007 §1 attestation, copied
 *   into the (single) context.
 * @param {object} [args.agentBinding] - PIP-008 agent attribution claim.
 * @returns {Promise<{ receipt: object, verification: object }>}
 */
export declare function issueFromKeyBundle({ keys, action, policy, policyHash: explicitPolicyHash, receiptId, issuedAt, expiresAt, expiresInSeconds, initiatorAttestation, agentBinding, }: AnyRecord): Promise<AnyRecord>;
/** Public verification material (approver public keys + log public key) from a key bundle. */
export declare function verificationMaterialFromKeyBundle(keys: AnyRecord): AnyRecord;
export declare const assembleTrustReceipt: typeof assembleAuthorizationReceipt;
export declare const issueTrustReceipt: typeof issueAuthorizationReceipt;
export {};
//# sourceMappingURL=index.d.ts.map