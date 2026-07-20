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

// ── canonicalization + hashing (byte-identical to packages/verify) ───────────

/** Recursive canonical JSON — depth-first key sort at every level (JCS-equivalent). */
export function canonicalize(value: any): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export function isCanonicalizable(value: any): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isInteger(value) && Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(isCanonicalizable);
  if (typeof value === 'object') return Object.values(value).every(isCanonicalizable);
  return false;
}

function assertCanonicalizable(value: any, label: string): void {
  if (!isCanonicalizable(value)) {
    throw new Error(`${label} is outside the EP canonicalization profile; encode non-integer quantities as strings`);
  }
}

const sha256hex = (s: string): string => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const sha256Bytes = (s: string): Buffer => crypto.createHash('sha256').update(s, 'utf8').digest();
const hashPair = (a: string, b: string): string => { const s = [a, b].sort(); return sha256hex(s[0] + s[1]); };

/** "sha256:<hex>" action hash of the canonical Action Object (I-D §3). */
export function actionHash(action: any): string {
  return `sha256:${sha256hex(canonicalize(action))}`;
}

/** "sha256:<hex>" of an evaluated policy document (I-D §4). */
export function policyHash(policy: any): string {
  return `sha256:${sha256hex(canonicalize(policy))}`;
}

// ── key material helpers ─────────────────────────────────────────────────────

/**
 * Export an Ed25519/EC public key to base64url SPKI DER.
 * @param {crypto.KeyObject} publicKey
 */
export function publicKeyToSpkiB64u(publicKey: any): string {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

/** Export a private key to base64url PKCS#8 DER (portable, JSON-safe). */
export function privateKeyToPkcs8B64u(privateKey: any): string {
  return privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
}

/** Rehydrate a private key from base64url PKCS#8 DER. */
export function privateKeyFromPkcs8B64u(privateKeyB64u: string): any {
  return crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64u, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
}

/** Generate an Ed25519 keypair and its base64url SPKI/PKCS#8 encodings. */
export function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    publicKeyB64u: publicKeyToSpkiB64u(publicKey),
    privateKeyB64u: privateKeyToPkcs8B64u(privateKey),
  };
}

/**
 * Format a human log name into the canonical log key id, e.g.
 * formatLogKeyId('acme') -> 'ep:log:acme#1'. Pass a generation for rotation.
 */
export function formatLogKeyId(name: string, generation = 1): string {
  return `ep:log:${name}#${generation}`;
}

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
export function generateIssuerKeyBundle({
  approverId = 'ep:approver:local',
  approverKeyId = 'ep:key:local-approver#1',
  logKeyId = formatLogKeyId('local'),
  validFrom = '2026-01-01T00:00:00Z',
  validTo = '2036-01-01T00:00:00Z',
} = {}) {
  const approver = generateEd25519KeyPair();
  const log = generateEd25519KeyPair();
  return {
    '@version': 'EP-ISSUER-KEYS-v1',
    approver: {
      id: approverId,
      key_id: approverKeyId,
      key_class: 'B',
      private_key: approver.privateKeyB64u,
      public_key: approver.publicKeyB64u,
      valid_from: validFrom,
      valid_to: validTo,
    },
    log: {
      key_id: logKeyId,
      private_key: log.privateKeyB64u,
      public_key: log.publicKeyB64u,
    },
  };
}

// ── initiator attestation (PIP-007) ───────────────────────────────────────────

/**
 * The six escalation triggers defined by PIP-007 §1. Exactly one is REQUIRED.
 * The first five are substantive reasons; `policy_rule` is the residual used
 * only when no substantive category fits (see the precedence rule).
 */
export const ESCALATION_TRIGGERS = Object.freeze([
  'irreversibility',
  'magnitude',
  'uncertainty',
  'novelty',
  'authority_gap',
  'policy_rule',
]);

/** PIP-007 §1: the free-text `statement` MUST NOT exceed 280 characters. */
export const ATTESTATION_STATEMENT_MAX = 280;

// The only members a v1 attestation may carry (PIP-007 §1: "no others").
const ATTESTATION_MEMBERS = Object.freeze(['escalation_trigger', 'policy_basis', 'statement']);

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
export function validateInitiatorAttestation(attestation: AnyRecord): AnyRecord {
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
    throw new Error('initiatorAttestation must be an object');
  }
  for (const key of Object.keys(attestation)) {
    if (!ATTESTATION_MEMBERS.includes(key)) {
      throw new Error(`initiatorAttestation has an unknown member "${key}" (PIP-007 §1 allows only ${ATTESTATION_MEMBERS.join(', ')})`);
    }
  }
  const { escalation_trigger: trigger, policy_basis: policyBasis, statement } = attestation;
  if (!ESCALATION_TRIGGERS.includes(trigger)) {
    throw new Error(`initiatorAttestation.escalation_trigger must be one of ${ESCALATION_TRIGGERS.join(', ')}`);
  }
  if (policyBasis !== undefined && (typeof policyBasis !== 'string' || policyBasis.length === 0)) {
    throw new Error('initiatorAttestation.policy_basis must be a non-empty string when present');
  }
  if (trigger === 'policy_rule' && !policyBasis) {
    throw new Error('initiatorAttestation.policy_basis is required when escalation_trigger is "policy_rule" (PIP-007 §1)');
  }
  if (statement !== undefined) {
    if (typeof statement !== 'string') throw new Error('initiatorAttestation.statement must be a string');
    if (statement.length > ATTESTATION_STATEMENT_MAX) {
      throw new Error(`initiatorAttestation.statement exceeds the ${ATTESTATION_STATEMENT_MAX}-character cap (PIP-007 §1)`);
    }
  }
  // Re-build in the canonical member order so every context carries the
  // identical object; canonicalize() sorts keys, but we keep the source object
  // stable too. Only defined members are copied through.
  const validated: AnyRecord = { escalation_trigger: trigger };
  if (policyBasis !== undefined) validated.policy_basis = policyBasis;
  if (statement !== undefined) validated.statement = statement;
  return Object.freeze(validated);
}

// ── contexts (I-D §4) ─────────────────────────────────────────────────────────

// PIP-008: the only members an agent_binding may carry.
const AGENT_BINDING_MEMBERS = Object.freeze(['agent_id', 'delegation', 'statement']);
const DELEGATION_MEMBERS = Object.freeze(['scheme', 'ref', 'hash', 'observed_at']);
const AGENT_BINDING_SHA256_RE = /^sha256:[0-9a-f]{64}$/;

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
export function validateAgentBinding(binding: AnyRecord): AnyRecord {
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) {
    throw new Error('agentBinding must be an object');
  }
  for (const key of Object.keys(binding)) {
    if (!AGENT_BINDING_MEMBERS.includes(key)) {
      throw new Error(`agentBinding has an unknown member "${key}" (PIP-008 §1 allows only ${AGENT_BINDING_MEMBERS.join(', ')})`);
    }
  }
  const { agent_id: agentId, delegation, statement } = binding;
  if (typeof agentId !== 'string' || agentId.length === 0) {
    throw new Error('agentBinding.agent_id is required and must be a non-empty string (PIP-008 §1)');
  }
  /** @type {{scheme: string, ref: string, hash?: string, observed_at?: string} | undefined} */
  let validatedDelegation;
  if (delegation !== undefined) {
    if (!delegation || typeof delegation !== 'object' || Array.isArray(delegation)) {
      throw new Error('agentBinding.delegation must be an object when present');
    }
    for (const key of Object.keys(delegation)) {
      if (!DELEGATION_MEMBERS.includes(key)) {
        throw new Error(`agentBinding.delegation has an unknown member "${key}" (PIP-008 §1 allows only ${DELEGATION_MEMBERS.join(', ')})`);
      }
    }
    const { scheme, ref, hash, observed_at: observedAt } = delegation;
    if (typeof scheme !== 'string' || scheme.length === 0) {
      throw new Error('agentBinding.delegation.scheme is required and must be a non-empty string');
    }
    if (typeof ref !== 'string' || ref.length === 0) {
      throw new Error('agentBinding.delegation.ref is required and must be a non-empty string');
    }
    if (hash !== undefined && (typeof hash !== 'string' || !AGENT_BINDING_SHA256_RE.test(hash))) {
      throw new Error('agentBinding.delegation.hash must be "sha256:<64-hex>" when present');
    }
    // PIP-008 §1.1 (freshness): OPTIONAL observed_at records WHEN the external
    // L4 evidence was observed/valid, so a verifier (PDP) can enforce a
    // freshness window on the upstream identity/delegation claim. Still a
    // claim, not proof — EP records it; it does not resolve the L4 evidence.
    if (observedAt !== undefined && (typeof observedAt !== 'string' || Number.isNaN(Date.parse(observedAt)))) {
      throw new Error('agentBinding.delegation.observed_at must be an RFC 3339 timestamp when present');
    }
    validatedDelegation = { scheme, ref } as AnyRecord;
    if (hash !== undefined) validatedDelegation.hash = hash;
    if (observedAt !== undefined) validatedDelegation.observed_at = observedAt;
    validatedDelegation = Object.freeze(validatedDelegation);
  }
  if (statement !== undefined) {
    if (typeof statement !== 'string') throw new Error('agentBinding.statement must be a string');
    if (statement.length > ATTESTATION_STATEMENT_MAX) {
      throw new Error(`agentBinding.statement exceeds the ${ATTESTATION_STATEMENT_MAX}-character cap (PIP-008 §1)`);
    }
  }
  /** @type {{agent_id: string, delegation?: object, statement?: string}} */
  const validated: AnyRecord = { agent_id: agentId };
  if (validatedDelegation !== undefined) validated.delegation = validatedDelegation;
  if (statement !== undefined) validated.statement = statement;
  return Object.freeze(validated);
}

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
export function buildContexts({ action, policyHash, approvers, requiredApprovals, issuedAt, expiresAt, prevReceiptHash, initiatorAttestation, agentBinding }: AnyRecord): AnyRecord[] {
  if (!action || typeof action !== 'object') throw new Error('buildContexts requires an action');
  if (!action.policy_id) throw new Error('action.policy_id is required');
  if (!Array.isArray(approvers) || approvers.length === 0) {
    throw new Error('buildContexts requires at least one approver');
  }
  // PIP-007 §1: validate once, then copy the SAME object into every context so
  // canonicalize(initiator_attestation) is identical across all of them.
  const attestation = initiatorAttestation === undefined
    ? undefined
    : validateInitiatorAttestation(initiatorAttestation);
  // PIP-008: same discipline — validate once, copy the identical agent_binding
  // object into every context so its canonical form matches across all of them.
  const binding = agentBinding === undefined
    ? undefined
    : validateAgentBinding(agentBinding);
  const aHash = actionHash(action);
  return approvers.map((approver, i) => {
    const ctx: AnyRecord = {
      ep_version: '1.0',
      context_type: 'ep.signoff.v1',
      action_hash: aHash,
      policy_id: action.policy_id,
      policy_hash: policyHash,
      initiator: action.initiator,
      approver,
      approver_index: i + 1,
      required_approvals: requiredApprovals ?? approvers.length,
      nonce: crypto.randomBytes(16).toString('base64url'),
      issued_at: issuedAt,
      expires_at: expiresAt,
    };
    if (prevReceiptHash) ctx.prev_receipt_hash = prevReceiptHash;
    if (attestation !== undefined) ctx.initiator_attestation = attestation;
    if (binding !== undefined) ctx.agent_binding = binding;
    return ctx;
  });
}

/** The 32-byte context digest an approver signs. */
export function contextDigest(context: AnyRecord): Buffer {
  return sha256Bytes(canonicalize(context));
}

// ── signers (Class B/C software keys) ────────────────────────────────────────

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
export function softwareSignerFromPrivateKey({ privateKey, privateKeyB64u, approverKeyId, signedAt, keyClass = 'B' }: AnyRecord): AnyRecord {
  if (keyClass === 'A') {
    throw new Error('Class A signoffs are device-bound (WebAuthn) and require the hosted ceremony, not a local software key');
  }
  const key = privateKey || privateKeyFromPkcs8B64u(privateKeyB64u);
  if (!key) throw new Error('softwareSignerFromPrivateKey requires privateKey or privateKeyB64u');
  return {
    approverKeyId,
    keyClass,
    signedAt,
    sign: (digest: Buffer) => crypto.sign(null, digest, key).toString('base64url'),
  };
}

// ── signoffs (I-D §5.3) ───────────────────────────────────────────────────────

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
export async function collectSignoffs(contexts: AnyRecord[], signers: AnyRecord[]): Promise<AnyRecord[]> {
  if (contexts.length !== signers.length) {
    throw new Error('collectSignoffs: one signer per context, in order');
  }
  const signoffs = [];
  for (let i = 0; i < contexts.length; i++) {
    const digest = contextDigest(contexts[i]);
    const s = signers[i];
    const keyClass = s.keyClass || 'B';
    const signoff: AnyRecord = {
      context_hash: `sha256:${digest.toString('hex')}`,
      key_class: keyClass,
      approver_key_id: s.approverKeyId,
      signed_at: s.signedAt,
    };
    if (keyClass === 'A') {
      if (typeof s.signWebAuthn !== 'function') throw new Error(`Class A signer ${s.approverKeyId} needs signWebAuthn`);
      signoff.webauthn = await s.signWebAuthn(digest);
      signoff.signature = signoff.webauthn.signature;
    } else {
      if (typeof s.sign !== 'function') throw new Error(`signer ${s.approverKeyId} needs sign()`);
      signoff.signature = await s.sign(digest);
    }
    signoffs.push(signoff);
  }
  return signoffs;
}

// ── Merkle log + checkpoint (I-D §6.2) ───────────────────────────────────────

/**
 * Build a sorted-pair Merkle tree over hex leaves; return the root and the
 * positioned inclusion path for leafIndex (the verifier's verifyMerkleAnchor
 * shape). Duplicates the last leaf when a level has an odd count.
 */
export function merkleProof(leaves: string[], leafIndex: number): AnyRecord {
  if (!Array.isArray(leaves) || leaves.length === 0) throw new Error('merkleProof: no leaves');
  let level = [...leaves];
  let index = leafIndex;
  const path = [];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i]; // duplicate last when odd
      next.push(hashPair(left, right));
      if (i === index || i + 1 === index) {
        const isLeft = index === i;
        path.push({ hash: isLeft ? right : left, position: isLeft ? 'right' : 'left' });
        index = next.length - 1;
      }
    }
    level = next;
  }
  return { root: level[0], path };
}

// ── EP-MERKLE-v2 anchor (CAT-2) ─────────────────────────────────────────────
// Domain-separated + positional, with the leaf bound to the receipt payload:
//   leaf_v2   = SHA-256(0x00 || canonicalJSON(payload))
//   branch_v2 = SHA-256(0x01 || leftHex || rightHex)   (positional, not sorted)
// A leaf can never collide with a branch (distinct domain tags), and a verifier
// recomputes leaf_hash from doc.payload, so a v2 anchor can't be lifted onto a
// different receipt. New issuance defaults to v2 via buildReceiptAnchorV2();
// the legacy sorted-pair tree (merkleProof above) remains for already-anchored
// v1 receipts only.
export const MERKLE_V2_ALG = 'EP-MERKLE-v2';
const leafHashV2 = (canonicalPayload: string): string =>
  crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalPayload, 'utf8')]))
    .digest('hex');
const hashPairV2 = (left: string, right: string): string =>
  crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')]))
    .digest('hex');

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
export function merkleProofV2(leaves: string[], leafIndex: number): AnyRecord {
  if (!Array.isArray(leaves) || leaves.length === 0) throw new Error('merkleProofV2: no leaves');
  let level = [...leaves];
  let index = leafIndex;
  const path = [];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) {
        // Odd tail: promote the lone node unchanged (no self-pairing).
        next.push(level[i]);
        if (i === index) index = next.length - 1;
        continue;
      }
      const left = level[i];
      const right = level[i + 1];
      next.push(hashPairV2(left, right));
      if (i === index || i + 1 === index) {
        const isLeft = index === i;
        path.push({ hash: isLeft ? right : left, position: isLeft ? 'right' : 'left' });
        index = next.length - 1;
      }
    }
    level = next;
  }
  return { root: level[0], path };
}

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
export function buildReceiptAnchorV2(payload: AnyRecord, priorLeaves: string[] = []): AnyRecord {
  assertCanonicalizable(payload, 'buildReceiptAnchorV2 payload');
  const leaf = leafHashV2(canonicalize(payload));
  const leaves = [...priorLeaves, leaf];
  const { root, path } = merkleProofV2(leaves, leaves.length - 1);
  return { alg: 'EP-MERKLE-v2', leaf_hash: leaf, merkle_proof: path, merkle_root: root };
}

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
export function assembleAuthorizationReceipt({ receiptId, action, contexts, signoffs, committedAt, log }: AnyRecord): AnyRecord {
  const logPrivateKey = log?.privateKey || (log?.privateKeyB64u && privateKeyFromPkcs8B64u(log.privateKeyB64u));
  if (!logPrivateKey || !log?.logKeyId) {
    throw new Error('assembleAuthorizationReceipt requires log.privateKey (or log.privateKeyB64u) and log.logKeyId');
  }
  assertCanonicalizable({ action, contexts, signoffs }, 'Trust Receipt signed material');

  const receipt: AnyRecord = {
    receipt_id: receiptId,
    action,
    action_hash: actionHash(action),
    contexts,
    signoffs,
    consumption: {
      nonce: crypto.randomBytes(16).toString('base64url'),
      state: 'COMMITTED',
      committed_at: committedAt,
    },
  };

  // EP-MERKLE-v2 log inclusion. Leaf is the domain-separated, payload-bound hash
  // of the canonical receipt WITHOUT log_proof / approver_key_proofs; the tree is
  // positional + domain-separated with NO odd-node duplication (CVE-2012-2459),
  // so the checkpoint root is a unique commitment the operator cannot equivocate.
  // Keep Trust Receipt log leaves on the same tree as single-receipt anchors.
  // priorLeaves MUST be v2 leaf hashes (hex). Legacy v1 minting is retained only
  // via merkleProof()/assembleAuthorizationReceiptLegacyV1() for pre-existing logs.
  const leaf = leafHashV2(canonicalize(receipt));
  const leaves = [...(log.priorLeaves || []), leaf];
  const leafIndex = leaves.length - 1;
  const { root, path } = merkleProofV2(leaves, leafIndex);

  const checkpoint = {
    tree_size: leaves.length,
    root_hash: `sha256:${root}`,
    log_key_id: log.logKeyId,
    merkle_alg: 'EP-MERKLE-v2',
  };
  const log_signature = crypto.sign(null, sha256Bytes(canonicalize(checkpoint)), logPrivateKey).toString('base64url');

  receipt.log_proof = {
    alg: MERKLE_V2_ALG,
    leaf_hash: `sha256:${leaf}`,
    leaf_index: leafIndex,
    inclusion_path: path,
    checkpoint: { ...checkpoint, log_signature },
  };
  return receipt;
}

/**
 * LEGACY (EP-MERKLE-v1) assembler — sorted-pair, undomain-separated, no
 * payload-bound leaf. DEPRECATED and INSECURE (leaf/branch second-preimage +
 * CVE-2012-2459 root equivocation). Retained ONLY to produce compatibility
 * artifacts for the opt-in legacy verification path; NEVER use for new issuance.
 * A receipt from this function verifies under verifyTrustReceipt ONLY when the
 * caller passes { allowLegacyMerkle: true }.
 */
export function assembleAuthorizationReceiptLegacyV1({ receiptId, action, contexts, signoffs, committedAt, log }: AnyRecord): AnyRecord {
  const logPrivateKey = log?.privateKey || (log?.privateKeyB64u && privateKeyFromPkcs8B64u(log.privateKeyB64u));
  if (!logPrivateKey || !log?.logKeyId) {
    throw new Error('assembleAuthorizationReceiptLegacyV1 requires log.privateKey (or log.privateKeyB64u) and log.logKeyId');
  }
  const receipt: AnyRecord = {
    receipt_id: receiptId,
    action,
    action_hash: actionHash(action),
    contexts,
    signoffs,
    consumption: {
      nonce: crypto.randomBytes(16).toString('base64url'),
      state: 'COMMITTED',
      committed_at: committedAt,
    },
  };
  const leaf = sha256hex(canonicalize(receipt));
  const leaves = [...(log.priorLeaves || []), leaf];
  const leafIndex = leaves.length - 1;
  const { root, path } = merkleProof(leaves, leafIndex);
  const checkpoint = { tree_size: leaves.length, root_hash: `sha256:${root}`, log_key_id: log.logKeyId };
  const log_signature = crypto.sign(null, sha256Bytes(canonicalize(checkpoint)), logPrivateKey).toString('base64url');
  receipt.log_proof = { leaf_index: leafIndex, inclusion_path: path, checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}

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
export async function issueAuthorizationReceipt({
  receiptId,
  action,
  policy,
  policyHash: explicitPolicyHash,
  approvers,
  requiredApprovals,
  issuedAt = new Date().toISOString(),
  expiresAt,
  expiresInSeconds = 3600,
  prevReceiptHash,
  initiatorAttestation,
  agentBinding,
  signers,
  committedAt,
  log,
}: AnyRecord): Promise<AnyRecord> {
  if (!receiptId) receiptId = `ep:receipt:${crypto.randomBytes(10).toString('base64url')}`;
  const finalExpiresAt = expiresAt || new Date(new Date(issuedAt).getTime() + expiresInSeconds * 1000).toISOString();
  const finalCommittedAt = committedAt || issuedAt;
  const finalPolicyHash = explicitPolicyHash || policyHash(policy || { policy_id: action?.policy_id || 'local' });

  const contexts = buildContexts({
    action,
    policyHash: finalPolicyHash,
    approvers,
    requiredApprovals,
    issuedAt,
    expiresAt: finalExpiresAt,
    prevReceiptHash,
    initiatorAttestation,
    agentBinding,
  });
  const signoffs = await collectSignoffs(contexts, signers);

  return assembleAuthorizationReceipt({
    receiptId,
    action,
    contexts,
    signoffs,
    committedAt: finalCommittedAt,
    log,
  });
}

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
export async function issueFromKeyBundle({
  keys,
  action,
  policy,
  policyHash: explicitPolicyHash,
  receiptId,
  issuedAt = new Date().toISOString(),
  expiresAt,
  expiresInSeconds = 3600,
  initiatorAttestation,
  agentBinding,
}: AnyRecord): Promise<AnyRecord> {
  if (!keys?.approver?.private_key || !keys?.log?.private_key) {
    throw new Error('keys must be an EP-ISSUER-KEYS-v1 bundle (approver + log private keys)');
  }

  const signer = softwareSignerFromPrivateKey({
    privateKeyB64u: keys.approver.private_key,
    approverKeyId: keys.approver.key_id,
    signedAt: issuedAt,
    keyClass: keys.approver.key_class || 'B',
  });

  const receipt = await issueAuthorizationReceipt({
    receiptId,
    action,
    policy,
    policyHash: explicitPolicyHash,
    approvers: [keys.approver.id],
    requiredApprovals: 1,
    issuedAt,
    expiresAt,
    expiresInSeconds,
    initiatorAttestation,
    agentBinding,
    signers: [signer],
    committedAt: issuedAt,
    log: {
      privateKeyB64u: keys.log.private_key,
      logKeyId: keys.log.key_id,
    },
  });

  return { receipt, verification: verificationMaterialFromKeyBundle(keys) };
}

/** Public verification material (approver public keys + log public key) from a key bundle. */
export function verificationMaterialFromKeyBundle(keys: AnyRecord): AnyRecord {
  return {
    '@version': 'EP-AUTHORIZATION-RECEIPT-VERIFICATION-v1',
    approver_keys: {
      [keys.approver.key_id]: {
        approver_id: keys.approver.id,
        public_key: keys.approver.public_key,
        key_class: keys.approver.key_class || 'B',
        valid_from: keys.approver.valid_from,
        valid_to: keys.approver.valid_to,
      },
    },
    log_public_key: keys.log.public_key,
  };
}

// Canonical protocol vocabulary aliases — the verifier and the I-D call the
// §6.2 document a "Trust Receipt"; keep those wire/internal identifiers stable.
export const assembleTrustReceipt = assembleAuthorizationReceipt;
export const issueTrustReceipt = issueAuthorizationReceipt;
