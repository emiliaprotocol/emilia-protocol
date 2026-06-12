/**
 * Trust Receipt issuer — emits I-D Section 6.2 Trust Receipts.
 * @license Apache-2.0
 *
 * The other half of @emilia-protocol/verify's verifyTrustReceipt(): assembles
 * and signs the full receipt — canonical Action Object + action hash,
 * per-approver Authorization Contexts, signoffs over the context digests,
 * consumption record, Merkle log inclusion, and an Ed25519 log-signed
 * checkpoint — using byte-level choices identical to the verifier's reference
 * profile (draft-schrock-ep-authorization-receipts Section 6.3):
 *
 *   - hashes are "sha256:<hex>"; canonicalization is recursive sorted-key JSON
 *   - a Class B/C signoff signs the raw 32-byte context digest (Ed25519)
 *   - a Class A signoff is a WebAuthn assertion whose challenge is
 *     base64url(context digest)
 *   - the receipt leaf is SHA-256 of the canonical receipt WITHOUT log_proof /
 *     approver_key_proofs; inclusion_path is positioned steps
 *   - the checkpoint signature is Ed25519 over the canonical checkpoint
 *     WITHOUT log_signature
 *
 * Signing is delegated: the issuer never holds approver keys. Each approver
 * entry supplies a callback (a software key in tests, the WebAuthn ceremony in
 * production). Receipts this module emits verify 7/7 under the published
 * verifier — proven in tests/trust-receipt-issuer.test.js.
 */

import crypto from 'node:crypto';

// ── canonicalization + hashing (byte-identical to packages/verify) ───────────

export function canonicalize(value) {
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

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hashPair = (a, b) => { const s = [a, b].sort(); return sha256hex(s[0] + s[1]); };

/** "sha256:<hex>" action hash of the canonical Action Object (I-D §3). */
export function actionHash(action) {
  return `sha256:${sha256hex(canonicalize(action))}`;
}

// ── contexts (I-D §4) ─────────────────────────────────────────────────────────

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
 * @returns {object[]} contexts
 */
export function buildContexts({ action, policyHash, approvers, requiredApprovals, issuedAt, expiresAt, prevReceiptHash }) {
  if (!action || !Array.isArray(approvers) || approvers.length === 0) {
    throw new Error('buildContexts requires an action and at least one approver');
  }
  const aHash = actionHash(action);
  return approvers.map((approver, i) => {
    const ctx = {
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
    return ctx;
  });
}

/** The 32-byte context digest an approver signs. */
export function contextDigest(context) {
  return crypto.createHash('sha256').update(canonicalize(context), 'utf8').digest();
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
 *   sign?: (digest: Buffer) => string,            // Class B/C: Ed25519 over the digest, b64u
 *   signWebAuthn?: (digest: Buffer) => { authenticator_data:string, client_data_json:string, signature:string },
 * }>} signers
 * @returns {Promise<object[]>} signoffs
 */
export async function collectSignoffs(contexts, signers) {
  if (contexts.length !== signers.length) {
    throw new Error('collectSignoffs: one signer per context, in order');
  }
  const signoffs = [];
  for (let i = 0; i < contexts.length; i++) {
    const digest = contextDigest(contexts[i]);
    const s = signers[i];
    const keyClass = s.keyClass || 'B';
    const signoff = {
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

// Build a sorted-pair Merkle tree over hex leaves; return the root and the
// positioned inclusion path for leafIndex (the verifier's verifyMerkleAnchor
// shape).
export function merkleProof(leaves, leafIndex) {
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

/**
 * Assemble and log-sign the complete Trust Receipt.
 *
 * @param {object} args
 * @param {string} args.receiptId
 * @param {object} args.action
 * @param {object[]} args.contexts
 * @param {object[]} args.signoffs
 * @param {string} args.committedAt - ISO-8601 consumption time
 * @param {object} args.log
 * @param {crypto.KeyObject} args.log.privateKey - the log's Ed25519 signing key
 * @param {string} args.log.logKeyId - e.g. "ep:log:acme#1"
 * @param {string[]} [args.log.priorLeaves] - existing log leaves (hex), oldest first
 * @returns {object} the Section 6.2 Trust Receipt (verifies under verifyTrustReceipt)
 */
export function assembleTrustReceipt({ receiptId, action, contexts, signoffs, committedAt, log }) {
  if (!log?.privateKey || !log?.logKeyId) throw new Error('assembleTrustReceipt requires log.privateKey and log.logKeyId');

  const receipt = {
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

  // Leaf = canonical receipt WITHOUT log_proof / approver_key_proofs.
  const leaf = sha256hex(canonicalize(receipt));
  const leaves = [...(log.priorLeaves || []), leaf];
  const leafIndex = leaves.length - 1;
  const { root, path } = merkleProof(leaves, leafIndex);

  const checkpoint = {
    tree_size: leaves.length,
    root_hash: `sha256:${root}`,
    log_key_id: log.logKeyId,
  };
  const log_signature = crypto.sign(
    null,
    crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(),
    log.privateKey,
  ).toString('base64url');

  receipt.log_proof = {
    leaf_index: leafIndex,
    inclusion_path: path,
    checkpoint: { ...checkpoint, log_signature },
  };
  return receipt;
}

/**
 * One-call issuance: contexts → signoffs → assembled, log-signed receipt.
 */
export async function issueTrustReceipt({
  receiptId, action, policyHash, approvers, requiredApprovals,
  issuedAt, expiresAt, prevReceiptHash, signers, committedAt, log,
}) {
  const contexts = buildContexts({ action, policyHash, approvers, requiredApprovals, issuedAt, expiresAt, prevReceiptHash });
  const signoffs = await collectSignoffs(contexts, signers);
  return assembleTrustReceipt({ receiptId, action, contexts, signoffs, committedAt, log });
}
