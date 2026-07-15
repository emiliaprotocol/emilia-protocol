/**
 * EMILIA Protocol — Chained Provenance Receipt (EP-PROVENANCE-CHAIN-v1)
 *
 * @license Apache-2.0
 *
 * REFERENCE IMPLEMENTATION of an ADDITIVE COMPOSITE over EP-RECEIPT-v1.
 * Spec: docs/EP-PROVENANCE-RECEIPT-SPEC.md. EXPERIMENTAL — governed by an
 * Extension PIP; not a production or customer claim; reports no metrics.
 *
 * This module BUNDLES existing artifacts and verifies the bundle by
 * COMPOSITION — it calls the FROZEN EP-RECEIPT-v1 verifier (verifyTrustReceipt,
 * I-D §6.3) verbatim on each embedded receipt and adds NO new trust:
 *
 *   root human signoff (EP-RECEIPT-v1)
 *     -> ordered delegation chain (DRP refs; each scope-contained in its parent)
 *       -> per-action approval (EP-RECEIPT-v1)
 *         -> execution reference (hash-bound to the approved action)
 *   (+ optional scoped agent_identity CLAIM, + optional named-owner liability)
 *
 * The EP Core (PIP-001) is frozen: this file does NOT modify the
 * EP-RECEIPT-v1 wire format, canonicalization, or signature. It imports the
 * existing verifier/issuer; it re-implements nothing cryptographic.
 *
 * FAIL CLOSED: any broken signature, scope-containment violation, tampered
 * leaf, missing per-action approval for an irreversible action, or a chain
 * that does not terminate in a root human signoff ⇒ { valid: false }.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';

// Compose the FROZEN v1 verifier and the v1 issuer's canonicalizer. These are
// the single source of cryptographic truth; this module adds no new trust.
// Imported by relative path to the in-repo package source — the same
// convention lib/trust-receipt/issuer.js uses for '../../packages/issue/index.js'
// — so this file uses the identical bytes as the published @emilia-protocol/*
// packages by construction.
import { verifyTrustReceipt } from '../../packages/verify/index.js';
import { canonicalize } from '../../packages/issue/index.js';

export const PROVENANCE_VERSION = 'EP-PROVENANCE-CHAIN-v1';

// Default human signoff classes: Class A == WebAuthn user-verified (a human
// with biometric/PIN). Fail-closed default; relax only for tests.
const DEFAULT_HUMAN_KEY_CLASSES = ['A'];

// ── small helpers ─────────────────────────────────────────────────────────

function hexOf(h) {
  return String(h || '').replace(/^sha256:/, '').toLowerCase();
}

/** A receipt carries a human signoff if any signoff has a human key_class. */
function hasHumanSignoff(receipt, humanClasses) {
  const set = new Set(humanClasses);
  const signoffs = Array.isArray(receipt?.signoffs) ? receipt.signoffs : [];
  return signoffs.some((s) => set.has(s?.key_class));
}

/** Approvers named by a receipt's contexts (the entities that signed). */
function receiptApprovers(receipt) {
  const ids = new Set();
  for (const ctx of receipt?.contexts || []) {
    if (ctx?.approver) ids.add(ctx.approver);
  }
  for (const s of receipt?.signoffs || []) {
    if (s?.approver_key_id) ids.add(s.approver_key_id);
  }
  return ids;
}

/** action_type the execution actually ran, read from the per-action approval. */
function executedActionType(doc) {
  return doc?.action_approval?.receipt?.action?.action_type ?? null;
}

/** Latest expires_at across a receipt's contexts (the root's temporal bound). */
function latestContextExpiry(receipt) {
  let max = null;
  for (const ctx of receipt?.contexts || []) {
    const t = Date.parse(ctx?.expires_at);
    if (!Number.isNaN(t) && (max === null || t > max)) max = t;
  }
  return max;
}

/** committed_at of a receipt's consumption record (ms epoch, or null). */
function committedAtMs(receipt) {
  const t = Date.parse(receipt?.consumption?.committed_at);
  return Number.isNaN(t) ? null : t;
}

/**
 * One action-type token is permitted by a scope array. Supports exact match,
 * '*' (any), and 'prefix.*' globs (e.g. 'payment.*' permits 'payment.release').
 */
function scopePermits(scope, actionType) {
  if (!Array.isArray(scope) || !actionType) return false;
  for (const grant of scope) {
    if (grant === '*' || grant === actionType) return true;
    if (typeof grant === 'string' && grant.endsWith('.*')) {
      const prefix = grant.slice(0, -2);
      if (actionType === prefix || actionType.startsWith(prefix + '.')) return true;
    }
  }
  return false;
}

/**
 * Parent-scope-containment for one hop (DelegateCannotExceedPrincipal, I-D §8):
 *   - every child action token is permitted by the parent scope;
 *   - child value cap <= parent value cap (null child inherits parent cap);
 *   - child expiry <= parent expiry.
 * Returns a list of human-readable violations (empty == contained).
 */
function scopeContainmentViolations(parent, child) {
  const violations = [];

  // 1. action-type containment
  for (const token of child.scope || []) {
    // a child glob is contained iff its prefix is permitted by the parent
    const probe = typeof token === 'string' && token.endsWith('.*') ? token.slice(0, -2) : token;
    if (!scopePermits(parent.scope, probe)) {
      violations.push(`child scope "${token}" exceeds parent scope [${(parent.scope || []).join(', ')}]`);
    }
  }

  // 2. value containment
  const parentCap = parent.max_value_usd;
  let childCap = child.max_value_usd;
  if (childCap === null || childCap === undefined) childCap = parentCap; // inherit, not uncap
  if (parentCap !== null && parentCap !== undefined) {
    if (childCap === null || childCap === undefined || Number(childCap) > Number(parentCap)) {
      violations.push(`child max_value_usd ${childCap} exceeds parent cap ${parentCap}`);
    }
  }

  // 3. temporal containment
  const pExp = Date.parse(parent.expires_at);
  const cExp = Date.parse(child.expires_at);
  if (!Number.isNaN(pExp) && !Number.isNaN(cExp) && cExp > pExp) {
    violations.push(`child expires_at ${child.expires_at} is after parent expires_at ${parent.expires_at}`);
  }

  return violations;
}

/**
 * Verify a detached signature attestation (delegation proof, agent identity,
 * liability). Returns true/false; never throws. This is the ONLY signature
 * primitive added here, and it grants NO trust by itself — callers treat its
 * result as evidence and gate accordingly.
 */
function verifyDetachedSignature(att) {
  try {
    if (!att?.signed_payload_b64u || !att?.signature_b64u || !att?.public_key) return false;
    if (att.algorithm && att.algorithm !== 'Ed25519') return false;
    const key = crypto.createPublicKey({
      key: Buffer.from(att.public_key, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(
      null,
      Buffer.from(att.signed_payload_b64u, 'base64url'),
      key,
      Buffer.from(att.signature_b64u, 'base64url'),
    );
  } catch {
    return false;
  }
}

// The delegation fields whose CANONICAL bytes the proof signature MUST cover.
// Mirrors lib/delegation.js's record shape. The verifier independently
// recomputes these bytes — a producer cannot claim a proof over one set of
// fields while presenting a widened/tampered set (DelegationFieldsAreSigned).
const DELEGATION_PROOF_FIELDS = [
  'delegation_id', 'delegator', 'delegatee', 'scope', 'max_value_usd', 'expires_at', 'constraints',
];

/** Canonical bytes the delegation proof signature is bound to (the link's own fields). */
function delegationProofBytes(link) {
  const subset = {};
  for (const f of DELEGATION_PROOF_FIELDS) subset[f] = link[f] ?? null;
  return Buffer.from(canonicalize(subset), 'utf8');
}

/**
 * Convert an action_type token into the scope grant the root receipt actually
 * authorized. A root that signed off on action_type "payment.release" authorizes
 * exactly "payment.release" (NOT '*'). The root scope is DERIVED, never assumed.
 */
function rootAuthorizedScope(rootReceipt) {
  const at = rootReceipt?.action?.action_type;
  return typeof at === 'string' && at.length > 0 ? [at] : [];
}

/**
 * Monotonic constraint narrowing (AgentROA "tighten-only" algebra): a child
 * delegation may add constraints but never RELAX one its parent set. Numeric
 * ceilings may only decrease, array allow-lists may only shrink (subset), other
 * types must be unchanged, and a parent's constraint key may not be dropped.
 */
function constraintsMonotonic(parentC, childC) {
  const p = parentC || {};
  const c = childC || {};
  for (const k of Object.keys(p)) {
    if (!(k in c)) return false;
    const pv = p[k];
    const cv = c[k];
    if (typeof pv === 'number' && typeof cv === 'number') {
      if (cv > pv) return false;
    } else if (Array.isArray(pv) && Array.isArray(cv)) {
      const pset = new Set(pv.map((x) => canonicalize(x)));
      if (!cv.every((x) => pset.has(canonicalize(x)))) return false;
    } else if (canonicalize(pv) !== canonicalize(cv)) {
      return false;
    }
  }
  return true;
}

// ── assembly ────────────────────────────────────────────────────────────────

/**
 * Assemble a Chained Provenance Receipt from already-issued v1 receipts and
 * DRP delegation references. This is pure data composition — it mints no keys,
 * signs no receipts, and adds no trust. The receipts must have been issued
 * elsewhere (e.g. packages/issue assembleAuthorizationReceipt).
 *
 * @param {object} args
 * @param {{ receipt: object, verification: object, human_key_classes?: string[] }} args.rootSignoff
 *   - the root human-signoff EP-RECEIPT-v1 + its pinned verification material
 * @param {Array<object>} [args.delegationChain] - ordered DRP delegation links
 * @param {{ receipt: object, verification: object }} [args.actionApproval]
 *   - the per-action approval EP-RECEIPT-v1 + its verification material
 * @param {object} args.execution - { action_hash, irreversible, executed_at, ... }
 * @param {object} [args.agentIdentity] - scoped agent-identity CLAIM
 * @param {object} [args.liability] - named-owner liability attestation (evidence)
 * @param {object} [args.metadata] - untrusted metadata
 * @returns {object} an EP-PROVENANCE-CHAIN-v1 document
 */
export function assembleProvenance({
  rootSignoff,
  delegationChain = [],
  actionApproval = undefined,
  execution,
  agentIdentity = undefined,
  liability = undefined,
  metadata = undefined,
}) {
  if (!rootSignoff?.receipt || !rootSignoff?.verification) {
    throw new Error('assembleProvenance requires rootSignoff.{receipt,verification}');
  }
  if (!execution?.action_hash || typeof execution.irreversible !== 'boolean') {
    throw new Error('assembleProvenance requires execution.{action_hash,irreversible}');
  }
  if (execution.irreversible && !actionApproval?.receipt) {
    throw new Error('assembleProvenance: an irreversible execution requires actionApproval.receipt (fail-closed)');
  }

  // Stamp/normalize sequence numbers in chain order so the chain is ordered.
  const chain = delegationChain.map((link, i) => ({
    sequence: link.sequence ?? i,
    ...link,
  }));

  const doc = {
    '@version': PROVENANCE_VERSION,
    root_signoff: {
      receipt: rootSignoff.receipt,
      verification: rootSignoff.verification,
      human_key_classes: rootSignoff.human_key_classes || DEFAULT_HUMAN_KEY_CLASSES,
    },
    delegation_chain: chain,
    execution,
  };
  if (actionApproval?.receipt) {
    doc.action_approval = {
      receipt: actionApproval.receipt,
      verification: actionApproval.verification,
    };
  }
  if (agentIdentity) doc.agent_identity = agentIdentity;
  if (liability) doc.liability = liability;
  doc.provenance_metadata = {
    chain_depth: chain.length,
    assembled_at: new Date().toISOString(),
    note: 'Composition of existing EP-RECEIPT-v1 receipts + DRP delegation references. No new trust.',
    ...(metadata || {}),
  };
  return doc;
}

// ── verification ──────────────────────────────────────────────────────────

/**
 * Verify a Chained Provenance Receipt fully offline. FAIL CLOSED.
 *
 * Composes the FROZEN v1 verifier (verifyTrustReceipt) on each embedded
 * receipt and layers chain/containment checks on top. Adds NO new trust: the
 * cryptographic verdict on each receipt is exactly verifyTrustReceipt()'s.
 *
 * Rejects the bundle (valid:false) on ANY of:
 *   - root receipt fails v1 verification;
 *   - root receipt carries no human signoff;
 *   - execution is irreversible but there is no valid per-action approval
 *     (or the approval carries no human signoff);
 *   - per-action approval receipt fails v1 verification;
 *   - execution.action_hash != action_approval.receipt.action_hash;
 *   - delegation chain head does not bind to a root approver;
 *   - any delegation is expired, unsigned (default), or signature-invalid;
 *   - any scope-containment violation along the chain;
 *   - the leaf delegation does not permit the executed action type.
 *
 * Optional agent_identity / liability blocks are ADVISORY: verified-if-signed
 * and reported, never able to make an otherwise-invalid bundle valid.
 *
 * @param {object} doc - an EP-PROVENANCE-CHAIN-v1 document
 * @param {object} [opts]
 * @param {string[]} [opts.humanKeyClasses=['A']] - key_class values counted as human.
 *   This is the ONLY source of human-class truth; the per-document
 *   root_signoff.human_key_classes field is NOT trusted to widen it.
 * @param {Record<string,{public_key:string}>} [opts.delegationKeys={}] - pinned
 *   proof keys per delegator id (mirrors root approver_keys). A delegation whose
 *   delegator has no pinned key, or whose proof key differs, is rejected.
 * @param {object} opts.rootVerification - relying-party-pinned
 *   {approver_keys, log_public_key, rp_id, allowed_origins} for
 *   root_signoff.receipt. Verification
 *   material carried inside `doc` is never a trust root.
 * @param {object} opts.actionVerification - relying-party-pinned
 *   {approver_keys, log_public_key, rp_id, allowed_origins} for
 *   action_approval.receipt.
 * @param {(exec:object)=>boolean} [opts.reversibilityAsserted] - verifier-supplied
 *   predicate that INDEPENDENTLY asserts the execution is reversible. Only this
 *   (never the producer's execution.irreversible flag) can drop the per-action
 *   approval requirement. Absent it, approval is required by default (fail-closed).
 * @param {boolean} [opts.allowUnsignedDelegations=false] - relax delegation proof requirement
 * @param {number}  [opts.now=Date.now()] - reference time for expiry checks (ms)
 * @param {boolean} [opts.requireActionApprovalAlways=false] - re-mandate per-action
 *   approval even when reversibility is independently asserted
 * @returns {{ valid:boolean, checks:object, errors:string[], links:object[],
 *             agent_identity:object|null, liability:object|null }}
 */
export function verifyProvenanceOffline(doc, opts = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const humanKeyClasses = opts.humanKeyClasses || DEFAULT_HUMAN_KEY_CLASSES;
  const allowUnsignedDelegations = opts.allowUnsignedDelegations === true;
  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  const requireActionApprovalAlways = opts.requireActionApprovalAlways === true;

  const checks = {
    version: false,
    root_receipt_valid: false,
    root_human_signoff: false,
    per_action_required: true,    // satisfied unless an irreversible action lacks approval
    action_receipt_valid: true,   // vacuously true when no approval is needed
    action_human_signoff: true,   // "
    execution_binding: true,      // "
    chain_anchored: true,         // head binds to a root approver (vacuous if empty)
    chain_links_bound: true,      // each hop binds to the prior delegatee
    delegations_signed: true,     // proof over the link's OWN canonical fields
    proof_key_bound: true,        // proof key bound to the named delegator
    delegations_not_expired: true,
    scope_containment: true,
    constraints_monotonic: true,
    leaf_permits_action: true,
    temporal_containment: true,
  };
  const errors = [];
  const links = [];
  const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
  const validVerificationProfile = (profile) => (
    profile
    && typeof profile === 'object'
    && profile.approver_keys
    && typeof profile.approver_keys === 'object'
    && typeof profile.log_public_key === 'string'
    && profile.log_public_key.length > 0
    && typeof profile.rp_id === 'string'
    && profile.rp_id.length > 0
    && Array.isArray(profile.allowed_origins)
    && profile.allowed_origins.length > 0
    && profile.allowed_origins.every((origin) => typeof origin === 'string' && origin.length > 0)
  );

  // ── 0. version ───────────────────────────────────────────────────────────
  if (doc?.['@version'] !== PROVENANCE_VERSION) {
    errors.push(`unsupported version: ${doc?.['@version']}`);
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  checks.version = true;

  // ── 1. root human signoff (the required termination) ─────────────────────
  const root = doc.root_signoff;
  const rootVerification = opts.rootVerification || opts.root_verification;
  if (!root?.receipt) {
    fail('root_receipt_valid', 'missing root_signoff.receipt');
  } else if (!validVerificationProfile(rootVerification)) {
    fail('root_receipt_valid', 'relying-party root verification profile is required');
  } else {
    const r0 = verifyTrustReceipt(root.receipt, {
      approverKeys: rootVerification.approver_keys,
      logPublicKey: rootVerification.log_public_key,
      rpId: rootVerification.rp_id,
      allowedOrigins: rootVerification.allowed_origins,
    });
    checks.root_receipt_valid = r0.valid;
    if (!r0.valid) errors.push(`root receipt failed v1 verification: ${(r0.errors || []).join('; ')}`);

    // Human classes are a VERIFIER-side policy only. The per-document
    // root_signoff.human_key_classes field is NOT trusted to widen 'human' — a
    // producer must not be able to mark a Class-B software key as a human
    // signoff. (Mirrors the action_approval human check, which already uses the
    // verifier's humanKeyClasses.)
    checks.root_human_signoff = hasHumanSignoff(root.receipt, humanKeyClasses);
    if (!checks.root_human_signoff) {
      errors.push(`root receipt carries no human signoff (need key_class in [${humanKeyClasses.join(', ')}])`);
    }
  }

  // ── 2. per-action approval (required by default; fail-closed) ────────────
  // A producer's `execution.irreversible` flag is UNTRUSTED: it can never DROP
  // the per-action approval requirement. Reversibility must be asserted
  // INDEPENDENTLY of the producer's self-label, via a verifier-supplied
  // predicate opts.reversibilityAsserted(exec) -> boolean. Absent such an
  // independent assertion, approval is REQUIRED regardless of the flag. (The
  // flag may still RAISE the bar — an explicit irreversible:true additionally
  // forces a human signoff on the approval below — but it may never lower it.)
  const exec = doc.execution || {};
  const reversibilityAsserted =
    typeof opts.reversibilityAsserted === 'function'
      ? opts.reversibilityAsserted(exec) === true
      : false;
  // Required unless reversibility is independently asserted. requireActionApprovalAlways
  // is retained as a hard override that re-mandates approval even if asserted reversible.
  const needApproval = requireActionApprovalAlways || !reversibilityAsserted;
  const approval = doc.action_approval;
  const actionVerification = opts.actionVerification || opts.action_verification;

  if (needApproval && !approval?.receipt) {
    fail('per_action_required',
      'execution is irreversible (or approval is always required) but no action_approval is present');
  }

  if (approval?.receipt) {
    if (!validVerificationProfile(actionVerification)) {
      fail('action_receipt_valid', 'relying-party action verification profile is required');
    } else {
      const ra = verifyTrustReceipt(approval.receipt, {
        approverKeys: actionVerification.approver_keys,
        logPublicKey: actionVerification.log_public_key,
        rpId: actionVerification.rp_id,
        allowedOrigins: actionVerification.allowed_origins,
      });
      checks.action_receipt_valid = ra.valid;
      if (!ra.valid) errors.push(`action_approval receipt failed v1 verification: ${(ra.errors || []).join('; ')}`);
    }

    if (exec.irreversible === true) {
      checks.action_human_signoff = hasHumanSignoff(approval.receipt, humanKeyClasses);
      if (!checks.action_human_signoff) {
        errors.push('action_approval for an irreversible action carries no human signoff');
      }
    }

    // execution must be hash-bound to the approved action.
    checks.execution_binding = hexOf(exec.action_hash) === hexOf(approval.receipt.action_hash);
    if (!checks.execution_binding) {
      errors.push('execution.action_hash does not match action_approval.receipt.action_hash');
    }
  }

  // ── 3. ordered delegation chain + scope containment ──────────────────────
  const chain = Array.isArray(doc.delegation_chain) ? [...doc.delegation_chain] : [];
  chain.sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));

  // The proof-key map binds each delegation's proof public key to the named
  // delegator (mirrors root_signoff approver_keys). Without an entry for a
  // delegator, that delegation's proof cannot be key-bound and is rejected.
  const delegationKeys = opts.delegationKeys || {};

  // Root authority is DERIVED from what the root receipt actually authorized —
  // never hardcoded to '*'. The head delegation must name a root approver, and
  // the whole chain (and a chain-less execution) is bounded by this scope, the
  // root value cap, and the root's context expiry.
  const rootApprovers = doc.root_signoff?.receipt ? receiptApprovers(doc.root_signoff.receipt) : new Set();
  const rootExpiry = latestContextExpiry(doc.root_signoff?.receipt);
  const rootScope = doc.root_signoff?.receipt ? rootAuthorizedScope(doc.root_signoff.receipt) : [];
  const rootAuthority = {
    scope: rootScope,                   // DERIVED from root_signoff.receipt.action
    max_value_usd: null,
    expires_at: rootExpiry !== null ? new Date(rootExpiry).toISOString() : undefined,
    id: '(root human signoff)',
  };
  let parent = rootAuthority;

  if (chain.length > 0) {
    const head = chain[0];
    // Anchor ONLY on the SIGNED delegator. parent_ref is not in
    // DELEGATION_PROOF_FIELDS (unsigned, attacker-controlled).
    checks.chain_anchored = rootApprovers.has(head.delegator);
    if (!checks.chain_anchored) {
      errors.push(`delegation chain head delegator "${head.delegator}" does not name a root-receipt approver`);
    }
  }

  let prevDelegatee = null; // delegatee of the previous hop, for inter-hop binding
  for (const link of chain) {
    const linkReport = { sequence: link.sequence, delegation_id: link.delegation_id, ok: true, issues: [] };

    // (a) inter-hop binding: every hop after the head MUST bind to the prior
    // delegatee via BOTH parent_ref and delegator. The head is anchored to a
    // root approver above; here we enforce the i>=1 links.
    if (prevDelegatee !== null) {
      const boundByParentRef = link.parent_ref === prevDelegatee;
      const boundByDelegator = link.delegator === prevDelegatee;
      if (!boundByParentRef || !boundByDelegator) {
        checks.chain_links_bound = false;
        linkReport.ok = false;
        linkReport.issues.push('inter_hop_link_broken');
        errors.push(
          `delegation ${link.delegation_id}: parent_ref "${link.parent_ref}" / delegator "${link.delegator}" `
          + `does not bind to prior delegatee "${prevDelegatee}"`,
        );
      }
    }

    // not expired at reference time
    const exp = Date.parse(link.expires_at);
    if (Number.isNaN(exp) || exp < now) {
      checks.delegations_not_expired = false;
      linkReport.ok = false;
      linkReport.issues.push('expired');
      errors.push(`delegation ${link.delegation_id} is expired`);
    }

    // (b)+(c) proof of the delegation record itself. The signature MUST be over
    // the CANONICAL bytes of THIS link's own fields (so scope/cap/expiry cannot
    // be tampered after signing), AND the proof key MUST be the key bound to the
    // named delegator (so an attacker key cannot be substituted).
    if (link.proof) {
      const sigOk = verifyDetachedSignature(link.proof);
      const boundBytes = delegationProofBytes(link);
      const presentedBytes = (() => {
        try { return Buffer.from(link.proof.signed_payload_b64u || '', 'base64url'); } catch { return Buffer.alloc(0); }
      })();
      const bytesMatch = sigOk && presentedBytes.equals(boundBytes);
      if (!sigOk || !bytesMatch) {
        checks.delegations_signed = false;
        linkReport.ok = false;
        linkReport.issues.push(sigOk ? 'proof_not_over_own_fields' : 'signature_invalid');
        errors.push(
          sigOk
            ? `delegation ${link.delegation_id} proof does not sign the delegation's own canonical fields (tampered)`
            : `delegation ${link.delegation_id} proof signature does not verify`,
        );
      }

      // (c) proof key must be the key pinned for the named delegator.
      const boundKey = delegationKeys[link.delegator]?.public_key;
      if (!boundKey) {
        checks.proof_key_bound = false;
        linkReport.ok = false;
        linkReport.issues.push('no_pinned_delegator_key');
        errors.push(`delegation ${link.delegation_id}: no pinned key for delegator "${link.delegator}" (cannot bind proof)`);
      } else if (boundKey !== link.proof.public_key) {
        checks.proof_key_bound = false;
        linkReport.ok = false;
        linkReport.issues.push('proof_key_not_bound_to_delegator');
        errors.push(`delegation ${link.delegation_id}: proof public key is not the key bound to delegator "${link.delegator}"`);
      }
    } else if (!allowUnsignedDelegations) {
      checks.delegations_signed = false;
      linkReport.ok = false;
      linkReport.issues.push('unsigned');
      errors.push(`delegation ${link.delegation_id} has no verifiable proof (fail-closed)`);
    }

    // scope containment vs parent
    const violations = scopeContainmentViolations(parent, link);
    if (violations.length > 0) {
      checks.scope_containment = false;
      linkReport.ok = false;
      linkReport.issues.push(...violations);
      for (const v of violations) errors.push(`delegation ${link.delegation_id}: ${v}`);
    }
    // monotonic constraint narrowing vs parent (AgentROA tighten-only algebra)
    if (!constraintsMonotonic(parent.constraints, link.constraints)) {
      checks.constraints_monotonic = false;
      linkReport.ok = false;
      linkReport.issues.push('constraints_relaxed');
      errors.push(`delegation ${link.delegation_id}: constraints relax a parent restriction (not monotonic)`);
    }

    links.push(linkReport);
    // Persist the EFFECTIVE (inherited) value cap forward — never the raw link
    // cap. A null/omitted child cap must inherit the parent's effective cap, or
    // a null mid-chain hop would re-open an unbounded cap for every descendant
    // (DelegateCannotExceedPrincipal / spec §4.2).
    let effectiveCap;
    if (link.max_value_usd === null || link.max_value_usd === undefined) {
      effectiveCap = parent.max_value_usd;            // inherit parent's effective cap
    } else if (parent.max_value_usd === null || parent.max_value_usd === undefined) {
      effectiveCap = link.max_value_usd;              // parent uncapped → child sets the cap
    } else {
      effectiveCap = Math.min(Number(link.max_value_usd), Number(parent.max_value_usd));
    }
    parent = { ...link, max_value_usd: effectiveCap };  // narrow down the chain
    prevDelegatee = link.delegatee;
  }

  // The executed action MUST be permitted by the leaf authority — and when the
  // chain is empty, the leaf authority IS the derived root authority. This
  // constrains a chain-less (direct) execution to the root's actual scope.
  const actionType = executedActionType(doc);
  if (!actionType) {
    checks.leaf_permits_action = false;
    errors.push('cannot determine executed action_type from action_approval (no per-action approval present)');
  } else if (!scopePermits(parent.scope, actionType)) {
    checks.leaf_permits_action = false;
    const where = chain.length > 0 ? 'leaf delegation' : 'root authority';
    errors.push(`${where} scope [${(parent.scope || []).join(', ')}] does not permit executed action "${actionType}"`);
  }

  // per-action approval commit time must fall within the leaf's (or root's) window
  {
    const commit = approval?.receipt ? committedAtMs(approval.receipt) : null;
    const leafExp = Date.parse(parent.expires_at);
    if (commit !== null && !Number.isNaN(leafExp) && commit > leafExp) {
      checks.temporal_containment = false;
      errors.push('per-action approval committed_at is after the leaf delegation expires_at');
    }
  }

  // ── 4. optional advisory claims (reported, NOT trusted) ──────────────────
  let agentIdentity = null;
  if (doc.agent_identity) {
    agentIdentity = {
      agent_id: doc.agent_identity.agent_id ?? null,
      claimed_by: doc.agent_identity.claimed_by ?? null,
      // a CLAIM, never proof of strong agent identity
      claim_only: true,
      attestation_signature_valid: doc.agent_identity.attestation
        ? verifyDetachedSignature(doc.agent_identity.attestation)
        : null,
    };
    if (agentIdentity.attestation_signature_valid === false) {
      errors.push('advisory: agent_identity.attestation signature does not verify (not gating)');
    }
  }

  let liability = null;
  if (doc.liability) {
    liability = {
      owner: doc.liability.owner ?? null,
      owner_name: doc.liability.owner_name ?? null,
      // EVIDENCE of a named accountable owner, never a legal determination
      evidence_only: true,
      attestation_signature_valid: doc.liability.attestation
        ? verifyDetachedSignature(doc.liability.attestation)
        : null,
    };
    if (liability.attestation_signature_valid === false) {
      errors.push('advisory: liability.attestation signature does not verify (not gating)');
    }
  }

  // ── verdict ──────────────────────────────────────────────────────────────
  // valid == conjunction of the gating checks ONLY. The advisory blocks above
  // are deliberately excluded: they can never make an invalid bundle valid.
  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors, links, agent_identity: agentIdentity, liability };
}

const provenance = { assembleProvenance, verifyProvenanceOffline, PROVENANCE_VERSION };
export default provenance;
