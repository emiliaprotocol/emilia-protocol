// SPDX-License-Identifier: Apache-2.0
/**
 * EP-PROVENANCE-CHAIN-v1 — offline verifier for a chained provenance receipt.
 *
 * Offline-package port of lib/provenance/chain.js (verifier only). Spec:
 * docs/EP-PROVENANCE-RECEIPT-SPEC.md. It composes the FROZEN §6.2 receipt
 * verifier (verifyTrustReceipt) verbatim on each embedded receipt and layers the
 * delegation-chain / scope-containment checks on top — adding NO new trust:
 *
 *   root human signoff (EP-RECEIPT-v1)
 *     -> ordered delegation chain (each scope-contained in its parent)
 *       -> per-action approval (EP-RECEIPT-v1)
 *         -> execution reference (hash-bound to the approved action)
 *
 * This is the human-authority ROOT for downstream machine delegation/execution
 * (the integration point with machine-execution attestation): it proves who
 * authorized, that each hop stayed within its principal's scope/cap/expiry
 * (DelegateCannotExceedPrincipal), and that the executed action is what a named
 * human approved. FAIL CLOSED on any broken signature, scope violation, tampered
 * leaf, or missing per-action approval for an irreversible action.
 */
import crypto from 'node:crypto';
import { verifyTrustReceipt, canonicalize } from './index.js';
import { canonicalizeStrictJson } from './strict-json.js';
import {
  verifyAgileSignatureSet,
  type AgilityOptions,
} from './pq-signature-agility.js';

type Obj = Record<string, any>;

interface ProvenanceOptions {
  humanKeyClasses?: string[];
  allowUnsignedDelegations?: boolean;
  now?: number;
  requireActionApprovalAlways?: boolean;
  rootVerification?: Obj;
  root_verification?: Obj;
  actionVerification?: Obj;
  action_verification?: Obj;
  delegationKeys?: Record<string, Obj>;
  reversibilityAsserted?: (execution: Obj) => boolean;
}

export const PROVENANCE_VERSION = 'EP-PROVENANCE-CHAIN-v1';
const DEFAULT_HUMAN_KEY_CLASSES = ['A'];

// Normalize to a bare lowercase hex digest, but ONLY if it is a well-formed
// 64-char SHA-256. A malformed value returns '' (which never equals a real
// digest), so comparisons fail closed instead of matching on a truncated/garbage
// string — and stay consistent across language implementations. (HI-2)
const hexOf = (h: unknown): string => {
  const s = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
};

// A concrete action_type is dot-separated non-empty segments. Rejecting empty
// segments closes the "double-dot" scope-escalation bypass where "a..b"
// .startsWith("a.") would let an attacker slip past a "a.*" containment. (SEV-1)
const WELL_FORMED_ACTION_TYPE = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
function isWellFormedActionType(s: unknown): s is string {
  return typeof s === 'string' && WELL_FORMED_ACTION_TYPE.test(s);
}

function isWellFormedScopeToken(s: unknown): s is string {
  if (s === '*') return true;
  if (typeof s !== 'string') return false;
  return s.endsWith('.*')
    ? isWellFormedActionType(s.slice(0, -2))
    : isWellFormedActionType(s);
}

function hasHumanSignoff(receipt: Obj, humanClasses: string[]): boolean {
  const set = new Set(humanClasses);
  const signoffs = Array.isArray(receipt?.signoffs) ? receipt.signoffs : [];
  return signoffs.some((s) => set.has(s?.key_class));
}

function receiptApprovers(receipt: Obj): Set<string> {
  const ids = new Set<string>();
  for (const ctx of receipt?.contexts || []) if (ctx?.approver) ids.add(ctx.approver);
  for (const s of receipt?.signoffs || []) if (s?.approver_key_id) ids.add(s.approver_key_id);
  return ids;
}

const executedActionType = (doc: Obj): string | null => doc?.action_approval?.receipt?.action?.action_type ?? null;

function latestContextExpiry(receipt: Obj): number | null {
  let max = null;
  for (const ctx of receipt?.contexts || []) {
    const t = Date.parse(ctx?.expires_at);
    if (!Number.isNaN(t) && (max === null || t > max)) max = t;
  }
  return max;
}

function committedAtMs(receipt: Obj): number | null {
  const t = Date.parse(receipt?.consumption?.committed_at);
  return Number.isNaN(t) ? null : t;
}

function scopePermits(scope: unknown, actionType: unknown): boolean {
  // Reject malformed action types (empty/leading/trailing/double-dot segments)
  // BEFORE any prefix match, so a crafted "a..b" can't bypass "a.*" containment.
  if (!Array.isArray(scope) || !isWellFormedActionType(actionType)) return false;
  for (const grant of scope) {
    if (!isWellFormedScopeToken(grant)) continue;
    if (grant === '*' || grant === actionType) return true;
    if (typeof grant === 'string' && grant.endsWith('.*')) {
      const prefix = grant.slice(0, -2);
      if (actionType === prefix || actionType.startsWith(prefix + '.')) return true;
    }
  }
  return false;
}

function scopeContainmentViolations(parent: Obj, child: Obj): string[] {
  const violations: string[] = [];
  for (const token of child.scope || []) {
    if (!isWellFormedScopeToken(token)) {
      violations.push(`child scope token ${JSON.stringify(token)} is malformed`);
      continue;
    }
    if (token === '*') {
      if (!Array.isArray(parent.scope) || !parent.scope.includes('*')) {
        violations.push(`child scope "*" exceeds parent scope [${(parent.scope || []).join(', ')}]`);
      }
      continue;
    }
    const probe = typeof token === 'string' && token.endsWith('.*') ? token.slice(0, -2) : token;
    if (!scopePermits(parent.scope, probe)) {
      violations.push(`child scope "${token}" exceeds parent scope [${(parent.scope || []).join(', ')}]`);
    }
  }
  // Cap containment, fail-closed on a non-numeric child cap. When the parent has a
  // finite cap, the child must be absent/null (inherits) OR a finite number <= parent.
  // A present-but-non-numeric child cap (e.g. "abc", {}, true) previously coerced to
  // NaN and the `NaN > parent` comparison was false, so it PASSED containment — a
  // fail-open (the JS sibling of the Go value-cap bug). Now it is a violation,
  // matching the Python and Go ports.
  const parentCap = parent.max_value_usd;
  const parentCapNum = Number(parentCap);
  const childCap = child.max_value_usd;
  if (childCap !== null && childCap !== undefined) {
    const childCapNum = Number(childCap);
    if (!Number.isFinite(childCapNum)) {
      violations.push(`child max_value_usd ${childCap} is not a valid cap within parent cap ${parentCap}`);
    } else if (parentCap !== null && parentCap !== undefined
        && Number.isFinite(parentCapNum) && childCapNum > parentCapNum) {
      violations.push(`child max_value_usd ${childCap} exceeds parent cap ${parentCap}; child is not a valid cap within parent cap`);
    }
  }
  const pExp = Date.parse(parent.expires_at);
  const cExp = Date.parse(child.expires_at);
  if (!Number.isNaN(pExp) && !Number.isNaN(cExp) && cExp > pExp) {
    violations.push(`child expires_at ${child.expires_at} is after parent expires_at ${parent.expires_at}`);
  }
  return violations;
}

function verifyDetachedSignature(att: Obj): boolean {
  try {
    if (!att?.signed_payload_b64u || !att?.signature_b64u || !att?.public_key) return false;
    if (att.algorithm && att.algorithm !== 'Ed25519') return false;
    const key = crypto.createPublicKey({ key: Buffer.from(att.public_key, 'base64url'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(att.signed_payload_b64u, 'base64url'), key, Buffer.from(att.signature_b64u, 'base64url'));
  } catch {
    return false;
  }
}

const DELEGATION_PROOF_FIELDS = ['delegation_id', 'delegator', 'delegatee', 'scope', 'max_value_usd', 'expires_at', 'constraints'];

function delegationProofBytes(link: Obj): Buffer {
  const subset: Obj = {};
  for (const f of DELEGATION_PROOF_FIELDS) subset[f] = link[f] ?? null;
  return Buffer.from(canonicalize(subset), 'utf8');
}

function rootAuthorizedScope(rootReceipt: Obj): string[] {
  const at = rootReceipt?.action?.action_type;
  return typeof at === 'string' && at.length > 0 ? [at] : [];
}

// Monotonic constraint narrowing (AgentROA "tighten-only" algebra): a child
// delegation may add constraints but never RELAX one its parent set. For each
// key the parent constrains, the child MUST also carry it; numeric ceilings may
// only decrease, array allow-lists may only shrink (subset), and any other type
// must be unchanged. Honest bound: constraint types beyond number/array are only
// checked for equality — a semantic relaxation inside an opaque object is not
// interpreted. Returns true when the child is contained.
function constraintsMonotonic(parentC: any, childC: any): boolean {
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

/**
 * Verify an EP-PROVENANCE-CHAIN-v1 document fully offline. FAIL CLOSED.
 * See lib/provenance/chain.js for the full contract; opts mirror it
 * (humanKeyClasses, delegationKeys, reversibilityAsserted, allowUnsignedDelegations,
 * now, requireActionApprovalAlways).
 */
export function verifyProvenanceOffline(doc: Obj, opts: ProvenanceOptions = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const humanKeyClasses = opts.humanKeyClasses || DEFAULT_HUMAN_KEY_CLASSES;
  const allowUnsignedDelegations = opts.allowUnsignedDelegations === true;
  const now = opts.now === undefined ? Date.now() : opts.now;
  const requireActionApprovalAlways = opts.requireActionApprovalAlways === true;

  const checks: Record<string, boolean> = {
    version: false, root_receipt_valid: false, root_human_signoff: false,
    per_action_required: true, action_receipt_valid: true, action_human_signoff: true,
    execution_binding: true, chain_anchored: true, chain_links_bound: true,
    delegations_signed: true, proof_key_bound: true, delegations_not_expired: true,
    scope_containment: true, constraints_monotonic: true, leaf_permits_action: true, temporal_containment: true,
  };
  const errors: string[] = [];
  const links: Obj[] = [];
  const fail = (key: string, msg: string): void => { checks[key] = false; errors.push(msg); };
  const validVerificationProfile = (profile: Obj | undefined): boolean => (
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

  if (!Number.isFinite(now)) {
    fail('delegations_not_expired', 'verification reference time must be finite');
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    errors.push(`unsupported version: ${(doc as any)?.['@version']}`);
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  try {
    canonicalizeStrictJson(doc, { maxDepth: 64, maxNodes: 100_000, maxStringBytes: 4_194_304 });
  } catch {
    fail('chain_links_bound', 'provenance document is outside the bounded canonical JSON domain');
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }

  if (doc?.['@version'] !== PROVENANCE_VERSION) {
    errors.push(`unsupported version: ${doc?.['@version']}`);
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  checks.version = true;

  const root = doc.root_signoff;
  const rootVerification = opts.rootVerification || opts.root_verification;
  if (!root?.receipt) {
    fail('root_receipt_valid', 'missing root_signoff.receipt');
  } else if (!validVerificationProfile(rootVerification)) {
    fail('root_receipt_valid', 'relying-party root verification profile is required');
  } else {
    const rootProfile = rootVerification as Obj;
    const r0 = verifyTrustReceipt(root.receipt, {
      approverKeys: rootProfile.approver_keys,
      logPublicKey: rootProfile.log_public_key,
      rpId: rootProfile.rp_id,
      allowedOrigins: rootProfile.allowed_origins,
    });
    checks.root_receipt_valid = r0.valid;
    if (!r0.valid) errors.push(`root receipt failed v1 verification: ${(r0.errors || []).join('; ')}`);
    checks.root_human_signoff = hasHumanSignoff(root.receipt, humanKeyClasses);
    if (!checks.root_human_signoff) errors.push(`root receipt carries no human signoff (need key_class in [${humanKeyClasses.join(', ')}])`);
  }

  const exec = doc.execution || {};
  let reversibilityAsserted = false;
  if (typeof opts.reversibilityAsserted === 'function') {
    try {
      reversibilityAsserted = opts.reversibilityAsserted(exec) === true;
    } catch {
      // Predicate failure cannot remove the per-action approval requirement.
      reversibilityAsserted = false;
    }
  }
  const needApproval = requireActionApprovalAlways || !reversibilityAsserted;
  const approval = doc.action_approval;
  const actionVerification = opts.actionVerification || opts.action_verification;
  if (needApproval && !approval?.receipt) {
    fail('per_action_required', 'execution is irreversible (or approval is always required) but no action_approval is present');
  }
  if (approval?.receipt) {
    if (!validVerificationProfile(actionVerification)) {
      fail('action_receipt_valid', 'relying-party action verification profile is required');
    } else {
      const actionProfile = actionVerification as Obj;
      const ra = verifyTrustReceipt(approval.receipt, {
        approverKeys: actionProfile.approver_keys,
        logPublicKey: actionProfile.log_public_key,
        rpId: actionProfile.rp_id,
        allowedOrigins: actionProfile.allowed_origins,
      });
      checks.action_receipt_valid = ra.valid;
      if (!ra.valid) errors.push(`action_approval receipt failed v1 verification: ${(ra.errors || []).join('; ')}`);
    }
    if (exec.irreversible === true) {
      checks.action_human_signoff = hasHumanSignoff(approval.receipt, humanKeyClasses);
      if (!checks.action_human_signoff) errors.push('action_approval for an irreversible action carries no human signoff');
    }
    const executionHash = hexOf(exec.action_hash);
    const approvalHash = hexOf(approval.receipt.action_hash);
    checks.execution_binding = executionHash !== ''
      && approvalHash !== ''
      && executionHash === approvalHash;
    if (!checks.execution_binding) errors.push('execution.action_hash does not match action_approval.receipt.action_hash');
  }

  const chain: Obj[] = Array.isArray(doc.delegation_chain) ? [...doc.delegation_chain] : [];
  chain.sort((a: Obj, b: Obj) => (a.sequence ?? 0) - (b.sequence ?? 0));
  const delegationKeys = opts.delegationKeys || {};
  const rootApprovers = doc.root_signoff?.receipt ? receiptApprovers(doc.root_signoff.receipt) : new Set();
  const rootExpiry = latestContextExpiry(doc.root_signoff?.receipt);
  const rootScope = doc.root_signoff?.receipt ? rootAuthorizedScope(doc.root_signoff.receipt) : [];
  let parent: Obj = {
    scope: rootScope, max_value_usd: null,
    expires_at: rootExpiry !== null ? new Date(rootExpiry).toISOString() : undefined,
    id: '(root human signoff)',
  };

  if (chain.length > 0) {
    const head = chain[0];
    // Anchor ONLY on the SIGNED delegator. parent_ref is not in
    // DELEGATION_PROOF_FIELDS, so it is unsigned and attacker-controlled;
    // trusting it here let a stranger's link claim a root approver as its
    // parent and falsely attribute the chain to a human who never delegated.
    checks.chain_anchored = rootApprovers.has(head.delegator);
    if (!checks.chain_anchored) errors.push(`delegation chain head delegator "${head.delegator}" does not name a root-receipt approver`);
  }

  let prevDelegatee = null;
  for (const link of chain) {
    const linkReport: Obj = { sequence: link.sequence, delegation_id: link.delegation_id, ok: true, issues: [] as string[] };
    if (prevDelegatee !== null) {
      if (link.parent_ref !== prevDelegatee || link.delegator !== prevDelegatee) {
        checks.chain_links_bound = false; linkReport.ok = false; linkReport.issues.push('inter_hop_link_broken');
        errors.push(`delegation ${link.delegation_id}: parent_ref "${link.parent_ref}" / delegator "${link.delegator}" does not bind to prior delegatee "${prevDelegatee}"`);
      }
    }
    const expM = Date.parse(link.expires_at);
    if (Number.isNaN(expM) || expM < now) {
      checks.delegations_not_expired = false; linkReport.ok = false; linkReport.issues.push('expired');
      errors.push(`delegation ${link.delegation_id} is expired`);
    }
    if (link.proof) {
      const sigOk = verifyDetachedSignature(link.proof);
      const boundBytes = delegationProofBytes(link);
      const presentedBytes = (() => { try { return Buffer.from(link.proof.signed_payload_b64u || '', 'base64url'); } catch { return Buffer.alloc(0); } })();
      const bytesMatch = sigOk && presentedBytes.equals(boundBytes);
      if (!sigOk || !bytesMatch) {
        checks.delegations_signed = false; linkReport.ok = false;
        linkReport.issues.push(sigOk ? 'proof_not_over_own_fields' : 'signature_invalid');
        errors.push(sigOk ? `delegation ${link.delegation_id} proof does not sign the delegation's own canonical fields (tampered)` : `delegation ${link.delegation_id} proof signature does not verify`);
      }
      const boundKey = delegationKeys[link.delegator]?.public_key;
      if (!boundKey) {
        checks.proof_key_bound = false; linkReport.ok = false; linkReport.issues.push('no_pinned_delegator_key');
        errors.push(`delegation ${link.delegation_id}: no pinned key for delegator "${link.delegator}" (cannot bind proof)`);
      } else if (boundKey !== link.proof.public_key) {
        checks.proof_key_bound = false; linkReport.ok = false; linkReport.issues.push('proof_key_not_bound_to_delegator');
        errors.push(`delegation ${link.delegation_id}: proof public key is not the key bound to delegator "${link.delegator}"`);
      }
    } else if (!allowUnsignedDelegations) {
      checks.delegations_signed = false; linkReport.ok = false; linkReport.issues.push('unsigned');
      errors.push(`delegation ${link.delegation_id} has no verifiable proof (fail-closed)`);
    }
    const violations = scopeContainmentViolations(parent, link);
    if (violations.length > 0) {
      checks.scope_containment = false; linkReport.ok = false; linkReport.issues.push(...violations);
      for (const v of violations) errors.push(`delegation ${link.delegation_id}: ${v}`);
    }
    if (!constraintsMonotonic(parent.constraints, link.constraints)) {
      checks.constraints_monotonic = false; linkReport.ok = false; linkReport.issues.push('constraints_relaxed');
      errors.push(`delegation ${link.delegation_id}: constraints relax a parent restriction (not monotonic)`);
    }
    links.push(linkReport);
    let effectiveCap;
    if (link.max_value_usd === null || link.max_value_usd === undefined) effectiveCap = parent.max_value_usd;
    else if (parent.max_value_usd === null || parent.max_value_usd === undefined) effectiveCap = link.max_value_usd;
    else effectiveCap = Math.min(Number(link.max_value_usd), Number(parent.max_value_usd));
    parent = { ...link, max_value_usd: effectiveCap };
    prevDelegatee = link.delegatee;
  }

  const actionType = executedActionType(doc);
  if (!actionType) {
    checks.leaf_permits_action = false;
    errors.push('cannot determine executed action_type from action_approval (no per-action approval present)');
  } else if (!scopePermits(parent.scope, actionType)) {
    checks.leaf_permits_action = false;
    const where = chain.length > 0 ? 'leaf delegation' : 'root authority';
    errors.push(`${where} scope [${(parent.scope || []).join(', ')}] does not permit executed action "${actionType}"`);
  }

  {
    const commit = approval?.receipt ? committedAtMs(approval.receipt) : null;
    const leafExp = Date.parse(parent.expires_at ?? '');
    if (commit !== null && !Number.isNaN(leafExp) && commit > leafExp) {
      checks.temporal_containment = false;
      errors.push('per-action approval committed_at is after the leaf delegation expires_at');
    }
  }

  let agentIdentity = null;
  if (doc.agent_identity) {
    agentIdentity = {
      agent_id: doc.agent_identity.agent_id ?? null,
      claimed_by: doc.agent_identity.claimed_by ?? null,
      claim_only: true,
      attestation_signature_valid: doc.agent_identity.attestation ? verifyDetachedSignature(doc.agent_identity.attestation) : null,
    };
    if (agentIdentity.attestation_signature_valid === false) errors.push('advisory: agent_identity.attestation signature does not verify (not gating)');
  }
  let liability = null;
  if (doc.liability) {
    liability = {
      owner: doc.liability.owner ?? null,
      owner_name: doc.liability.owner_name ?? null,
      evidence_only: true,
      attestation_signature_valid: doc.liability.attestation ? verifyDetachedSignature(doc.liability.attestation) : null,
    };
    if (liability.attestation_signature_valid === false) errors.push('advisory: liability.attestation signature does not verify (not gating)');
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors, links, agent_identity: agentIdentity, liability };
}

// ===========================================================================
// EP-PROVENANCE-CHAIN-v2 -- hybrid (Ed25519 + ML-DSA-65) delegation-link proof
// ===========================================================================
/**
 * Reference hybrid migration for this surface. The chain document's OWN
 * cryptographic surface -- the part packages/verify/src/provenance.ts owns
 * directly -- is the delegation-link proof (delegationProofBytes /
 * verifyDetachedSignature above). The embedded root/action receipts remain
 * whatever EP-RECEIPT-v1/v2 the receipt-issuance hybridization workstream
 * (packages/issue, packages/verify/src/index.ts) ships; this file composes
 * verifyTrustReceipt UNCHANGED in both v1 and v2, exactly as the v1 header
 * describes ("adds NO new trust"). Copies the five moves from
 * EP-REVOCATION-v2 (packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP. The document's `@version` moves EP-PROVENANCE-CHAIN-v1 to
 *    -v2. verifyProvenanceOffline above is UNCHANGED and refuses a v2
 *    document on the version marker before inspecting any delegation proof.
 * 2. SET SHAPE. Each delegation link's `proof_set` (replacing v1's `proof`)
 *    carries `required_algorithms` plus a `signatures` array shaped exactly
 *    like EP-SIG-AGILITY-v1's AgileSignature ({alg, sig, key_id?}), one entry
 *    per algorithm, reusing that shape verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (delegationProofV2Bytes), independently recomputed by the verifier from
 *    the registered set -- never read off the presented link.
 * 4. V1 COMPATIBILITY. v1 documents keep verifying, unchanged, through the
 *    sync verifyProvenanceOffline above. v2 verification is a separate ASYNC
 *    entry point (ML-DSA verification is async) because a delegation chain
 *    may be arbitrarily long and every hop's proof must be awaited.
 * 5. NAMED REFUSALS. Nothing throws on caller input; a missing ML-DSA backend
 *    is a refusal via the agility module's `pq_backend_unavailable`, never a
 *    skipped check and never a pass on the Ed25519 leg alone.
 *
 * HARDENING BEYOND V1. verifyDelegationProofSetV2 verifies ONLY against the
 * relying-party-PINNED key pair for the delegator -- it never reads a public
 * key off the presented proof at all, so there is no "presented key equals
 * pinned key" indirection to get wrong (v1's proof_key_bound check exists
 * only because v1 carries the signer's public key inline; v2 doesn't).
 */

export const PROVENANCE_V2_VERSION = 'EP-PROVENANCE-CHAIN-v2';
export const PROVENANCE_DELEGATION_PROOF_V2_VERSION = 'EP-PROVENANCE-DELEGATION-PROOF-v2';
/** The registered required algorithm set, in canonical order. */
export const PROVENANCE_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

export interface ProvenanceDelegationV2Pin {
  /** Ed25519: base64url SPKI DER. */
  public_key?: string;
  /** ML-DSA-65: base64url of the raw 1952-byte public key. */
  pq_public_key?: string;
}

export interface ProvenanceV2Options extends AgilityOptions {
  humanKeyClasses?: string[];
  allowUnsignedDelegations?: boolean;
  now?: number;
  requireActionApprovalAlways?: boolean;
  rootVerification?: Obj;
  root_verification?: Obj;
  actionVerification?: Obj;
  action_verification?: Obj;
  delegationKeys?: Record<string, ProvenanceDelegationV2Pin>;
  reversibilityAsserted?: (execution: Obj) => boolean;
}

function algorithmSetMatchesRegisteredProvenance(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === PROVENANCE_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === PROVENANCE_V2_REQUIRED_ALGORITHMS[i]);
}

/**
 * Bytes BOTH legs sign for one delegation link's hybrid proof. Same signed
 * field subset as v1's delegationProofBytes (DELEGATION_PROOF_FIELDS),
 * domain-separated and committing the REGISTERED algorithm set. Recomputed
 * independently by the verifier; never trusts a presented algorithm list.
 */
export function delegationProofV2Bytes(
  link: Obj,
  requiredAlgorithms: readonly string[] = PROVENANCE_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!algorithmSetMatchesRegisteredProvenance(requiredAlgorithms)) {
    throw new Error('delegationProofV2Bytes: algorithm set is not the registered EP-PROVENANCE-CHAIN-v2 set');
  }
  const subset: Obj = {
    '@version': PROVENANCE_DELEGATION_PROOF_V2_VERSION,
    required_algorithms: [...requiredAlgorithms],
  };
  for (const f of DELEGATION_PROOF_FIELDS) subset[f] = link[f] ?? null;
  return Buffer.from(canonicalize(subset), 'utf8');
}

/**
 * Verify one v2 (hybrid) delegation-link `proof_set`. FAIL-CLOSED, never
 * throws. A missing pin, a stripped leg, or a narrowed `required_algorithms`
 * all refuse; neither algorithm alone ever suffices.
 */
export async function verifyDelegationProofSetV2(
  link: Obj,
  pin: ProvenanceDelegationV2Pin | undefined,
  opts: AgilityOptions = {},
): Promise<boolean> {
  try {
    const proofSet = link?.proof_set;
    if (!proofSet || typeof proofSet !== 'object' || Array.isArray(proofSet)) return false;
    if (!algorithmSetMatchesRegisteredProvenance(proofSet.required_algorithms)) return false;
    const signatures = proofSet.signatures;
    if (!Array.isArray(signatures) || signatures.length !== 2) return false;
    const seen = new Set<string>();
    for (const s of signatures) {
      if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || seen.has(s.alg)) {
        return false;
      }
      seen.add(s.alg);
    }
    if (!PROVENANCE_V2_REQUIRED_ALGORITHMS.every((alg) => seen.has(alg))) return false;
    if (typeof pin?.public_key !== 'string' || !pin.public_key
      || typeof pin?.pq_public_key !== 'string' || !pin.pq_public_key) return false;
    const bytes = delegationProofV2Bytes(link);
    const setResult = await verifyAgileSignatureSet(
      new Uint8Array(bytes),
      signatures,
      [
        { alg: 'Ed25519', public_key: pin.public_key },
        { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
      ],
      { ...opts, policy: 'hybrid_all', requiredAlgorithms: [...PROVENANCE_V2_REQUIRED_ALGORITHMS] },
    );
    return setResult.verified === true;
  } catch {
    return false;
  }
}

/**
 * Verify an EP-PROVENANCE-CHAIN-v2 document fully offline. FAIL CLOSED.
 * Identical control flow to verifyProvenanceOffline (root/action receipt
 * verification via the unchanged verifyTrustReceipt, scope containment,
 * monotonic constraints, leaf-permits-action) except each delegation link's
 * proof is verified via verifyDelegationProofSetV2 (hybrid, async) against
 * `link.proof_set` instead of verifyDetachedSignature against `link.proof`.
 */
export async function verifyProvenanceOfflineV2(doc: Obj, opts: ProvenanceV2Options = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const humanKeyClasses = opts.humanKeyClasses || DEFAULT_HUMAN_KEY_CLASSES;
  const allowUnsignedDelegations = opts.allowUnsignedDelegations === true;
  const now = opts.now === undefined ? Date.now() : opts.now;
  const requireActionApprovalAlways = opts.requireActionApprovalAlways === true;

  const checks: Record<string, boolean> = {
    version: false, root_receipt_valid: false, root_human_signoff: false,
    per_action_required: true, action_receipt_valid: true, action_human_signoff: true,
    execution_binding: true, chain_anchored: true, chain_links_bound: true,
    delegations_signed: true, proof_key_bound: true, delegations_not_expired: true,
    scope_containment: true, constraints_monotonic: true, leaf_permits_action: true, temporal_containment: true,
  };
  const errors: string[] = [];
  const links: Obj[] = [];
  const fail = (key: string, msg: string): void => { checks[key] = false; errors.push(msg); };
  const validVerificationProfile = (profile: Obj | undefined): boolean => (
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

  if (!Number.isFinite(now)) {
    fail('delegations_not_expired', 'verification reference time must be finite');
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    errors.push(`unsupported version: ${(doc as any)?.['@version']}`);
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  try {
    canonicalizeStrictJson(doc, { maxDepth: 64, maxNodes: 100_000, maxStringBytes: 4_194_304 });
  } catch {
    fail('chain_links_bound', 'provenance document is outside the bounded canonical JSON domain');
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }

  if (doc?.['@version'] !== PROVENANCE_V2_VERSION) {
    errors.push(`unsupported version: ${doc?.['@version']}`);
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  checks.version = true;

  const root = doc.root_signoff;
  const rootVerification = opts.rootVerification || opts.root_verification;
  if (!root?.receipt) {
    fail('root_receipt_valid', 'missing root_signoff.receipt');
  } else if (!validVerificationProfile(rootVerification)) {
    fail('root_receipt_valid', 'relying-party root verification profile is required');
  } else {
    const rootProfile = rootVerification as Obj;
    const r0 = verifyTrustReceipt(root.receipt, {
      approverKeys: rootProfile.approver_keys,
      logPublicKey: rootProfile.log_public_key,
      rpId: rootProfile.rp_id,
      allowedOrigins: rootProfile.allowed_origins,
    });
    checks.root_receipt_valid = r0.valid;
    if (!r0.valid) errors.push(`root receipt failed v1 verification: ${(r0.errors || []).join('; ')}`);
    checks.root_human_signoff = hasHumanSignoff(root.receipt, humanKeyClasses);
    if (!checks.root_human_signoff) errors.push(`root receipt carries no human signoff (need key_class in [${humanKeyClasses.join(', ')}])`);
  }

  const exec = doc.execution || {};
  let reversibilityAsserted = false;
  if (typeof opts.reversibilityAsserted === 'function') {
    try {
      reversibilityAsserted = opts.reversibilityAsserted(exec) === true;
    } catch {
      reversibilityAsserted = false;
    }
  }
  const needApproval = requireActionApprovalAlways || !reversibilityAsserted;
  const approval = doc.action_approval;
  const actionVerification = opts.actionVerification || opts.action_verification;
  if (needApproval && !approval?.receipt) {
    fail('per_action_required', 'execution is irreversible (or approval is always required) but no action_approval is present');
  }
  if (approval?.receipt) {
    if (!validVerificationProfile(actionVerification)) {
      fail('action_receipt_valid', 'relying-party action verification profile is required');
    } else {
      const actionProfile = actionVerification as Obj;
      const ra = verifyTrustReceipt(approval.receipt, {
        approverKeys: actionProfile.approver_keys,
        logPublicKey: actionProfile.log_public_key,
        rpId: actionProfile.rp_id,
        allowedOrigins: actionProfile.allowed_origins,
      });
      checks.action_receipt_valid = ra.valid;
      if (!ra.valid) errors.push(`action_approval receipt failed v1 verification: ${(ra.errors || []).join('; ')}`);
    }
    if (exec.irreversible === true) {
      checks.action_human_signoff = hasHumanSignoff(approval.receipt, humanKeyClasses);
      if (!checks.action_human_signoff) errors.push('action_approval for an irreversible action carries no human signoff');
    }
    const executionHash = hexOf(exec.action_hash);
    const approvalHash = hexOf(approval.receipt.action_hash);
    checks.execution_binding = executionHash !== ''
      && approvalHash !== ''
      && executionHash === approvalHash;
    if (!checks.execution_binding) errors.push('execution.action_hash does not match action_approval.receipt.action_hash');
  }

  const chain: Obj[] = Array.isArray(doc.delegation_chain) ? [...doc.delegation_chain] : [];
  chain.sort((a: Obj, b: Obj) => (a.sequence ?? 0) - (b.sequence ?? 0));
  const delegationKeys = opts.delegationKeys || {};
  const rootApprovers = doc.root_signoff?.receipt ? receiptApprovers(doc.root_signoff.receipt) : new Set();
  const rootExpiry = latestContextExpiry(doc.root_signoff?.receipt);
  const rootScope = doc.root_signoff?.receipt ? rootAuthorizedScope(doc.root_signoff.receipt) : [];
  let parent: Obj = {
    scope: rootScope, max_value_usd: null,
    expires_at: rootExpiry !== null ? new Date(rootExpiry).toISOString() : undefined,
    id: '(root human signoff)',
  };

  if (chain.length > 0) {
    const head = chain[0];
    checks.chain_anchored = rootApprovers.has(head.delegator);
    if (!checks.chain_anchored) errors.push(`delegation chain head delegator "${head.delegator}" does not name a root-receipt approver`);
  }

  let prevDelegatee = null;
  for (const link of chain) {
    const linkReport: Obj = { sequence: link.sequence, delegation_id: link.delegation_id, ok: true, issues: [] as string[] };
    if (prevDelegatee !== null) {
      if (link.parent_ref !== prevDelegatee || link.delegator !== prevDelegatee) {
        checks.chain_links_bound = false; linkReport.ok = false; linkReport.issues.push('inter_hop_link_broken');
        errors.push(`delegation ${link.delegation_id}: parent_ref "${link.parent_ref}" / delegator "${link.delegator}" does not bind to prior delegatee "${prevDelegatee}"`);
      }
    }
    const expM = Date.parse(link.expires_at);
    if (Number.isNaN(expM) || expM < now) {
      checks.delegations_not_expired = false; linkReport.ok = false; linkReport.issues.push('expired');
      errors.push(`delegation ${link.delegation_id} is expired`);
    }
    if (link.proof_set) {
      const pin = delegationKeys[link.delegator];
      if (!pin?.public_key || !pin?.pq_public_key) {
        checks.proof_key_bound = false; linkReport.ok = false; linkReport.issues.push('no_pinned_delegator_key_pair');
        errors.push(`delegation ${link.delegation_id}: no pinned Ed25519 + ML-DSA-65 key pair for delegator "${link.delegator}" (cannot bind proof)`);
      } else {
        const proofOk = await verifyDelegationProofSetV2(link, pin, opts);
        if (!proofOk) {
          checks.delegations_signed = false; linkReport.ok = false; linkReport.issues.push('signature_set_invalid');
          errors.push(`delegation ${link.delegation_id} hybrid proof set does not verify under the pinned Ed25519 + ML-DSA-65 keys`);
        }
      }
    } else if (!allowUnsignedDelegations) {
      checks.delegations_signed = false; linkReport.ok = false; linkReport.issues.push('unsigned');
      errors.push(`delegation ${link.delegation_id} has no verifiable proof_set (fail-closed)`);
    }
    const violations = scopeContainmentViolations(parent, link);
    if (violations.length > 0) {
      checks.scope_containment = false; linkReport.ok = false; linkReport.issues.push(...violations);
      for (const v of violations) errors.push(`delegation ${link.delegation_id}: ${v}`);
    }
    if (!constraintsMonotonic(parent.constraints, link.constraints)) {
      checks.constraints_monotonic = false; linkReport.ok = false; linkReport.issues.push('constraints_relaxed');
      errors.push(`delegation ${link.delegation_id}: constraints relax a parent restriction (not monotonic)`);
    }
    links.push(linkReport);
    let effectiveCap;
    if (link.max_value_usd === null || link.max_value_usd === undefined) effectiveCap = parent.max_value_usd;
    else if (parent.max_value_usd === null || parent.max_value_usd === undefined) effectiveCap = link.max_value_usd;
    else effectiveCap = Math.min(Number(link.max_value_usd), Number(parent.max_value_usd));
    parent = { ...link, max_value_usd: effectiveCap };
    prevDelegatee = link.delegatee;
  }

  const actionType = executedActionType(doc);
  if (!actionType) {
    checks.leaf_permits_action = false;
    errors.push('cannot determine executed action_type from action_approval (no per-action approval present)');
  } else if (!scopePermits(parent.scope, actionType)) {
    checks.leaf_permits_action = false;
    const where = chain.length > 0 ? 'leaf delegation' : 'root authority';
    errors.push(`${where} scope [${(parent.scope || []).join(', ')}] does not permit executed action "${actionType}"`);
  }

  {
    const commit = approval?.receipt ? committedAtMs(approval.receipt) : null;
    const leafExp = Date.parse(parent.expires_at ?? '');
    if (commit !== null && !Number.isNaN(leafExp) && commit > leafExp) {
      checks.temporal_containment = false;
      errors.push('per-action approval committed_at is after the leaf delegation expires_at');
    }
  }

  let agentIdentity = null;
  if (doc.agent_identity) {
    agentIdentity = {
      agent_id: doc.agent_identity.agent_id ?? null,
      claimed_by: doc.agent_identity.claimed_by ?? null,
      claim_only: true,
      attestation_signature_valid: doc.agent_identity.attestation ? verifyDetachedSignature(doc.agent_identity.attestation) : null,
    };
    if (agentIdentity.attestation_signature_valid === false) errors.push('advisory: agent_identity.attestation signature does not verify (not gating)');
  }
  let liability = null;
  if (doc.liability) {
    liability = {
      owner: doc.liability.owner ?? null,
      owner_name: doc.liability.owner_name ?? null,
      evidence_only: true,
      attestation_signature_valid: doc.liability.attestation ? verifyDetachedSignature(doc.liability.attestation) : null,
    };
    if (liability.attestation_signature_valid === false) errors.push('advisory: liability.attestation signature does not verify (not gating)');
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors, links, agent_identity: agentIdentity, liability };
}

/**
 * Route a document of EITHER version to its verifier. A `@version` naming
 * neither refuses through the v1 (sync) verifier's version check, which is
 * the fail-closed answer.
 */
export async function verifyProvenanceOfflineStatement(doc: Obj, opts: ProvenanceV2Options = {}) {
  if (doc && typeof doc === 'object' && !Array.isArray(doc) && doc['@version'] === PROVENANCE_V2_VERSION) {
    return verifyProvenanceOfflineV2(doc, opts);
  }
  return verifyProvenanceOffline(doc, opts as ProvenanceOptions);
}
