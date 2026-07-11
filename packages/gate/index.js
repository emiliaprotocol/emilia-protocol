/**
 * @emilia-protocol/gate — EMILIA Gate: the Trusted Action Firewall.
 * @license Apache-2.0
 *
 * Deny-by-default enforcement for consequential machine actions. A guarded
 * action runs ONLY if it arrives with a receipt that is:
 *   1. valid          — Ed25519 over canonical JSON, signed by a pinned issuer;
 *   2. in-scope       — bound to the exact action the manifest guards;
 *   3. sufficiently   — meets the action's required assurance tier, and the
 *      assured           credited tier is CRYPTOGRAPHICALLY VERIFIED, not read
 *                        from self-asserted payload fields: class_a requires a
 *                        valid WebAuthn device signoff, quorum requires a valid
 *                        EP-QUORUM-v1 (distinct humans + distinct keys +
 *                        threshold + per-signer assertions);
 *   4. fresh          — within max age; and
 *   5. unused         — not a replay (one-time consumption).
 * Otherwise it is refused with a machine-readable Receipt-Required challenge
 * (HTTP 428). Every decision is appended to a tamper-evident evidence log.
 *
 * It is NOT authentication ("who are you") and NOT permissions ("are you
 * allowed here"). It is a policy-enforcement point that requires portable proof
 * a named human authorized THIS exact action before the world is mutated.
 *
 * Composes @emilia-protocol/require-receipt (manifest + verify + challenge) and
 * adds the three things a firewall needs over a bare verifier: assurance-tier
 * enforcement, replay defense, and the evidence log. Fails closed.
 */
const {
  verifyEmiliaReceipt,
  receiptChallenge,
  receiptRequiredHeader,
  validateActionRiskManifest,
  findActionRequirement,
  evaluateReceiptAssurance,
  receiptAssuranceTier: receiptAssuranceTierFromProof,
  RECEIPT_REQUIRED_STATUS,
  RECEIPT_REQUIRED_HEADER,
} = await import('@emilia-protocol/require-receipt').catch(() => import('../require-receipt/index.js'));
// The real per-signer verifiers (WebAuthn device-signoff + M-of-N quorum). The
// Gate MUST use these to CREDIT class_a / quorum — a receipt's self-asserted
// outcome string or a fabricated quorum block is NOT proof. Same resolution
// pattern as require-receipt: prefer the published package, fall back to the
// in-repo source so the monorepo test/build works without a node_modules link.
const { verifyWebAuthnSignoff, verifyQuorum } = await import('@emilia-protocol/verify')
  .catch(() => import('../verify/index.js'));
import { MemoryConsumptionStore } from './store.js';
import { createEvidenceLog } from './evidence.js';
import { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest } from './action-packs.js';
import { hashCanonical, verifyExecutionBinding } from './execution-binding.js';
import { buildReliancePacket, ADMISSIBILITY_VERDICTS } from './reliance-packet.js';
import { createEg1Harness, makeGateInvoke, runEg1, EG1_DEFAULT_SELECTOR, mintDeviceSignoff, mintQuorumEvidence } from './eg1-conformance.js';
import { CF1_VERSION, CF1_CHECKS, runCf1 } from './cf1-conformance.js';
import { createKeyRegistry, asKeyRegistry } from './key-registry.js';
import { classifyRetention, buildRetentionExport } from './retention.js';
import { createDefaultActionControlManifest, findActionControl, validateActionControlManifest } from './action-control-manifest.js';

export { MemoryConsumptionStore, createEvidenceLog };
export { createDurableConsumptionStore, createMemoryBackend, DURABLE_CONSUMPTION_VERSION } from './store.js';
export { createDurableChallengeStore, challengeStorageKey, challengeBodyDigest, DURABLE_CHALLENGE_STORE_VERSION } from './challenge-store.js';
export { createKeyRegistry, asKeyRegistry } from './key-registry.js';
export { classifyRetention, buildRetentionExport, RETENTION_EXPORT_VERSION } from './retention.js';
export { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest };
export {
  ACTION_CONTROL_MANIFEST_VERSION,
  ACTION_CONTROL_SCHEMA_URL,
  ACTION_CONTROL_CONFORMANCE_LEVEL,
  ACTION_CONTROL_DEFAULTS,
  ACTION_CONTROL_EVIDENCE_PROFILES,
  ACTION_CONTROL_CONFORMANCE_CHECKS,
  toActionControl,
  createDefaultActionControlManifest,
  findActionControl,
  validateActionControlManifest,
} from './action-control-manifest.js';
export { EXECUTION_BINDING_VERSION, canonicalize, hashCanonical, materialFieldsFor, verifyExecutionBinding } from './execution-binding.js';
export { RELIANCE_PACKET_VERSION, ADMISSIBILITY_VERDICTS, buildReliancePacket } from './reliance-packet.js';
export {
  EXTERNAL_VERIFICATION_STATEMENT_VERSION,
  EXTERNAL_VERIFICATION_DOMAIN,
  externalVerificationDigest,
  signExternalVerificationStatement,
  verifyExternalVerificationStatement,
} from './reports/external-verification.js';
export {
  EG1_VERSION, EG1_CHECKS, EG1_DEFAULT_ACTION, EG1_DEFAULT_SELECTOR,
  createEg1Harness, makeGateInvoke, runEg1, mintDeviceSignoff, mintQuorumEvidence,
} from './eg1-conformance.js';
export { CF1_VERSION, CF1_CHECKS, runCf1 } from './cf1-conformance.js';
export const ASSURANCE_TIERS = ['software', 'class_a', 'quorum'];
const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };

/**
 * Verify a PRE-COMPUTED reliance packet's admissibility block against a profile
 * the relying party PINNED. This is the gate's whole job re: admissibility — it
 * does NOT re-evaluate raw evidence and does NOT define the bar. The relying
 * party's own evaluator (lib/evidence/admissibility-profiles.js) computes the
 * verdict OFFLINE against its pinned profile and produces the reliance packet;
 * the gate only confirms the packet answers the SAME profile_hash and carries an
 * 'admissible' verdict. Pure, dependency-light, fail-closed.
 *
 * @param {{id?:string, profile_hash:string}} pinned  the profile the relying party requires
 * @param {object|null} presented  a reliance packet, or its `.admissibility` block,
 *   as produced by buildReliancePacket / the relying party's evaluator
 * @returns {{ok:boolean, reason:string|null, pinned_hash:string, presented_hash:string|null, verdict:string|null}}
 *   ok:true ONLY when the presented profile_hash equals the pinned hash AND the
 *   verdict is exactly 'admissible'. Every other case fails closed with a distinct reason.
 */
export function verifyAdmissibilityAgainstPinnedProfile(pinned, presented) {
  const pinnedHash = pinned && typeof pinned.profile_hash === 'string' ? pinned.profile_hash : null;
  // A pin with no hash is a misconfiguration: refuse, do not silently pass.
  if (!pinnedHash) {
    return { ok: false, reason: 'pinned_profile_missing_hash', pinned_hash: null, presented_hash: null, verdict: null };
  }
  // Accept either a full reliance packet (has .admissibility) or the block itself.
  const adm = presented && typeof presented === 'object'
    ? (presented.admissibility !== undefined ? presented.admissibility : presented)
    : null;
  if (!adm || typeof adm !== 'object') {
    return { ok: false, reason: 'admissibility_profile_pinned_but_absent', pinned_hash: pinnedHash, presented_hash: null, verdict: null };
  }
  const presentedHash = typeof adm.profile_hash === 'string' ? adm.profile_hash : null;
  const verdict = typeof adm.verdict === 'string' ? adm.verdict : null;
  // Constant-work equality is unnecessary (hashes are public), but the mismatch
  // MUST be a distinct, named refusal: a presented verdict for a DIFFERENT bar is
  // not evidence about the pinned bar.
  if (presentedHash === null || presentedHash !== pinnedHash) {
    return { ok: false, reason: 'profile_hash_mismatch', pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
  }
  // Verdict must be recognized AND exactly 'admissible'. Any other closed-set
  // member (missing_evidence/stale/conflicted/unverifiable), an unrecognized
  // string, or a missing verdict fails closed and names the verdict it saw.
  if (verdict === null || !ADMISSIBILITY_VERDICTS.includes(verdict)) {
    return { ok: false, reason: 'admissibility_verdict_unrecognized', pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
  }
  if (verdict !== 'admissible') {
    return { ok: false, reason: `admissibility_not_admissible:${verdict}`, pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
  }
  return { ok: true, reason: null, pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
}

/**
 * The assurance tier a receipt has CRYPTOGRAPHICALLY EARNED.
 *
 * SECURITY: the credited tier is NEVER inferred from self-asserted payload
 * fields. A bare `quorum:{signers,threshold}` block or an `outcome:
 * 'allow_with_signoff'` string with no verifiable signature earns only
 * `software` — it will be refused `assurance_too_low` by any guard that needs
 * more. Fail-closed by construction.
 *
 * Two independent cryptographic proof shapes are accepted; a receipt earns the
 * HIGHEST tier any of them proves:
 *
 *  (a) Pinned assurance proof (`payload.assurance_proof`, EP-ASSURANCE-PROOF-v1):
 *      per-signer signatures verified against PINNED approver keys (opts.approverKeys)
 *      or a caller-supplied verifier (opts.verifyAssurance). This is the primary,
 *      strongest model — the verifier never trusts a key that travels inside the
 *      receipt. Delegated to require-receipt's receiptAssuranceTierFromProof.
 *
 *  (b) Self-contained embedded evidence (DoD audit fix): a full EP-QUORUM-v1
 *      document (payload.quorum) whose per-signer WebAuthn assertions verify via
 *      verifyQuorum (distinct humans + distinct keys + threshold + action-binding
 *      + window) earns `quorum`; a WebAuthn device signoff (payload.signoff =
 *      {context, webauthn}) that verifies against the approver's own key via
 *      verifyWebAuthnSignoff earns `class_a`. Used where the approver keys travel
 *      with the receipt rather than being pinned by the relying party.
 *
 *      TRUST-LAUNDERING GUARD: an approver key carried INSIDE the receipt proves
 *      only that whoever minted the receipt also holds that key — it is NOT proof
 *      the relying party trusts that human. Crediting an elevated tier off such a
 *      key would collapse VERIFIED into ACCEPTED (any party can mint a fresh
 *      keypair, self-sign a signoff, and embed both). So path (b) elevates the
 *      tier ONLY when either: (i) the caller explicitly opts in with
 *      `allowEmbeddedApproverKeys:true` (the documented self-contained mode,
 *      DEFAULT OFF); or (ii) every embedded approver key that would earn the
 *      credit is present in the relying party's PINNED approver key set
 *      (opts.approverKeys). With no pin and no opt-in, path (b) may still VERIFY
 *      the signoff/quorum, but it does NOT elevate above `software`. Fail-closed.
 *
 * @param {object} doc  the EP-RECEIPT-v1 document
 * @param {object} [opts]
 * @param {object} [opts.approverKeys] pinned approver keys for path (a) and the
 *   path-(b) fallback: a receipt-embedded approver key elevates the tier only if
 *   it is one of these pinned keys (unless allowEmbeddedApproverKeys is set)
 * @param {boolean} [opts.allowEmbeddedApproverKeys=false] explicit opt-in to the
 *   self-contained mode where an UNPINNED approver key carried inside the receipt
 *   may still elevate the path-(b) tier. DEFAULT OFF (fail-closed).
 * @param {function} [opts.verifyAssurance] custom assurance verifier for path (a)
 * @param {string} [opts.rpId]  bind embedded device assertions to this WebAuthn RP id (path b)
 * @param {boolean} [opts.detail] return a {tier, quorum, signoff} object instead of the string
 * @returns {'software'|'class_a'|'quorum'|object} the highest tier proven
 */
export function receiptAssuranceTier(doc, opts = {}) {
  const detail = { tier: 'software', quorum: null, signoff: null };

  // --- Path (a): pinned assurance proof / caller-supplied verifier. ---
  // Never inferred from receipt fields without a pinned key or explicit verifier.
  let proofTier = 'software';
  try {
    proofTier = receiptAssuranceTierFromProof(doc, opts) || 'software';
  } catch { proofTier = 'software'; }
  if ((TIER_RANK[proofTier] ?? 0) > (TIER_RANK[detail.tier] ?? 0)) detail.tier = proofTier;

  // --- Path (b): self-contained embedded per-signer evidence (DoD audit fix). ---
  const p = doc?.payload || {};
  const verifyOpts = opts.rpId ? { rpId: opts.rpId } : {};
  // The relying party's PINNED approver public keys (base64url SPKI-DER strings).
  // An embedded approver key elevates the tier only if it is in this set, unless
  // the caller explicitly opts into the self-contained mode.
  const allowEmbedded = opts.allowEmbeddedApproverKeys === true;
  const pinnedKeys = pinnedApproverKeySet(opts.approverKeys);
  const keyIsTrusted = (k) => allowEmbedded || (typeof k === 'string' && pinnedKeys.has(k));

  // quorum: a real, self-contained EP-QUORUM-v1 evidence document. Accept it
  // under payload.quorum or payload.claim.quorum. It only counts if it is a full
  // quorum document (policy + members with WebAuthn signoffs) AND verifyQuorum
  // returns valid. A bare {signers,threshold} block has no members to verify and
  // therefore CANNOT be credited quorum. The cryptographic verification runs
  // regardless (so `detail.quorum` reports validity), but the tier elevates only
  // when every member's embedded approver key is pinned (or the caller opted in).
  const q = p.quorum || p.claim?.quorum;
  if (detail.tier !== 'quorum' && isQuorumEvidence(q)) {
    const qr = verifyQuorum(q, verifyOpts);
    const membersTrusted = allowEmbedded
      || (Array.isArray(q.members) && q.members.length > 0
          && q.members.every((m) => keyIsTrusted(m?.approver_public_key)));
    detail.quorum = { valid: qr.valid, checks: qr.checks, embedded_keys_trusted: membersTrusted };
    if (qr.valid && membersTrusted) detail.tier = 'quorum';
  }

  // class_a: a verifiable WebAuthn device signoff. The signoff evidence is
  // {context, webauthn}; the approver key travels with it (signoff.approver_public_key)
  // or alongside it (payload.approver_public_key). That key elevates the tier only
  // when it is pinned by the relying party (or the caller opted into embedded keys).
  if ((TIER_RANK[detail.tier] ?? 0) < TIER_RANK.class_a) {
    const so = p.signoff || p.claim?.signoff;
    if (isSignoffEvidence(so)) {
      const key = so.approver_public_key || p.approver_public_key || p.claim?.approver_public_key;
      if (key) {
        const sr = verifyWebAuthnSignoff(so, key, verifyOpts);
        const trusted = keyIsTrusted(key);
        detail.signoff = { valid: sr.valid, checks: sr.checks, embedded_key_trusted: trusted };
        if (sr.valid && trusted && (TIER_RANK[detail.tier] ?? 0) < TIER_RANK.class_a) detail.tier = 'class_a';
      }
    }
  }

  return opts.detail ? detail : detail.tier;
}

/**
 * The set of PINNED approver public keys (base64url SPKI-DER strings) a relying
 * party trusts, from the same `approverKeys` map path (a) uses. Accepts either a
 * map of { keyId: { public_key } } (the EP-ASSURANCE-PROOF-v1 shape) or a plain
 * array/set of key strings. Used to decide whether a receipt-embedded approver
 * key may elevate the path-(b) tier. Never throws.
 */
function pinnedApproverKeySet(approverKeys) {
  const out = new Set();
  if (!approverKeys) return out;
  if (approverKeys instanceof Set) {
    for (const k of approverKeys) if (typeof k === 'string' && k) out.add(k);
    return out;
  }
  if (Array.isArray(approverKeys)) {
    for (const k of approverKeys) if (typeof k === 'string' && k) out.add(k);
    return out;
  }
  if (typeof approverKeys === 'object') {
    for (const entry of Object.values(approverKeys)) {
      if (typeof entry === 'string' && entry) { out.add(entry); continue; }
      const pk = entry && typeof entry === 'object' ? entry.public_key : null;
      if (typeof pk === 'string' && pk) out.add(pk);
    }
  }
  return out;
}

/** A quorum evidence doc must carry members with per-signer signoffs to be verifiable. */
function isQuorumEvidence(q) {
  return !!q && typeof q === 'object' && q.policy && Array.isArray(q.members) && q.members.length > 0
    && typeof q.action_hash === 'string' && q.action_hash.length > 0;
}
/** A device signoff must carry the WebAuthn assertion material to be verifiable. */
function isSignoffEvidence(s) {
  return !!s && typeof s === 'object' && s.context && s.webauthn;
}

/**
 * Create a gate.
 * @param {object} opts
 * @param {object} [opts.manifest]      EP-ACTION-RISK-MANIFEST-v0.1 (which actions are guarded, their tier)
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER issuer keys you trust
 * @param {number} [opts.maxAgeSec=900] reject receipts older than this
 * @param {object} [opts.store]         consumption store (default in-memory)
 * @param {object} [opts.log]           evidence log (default in-memory, hash-chained)
 * @param {boolean} [opts.allowInlineKey=false] accept the receipt's own key (integrity, NOT trust)
 * @param {object} [opts.keyRegistry] a key registry (createKeyRegistry) for rotation + revocation;
 *   if given it supersedes trustedKeys — a receipt is verified only against keys valid (and not
 *   revoked) at its issuance time.
 * @param {object} [opts.approverKeys] PINNED approver keys ({ keyId: { public_key, key_class } }).
 *   Used both for the pinned assurance-proof path and to authorize receipt-embedded
 *   approver keys under the self-contained embedded-evidence path.
 * @param {boolean} [opts.allowEmbeddedApproverKeys=false] opt into the self-contained
 *   embedded-evidence mode: when true, a class_a/quorum tier may be credited from an
 *   approver key carried INSIDE the receipt even if that key is not pinned. DEFAULT OFF
 *   — with no pinned approverKeys and no opt-in, embedded evidence verifies but does not
 *   elevate above 'software' (prevents VERIFIED collapsing into ACCEPTED / trust-laundering).
 */
export function createGate({ manifest = null, trustedKeys = [], maxAgeSec = 900, store, log, allowInlineKey = false, allowEphemeralStore = false, strictEvidence = true, now = Date.now, keyRegistry = null, approverKeys = {}, approver_keys = null, verifyAssurance = null, rpId = null, requiredAdmissibilityProfile = null, allowEmbeddedApproverKeys = false } = {}) {
  // Production key custody: a registry (rotation + revocation) supersedes a flat
  // trustedKeys list. A flat list is coerced to an always-valid registry, so
  // existing callers are unchanged.
  const registry = keyRegistry ? asKeyRegistry(keyRegistry) : (trustedKeys.length ? asKeyRegistry(trustedKeys) : null);
  if (manifest) {
    const m = validateActionRiskManifest(manifest);
    if (!m.ok) throw new Error('EMILIA Gate: invalid action-risk manifest: ' + m.errors.join('; '));
  }
  if (allowInlineKey) {
    // eslint-disable-next-line no-console
    console.warn('EMILIA Gate: allowInlineKey=true accepts a receipt\'s OWN key. This proves INTEGRITY (the receipt was not tampered with) but NOT issuer TRUST (anyone can mint a receipt with their own key). Use for demos only; pin trustedKeys in production.');
  }
  // Replay defense is only sound if the consumption store is shared across every
  // instance that can serve the action. The in-memory default is per-process, so
  // a receipt consumed on one pod/lambda could be replayed on another. Fail
  // CLOSED in production unless the operator explicitly accepts a single instance.
  let consumption = store;
  if (!consumption) {
    const isProd = typeof process !== 'undefined' && process.env && process.env.NODE_ENV === 'production';
    if (isProd && !allowEphemeralStore) {
      throw new Error('EMILIA Gate: no consumption store provided. The default in-memory store is per-process and is NOT safe for multi-instance or serverless deployments — a receipt consumed on one instance can be replayed on another, defeating one-time consumption. Provide a shared store ({ async consume(key) {...} }, e.g. Redis/DB-backed), or pass allowEphemeralStore:true to acknowledge a single-instance deployment.');
    }
    consumption = new MemoryConsumptionStore();
  }
  const evidence = log || createEvidenceLog({ strict: strictEvidence });

  async function check({ selector = {}, receipt = null, observedAction = null, consumptionMode = 'consume', admissibilityProfile = null, reliancePacket: presentedPacket = null, admissibility = null } = {}) {
    const requirement = manifest ? findActionRequirement(manifest, selector) : null;
    const action = requirement?.action_type || selector.action_type || selector.action || null;
    // Assurance tier the action requires (cryptographically checked below). For a
    // manifest-guarded action the tier MUST be declared explicitly: never fall
    // back to the weakest 'software' tier because assurance_class was omitted —
    // that would let a guarded, possibly critical, action accept a bare
    // machine-signed receipt (a fail-open). A guarded requirement with no tier
    // is a misconfiguration and fails closed just below. Only selector-only
    // checks (no manifest requirement) use the documented 'software' default.
    const requiredTier = requirement
      ? requirement.assurance_class
      : (selector.assurance_class || 'software');
    const observed = observedAction || selector.observedAction || selector.actionDetails || null;

    async function decide(allow, status, reason, extra = {}) {
      const entry = {
        kind: 'decision',
        at: new Date(typeof now === 'function' ? now() : now).toISOString(),
        action,
        allow,
        status,
        reason,
        selector: { ...selector },
        required_tier: requiredTier,
        receipt_id: receipt?.payload?.receipt_id ?? null,
        subject: receipt?.payload?.subject ?? null,
        observed_action_hash: observed ? hashCanonical(observed) : null,
        ...extra,
      };
      let record;
      try {
        record = await evidence.record(entry);
      } catch (e) {
        // The decision could not be durably recorded. Fail CLOSED: never
        // authorize an action we cannot account for. Downgrade any allow to a
        // refusal and best-effort note the downgrade (non-fatal if that fails too).
        allow = false;
        status = RECEIPT_REQUIRED_STATUS;
        reason = 'evidence_log_failed';
        try {
          record = await evidence.record({ ...entry, allow: false, status, reason, evidence_error: String(e?.message ?? e) });
        } catch {
          record = null;
        }
      }
      const out = { allow, status, reason, action, requirement, evidence: record };
      if (!allow) {
        out.challenge = receiptChallenge(action, reason, {
          status: RECEIPT_REQUIRED_STATUS,
          assuranceClass: requiredTier,
          maxAgeSec,
          manifest: selector.manifestUrl,
        });
        out.header = receiptRequiredHeader({ action, assuranceClass: requiredTier, maxAgeSec });
      }
      return out;
    }

    // Manifest present and this selector is not guarded (or explicitly not required): pass through.
    if (manifest && (!requirement || requirement.receipt_required === false)) {
      return decide(true, 200, 'not_guarded');
    }
    // Guarded, but no receipt was presented.
    if (!receipt) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'receipt_required');
    }
    // A manifest-guarded action that declares no assurance_class is a
    // misconfiguration. Fail CLOSED rather than defaulting to the weakest tier
    // (which would accept a bare machine-signed receipt for a guarded action).
    // validateActionRiskManifest also rejects such a manifest at author time;
    // this is defense in depth for a manifest loaded without re-validation.
    if (requirement && requirement.receipt_required !== false && !requiredTier) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'manifest_missing_assurance_class');
    }
    // Signature / freshness / action-binding / outcome. Production key custody:
    // resolve the issuer keys valid (and not revoked) at THIS receipt's issuance
    // time. A revoked or out-of-window key is excluded, so its signature does not
    // verify and the action is refused (fail closed).
    const effectiveKeys = registry
      ? registry.keysValidAt(receipt?.payload?.created_at)
      : trustedKeys;
    const v = verifyEmiliaReceipt(receipt, { trustedKeys: effectiveKeys, allowInlineKey, action, maxAgeSec });
    if (!v.ok) {
      return decide(false, RECEIPT_REQUIRED_STATUS, `receipt_rejected:${v.reason}`, { rejected: v });
    }
    // Assurance tier. CRYPTOGRAPHICALLY VERIFIED — never inferred from
    // self-asserted payload fields. The credited tier is the HIGHER of two
    // independent proof paths:
    //   (a) pinned assurance proof (payload.assurance_proof verified against
    //       pinned approverKeys) or a caller-supplied verifyAssurance hook;
    //   (b) self-contained embedded per-signer evidence (EP-QUORUM-v1 /
    //       WebAuthn device signoff) re-verified via verifyQuorum /
    //       verifyWebAuthnSignoff (DoD audit fix).
    // A receipt that only CLAIMS a higher tier earns 'software' and is refused.
    const assurance = evaluateReceiptAssurance(receipt, requiredTier, {
      approverKeys: approver_keys || approverKeys,
      verifyAssurance,
    });
    const tierResult = receiptAssuranceTier(receipt, {
      rpId, detail: true, approverKeys: approver_keys || approverKeys, verifyAssurance,
      // Trust-laundering guard: a receipt-embedded approver key does NOT elevate
      // the tier unless it is in the pinned approverKeys set, or the operator
      // explicitly opted into the self-contained embedded-evidence mode. DEFAULT OFF.
      allowEmbeddedApproverKeys,
    });
    // Take the strongest tier either path proves.
    const have = (TIER_RANK[assurance.have] ?? 0) >= (TIER_RANK[tierResult.tier] ?? 0)
      ? assurance.have : tierResult.tier;
    const needRank = TIER_RANK[requiredTier];
    // Fail CLOSED on an unknown / mis-cased required tier: never silently treat
    // it as 'software'. If a manifest asks for a tier this gate does not model,
    // no receipt can satisfy it.
    if (needRank === undefined) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'unknown_required_tier', { have_tier: have, need_tier: requiredTier, assurance_tier_source: 'cryptographic_verification' });
    }
    if ((TIER_RANK[have] ?? 0) < needRank) {
      // The credited tier (from either proof path) is below what the action
      // requires. The canonical machine-readable reason is 'assurance_too_low';
      // main's proof-path detail (e.g. 'assurance_proof_required') is surfaced
      // separately so callers keep the diagnostic without changing the contract.
      return decide(false, RECEIPT_REQUIRED_STATUS, 'assurance_too_low', {
        have_tier: have, need_tier: requiredTier,
        assurance_tier_source: 'cryptographic_verification',
        assurance_detail: assurance.reason || null,
        tier_evidence: { quorum: tierResult.quorum, signoff: tierResult.signoff },
      });
    }
    // The high-risk action packs define material fields that must be observed
    // by the executor from the system of record. A signed, harmless-looking
    // claim cannot authorize a different real mutation.
    const executionBinding = verifyExecutionBinding({ requirement, receipt, observedAction: observed });
    if (!executionBinding.ok) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'execution_binding_failed', { execution_binding: executionBinding, have_tier: have, assurance_tier_source: 'cryptographic_verification' });
    }
    // OPT-IN admissibility pinning. When the caller pins a required admissibility
    // profile {id, profile_hash} (gate-level requiredAdmissibilityProfile, a
    // per-call admissibilityProfile, or selector.admissibilityProfile), the gate
    // REFUSES unless a presented reliance packet's admissibility block was computed
    // against the SAME pinned profile_hash AND carries an 'admissible' verdict. The
    // gate does NOT re-evaluate raw evidence and does NOT define the bar — the
    // relying party's own evaluator produced the verdict OFFLINE against its pinned
    // profile. Checked BEFORE consumption so a mismatch never burns the receipt.
    // When no profile is pinned, this whole block is inert — behavior is
    // byte-for-byte unchanged from the pre-admissibility gate.
    const pinnedProfile = admissibilityProfile || selector.admissibilityProfile || requiredAdmissibilityProfile;
    if (pinnedProfile) {
      const presentedAdmissibility = admissibility ?? presentedPacket ?? selector.reliancePacket ?? selector.admissibility ?? null;
      const adm = verifyAdmissibilityAgainstPinnedProfile(pinnedProfile, presentedAdmissibility);
      if (!adm.ok) {
        return decide(false, RECEIPT_REQUIRED_STATUS, adm.reason, {
          admissibility_check: adm,
          pinned_profile: { id: pinnedProfile.id ?? null, profile_hash: pinnedProfile.profile_hash ?? null },
          have_tier: have,
          assurance_tier_source: 'cryptographic_verification',
        });
      }
    }
    // One-time consumption (replay defense). Require a stable, issuer-generated
    // receipt_id — never fall back to a content hash, whose canonicalization can
    // differ across language implementations and silently break replay detection
    // when services of different languages share a store.
    const receiptId = receipt?.payload?.receipt_id;
    if (!receiptId) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'receipt_rejected:missing_receipt_id');
    }
    let fresh;
    if (consumptionMode === 'reserve') {
      if (typeof consumption.reserve !== 'function') {
        return decide(false, RECEIPT_REQUIRED_STATUS, 'consumption_store_lacks_reserve', { consumption_key: receiptId });
      }
      fresh = await consumption.reserve(receiptId);
    } else if (consumptionMode === 'none') {
      fresh = true;
    } else {
      fresh = await consumption.consume(receiptId);
    }
    if (!fresh) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'replay_refused', { consumption_key: receiptId });
    }
    const allowExtra = { signer: v.signer, outcome: v.outcome, have_tier: have, assurance_tier_source: 'cryptographic_verification', execution_binding: executionBinding, consumption_mode: consumptionMode };
    // Carry the admissibility block (from the presented packet) onto the decision
    // so a reliance packet built from this decision embeds the verdict the relying
    // party's evaluator computed. Only when something was actually presented.
    const presentedAdmForAllow = admissibility ?? presentedPacket ?? selector.reliancePacket ?? selector.admissibility ?? null;
    if (presentedAdmForAllow) {
      const admBlock = presentedAdmForAllow.admissibility !== undefined ? presentedAdmForAllow.admissibility : presentedAdmForAllow;
      if (admBlock) allowExtra.admissibility = admBlock;
    }
    return decide(true, 200, 'allow', allowExtra);
  }

  /** Express/Connect middleware: refuse the route unless a sufficient receipt is present. */
  function middleware(opts = {}) {
    return async function emiliaGate(req, res, next) {
      let selector = typeof opts.selector === 'function' ? opts.selector(req) : { ...(opts.selector || {}) };
      if (opts.action && !selector.action_type) {
        selector.action_type = typeof opts.action === 'function' ? opts.action(req) : opts.action;
      }
      let doc = null;
      const hdr = req.headers?.['x-emilia-receipt'];
      if (hdr) { try { doc = JSON.parse(Buffer.from(hdr, 'base64').toString('utf8')); } catch { /* fallthrough */ } }
      if (!doc && req.body?.emilia_receipt) doc = req.body.emilia_receipt;
      const observedAction = typeof opts.observedAction === 'function'
        ? opts.observedAction(req)
        : (opts.observedAction || req.emiliaObservedAction || null);
      const out = await check({ selector, receipt: doc, observedAction });
      if (!out.allow) {
        res.setHeader(RECEIPT_REQUIRED_HEADER, out.header);
        return res.status(out.status).json(out.challenge);
      }
      req.emiliaGate = out;
      return next();
    };
  }

  /**
   * Emit a post-execution receipt bound to a prior authorization decision — the
   * "execution emits proof" half of the loop (maps to the EP Commit seal). It
   * commits to the exact authorization decision (`authorizes_decision` = that
   * decision's evidence hash), so authorization and execution are one chain.
   */
  async function recordExecution({ authorization, outcome = 'executed', detail, observedAction = null, executionBinding = null } = {}) {
    const auth = authorization?.evidence || authorization || {};
    return evidence.record({
      kind: 'execution',
      at: new Date(typeof now === 'function' ? now() : now).toISOString(),
      authorizes_decision: auth.hash ?? null,
      action: authorization?.action ?? auth.action ?? null,
      receipt_id: auth.receipt_id ?? null,
      outcome, // 'executed' | 'failed'
      observed_action_hash: observedAction ? hashCanonical(observedAction) : null,
      execution_binding: executionBinding || authorization?.evidence?.execution_binding || authorization?.execution_binding || null,
      ...(detail !== undefined ? { detail } : {}),
    });
  }

  /**
   * Recommended end-to-end path. Reserves the receipt, runs the side effect,
   * commits one-time consumption only after success, and records execution.
   * Once the executor is invoked, an exception is an INDETERMINATE outcome: the
   * external effect may have happened before its response was lost. The receipt
   * is therefore committed (or left reserved if the store is unavailable),
   * never released automatically. Callers that need retries must make the
   * downstream effect idempotent under the receipt id and reconcile its result.
   */
  async function run({ selector = {}, receipt = null, observedAction = null, admissibilityProfile = null, reliancePacket: presentedPacket = null, admissibility = null } = {}, fn, opts = {}) {
    if (typeof fn !== 'function') throw new Error('EMILIA Gate run(): fn is required');
    const authorization = await check({ selector, receipt, observedAction, consumptionMode: 'reserve', admissibilityProfile, reliancePacket: presentedPacket, admissibility });
    if (!authorization.allow) {
      return { ok: false, status: authorization.status, body: authorization.challenge, authorization };
    }
    const receiptId = authorization.evidence?.receipt_id;
    let phase = 'reserved';
    let consumptionCommitted = false;
    try {
      phase = 'effect_attempted';
      const result = await fn(authorization);
      phase = 'effect_returned';
      if (typeof consumption.commit === 'function') await consumption.commit(receiptId);
      consumptionCommitted = true;
      phase = 'consumed';
      if (opts.recordExecution === false) return { ok: true, result, authorization, execution: null, packet: null };
      phase = 'recording_execution';
      const execution = await recordExecution({ authorization, outcome: 'executed', observedAction });
      return { ok: true, result, authorization, execution, packet: reliancePacket({ authorization, execution }) };
    } catch (e) {
      // An exception after invoking fn() cannot establish that no external
      // effect occurred. Burn the approval if possible; if storage is down, the
      // ownership-fenced reservation remains and still blocks replay.
      let consumptionError = null;
      if (!consumptionCommitted && phase !== 'reserved' && typeof consumption.commit === 'function') {
        try {
          await consumption.commit(receiptId);
          consumptionCommitted = true;
        } catch (commitError) {
          consumptionError = commitError;
        }
      }
      if (opts.recordExecution !== false && phase !== 'recording_execution') {
        try {
          await recordExecution({
            authorization,
            outcome: 'indeterminate',
            // Exception text frequently contains provider payloads, record IDs,
            // or secrets. The caller still receives the original exception;
            // the portable evidence record carries only the closed outcome.
            detail: { code: 'effect_attempted_outcome_unknown' },
            observedAction,
          });
        } catch (recordError) {
          if (!consumptionError) consumptionError = recordError;
        }
      }
      if (consumptionError && e && typeof e === 'object') {
        e.consumption_error = String(consumptionError?.message ?? consumptionError);
      }
      throw e;
    }
  }

  /**
   * Wrap any function so it runs only behind a passing gate check, and (unless
   * disabled) emits an execution receipt after it runs — the full firewall loop:
   * request -> check -> execute -> execution receipt. Framework-agnostic.
   */
  function guard(fn, opts = {}) {
    return async function guarded(...args) {
      const selector = typeof opts.selector === 'function' ? opts.selector(...args) : (opts.selector || {});
      const receipt = typeof opts.receipt === 'function' ? opts.receipt(...args) : (opts.receipt ?? null);
      const observedAction = typeof opts.observedAction === 'function'
        ? opts.observedAction(...args)
        : (opts.observedAction || selector.observedAction || null);
      const admissibilityProfile = typeof opts.admissibilityProfile === 'function'
        ? opts.admissibilityProfile(...args)
        : (opts.admissibilityProfile ?? null);
      const presentedPacket = typeof opts.reliancePacket === 'function'
        ? opts.reliancePacket(...args)
        : (opts.reliancePacket ?? opts.admissibility ?? null);
      const out = await run({ selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket }, () => fn(...args), { recordExecution: opts.recordExecution });
      if (!out.ok) {
        const e = new Error(`EMILIA Gate refused (${out.authorization.reason})`);
        e.code = 'EMILIA_RECEIPT_REQUIRED';
        e.gate = out.authorization;
        throw e;
      }
      return out.result;
    };
  }

  function reliancePacket({ authorization, execution = null, binding = null, admissibility = null } = {}) {
    // The admissibility block rides on the authorization decision's evidence when
    // a reliance packet was presented at check() time; an explicit `admissibility`
    // arg overrides it. buildReliancePacket fails closed on a non-'admissible'
    // block, so a do_not_rely verdict can never be laundered into rely here.
    const adm = admissibility
      ?? authorization?.evidence?.admissibility
      ?? authorization?.admissibility
      ?? null;
    return buildReliancePacket({
      decision: authorization,
      execution,
      evidence,
      manifest,
      binding,
      admissibility: adm,
    });
  }

  /** Retention classification over this gate's evidence log (hot/cold/expired/legal-hold). */
  function retention(opts = {}) {
    return classifyRetention(evidence.all(), opts);
  }
  /** The auditor/SIEM export manifest for this gate's evidence log. */
  function retentionExport(opts = {}) {
    return buildRetentionExport(evidence.all(), opts);
  }

  return {
    check, run, recordExecution, middleware, guard, reliancePacket, evidence,
    store: consumption, keyRegistry: registry, retention, retentionExport,
  };
}

export function createTrustedActionFirewall(opts = {}) {
  const { manifest = createDefaultActionRiskManifest(), ...rest } = opts;
  return createGate({ ...rest, manifest });
}

/**
 * EG-1 conformance for an existing gate. The gate MUST have been built trusting
 * `harness.publicKey` (otherwise every valid receipt is rejected and the gate
 * cannot earn EG-1). Returns the EG-1 JSON report.
 * @param {object} o
 * @param {object} o.gate     an EMILIA Gate (createGate/createTrustedActionFirewall)
 * @param {object} o.harness  the harness whose key the gate trusts (createEg1Harness)
 * @param {object} [o.action] the high-risk action to exercise
 * @param {object} [o.selector] the manifest selector for that action
 */
export async function gateConformance({ gate, harness, action, selector = EG1_DEFAULT_SELECTOR } = {}) {
  if (!gate || typeof gate.run !== 'function') {
    throw new Error('gateConformance requires a gate built trusting harness.publicKey');
  }
  if (!harness) throw new Error('gateConformance requires the harness whose key the gate trusts');
  const act = action || harness.action;
  const invoke = makeGateInvoke(gate, { selector, action: act });
  return runEg1({ invoke, harness, action: act });
}

/**
 * Self-certify the reference gate: build a default Trusted Action Firewall that
 * trusts a fresh EG-1 harness key, then run all eight checks. This is the
 * canonical "EMILIA Gate earns EG-1" proof — runnable as a CLI (`eg1.mjs`),
 * shown on /gate, and the template an adopter copies for their integration.
 */
export async function gateConformanceSelfTest({ now } = {}) {
  const harness = createEg1Harness({ now });
  const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, now });
  return gateConformance({ gate, harness });
}

/**
 * CF-1 (Consequence Firewall) conformance for an existing gate. Runs the eight
 * EG-1 runtime checks plus the three CF-1 category checks: the action is
 * declared consequential by the manifest, a gate pinned to the WRONG issuer key
 * refuses a valid receipt, and the allowed run emits offline-verifiable reliance
 * evidence. The `gate` MUST trust `harness.publicKey`; `wrongGate` MUST trust a
 * DIFFERENT key (otherwise wrong_authority_refused cannot be demonstrated).
 * @param {object} o
 * @param {object} o.gate       an EMILIA Gate trusting harness.publicKey
 * @param {object} [o.wrongGate] a sibling gate trusting a different (wrong) key
 * @param {object} o.harness    from createEg1Harness()
 * @param {object} [o.manifest] the action-risk manifest (to resolve the requirement)
 * @param {object} [o.selector] the manifest selector for the action
 * @param {object} [o.action]   the high-risk action to exercise
 */
export async function cf1Conformance({ gate, wrongGate, harness, manifest = null, selector = EG1_DEFAULT_SELECTOR, action } = {}) {
  if (!gate || typeof gate.run !== 'function') throw new Error('cf1Conformance requires a gate built trusting harness.publicKey');
  if (!harness) throw new Error('cf1Conformance requires the harness whose key the gate trusts');
  const act = action || harness.action;
  const invoke = makeGateInvoke(gate, { selector, action: act });
  const wrongInvoke = (wrongGate && typeof wrongGate.run === 'function')
    ? makeGateInvoke(wrongGate, { selector, action: act }) : undefined;
  const requirement = manifest ? findActionRequirement(manifest, selector) : null;
  return runCf1({ invoke, wrongInvoke, harness, action: act, requirement });
}

/**
 * Self-certify the reference gate against CF-1: a default Trusted Action
 * Firewall trusting a fresh harness key, a sibling firewall trusting a DIFFERENT
 * key (for wrong_authority_refused), and the default action-risk manifest (for
 * consequential_action_declared). The canonical "reference gate earns CF-1"
 * proof — runnable as a CLI (`cf1.mjs`).
 */
export async function cf1ConformanceSelfTest({ now } = {}) {
  const harness = createEg1Harness({ now });
  const manifest = createDefaultActionRiskManifest();
  const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, now });
  const wrongHarness = createEg1Harness({ now });
  const wrongGate = createTrustedActionFirewall({ trustedKeys: [wrongHarness.publicKey], approverKeys: wrongHarness.approverKeys, now });
  return cf1Conformance({ gate, wrongGate, harness, manifest, selector: EG1_DEFAULT_SELECTOR, action: harness.action });
}

export default {
  createGate,
  createTrustedActionFirewall,
  receiptAssuranceTier,
  verifyAdmissibilityAgainstPinnedProfile,
  ADMISSIBILITY_VERDICTS,
  MemoryConsumptionStore,
  createEvidenceLog,
  ASSURANCE_TIERS,
  DEFAULT_GATE_MANIFEST,
  HIGH_RISK_ACTION_PACKS,
  gateConformance,
  gateConformanceSelfTest,
  cf1Conformance,
  cf1ConformanceSelfTest,
  CF1_VERSION,
  CF1_CHECKS,
  runCf1,
  createEg1Harness,
  runEg1,
  createKeyRegistry,
  asKeyRegistry,
  classifyRetention,
  buildRetentionExport,
  createDefaultActionControlManifest,
  findActionControl,
  validateActionControlManifest,
};
