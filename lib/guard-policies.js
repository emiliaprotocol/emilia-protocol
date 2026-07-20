/**
 * EP GovGuard + FinGuard — pre-execution policy templates.
 * @license Apache-2.0
 *
 * Implements the policy decision logic from
 * /Users/imanschrock/Desktop/Ventures/emilia_govguard_finguard_coding_changes.md
 * §4 ("Policy Engine"), backed by EP's existing handshake/policy primitives.
 *
 * Modes (per MD §9):
 *   - observe — evaluate, generate receipt, log decision, NEVER block
 *   - warn    — evaluate, return decision, allow caller to choose
 *   - enforce — evaluate, fail-closed if signoff missing or policy denies
 *
 * Decision semantics (per MD §4.2):
 *   allow              — execute without further gating
 *   observe            — log only (used in observe mode)
 *   allow_with_signoff — require human approval before consume
 *   deny               — refuse outright (impossible travel, compromised device)
 */

import crypto from 'node:crypto';
import { screenAml } from './aml/screening.js';

// ─── Action types (per MD §4.3) ───────────────────────────────────────────

export const GUARD_ACTION_TYPES = Object.freeze({
  // GovGuard
  BENEFIT_BANK_ACCOUNT_CHANGE: 'benefit_bank_account_change',
  BENEFIT_ADDRESS_CHANGE: 'benefit_address_change',
  CASEWORKER_OVERRIDE: 'caseworker_override',
  GOV_VENDOR_PAYMENT_DESTINATION_CHANGE: 'gov.vendor_payment_destination_change',
  GOV_DISBURSEMENT_RELEASE: 'gov.disbursement_release',
  GOV_GRANT_DISBURSEMENT: 'gov.grant_disbursement',
  GOV_PROVIDER_ENROLLMENT_CHANGE: 'gov.provider_enrollment_change',
  GOV_ELIGIBILITY_OVERRIDE: 'gov.eligibility_override',
  // FinGuard
  VENDOR_BANK_ACCOUNT_CHANGE: 'vendor_bank_account_change',
  BENEFICIARY_CREATION: 'beneficiary_creation',
  LARGE_PAYMENT_RELEASE: 'large_payment_release',
  AI_AGENT_PAYMENT_ACTION: 'ai_agent_payment_action',
  // Control plane
  POLICY_ROLLOUT: 'policy_rollout',
});

export const GUARD_DECISIONS = Object.freeze({
  ALLOW: 'allow',
  OBSERVE: 'observe',
  ALLOW_WITH_SIGNOFF: 'allow_with_signoff',
  DENY: 'deny',
});

export const ENFORCEMENT_MODES = Object.freeze({
  OBSERVE: 'observe',
  WARN: 'warn',
  ENFORCE: 'enforce',
});

/**
 * Fields whose change indicates the destination of money is moving.
 * Per MD §4.4 — any change to these requires accountable signoff.
 */
const MONEY_DESTINATION_FIELDS = Object.freeze([
  'destination_hash',
  'payment_destination_hash',
  'bank_account',
  'bank_account_hash',
  'routing_number',
  'routing_number_hash',
  'iban',
  'swift_bic',
  'beneficiary_name',
  'payment_address',
]);

/**
 * Benefit/contact fields that can redirect notices, credentials, eligibility
 * evidence, or downstream disbursement routing without touching a bank-field
 * directly. GovGuard treats these as Class-A signoff fields; cosmetic fields
 * such as display_name can still default-allow.
 */
const BENEFIT_IDENTITY_ROUTING_FIELDS = Object.freeze([
  'mailing_address',
  'residential_address',
  'eligibility_address',
  'address_hash',
  'mailing_address_hash',
  'phone',
  'phone_hash',
  'email',
  'email_hash',
  'contact_method',
  'identity_document',
  'identity_document_hash',
  'identity_status',
]);

/**
 * Risk flags that fail closed (deny outright, no signoff path).
 */
const HARD_DENY_FLAGS = Object.freeze(['impossible_travel', 'known_compromised_device']);

/**
 * Amount-tiered escalation for payment releases (per MD §4.4).
 *   >= $50,000    → single accountable signoff
 *   >= $1,000,000 → dual authorization (a second, senior approver)
 * The tier is surfaced as `signoff_tier` on the decision so consume-time
 * enforcement and the receipt record how strong the approval must be.
 */
const SIGNOFF_THRESHOLD_USD = 50_000;
const DUAL_AUTH_THRESHOLD_USD = 1_000_000;
// Back-compat alias for any external reference to the original constant.
const LARGE_PAYMENT_THRESHOLD_USD = SIGNOFF_THRESHOLD_USD;

/** Resolve the payment signoff tier for a USD amount, or null if below floor. */
function paymentSignoffTier(amount) {
  if (typeof amount !== 'number' || Number.isNaN(amount)) return null;
  if (amount >= DUAL_AUTH_THRESHOLD_USD) return 'dual';
  if (amount >= SIGNOFF_THRESHOLD_USD) return 'single';
  return null;
}

/**
 * High-risk action types that require Class A by default: a named human must
 * approve with an approver-held device key (WebAuthn/passkey, key_class 'A') or
 * a quorum — a software/platform signer (key_class 'C') is insufficient.
 */
const CLASS_A_ACTIONS = Object.freeze([
  GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE,
  GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE,
  GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE,
  GUARD_ACTION_TYPES.GOV_VENDOR_PAYMENT_DESTINATION_CHANGE,
  GUARD_ACTION_TYPES.GOV_DISBURSEMENT_RELEASE,
  GUARD_ACTION_TYPES.GOV_GRANT_DISBURSEMENT,
  GUARD_ACTION_TYPES.GOV_PROVIDER_ENROLLMENT_CHANGE,
  GUARD_ACTION_TYPES.GOV_ELIGIBILITY_OVERRIDE,
  GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE,
  GUARD_ACTION_TYPES.BENEFICIARY_CREATION,
  GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
  GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION,
  GUARD_ACTION_TYPES.POLICY_ROLLOUT,
]);

/**
 * Class A by default. Stamp `requiredAssurance: 'A'` on any signoff-requiring
 * decision for a high-risk action (the CLASS_A_ACTIONS set, or any money-
 * destination change). This is recorded on the receipt and is the flag the
 * consume gate / strict verifier enforce against — a software signer stays
 * valid only for low-risk or observe-mode actions. Purely additive: callers
 * that don't read it are unchanged.
 */
function stampAssurance(decision, input) {
  if (!decision?.signoffRequired) return decision;
  const touchesMoneyDestination = (input.targetChangedFields || []).some((f) =>
    MONEY_DESTINATION_FIELDS.includes(f),
  );
  if (CLASS_A_ACTIONS.includes(input.actionType) || touchesMoneyDestination) {
    return { ...decision, requiredAssurance: 'A' };
  }
  return decision;
}

/**
 * MINT-TIME KEY-CLASS FLOOR — unconditionally-critical action types.
 *
 * The action-risk manifest (packages/gate/action-packs.js) marks money
 * movement, changing where money flows, and payee creation as `critical`.
 * packages/require-receipt + packages/gate already refuse to author or issue a
 * bare software-tier receipt for a `critical` action (the critical->class_a
 * floor). The mint path must enforce the SAME floor at issuance: these actions
 * must never be mintable as a bare ALLOW (a software/machine-tier receipt with
 * no human signoff).
 *
 * These CLASS_A_ACTIONS could previously fall through basePolicy() to the
 * default-ALLOW branch, issuing exactly that bare receipt whenever the caller
 * did not happen to name a money-destination changed field (or, for a payment
 * release, supplied an amount below the $50k threshold or omitted it):
 *   - benefit_bank_account_change  (no explicit basePolicy branch)
 *   - beneficiary_creation         (no explicit basePolicy branch)
 *   - large_payment_release        (amount < $50k, or amount omitted)
 *
 * This set is DELIBERATELY NARROWER than CLASS_A_ACTIONS: it excludes
 * benefit_address_change, whose criticality is field-conditional by design (a
 * cosmetic display_name change is meant to default-allow; only identity/routing
 * fields escalate, handled in basePolicy). We floor only the action types that
 * are critical no matter which fields change: releasing money and moving where
 * money goes. The other CLASS_A_ACTIONS (caseworker_override, the gov.* family,
 * ai_agent_payment_action, and any money-destination field change) already
 * escalate to signoff in basePolicy, so this floor never sees them as a bare
 * ALLOW.
 */
const MINT_CRITICAL_FLOOR_ACTIONS = Object.freeze([
  GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE,
  GUARD_ACTION_TYPES.BENEFICIARY_CREATION,
  GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
]);

/**
 * KEY-CLASS FLOOR (mint-time, fail-closed).
 *
 * Any unconditionally-critical action (MINT_CRITICAL_FLOOR_ACTIONS) whose base
 * decision is a bare ALLOW is ESCALATED to ALLOW_WITH_SIGNOFF with
 * requiredAssurance:'A', so the receipt demands a named human (Class-A) or
 * quorum before consume. It only ever makes a decision MORE restrictive; it
 * never relaxes a DENY or an existing signoff, and it is inert for every other
 * action type. This is the weakest-credible (fail-safe) default: when the
 * engine has no positive reason to allow a critical action outright, it
 * requires a human rather than issuing a bare software-tier receipt.
 */
function applyCriticalKeyClassFloor(decision, input) {
  if (!decision || decision.decision !== GUARD_DECISIONS.ALLOW) return decision;
  if (!MINT_CRITICAL_FLOOR_ACTIONS.includes(input.actionType)) return decision;
  return {
    ...decision,
    decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
    signoffRequired: true,
    requiredAssurance: 'A',
    reasons: [
      'Critical action (key-class floor): a named human signoff (Class A) or quorum is required before this action can be minted at a software tier.',
      ...(decision.reasons || []),
    ],
  };
}

/**
 * #4 Policy-content hash. The guard engine's "policy" is its rule material (the
 * money-destination fields, thresholds, hard-deny flags, and Class-A set that
 * actually determine a decision), not a DB row. Bind a hash of that CONTENT
 * into the receipt's policy_hash so a verifier detects a change to the rules in
 * effect — not just the policy_id/version label. Bump `policy_engine` when the
 * rule material changes meaningfully.
 */
export const GUARD_POLICY_CONTENT = Object.freeze({
  policy_engine: 'EP-GUARD-POLICY-v2',
  money_destination_fields: [...MONEY_DESTINATION_FIELDS],
  benefit_identity_routing_fields: [...BENEFIT_IDENTITY_ROUTING_FIELDS],
  hard_deny_flags: [...HARD_DENY_FLAGS],
  signoff_threshold_usd: SIGNOFF_THRESHOLD_USD,
  dual_auth_threshold_usd: DUAL_AUTH_THRESHOLD_USD,
  class_a_actions: [...CLASS_A_ACTIONS],
});

/** SHA-256 of the canonical guard policy content (hex). */
export function guardPolicyContentHash() {
  return hashCanonicalAction(GUARD_POLICY_CONTENT);
}

/**
 * Compute the receipt policy_hash binding both WHICH policy applied and the
 * exact rule CONTENT that governed the decision.
 */
export function computeGuardPolicyHash(policyId) {
  return hashCanonicalAction({ policy_id: policyId, policy_content_hash: guardPolicyContentHash() });
}

/**
 * Evaluate a guard policy against an action input. Pure function — no I/O.
 *
 * @param {object} input - the policy input
 * @param {string} input.organizationId
 * @param {string} input.actorId
 * @param {string} input.actorRole
 * @param {string} input.actionType
 * @param {string[]} input.targetChangedFields
 * @param {number} [input.amount]
 * @param {string} [input.currency]
 * @param {string[]} input.riskFlags
 * @param {'password'|'mfa'|'phishing_resistant_mfa'|'service_account'} input.authStrength
 * @param {string} [input.initiatorId]
 * @param {string} [input.approverId]
 * @param {object} [input.aml] - optional AML context (counterpartyName,
 *   counterpartyCountry, amount, recentAmounts). When present, sanctions hits
 *   fail closed and structuring/velocity escalate to signoff.
 * @returns {{ decision: string, reasons: string[], signoffRequired: boolean, aml_signals?: string[], requiredAssurance?: string }}
 */
export function evaluateGuardPolicy(input) {
  // Base policy, then Class-A assurance stamp, then the mint-time key-class
  // floor. The floor runs on the stamped decision so a critical action that
  // fell through to a bare ALLOW is escalated to ALLOW_WITH_SIGNOFF (Class A)
  // BEFORE AML screening — AML can only escalate further (deny still trumps
  // below), never relax it.
  const base = applyCriticalKeyClassFloor(stampAssurance(basePolicy(input), input), input);
  const aml = screenAml(input?.aml);

  // A sanctions/embargo hit fails closed and trumps any non-deny base decision.
  if (aml.recommendation === 'deny' && base.decision !== GUARD_DECISIONS.DENY) {
    return {
      decision: GUARD_DECISIONS.DENY,
      reasons: ['AML: blocked counterparty or embargoed jurisdiction — fail closed.', ...aml.signals],
      signoffRequired: false,
      aml_signals: aml.signals,
    };
  }

  // Structuring / velocity / near-threshold escalate an otherwise-allow action
  // to accountable signoff (a human owns the AML risk).
  if (base.decision === GUARD_DECISIONS.ALLOW && aml.recommendation === 'signoff') {
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons: ['AML risk signals require accountable signoff.', ...aml.signals],
      signoffRequired: true,
      requiredAssurance: 'A', // AML-escalated money movement is high-risk by nature.
      aml_signals: aml.signals,
    };
  }

  // Otherwise return the base decision, surfacing any AML signals as evidence.
  return aml.signals.length ? { ...base, aml_signals: aml.signals } : base;
}

/** Base GovGuard/FinGuard policy (pre-AML). Pure function — no I/O. */
function basePolicy(input) {
  const reasons = [];

  // ── Layer 1: hard-deny risk flags (per MD §4.4) ────────────────────────
  for (const flag of HARD_DENY_FLAGS) {
    if (input.riskFlags?.includes(flag)) {
      return {
        decision: GUARD_DECISIONS.DENY,
        reasons: [denyReason(flag)],
        signoffRequired: false,
      };
    }
  }

  // ── Layer 2: money-destination changes always require signoff ──────────
  const touchesMoneyDestination = (input.targetChangedFields || []).some((f) =>
    MONEY_DESTINATION_FIELDS.includes(f),
  );
  if (touchesMoneyDestination) {
    reasons.push('Money destination change requires accountable signoff.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  // ── Layer 3: action-type-specific gates ────────────────────────────────
  if (input.actionType === GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE) {
    const touchesBenefitIdentityRouting = (input.targetChangedFields || []).some((f) =>
      BENEFIT_IDENTITY_ROUTING_FIELDS.includes(f),
    );
    if (touchesBenefitIdentityRouting) {
      reasons.push('Benefit address/contact/identity routing change requires accountable signoff.');
      return {
        decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
        reasons,
        signoffRequired: true,
      };
    }
  }

  if (input.actionType === GUARD_ACTION_TYPES.GOV_VENDOR_PAYMENT_DESTINATION_CHANGE) {
    reasons.push('Government vendor payment-destination change requires accountable signoff before future payments can route.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.GOV_DISBURSEMENT_RELEASE
    || input.actionType === GUARD_ACTION_TYPES.GOV_GRANT_DISBURSEMENT) {
    const tier = paymentSignoffTier(input.amount) || 'single';
    if (tier === 'dual') {
      reasons.push(
        `Government disbursement of $${input.amount} >= $${DUAL_AUTH_THRESHOLD_USD} requires dual authorization.`,
      );
    } else {
      reasons.push('Government disbursement release requires accountable signoff before funds move.');
    }
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
      signoffTier: tier,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.GOV_PROVIDER_ENROLLMENT_CHANGE) {
    reasons.push('Provider enrollment change requires accountable signoff before the provider can receive or redirect public funds.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.GOV_ELIGIBILITY_OVERRIDE) {
    reasons.push('Eligibility override requires supervisor signoff because it changes a regulated benefit decision.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE) {
    const tier = paymentSignoffTier(input.amount);
    if (tier === 'dual') {
      reasons.push(
        `Payment release of $${input.amount} >= $${DUAL_AUTH_THRESHOLD_USD} requires dual authorization (a second, senior approver).`,
      );
      return {
        decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
        reasons,
        signoffRequired: true,
        signoffTier: 'dual',
      };
    }
    if (tier === 'single') {
      reasons.push(
        `Payment release of $${input.amount} >= $${SIGNOFF_THRESHOLD_USD} requires accountable signoff.`,
      );
      return {
        decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
        reasons,
        signoffRequired: true,
        signoffTier: 'single',
      };
    }
  }

  if (input.actionType === GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION) {
    reasons.push('AI-agent initiated financial action requires human accountability.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE) {
    reasons.push('Caseworker override requires supervisor signoff.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.POLICY_ROLLOUT) {
    reasons.push('Policy rollout activation requires accountable human signoff.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  // ── Layer 4: default-allow ─────────────────────────────────────────────
  return {
    decision: GUARD_DECISIONS.ALLOW,
    reasons: ['Policy satisfied.'],
    signoffRequired: false,
  };
}

// ─── PIP-007: initiator escalation attestation ─────────────────────────────
//
// When the engine escalates an action to ALLOW_WITH_SIGNOFF, the contexts built
// for that receipt (I-D §6.2) may carry an `initiator_attestation` — the
// initiator's own stated reason for asking a human (PIP-007 §1). This is the
// population mapping from the deterministic escalation sources here to the
// PIP-007 enum, exactly as PIP-007's Deployment-guidance table specifies. We
// never fabricate `uncertainty`/`novelty` signals the engine does not have:
// `uncertainty` is used ONLY where the AML layer already produced an
// uncertainty-shaped signal (structuring/velocity/near-threshold).

/** PIP-007 §1: free-text statement cap. */
export const ATTESTATION_STATEMENT_MAX = 280;

/** Cap a reason string to the PIP-007 §1 statement length (ellipsis-safe). */
function capStatement(s) {
  const text = String(s || '');
  if (text.length <= ATTESTATION_STATEMENT_MAX) return text;
  return `${text.slice(0, ATTESTATION_STATEMENT_MAX - 1)}…`;
}

/**
 * Build the deterministic rule id (`policy_basis`) for an escalation source.
 * The rule lives under the evaluated policy, so the basis is
 * `<policyId>/rule:<name>` — the same shape as PIP-007's example
 * (`ep:policy:wires-over-100k@v12/rule:dual-auth`).
 */
function ruleBasis(policyId, ruleName) {
  return `${policyId || 'ep:policy:guard'}/rule:${ruleName}`;
}

/**
 * Map a guard decision (and the inputs that produced it) to a PIP-007 §1
 * initiator escalation attestation. Returns undefined when the decision did not
 * escalate to signoff (no context, no attestation) — per PIP-007, non-escalation
 * is out of wire-format scope.
 *
 * Trigger/basis precedence (PIP-007 §1): `escalation_trigger` names the
 * substantive reason even though a deterministic rule fired; `policy_basis` is
 * populated in every row precisely because one did. `policy_rule` is used only
 * where no substantive category fits (the money-destination change).
 *
 * @param {{ decision:string, signoffRequired?:boolean, reasons?:string[], signoffTier?:string, aml_signals?:string[] }} decision
 * @param {object} [ctx]
 * @param {string}   [ctx.actionType]          - GUARD_ACTION_TYPES.* value
 * @param {string}   [ctx.policyId]            - the evaluated policy id
 * @param {string[]} [ctx.targetChangedFields] - fields the action changes
 * @returns {{ escalation_trigger:string, policy_basis?:string, statement?:string } | undefined}
 */
export function buildInitiatorAttestation(decision, { actionType, policyId, targetChangedFields } = {}) {
  if (!decision || !decision.signoffRequired || decision.decision !== GUARD_DECISIONS.ALLOW_WITH_SIGNOFF) {
    return undefined;
  }

  const statement = capStatement((decision.reasons || []).join(' '));

  // AML structuring/velocity/near-threshold → uncertainty (the AML rule).
  // The engine HAS this uncertainty-shaped signal, so it is not fabricated.
  if (Array.isArray(decision.aml_signals) && decision.aml_signals.length > 0) {
    return { escalation_trigger: 'uncertainty', policy_basis: ruleBasis(policyId, 'aml-screening'), statement };
  }

  // AI-agent-initiated financial action → authority_gap (the agent-action rule).
  if (actionType === GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION) {
    return { escalation_trigger: 'authority_gap', policy_basis: ruleBasis(policyId, 'ai-agent-action'), statement };
  }

  // Money-destination field change → policy_rule (no substantive category
  // fits; the destination-change rule made it mandatory).
  const touchesMoneyDestination = (targetChangedFields || []).some((f) => MONEY_DESTINATION_FIELDS.includes(f));
  if (touchesMoneyDestination) {
    return { escalation_trigger: 'policy_rule', policy_basis: ruleBasis(policyId, 'money-destination-change'), statement };
  }

  // Large-payment release (single/dual tier) → magnitude (the threshold rule).
  if ((actionType === GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE
    || actionType === GUARD_ACTION_TYPES.GOV_DISBURSEMENT_RELEASE
    || actionType === GUARD_ACTION_TYPES.GOV_GRANT_DISBURSEMENT) && decision.signoffTier) {
    return { escalation_trigger: 'magnitude', policy_basis: ruleBasis(policyId, `payment-threshold-${decision.signoffTier}`), statement };
  }

  // GovGuard deterministic rules with no better substantive trigger.
  if (actionType === GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE
    || actionType === GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE
    || actionType === GUARD_ACTION_TYPES.GOV_VENDOR_PAYMENT_DESTINATION_CHANGE
    || actionType === GUARD_ACTION_TYPES.GOV_PROVIDER_ENROLLMENT_CHANGE
    || actionType === GUARD_ACTION_TYPES.GOV_ELIGIBILITY_OVERRIDE
    || actionType === GUARD_ACTION_TYPES.POLICY_ROLLOUT) {
    const rule = {
      [GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE]: 'caseworker-override',
      [GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE]: 'benefit-identity-routing-change',
      [GUARD_ACTION_TYPES.GOV_VENDOR_PAYMENT_DESTINATION_CHANGE]: 'gov-vendor-payment-destination-change',
      [GUARD_ACTION_TYPES.GOV_PROVIDER_ENROLLMENT_CHANGE]: 'gov-provider-enrollment-change',
      [GUARD_ACTION_TYPES.GOV_ELIGIBILITY_OVERRIDE]: 'gov-eligibility-override',
      [GUARD_ACTION_TYPES.POLICY_ROLLOUT]: 'policy-rollout',
    }[actionType];
    return { escalation_trigger: 'policy_rule', policy_basis: ruleBasis(policyId, rule), statement };
  }

  // Any other signoff-required escalation came from a deterministic rule with no
  // substantive category that fits — encode it as policy_rule (PIP-007 §1
  // requires policy_basis whenever a rule fired).
  return { escalation_trigger: 'policy_rule', policy_basis: ruleBasis(policyId, 'signoff-required'), statement };
}

/**
 * Apply enforcement mode to a base decision (per MD §9).
 *
 * Observe mode: any blocking decision becomes observe; signoffRequired stays
 * true so the receipt records what *would* have been required, but the
 * caller is not blocked.
 *
 * Warn mode: returns the decision verbatim; the caller decides whether to
 * proceed (used for staged rollouts).
 *
 * Enforce mode: returns the decision verbatim; caller MUST honor it.
 *
 * @param {{decision: string, reasons: string[], signoffRequired: boolean}} base
 * @param {string} mode - one of ENFORCEMENT_MODES
 */
export function applyEnforcementMode(base, mode) {
  if (mode === ENFORCEMENT_MODES.OBSERVE) {
    if (base.decision === GUARD_DECISIONS.DENY || base.decision === GUARD_DECISIONS.ALLOW_WITH_SIGNOFF) {
      return {
        ...base,
        decision: GUARD_DECISIONS.OBSERVE,
        observed_decision: base.decision,
        reasons: [
          ...base.reasons,
          'Mode=observe: this would have been blocked or required signoff in enforce mode.',
        ],
      };
    }
  }
  return base;
}

/**
 * Canonical action hash (per MD §3.1). Deterministic JSON serialization
 * with sorted keys. NOT a security boundary by itself — it is the
 * binding-key that pins a receipt to the exact action. EP's existing
 * lib/handshake/invariants.js sha256() helper uses the same shape.
 *
 * @param {Record<string, unknown>} action
 * @returns {string} hex-encoded sha256
 */
export function hashCanonicalAction(action) {
  return crypto.createHash('sha256').update(canonicalize(action)).digest('hex');
}

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function denyReason(flag) {
  if (flag === 'impossible_travel') return 'Impossible travel detected.';
  if (flag === 'known_compromised_device') return 'Known compromised device.';
  return `Risk flag: ${flag}`;
}
