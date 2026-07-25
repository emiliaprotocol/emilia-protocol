// SPDX-License-Identifier: Apache-2.0

/**
 * Finite executable model for exactly two security claims:
 *   - signed-denial-cannot-authorize
 *   - scoped-authority-is-pinned
 *
 * A standalone Authorization Evidence Challenge is carried as opaque context.
 * Its presentation method may name another wire format, but the challenge is
 * neither authorization nor a receipt and none of its fields grant authority.
 */

export const DENIAL_AUTHORIZATION_OUTPUTS = Object.freeze([
  "approval",
  "separationOfDuties",
  "quorum",
  "assurance",
  "authority",
  "actionMaterial",
  "reliance",
]);

export const SCOPED_AUTHORITY_CHECKS = Object.freeze([
  "registryIssuerPinned",
  "actionMembership",
  "timeWindowOrdering",
  "amountCeiling",
  "currency",
  "organization",
  "role",
  "policy",
  "monotoneDelegation",
]);

export const FORMAL_MODEL_VERSION =
  "EP-TWO-CLAIM-BOUNDED-ASSURANCE-MODEL-v1";

export const DENIAL_OBLIGATIONS = Object.freeze({
  approval: "SignedDenialApprovalRefused",
  separationOfDuties: "SignedDenialSeparationOfDutiesRefused",
  quorum: "SignedDenialQuorumRefused",
  assurance: "SignedDenialAssuranceRefused",
  authority: "SignedDenialAuthorityRefused",
  actionMaterial: "SignedDenialActionMaterialRefused",
  reliance: "SignedDenialRelianceRefused",
});

export const SCOPED_AUTHORITY_OBLIGATIONS = Object.freeze({
  registryIssuerPinned: "ScopedAuthorityRegistryIssuerPinned",
  actionMembership: "ScopedAuthorityActionMembership",
  timeWindowOrdering: "ScopedAuthorityTimeWindowOrdered",
  amountCeiling: "ScopedAuthorityAmountCeiling",
  currency: "ScopedAuthorityCurrencyPinned",
  organization: "ScopedAuthorityOrganizationPinned",
  role: "ScopedAuthorityRolePinned",
  policy: "ScopedAuthorityPolicyPinned",
  monotoneDelegation: "ScopedAuthorityDelegationMonotone",
});

export const FORMAL_OBLIGATIONS = Object.freeze([
  ...Object.values(DENIAL_OBLIGATIONS),
  ...Object.values(SCOPED_AUTHORITY_OBLIGATIONS),
]);

const clone = (value) => structuredClone(value);

function finiteInstant(value) {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : null;
}

function exactSetSubset(child, parent) {
  if (!Array.isArray(child) || !Array.isArray(parent)) return false;
  const parentSet = new Set(parent);
  return child.every((member) => parentSet.has(member));
}

function wellOrderedWindow(scope) {
  const from = finiteInstant(scope?.validFrom);
  const to = finiteInstant(scope?.validTo);
  return from !== null && to !== null && from <= to;
}

function requestInsideWindow(scope, at) {
  if (!wellOrderedWindow(scope)) return false;
  const instant = finiteInstant(at);
  const from = finiteInstant(scope?.validFrom);
  const to = finiteInstant(scope?.validTo);
  return (
    instant !== null &&
    from !== null &&
    to !== null &&
    from <= instant &&
    instant <= to
  );
}

function finiteNonNegative(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

/**
 * Delegation is monotone only when every child is a subset of its parent on
 * actions, time, amount and exact contextual dimensions. The chain is ordered
 * leaf first: [child, parent, grandparent, ...].
 */
export function isMonotoneDelegation(chain) {
  if (!Array.isArray(chain) || chain.length === 0) return false;
  for (let index = 0; index < chain.length - 1; index += 1) {
    const child = chain[index];
    const parent = chain[index + 1];
    const childFrom = finiteInstant(child?.validFrom);
    const childTo = finiteInstant(child?.validTo);
    const parentFrom = finiteInstant(parent?.validFrom);
    const parentTo = finiteInstant(parent?.validTo);
    if (
      !exactSetSubset(child.actions, parent.actions) ||
      !wellOrderedWindow(child) ||
      !wellOrderedWindow(parent) ||
      childFrom === null ||
      childTo === null ||
      parentFrom === null ||
      parentTo === null ||
      childFrom < parentFrom ||
      childTo > parentTo ||
      !finiteNonNegative(child.maxAmount) ||
      !finiteNonNegative(parent.maxAmount) ||
      child.maxAmount > parent.maxAmount ||
      child.currency !== parent.currency ||
      child.organization !== parent.organization ||
      child.role !== parent.role ||
      child.policy !== parent.policy
    ) {
      return false;
    }
  }
  return true;
}

/**
 * The seven authorization predicates are deliberately calculated separately.
 * They are not aliases for one tuple comparison or a cascade from `approval`.
 */
export function evaluateSignedDecision(input) {
  const decisionIsApproval = input?.decision === "approved";
  const signatureAndContext =
    input?.signatureValid === true &&
    input?.actionDigestMatches === true &&
    input?.nonceMatches === true &&
    input?.policyContextPinned === true;
  const evidenceWindowValid = input?.withinWindow === true;
  const decisionEvidenceVerified = signatureAndContext && evidenceWindowValid;

  const authorizationOutputs = {
    approval: decisionIsApproval && decisionEvidenceVerified,
    separationOfDuties:
      decisionIsApproval &&
      signatureAndContext &&
      input?.nonInitiator === true &&
      input?.distinctApprover === true,
    quorum:
      decisionIsApproval &&
      signatureAndContext &&
      input?.quorumReached === true,
    assurance:
      decisionIsApproval &&
      signatureAndContext &&
      input?.assuranceSatisfied === true,
    authority:
      decisionIsApproval &&
      signatureAndContext &&
      input?.authorityWithinScope === true,
    actionMaterial:
      decisionIsApproval &&
      input?.actionDigestMatches === true &&
      input?.actionMaterialMatches === true,
    reliance:
      decisionIsApproval &&
      signatureAndContext &&
      evidenceWindowValid &&
      input?.nonInitiator === true &&
      input?.distinctApprover === true &&
      input?.quorumReached === true &&
      input?.assuranceSatisfied === true &&
      input?.authorityWithinScope === true &&
      input?.actionMaterialMatches === true &&
      input?.relianceProfilePinned === true &&
      input?.freshnessSatisfied === true,
  };

  return Object.freeze({
    decision: input?.decision ?? null,
    decisionEvidenceVerified,
    authorizationOutputs: Object.freeze(authorizationOutputs),
    challengeContext: clone(input?.challengeContext ?? null),
    challengeAuthorizes: false,
    challengeIsReceipt: false,
  });
}

export function evaluateScopedAuthority(proof, request, pin) {
  const grant = proof?.grant ?? {};
  const chain = [grant, ...(grant.delegationChain ?? [])];
  const checks = {
    registryIssuerPinned:
      typeof pin?.issuerId === "string" &&
      proof?.issuerId === pin.issuerId &&
      proof?.registryHead === pin.registryHead &&
      Number.isSafeInteger(proof?.registryEpoch) &&
      proof.registryEpoch >= pin.minRegistryEpoch,
    actionMembership:
      Array.isArray(grant.actions) &&
      grant.actions.includes(request?.actionType),
    timeWindowOrdering: requestInsideWindow(grant, request?.at),
    amountCeiling:
      finiteNonNegative(request?.amount) &&
      finiteNonNegative(grant.maxAmount) &&
      request.amount <= grant.maxAmount,
    currency:
      typeof request?.currency === "string" &&
      request.currency === grant.currency,
    organization:
      typeof request?.organization === "string" &&
      request.organization === grant.organization,
    role:
      typeof request?.requiredRole === "string" &&
      request.requiredRole === grant.role,
    policy:
      typeof request?.policy === "string" &&
      request.policy === grant.policy,
    monotoneDelegation: isMonotoneDelegation(chain),
  };

  return Object.freeze({
    checks: Object.freeze(checks),
    authorized: SCOPED_AUTHORITY_CHECKS.every(
      (check) => checks[check] === true,
    ),
  });
}

export function signedDenialFixture() {
  return {
    decision: "denied",
    signatureValid: true,
    actionDigestMatches: true,
    nonceMatches: true,
    policyContextPinned: true,
    withinWindow: true,
    nonInitiator: true,
    distinctApprover: true,
    quorumReached: true,
    assuranceSatisfied: true,
    authorityWithinScope: true,
    actionMaterialMatches: true,
    relianceProfilePinned: true,
    freshnessSatisfied: true,
    challengeContext: {
      wireFormat: "draft-schrock-ae-challenge-00",
      actionDigest: `sha256:${"a".repeat(64)}`,
      missingEvidence: [
        {
          type: "authorization_receipt",
          maxAgeSec: 300,
        },
      ],
      freshnessPolicyContext: {
        policyId: "policy:bounded-assurance:v1",
        policyDigest: `sha256:${"b".repeat(64)}`,
      },
      expiresAt: "2026-07-24T20:05:00.000Z",
      nonce: "challenge_nonce_123456",
      presentationMethod: ["ep-aec-v1"],
    },
  };
}

export function scopedAuthorityFixture() {
  const parent = {
    authorityId: "authority:parent",
    actions: ["wire.release", "payment.release"],
    validFrom: "2026-01-01T00:00:00.000Z",
    validTo: "2027-01-01T00:00:00.000Z",
    maxAmount: 1000,
    currency: "USD",
    organization: "org-a",
    role: "finance-operator",
    policy: "policy:wire-release:v1",
    delegationChain: [],
  };
  const grant = {
    authorityId: "authority:child",
    actions: ["wire.release"],
    validFrom: "2026-02-01T00:00:00.000Z",
    validTo: "2026-12-01T00:00:00.000Z",
    maxAmount: 500,
    currency: "USD",
    organization: "org-a",
    role: "finance-operator",
    policy: "policy:wire-release:v1",
    delegationChain: [parent],
  };
  return {
    proof: {
      issuerId: "registry:trusted",
      registryHead: `sha256:${"1".repeat(64)}`,
      registryEpoch: 17,
      grant,
    },
    request: {
      actionType: "wire.release",
      at: "2026-07-24T19:00:00.000Z",
      amount: 100,
      currency: "USD",
      organization: "org-a",
      requiredRole: "finance-operator",
      policy: "policy:wire-release:v1",
    },
    pin: {
      issuerId: "registry:trusted",
      registryHead: `sha256:${"1".repeat(64)}`,
      minRegistryEpoch: 17,
    },
  };
}

function violation(id, violatedCheck, mutate) {
  const fixture = scopedAuthorityFixture();
  mutate(fixture);
  return { id, violatedCheck, ...fixture };
}

export function scopeViolationCases() {
  return [
    violation("unpinned-registry-issuer", "registryIssuerPinned", (fixture) => {
      fixture.pin.issuerId = "registry:other";
    }),
    violation("action-outside-membership", "actionMembership", (fixture) => {
      fixture.request.actionType = "admin.delete";
    }),
    violation("request-after-window", "timeWindowOrdering", (fixture) => {
      fixture.request.at = "2027-02-01T00:00:00.000Z";
    }),
    violation("amount-over-ceiling", "amountCeiling", (fixture) => {
      fixture.request.amount = 501;
    }),
    violation("currency-mismatch", "currency", (fixture) => {
      fixture.request.currency = "EUR";
    }),
    violation("organization-mismatch", "organization", (fixture) => {
      fixture.request.organization = "org-b";
    }),
    violation("role-mismatch", "role", (fixture) => {
      fixture.request.requiredRole = "auditor";
    }),
    violation("policy-mismatch", "policy", (fixture) => {
      fixture.request.policy = "policy:other:v1";
    }),
    violation(
      "delegation-action-widens-parent",
      "monotoneDelegation",
      (fixture) => {
        fixture.proof.grant.actions.push("admin.delete");
      },
    ),
    violation(
      "delegation-time-widens-parent",
      "monotoneDelegation",
      (fixture) => {
        fixture.proof.grant.validFrom = "2025-12-01T00:00:00.000Z";
      },
    ),
    violation(
      "delegation-amount-widens-parent",
      "monotoneDelegation",
      (fixture) => {
        fixture.proof.grant.maxAmount = 1001;
      },
    ),
    violation(
      "delegation-currency-widens-parent",
      "monotoneDelegation",
      (fixture) => {
        fixture.proof.grant.currency = "EUR";
        fixture.request.currency = "EUR";
      },
    ),
    violation(
      "delegation-organization-widens-parent",
      "monotoneDelegation",
      (fixture) => {
        fixture.proof.grant.organization = "org-b";
        fixture.request.organization = "org-b";
      },
    ),
    violation(
      "delegation-role-widens-parent",
      "monotoneDelegation",
      (fixture) => {
        fixture.proof.grant.role = "auditor";
        fixture.request.requiredRole = "auditor";
      },
    ),
    violation(
      "delegation-policy-widens-parent",
      "monotoneDelegation",
      (fixture) => {
        fixture.proof.grant.policy = "policy:other:v1";
        fixture.request.policy = "policy:other:v1";
      },
    ),
  ];
}
