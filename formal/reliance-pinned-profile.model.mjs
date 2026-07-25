// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-PINNED-PROFILE-BOUNDED-MODEL-v1
 *
 * A finite executable abstraction of the relying party's closed reliance
 * decision. The model deliberately keeps every required leg independent:
 * cryptographic signed material is not assurance, assurance is not
 * organization-bound authority, registry-head equality is not epoch ordering,
 * and authenticated revocation is not freshness.
 */

export const FORMAL_MODEL_VERSION =
  "EP-RELIANCE-PINNED-PROFILE-BOUNDED-MODEL-v1";

export const FORMAL_OBLIGATIONS = Object.freeze([
  "PinnedProfileRequired",
  "SignedMaterialRequired",
  "AssuranceRequired",
  "OrganizationAuthorityRequired",
  "ExactRegistryHeadRequired",
  "RegistryEpochFloorOrdered",
  "PolicyRequired",
  "AuthenticatedRevocationRequired",
  "FreshRevocationRequired",
  "IssuerRequired",
  "UnconsumedStateRequired",
]);

const BOOLEAN_REQUIREMENTS = Object.freeze({
  PinnedProfileRequired: "profile_pinned",
  SignedMaterialRequired: "signed_material_valid",
  AssuranceRequired: "assurance_satisfied",
  OrganizationAuthorityRequired: "organization_authority_matches",
  ExactRegistryHeadRequired: "registry_head_exact",
  PolicyRequired: "policy_accepted",
  AuthenticatedRevocationRequired: "revocation_authenticated",
  FreshRevocationRequired: "revocation_fresh",
  IssuerRequired: "issuer_pinned",
  UnconsumedStateRequired: "authorization_unconsumed",
});

export const BOOLEAN_STATE_FIELDS = Object.freeze(
  Object.values(BOOLEAN_REQUIREMENTS),
);

const EPOCHS = Object.freeze([0, 1, 2]);

export const SOUND_RELIANCE_STATE = Object.freeze({
  ...Object.fromEntries(
    BOOLEAN_STATE_FIELDS.map((field) => [field, true]),
  ),
  registry_epoch: 1,
  minimum_registry_epoch: 1,
});

export const UNSAFE_RELIANCE_VARIANTS = Object.freeze(
  Object.fromEntries(
    FORMAL_OBLIGATIONS.map((obligation) => [
      obligation,
      Object.freeze({ bypass_obligation: obligation }),
    ]),
  ),
);

export function relianceRequirementSatisfied(state, obligation) {
  if (obligation === "RegistryEpochFloorOrdered") {
    return (
      Number.isInteger(state.registry_epoch) &&
      Number.isInteger(state.minimum_registry_epoch) &&
      state.registry_epoch >= state.minimum_registry_epoch
    );
  }
  const field = BOOLEAN_REQUIREMENTS[obligation];
  if (!field) throw new Error(`unknown reliance obligation: ${obligation}`);
  return state[field] === true;
}

export function evaluateRelianceState(state, semantics = {}) {
  const checks = Object.fromEntries(
    FORMAL_OBLIGATIONS.map((obligation) => [
      obligation,
      semantics.bypass_obligation === obligation
        ? true
        : relianceRequirementSatisfied(state, obligation),
    ]),
  );
  const failedObligation =
    FORMAL_OBLIGATIONS.find((obligation) => checks[obligation] !== true) ??
    null;
  return {
    accepted: failedObligation === null,
    failed_obligation: failedObligation,
    checks,
  };
}

export function* enumerateRelianceStates() {
  const combinations = 1 << BOOLEAN_STATE_FIELDS.length;
  for (let mask = 0; mask < combinations; mask += 1) {
    const booleans = Object.fromEntries(
      BOOLEAN_STATE_FIELDS.map((field, index) => [
        field,
        (mask & (1 << index)) !== 0,
      ]),
    );
    for (const registry_epoch of EPOCHS) {
      for (const minimum_registry_epoch of EPOCHS) {
        yield {
          ...booleans,
          registry_epoch,
          minimum_registry_epoch,
        };
      }
    }
  }
}

export const MODEL_INTERNALS = Object.freeze({
  booleanRequirements: BOOLEAN_REQUIREMENTS,
  epochs: EPOCHS,
});
