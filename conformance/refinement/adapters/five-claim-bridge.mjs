// SPDX-License-Identifier: Apache-2.0

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
} from "node:crypto";
import { readFileSync } from "node:fs";

import { computeCaid } from "../../../caid/impl/js/caid.mjs";
import { verifyAuthorityProofViaDocument } from "../../../lib/authority/document-proof-join.js";
import {
  evaluateBranchAllocation,
} from "../../../formal/conservation-authority.model.mjs";
import {
  evaluateAuthorityState,
  evaluateOutcomeState,
} from "../../../formal/outcome-authority-join.model.mjs";
import {
  AUTHORITY_ALLOCATION_VERSION,
  CAPABILITY_CAID_SCOPE_PROFILE,
  createDefaultActionRiskManifest,
  createEg1Harness,
  createGate,
  createMemoryAuthorityAllocationStore,
  createMemoryCapabilityStore,
  createRuntimeMonitor,
  mintCapabilityReceipt,
  validateAuthorityAllocationSnapshot,
} from "../../../packages/gate/dist/index.js";
import { canonicalEvidenceJson } from "../../../packages/gate/dist/evidence.js";
import { canonicalize as gateCanonicalize } from "../../../packages/gate/dist/execution-binding.js";
import {
  createReceiptProgramKernel,
  verifyReceiptProgramCertificate,
} from "../../../packages/gate/dist/receipt-program.js";
import { verifyAuthorityProgram } from "../../../packages/verify/dist/authority-program.js";
import {
  canonicalize as verifyCanonicalize,
  verifyOutcomeBinding,
  verifyOutcomeObservationSet,
} from "../../../packages/verify/dist/index.js";

const OUTCOME_VECTORS = readJson(
  new URL("../../vectors/outcome-binding.exec.v1.json", import.meta.url),
);
const OUTCOME_SOURCE_VECTORS = readJson(
  new URL("../../vectors/outcome-binding.sources.v1.json", import.meta.url),
);
const AUTHORITY_JOIN_VECTORS = readJson(
  new URL(
    "../../vectors/authority-document-proof-join.exec.v1.json",
    import.meta.url,
  ),
);
const AUTHORITY_PROGRAM_VECTOR = readJson(
  new URL("../../vectors/authority-program.v1.json", import.meta.url),
);

function readJson(url) {
  return JSON.parse(readFileSync(url, "utf8"));
}

function assertBridge(condition, message) {
  if (!condition) {
    throw new Error(`five-claim runtime bridge failed: ${message}`);
  }
}

function relation(sharedInput, formalProjection, runtimeProjection) {
  const fields = Object.keys(formalProjection).sort();
  assertBridge(
    fields.length > 0 &&
      fields.every(
        (field) =>
          Object.hasOwn(runtimeProjection, field) &&
          Object.is(formalProjection[field], runtimeProjection[field]),
      ),
    "formal/runtime relation projections did not match",
  );
  return {
    shared_input: sharedInput,
    formal_projection: formalProjection,
    runtime_projection: runtimeProjection,
    fields,
  };
}

function deterministicEd25519(byte) {
  const seed = Buffer.alloc(32, byte);
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function publicKeyB64(privateKey) {
  return createPublicKey(privateKey)
    .export({ type: "spki", format: "der" })
    .toString("base64url");
}

function signedBaseReceipt(privateKey) {
  const payload = {
    receipt_id: "ep:receipt:refinement-authority",
    created_at: "2026-07-24T16:00:00.000Z",
    subject: "ep:operator:refinement",
    claim: {
      action_type: "payment.release",
      outcome: "allow",
      capability_only: true,
    },
  };
  return {
    "@version": "EP-RECEIPT-v1",
    payload,
    signature: {
      algorithm: "Ed25519",
      value: cryptoSign(
        null,
        Buffer.from(gateCanonicalize(payload)),
        privateKey,
      ).toString("base64url"),
    },
    public_key: publicKeyB64(privateKey),
  };
}

export async function runConservationAuthorityScenario(scenario) {
  const overallocated =
    scenario === "conservation-authority-sibling-overallocation-refused";
  if (
    scenario !== "conservation-authority-balanced-allocation" &&
    !overallocated
  ) {
    throw new Error(
      `unsupported conservation-authority scenario: ${scenario}`,
    );
  }
  const sharedInput = {
    parent_budget: { cents: 2, calls: 2 },
    allocations: overallocated
      ? [
          { cents: 2, calls: 1 },
          { cents: 1, calls: 1 },
        ]
      : [
          { cents: 1, calls: 1 },
          { cents: 1, calls: 1 },
        ],
    reservations: [
      { cents: 0, calls: 0 },
      { cents: 0, calls: 0 },
    ],
    allocation_epoch_matches_authority: true,
  };
  const formal = evaluateBranchAllocation(sharedInput);
  const pin = {
    relying_party_id: "rp:scenario-conformance",
    authority_head: `sha256:${"1".repeat(64)}`,
    authority_epoch: 7,
  };
  const expiry = "2026-07-25T16:00:00.000Z";
  /** @type {import("../../../packages/gate/src/authority-allocation.ts").AuthorityAllocationSnapshot} */
  const snapshot = {
    version: AUTHORITY_ALLOCATION_VERSION,
    relying_party_id: pin.relying_party_id,
    parent_id: "authority:scenario-parent",
    authority_head: pin.authority_head,
    authority_epoch: pin.authority_epoch,
    actions: ["inspect", "release"],
    audiences: ["merchant-a", "merchant-b"],
    budget: sharedInput.parent_budget,
    max_active_children: sharedInput.allocations.length,
    expires_at: expiry,
    sibling_allocations: sharedInput.allocations.map((budget, index) => ({
      allocation_id: `branch:${index + 1}`,
      parent_id: "authority:scenario-parent",
      actions: [index === 0 ? "release" : "inspect"],
      audiences: [index === 0 ? "merchant-a" : "merchant-b"],
      budget,
      expires_at: expiry,
    })),
  };
  let runtimeAccepted = true;
  let runtimeReason = "accepted";
  try {
    validateAuthorityAllocationSnapshot(snapshot, pin);
    const store = createMemoryAuthorityAllocationStore();
    const installed = await store.installSnapshot(snapshot, pin);
    assertBridge(installed.ok === true, "balanced allocation did not install");
  } catch (error) {
    runtimeAccepted = false;
    runtimeReason = error?.code ?? "rejected";
  }
  assertBridge(
    runtimeAccepted === formal.accepted,
    "allocation model and runtime disagreed",
  );
  if (overallocated) {
    assertBridge(
      runtimeReason === "aggregate_sibling_overspend",
      `unexpected over-allocation refusal: ${runtimeReason}`,
    );
  }
  const formalProjection = {
    accepted: formal.accepted,
    aggregateWithinParent: formal.aggregate_within_parent,
    allocationAuthoritative: formal.allocation_authoritative,
  };
  const runtimeProjection = {
    accepted: runtimeAccepted,
    aggregateWithinParent:
      runtimeReason !== "aggregate_sibling_overspend",
    allocationAuthoritative: runtimeReason !== "authority_pin_mismatch",
  };

  return {
    scenario,
    steps: [
      {
        operator: overallocated
          ? "AttemptSiblingOverallocation"
          : "InstallBalancedAllocation",
        accepted: runtimeAccepted,
        projection: {
          allocationState: runtimeAccepted ? "accepted" : "refused",
          aggregateWithinParent:
            runtimeProjection.aggregateWithinParent,
          allocationAuthoritative:
            runtimeProjection.allocationAuthoritative,
        },
      },
    ],
    relation: relation(sharedInput, formalProjection, runtimeProjection),
  };
}

function outcomeOptions(vector) {
  return {
    receiptOptions: OUTCOME_VECTORS.common.receipt_options,
    executorKeys: Object.hasOwn(vector, "executor_keys")
      ? vector.executor_keys
      : OUTCOME_VECTORS.common.executor_keys,
    now: OUTCOME_VECTORS.common.now,
    ...(Object.hasOwn(vector, "policy_predicted_effects")
      ? { policyPredictedEffects: vector.policy_predicted_effects }
      : {}),
  };
}

export async function runOutcomeBindingScenario(scenario) {
  const vectorId =
    scenario === "outcome-binding-exact-accept"
      ? "accept_real_receipt_and_executor_attestation"
      : scenario === "outcome-binding-action-substitution-refused"
        ? "reject_resigned_action_swap"
        : null;
  if (!vectorId) {
    throw new Error(
      `unsupported outcome-binding refinement scenario: ${scenario}`,
    );
  }
  const vector = OUTCOME_VECTORS.vectors.find(
    (candidate) => candidate.id === vectorId,
  );
  assertBridge(vector, `outcome vector ${vectorId} is missing`);
  const result = verifyOutcomeBinding(
    OUTCOME_VECTORS.common.receipt,
    vector.attestation,
    outcomeOptions(vector),
  );
  const accepted = vectorId.startsWith("accept_");
  assertBridge(
    result.valid === accepted &&
      result.checks?.receipt_verified === true &&
      result.checks?.attestation_verified === true &&
      result.checks?.action_bound === accepted &&
      /^sha256:[0-9a-f]{64}$/u.test(result.result_digest),
    `outcome binding ${vectorId} did not reach the exact-action boundary`,
  );
  const sharedInput = {
    receipt_verified: result.checks.receipt_verified,
    attestation_verified: result.checks.attestation_verified,
    signed_predictions_bound: result.checks.signed_predictions,
    receipt_id_match: result.checks.receipt_bound,
    receipt_digest_match: result.checks.receipt_digest_bound,
    action_digest_match: result.checks.action_bound,
    consumption_nonce_match: result.checks.consumption_bound,
    signed_outcome: result.outcome_binding.outcome,
    policy_present: false,
    policy_outcome: "in_bounds",
  };
  const formal = evaluateOutcomeState(sharedInput);
  const formalProjection = {
    accepted: formal.accepted,
    exactBinding: formal.exact_binding,
    outcome: formal.final_outcome,
  };
  const runtimeProjection = {
    accepted: result.valid,
    exactBinding:
      result.checks.receipt_verified &&
      result.checks.attestation_verified &&
      result.checks.signed_predictions &&
      result.checks.receipt_bound &&
      result.checks.receipt_digest_bound &&
      result.checks.action_bound &&
      result.checks.consumption_bound,
    outcome: result.outcome_binding.outcome,
  };
  return {
    scenario,
    steps: [
      {
        operator: accepted
          ? "VerifyExactOutcomeBinding"
          : "AttemptActionDigestSubstitution",
        accepted,
        projection: {
          outcomeState: accepted ? "in_bounds" : "incomparable",
          receiptVerified: result.checks.receipt_verified,
          attestationVerified: result.checks.attestation_verified,
          actionBound: result.checks.action_bound,
          resultCommitted: true,
        },
      },
    ],
    relation: relation(sharedInput, formalProjection, runtimeProjection),
  };
}

export async function runOutcomeSourceScenario(scenario) {
  const vectorsByScenario = Object.freeze({
    "outcome-sources-independent-current-accept":
      "accept_executor_and_independent_observer",
    "outcome-sources-reused-key-refused":
      "refuse_executor_key_reused_as_independent_observer",
    "outcome-sources-shared-domain-refused":
      "refuse_shared_executor_observer_control_domain",
    "outcome-sources-noncurrent-key-refused":
      "refuse_compromised_observer_key",
    "outcome-sources-window-substitution-refused":
      "refuse_observer_window_substitution",
    "outcome-sources-insufficient-quorum-refused":
      "refuse_insufficient_distinct_observer_quorum",
  });
  const vectorId = vectorsByScenario[scenario] ?? null;
  if (!vectorId) {
    throw new Error(`unsupported outcome-source refinement scenario: ${scenario}`);
  }
  const vector = OUTCOME_SOURCE_VECTORS.vectors.find(
    (candidate) => candidate.id === vectorId,
  );
  assertBridge(vector, `outcome-source vector ${vectorId} is missing`);
  const result = verifyOutcomeObservationSet(
    OUTCOME_SOURCE_VECTORS.common.predicted_effects,
    vector.observations,
    {
      ...OUTCOME_SOURCE_VECTORS.common.options,
      ...(vector.options_override ?? {}),
    },
  );
  const errors = result.errors ?? [];
  const sourceKeysDistinct = !errors.some((error) =>
    error.includes("independent_source_key_reused"),
  );
  const controlDomainsDistinct = !errors.some((error) =>
    error.includes("independent_control_domain_reused"),
  );
  const sourceKeyCurrent = !errors.some((error) =>
    error.includes("outcome_source_key_not_current"),
  );
  const observationWindowValid = result.checks?.observation_windows === true;
  const sourceQuorumMet = result.checks?.source_requirements === true;
  const sharedInput = {
    receipt_verified: true,
    attestation_verified: result.checks?.observations_verified === true,
    signed_predictions_bound: result.checks?.predictions_valid === true,
    receipt_id_match: result.checks?.exact_bindings === true,
    receipt_digest_match: result.checks?.exact_bindings === true,
    action_digest_match: result.checks?.exact_bindings === true,
    consumption_nonce_match: result.checks?.exact_bindings === true,
    source_keys_distinct: sourceKeysDistinct,
    control_domains_distinct: controlDomainsDistinct,
    source_key_current: sourceKeyCurrent,
    observation_window_valid: observationWindowValid,
    source_quorum_met: sourceQuorumMet,
    signed_outcome: result.outcome ?? "in_bounds",
    policy_present: false,
    policy_outcome: "in_bounds",
  };
  const formal = evaluateOutcomeState(sharedInput);
  const formalProjection = {
    accepted: formal.accepted,
    sourceKeysDistinct: formal.state.source_keys_distinct,
    controlDomainsDistinct: formal.state.control_domains_distinct,
    sourceKeyCurrent: formal.state.source_key_current,
    observationWindowValid: formal.state.observation_window_valid,
    sourceQuorumMet: formal.state.source_quorum_met,
  };
  const runtimeProjection = {
    accepted: result.valid,
    sourceKeysDistinct,
    controlDomainsDistinct,
    sourceKeyCurrent,
    observationWindowValid,
    sourceQuorumMet,
  };
  const operators = Object.freeze({
    "outcome-sources-independent-current-accept":
      "VerifyIndependentCurrentOutcomeSources",
    "outcome-sources-reused-key-refused":
      "RefuseReusedIndependentObserverKey",
    "outcome-sources-shared-domain-refused":
      "RefuseSharedObserverControlDomain",
    "outcome-sources-noncurrent-key-refused":
      "RefuseNoncurrentOutcomeSourceKey",
    "outcome-sources-window-substitution-refused":
      "RefuseUnboundObservationWindow",
    "outcome-sources-insufficient-quorum-refused":
      "RefuseInsufficientOutcomeSourceQuorum",
  });
  return {
    scenario,
    steps: [{
      operator: operators[scenario],
      accepted: result.valid,
      projection: {
        outcomeState: result.valid ? "reconciled" : "indeterminate",
        sourceKeysDistinct,
        controlDomainsDistinct,
        sourceKeyCurrent,
        observationWindowValid,
        sourceQuorumMet,
      },
    }],
    relation: relation(sharedInput, formalProjection, runtimeProjection),
  };
}

export async function runAuthorityDocumentProofJoinScenario(scenario) {
  const vectorId =
    scenario === "authority-document-newest-key-accept"
      ? "accept_anchored_document_key_at_issuance"
      : scenario === "authority-document-key-resurrection-refused"
        ? "reject_key_absent_from_document"
        : null;
  if (!vectorId) {
    throw new Error(
      `unsupported authority-document refinement scenario: ${scenario}`,
    );
  }
  const vector = AUTHORITY_JOIN_VECTORS.vectors.find(
    (candidate) => candidate.id === vectorId,
  );
  assertBridge(vector, `authority-document vector ${vectorId} is missing`);
  const result = verifyAuthorityProofViaDocument(
    vector.proof,
    vector.docs,
    vector.opts,
  );
  const accepted = vectorId.startsWith("accept_");
  assertBridge(
    result.verified === true &&
      result.issuer_accepted === accepted &&
      result.checks?.document_chain === true &&
      result.checks?.proof_signature === true &&
      result.checks?.issuer_key_resolved === accepted &&
      (accepted ||
        ("reason" in result &&
          result.reason === "authority_proof_key_unresolvable")),
    `authority-document ${vectorId} did not enforce the newest-document key set`,
  );
  const sharedInput = {
    document_chain_verified: result.checks.document_chain,
    continuity_verified: result.checks.continuity,
    document_anchor_present: result.checks.document_anchor,
    organization_bound: result.checks.organization_binding,
    proof_document_bound: result.checks.proof_document_binding,
    registry_issuer_bound: result.checks.registry_issuer_binding,
    proof_key_present_in_older: true,
    proof_key_present_in_newest: result.checks.issuer_key_resolved,
    proof_key_usage_valid: result.checks.issuer_key_usage,
    proof_key_revoked: false,
    proof_signature_verified: result.checks.proof_signature,
    proof_time_anchor_verified: result.checks.proof_time_anchor,
    registry_head_pin_present:
      typeof vector.opts.expectRegistryHead === "string",
    registry_epoch_pin_present:
      Number.isSafeInteger(vector.opts.expectMinEpoch),
    registry_head_matches: result.checks.registry_head,
    registry_epoch_fresh: result.checks.epoch_fresh,
  };
  const formal = evaluateAuthorityState(sharedInput);
  const formalProjection = {
    issuerAccepted: formal.issuer_accepted,
    newestKeyResolved: formal.proof_key_resolvable,
  };
  const runtimeProjection = {
    issuerAccepted: result.issuer_accepted,
    newestKeyResolved: result.checks.issuer_key_resolved,
  };
  return {
    scenario,
    steps: [
      {
        operator: accepted
          ? "VerifyNewestDocumentProofKey"
          : "AttemptOlderDocumentKeyResurrection",
        accepted,
        projection: {
          authorityJoinState: accepted ? "issuer_accepted" : "refused",
          documentChainVerified: result.checks.document_chain,
          proofSignatureVerified: result.checks.proof_signature,
          newestKeyResolved: result.checks.issuer_key_resolved,
          registryPinned:
            result.checks.registry_head && result.checks.epoch_fresh,
        },
      },
    ],
    relation: relation(sharedInput, formalProjection, runtimeProjection),
  };
}

/** @returns {NonNullable<Parameters<typeof verifyAuthorityProgram>[2]>} */
function authorityProgramOptions() {
  const vector = AUTHORITY_PROGRAM_VECTOR;
  const rootActionHash = createHash("sha256")
    .update(verifyCanonicalize(vector.root_action), "utf8")
    .digest();
  return {
    programPin: vector.program_pin,
    stageKeys: vector.stage_keys,
    verifyAec: ({ stage_id }) =>
      vector.native_results.stages[stage_id]?.aec,
    verifyAom: ({ stage_id }) =>
      vector.native_results.stages[stage_id]?.aom,
    verifyCapabilityNarrowing: ({ stage_id }) =>
      vector.native_results.stages[stage_id]?.capability,
    verifyParallelAllocation: ({ parallel_id }) =>
      vector.native_results.parallel_allocations[parallel_id],
    verifyRootActionBinding: () => ({
      valid: true,
      root_caid:
        `caid:1:${vector.root_action.action_type}:jcs-sha256:` +
        rootActionHash.toString("base64url"),
      root_action_digest: `sha256:${rootActionHash.toString("hex")}`,
    }),
  };
}

export async function runAuthorityProgramScenario(scenario) {
  const missingRoot =
    scenario === "authority-program-missing-root-binding-refused";
  if (
    scenario !== "authority-program-complete-fold" &&
    !missingRoot
  ) {
    throw new Error(
      `unsupported authority-program refinement scenario: ${scenario}`,
    );
  }
  const options = authorityProgramOptions();
  if (missingRoot) delete options.verifyRootActionBinding;
  const result = verifyAuthorityProgram(
    AUTHORITY_PROGRAM_VECTOR.program,
    AUTHORITY_PROGRAM_VECTOR.stage_receipts,
    options,
  );
  if (missingRoot) {
    assertBridge(
      result.valid === false &&
        result.reason === "root_action_binding_unproven" &&
        Object.keys(result.stage_receipt_digests ?? {}).length === 0,
      `authority program accepted a missing root binding: ${result.reason}`,
    );
    return {
      scenario,
      steps: [
        {
          operator: "AttemptMissingRootActionBinding",
          accepted: false,
          projection: {
            programStatus: "invalid",
            checkedStages: 0,
            rootActionBound: false,
            executionProven: false,
          },
        },
      ],
    };
  }

  const checkedStages = Object.keys(result.stage_receipt_digests ?? {});
  assertBridge(
    result.valid === true &&
      result.root_action_binding_status === "verified" &&
      result.parallel_allocation_status === "verified" &&
      result.execution_proven === false &&
      checkedStages.sort().join(",") ===
        "stage-a,stage-b,stage-c,stage-d",
    `authority program did not complete the exact fold: ${result.reason}`,
  );
  const projection = (programStatus, count) => ({
    programStatus,
    checkedStages: count,
    rootActionBound: true,
    executionProven: false,
  });
  return {
    scenario,
    steps: [
      {
        operator: "CheckStageA",
        accepted: true,
        projection: projection("checking", 1),
      },
      {
        operator: "CheckStageB",
        accepted: true,
        projection: projection("checking", 2),
      },
      {
        operator: "CheckStageC",
        accepted: true,
        projection: projection("checking", 3),
      },
      {
        operator: "CheckStageD",
        accepted: true,
        projection: projection("checking", 4),
      },
      {
        operator: "FinalizeAuthorityProgram",
        accepted: true,
        projection: projection("valid", 4),
      },
    ],
  };
}

const RECEIPT_PROGRAM_NOW = Date.parse("2026-07-24T17:00:00.000Z");
const RECEIPT_PROGRAM_CONTEXT = Object.freeze({
  issuer: "emilia-refinement-operator",
  tenant: "tenant_five_claim_bridge",
  environment: "test",
  audience: "formal-runtime-refinement",
  key_id: "local-dev",
});
const RECEIPT_PROGRAM_SELECTOR = Object.freeze({
  protocol: "mcp",
  tool: "release_payment",
});
const RECEIPT_PROGRAM_BENEFICIARY = `sha256:${"b".repeat(64)}`;
const RECEIPT_PROGRAM_ACTION = Object.freeze({
  action_type: "payment.release",
  amount: "40.00",
  amount_usd: 40,
  currency: "USD",
  beneficiary_account: RECEIPT_PROGRAM_BENEFICIARY,
  beneficiary_account_hash: RECEIPT_PROGRAM_BENEFICIARY,
  payment_instruction_id: "pi_five_claim_bridge_1",
});
const RECEIPT_PROGRAM_DEFINITIONS = Object.freeze([
  {
    action_type: "payment.release.1",
    required_fields: [
      { name: "amount", type: "amount-string" },
      {
        name: "currency",
        type: "enum",
        values_ref: "ISO 4217 alpha-3",
      },
      { name: "beneficiary_account", type: "digest" },
      { name: "payment_instruction_id", type: "string" },
    ],
    optional_fields: [],
  },
]);

function receiptProgramCaidAction(action) {
  return {
    action_type: "payment.release.1",
    amount: action.amount,
    currency: action.currency,
    beneficiary_account: action.beneficiary_account,
    payment_instruction_id: action.payment_instruction_id,
  };
}

function resolveReceiptProgramCaid(action) {
  const result = computeCaid(receiptProgramCaidAction(action), {
    suite: "jcs-sha256",
    definitions: RECEIPT_PROGRAM_DEFINITIONS,
  });
  if (!result.caid) throw new Error(result.refusals?.join(",") ?? "caid_failed");
  return result.caid;
}

function receiptProgramFixture() {
  const action = RECEIPT_PROGRAM_ACTION;
  const harness = createEg1Harness({
    action,
    now: () => RECEIPT_PROGRAM_NOW,
    idPrefix: "five-claim-refinement",
  });
  const capabilityIssuerPrivateKey = deterministicEd25519(0x71);
  const capabilityIssuerPublicKey = publicKeyB64(
    capabilityIssuerPrivateKey,
  );
  const certificatePrivateKey = deterministicEd25519(0x72);
  const certificatePublicKey = publicKeyB64(certificatePrivateKey);
  const caid = resolveReceiptProgramCaid(action);
  const baseReceipt = harness.mint({
    outcome: "allow_with_signoff",
    extra: { capability_only: true },
  });
  const capability = mintCapabilityReceipt(baseReceipt, {
    issuerPrivateKey: capabilityIssuerPrivateKey,
    budget: { amount: 100, currency: "USD" },
    expiry: RECEIPT_PROGRAM_NOW + 60_000,
    secret: Buffer.alloc(32, 0x73),
    capabilityId: "cap_five_claim_receipt_program",
    scope: {
      profile: CAPABILITY_CAID_SCOPE_PROFILE,
      operation_id_field: "payment_instruction_id",
      caids: [caid],
    },
  });
  const capabilityStore = createMemoryCapabilityStore();
  assertBridge(
    capabilityStore.registerCapability(capability.capabilityReceipt) ===
      true,
    "receipt-program capability was not registered",
  );
  const gate = createGate({
    manifest: createDefaultActionRiskManifest(),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    capabilityStore,
    capabilityTrustedIssuerKeys: [capabilityIssuerPublicKey],
    capabilityCaidResolver: resolveReceiptProgramCaid,
    runtimeMonitor: createRuntimeMonitor({
      now: () => RECEIPT_PROGRAM_NOW,
    }),
    allowEphemeralStore: true,
    now: () => RECEIPT_PROGRAM_NOW,
  });
  const kernel = createReceiptProgramKernel({
    gate,
    resolveCaid: resolveReceiptProgramCaid,
    operationIdField: "payment_instruction_id",
    certificatePrivateKey,
    certificateContext: RECEIPT_PROGRAM_CONTEXT,
    effectTimeoutMs: 1_000,
    allowEphemeralState: true,
    now: () => RECEIPT_PROGRAM_NOW,
  });
  return {
    action,
    harness,
    caid,
    capability,
    capabilityStore,
    certificatePublicKey,
    gate,
    kernel,
  };
}

function receiptProgramRequest(fixture, caid = fixture.caid) {
  return {
    programId: "five-claim-receipt-program",
    instructionId: "release-refinement-milestone",
    caid,
    selector: RECEIPT_PROGRAM_SELECTOR,
    observedAction: fixture.action,
    capability: {
      capabilityReceipt: fixture.capability.capabilityReceipt,
      secret: fixture.capability.secret,
      action: {
        amount: fixture.action.amount_usd,
        currency: fixture.action.currency,
      },
      operationId: fixture.action.payment_instruction_id,
    },
  };
}

function verifyReceiptProgramOutput(fixture, output) {
  return verifyReceiptProgramCertificate(output.certificate, {
    trustedCertificateKeys: {
      [RECEIPT_PROGRAM_CONTEXT.key_id]:
        fixture.certificatePublicKey,
    },
    resolveCaid: resolveReceiptProgramCaid,
    expectedContext: RECEIPT_PROGRAM_CONTEXT,
    certificateEvidence: output.certificate_evidence,
    verifyCertificateInclusion: (candidate) =>
      fixture.gate.evidence
        .all()
        .some(
          (record) =>
            canonicalEvidenceJson(record) ===
            canonicalEvidenceJson(candidate),
        ),
  });
}

export async function runReceiptProgramScenario(scenario) {
  const substituted =
    scenario === "receipt-program-caid-substitution-refused";
  if (
    scenario !== "receipt-program-caid-budget-terminal" &&
    !substituted
  ) {
    throw new Error(
      `unsupported receipt-program refinement scenario: ${scenario}`,
    );
  }
  const fixture = receiptProgramFixture();
  let providerCalls = 0;
  let providerEntryObserved = false;
  const suppliedCaid = substituted
    ? `${fixture.caid.slice(0, -1)}${
        fixture.caid.endsWith("A") ? "B" : "A"
      }`
    : fixture.caid;
  const output = await fixture.kernel.run(
    receiptProgramRequest(fixture, suppliedCaid),
    async () => {
      providerCalls += 1;
      const operation = fixture.capabilityStore.getOperation(
        fixture.action.payment_instruction_id,
      );
      const state = fixture.capabilityStore.getState(
        "cap_five_claim_receipt_program",
      );
      providerEntryObserved =
        operation?.status === "provider_entered" &&
        state?.reserved_amount === 0 &&
        state?.consumed_amount === 40;
      return {
        provider: "simulated-refinement-custodian",
        status: "settled",
      };
    },
  );
  const state = fixture.capabilityStore.getState(
    "cap_five_claim_receipt_program",
  );
  const operation = fixture.capabilityStore.getOperation(
    fixture.action.payment_instruction_id,
  );
  const certificate = verifyReceiptProgramOutput(fixture, output);

  if (substituted) {
    assertBridge(
      output.ok === false &&
        output.outcome === "refused" &&
        output.reason === "caid_mismatch" &&
        providerCalls === 0 &&
        state?.consumed_amount === 0 &&
        state?.reserved_amount === 0 &&
        operation === null &&
        certificate.ok === true &&
        certificate.certificate_persisted === true,
      `receipt program did not refuse CAID substitution before reservation: ${output.reason}`,
    );
    return {
      scenario,
      steps: [
        {
          operator: "AttemptReceiptProgramReserveBeforeMatch",
          accepted: false,
          projection: {
            attemptPhase: "terminal",
            attemptOutcome: "refused",
            attemptMatched: false,
            attemptAuthorized: false,
            attemptEffectEntered: false,
            attemptExecutionEvidence: false,
            attemptCertificate: "persisted",
            operationStatus: "open",
            operationOutcome: "none",
          },
        },
      ],
    };
  }

  assertBridge(
    output.ok === true &&
      output.outcome === "executed" &&
      providerEntryObserved &&
      providerCalls === 1 &&
      state?.consumed_amount === 40 &&
      state?.reserved_amount === 0 &&
      operation?.outcome === "executed" &&
      certificate.ok === true &&
      certificate.certificate_persisted === true,
    `receipt program did not commit one bounded terminal effect: ${output.reason}`,
  );
  return {
    scenario,
    steps: [
      {
        operator: "MatchReceiptProgramCaid",
        accepted: true,
        projection: {
          attemptPhase: "matched",
          attemptOutcome: "none",
          attemptMatched: true,
          attemptAuthorized: false,
          attemptEffectEntered: false,
          attemptExecutionEvidence: false,
          attemptCertificate: "none",
          operationStatus: "open",
          operationOutcome: "none",
        },
      },
      {
        operator: "ReserveReceiptProgramBudget",
        accepted: true,
        projection: {
          attemptPhase: "reserved",
          attemptOutcome: "none",
          attemptMatched: true,
          attemptAuthorized: true,
          attemptEffectEntered: false,
          attemptExecutionEvidence: false,
          attemptCertificate: "none",
          operationStatus: "reserved",
          operationOutcome: "none",
        },
      },
      {
        operator: "InvokeReceiptProgramProvider",
        accepted: true,
        projection: {
          attemptPhase: "executing",
          attemptOutcome: "none",
          attemptMatched: true,
          attemptAuthorized: true,
          attemptEffectEntered: true,
          attemptExecutionEvidence: false,
          attemptCertificate: "none",
          operationStatus: "reserved",
          operationOutcome: "none",
        },
      },
      {
        operator: "RecordReceiptProgramProviderReturn",
        accepted: true,
        projection: {
          attemptPhase: "effect_returned",
          attemptOutcome: "none",
          attemptMatched: true,
          attemptAuthorized: true,
          attemptEffectEntered: true,
          attemptExecutionEvidence: false,
          attemptCertificate: "none",
          operationStatus: "reserved",
          operationOutcome: "none",
        },
      },
      {
        operator: "CommitReceiptProgramTerminalOutcome",
        accepted: true,
        projection: {
          attemptPhase: "certifying",
          attemptOutcome: "executed",
          attemptMatched: true,
          attemptAuthorized: true,
          attemptEffectEntered: true,
          attemptExecutionEvidence: true,
          attemptCertificate: "none",
          operationStatus: "committed",
          operationOutcome: "executed",
        },
      },
      {
        operator: "AppendReceiptProgramCertificate",
        accepted: true,
        projection: {
          attemptPhase: "terminal",
          attemptOutcome: "executed",
          attemptMatched: true,
          attemptAuthorized: true,
          attemptEffectEntered: true,
          attemptExecutionEvidence: true,
          attemptCertificate: "persisted",
          operationStatus: "committed",
          operationOutcome: "executed",
        },
      },
    ],
  };
}
