// SPDX-License-Identifier: Apache-2.0

import { computeCaid } from "../../../caid/impl/js/caid.mjs";
import {
  createRemedyMemoryStore,
  createRemedyProgramKernel,
} from "../../../packages/gate/dist/remedy-program.js";
import type {
  Projection,
  RuntimeScenarioResult,
  RuntimeStep,
} from "../types.mjs";
import { runActionEscrowScenario } from "./action-escrow.mjs";
import { runAecScenario } from "./aec.mjs";
import {
  assertAebExecutionStatus,
  runConsequenceLifecycleScenario,
} from "./consequence-lifecycle.mjs";
import { runGraceScenario } from "./grace-curtailment.mjs";
import { runMobileContinuityScenario } from "./mobile-continuity.mjs";
import { runMobileEnrollmentScenario } from "./mobile-enrollment.mjs";
import { runModelToMatterScenario } from "./model-to-matter.mjs";
import { runNetworkWitnessScenario } from "./network-witness.mjs";
import { runRevocationScenario } from "./revocation.mjs";

const HASH = (char: string) => `sha256:${char.repeat(64)}`;
const ORIGINAL_CAID =
  `caid:1:commerce.purchase.1:jcs-sha256:${"A".repeat(43)}`;
const REMEDY_CAID =
  `caid:1:payments.refund.1:jcs-sha256:${"B".repeat(43)}`;
const NOW = Date.parse("2026-07-22T19:00:00.000Z");

type ComposedState = {
  phase: string;
  caid: string;
  aebState: string;
  aecState: string;
  approvalBound: boolean;
  actionEscrowClear: boolean;
  modelToMatterClear: boolean;
  graceClear: boolean;
  mobileContinuityClear: boolean;
  mobileEnrollmentClear: boolean;
  statusState: string;
  witnessState: string;
  everWitnessPoisoned: boolean;
  revoked: boolean;
  escrowState: string;
  providerCalls: number;
  replayRefused: boolean;
  reconciliationAuthenticated: boolean;
  originalEffect: string;
  disputeOpen: boolean;
  remedyCaid: string;
  remedyAuthorized: boolean;
  remedyCalls: number;
  remedyReplayRefused: boolean;
  remedyReconciliationAuthenticated: boolean;
  remedyEffect: string;
};

function initialState(): ComposedState {
  return {
    phase: "START",
    caid: "none",
    aebState: "UNVERIFIED",
    aecState: "UNSATISFIED",
    approvalBound: false,
    actionEscrowClear: false,
    modelToMatterClear: false,
    graceClear: false,
    mobileContinuityClear: false,
    mobileEnrollmentClear: false,
    statusState: "UNCHECKED",
    witnessState: "UNCHECKED",
    everWitnessPoisoned: false,
    revoked: false,
    escrowState: "OPEN",
    providerCalls: 0,
    replayRefused: false,
    reconciliationAuthenticated: false,
    originalEffect: "NONE",
    disputeOpen: false,
    remedyCaid: "none",
    remedyAuthorized: false,
    remedyCalls: 0,
    remedyReplayRefused: false,
    remedyReconciliationAuthenticated: false,
    remedyEffect: "NONE",
  };
}

function requireRuntime(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`composed trust lifecycle refinement failed: ${message}`);
  }
}

function accepted(
  steps: RuntimeStep[],
  operator: string,
  state: ComposedState,
  projection: Projection,
): void {
  steps.push({
    operator,
    accepted: true,
    projection: { phase: state.phase, ...projection },
  });
}

function refused(
  steps: RuntimeStep[],
  operator: string,
  state: ComposedState,
  projection: Projection = {},
): void {
  steps.push({
    operator,
    accepted: false,
    projection: { phase: state.phase, ...projection },
  });
}

function bindExactCaid(): void {
  const result = computeCaid(
    {
      action_type: "payment.release.1",
      amount: "250000.00",
      currency: "USD",
      beneficiary_account: HASH("a"),
      payment_instruction_id: "instruction:formal-composed-1",
    },
    {
      suite: "jcs-sha256",
      definitions: [
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
      ],
    },
  );
  requireRuntime(
    typeof result.caid === "string" && typeof result.digest === "string",
    `CAID issuer refused the exact action: ${JSON.stringify(result)}`,
  );
}

function digestEvidence(id: string): string {
  return `sha256:${Buffer.from(id).toString("hex").padEnd(64, "0").slice(0, 64)}`;
}

async function exerciseRemedyKernel(): Promise<{
  originalAuthorityRefused: boolean;
  replayRefused: boolean;
}> {
  const original = {
    caid: ORIGINAL_CAID,
    action_digest: HASH("a"),
    operation_id: "purchase-release-1",
    consequence_mode: "action-escrow",
    consequence_digest: HASH("b"),
    terminal_evidence_digest: HASH("c"),
    outcome: "executed",
    occurred_at: "2026-07-22T18:00:00.000Z",
  };
  const kernel = createRemedyProgramKernel({
    store: createRemedyMemoryStore(),
    allowEphemeralState: true,
    now: () => NOW,
    verifyOriginalEffect: ({ original: candidate }: any) => ({
      ok: true,
      ...candidate,
      evidence_digest: candidate.terminal_evidence_digest,
    }),
    verifyRevocation: ({ evidence, expected }: any) => ({
      ok: true,
      evidence_id: evidence.id,
      evidence_digest: evidence.digest,
      target_operation_id: expected.original.operation_id,
      action_digest: expected.original.action_digest,
      authority_id: "authority:revoker",
      revoked_at: "2026-07-22T18:20:00.000Z",
    }),
    verifyDispute: ({ dispute, expected }: any) => ({
      ok: true,
      ...dispute,
      original_operation_id: expected.original.operation_id,
      original_action_digest: expected.original.action_digest,
    }),
    verifyRemedyAuthorization: ({ authorization, expected }: any) => ({
      ok: true,
      ...authorization,
      dispute_id: expected.dispute.dispute_id,
      original_operation_id: expected.original.operation_id,
      destination_binding_digest: expected.destination_binding_digest,
      unit: expected.unit,
    }),
    verifyRemedyOutcome: ({
      evidence,
      outcome,
      expected,
    }: any) => ({
      ok: true,
      ...evidence,
      remedy_operation_id: expected.remedy_operation_id,
      remedy_action_digest: expected.remedy_action_digest,
      destination_binding_digest: expected.destination_binding_digest,
      units: expected.units,
      unit: expected.unit,
      outcome,
    }),
    verifyOriginalReconciliation: () => ({ ok: false }),
  });
  const context = {
    tenantId: "tenant:formal-composed",
    instanceId: "remedy-case:formal-composed",
  };
  const created = await kernel.create({
    ...context,
    environment: "production",
    audience: "merchant:formal",
    original,
    remedyProfileDigest: HASH("d"),
    destinationBindingDigest: HASH("e"),
    maxRemedyUnits: 10_000,
    unit: "USD-cent",
    evidence: { statement: "terminal-action-escrow-statement" },
  });
  requireRuntime(created.ok, `remedy case create failed: ${created.reason}`);

  const revoked = await kernel.recordRevocation({
    ...context,
    evidence: {
      id: "revocation-evidence-1",
      digest: digestEvidence("revocation-evidence-1"),
    },
  });
  requireRuntime(
    revoked.ok &&
      revoked.state?.status === "effect_executed" &&
      (revoked.state as any).original.outcome === "executed",
    `late revocation rewrote the original effect: ${revoked.reason}`,
  );

  const dispute = {
    dispute_id: "dispute-1",
    evidence_id: "dispute-evidence-1",
    evidence_digest: digestEvidence("dispute-evidence-1"),
    challenger_id: "buyer:formal",
    requested_units: 10_000,
    opened_at: "2026-07-22T18:25:00.000Z",
  };
  const opened = await kernel.openDispute({ ...context, dispute });
  requireRuntime(opened.ok, `dispute open failed: ${opened.reason}`);

  const authorization = {
    evidence_id: "remedy-authorization-1",
    evidence_digest: digestEvidence("remedy-authorization-1"),
    remedy_operation_id: "refund-operation-1",
    remedy_caid: REMEDY_CAID,
    remedy_action_digest: HASH("f"),
    consequence_mode: "receipt-program",
    capability_template_digest: HASH("1"),
    escrow_profile_digest: null,
    units: 10_000,
    authorized_at: "2026-07-22T18:30:00.000Z",
  };
  const originalAuthority = await kernel.authorizeRemedy({
    ...context,
    authorization: {
      ...authorization,
      evidence_id: "bad-remedy-authorization-1",
      evidence_digest: digestEvidence("bad-remedy-authorization-1"),
      remedy_caid: ORIGINAL_CAID,
      remedy_action_digest: original.action_digest,
    },
  });
  requireRuntime(
    !originalAuthority.ok &&
      originalAuthority.reason === "remedy_must_be_compensating",
    "original authority was accepted as remedy authority",
  );

  const authorized = await kernel.authorizeRemedy({
    ...context,
    authorization,
  });
  requireRuntime(
    authorized.ok && authorized.state?.status === "remedy_authorized",
    `separate remedy authorization failed: ${authorized.reason}`,
  );
  const claimed = await kernel.claimRemedy({
    ...context,
    remedyOperationId: authorization.remedy_operation_id,
    claimToken: "worker:formal",
  });
  requireRuntime(claimed.ok, `remedy claim failed: ${claimed.reason}`);
  const uncertain = await kernel.finalizeRemedy({
    ...context,
    remedyOperationId: authorization.remedy_operation_id,
    claimToken: "worker:formal",
    outcome: "indeterminate",
    evidence: {
      evidence_id: "provider-timeout-1",
      evidence_digest: digestEvidence("provider-timeout-1"),
      observed_at: "2026-07-22T18:35:00.000Z",
    },
  });
  requireRuntime(
    uncertain.ok && uncertain.state?.status === "remedy_indeterminate",
    `remedy timeout was not fenced: ${uncertain.reason}`,
  );
  const replay = await kernel.claimRemedy({
    ...context,
    remedyOperationId: authorization.remedy_operation_id,
    claimToken: "worker:formal",
  });
  requireRuntime(
    !replay.ok && replay.reason === "remedy_indeterminate",
    "indeterminate remedy was blindly replayable",
  );
  const reconciled = await kernel.reconcileRemedy({
    ...context,
    remedyOperationId: authorization.remedy_operation_id,
    outcome: "executed",
    evidence: {
      evidence_id: "provider-reconciliation-1",
      evidence_digest: digestEvidence("provider-reconciliation-1"),
      observed_at: "2026-07-22T18:40:00.000Z",
    },
  });
  requireRuntime(
    reconciled.ok &&
      reconciled.state?.status === "remedied" &&
      (reconciled.state as any).original.outcome === "executed",
    `authenticated remedy reconciliation failed: ${reconciled.reason}`,
  );
  return { originalAuthorityRefused: true, replayRefused: true };
}

let preflight: Promise<void> | null = null;

async function ensureComposedRuntimeEvidence(): Promise<void> {
  if (!preflight) {
    preflight = (async () => {
      bindExactCaid();
      assertAebExecutionStatus("fresh");
      await runAecScenario("aec-exact-role-map");
      await runActionEscrowScenario("escrow-release-once");
      await runModelToMatterScenario("model-to-matter-clearance-once");
      await runGraceScenario("grace-settle-once");
      await runMobileContinuityScenario("mobile-timeout-reconcile");
      await runMobileEnrollmentScenario("mobile-enroll-two-rows");
      await runNetworkWitnessScenario("network-witness-coordinate-isolation");
      await runConsequenceLifecycleScenario(
        "consequence-indeterminate-reconcile",
      );
      await runRevocationScenario("revocation-effective-terminal");
      await exerciseRemedyKernel();
    })();
  }
  await preflight;
}

function fullLifecycleSteps(): RuntimeStep[] {
  const state = initialState();
  const steps: RuntimeStep[] = [];
  state.phase = "CAID_BOUND";
  state.caid = "caid:action";
  accepted(steps, "BindExactCAID", state, { caid: state.caid });
  state.phase = "AEB_VERIFIED";
  state.aebState = "VERIFIED_ACCEPTED";
  accepted(steps, "VerifyAEB", state, { aebState: state.aebState });
  state.phase = "AEC_SATISFIED";
  state.aecState = "MACHINE_AND_HUMAN";
  accepted(steps, "SatisfyExactAEC", state, { aecState: state.aecState });
  state.phase = "APPROVED";
  state.approvalBound = true;
  accepted(steps, "CaptureApproval", state, {
    approvalBound: state.approvalBound,
  });
  state.phase = "ACTION_ESCROW_CLEAR";
  state.actionEscrowClear = true;
  accepted(steps, "ClearActionEscrow", state, {
    actionEscrowClear: state.actionEscrowClear,
  });
  state.phase = "MODEL_TO_MATTER_CLEAR";
  state.modelToMatterClear = true;
  accepted(steps, "ClearModelToMatter", state, {
    modelToMatterClear: state.modelToMatterClear,
  });
  state.phase = "GRACE_CLEAR";
  state.graceClear = true;
  accepted(steps, "ClearGRACE", state, { graceClear: state.graceClear });
  state.phase = "MOBILE_CONTINUITY_CLEAR";
  state.mobileContinuityClear = true;
  accepted(steps, "ClearMobileContinuity", state, {
    mobileContinuityClear: state.mobileContinuityClear,
  });
  state.phase = "MOBILE_ENROLLMENT_CLEAR";
  state.mobileEnrollmentClear = true;
  accepted(steps, "ClearMobileEnrollment", state, {
    mobileEnrollmentClear: state.mobileEnrollmentClear,
  });
  state.phase = "STATUS_FRESH";
  state.statusState = "FRESH_NOT_REVOKED";
  accepted(steps, "AcceptFreshStatus", state, {
    statusState: state.statusState,
  });
  state.phase = "WITNESS_CLEAN";
  state.witnessState = "CLEAN";
  accepted(steps, "AcceptCleanWitness", state, {
    witnessState: state.witnessState,
    everWitnessPoisoned: state.everWitnessPoisoned,
  });
  state.phase = "RESERVED";
  state.escrowState = "RESERVED";
  accepted(steps, "ReserveEscrow", state, {
    escrowState: state.escrowState,
  });
  state.phase = "INVOKING";
  state.providerCalls = 1;
  accepted(steps, "InvokeProvider", state, {
    providerCalls: state.providerCalls,
  });
  state.phase = "INDETERMINATE";
  state.originalEffect = "INDETERMINATE";
  accepted(steps, "MarkIndeterminate", state, {
    originalEffect: state.originalEffect,
  });
  state.phase = "REPLAY_FENCED";
  state.replayRefused = true;
  refused(steps, "RefuseBlindReplay", state, {
    providerCalls: state.providerCalls,
    replayRefused: state.replayRefused,
  });
  state.phase = "EXECUTED";
  state.reconciliationAuthenticated = true;
  state.originalEffect = "EXECUTED";
  state.escrowState = "CONSUMED";
  accepted(steps, "ReconcileExecuted", state, {
    reconciliationAuthenticated: state.reconciliationAuthenticated,
    originalEffect: state.originalEffect,
    escrowState: state.escrowState,
  });
  state.phase = "LATE_REVOKED";
  state.revoked = true;
  accepted(steps, "RecordLateRevocation", state, {
    revoked: state.revoked,
    originalEffect: state.originalEffect,
  });
  state.phase = "DISPUTED";
  state.disputeOpen = true;
  accepted(steps, "OpenDispute", state, { disputeOpen: state.disputeOpen });
  state.phase = "REMEDY_AUTHORIZED";
  state.remedyCaid = "caid:remedy";
  state.remedyAuthorized = true;
  accepted(steps, "AuthorizeSeparateRemedy", state, {
    remedyCaid: state.remedyCaid,
    remedyAuthorized: state.remedyAuthorized,
  });
  state.phase = "REMEDY_INVOKING";
  state.remedyCalls = 1;
  accepted(steps, "InvokeRemedy", state, { remedyCalls: state.remedyCalls });
  state.phase = "REMEDY_INDETERMINATE";
  state.remedyEffect = "INDETERMINATE";
  accepted(steps, "MarkRemedyIndeterminate", state, {
    remedyEffect: state.remedyEffect,
  });
  state.phase = "REMEDY_REPLAY_FENCED";
  state.remedyReplayRefused = true;
  refused(steps, "RefuseRemedyBlindReplay", state, {
    remedyCalls: state.remedyCalls,
    remedyReplayRefused: state.remedyReplayRefused,
  });
  state.phase = "REMEDIED";
  state.remedyReconciliationAuthenticated = true;
  state.remedyEffect = "EXECUTED";
  accepted(steps, "ReconcileRemedyExecuted", state, {
    remedyReconciliationAuthenticated:
      state.remedyReconciliationAuthenticated,
    remedyEffect: state.remedyEffect,
    originalEffect: state.originalEffect,
  });
  return steps;
}

function stateAfter(operator: string): ComposedState {
  const state = initialState();
  for (const step of fullLifecycleSteps()) {
    switch (step.operator) {
      case "BindExactCAID":
        state.phase = "CAID_BOUND";
        state.caid = "caid:action";
        break;
      case "VerifyAEB":
        state.phase = "AEB_VERIFIED";
        state.aebState = "VERIFIED_ACCEPTED";
        break;
      case "SatisfyExactAEC":
        state.phase = "AEC_SATISFIED";
        state.aecState = "MACHINE_AND_HUMAN";
        break;
      case "CaptureApproval":
        state.phase = "APPROVED";
        state.approvalBound = true;
        break;
      case "ClearActionEscrow":
        state.phase = "ACTION_ESCROW_CLEAR";
        state.actionEscrowClear = true;
        break;
      case "ClearModelToMatter":
        state.phase = "MODEL_TO_MATTER_CLEAR";
        state.modelToMatterClear = true;
        break;
      case "ClearGRACE":
        state.phase = "GRACE_CLEAR";
        state.graceClear = true;
        break;
      case "ClearMobileContinuity":
        state.phase = "MOBILE_CONTINUITY_CLEAR";
        state.mobileContinuityClear = true;
        break;
      case "ClearMobileEnrollment":
        state.phase = "MOBILE_ENROLLMENT_CLEAR";
        state.mobileEnrollmentClear = true;
        break;
      case "AcceptFreshStatus":
        state.phase = "STATUS_FRESH";
        state.statusState = "FRESH_NOT_REVOKED";
        break;
      case "AcceptCleanWitness":
        state.phase = "WITNESS_CLEAN";
        state.witnessState = "CLEAN";
        break;
      case "ReserveEscrow":
        state.phase = "RESERVED";
        state.escrowState = "RESERVED";
        break;
      case "InvokeProvider":
        state.phase = "INVOKING";
        state.providerCalls = 1;
        break;
      case "MarkIndeterminate":
        state.phase = "INDETERMINATE";
        state.originalEffect = "INDETERMINATE";
        break;
      case "RefuseBlindReplay":
        state.phase = "REPLAY_FENCED";
        state.replayRefused = true;
        break;
      case "ReconcileExecuted":
        state.phase = "EXECUTED";
        state.reconciliationAuthenticated = true;
        state.originalEffect = "EXECUTED";
        state.escrowState = "CONSUMED";
        break;
      case "RecordLateRevocation":
        state.phase = "LATE_REVOKED";
        state.revoked = true;
        break;
      case "OpenDispute":
        state.phase = "DISPUTED";
        state.disputeOpen = true;
        break;
      case "AuthorizeSeparateRemedy":
        state.phase = "REMEDY_AUTHORIZED";
        state.remedyCaid = "caid:remedy";
        state.remedyAuthorized = true;
        break;
      case "InvokeRemedy":
        state.phase = "REMEDY_INVOKING";
        state.remedyCalls = 1;
        break;
      case "MarkRemedyIndeterminate":
        state.phase = "REMEDY_INDETERMINATE";
        state.remedyEffect = "INDETERMINATE";
        break;
      case "RefuseRemedyBlindReplay":
        state.phase = "REMEDY_REPLAY_FENCED";
        state.remedyReplayRefused = true;
        break;
      case "ReconcileRemedyExecuted":
        state.phase = "REMEDIED";
        state.remedyReconciliationAuthenticated = true;
        state.remedyEffect = "EXECUTED";
        break;
    }
    if (step.operator === operator) return state;
  }
  throw new Error(`unknown composed lifecycle prefix operator: ${operator}`);
}

export async function runComposedTrustLifecycleScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  await ensureComposedRuntimeEvidence();
  if (scenario === "composed-full-remedy") {
    return { scenario, steps: fullLifecycleSteps() };
  }
  if (scenario === "composed-role-substitution-refused") {
    await runAecScenario("aec-role-substitution-refused");
    const state = stateAfter("VerifyAEB");
    state.phase = "AEC_ROLE_SUBSTITUTION_REFUSED";
    state.aecState = "SUBSTITUTED_REFUSED";
    return {
      scenario,
      steps: [
        {
          operator: "PresentSubstitutedAECRole",
          accepted: false,
          projection: { phase: state.phase, aecState: state.aecState },
        },
      ],
    };
  }
  if (scenario === "composed-role-substitution-mutation") {
    await runAecScenario("aec-role-substitution-refused");
    const state = stateAfter("VerifyAEB");
    return {
      scenario,
      steps: [
        {
          operator: "UnsafeRoleSubstitution",
          accepted: false,
          projection: { phase: state.phase, aecState: state.aecState },
        },
      ],
    };
  }
  if (scenario === "composed-stale-status-refused") {
    assertAebExecutionStatus("stale");
    const state = stateAfter("ClearMobileEnrollment");
    state.phase = "STALE_STATUS_REFUSED";
    state.statusState = "STALE_REFUSED";
    return {
      scenario,
      steps: [
        {
          operator: "RejectStaleStatus",
          accepted: false,
          projection: { phase: state.phase, statusState: state.statusState },
        },
        {
          operator: "UnsafeStaleStatusReserve",
          accepted: false,
          projection: { phase: state.phase, escrowState: state.escrowState },
        },
      ],
    };
  }
  if (scenario === "composed-poisoned-witness-refused") {
    await runNetworkWitnessScenario("network-witness-poison-clear-refused");
    const state = stateAfter("AcceptFreshStatus");
    state.phase = "WITNESS_POISONED";
    state.witnessState = "POISONED";
    state.everWitnessPoisoned = true;
    return {
      scenario,
      steps: [
        {
          operator: "PoisonWitnessStream",
          accepted: false,
          projection: {
            phase: state.phase,
            witnessState: state.witnessState,
            everWitnessPoisoned: state.everWitnessPoisoned,
          },
        },
        {
          operator: "UnsafePoisonedWitnessReserve",
          accepted: false,
          projection: { phase: state.phase, escrowState: state.escrowState },
        },
      ],
    };
  }
  if (scenario === "composed-revoked-invocation-refused") {
    assertAebExecutionStatus("revoked");
    await runRevocationScenario("revocation-effective-terminal");
    const state = stateAfter("ReserveEscrow");
    state.phase = "PRE_EXECUTION_REVOKED";
    state.revoked = true;
    const steps: RuntimeStep[] = [];
    accepted(steps, "RecordPreExecutionRevocation", state, {
      revoked: state.revoked,
    });
    state.phase = "REVOKED_INVOCATION_REFUSED";
    refused(steps, "RefuseRevokedInvocation", state, {
      providerCalls: state.providerCalls,
    });
    return { scenario, steps };
  }
  if (scenario === "composed-revoked-invocation-mutation") {
    const state = stateAfter("ReserveEscrow");
    state.phase = "PRE_EXECUTION_REVOKED";
    state.revoked = true;
    return {
      scenario,
      steps: [
        {
          operator: "RecordPreExecutionRevocation",
          accepted: true,
          projection: { phase: state.phase, revoked: state.revoked },
        },
        {
          operator: "UnsafeRevokedInvocation",
          accepted: false,
          projection: { phase: state.phase, providerCalls: state.providerCalls },
        },
      ],
    };
  }
  if (scenario === "composed-blind-replay-mutation") {
    await runConsequenceLifecycleScenario(
      "consequence-blind-replay-refused",
    );
    const state = stateAfter("MarkIndeterminate");
    return {
      scenario,
      steps: [
        {
          operator: "UnsafeBlindReplay",
          accepted: false,
          projection: { phase: state.phase, providerCalls: state.providerCalls },
        },
      ],
    };
  }
  if (scenario === "composed-unauthenticated-reconciliation-mutation") {
    const state = stateAfter("RefuseBlindReplay");
    return {
      scenario,
      steps: [
        {
          operator: "UnsafeUnauthenticatedReconciliation",
          accepted: false,
          projection: {
            phase: state.phase,
            reconciliationAuthenticated: state.reconciliationAuthenticated,
            originalEffect: state.originalEffect,
          },
        },
      ],
    };
  }
  if (scenario === "composed-original-authority-remedy-mutation") {
    const state = stateAfter("OpenDispute");
    return {
      scenario,
      steps: [
        {
          operator: "UnsafeOriginalAuthorityAsRemedy",
          accepted: false,
          projection: {
            phase: state.phase,
            remedyCaid: state.remedyCaid,
            remedyAuthorized: state.remedyAuthorized,
          },
        },
      ],
    };
  }
  if (scenario === "composed-remedy-blind-replay-mutation") {
    const state = stateAfter("MarkRemedyIndeterminate");
    return {
      scenario,
      steps: [
        {
          operator: "UnsafeRemedyBlindReplay",
          accepted: false,
          projection: { phase: state.phase, remedyCalls: state.remedyCalls },
        },
      ],
    };
  }
  throw new Error(
    `unsupported composed trust lifecycle refinement scenario: ${scenario}`,
  );
}
