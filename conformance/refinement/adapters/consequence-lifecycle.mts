// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import {
  createEg1Harness,
  createTrustedActionFirewall,
  EG1_DEFAULT_SELECTOR,
} from "../../../packages/gate/dist/index.js";
import { createAECExecutionGate } from "../../../packages/gate/dist/aec-execution.js";
import { createEvidenceLog } from "../../../packages/gate/dist/evidence.js";
import {
  PROPOSAL_TO_EFFECT_VERSION,
  createProposalToEffect,
  proposalToEffectConsumptionNonce,
} from "../../../packages/gate/dist/proposal-to-effect.js";
import { MemoryConsumptionStore } from "../../../packages/gate/dist/store.js";
import {
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  pinnedConfigDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from "../../../packages/verify/aeb-adapter-contract.js";
import type {
  Projection,
  RuntimeScenarioResult,
  RuntimeStep,
} from "../types.mjs";

const NOW = "2026-07-22T12:00:00.000Z";
const CAID = `caid:1:payment.release.1:jcs-sha256:${"A".repeat(43)}`;
const PROPOSAL_INTEGRITY_KEY = crypto
  .createHash("sha256")
  .update("formal-consequence-lifecycle-key")
  .digest();
const SERVER_CONTEXT = Object.freeze({
  tenant_id: "tenant:formal-refinement",
  provider_id: "provider:payments",
  provider_account_id: "account:merchant-1",
  environment: "sandbox",
  executor_id: "executor:gate-1",
});
const EFFECT = Object.freeze({
  provider_transaction_id: "provider:transaction:release-1",
  outcome: "COMMITTED",
  released_amount: 82_000,
  currency: "USD",
});
const EFFECT_DIGEST_CORRECT =
  "sha256:5a008d03443c110476b4a05a78e5faf8076f3524d59d432eee26fc8f6c8eabef";
const EFFECT_DIGEST_WRONG = `sha256:${"0".repeat(64)}`;
const RECONCILIATION_EVIDENCE_ID = "evidence:attempt:release-1";
const NO_EVIDENCE = "NO_EVIDENCE";
const NO_DIGEST = "NO_DIGEST";

type AnyRecord = Record<string, any>;
type AttemptState =
  | "RESERVED"
  | "INVOKING"
  | "INDETERMINATE"
  | "COMMITTED"
  | "RELEASED"
  | "ESCALATED";

const AEC_SUITE = JSON.parse(
  readFileSync(
    new URL("../../../conformance/vectors/aec-role.v1.json", import.meta.url),
    "utf8",
  ),
);
const AEC_VECTOR = structuredClone(
  AEC_SUITE.vectors.find(
    (candidate: AnyRecord) => candidate.id === "accept_pinned_human_receipt",
  ),
);

function ensure(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function projection(
  executeStage: string,
  executeInvokeCount: number,
  executeEscrowState: string,
  reconciledBy = NO_EVIDENCE,
  effectDigest = NO_DIGEST,
): Projection {
  return {
    executeStage,
    executeInvokeCount,
    executeEscrowState,
    reconciledBy,
    effectDigest,
    remedyState: "NONE",
  };
}

function registryEntry(
  entryId: string,
  kind: string,
  version: string,
  definition: unknown,
) {
  const entry: AnyRecord = {
    kind,
    version,
    status: "active",
    definition,
  };
  entry.definition_digest = registryEntryDigest(entryId, entry as any);
  return entry;
}

function createAebFixture(action: AnyRecord) {
  const adapter = {
    id: "formal:human",
    version: "1",
    verifyNative({ artifact, status, trust_roots: trustRoots }: AnyRecord) {
      const trusted = trustRoots.includes(artifact.root);
      return {
        native_verification: trusted ? "VERIFIED" : "FAILED",
        acceptance: trusted ? "ACCEPTED" : "REJECTED",
        evidence_digest: digestAeb(artifact),
        status_digest: digestAeb({
          checked_at: status.checked_at,
          expires_at: status.expires_at,
          revocation_checked: status.revocation_checked,
          revoked: status.revoked,
          consumed: status.consumed,
          unavailable: status.unavailable === true,
        }),
        replay_unit: digestAeb({
          root: artifact.root,
          caid: artifact.caid,
          subject: "human:alice",
        }),
        evidence_role: "human-authorization",
        subject: { id: "human:alice", kind: "human" },
        reasons: trusted ? [] : ["native_trust_root_not_pinned"],
      };
    },
    mapAction({
      artifact,
      native,
      expected_action: expectedAction,
    }: AnyRecord) {
      return {
        mapping:
          native.native_verification === "VERIFIED" ? "MATCH" : "INDETERMINATE",
        caid: artifact.caid,
        action_digest: digestAeb(expectedAction),
        reasons: [],
      };
    },
  };
  const profile: AnyRecord = {
    version: "payment-release-v1",
    definition: { action_type: "payment.release" },
    registry_entry_ref: "mapping:payment-release",
    mapper_id: "mapper:payment-release",
    resolver: {
      id: "resolver:payment-release",
      version: "1",
      implementation_digest: digestAeb({
        implementation: "resolver:payment-release:1",
      }),
    },
    semantic_equivalence: {
      assertion: "EQUIVALENT_UNDER_PROFILE",
      loss_policy: "NO_MATERIAL_FIELD_LOSS",
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
  };
  profile.profile_digest = mappingProfileDigest(
    "payment-release",
    profile as any,
  );
  const entries: AnyRecord = {
    "mapping:payment-release": registryEntry(
      "mapping:payment-release",
      "mapping-profile",
      "1",
      { profile_digest: profile.profile_digest },
    ),
    "role:human-authorization": registryEntry(
      "role:human-authorization",
      "evidence-role",
      "1",
      { role: "human-authorization", subject_kinds: ["human"] },
    ),
  };
  const registry: AnyRecord = {
    "@version": "EP-EVIDENCE-REGISTRY-v1",
    registry_id: "registry:formal-consequence-lifecycle",
    epoch: 1,
    entries,
  };
  registry.registry_digest = unifiedRegistryDigest(registry as any);
  const pin: AnyRecord = {
    version: "1",
    trust_roots: ["root:formal"],
    config: { mode: "offline" },
    max_status_age_sec: 300,
  };
  pin.config_digest = adapterPinDigest("formal:human", pin as any);
  const evaluator = crypto.generateKeyPairSync("ed25519");
  const evaluatorPublicKey = evaluator.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64url");
  const config: AnyRecord = {
    "@version": "AEB-ADAPTER-v1",
    relying_party_id: "rp:formal-consequence-lifecycle",
    evaluator_keys: {
      "eval:formal": { public_key: evaluatorPublicKey },
    },
    registry,
    accepted_mappers: ["mapper:payment-release"],
    adapters: { "formal:human": pin },
    profiles: { "payment-release": profile },
    requirements: {
      "requirement:proposal-to-effect": {
        "@version": "AEB-REQUIREMENT-v1",
        all_of: ["human-authorization"],
        terms: [
          { type: "initiator-exclusion", roles: ["human-authorization"] },
          { type: "executor-exclusion", roles: ["human-authorization"] },
          { type: "one-time-consumption" },
        ],
      },
    },
  };
  const artifact = {
    root: "root:formal",
    caid: CAID,
    action,
  };
  const status = {
    checked_at: "2026-07-22T11:59:00.000Z",
    expires_at: "2026-07-22T12:05:00.000Z",
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  const evaluation = evaluateAebEvidence({
    config,
    adapters: { "formal:human": adapter },
    operation_id: "operation:release-1",
    consumption_nonce: proposalToEffectConsumptionNonce(
      "operation:release-1",
      pinnedConfigDigest(config as any),
    ),
    initiator_id: "agent:buyer",
    executor_id: SERVER_CONTEXT.executor_id,
    requirement_ref: "requirement:proposal-to-effect",
    caid: CAID,
    expected_action: action,
    legs: [
      {
        adapter_id: "formal:human",
        profile_id: "payment-release",
        artifact_ref: "artifact:human-approval",
        artifact,
        status,
      },
    ],
    evaluated_at: NOW,
    signer: {
      key_id: "eval:formal",
      private_key: evaluator.privateKey,
    },
  } as any).record;
  return {
    adapters: { "formal:human": adapter },
    artifacts: { "artifact:human-approval": artifact },
    statuses: { "artifact:human-approval": status },
    config,
    evaluation,
  };
}

function createAebStore() {
  const states = new Map<string, "RESERVED" | "CONSUMED">();
  const replayOwners = new Map<string, string>();
  return {
    durable: true as const,
    ownershipFenced: true as const,
    permanentConsumption: true as const,
    atomicReplayFenced: true as const,
    states,
    async reserve(key: string, replayKeys: readonly string[]) {
      if (states.has(key)) return false;
      if (replayKeys.some((replayKey) => replayOwners.has(replayKey))) {
        return "NATIVE_REPLAY_CONFLICT";
      }
      states.set(key, "RESERVED");
      for (const replayKey of replayKeys) replayOwners.set(replayKey, key);
      return "RESERVED";
    },
    async commit(key: string) {
      if (states.get(key) !== "RESERVED") return false;
      states.set(key, "CONSUMED");
      return true;
    },
    async release(key: string) {
      if (states.get(key) !== "RESERVED") return false;
      states.delete(key);
      for (const [replayKey, owner] of replayOwners) {
        if (owner === key) replayOwners.delete(replayKey);
      }
      return true;
    },
  };
}

function createAttemptStore() {
  const entries = new Map<string, AnyRecord>();
  const events: string[] = [];
  const keyFor = (tenantId: string, attemptId: string) =>
    `${tenantId}\0${attemptId}`;
  return {
    durable: true as const,
    ownershipFenced: true as const,
    compareAndSwap: true as const,
    atomicEvidenceBinding: true as const,
    entries,
    events,
    async reserve(binding: AnyRecord) {
      const key = keyFor(binding.tenant_id, binding.attempt_id);
      if (entries.has(key)) {
        return { reserved: false, reason: "attempt_exists" };
      }
      const owner = "owner:formal-consequence-lifecycle";
      entries.set(key, {
        ...structuredClone(binding),
        owner,
        state: "RESERVED" as AttemptState,
        evidence: null,
      });
      events.push("RESERVED");
      return { reserved: true, owner };
    },
    async transition(input: AnyRecord) {
      const entry = entries.get(keyFor(input.tenant_id, input.attempt_id));
      if (
        !entry ||
        entry.owner !== input.owner ||
        entry.state !== input.expected_state
      ) {
        return false;
      }
      const allowed =
        (input.expected_state === "RESERVED" &&
          input.next_state === "INVOKING") ||
        (input.expected_state === "INVOKING" &&
          input.next_state === "INDETERMINATE") ||
        (input.expected_state === "INDETERMINATE" &&
          ["COMMITTED", "RELEASED", "ESCALATED"].includes(input.next_state));
      if (!allowed) return false;
      entry.state = input.next_state;
      events.push(`${input.expected_state}->${input.next_state}`);
      return true;
    },
    async reconcile(input: AnyRecord) {
      const entry = entries.get(keyFor(input.tenant_id, input.attempt_id));
      if (
        !entry ||
        entry.owner !== input.owner ||
        input.expected_state !== "INDETERMINATE" ||
        entry.state !== "INDETERMINATE"
      ) {
        return false;
      }
      const exact =
        entry.tenant_id === input.evidence.tenant_id &&
        entry.request_digest === input.evidence.request_digest &&
        entry.provider_id === input.evidence.provider_id &&
        entry.provider_account_id === input.evidence.provider_account_id &&
        entry.environment === input.evidence.environment &&
        entry.attempt_id === input.evidence.attempt_id;
      if (!exact) return false;
      entry.evidence = structuredClone(input.evidence);
      entry.state = input.next_state;
      events.push(`INDETERMINATE->${input.next_state}`);
      return true;
    },
    async read(binding: AnyRecord) {
      const entry = entries.get(keyFor(binding.tenant_id, binding.attempt_id));
      if (
        !entry ||
        entry.provider_id !== binding.provider_id ||
        entry.provider_account_id !== binding.provider_account_id ||
        entry.environment !== binding.environment ||
        entry.request_digest !== binding.request_digest
      ) {
        return null;
      }
      return {
        state: entry.state,
        evidence_digest: entry.evidence?.evidence_digest ?? null,
      };
    },
  };
}

function providerEvidence(
  proposal: AnyRecord,
  attempt: AnyRecord,
  overrides: AnyRecord = {},
) {
  return {
    authenticated: true,
    evidence_id: RECONCILIATION_EVIDENCE_ID,
    observed_at: NOW,
    outcome: "COMMITTED",
    operation_id: proposal.operation_id,
    caid: proposal.caid,
    action_digest: proposal.aeb_action_digest,
    tenant_id: proposal.consequence.tenant_id,
    request_digest: proposal.consequence.request_digest,
    provider_id: proposal.consequence.provider_id,
    provider_account_id: proposal.consequence.provider_account_id,
    environment: proposal.consequence.environment,
    attempt_id: attempt.attempt_id,
    effect: structuredClone(EFFECT),
    effect_digest: EFFECT_DIGEST_CORRECT,
    ...overrides,
  };
}

function createRuntimeFixture() {
  ensure(AEC_VECTOR, "AEC conformance vector is missing");
  const action = structuredClone(AEC_VECTOR.aec_chain.action);
  ensure(
    digestAeb(EFFECT) === EFFECT_DIGEST_CORRECT,
    "pinned effect digest drifted",
  );
  const now = () => Date.parse(NOW);
  const harness = createEg1Harness({
    now,
    action,
    idPrefix: "formal-consequence",
  });
  const gate = createTrustedActionFirewall({
    manifest: {
      "@version": "EP-ACTION-RISK-MANIFEST-v0.1",
      actions: [
        {
          id: "formal.payment.release",
          label: "Formal refinement payment release",
          action_type: action.action_type,
          risk: "critical",
          receipt_required: true,
          assurance_class: "class_a",
          match: { ...EG1_DEFAULT_SELECTOR },
          execution_binding: {
            required_fields: Object.keys(action),
          },
        },
      ],
    },
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    allowEphemeralStore: true,
    now,
  });
  const aecGate = createAECExecutionGate({
    requirement: AEC_VECTOR.requirement,
    policiesByType: AEC_VECTOR.policies_by_type,
    humanFloor: "class_a",
    store: new MemoryConsumptionStore() as any,
    log: createEvidenceLog({ strict: true }),
    allowEphemeralState: true,
    now: () => Date.parse(AEC_VECTOR.verification_time),
  });
  const aeb = createAebFixture(action);
  const aebStore = createAebStore();
  const attemptStore = createAttemptStore();
  const controller = createProposalToEffect({
    gate,
    proposal_integrity: {
      hmac_sha256_key: PROPOSAL_INTEGRITY_KEY,
    },
    consequence: {
      ...SERVER_CONTEXT,
      store: attemptStore as any,
      create_attempt_id: async () => "attempt:release-1",
    },
    profiles: {
      "payment-release": {
        id: "payment-release",
        action_type: action.action_type,
        selector: EG1_DEFAULT_SELECTOR,
        required_fields: Object.keys(action),
        authorization: {
          authorization_endpoint: "https://approve.example.test/v1/approvals",
          flow: "EP-APPROVAL-v1",
        },
        aeb_requirement_ref: "requirement:proposal-to-effect",
        ttl_sec: 300,
        canonicalize_action(input: unknown) {
          return { action: structuredClone(input) as AnyRecord, caid: CAID };
        },
      },
    },
    aeb: {
      config: aeb.config as any,
      adapters: aeb.adapters as any,
      store: aebStore as any,
      resolve_artifacts: async () => aeb.artifacts,
      currentStatusResolver: async ({ leg }: AnyRecord) =>
        aeb.statuses[leg.artifact_ref],
      statusVerifier: async ({ status_artifact: status }: AnyRecord) => ({
        valid: true,
        outcome: "current_not_revoked",
        status: structuredClone(status),
      }),
      verify_provider_evidence: async ({ evidence, expected }: AnyRecord) => {
        const derivedEffectDigest = digestAeb(evidence?.effect);
        const valid =
          evidence?.authenticated === true &&
          evidence.operation_id === expected.operation_id &&
          evidence.caid === expected.caid &&
          evidence.action_digest === expected.action_digest &&
          evidence.tenant_id === expected.tenant_id &&
          evidence.request_digest === expected.request_digest &&
          evidence.provider_id === expected.provider_id &&
          evidence.provider_account_id === expected.provider_account_id &&
          evidence.environment === expected.environment &&
          evidence.attempt_id === expected.attempt_id &&
          evidence.effect_digest === derivedEffectDigest &&
          evidence.effect_digest === EFFECT_DIGEST_CORRECT;
        let reason: string | undefined;
        if (evidence?.authenticated !== true) {
          reason = "provider_authentication_required";
        } else if (
          evidence?.effect_digest !== derivedEffectDigest ||
          evidence?.effect_digest !== EFFECT_DIGEST_CORRECT
        ) {
          reason = "provider_effect_digest_mismatch";
        } else if (!valid) {
          reason = "provider_evidence_binding_mismatch";
        }
        return {
          valid,
          outcome: evidence?.outcome,
          evidence_id: evidence?.evidence_id,
          observed_at: evidence?.observed_at,
          tenant_id: evidence?.tenant_id,
          request_digest: evidence?.request_digest,
          provider_id: evidence?.provider_id,
          provider_account_id: evidence?.provider_account_id,
          environment: evidence?.environment,
          attempt_id: evidence?.attempt_id,
          operation_id: evidence?.operation_id,
          caid: evidence?.caid,
          action_digest: evidence?.action_digest,
          evidence_digest: valid ? derivedEffectDigest : undefined,
          reason,
        };
      },
    },
    now,
  });
  const proposal = controller.prepare({
    proposal_id: "proposal:release-1",
    profile_id: "payment-release",
    operation_id: "operation:release-1",
    initiator_id: "agent:buyer",
    action,
  });
  ensure(
    proposal["@version"] === PROPOSAL_TO_EFFECT_VERSION,
    "proposal-to-effect prepare did not return the production version",
  );
  return {
    aeb,
    aebStore,
    aecGate,
    attemptStore,
    controller,
    gate,
    harness,
    proposal,
  };
}

async function enterIndeterminate(
  fixture: ReturnType<typeof createRuntimeFixture>,
) {
  let providerCalls = 0;
  let attempt: AnyRecord | null = null;
  try {
    const result = await fixture.controller.execute(
      {
        proposal: fixture.proposal,
        receipt: fixture.harness.mint(),
        evaluation: fixture.aeb.evaluation,
      },
      async ({ action }: AnyRecord) =>
        fixture.aecGate.run(
          {
            chain: structuredClone(AEC_VECTOR.aec_chain),
            expectedAction: action,
          },
          async () => {
            providerCalls += 1;
            throw new Error("provider response lost");
          },
        ),
    );
    throw new Error(
      `indeterminate provider execution unexpectedly returned: ${JSON.stringify(result)}`,
    );
  } catch (error: any) {
    const publicAttempt = error?.proposalToEffect?.attempt;
    const handle = fixture.controller.getReconciliationHandle(error);
    attempt = handle ? { ...publicAttempt, ...handle } : null;
    ensure(
      error?.emiliaGateOutcome?.outcome === "indeterminate",
      `Gate did not classify the lost provider response as indeterminate: ${JSON.stringify(
        {
          message: error?.message,
          gate: error?.emiliaGateOutcome,
          proposal: error?.proposalToEffect,
        },
      )}`,
    );
  }
  ensure(attempt, "proposal-to-effect did not issue a reconciliation handle");
  ensure(providerCalls === 1, "provider was not invoked exactly once");
  ensure(
    fixture.attemptStore.events.join(",") ===
      "RESERVED,RESERVED->INVOKING,INVOKING->INDETERMINATE",
    "proposal-to-effect did not reserve, invoke, and freeze in order",
  );
  ensure(
    (fixture.aecGate.evidence as any)
      .all()
      .some((entry: AnyRecord) => entry.outcome === "indeterminate"),
    "AEC did not record the provider outcome as indeterminate",
  );
  return { attempt, providerCalls };
}

function lifecycleStepsThroughIndeterminate(): RuntimeStep[] {
  return [
    {
      operator: "RefuseInvalidAdmission(AdmissionWrongCAID)",
      accepted: false,
      projection: projection("PROPOSED", 0, "OPEN"),
    },
    {
      operator: "RefuseInvalidAdmission(AdmissionUnauthenticated)",
      accepted: false,
      projection: projection("PROPOSED", 0, "OPEN"),
    },
    {
      operator: "Admit(ExecuteOp, AdmissionExecute)",
      accepted: true,
      projection: projection("ADMITTED", 0, "OPEN"),
    },
    {
      operator: "Approve(ExecuteOp, ApprovalExecute)",
      accepted: true,
      projection: projection("APPROVED", 0, "OPEN"),
    },
    {
      operator: "ReserveEscrow(ExecuteOp)",
      accepted: true,
      projection: projection("RESERVED", 0, "RESERVED"),
    },
    {
      operator: "InvokeProvider",
      accepted: true,
      projection: projection("INVOKING", 1, "RESERVED"),
    },
    {
      operator: "MarkIndeterminate",
      accepted: true,
      projection: projection("INDETERMINATE", 1, "RESERVED"),
    },
  ];
}

async function refuseInvalidAdmissions(
  fixture: ReturnType<typeof createRuntimeFixture>,
) {
  let providerCalls = 0;
  const wrongCaid = await fixture.controller.execute(
    {
      proposal: fixture.proposal,
      receipt: fixture.harness.mint(),
      evaluation: {
        ...structuredClone(fixture.aeb.evaluation),
        caid: "caid:1:payment.release.1:jcs-sha256:WRONG",
      },
    },
    async () => {
      providerCalls += 1;
    },
  );
  ensure(
    wrongCaid?.ok === false &&
      wrongCaid.reason === "aeb_evaluation_binding_mismatch",
    "wrong-CAID admission was not refused",
  );

  const unauthenticated = await fixture.controller.execute(
    {
      proposal: fixture.proposal,
      receipt: null,
      evaluation: fixture.aeb.evaluation,
    },
    async () => {
      providerCalls += 1;
    },
  );
  ensure(
    unauthenticated?.ok === false && typeof unauthenticated.reason === "string",
    "unauthenticated admission was not refused",
  );
  ensure(providerCalls === 0, "invalid admission crossed the effect boundary");
}

async function refuseBlindReplay(
  fixture: ReturnType<typeof createRuntimeFixture>,
  providerCalls: number,
) {
  const replay = await fixture.controller.execute(
    {
      proposal: fixture.proposal,
      receipt: fixture.harness.mint(),
      evaluation: fixture.aeb.evaluation,
    },
    async () => {
      providerCalls += 1;
      throw new Error("blind replay crossed the effect boundary");
    },
  );
  ensure(replay?.ok === false, "blind replay was not refused");
  ensure(
    replay.reason === "aeb_consumption_conflict",
    `blind replay refusal drifted: ${replay.reason}`,
  );
  ensure(providerCalls === 1, "blind replay invoked the provider");
  return providerCalls;
}

export async function runConsequenceLifecycleScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  if (
    scenario !== "consequence-indeterminate-reconcile" &&
    scenario !== "consequence-blind-replay-refused"
  ) {
    throw new Error(
      `unknown consequence lifecycle refinement scenario: ${scenario}`,
    );
  }

  const fixture = createRuntimeFixture();
  await refuseInvalidAdmissions(fixture);
  const entered = await enterIndeterminate(fixture);
  let providerCalls = await refuseBlindReplay(fixture, entered.providerCalls);
  const steps = lifecycleStepsThroughIndeterminate();
  steps.push({
    operator: "RefuseBlindReplay",
    accepted: false,
    projection: projection("INDETERMINATE", 1, "RESERVED"),
  });
  if (scenario === "consequence-blind-replay-refused") {
    return { scenario, steps };
  }

  const wrongCaid = await fixture.controller.reconcile({
    proposal: fixture.proposal,
    evaluation: fixture.aeb.evaluation,
    attempt: entered.attempt as any,
    provider_evidence: providerEvidence(fixture.proposal, entered.attempt, {
      caid: "caid:1:payment.release.1:jcs-sha256:WRONG",
    }),
  });
  ensure(
    wrongCaid?.ok === false &&
      wrongCaid.reason === "provider_evidence_binding_mismatch",
    "wrong-CAID reconciliation was not refused",
  );
  steps.push({
    operator: "RefuseInvalidReconciliation(ReconcileWrongCAID)",
    accepted: false,
    projection: projection("INDETERMINATE", 1, "RESERVED"),
  });

  const wrongOperation = await fixture.controller.reconcile({
    proposal: fixture.proposal,
    evaluation: fixture.aeb.evaluation,
    attempt: entered.attempt as any,
    provider_evidence: providerEvidence(fixture.proposal, entered.attempt, {
      operation_id: "operation:wrong",
    }),
  });
  ensure(
    wrongOperation?.ok === false &&
      wrongOperation.reason === "provider_evidence_binding_mismatch",
    "wrong-operation reconciliation was not refused",
  );
  steps.push({
    operator: "RefuseInvalidReconciliation(ReconcileWrongOperation)",
    accepted: false,
    projection: projection("INDETERMINATE", 1, "RESERVED"),
  });

  const wrongDigest = await fixture.controller.reconcile({
    proposal: fixture.proposal,
    evaluation: fixture.aeb.evaluation,
    attempt: entered.attempt as any,
    provider_evidence: providerEvidence(fixture.proposal, entered.attempt, {
      effect_digest: EFFECT_DIGEST_WRONG,
    }),
  });
  ensure(
    wrongDigest?.ok === false &&
      wrongDigest.reason === "provider_effect_digest_mismatch",
    "wrong effect digest was not refused",
  );
  steps.push({
    operator: "RefuseInvalidReconciliation(ReconcileWrongEffectDigest)",
    accepted: false,
    projection: projection("INDETERMINATE", 1, "RESERVED"),
  });

  const unauthenticated = await fixture.controller.reconcile({
    proposal: fixture.proposal,
    evaluation: fixture.aeb.evaluation,
    attempt: entered.attempt as any,
    provider_evidence: providerEvidence(fixture.proposal, entered.attempt, {
      authenticated: false,
    }),
  });
  ensure(
    unauthenticated?.ok === false &&
      unauthenticated.reason === "provider_authentication_required",
    "unauthenticated reconciliation was not refused",
  );
  steps.push({
    operator: "RefuseInvalidReconciliation(ReconcileUnauthenticated)",
    accepted: false,
    projection: projection("INDETERMINATE", 1, "RESERVED"),
  });

  const exactEvidence = providerEvidence(fixture.proposal, entered.attempt);
  const reconciled = await fixture.controller.reconcile({
    proposal: fixture.proposal,
    evaluation: fixture.aeb.evaluation,
    attempt: entered.attempt as any,
    provider_evidence: exactEvidence,
  });
  ensure(
    reconciled?.ok === true && reconciled.state === "COMMITTED",
    "authenticated exact reconciliation did not commit",
  );
  ensure(
    reconciled.evidence_digest === EFFECT_DIGEST_CORRECT,
    "terminal reconciliation did not bind the exact effect digest",
  );
  ensure(
    [...fixture.aebStore.states.values()].every(
      (state) => state === "CONSUMED",
    ),
    "AEB authorization was not consumed after exact reconciliation",
  );
  const storedAttempt = fixture.attemptStore.entries.get(
    `${entered.attempt.tenant_id}\0${entered.attempt.attempt_id}`,
  );
  ensure(
    storedAttempt?.state === "COMMITTED" &&
      storedAttempt.evidence?.evidence_id === RECONCILIATION_EVIDENCE_ID &&
      storedAttempt.evidence?.evidence_digest === EFFECT_DIGEST_CORRECT,
    "durable attempt did not retain exact authenticated reconciliation",
  );
  ensure(providerCalls === 1, "reconciliation re-invoked the provider");
  steps.push({
    operator: "ReconcileExact(ReconcileExecute)",
    accepted: true,
    projection: projection(
      "EFFECT",
      1,
      "CONSUMED",
      RECONCILIATION_EVIDENCE_ID,
      EFFECT_DIGEST_CORRECT,
    ),
  });
  return { scenario, steps };
}
