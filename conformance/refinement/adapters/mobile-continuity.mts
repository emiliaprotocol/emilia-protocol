// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";

import {
  buildMobileActionIdentity,
  buildMobileProviderOutcome,
} from "../../../lib/mobile/action-continuity.js";
import {
  consumeMobileAction,
  markMobileActionIndeterminate,
  reconcileMobileActionOperation,
} from "../../../lib/mobile/store.js";
import type { RuntimeScenarioResult } from "../types.mjs";

const ENTITY_REF = "tenant:expected";
const ACTION_REFERENCE = "mobact_refinement_mobile_action_0001";
const OPERATION_ID = "mobile-operation-refinement-1";
const CONSUMPTION_NONCE = "mobile-consumption-refinement-0001";
const EXECUTOR_ID = "executor:expected";
const CONSUMED_AT = "2026-07-23T20:00:00.000Z";
const OBSERVED_AT = "2026-07-23T20:01:00.000Z";
const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

type ContinuityState = {
  phase: string;
  tenant: string;
  executor: string;
  providerCalls: number;
  fenced: boolean;
  outcomeAuthenticated: boolean;
  outcomeTenant: string;
  outcomeExecutor: string;
  replayRefused: boolean;
  reconciliationRefused: boolean;
};

function deterministicExecutorKey(): crypto.KeyObject {
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.alloc(32, 0x42)]),
    format: "der",
    type: "pkcs8",
  });
}

function projection(state: ContinuityState) {
  return {
    mobileState: state.phase,
    mobileTenant: state.tenant,
    mobileExecutor: state.executor,
    mobileProviderCalls: state.providerCalls,
    mobileFenced: state.fenced,
    mobileOutcomeAuthenticated: state.outcomeAuthenticated,
    mobileOutcomeTenant: state.outcomeTenant,
    mobileOutcomeExecutor: state.outcomeExecutor,
    mobileReplayRefused: state.replayRefused,
    mobileReconciliationRefused: state.reconciliationRefused,
  };
}

function createDeterministicMobileBackend({
  actionCaid,
  actionDigest,
  executorKeyId,
  executorPublicKey,
}: {
  actionCaid: string;
  actionDigest: string;
  executorKeyId: string;
  executorPublicKey: string;
}) {
  const state: ContinuityState = {
    phase: "idle",
    tenant: "none",
    executor: "none",
    providerCalls: 0,
    fenced: false,
    outcomeAuthenticated: false,
    outcomeTenant: "none",
    outcomeExecutor: "none",
    replayRefused: false,
    reconciliationRefused: false,
  };
  let invokedProjection: ReturnType<typeof projection> | null = null;

  const supabase = {
    async rpc(name: string, args: Record<string, unknown>) {
      if (name === "consume_mobile_action") {
        const exactRequest =
          args.p_entity_ref === ENTITY_REF &&
          args.p_action_reference === ACTION_REFERENCE &&
          args.p_executor_id === EXECUTOR_ID;
        if (!exactRequest)
          return {
            data: { ok: false, reason: "binding_mismatch" },
            error: null,
          };
        if (state.phase !== "idle") {
          state.replayRefused = true;
          return {
            data: { ok: false, reason: "already_consumed" },
            error: null,
          };
        }
        state.phase = "reserved";
        state.tenant = ENTITY_REF;
        state.executor = EXECUTOR_ID;
        return {
          data: {
            ok: true,
            operation_id: args.p_operation_id,
            action_caid: actionCaid,
            consumption_nonce: args.p_consumption_nonce,
            executor_id: EXECUTOR_ID,
            executor_key_id: executorKeyId,
            state: "consumed",
          },
          error: null,
        };
      }

      if (name === "mark_mobile_action_indeterminate") {
        if (
          args.p_entity_ref !== ENTITY_REF ||
          args.p_operation_id !== OPERATION_ID
        ) {
          return {
            data: { ok: false, reason: "binding_mismatch" },
            error: null,
          };
        }
        if (state.phase !== "reserved") {
          return {
            data: { ok: false, reason: "already_terminal" },
            error: null,
          };
        }
        state.phase = "provider_invoked";
        state.providerCalls = 1;
        invokedProjection = projection(state);
        state.phase = "indeterminate";
        state.fenced = true;
        return {
          data: { ok: true, state: "indeterminate", retry_safe: false },
          error: null,
        };
      }

      if (name === "reconcile_mobile_action_operation") {
        const exactEvidence =
          args.p_entity_ref === ENTITY_REF &&
          args.p_operation_id === OPERATION_ID &&
          args.p_executor_id === EXECUTOR_ID &&
          args.p_executor_key_id === executorKeyId &&
          args.p_outcome === "executed" &&
          (args.p_provider_evidence as Record<string, unknown>)?.action_caid ===
            actionCaid &&
          (args.p_provider_evidence as Record<string, unknown>)
            ?.action_digest === actionDigest;
        if (!exactEvidence || state.phase !== "indeterminate") {
          state.reconciliationRefused = true;
          return {
            data: { ok: false, reason: "provider_evidence_mismatch" },
            error: null,
          };
        }
        state.phase = "executed";
        state.outcomeAuthenticated = true;
        state.outcomeTenant = ENTITY_REF;
        state.outcomeExecutor = EXECUTOR_ID;
        return {
          data: { ok: true, state: "executed", retry_safe: false },
          error: null,
        };
      }

      return { data: null, error: { message: `unexpected RPC ${name}` } };
    },
    from(table: string) {
      const filters = new Map<string, unknown>();
      const builder = {
        select() {
          return builder;
        },
        eq(field: string, value: unknown) {
          filters.set(field, value);
          return builder;
        },
        async maybeSingle() {
          const exactPin =
            table === "mobile_executor_keys" &&
            filters.get("entity_ref") === ENTITY_REF &&
            filters.get("executor_id") === EXECUTOR_ID &&
            filters.get("key_id") === executorKeyId &&
            filters.get("status") === "active";
          return {
            data: exactPin
              ? {
                  executor_id: EXECUTOR_ID,
                  key_id: executorKeyId,
                  public_key: executorPublicKey,
                }
              : null,
            error: null,
          };
        },
      };
      return builder;
    },
  };

  return {
    state,
    supabase,
    invokedProjection: () => invokedProjection,
  };
}

function fixture() {
  const action = {
    "@type": "treasury.disbursement.release",
    action_id: "payment-refinement-1",
    amount_minor: 20_000,
    beneficiary_id: "vendor:refinement-bicycle",
    currency: "USD",
  };
  const identity = buildMobileActionIdentity({
    actionReference: ACTION_REFERENCE,
    action,
  });
  const privateKey = deterministicExecutorKey();
  const evidence = buildMobileProviderOutcome({
    operationId: OPERATION_ID,
    actionCaid: identity.action_caid,
    actionDigest: identity.action_digest,
    consumptionNonce: CONSUMPTION_NONCE,
    executorId: EXECUTOR_ID,
    outcome: "executed",
    observedAt: OBSERVED_AT,
    providerReference: "provider-effect-refinement-1",
    privateKey,
  });
  const operation = {
    operation_id: OPERATION_ID,
    action_caid: identity.action_caid,
    action_digest: identity.action_digest,
    consumption_nonce: CONSUMPTION_NONCE,
    executor_id: EXECUTOR_ID,
    executor_key_id: evidence.proof.key_id,
    consumed_at: CONSUMED_AT,
  };
  const backend = createDeterministicMobileBackend({
    actionCaid: identity.action_caid,
    actionDigest: identity.action_digest,
    executorKeyId: evidence.proof.key_id,
    executorPublicKey: evidence.proof.public_key,
  });
  return { backend, evidence, operation };
}

async function reserve(backend: ReturnType<typeof fixture>["backend"]) {
  return consumeMobileAction(backend.supabase as never, {
    entityRef: ENTITY_REF,
    actionReference: ACTION_REFERENCE,
    operationId: OPERATION_ID,
    consumptionNonce: CONSUMPTION_NONCE,
    executorId: EXECUTOR_ID,
  });
}

export async function runMobileContinuityScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  if (scenario === "mobile-timeout-reconcile") {
    const { backend, evidence, operation } = fixture();
    const reserved = await reserve(backend);
    if (reserved.ok !== true)
      throw new Error(`mobile reservation failed: ${reserved.reason}`);
    const reservedProjection = projection(backend.state);

    const timedOut = await markMobileActionIndeterminate(
      backend.supabase as never,
      {
        entityRef: ENTITY_REF,
        operationId: OPERATION_ID,
      },
    );
    if (timedOut.ok !== true)
      throw new Error(`mobile timeout fence failed: ${timedOut.reason}`);
    const providerProjection = backend.invokedProjection();
    if (!providerProjection)
      throw new Error("provider invocation was not observed before timeout");
    const timeoutProjection = projection(backend.state);

    const reconciled = await reconcileMobileActionOperation(
      backend.supabase as never,
      {
        entityRef: ENTITY_REF,
        operation,
        evidence,
      },
    );
    if (reconciled.ok !== true)
      throw new Error(`mobile reconciliation failed: ${reconciled.reason}`);

    return {
      scenario,
      steps: [
        {
          operator: "ReserveMobileAction",
          accepted: true,
          projection: reservedProjection,
        },
        {
          operator: "InvokeMobileProvider",
          accepted: true,
          projection: providerProjection,
        },
        {
          operator: "MobileTimeout",
          accepted: true,
          projection: timeoutProjection,
        },
        {
          operator: "ReconcileExactMobileOutcome",
          accepted: true,
          projection: projection(backend.state),
        },
      ],
    };
  }

  if (scenario === "mobile-replay-refused") {
    const { backend } = fixture();
    const reserved = await reserve(backend);
    if (reserved.ok !== true)
      throw new Error(`mobile reservation failed: ${reserved.reason}`);
    const reservedProjection = projection(backend.state);

    const timedOut = await markMobileActionIndeterminate(
      backend.supabase as never,
      {
        entityRef: ENTITY_REF,
        operationId: OPERATION_ID,
      },
    );
    if (timedOut.ok !== true)
      throw new Error(`mobile timeout fence failed: ${timedOut.reason}`);
    const providerProjection = backend.invokedProjection();
    if (!providerProjection)
      throw new Error("provider invocation was not observed before timeout");
    const timeoutProjection = projection(backend.state);

    const replay = await consumeMobileAction(backend.supabase as never, {
      entityRef: ENTITY_REF,
      actionReference: ACTION_REFERENCE,
      operationId: "mobile-operation-refinement-replay",
      consumptionNonce: "mobile-consumption-refinement-replay",
      executorId: EXECUTOR_ID,
    });
    if (replay.ok !== false || replay.reason !== "already_consumed") {
      throw new Error(
        "mobile replay was not refused by the production consumption boundary",
      );
    }

    return {
      scenario,
      steps: [
        {
          operator: "ReserveMobileAction",
          accepted: true,
          projection: reservedProjection,
        },
        {
          operator: "InvokeMobileProvider",
          accepted: true,
          projection: providerProjection,
        },
        {
          operator: "MobileTimeout",
          accepted: true,
          projection: timeoutProjection,
        },
        {
          operator: "AttemptMobileProviderReplay",
          accepted: false,
          projection: projection(backend.state),
        },
      ],
    };
  }

  throw new Error(
    `unsupported mobile continuity refinement scenario: ${scenario}`,
  );
}
