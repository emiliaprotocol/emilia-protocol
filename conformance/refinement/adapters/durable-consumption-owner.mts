// SPDX-License-Identifier: Apache-2.0
import {
  createDurableConsumptionStore,
  createMemoryBackend,
} from "../../../packages/gate/dist/store.js";
import type { RuntimeScenarioResult } from "../types.mjs";

function token(value: string): () => string {
  return () => `${value}-token-0000000000000001`;
}

function relation(
  sharedInput: unknown,
  formalProjection: Record<string, string | number | boolean>,
  runtimeProjection: Record<string, string | number | boolean>,
) {
  const fields = Object.keys(formalProjection).sort();
  if (
    !fields.every(
      (field) =>
        Object.hasOwn(runtimeProjection, field) &&
        Object.is(formalProjection[field], runtimeProjection[field]),
    )
  ) {
    throw new Error("durable-consumption formal/runtime projection mismatch");
  }
  return {
    shared_input: sharedInput,
    formal_projection: formalProjection,
    runtime_projection: runtimeProjection,
    fields,
  };
}

export async function runDurableConsumptionOwnerScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  const backend = createMemoryBackend();
  const ownerA = createDurableConsumptionStore(backend, {
    reservationTokenFactory: token("owner-a"),
  });
  const ownerB = createDurableConsumptionStore(backend, {
    reservationTokenFactory: token("owner-b"),
  });

  if (scenario === "durable-consumption-owner-happy-path") {
    const reserved = await ownerA.reserve("receipt:owner-fence");
    const competingReserve = await ownerB.reserve("receipt:owner-fence");
    const committed = await ownerA.commit("receipt:owner-fence");
    const replayReserve = await ownerB.reserve("receipt:owner-fence");
    const projection = {
      reservationState: reserved ? "RESERVED" : "REFUSED",
      competingReservationRefused: competingReserve === false,
      ownerCommitAccepted: committed === true,
      replayRefused: replayReserve === false,
    };
    return {
      scenario,
      steps: [
        {
          operator: "ReserveByOwner",
          accepted: reserved,
          projection: {
            reservationState: projection.reservationState,
            competingReservationRefused:
              projection.competingReservationRefused,
            ownerCommitAccepted: false,
            replayRefused: false,
          },
        },
        {
          operator: "CommitByOwner",
          accepted: committed,
          projection,
        },
      ],
      relation: relation(
        { owner: "owner-a", competing_owner: "owner-b" },
        projection,
        projection,
      ),
    };
  }

  if (scenario === "durable-consumption-stale-owner-refused") {
    await ownerA.reserve("receipt:stale-owner");
    await backend.compareAndSet(
      "receipt:stale-owner",
      "reserved:v2:owner-a-token-0000000000000001",
      "reserved:v2:owner-b-token-0000000000000001",
    );
    let staleCommitRefused = false;
    let staleReleaseRefused = false;
    try {
      await ownerA.commit("receipt:stale-owner");
    } catch {
      staleCommitRefused = true;
    }
    try {
      await ownerA.release("receipt:stale-owner");
    } catch {
      staleReleaseRefused = true;
    }
    const replacementPreserved =
      (await backend.get("receipt:stale-owner")) ===
      "reserved:v2:owner-b-token-0000000000000001";
    const projection = {
      staleCommitRefused,
      staleReleaseRefused,
      replacementPreserved,
    };
    return {
      scenario,
      steps: [
        {
          operator: "AttemptStaleOwnerTerminalMutation",
          accepted: false,
          projection,
        },
      ],
      relation: relation(
        {
          stale_owner: "owner-a",
          replacement_owner: "owner-b",
        },
        projection,
        projection,
      ),
    };
  }

  if (scenario === "durable-consumption-restart-refused") {
    await ownerA.reserve("receipt:restart");
    const restarted = createDurableConsumptionStore(backend, {
      reservationTokenFactory: token("restarted"),
    });
    let restartCommitRefused = false;
    let restartReleaseRefused = false;
    try {
      await restarted.commit("receipt:restart");
    } catch {
      restartCommitRefused = true;
    }
    try {
      await restarted.release("receipt:restart");
    } catch {
      restartReleaseRefused = true;
    }
    const reservationPreserved =
      /^reserved:v2:/u.test((await backend.get("receipt:restart")) ?? "");
    const projection = {
      restartCommitRefused,
      restartReleaseRefused,
      reservationPreserved,
    };
    return {
      scenario,
      steps: [
        {
          operator: "AttemptRestartedProcessTerminalMutation",
          accepted: false,
          projection,
        },
      ],
      relation: relation(
        { restarted_process_has_owner_token: false },
        projection,
        projection,
      ),
    };
  }

  throw new Error(`unsupported durable-consumption scenario: ${scenario}`);
}

