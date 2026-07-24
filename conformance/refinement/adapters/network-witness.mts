// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import {
  acceptNetworkWitnessStatement,
  createMemoryWitnessSequenceStore,
  signNetworkWitnessStatement,
} from "../../../packages/gate/dist/network-witness.js";
import type { RuntimeScenarioResult } from "../types.mjs";

const NOW = Date.parse("2026-07-16T20:00:00.000Z");
const ACTION = `sha256:${"11".repeat(32)}`;
const CONFLICT_ACTION = `sha256:${"44".repeat(32)}`;
const CONFIG = `sha256:${"22".repeat(32)}`;
const FLOW = `sha256:${"33".repeat(32)}`;
const TENANT_A = "tenant:refinement-a";
const TENANT_B = "tenant:refinement-b";
const GATE_A = "gate:refinement-a";
const GATE_B = "gate:refinement-b";
const WITNESS_A = "witness:refinement-edge-a";
const WITNESS_B = "witness:refinement-edge-b";
const CAPTURE_A = "capture:refinement-ingress-a";
const CAPTURE_B = "capture:refinement-ingress-b";

function lengthPrefixed(value: string): string {
  return `${Buffer.byteLength(value, "utf8")}:${value}`;
}

function exactStreamId(
  tenant: string,
  gate: string,
  witness: string,
  capturePoint: string,
): string {
  return [tenant, gate, witness, capturePoint].map(lengthPrefixed).join("|");
}

function exactStreamIdFromVerified(
  tenant: string,
  gate: string,
  verifiedStreamId: string,
): string {
  const parts = verifiedStreamId.split("\0");
  assertRuntime(
    parts.length === 2 && parts.every((part) => part.length > 0),
    "verified witness stream did not contain exactly witness and capture point",
  );
  return exactStreamId(tenant, gate, parts[0], parts[1]);
}

function scopedSequenceStore(
  memoryStore: ReturnType<typeof createMemoryWitnessSequenceStore>,
  tenant: string,
  gate: string,
) {
  return {
    durable: true,
    advance: (
      verifiedStreamId: string,
      sequence: number,
      statementDigest: string,
    ) =>
      memoryStore.advance(
        exactStreamIdFromVerified(tenant, gate, verifiedStreamId),
        sequence,
        statementDigest,
      ),
  };
}

function deterministicEd25519Fixture() {
  // RFC 8032 section 7.1, test vector 1. This is a public test key only.
  const seed = Buffer.from(
    "9d61b19deffd5a60ba844af492ec2cc4" + "4449c5697b326919703bac031cae7f60",
    "hex",
  );
  const publicKeyDer = Buffer.from(
    "302a300506032b6570032100" +
      "d75a980182b10ab7d54bfed3c964073a" +
      "0ee172f3daa62325af021a68f707511a",
    "hex",
  );
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return {
    privateKey: crypto.createPrivateKey({
      key: Buffer.concat([pkcs8Prefix, seed]),
      format: "der",
      type: "pkcs8",
    }),
    publicKeyB64u: publicKeyDer.toString("base64url"),
  };
}

function assertRuntime(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`network witness refinement failed: ${message}`);
  }
}

function statement(
  privateKey: crypto.KeyObject,
  sequence: number,
  {
    actionDigest = ACTION,
    event = "request_observed",
    direction = "ingress",
    observedAt = "2026-07-16T19:59:30.000Z",
    witnessId = WITNESS_A,
    capturePointId = CAPTURE_A,
  }: {
    actionDigest?: string;
    event?: string;
    direction?: string;
    observedAt?: string;
    witnessId?: string;
    capturePointId?: string;
  } = {},
) {
  return signNetworkWitnessStatement(
    {
      witness_id: witnessId,
      capture_point_id: capturePointId,
      sequence,
      observed_at: observedAt,
      event,
      direction,
      action_digest: actionDigest,
      flow_digest: FLOW,
      byte_count: 487 + sequence,
      config_digest: CONFIG,
    },
    privateKey,
  );
}

function projection(
  headSequence: number,
  poisoned: boolean,
  lastWitnessVerdict: "accepted" | "refused",
) {
  return {
    headSequence,
    poisoned,
    lastWitnessVerdict,
  };
}

async function runCoordinateIsolationScenario(
  privateKey: crypto.KeyObject,
  publicKeyB64u: string,
): Promise<RuntimeScenarioResult> {
  const memoryStore = createMemoryWitnessSequenceStore();
  const first = statement(privateKey, 1);
  const pins = [
    {
      witness_id: WITNESS_A,
      key_id: first.witness.key_id,
      public_key: publicKeyB64u,
      capture_point_ids: [CAPTURE_A, CAPTURE_B],
      config_digests: [CONFIG],
    },
    {
      witness_id: WITNESS_B,
      key_id: first.witness.key_id,
      public_key: publicKeyB64u,
      capture_point_ids: [CAPTURE_A],
      config_digests: [CONFIG],
    },
  ];
  const coordinates = [
    {
      operator: "AcceptWitness(WitnessASeq1)",
      tenant: TENANT_A,
      gate: GATE_A,
      witness: WITNESS_A,
      capture: CAPTURE_A,
    },
    {
      operator: "AcceptWitness(WitnessTenantBSeq1)",
      tenant: TENANT_B,
      gate: GATE_A,
      witness: WITNESS_A,
      capture: CAPTURE_A,
    },
    {
      operator: "AcceptWitness(WitnessGateBSeq1)",
      tenant: TENANT_A,
      gate: GATE_B,
      witness: WITNESS_A,
      capture: CAPTURE_A,
    },
    {
      operator: "AcceptWitness(WitnessBSeq1)",
      tenant: TENANT_A,
      gate: GATE_A,
      witness: WITNESS_B,
      capture: CAPTURE_A,
    },
    {
      operator: "AcceptWitness(WitnessCaptureBSeq1)",
      tenant: TENANT_A,
      gate: GATE_A,
      witness: WITNESS_A,
      capture: CAPTURE_B,
    },
  ] as const;
  const expectedKeys = coordinates.map(({ tenant, gate, witness, capture }) =>
    exactStreamId(tenant, gate, witness, capture),
  );
  assertRuntime(
    new Set(expectedKeys).size === expectedKeys.length,
    "one-coordinate stream fixtures did not produce distinct exact keys",
  );
  const steps: RuntimeScenarioResult["steps"] = [];
  for (const [index, coordinate] of coordinates.entries()) {
    const signed = statement(privateKey, 1, {
      witnessId: coordinate.witness,
      capturePointId: coordinate.capture,
    });
    const accepted = await acceptNetworkWitnessStatement(signed, {
      pinnedWitnesses: pins,
      expectedActionDigest: ACTION,
      now: NOW,
      sequenceStore: scopedSequenceStore(
        memoryStore,
        coordinate.tenant,
        coordinate.gate,
      ),
    });
    assertRuntime(
      accepted.accepted &&
        accepted.consumed &&
        accepted.sequence === 1 &&
        accepted.witness_id === coordinate.witness &&
        accepted.capture_point_id === coordinate.capture,
      `${coordinate.operator} was refused: ${accepted.reason}`,
    );
    const snapshotKeys = new Set(
      memoryStore.snapshot().map(({ stream_id: streamId }) => streamId),
    );
    assertRuntime(
      snapshotKeys.size === index + 1 &&
        expectedKeys.slice(0, index + 1).every((key) => snapshotKeys.has(key)),
      `${coordinate.operator} did not advance only its exact tenant/gate/witness/capture stream`,
    );
    steps.push({
      operator: coordinate.operator,
      accepted: true,
      projection: { acceptedStreamCount: index + 1 },
    });
  }
  return { scenario: "network-witness-coordinate-isolation", steps };
}

export async function runNetworkWitnessScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  if (
    ![
      "network-witness-coordinate-isolation",
      "network-witness-monotonic-poison",
      "network-witness-poison-clear-refused",
    ].includes(scenario)
  ) {
    throw new Error(
      `unsupported network witness refinement scenario: ${scenario}`,
    );
  }

  const { privateKey, publicKeyB64u } = deterministicEd25519Fixture();
  if (scenario === "network-witness-coordinate-isolation") {
    return runCoordinateIsolationScenario(privateKey, publicKeyB64u);
  }
  const first = statement(privateKey, 1);
  const pin = {
    witness_id: WITNESS_A,
    key_id: first.witness.key_id,
    public_key: publicKeyB64u,
    capture_point_ids: [CAPTURE_A],
    config_digests: [CONFIG],
  };
  const memoryStore = createMemoryWitnessSequenceStore();
  const sequenceStore = scopedSequenceStore(memoryStore, TENANT_A, GATE_A);
  const options = {
    pinnedWitnesses: [pin],
    expectedActionDigest: ACTION,
    now: NOW,
    sequenceStore,
  };
  const steps: RuntimeScenarioResult["steps"] = [];

  const acceptedFirst = await acceptNetworkWitnessStatement(first, options);
  assertRuntime(
    acceptedFirst.accepted &&
      acceptedFirst.consumed &&
      acceptedFirst.sequence === 1,
    `first statement was refused: ${acceptedFirst.reason}`,
  );
  steps.push({
    operator: "AcceptWitness(WitnessASeq1)",
    accepted: true,
    projection: projection(1, false, "accepted"),
  });
  steps.push({
    operator: "AdvanceTimeToOne",
    accepted: true,
    projection: projection(1, false, "accepted"),
  });

  const second = statement(privateKey, 2, {
    observedAt: "2026-07-16T19:59:40.000Z",
  });
  const acceptedSecond = await acceptNetworkWitnessStatement(second, options);
  assertRuntime(
    acceptedSecond.accepted &&
      acceptedSecond.consumed &&
      acceptedSecond.sequence === 2,
    `monotonic statement was refused: ${acceptedSecond.reason}`,
  );
  steps.push({
    operator: "AcceptWitness(WitnessASeq2)",
    accepted: true,
    projection: projection(2, false, "accepted"),
  });

  const conflict = statement(privateKey, 2, {
    actionDigest: CONFLICT_ACTION,
    event: "response_observed",
    direction: "egress",
    observedAt: "2026-07-16T19:59:45.000Z",
  });
  const poisoned = await acceptNetworkWitnessStatement(conflict, {
    ...options,
    expectedActionDigest: CONFLICT_ACTION,
  });
  assertRuntime(
    !poisoned.accepted &&
      !poisoned.consumed &&
      poisoned.reason === "sequence_equivocation",
    "same-sequence conflicting signed statement did not poison the stream",
  );
  const poisonedSnapshot = memoryStore
    .snapshot()
    .find(
      ({ stream_id: streamId }) =>
        streamId === exactStreamId(TENANT_A, GATE_A, WITNESS_A, CAPTURE_A),
    );
  assertRuntime(
    poisonedSnapshot?.sequence === 2 && poisonedSnapshot.equivocated === true,
    "sequence store did not persist the poisoned head",
  );
  steps.push({
    operator: "PoisonWitnessStream(WitnessASeq2Conflict)",
    accepted: false,
    projection: projection(2, true, "refused"),
  });

  if (scenario === "network-witness-poison-clear-refused") {
    const later = statement(privateKey, 3, {
      observedAt: "2026-07-16T19:59:50.000Z",
    });
    const clearAttempt = await acceptNetworkWitnessStatement(later, options);
    assertRuntime(
      !clearAttempt.accepted &&
        !clearAttempt.consumed &&
        clearAttempt.reason === "sequence_equivocation",
      "later signed statement cleared or bypassed permanent stream poison",
    );
    const finalSnapshot = memoryStore
      .snapshot()
      .find(
        ({ stream_id: streamId }) =>
          streamId === exactStreamId(TENANT_A, GATE_A, WITNESS_A, CAPTURE_A),
      );
    assertRuntime(
      finalSnapshot?.sequence === 2 && finalSnapshot.equivocated === true,
      "poison-clear attempt changed the accepted stream head",
    );
    steps.push({
      operator: "RefuseWitness(WitnessASeq3)",
      accepted: false,
      projection: projection(2, true, "refused"),
    });
  }

  return { scenario, steps };
}
