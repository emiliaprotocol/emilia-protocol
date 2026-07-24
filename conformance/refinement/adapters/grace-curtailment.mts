// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import {
  buildMobileActionIdentity,
  buildMobileAuthorizationContext,
  hashCanonical,
} from "../../../packages/mobile/index.js";
import { FLEX_ENVELOPE_VERSION } from "../../../lib/grace/curtailment.js";
import {
  buildCurtailmentControlledAction,
  buildCurtailmentPresentation,
  createCurtailmentAction,
  executeGraceCurtailment,
  graceDigest,
  verifyGraceMobileAuthorization,
} from "../../../lib/grace/mobile-grid.js";
import {
  createCosaReferenceActuator,
  createFencedMemoryStore,
  createReferenceMeter,
} from "../../../lib/grace/reference-adapters.js";
import type { RuntimeScenarioResult } from "../types.mjs";

const RP_ID = "www.emiliaprotocol.ai";
const ORIGIN = "https://www.emiliaprotocol.ai";
const PROFILE_HASH = `sha256:${"9".repeat(64)}`;
const GATE_TIME = "2026-07-15T20:15:00.000Z";
const METER_TIME = "2026-07-15T21:45:01.000Z";

// Ephemeral P-256 conformance keys. No private-key material is stored in source
// or emitted by the selected-trace projection.
const APPROVER_PRIVATE_KEYS = Object.freeze([
  crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey,
  crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey,
]);

const envelope = Object.freeze({
  "@version": FLEX_ENVELOPE_VERSION,
  envelope_id: "grace:envelope:refinement-summer-2026",
  bounds: Object.freeze({
    max_event_mw: 30,
    max_period_mwh: 250,
    max_events: 12,
    max_event_hours: 48,
    min_notice_minutes: 10,
    window: Object.freeze({
      start: "2026-06-01T00:00:00.000Z",
      end: "2026-09-30T23:59:59.000Z",
    }),
  }),
});

const action = Object.freeze(
  createCurtailmentAction({
    actionId: "grace:event:caiso-refinement-0042",
    facility: "facility:us-west-dc-17",
    targetDeltaKw: "18000",
    notBefore: GATE_TIME,
    notAfter: "2026-07-15T21:45:00.000Z",
    issuedAt: "2026-07-15T20:00:00.000Z",
    baselineMethodHash: `sha256:${"b".repeat(64)}`,
    envelopeId: envelope.envelope_id,
    requestedBy: "ep:agent:grid-coordinator",
  }),
);

const presentation = Object.freeze(buildCurtailmentPresentation(action));
const policy = Object.freeze({
  policy_id: "ep:grace:mobile-curtailment:v1",
  human_approval: "class_a",
  required_approvals: 2,
  approvers: Object.freeze([
    "ep:approver:grid-operator",
    "ep:approver:facility-operator",
  ]),
});

function ed25519FromSeed(keyId: string, byte: number) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, byte),
    ]),
    format: "der",
    type: "pkcs8",
  });
  return {
    privateKey,
    keyId,
    trust: {
      key_id: keyId,
      public_key_spki: crypto
        .createPublicKey(privateKey as any)
        .export({ type: "spki", format: "der" })
        .toString("base64url"),
    },
  };
}

function fixedP256(index: number) {
  const privateKey = APPROVER_PRIVATE_KEYS[index - 1];
  return {
    privateKey,
    spki: crypto
      .createPublicKey(privateKey as any)
      .export({ type: "spki", format: "der" })
      .toString("base64url"),
  };
}

function approval({
  approver,
  role,
  index,
}: {
  approver: string;
  role: string;
  index: number;
}) {
  const key = fixedP256(index);
  const credentialId = Buffer.alloc(32, index).toString("base64url");
  const deviceKeyId = `ep:key:refinement-${index}`;
  const controlledAction = buildCurtailmentControlledAction(action);
  const actionIdentity = buildMobileActionIdentity({
    actionReference: action.action_id,
    action: controlledAction,
  });
  const context = buildMobileAuthorizationContext({
    actionHash: graceDigest(controlledAction),
    actionReference: action.action_id,
    actionCaid: actionIdentity.action_caid,
    actionDigest: actionIdentity.action_digest,
    policyId: policy.policy_id,
    policyHash: graceDigest(policy),
    initiatorId: action.requested_by,
    approverId: approver,
    approverIndex: index,
    requiredApprovals: 2,
    nonce: `sig_refinement_${index}`,
    issuedAt: `2026-07-15T20:0${index}:00.000Z`,
    expiresAt: "2026-07-15T20:10:00.000Z",
    decision: "approved",
    displayHash: graceDigest(presentation),
    profileHash: PROFILE_HASH,
    platform: "ios",
    appId: "ai.emiliaprotocol.approver",
    deviceKeyId,
    credentialId,
    attestationKeyId: `appattest_refinement_${index}`,
  });
  const clientData = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(
        graceDigest(context).slice("sha256:".length),
        "hex",
      ).toString("base64url"),
      origin: ORIGIN,
      crossOrigin: false,
    }),
    "utf8",
  );
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(index);
  const authenticatorData = Buffer.concat([
    crypto.createHash("sha256").update(RP_ID, "utf8").digest(),
    Buffer.from([0x05]),
    counter,
  ]);
  const signed = Buffer.concat([
    authenticatorData,
    crypto.createHash("sha256").update(clientData).digest(),
  ]);
  return {
    evidence: {
      context,
      signoff: {
        context_hash: hashCanonical(context),
        key_class: "A",
        approver_key_id: deviceKeyId,
        signed_at: context.issued_at,
        webauthn: {
          authenticator_data: authenticatorData.toString("base64url"),
          client_data_json: clientData.toString("base64url"),
          signature: crypto
            .sign("sha256", signed, key.privateKey)
            .toString("base64url"),
        },
      },
    },
    roster: {
      role,
      approver,
      device_key_id: deviceKeyId,
      public_key_spki: key.spki,
      platform: "ios",
      app_id: "ai.emiliaprotocol.approver",
      credential_id: credentialId,
    },
  };
}

function authorizationFixture() {
  const first = approval({
    approver: policy.approvers[0],
    role: "grid_operator",
    index: 1,
  });
  const second = approval({
    approver: policy.approvers[1],
    role: "facility_operator",
    index: 2,
  });
  return {
    evidence: [first.evidence, second.evidence],
    profile: {
      required: 2,
      rp_id: RP_ID,
      allowed_origins: [ORIGIN],
      mobile_profile_hash: PROFILE_HASH,
      max_challenge_age_ms: 600000,
      window_sec: 900,
      approvers: [first.roster, second.roster],
    },
  };
}

function runtime() {
  const actuatorKey = ed25519FromSeed("ep:key:cosa-refinement", 0x11);
  const meterKey = ed25519FromSeed("ep:key:meter-refinement", 0x22);
  const capsuleKey = ed25519FromSeed("ep:key:action-state-refinement", 0x33);
  return {
    actuatorKey,
    meterKey,
    capsuleKey,
    actuator: createCosaReferenceActuator({
      ...actuatorKey,
      clock: () => GATE_TIME,
    }),
    meter: createReferenceMeter({
      ...meterKey,
      baselineMw: "64.000",
      clock: () => METER_TIME,
    }),
    executionStore: createFencedMemoryStore(),
    settlementStore: createFencedMemoryStore(),
  };
}

function graceProjection({
  graceState,
  graceDispatchCount,
  graceMeterRecorded,
  graceSettlementCount,
  graceReplayRefused,
}: {
  graceState: string;
  graceDispatchCount: number;
  graceMeterRecorded: boolean;
  graceSettlementCount: number;
  graceReplayRefused: boolean;
}) {
  return {
    graceState,
    graceAuthorizationVerified: true,
    graceEnvelopeVerified: true,
    graceDispatchCount,
    graceMeterRecorded,
    graceSettlementCount,
    graceReplayRefused,
  };
}

function assertRuntime(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`GRACE refinement failed: ${message}`);
}

export async function runGraceScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  if (
    !["grace-settle-once", "grace-indeterminate-replay-refused"].includes(
      scenario,
    )
  ) {
    throw new Error(`unsupported GRACE refinement scenario: ${scenario}`);
  }

  const authorization = authorizationFixture();
  const verified = verifyGraceMobileAuthorization({
    action,
    presentation,
    policy,
    evidence: authorization.evidence,
    profile: authorization.profile,
  });
  assertRuntime(verified.valid, "the deterministic Class-A quorum was refused");

  const state = runtime();
  const steps: RuntimeScenarioResult["steps"] = [
    {
      operator: "AuthorizeGrace",
      accepted: true,
      projection: graceProjection({
        graceState: "authorized",
        graceDispatchCount: 0,
        graceMeterRecorded: false,
        graceSettlementCount: 0,
        graceReplayRefused: false,
      }),
    },
  ];
  let settlements = 0;

  const common = {
    action,
    envelope,
    spent: {},
    presentation,
    policy,
    authorizationEvidence: authorization.evidence,
    authorizationProfile: authorization.profile,
    executionStore: state.executionStore,
    actuatorTrust: state.actuatorKey.trust,
    meterTrust: state.meterKey.trust,
    settlementStore: state.settlementStore,
    operator: "operator:us-west-dc-17",
    developer: "cosa-reference-adapter/1.0",
    capsuleSigner: state.capsuleKey,
    clock: () => GATE_TIME,
  };

  if (scenario === "grace-settle-once") {
    const actuator = {
      verify: state.actuator.verify,
      async dispatch(request: Record<string, any>) {
        const acknowledgment = await state.actuator.dispatch(request);
        steps.push({
          operator: "DispatchGrace",
          accepted: true,
          projection: graceProjection({
            graceState: "dispatched",
            graceDispatchCount: 1,
            graceMeterRecorded: false,
            graceSettlementCount: 0,
            graceReplayRefused: false,
          }),
        });
        return acknowledgment;
      },
    };
    const meter = {
      verify: state.meter.verify,
      async observe(input: Record<string, any>) {
        const statement = await state.meter.observe(input);
        steps.push({
          operator: "RecordGraceMeter",
          accepted: true,
          projection: graceProjection({
            graceState: "metered",
            graceDispatchCount: 1,
            graceMeterRecorded: true,
            graceSettlementCount: 0,
            graceReplayRefused: false,
          }),
        });
        return statement;
      },
    };
    const result = await executeGraceCurtailment({
      ...common,
      actuator,
      meter,
      settle: async ({ key }: { key: string }) => {
        settlements += 1;
        return {
          settlement_id: "settlement:refinement:0042",
          entitlement_key: key,
        };
      },
    });
    assertRuntime(
      result.ok &&
        result.verdict === "executed_measured_settled" &&
        state.actuator.invocationCount() === 1 &&
        settlements === 1,
      "the authorized curtailment did not dispatch, meter, and settle exactly once",
    );
    steps.push({
      operator: "SettleGrace",
      accepted: true,
      projection: graceProjection({
        graceState: "settled",
        graceDispatchCount: 1,
        graceMeterRecorded: true,
        graceSettlementCount: 1,
        graceReplayRefused: false,
      }),
    });
    return { scenario, steps };
  }

  let dispatchAttempts = 0;
  const lostResponseActuator = {
    verify: state.actuator.verify,
    async dispatch(request: Record<string, any>) {
      dispatchAttempts += 1;
      await state.actuator.dispatch(request);
      steps.push({
        operator: "DispatchGrace",
        accepted: true,
        projection: graceProjection({
          graceState: "dispatched",
          graceDispatchCount: 1,
          graceMeterRecorded: false,
          graceSettlementCount: 0,
          graceReplayRefused: false,
        }),
      });
      throw new Error("COSA response lost after dispatch");
    },
  };
  const first = await executeGraceCurtailment({
    ...common,
    actuator: lostResponseActuator,
    meter: state.meter,
    settle: async () => {
      settlements += 1;
      return { settlement_id: "must-not-settle" };
    },
  });
  assertRuntime(
    !first.ok &&
      first.verdict === "execution_indeterminate" &&
      first.retry_safe === false &&
      dispatchAttempts === 1 &&
      settlements === 0,
    "lost dispatch response was not fenced as indeterminate",
  );
  steps.push({
    operator: "GraceTimeout",
    accepted: true,
    projection: graceProjection({
      graceState: "indeterminate",
      graceDispatchCount: 1,
      graceMeterRecorded: false,
      graceSettlementCount: 0,
      graceReplayRefused: false,
    }),
  });

  const replay = await executeGraceCurtailment({
    ...common,
    actuator: lostResponseActuator,
    meter: state.meter,
    settle: async () => {
      settlements += 1;
      return { settlement_id: "must-not-settle" };
    },
  });
  assertRuntime(
    !replay.ok &&
      replay.verdict === "refuse_replay" &&
      dispatchAttempts === 1 &&
      state.actuator.invocationCount() === 1 &&
      settlements === 0,
    "indeterminate dispatch replay reached the actuator or settlement",
  );
  steps.push({
    operator: "AttemptGraceReplay",
    accepted: false,
    projection: graceProjection({
      graceState: "indeterminate",
      graceDispatchCount: 1,
      graceMeterRecorded: false,
      graceSettlementCount: 0,
      graceReplayRefused: true,
    }),
  });

  return { scenario, steps };
}
