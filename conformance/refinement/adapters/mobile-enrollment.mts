// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";

import {
  buildMobileEnrollmentBinding,
  createMobileEnrollmentService,
  MOBILE_ENROLLMENT_CHALLENGE_VERSION,
  MOBILE_ENROLLMENT_VERSION,
} from "../../../packages/mobile/enrollment.js";
import { canonicalize } from "../../../packages/verify/index.js";
import type { RuntimeScenarioResult } from "../types.mjs";

const NOW = "2026-07-23T20:02:00.000Z";
const APPROVER_ID = "ep:approver:refinement-supervisor";
const CALLER = Object.freeze({ subject: "agency-user-refinement-1" });

function b64url(value: Buffer): string {
  return value.toString("base64url");
}

function deterministicP256() {
  const d = Buffer.alloc(32, 0x24);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const publicPoint = ecdh.getPublicKey(undefined, "uncompressed");
  const x = b64url(publicPoint.subarray(1, 33));
  const y = b64url(publicPoint.subarray(33, 65));
  const publicKey = crypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x, y },
    format: "jwk",
  });
  return {
    spki: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64url"),
    pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function hashBinding(value: unknown): string {
  return crypto
    .createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("base64url");
}

function enrollmentProjection({
  state,
  rows,
  activations,
  replayRefused = false,
}: {
  state: string;
  rows: string;
  activations: number;
  replayRefused?: boolean;
}) {
  return {
    enrollmentState: state,
    enrollmentRowCount: rows === "platform,webauthn" ? 2 : 1,
    enrollmentActivationCount: activations,
    enrollmentReplayRefused: replayRefused,
  };
}

function challenge() {
  const base = {
    "@version": "AE-CHALLENGE-v1",
    challenge_profile: MOBILE_ENROLLMENT_CHALLENGE_VERSION,
    challenge_id: "enr_refinement_challenge_0001",
    enrollment_id: "enr_refinement_challenge_0001",
    nonce: "reg_refinement_nonce_0000000000000001",
    challenge: "reg_refinement_webauthn_challenge_0001",
    approver_id: APPROVER_ID,
    platform: "ios",
    app_id: "gov.example.refinement-approvals",
    rp_id: "approve.example.gov",
    origin: "https://approve.example.gov",
    user: {
      id: Buffer.from(APPROVER_ID, "utf8").toString("base64url"),
      name: "refinement-supervisor@example.gov",
      display_name: "Refinement Supervisor",
    },
    enrollment_valid_to: "2027-07-23T20:00:00.000Z",
    issued_at: "2026-07-23T20:00:00.000Z",
    expires_at: "2026-07-23T20:05:00.000Z",
  };
  const binding = buildMobileEnrollmentBinding(base);
  return {
    ...base,
    webauthn: {
      rp: { id: base.rp_id, name: "EMILIA Government Approval" },
      challenge: base.challenge,
      user: { ...base.user },
      pub_key_cred_params: [{ type: "public-key", alg: -7 }],
      authenticator_selection: {
        resident_key: "preferred",
        user_verification: "required",
      },
      attestation: "direct",
      timeout_ms: 300_000,
    },
    platform_binding: binding,
    platform_request_hash: hashBinding(binding),
  };
}

function responseFor(item: ReturnType<typeof challenge>) {
  return {
    "@version": MOBILE_ENROLLMENT_VERSION,
    enrollment_id: item.enrollment_id,
    approver_id: item.approver_id,
    platform: item.platform,
    app_id: item.app_id,
    platform_request_hash: item.platform_request_hash,
    attestation_key_id: "appattest_refinement_key_1",
    requested_valid_to: item.enrollment_valid_to,
    passkey_registration: { id: "refinement-public-key-credential" },
    platform_attestation: {
      format: "apple-app-attest-enrollment",
      token: "refinement-opaque-token",
      request_hash: item.platform_request_hash,
    },
  };
}

type EnrollmentActivationMutation = "none" | "drop_platform_row";

function verifiedEnrollmentRows(value: unknown): string[] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  const enrollment = value as Record<string, unknown>;
  const rows: string[] = [];
  if (
    typeof enrollment.credential_id === "string" &&
    typeof enrollment.public_key_spki === "string"
  ) {
    rows.push("webauthn");
  }
  if (
    typeof enrollment.attestation_key_id === "string" &&
    typeof enrollment.platform_public_key === "string"
  ) {
    rows.push("platform");
  }
  return rows.sort();
}

function enrollmentRuntime({
  activationMutation = "none",
}: {
  activationMutation?: EnrollmentActivationMutation;
}) {
  const key = deterministicP256();
  const expectedChallenge = challenge();
  let consumed = false;
  const verifierEvents: string[] = [];
  const stored: unknown[] = [];
  let activationAttempts = 0;
  let activationRowsSeen: string[] = [];
  let activationRefusal: string | null = null;

  const activationBoundary = {
    durable: true,
    async enrollAtomically(item: Record<string, any>) {
      activationAttempts += 1;
      activationRowsSeen = verifiedEnrollmentRows(item.enrollment);
      if (activationRowsSeen.join(",") !== "platform,webauthn") {
        activationRefusal = "requires_both_verified_rows";
        return false;
      }
      stored.push(item);
      return true;
    },
  };

  const directory =
    activationMutation === "drop_platform_row"
      ? {
          durable: true,
          async enrollAtomically(item: Record<string, any>) {
            const {
              attestation_key_id: _attestationKeyId,
              platform_public_key: _platformPublicKey,
              ...webauthnOnly
            } = item.enrollment;
            return activationBoundary.enrollAtomically({
              ...item,
              enrollment: webauthnOnly,
            });
          },
        }
      : activationBoundary;

  const service = createMobileEnrollmentService({
    challengeStore: {
      durable: true,
      async register() {
        return true;
      },
      async consume(item: Record<string, unknown>) {
        if (
          consumed ||
          item.enrollment_id !== expectedChallenge.enrollment_id ||
          item.platform_request_hash !== expectedChallenge.platform_request_hash
        ) {
          return false;
        }
        consumed = true;
        return true;
      },
    },
    directory,
    clock: () => NOW,
    verifyPasskeyRegistration: async (request: Record<string, unknown>) => {
      if (
        request.expectedChallenge !== expectedChallenge.challenge ||
        request.expectedOrigin !== expectedChallenge.origin ||
        request.expectedRPID !== expectedChallenge.rp_id ||
        request.requireUserVerification !== true ||
        request.allowedAlgorithm !== "ES256"
      ) {
        return { valid: false };
      }
      verifierEvents.push("webauthn");
      return {
        valid: true,
        algorithm: "ES256",
        credential_id: Buffer.alloc(32, 0x31).toString("base64url"),
        public_key_spki: key.spki,
        sign_count: 1,
        attestation_format: "packed",
      };
    },
    verifyPlatformEnrollment: async (request: Record<string, unknown>) => {
      verifierEvents.push("platform");
      return {
        valid: true,
        request_hash: request.expected_request_hash,
        app_id: request.expected_app_id,
        attestation_key_id: request.expected_attestation_key_id,
        platform: request.platform,
        hardware_backed: true,
        strong_integrity: true,
        platform_public_key: key.pem,
      };
    },
    authorizeEnrollment: async (request: Record<string, any>) =>
      request.operation === "mobile.enrollment.complete" &&
      request.caller?.subject === CALLER.subject &&
      request.approver_id === APPROVER_ID,
  });

  return {
    expectedChallenge,
    response: responseFor(expectedChallenge),
    service,
    stored,
    verifierEvents,
    wasConsumed: () => consumed,
    activationAttempts: () => activationAttempts,
    activationRowsSeen: () => [...activationRowsSeen],
    activationRefusal: () => activationRefusal,
  };
}

export async function runMobileEnrollmentScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  if (scenario === "mobile-enroll-two-rows") {
    const runtime = enrollmentRuntime({});
    const result = await runtime.service.complete({
      caller: CALLER,
      challenge: runtime.expectedChallenge,
      response: runtime.response,
    });
    if (
      result.ok !== true ||
      result.verdict !== "enrolled" ||
      runtime.stored.length !== 1 ||
      runtime.wasConsumed() !== true ||
      runtime.verifierEvents.join(",") !== "webauthn,platform" ||
      runtime.activationAttempts() !== 1 ||
      runtime.activationRowsSeen().join(",") !== "platform,webauthn" ||
      runtime.activationRefusal() !== null
    ) {
      throw new Error("two-row mobile enrollment did not atomically activate");
    }
    return {
      scenario,
      steps: [
        {
          operator: "VerifyWebAuthnEnrollment",
          accepted: true,
          projection: enrollmentProjection({
            state: "webauthn_only",
            rows: "webauthn",
            activations: 0,
          }),
        },
        {
          operator: "VerifyPlatformEnrollment",
          accepted: true,
          projection: enrollmentProjection({
            state: "ready",
            rows: "platform,webauthn",
            activations: 0,
          }),
        },
        {
          operator: "ActivateEnrollment",
          accepted: true,
          projection: enrollmentProjection({
            state: "active",
            rows: "platform,webauthn",
            activations: 1,
          }),
        },
      ],
    };
  }

  if (scenario === "mobile-enroll-incomplete-at-activation-refused") {
    const runtime = enrollmentRuntime({
      activationMutation: "drop_platform_row",
    });
    const result = await runtime.service.complete({
      caller: CALLER,
      challenge: runtime.expectedChallenge,
      response: runtime.response,
    });
    if (
      result.ok !== false ||
      result.verdict !== "refuse_store_unavailable" ||
      runtime.stored.length !== 0 ||
      runtime.wasConsumed() !== true ||
      runtime.verifierEvents.join(",") !== "webauthn,platform" ||
      runtime.activationAttempts() !== 1 ||
      runtime.activationRowsSeen().join(",") !== "webauthn" ||
      runtime.activationRefusal() !== "requires_both_verified_rows"
    ) {
      throw new Error(
        "valid enrollment evidence did not reach and fail the two-row activation boundary",
      );
    }
    return {
      scenario,
      steps: [
        {
          operator: "VerifyWebAuthnEnrollment",
          accepted: true,
          projection: enrollmentProjection({
            state: "webauthn_only",
            rows: "webauthn",
            activations: 0,
          }),
        },
        {
          operator: "AttemptActivateIncompleteEnrollment",
          accepted: false,
          projection: enrollmentProjection({
            state: "webauthn_only",
            rows: "webauthn",
            activations: 0,
          }),
        },
      ],
    };
  }

  throw new Error(
    `unsupported mobile enrollment refinement scenario: ${scenario}`,
  );
}
