// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { hashCanonical } from "../packages/gate/execution-binding.js";
import {
  TRUST_PROGRAM_VERSION,
  TRUST_STAGE_RECEIPT_VERSION,
  createTrustProgramKernel,
  validateTrustProgram,
  verifyTrustStageReceipt,
} from "../packages/gate/trust-program.js";

const here = dirname(fileURLToPath(import.meta.url));
const catalogPath = resolve(here, "vectors", "trust-program.v1.json");
const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
const now = Date.parse(catalog.reference_time);

function digest(value) {
  return `sha256:${hashCanonical(value)}`;
}

function instant(offsetSeconds) {
  return new Date(now + offsetSeconds * 1000).toISOString();
}

function decodePointerToken(token) {
  return token.replaceAll("~1", "/").replaceAll("~0", "~");
}

function applyMutation(target, mutation) {
  const tokens = mutation.path.split("/").slice(1).map(decodePointerToken);
  expect(
    tokens.length,
    `empty mutation path in ${mutation.path}`,
  ).toBeGreaterThan(0);
  const leaf = tokens.pop();
  let parent = target;
  for (const token of tokens) parent = parent[token];
  if (mutation.op === "add" && Array.isArray(parent) && leaf === "-") {
    parent.push(structuredClone(mutation.value));
    return;
  }
  if (mutation.op === "remove") {
    delete parent[leaf];
    return;
  }
  expect(["add", "replace"]).toContain(mutation.op);
  parent[leaf] = structuredClone(mutation.value);
}

function mutatedProgram(vector) {
  const program = structuredClone(catalog.program);
  for (const mutation of vector.program_mutations ?? [])
    applyMutation(program, mutation);
  return program;
}

function createAtomicStore(compareAndSwapBarrierSize = 0) {
  const records = new Map();
  let arrivals = 0;
  let releaseBarrier;
  const barrier = new Promise((resolveBarrier) => {
    releaseBarrier = resolveBarrier;
  });

  return {
    durable: false,
    async create(state) {
      if (records.has(state.instance_id))
        return { ok: false, reason: "instance_exists" };
      records.set(state.instance_id, structuredClone(state));
      return { ok: true, state: structuredClone(state) };
    },
    async get(instanceId) {
      const state = records.get(instanceId);
      return state
        ? { ok: true, state: structuredClone(state) }
        : { ok: false, reason: "instance_not_found" };
    },
    async compareAndSwap({ instanceId, expectedRevision, state }) {
      if (arrivals < compareAndSwapBarrierSize) {
        arrivals += 1;
        if (arrivals === compareAndSwapBarrierSize) releaseBarrier();
        await barrier;
      }
      const current = records.get(instanceId);
      if (!current) return { ok: false, reason: "instance_not_found" };
      if (current.revision !== expectedRevision)
        return { ok: false, reason: "revision_conflict" };
      records.set(instanceId, structuredClone(state));
      return { ok: true, state: structuredClone(state) };
    },
    async invalidate({ instanceId, expectedRevision, reason, at }) {
      const current = records.get(instanceId);
      if (!current) return { ok: false, reason: "instance_not_found" };
      if (current.revision !== expectedRevision)
        return { ok: false, reason: "revision_conflict" };
      const next = structuredClone(current);
      next.status = "invalidated";
      next.invalidation_reason = reason;
      next.revision += 1;
      next.updated_at = new Date(at).toISOString();
      for (const stage of Object.values(next.stages)) stage.status = "invalidated";
      if (["locked", "ready"].includes(next.execution.status)) {
        next.execution.status = "invalidated";
      }
      records.set(instanceId, next);
      return { ok: true, state: structuredClone(next) };
    },
  };
}

function verifier() {
  return async ({ artifact }) => ({
    valid: artifact.valid === true,
    reason:
      artifact.valid === true
        ? null
        : (artifact.failure_reason ?? "evidence_verification_failed"),
    binding_digest: artifact.binding_digest,
    policy_digest: artifact.policy_digest,
    subjects: artifact.subjects,
    key_fingerprints: artifact.key_fingerprints,
    issued_at: artifact.issued_at,
    expires_at: artifact.expires_at,
    revocation_checked_at: artifact.revocation_checked_at,
  });
}

function createHarness(vector) {
  const program = mutatedProgram(vector);
  const receiptKeys = generateKeyPairSync("ed25519");
  const profiles = new Set(
    program.stages.flatMap((stage) =>
      stage.requirements.map((requirement) => requirement.verifier_profile),
    ),
  );
  const sharedVerifier = verifier();
  const verifiers = Object.fromEntries(
    [...profiles].map((profile) => [profile, sharedVerifier]),
  );
  const store = createAtomicStore(vector.compare_and_swap_barrier_size ?? 0);
  const kernel = createTrustProgramKernel({
    program,
    store,
    verifiers,
    receiptPrivateKey: receiptKeys.privateKey,
    receiptContext: {
      issuer: "emilia-conformance",
      tenant: "trust-program-vector-tenant",
      environment: "conformance",
      audience: catalog.suite,
      key_id: "trust-program-vector-key",
    },
    allowEphemeralState: true,
    now: () => now,
  });
  const trustedReceiptKeys = {
    "trust-program-vector-key": receiptKeys.publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64url"),
  };
  return { program, kernel, trustedReceiptKeys };
}

function requirementFor(program, stageId, requirementId) {
  const stage = program.stages.find(
    (candidate) => candidate.stage_id === stageId,
  );
  return stage?.requirements.find(
    (candidate) => candidate.requirement_id === requirementId,
  );
}

function artifactFrom(spec, challenge, requirement) {
  const binding = {
    ...structuredClone(challenge.binding),
    ...structuredClone(spec.binding_overrides ?? {}),
  };
  const artifact = {
    "@version": "EP-GATE-TRUST-PROGRAM-VECTOR-EVIDENCE-v1",
    evidence_id: spec.evidence_id,
    valid: spec.valid ?? true,
    binding_digest: spec.binding_digest ?? digest(binding),
    policy_digest: spec.policy_digest ?? requirement.policy_digest,
    subjects: structuredClone(spec.subjects ?? []),
    key_fingerprints: structuredClone(spec.key_fingerprints ?? []),
    issued_at: Object.hasOwn(spec, "issued_at")
      ? spec.issued_at
      : instant(spec.issued_at_offset_sec ?? -5),
    expires_at: Object.hasOwn(spec, "expires_at")
      ? spec.expires_at
      : instant(spec.expires_at_offset_sec ?? 60),
    revocation_checked_at: Object.hasOwn(spec, "revocation_checked_at")
      ? spec.revocation_checked_at
      : instant(spec.revocation_checked_at_offset_sec ?? -1),
  };
  if (spec.failure_reason) artifact.failure_reason = spec.failure_reason;
  return artifact;
}

async function currentState(context) {
  const loaded = await context.kernel.status(context.instanceId);
  expect(loaded.ok).toBe(true);
  return loaded.state;
}

async function assertExpected(context, result, expected) {
  if (Object.hasOwn(expected, "ok")) expect(result.ok).toBe(expected.ok);
  if (Object.hasOwn(expected, "valid"))
    expect(result.valid).toBe(expected.valid);
  if (Object.hasOwn(expected, "reason"))
    expect(result.reason).toBe(expected.reason);
  if (Object.hasOwn(expected, "stage_completed")) {
    expect(result.stage_completed).toBe(expected.stage_completed);
  }
  if (expected.binding_fields)
    expect(result.binding).toMatchObject(expected.binding_fields);
  if (expected.authorization_binding_fields) {
    expect(result.authorization_binding).toMatchObject(
      expected.authorization_binding_fields,
    );
  }
  if (expected.terminal_stage_receipt_refs) {
    const receiptDigests = expected.terminal_stage_receipt_refs
      .map((reference) => context.receipts[reference].receipt_digest)
      .sort();
    expect(result.authorization_binding.terminal_stage_receipt_digests).toEqual(
      receiptDigests,
    );
  }
  const needsState =
    Object.hasOwn(expected, "revision") ||
    Object.hasOwn(expected, "state_status") ||
    Object.hasOwn(expected, "execution_status") ||
    expected.stage_statuses;
  if (!needsState) return;
  const state = await currentState(context);
  if (Object.hasOwn(expected, "revision"))
    expect(state.revision).toBe(expected.revision);
  if (Object.hasOwn(expected, "state_status"))
    expect(state.status).toBe(expected.state_status);
  if (Object.hasOwn(expected, "execution_status")) {
    expect(state.execution.status).toBe(expected.execution_status);
  }
  for (const [stageId, status] of Object.entries(
    expected.stage_statuses ?? {},
  )) {
    expect(state.stages[stageId].status).toBe(status);
  }
}

async function buildAdmission(context, operation) {
  const challenge = await context.kernel.challenge({
    instanceId: context.instanceId,
    stageId: operation.stage_id,
    requirementId: operation.requirement_id,
  });
  expect(
    challenge.ok,
    `challenge failed before admission: ${challenge.reason}`,
  ).toBe(true);
  if (operation.artifact_ref) {
    return {
      artifact: structuredClone(context.artifacts[operation.artifact_ref]),
      challenge,
    };
  }
  const requirement = requirementFor(
    context.program,
    operation.stage_id,
    operation.requirement_id,
  );
  expect(
    requirement,
    `${operation.stage_id}/${operation.requirement_id} is absent`,
  ).toBeTruthy();
  return {
    artifact: artifactFrom(operation.artifact, challenge, requirement),
    challenge,
  };
}

async function runOperation(context, operation) {
  if (operation.op === "start") {
    context.instanceId = operation.instance_id;
    const result = await context.kernel.start({
      instanceId: context.instanceId,
    });
    await assertExpected(context, result, operation.expect);
    return;
  }

  if (operation.op === "challenge") {
    const result = await context.kernel.challenge({
      instanceId: context.instanceId,
      stageId: operation.stage_id,
      requirementId: operation.requirement_id,
    });
    await assertExpected(context, result, operation.expect);
    return;
  }

  if (operation.op === "admit") {
    const { artifact } = await buildAdmission(context, operation);
    if (operation.save_artifact_as)
      context.artifacts[operation.save_artifact_as] = structuredClone(artifact);
    const result = await context.kernel.admit({
      instanceId: context.instanceId,
      stageId: operation.stage_id,
      requirementId: operation.requirement_id,
      artifact,
    });
    if (operation.save_receipt_as && result.stage_receipt) {
      context.receipts[operation.save_receipt_as] = structuredClone(
        result.stage_receipt,
      );
    }
    await assertExpected(context, result, operation.expect);
    return;
  }

  if (operation.op === "concurrent_admit") {
    const admissions = await Promise.all(
      operation.admissions.map(async (admission) => {
        const { artifact } = await buildAdmission(context, admission);
        return { admission, artifact };
      }),
    );
    const results = await Promise.all(
      admissions.map(({ admission, artifact }) =>
        context.kernel.admit({
          instanceId: context.instanceId,
          stageId: admission.stage_id,
          requirementId: admission.requirement_id,
          artifact,
        }),
      ),
    );
    expect(results.filter((result) => result.ok).length).toBe(
      operation.expect.ok_count,
    );
    expect(
      results
        .filter((result) => !result.ok)
        .map((result) => result.reason)
        .sort(),
    ).toEqual([...operation.expect.reasons].sort());
    await assertExpected(context, {}, operation.expect);
    return;
  }

  if (operation.op === "verify_receipt") {
    const receipt = structuredClone(context.receipts[operation.receipt_ref]);
    for (const mutation of operation.receipt_mutations ?? [])
      applyMutation(receipt, mutation);
    const expectedPayload = structuredClone(operation.expected_payload ?? {});
    if (operation.expected_predecessor_receipt_refs) {
      expectedPayload.predecessor_receipt_digests =
        operation.expected_predecessor_receipt_refs
          .map((reference) => context.receipts[reference].receipt_digest)
          .sort();
    }
    const result = verifyTrustStageReceipt(receipt, {
      trustedKeys: context.trustedReceiptKeys,
      expected: expectedPayload,
    });
    await assertExpected(context, result, operation.expect);
    return;
  }

  if (operation.op === "claim") {
    const result = await context.kernel.claimExecution({
      instanceId: context.instanceId,
    });
    if (operation.save_claim_as && result.claim_token) {
      context.claims[operation.save_claim_as] = result.claim_token;
    }
    await assertExpected(context, result, operation.expect);
    return;
  }

  if (operation.op === "finalize") {
    const result = await context.kernel.finalizeExecution({
      instanceId: context.instanceId,
      claimToken: context.claims[operation.claim_ref],
      outcome: operation.outcome,
      evidenceDigest: operation.evidence_digest,
    });
    await assertExpected(context, result, operation.expect);
    return;
  }

  if (operation.op === "invalidate") {
    const result = await context.kernel.invalidate({
      instanceId: context.instanceId,
      expectedRevision: operation.expected_revision,
      reason: operation.reason,
    });
    await assertExpected(context, result, operation.expect);
    return;
  }

  if (operation.op === "reconcile") {
    const result = await context.kernel.reconcileExecution({
      instanceId: context.instanceId,
      outcome: operation.outcome,
      evidenceDigest: operation.evidence_digest,
    });
    await assertExpected(context, result, operation.expect);
    return;
  }

  throw new Error(
    `unsupported trust-program vector operation: ${operation.op}`,
  );
}

describe("EP Gate Trust Program conformance catalog", () => {
  it("is a closed internal suite with complete required coverage", () => {
    expect(catalog.suite).toBe("EP-GATE-TRUST-PROGRAM-v1");
    expect(catalog.machine_discriminator).toBe(TRUST_PROGRAM_VERSION);
    expect(catalog.stage_receipt_discriminator).toBe(
      TRUST_STAGE_RECEIPT_VERSION,
    );
    expect(catalog.artifact_classification).toBe(
      "closed_internal_operational_profile",
    );
    expect(catalog.standardization_status).toEqual({
      standard: false,
      ietf_draft: false,
      external_interoperability_claim: false,
    });
    expect(catalog.vector_count).toBe(catalog.vectors.length);
    expect(new Set(catalog.vectors.map((vector) => vector.id)).size).toBe(
      catalog.vectors.length,
    );
    const covered = new Set(catalog.vectors.flatMap((vector) => vector.covers));
    expect(
      [...catalog.required_coverage].filter(
        (requirement) => !covered.has(requirement),
      ),
    ).toEqual([]);
  });

  for (const vector of catalog.vectors) {
    it(`${vector.id}: ${vector.description}`, async () => {
      if (vector.mode === "program_validation") {
        const result = validateTrustProgram(mutatedProgram(vector));
        expect(result.valid).toBe(vector.expect.valid);
        expect(result.reason).toBe(vector.expect.reason);
        return;
      }
      expect(vector.mode).toBe("kernel_flow");
      const harness = createHarness(vector);
      const context = {
        ...harness,
        instanceId: null,
        artifacts: {},
        receipts: {},
        claims: {},
      };
      for (const operation of vector.operations)
        await runOperation(context, operation);
    });
  }
});
