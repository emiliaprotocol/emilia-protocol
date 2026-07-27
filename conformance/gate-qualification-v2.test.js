// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  GATE_QUALIFICATION_V2_VECTOR_VERSION,
  runGateQualificationV2Vector,
  validateGateQualificationV2Corpus,
  vectorResultMatches,
} from "./refinement/adapters/gate-qualification-v2.mts";

const vectorUrl = new URL(
  "./vectors/gate-qualification.v2.json",
  import.meta.url,
);
const rawCorpus = JSON.parse(readFileSync(vectorUrl, "utf8"));
const corpus = validateGateQualificationV2Corpus(rawCorpus);
const sourceBytes = JSON.stringify(rawCorpus);

test("Gate Qualification v2 corpus is closed, versioned, unique, and immutable", () => {
  assert.equal(
    corpus["@version"],
    GATE_QUALIFICATION_V2_VECTOR_VERSION,
  );
  assert.equal(corpus.vectors.length, 79);
  assert.equal(
    new Set(corpus.vectors.map((vector) => vector.id)).size,
    corpus.vectors.length,
  );
  assert.equal(Object.isFrozen(corpus), true);
  assert.equal(Object.isFrozen(corpus.base), true);
  assert.equal(Object.isFrozen(corpus.vectors), true);
  assert.equal(Object.isFrozen(corpus.vectors[0]), true);
});

test("Gate Qualification v2 corpus covers every frozen hostile boundary", () => {
  const families = new Set(corpus.vectors.map((vector) => vector.family));
  for (const family of [
    "identity",
    "assignment",
    "evaluation-integrity",
    "qualification-status",
    "begin-invocation-binding",
    "canonicalization",
    "snapshot-binding",
    "concurrency",
    "resource-fencing",
    "supersession",
    "crash-boundary",
    "provider-boundary",
    "provider-evidence",
    "retry-safety",
    "shadow-safety",
  ]) {
    assert.ok(families.has(family), `missing vector family ${family}`);
  }

  const identityTargets = new Set(
    corpus.vectors
      .filter((vector) => vector.family === "identity")
      .map((vector) => vector.mutation?.target),
  );
  for (const target of [
    "runtime.static.code_digests.0",
    "runtime.static.dependency_digests.0",
    "runtime.static.prompt_template_digests.0",
    "runtime.static.tool_definition_digests.0",
    "runtime.static.effective_permissions_digest",
    "runtime.static.model.identity",
    "runtime.static.model.artifact_digest",
    "runtime.static.model.version",
    "runtime.static.retrieval_configuration_digest",
    "runtime.dynamic_retrieval_root",
    "runtime.memory_state_digest",
    "runtime.user_input_digest",
    "runtime.static.builder_orchestrator_digest",
    "runtime.candidate_manifest_digest",
  ]) {
    assert.ok(identityTargets.has(target), `missing identity target ${target}`);
  }

  const faults = new Set(
    corpus.vectors.map((vector) => vector.mutation?.fault),
  );
  for (const fault of [
    "cross_assignment_reuse",
    "omitted_terminal_outcome",
    "discarded_attempt",
    "challenge_grinding",
    "selective_rerun",
    "status_stale",
    "status_revoked",
    "status_equivocated",
  ]) {
    assert.ok(faults.has(fault), `missing hostile fault ${fault}`);
  }

  const recheckTargets = new Set(
    corpus.vectors
      .filter((vector) => vector.operation === "begin_recheck")
      .map((vector) => vector.mutation?.target),
  );
  for (const target of [
    "currentness.runtime_measurement_digest",
    "currentness.candidate_match",
    "currentness.trust_configuration_digest",
    "currentness.qualification_status_sequence",
    "body.effect_request_digest",
    "body.provider.provider_id",
    "body.provider.account_id",
    "body.tenant_id",
    "body.operation_id",
    "body.caid",
    "body.action_digest",
  ]) {
    assert.ok(recheckTargets.has(target), `missing recheck target ${target}`);
  }

  const snapshotTargets = new Set(
    corpus.vectors
      .filter((vector) => vector.operation === "snapshot")
      .map((vector) => vector.mutation?.target),
  );
  for (const target of [
    "provider.provider_id",
    "executor_adapter_digest",
    "provider.account_id",
    "provider.environment",
    "tenant_id",
  ]) {
    assert.ok(snapshotTargets.has(target), `missing snapshot target ${target}`);
  }

  const crashScenarios = new Set(
    corpus.vectors
      .filter((vector) => vector.operation === "crash")
      .map((vector) => vector.scenario),
  );
  assert.deepEqual(
    [...crashScenarios].sort(),
    [
      "after_begin_write",
      "after_effect_outcome_write",
      "after_provider_outcome_write",
      "after_recovery_write",
      "after_release_write",
      "after_reserve_write",
      "after_supersession_write",
    ],
  );

  const providerScenarios = new Set(
    corpus.vectors
      .filter((vector) => vector.operation === "provider")
      .map((vector) => vector.scenario),
  );
  for (const scenario of [
    "crash_before_provider",
    "crash_after_provider",
    "timeout",
    "forged_evidence",
    "replayed_evidence",
    "contradictory_committed_no_effect",
    "contradictory_not_committed_effect",
    "committed_diverged",
    "post_begin_no_blind_retry",
    "no_blind_retry",
  ]) {
    assert.ok(
      providerScenarios.has(scenario),
      `missing provider scenario ${scenario}`,
    );
  }

  const ids = new Set(corpus.vectors.map((vector) => vector.id));
  for (const id of [
    "shadow-non-actuation",
    "transactional-currentness-before-actuation",
    "recovery-token-rotation",
    "same-operation-reserved-only-supersession",
    "committed-diverged-independent",
    "post-begin-no-blind-retry",
  ]) {
    assert.ok(ids.has(id), `missing canonical vector ${id}`);
  }
});

test("Gate Qualification v2 corpus validation rejects open extensions", () => {
  assert.throws(
    () => validateGateQualificationV2Corpus({ ...rawCorpus, extension: true }),
    /unknown fields: extension/,
  );
  assert.throws(
    () => validateGateQualificationV2Corpus({
      ...rawCorpus,
      base: { ...rawCorpus.base, gate_request: {} },
    }),
    /vector corpus base has unknown fields: gate_request/,
  );
});

for (const vector of corpus.vectors) {
  test(`Gate Qualification v2 vector: ${vector.id}`, async () => {
    const before = JSON.stringify(corpus);
    const actual = await runGateQualificationV2Vector(vector, corpus);
    const match = vectorResultMatches(actual, vector.expected);
    assert.equal(
      match.ok,
      true,
      `${vector.id}\n${match.mismatches.join("\n")}\nactual=${JSON.stringify(actual)}`,
    );
    assert.equal(JSON.stringify(corpus), before, `${vector.id} mutated corpus`);
    assert.equal(Object.isFrozen(actual), true);
  });
}

test("Gate Qualification v2 adapter leaves source JSON unchanged", () => {
  assert.equal(JSON.stringify(rawCorpus), sourceBytes);
});
