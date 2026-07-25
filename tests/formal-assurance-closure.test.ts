// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  runFormalRuntimeTraceGate,
  runRuntimeTraceConformance,
} from "../scripts/check-formal-runtime-traces.mjs";
import { validateTraceManifest } from "../conformance/refinement/schema.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (relative: string) =>
  JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));

const MODEL_CONTRACTS = Object.freeze([
  {
    model: "formal/ep_composed_trust_lifecycle.tla",
    config: "formal/ep_composed_trust_lifecycle.cfg",
    result: "formal/results/ep-composed-trust-lifecycle.tlc.summary.txt",
    marker: "EP-COMPOSED-TRUST-LIFECYCLE-TLC-BOUNDED-v1",
  },
  {
    model: "formal/ep_consequence_lifecycle.tla",
    config: "formal/ep_consequence_lifecycle.cfg",
    result: "formal/results/ep-consequence-lifecycle.tlc.summary.txt",
    marker: "EP-CONSEQUENCE-LIFECYCLE-TLC-BOUNDED-v1",
  },
  {
    model: "formal/ep_revocation_witness.tla",
    config: "formal/ep_revocation_witness.cfg",
    result: "formal/results/ep-revocation-witness.tlc.summary.txt",
    marker: "EP-REVOCATION-WITNESS-TLC-BOUNDED-v1",
  },
  {
    model: "formal/ep_effect_profiles.tla",
    config: "formal/ep_effect_profiles.cfg",
    result: "formal/results/ep-effect-profiles.tlc.summary.txt",
    marker: "EP-EFFECT-PROFILES-TLC-BOUNDED-v1",
  },
  {
    model: "formal/ep_authority_program.tla",
    config: "formal/ep_authority_program.cfg",
    result: "formal/results/ep-authority-program.tlc.summary.txt",
    marker: "EP-AUTHORITY-PROGRAM-TLC-BOUNDED-v1",
  },
  {
    model: "formal/ep_receipt_program.tla",
    config: "formal/ep_receipt_program.cfg",
    result: "formal/results/ep-receipt-program.tlc.summary.txt",
    marker: "EP-RECEIPT-PROGRAM-TLC-BOUNDED-v1",
  },
]);

const PREEXISTING_CLOSED_CLAIMS = Object.freeze([
  "action-escrow-releases-one-exact-milestone-once",
  "aec-role-substitution-refused",
  "grace-curtailment-is-authorized-measured-and-single-use",
  "mobile-action-continuity-is-tenant-and-executor-bound",
  "mobile-enrollment-requires-two-verified-rows",
  "model-to-matter-clearance-is-exact-and-single-use",
  "network-witness-equivocation-permanently-poisons-stream",
  "revocation-is-pinned-effective-and-terminal",
  "ambiguous-effect-is-never-auto-retried",
]);

const FIVE_CLAIM_RUNTIME_BRIDGE = Object.freeze([
  {
    claim: "conservation-of-authority-is-bounded-and-non-amplifying",
    model: "formal/conservation-authority.model.mjs",
    adapter: "conservation-authority",
    runtimeSource: "packages/gate/src/authority-allocation.ts",
    obligation: "AggregateBranchBudgetIsConserved",
    backend: "bounded_checker",
  },
  {
    claim: "outcome-binding-is-exact-and-fail-closed",
    model: "formal/outcome-authority-join.model.mjs",
    adapter: "outcome-binding",
    runtimeSource: "packages/verify/src/outcome-binding.ts",
    obligation: "ExactActionReceiptBinding",
    backend: "bounded_checker",
  },
  {
    claim: "authority-document-proof-join-is-pinned-and-non-resurrecting",
    model: "formal/outcome-authority-join.model.mjs",
    adapter: "authority-document-proof-join",
    runtimeSource: "lib/authority/document-proof-join.ts",
    obligation: "NewestAuthorityDocumentPreventsKeyResurrection",
    backend: "bounded_checker",
  },
  {
    claim: "authority-program-composition-is-root-bound-and-closed",
    model: "formal/ep_authority_program.tla",
    adapter: "authority-program",
    runtimeSource: "packages/verify/src/authority-program.ts",
    obligation: "ValidImpliesRootActionBinding",
    backend: "tla",
  },
  {
    claim: "receipt-program-is-caid-bound-budgeted-and-terminal",
    model: "formal/ep_receipt_program.tla",
    adapter: "receipt-program",
    runtimeSource: "packages/gate/src/receipt-program.ts",
    obligation: "PipelineOrderSafety",
    backend: "tla",
  },
]);

const CLOSED_CLAIMS = Object.freeze([
  ...PREEXISTING_CLOSED_CLAIMS,
  ...FIVE_CLAIM_RUNTIME_BRIDGE.map(({ claim }) => claim),
  "durable-consumption-is-owner-fenced",
  "signed-denial-cannot-authorize",
  "scoped-authority-is-pinned",
  "reliance-requires-pinned-profile",
  "evidence-challenge-is-durably-registered-and-consumed",
  "aec-execution-is-action-keyed-and-fleet-fail-closed",
]);

describe("formal assurance closure contract", () => {
  it("pins six bounded models, configurations, and result summaries", () => {
    for (const contract of MODEL_CONTRACTS) {
      for (const relative of [
        contract.model,
        contract.config,
        contract.result,
      ]) {
        expect(fs.existsSync(path.join(root, relative)), relative).toBe(true);
      }
      expect(
        fs.readFileSync(path.join(root, contract.result), "utf8"),
      ).toContain(contract.marker);
      expect(
        fs.readFileSync(path.join(root, contract.result), "utf8"),
      ).toContain("Model checking completed. No error has been found.");
    }
  });

  it("replays every governed runtime scenario against the committed projection contract", async () => {
    const manifest = readJson("formal/runtime-scenarios.v2.json");
    const sound = manifest.scenarios.filter(
      (scenario: { kind: string }) => scenario.kind === "sound",
    ).length;
    const negativeControls = manifest.scenarios.filter(
      (scenario: { kind: string }) =>
        scenario.kind === "paired_negative_control",
    ).length;
    const result = await runRuntimeTraceConformance();
    expect(result.scenarios).toBe(manifest.scenarios.length);
    expect(result.sound_scenarios).toBe(sound);
    expect(result.paired_negative_controls_rejected).toBe(negativeControls);
    expect(result.claims).toEqual([...CLOSED_CLAIMS].sort());
  });

  it("bridges each assigned claim through sound evidence and a paired formal-counterexample/runtime-refusal control", () => {
    const manifest = readJson("formal/runtime-scenarios.v2.json");
    const evidence = readJson(
      "formal/results/formal-runtime-scenario-conformance.v2.json",
    );

    for (const contract of FIVE_CLAIM_RUNTIME_BRIDGE) {
      const model = manifest.models[contract.model];
      expect(model, contract.claim).toBeTruthy();
      expect(model.kind ?? "tla", contract.claim).toBe(contract.backend);

      const scenarios = manifest.scenarios.filter(
        (scenario: any) =>
          scenario.claim_id === contract.claim &&
          scenario.model === contract.model &&
          scenario.adapter === contract.adapter,
      );
      expect(
        scenarios.filter((scenario: any) => scenario.kind === "sound"),
        contract.claim,
      ).toHaveLength(1);
      expect(
        scenarios.filter(
          (scenario: any) => scenario.kind === "paired_negative_control",
        ),
        contract.claim,
      ).toHaveLength(1);
      expect(
        scenarios.every((scenario: any) =>
          scenario.runtime_sources.includes(contract.runtimeSource),
        ),
        contract.claim,
      ).toBe(true);
      expect(
        scenarios.find(
          (scenario: any) => scenario.kind === "paired_negative_control",
        )
          ?.mutation?.obligation,
        contract.claim,
      ).toBe(contract.obligation);

      const conformed = evidence.scenarios.filter(
        (scenario: any) =>
          scenario.claim_id === contract.claim &&
          scenario.model === contract.model &&
          scenario.adapter === contract.adapter &&
          scenario.matched === true,
      );
      const sound = conformed.find((scenario: any) => scenario.kind === "sound");
      const negative = conformed.find(
        (scenario: any) => scenario.kind === "paired_negative_control",
      );
      expect(sound?.formal?.status, contract.claim).toBe("matched");
      expect(negative?.formal?.status, contract.claim).toBe(
        "counterexample_detected",
      );
      expect(negative?.formal?.obligation, contract.claim).toBe(
        contract.obligation,
      );
      expect(
        negative?.runtime?.steps?.at(-1)?.accepted,
        contract.claim,
      ).toBe(false);

      if (contract.backend === "bounded_checker") {
        for (const scenario of conformed) {
          expect(scenario.relation?.shared_input, scenario.id).toBeTruthy();
          expect(scenario.relation?.status, scenario.id).toBe("matched");
          expect(
            scenario.relation?.fields?.length,
            scenario.id,
          ).toBeGreaterThan(0);
          expect(
            scenario.relation?.formal_projection,
            scenario.id,
          ).toBeTruthy();
          expect(
            scenario.relation?.runtime_projection,
            scenario.id,
          ).toBeTruthy();
          for (const field of scenario.relation.fields) {
            expect(
              scenario.relation.formal_projection[field],
              `${scenario.id}:${field}`,
            ).toEqual(scenario.relation.runtime_projection[field]);
          }
        }
        expect(sound?.formal?.backend, contract.claim).toBe(
          "bounded_exhaustive_state_exploration",
        );
        expect(negative?.formal?.backend, contract.claim).toBe(
          "bounded_exhaustive_state_exploration",
        );
        expect(
          negative?.formal?.checks?.find(
            (row: any) => row.obligation === contract.obligation,
          )?.mutation_counterexample_sha256,
          contract.claim,
        ).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(negative?.formal?.control, contract.claim).toMatchObject({
          kind: "formal_mutation_counterexample",
          obligation: contract.obligation,
          sound_input_refused: true,
          mutant_input_accepted: true,
        });
        expect(negative?.control_semantics, contract.claim).toBe(
          "paired_formal_counterexample_runtime_refusal",
        );
      }
    }
  });

  it("derives nonempty selected scenario metadata from operators and formal-entry obligations", () => {
    const manifest = readJson("formal/runtime-scenarios.v2.json");
    const claims = readJson("security/claims.v1.json").claims;

    for (const contract of FIVE_CLAIM_RUNTIME_BRIDGE) {
      const scenarios = manifest.scenarios.filter(
        (scenario: any) =>
          scenario.claim_id === contract.claim &&
          scenario.model === contract.model,
      );
      const tracedActions = [
        ...new Set(
          scenarios.flatMap((scenario: any) =>
            scenario.steps.map((step: any) => step.operator),
          ),
        ),
      ].sort();
      const tracedObligations = [
        ...new Set(
          scenarios.flatMap((scenario: any) => scenario.obligations),
        ),
      ].sort();
      const claim = claims.find(
        (candidate: any) => candidate.claim_id === contract.claim,
      );
      const formal = claim.formal.find(
        (entry: any) => entry.model === contract.model,
      );

      expect(tracedActions.length, contract.claim).toBeGreaterThan(0);
      expect(tracedObligations.length, contract.claim).toBeGreaterThan(0);
      expect(
        tracedObligations.every((obligation: string) =>
          formal.obligations.includes(obligation),
        ),
        contract.claim,
      ).toBe(true);
    }
  });

  it("records literal implementation-backed coverage while preserving the bounded claim status", () => {
    const claims = readJson("security/claims.v1.json").claims;
    for (const claimId of CLOSED_CLAIMS) {
      const claim = claims.find(
        (candidate: any) => candidate.claim_id === claimId,
      );
      expect(claim, claimId).toBeTruthy();
      expect(
        claim.formal.some((entry: any) => entry.status === "partial"),
        claimId,
      ).toBe(true);
      expect(
        claim.formal.some(
          (entry: any) =>
            [
              "bounded_tla_model_checking",
              "bounded_exhaustive_state_exploration",
            ].includes(entry.method) &&
            typeof entry.model === "string" &&
            typeof entry.runner === "string" &&
            typeof entry.result_evidence === "string" &&
            Array.isArray(entry.obligations) &&
            entry.obligations.length > 0,
        ),
        claimId,
      ).toBe(true);
    }
  });

  it("requires every declared composed action to have a governed runtime scenario", () => {
    const manifest = readJson("formal/runtime-scenarios.v2.json");
    const composed =
      manifest.models["formal/ep_composed_trust_lifecycle.tla"];
    expect(composed.required_actions).toHaveLength(28);
    const covered = new Set(
      manifest.scenarios
        .filter(
          (scenario: any) =>
            scenario.model === "formal/ep_composed_trust_lifecycle.tla",
        )
        .flatMap((scenario: any) => [
          ...(scenario.formal_prefix ?? []),
          ...scenario.steps.map((step: any) => step.operator),
        ]),
    );
    expect(
      composed.required_actions.filter(
        (action: string) => !covered.has(action),
      ),
    ).toEqual([]);

    const evidence = readJson(
      "formal/results/formal-runtime-scenario-conformance.v2.json",
    );
    expect(evidence.summary.required_model_actions).toBe(28);
    expect(evidence.summary.covered_model_actions).toBe(28);
    expect(evidence.summary.action_complete_models).toEqual([
      "formal/ep_composed_trust_lifecycle.tla",
    ]);
  });

  it("fails closed when a required composed action loses its scenario", () => {
    const manifest = structuredClone(
      readJson("formal/runtime-scenarios.v2.json"),
    );
    manifest.scenarios = manifest.scenarios.filter(
      (scenario: any) =>
        scenario.id !== "composed-aec-role-substitution-refusal",
    );
    expect(() => validateTraceManifest(manifest)).toThrow(
      /required_actions are not trace-covered: PresentSubstitutedAECRole/,
    );
  });

  it("keeps the selected-scenario boundary explicit", () => {
    const result = readJson(
      "formal/results/formal-runtime-scenario-conformance.v2.json",
    );
    expect(result.method).toBe("bounded_selected_scenario_conformance");
    expect(result.limitations).toContain(
      "Selected-scenario conformance is not a mechanized implementation refinement proof.",
    );
  });

  it("never accepts a committed formal verdict as its own checking oracle", async () => {
    await expect(runFormalRuntimeTraceGate()).rejects.toThrow(
      /requires --tlc-jar or TLA2TOOLS_JAR/,
    );
  });

  it("content-addresses the executable scenario-conformance closure and its generation contract", () => {
    const evidence = readJson(
      "formal/results/formal-runtime-scenario-conformance.v2.json",
    );
    const inputs = new Set(
      evidence.inputs.map((entry: { path: string }) => entry.path),
    );
    for (const required of [
      "scripts/check-formal-runtime-traces.mjs",
      "conformance/refinement/harness.mjs",
      "conformance/refinement/adapters/consequence-lifecycle.mjs",
      "conformance/refinement/adapters/composed-trust-lifecycle.mjs",
      "conformance/refinement/adapters/five-claim-bridge.mjs",
      "formal/check-conservation-authority.mjs",
      "formal/check-outcome-authority-join.mjs",
      "formal/ep_authority_program.tla",
      "formal/ep_authority_program.cfg",
      "formal/ep_receipt_program.tla",
      "formal/ep_receipt_program.cfg",
      "conformance/vectors/authority-document-proof-join.exec.v1.json",
      "conformance/vectors/authority-program.v1.json",
      "conformance/vectors/outcome-binding.exec.v1.json",
      "packages/gate/src/authority-allocation.ts",
      "packages/gate/src/receipt-program.ts",
      "packages/verify/src/authority-program.ts",
      "packages/verify/src/outcome-binding.ts",
      "lib/authority/document-proof-join.ts",
      "scripts/build-standalone-runtimes.mjs",
      "scripts/standalone-runtime-targets.mjs",
      "package.json",
      "package-lock.json",
    ]) {
      expect(inputs.has(required), required).toBe(true);
    }
  });

  it("forces TLC execution in both governed CI lanes", () => {
    const ci = fs.readFileSync(
      path.join(root, ".github/workflows/ci.yml"),
      "utf8",
    );
    const tlc = fs.readFileSync(
      path.join(root, ".github/workflows/tlc.yml"),
      "utf8",
    );
    expect(ci).toContain("TLA2TOOLS_JAR:");
    expect(ci).toContain("Download pinned TLC model checker");
    expect(tlc).toContain("'packages/gate/**'");
    expect(tlc).toContain("'package-lock.json'");
  });
});
