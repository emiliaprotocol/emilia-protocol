// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  runFormalRuntimeTraceGate,
  runRuntimeTraceConformance,
} from "../scripts/check-formal-runtime-traces.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (relative: string) =>
  JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));

const MODEL_CONTRACTS = Object.freeze([
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
]);

const CLOSED_CLAIMS = Object.freeze([
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

describe("formal assurance closure contract", () => {
  it("pins three bounded models, configurations, and result summaries", () => {
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

  it("replays every governed runtime trace against the committed projection contract", async () => {
    const manifest = readJson("formal/runtime-traces.v1.json");
    const sound = manifest.traces.filter(
      (trace: { kind: string }) => trace.kind === "sound",
    ).length;
    const unsafe = manifest.traces.filter(
      (trace: { kind: string }) => trace.kind === "unsafe_mutation",
    ).length;
    const result = await runRuntimeTraceConformance();
    expect(result.traces).toBe(manifest.traces.length);
    expect(result.sound_traces).toBe(sound);
    expect(result.unsafe_mutations_rejected).toBe(unsafe);
    expect(result.claims).toEqual([...CLOSED_CLAIMS].sort());
  });

  it("moves implementation-backed gaps to bounded partial formal coverage", () => {
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
            entry.method === "bounded_tla_model_checking" &&
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

  it("keeps the refinement boundary explicit", () => {
    const result = readJson(
      "formal/results/formal-runtime-refinement.v1.json",
    );
    expect(result.method).toBe("bounded_selected_trace_refinement");
    expect(result.limitations).toContain(
      "Trace refinement tests selected transitions; it is not a mechanized implementation refinement proof.",
    );
  });

  it("never accepts a committed formal verdict as its own checking oracle", async () => {
    await expect(runFormalRuntimeTraceGate()).rejects.toThrow(
      /requires --tlc-jar or TLA2TOOLS_JAR/,
    );
  });

  it("content-addresses the executable refinement closure and its generation contract", () => {
    const evidence = readJson(
      "formal/results/formal-runtime-refinement.v1.json",
    );
    const inputs = new Set(
      evidence.inputs.map((entry: { path: string }) => entry.path),
    );
    for (const required of [
      "scripts/check-formal-runtime-traces.mjs",
      "conformance/refinement/harness.mjs",
      "conformance/refinement/adapters/consequence-lifecycle.mjs",
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
