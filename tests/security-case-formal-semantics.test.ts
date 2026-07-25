// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "..");
const verifier = path.join(root, "scripts", "verify-security-case.mjs");
const loader = path.join(root, "scripts", "ts-loader", "register.mjs");
const temporaryDirectory = fs.mkdtempSync(
  path.join(root, ".ep-security-formal-semantics-"),
);
const scenarioFixturePath = path.join(
  temporaryDirectory,
  "runtime-scenarios.v2.json",
);
const legacyScenarioFixturePath = path.join(
  temporaryDirectory,
  "runtime-traces.v1.json",
);
const conformanceFixturePath = path.join(
  temporaryDirectory,
  "formal-runtime-scenario-conformance.v2.json",
);
const legacyConformanceFixturePath = path.join(
  temporaryDirectory,
  "formal-runtime-refinement.v1.json",
);
const scenarioFixture = JSON.parse(
  fs.readFileSync(
    path.join(root, "formal", "runtime-scenarios.v2.json"),
    "utf8",
  ),
);
const legacyScenarioFixture = structuredClone(scenarioFixture);
legacyScenarioFixture["@version"] = "EP-FORMAL-RUNTIME-TRACES-v2";
legacyScenarioFixture.traces = legacyScenarioFixture.scenarios;
delete legacyScenarioFixture.scenarios;
fs.writeFileSync(
  legacyScenarioFixturePath,
  `${JSON.stringify(legacyScenarioFixture, null, 2)}\n`,
);
scenarioFixture["@version"] =
  "EP-RUNTIME-SCENARIO-CONFORMANCE-MANIFEST-v2";
fs.writeFileSync(
  scenarioFixturePath,
  `${JSON.stringify(scenarioFixture, null, 2)}\n`,
);
const conformanceFixture = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "formal",
      "results",
      "formal-runtime-scenario-conformance.v2.json",
    ),
    "utf8",
  ),
);
const legacyConformanceFixture = structuredClone(conformanceFixture);
legacyConformanceFixture["@version"] =
  "EP-FORMAL-RUNTIME-REFINEMENT-EVIDENCE-v1";
legacyConformanceFixture.method = "bounded_selected_trace_refinement";
legacyConformanceFixture.traces = legacyConformanceFixture.scenarios;
delete legacyConformanceFixture.scenarios;
fs.writeFileSync(
  legacyConformanceFixturePath,
  `${JSON.stringify(legacyConformanceFixture, null, 2)}\n`,
);
conformanceFixture["@version"] =
  "EP-SELECTED-SCENARIO-CONFORMANCE-EVIDENCE-v2";
conformanceFixture.method = "bounded_selected_scenario_conformance";
fs.writeFileSync(
  conformanceFixturePath,
  `${JSON.stringify(conformanceFixture, null, 2)}\n`,
);

const readSourceCase = (): any =>
  JSON.parse(
    fs.readFileSync(path.join(root, "security", "claims.v1.json"), "utf8"),
  );

function normalizedSourceCase(): any {
  const sourceCase = readSourceCase();
  for (const claim of sourceCase.claims) {
    for (const formal of claim.formal ?? []) {
      if (formal.status === "not_modeled") continue;
      formal.method ??= "symbolic_protocol_analysis";
      if (
        formal.method === "symbolic_protocol_analysis" &&
        formal.status === "partial"
      ) {
        formal.covered_statement = "The named symbolic lemma is covered.";
        formal.unmodeled_statement =
          "Concrete implementation behavior remains unmodeled.";
      }
      if (
        formal.trace_evidence ||
        formal.trace_runner ||
        formal.refinement_evidence ||
        formal.scenario_evidence ||
        formal.scenario_runner ||
        formal.conformance_evidence
      ) {
        formal.scenario_evidence = path.relative(root, scenarioFixturePath);
        formal.scenario_runner =
          formal.scenario_runner ??
          formal.trace_runner ??
          "scripts/check-formal-runtime-traces.mjs";
        formal.conformance_evidence = path.relative(
          root,
          conformanceFixturePath,
        );
        formal.scenario_coverage = "selected";
        formal.covered_actions = ["RepresentativeRuntimeAction"];
        formal.covered_obligations = [formal.obligations[0]];
        delete formal.trace_evidence;
        delete formal.trace_runner;
        delete formal.refinement_evidence;
        delete formal.trace_coverage;
        delete formal.traced_actions;
        delete formal.traced_obligations;
      }
    }
  }
  return sourceCase;
}

function findFormal(
  sourceCase: any,
  predicate: (formal: any) => boolean,
): any {
  for (const claim of sourceCase.claims) {
    const formal = (claim.formal ?? []).find(predicate);
    if (formal) return formal;
  }
  throw new Error("formal test fixture entry not found");
}

function runMutatedCase(mutate: (sourceCase: any) => void) {
  const sourceCase = normalizedSourceCase();
  mutate(sourceCase);
  const sourcePath = path.join(
    temporaryDirectory,
    `claims-${crypto.randomUUID()}.json`,
  );
  fs.writeFileSync(sourcePath, `${JSON.stringify(sourceCase, null, 2)}\n`);
  return spawnSync(
    process.execPath,
    [
      "--import",
      loader,
      verifier,
      "--source",
      sourcePath,
      "--validate-only",
    ],
    { cwd: root, encoding: "utf8" },
  );
}

function expectRejected(
  mutate: (sourceCase: any) => void,
  message: RegExp,
): void {
  const result = runMutatedCase(mutate);
  expect(`${result.stdout}${result.stderr}`).toMatch(message);
  expect(result.status).toBe(1);
}

afterAll(() => {
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

describe("security-case formal metadata semantics", () => {
  it("accepts explicit symbolic partial and verified vocabulary", () => {
    const result = runMutatedCase(() => {});
    expect(`${result.stdout}${result.stderr}`).toContain(
      "SECURITY CASE: METADATA OK",
    );
    expect(result.status).toBe(0);
  });

  it("rejects omitted and unknown formal methods", () => {
    expectRejected((sourceCase) => {
      delete findFormal(
        sourceCase,
        (formal) => formal.method === "symbolic_protocol_analysis",
      ).method;
    }, /formal method must be one of/);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.method === "symbolic_protocol_analysis",
      ).method = "informal_argument";
    }, /formal method must be one of/);
  });

  it("requires covered and unmodeled statements only for partial symbolic analysis", () => {
    expectRejected((sourceCase) => {
      delete findFormal(
        sourceCase,
        (formal) =>
          formal.method === "symbolic_protocol_analysis" &&
          formal.status === "partial",
      ).covered_statement;
    }, /partial symbolic protocol analysis requires a non-empty covered_statement/);
    expectRejected((sourceCase) => {
      delete findFormal(
        sourceCase,
        (formal) =>
          formal.method === "symbolic_protocol_analysis" &&
          formal.status === "partial",
      ).unmodeled_statement;
    }, /partial symbolic protocol analysis requires a non-empty unmodeled_statement/);

    const verified = runMutatedCase((sourceCase) => {
      const formal = findFormal(
        sourceCase,
        (entry) =>
          entry.method === "symbolic_protocol_analysis" &&
          entry.status === "verified",
      );
      delete formal.covered_statement;
      delete formal.unmodeled_statement;
    });
    expect(verified.status).toBe(0);
  });

  it("requires selected, non-empty machine-readable scenario coverage", () => {
    expectRejected((sourceCase) => {
      delete findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).scenario_coverage;
    }, /bounded scenario conformance requires scenario_coverage selected/);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).covered_actions = [];
    }, /bounded scenario conformance requires non-empty covered_actions/);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).covered_obligations = [];
    }, /bounded scenario conformance requires non-empty covered_obligations/);
  });

  it("rejects legacy trace/refinement metadata and v1 evidence", () => {
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).trace_evidence = "formal/runtime-traces.v1.json";
    }, /legacy bounded trace\/refinement metadata is not accepted/);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).scenario_evidence = path.relative(root, legacyScenarioFixturePath);
    }, /must not contain legacy traces|unknown fields: traces/);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).conformance_evidence = path.relative(
        root,
        legacyConformanceFixturePath,
      );
    }, /must not contain the legacy traces array|must contain executed v2 selected-scenario conformance evidence/);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.method === "symbolic_protocol_analysis",
      ).scenario_coverage = "selected";
    }, /runtime scenario conformance metadata is only valid for bounded formal methods/);
  });

  it("rejects legacy negative kinds, unbound rows, weak summaries, and noncanonical runners", () => {
    const badKindPath = path.join(
      temporaryDirectory,
      `scenario-bad-kind-${crypto.randomUUID()}.json`,
    );
    const badKind = structuredClone(scenarioFixture);
    badKind.scenarios.find(
      (scenario: any) =>
        scenario.kind === "paired_negative_control",
    ).kind = "unsafe_mutation";
    fs.writeFileSync(badKindPath, `${JSON.stringify(badKind, null, 2)}\n`);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).scenario_evidence = path.relative(root, badKindPath);
    }, /kind must be sound or paired_negative_control/);

    const badEvidencePath = path.join(
      temporaryDirectory,
      `conformance-bad-id-${crypto.randomUUID()}.json`,
    );
    const badEvidence = structuredClone(conformanceFixture);
    badEvidence.scenarios[0].id = "not-in-the-manifest";
    fs.writeFileSync(
      badEvidencePath,
      `${JSON.stringify(badEvidence, null, 2)}\n`,
    );
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).conformance_evidence = path.relative(root, badEvidencePath);
    }, /is not manifest-bound/);

    const weakSummaryPath = path.join(
      temporaryDirectory,
      `conformance-weak-summary-${crypto.randomUUID()}.json`,
    );
    const weakSummary = structuredClone(conformanceFixture);
    weakSummary.summary = {};
    fs.writeFileSync(
      weakSummaryPath,
      `${JSON.stringify(weakSummary, null, 2)}\n`,
    );
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).conformance_evidence = path.relative(root, weakSummaryPath);
    }, /summary is missing or not re-derived/);

    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).scenario_runner = "scripts/not-the-governed-runner.mjs";
    }, /scenario_runner must name the canonical executed runner|evidence file not found/);
  });

  it("rejects covered obligations outside the formal obligation set", () => {
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).covered_obligations = ["UndeclaredFormalObligation"];
    }, /covered_obligations must be a subset of obligations/);
    expectRejected((sourceCase) => {
      const formal = findFormal(
        sourceCase,
        (entry) =>
          entry.method === "bounded_exhaustive_state_exploration" &&
          !entry.scenario_evidence,
      );
      formal.scenario_evidence = path.relative(root, scenarioFixturePath);
      formal.scenario_runner = "scripts/check-formal-runtime-traces.mjs";
      formal.conformance_evidence = path.relative(
        root,
        conformanceFixturePath,
      );
      formal.scenario_coverage = "selected";
      formal.covered_actions = ["RepresentativeRuntimeAction"];
      formal.covered_obligations = ["UndeclaredFormalObligation"];
      formal.scope += " These selected scenarios are not a refinement proof.";
    }, /covered_obligations must be a subset of obligations/);
  });

  it("keeps selected bounded scenarios partial and short of a refinement proof", () => {
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) =>
          formal.method === "bounded_tla_model_checking" &&
          formal.scenario_coverage === "selected",
      ).status = "verified";
    }, /bounded TLA\+ formal evidence must remain status partial/);
    expectRejected((sourceCase) => {
      findFormal(
        sourceCase,
        (formal) => formal.scenario_coverage === "selected",
      ).scope = "Bounded same-team selected runtime scenarios.";
    }, /selected scenario conformance must state that it is not a refinement proof/);
  });
});
