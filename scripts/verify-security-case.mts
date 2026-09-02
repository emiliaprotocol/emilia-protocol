#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Resolve and execute every exact security claim, then bind the result to the
// reproducible release artifacts reviewers receive. This gate deliberately
// rejects keyword/substr coverage as evidence of an invariant.
//
// Security claims import the repository's TypeScript source directly. Register
// the same NodeNext `.js` -> `.ts` source resolver used by CI before any of
// those dynamic imports execute; otherwise the security gate silently loses
// executable coverage after a source file is converted from JS to TS.
import "./ts-loader/register.mjs";

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyReproduciblePackage } from "./verify-reproducible-package.mjs";
import { strictParseGate } from "../conformance/runners/strict-json.mjs";
import {
  buildSuiteContract,
  compareResultRow,
  executionSuiteFile,
  validateResultRows,
} from "../conformance/result-contract.mjs";
import { validateTraceManifest } from "../conformance/refinement/schema.mjs";
// The governed security case dynamically executes TypeScript-migrated source
// whose historical import specifiers still end in .js. Register the same
// resolver CI uses so `npm run check:security-case` is not CI-environment-only.
import "./ts-loader/register.mjs";

const ROOT: string = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
// Release-correspondence claims perform two clean, lifecycle-disabled package
// builds from exact Git objects. Cold CI can exceed three minutes, so retain a
// finite but realistic fail-closed bound for every executed evidence command.
const EXECUTION_TIMEOUT_MS: number = 600_000;
const args: string[] = process.argv.slice(2);
const execute: boolean = args.includes("--execute");
const validateOnly: boolean = args.includes("--validate-only");
const sourceIndex: number = args.indexOf("--source");
const sourceArgument: string | null =
  sourceIndex >= 0 ? args[sourceIndex + 1] : null;
if (sourceIndex >= 0 && !sourceArgument)
  throw new Error("--source requires a path");
if (sourceArgument && !validateOnly)
  throw new Error("--source may only be used with --validate-only");
if (execute && validateOnly)
  throw new Error("--execute and --validate-only cannot be combined");
const SOURCE: string = sourceArgument
  ? path.resolve(sourceArgument)
  : path.join(ROOT, "security", "claims.v1.json");
const DEFAULT_RESOLVED: string = path.join(
  ROOT,
  "security",
  "security-case.json",
);
const SELF: string = fileURLToPath(import.meta.url);
const emitIndex: number = args.indexOf("--emit");
const emitPath: string | null = emitIndex >= 0 ? args[emitIndex + 1] : null;
if (emitIndex >= 0 && !emitPath) throw new Error("--emit requires a path");

const errors: string[] = [];
const evidenceFiles: Set<string> = new Set([
  path.relative(ROOT, SOURCE),
  path.relative(ROOT, SELF),
  "conformance/result-contract.mjs",
  "conformance/runners/strict-json.mjs",
  "conformance/suites.mjs",
]);
const executionPlan: Map<string, any> = new Map();
const crossLanguageCases: Map<string, Map<string, any>> = new Map();
const boundedFormalPlan: Map<string, any> = new Map();
const scenarioConformancePlan: Map<string, Set<string>> = new Map();
const executionEvidence: any[] = [];
const FORMAL_METHODS: ReadonlySet<string> = new Set([
  "symbolic_protocol_analysis",
  "bounded_exhaustive_state_exploration",
  "bounded_tla_model_checking",
]);
const LEGACY_RUNTIME_EVIDENCE_FIELDS: readonly string[] = [
  "trace_evidence",
  "trace_runner",
  "refinement_evidence",
  "trace_coverage",
  "traced_actions",
  "traced_obligations",
];
const SCENARIO_CONFORMANCE_FIELDS: readonly string[] = [
  "scenario_evidence",
  "scenario_runner",
  "conformance_evidence",
  "scenario_coverage",
  "covered_actions",
  "covered_obligations",
];
const fail = (id: string, message: string): void => {
  errors.push(`[${id}] ${message}`);
};
const nonEmpty = (value: any): boolean =>
  typeof value === "string" && value.trim().length > 0;
const nonEmptyStringArray = (value: any): value is string[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.every((entry) => nonEmpty(entry));
const statesNoRefinementProof = (value: any): boolean =>
  nonEmpty(value) &&
  /\bnot (?:a )?(?:(?:full|mechanized implementation) )?refinement proof\b/i.test(
    value,
  );
const scenarioRows = (document: any): any[] =>
  Array.isArray(document?.scenarios) ? document.scenarios : [];
const escaped = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function resolveFile(id: string, relative: string): string | null {
  if (!nonEmpty(relative)) {
    fail(id, "missing evidence file path");
    return null;
  }
  const absolute = path.resolve(ROOT, relative);
  if (absolute !== ROOT && !absolute.startsWith(`${ROOT}${path.sep}`)) {
    fail(id, `path escapes repository: ${relative}`);
    return null;
  }
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
    fail(id, `evidence file not found: ${relative}`);
    return null;
  }
  evidenceFiles.add(path.relative(ROOT, absolute));
  return absolute;
}

function deepSubset(actual: any, expected: any): boolean {
  if (expected === null || typeof expected !== "object")
    return Object.is(actual, expected);
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      expected.length === actual.length &&
      expected.every((value: any, index: number) =>
        deepSubset(actual[index], value),
      )
    );
  }
  return (
    actual !== null &&
    typeof actual === "object" &&
    Object.entries(expected).every(([key, value]: [string, any]) =>
      deepSubset(actual[key], value),
    )
  );
}

function parseStrictJson(text: string, label: string): any {
  const gate = strictParseGate(text);
  if (!gate.ok) throw new Error(`${label}: ${gate.reason}`);
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label}: ${(error as any).message}`);
  }
}

function hasNamedDeclaration(
  source: string,
  language: string,
  symbol: string,
): boolean {
  const name: string = escaped(symbol);
  if (language === "python")
    return new RegExp(`^def\\s+${name}\\s*\\(`, "m").test(source);
  if (language === "go")
    return new RegExp(`^func\\s+(?:\\([^)]*\\)\\s*)?${name}\\s*\\(`, "m").test(
      source,
    );
  return new RegExp(
    `(?:^|\\n)\\s*(?:export\\s+)?(?:async\\s+)?(?:function|class)\\s+${name}\\b|(?:^|\\n)\\s*(?:export\\s+)?(?:const|let|var)\\s+${name}\\s*=`,
    "m",
  ).test(source);
}

function hasExactTestTitle(source: string, title: string): boolean {
  const name: string = escaped(title);
  return new RegExp(`(?:test|it)\\s*\\(\\s*(['\"\`])${name}\\1`).test(source);
}

// Return the callback body of the exactly titled test, skipping any options
// object argument (`test(title, { skip }, async () => { ... })`). Returns null
// when the title is absent or its callback body cannot be delimited.
function testCallbackBody(source: string, title: string): string | null {
  const declaration = new RegExp(
    `(?:test|it)\\s*\\(\\s*(['\"\`])${escaped(title)}\\1`,
  ).exec(source);
  if (!declaration) return null;
  const bodyStart = /=>\s*\{|function\b[^(){}]*\([^()]*\)\s*\{/g;
  bodyStart.lastIndex = declaration.index + declaration[0].length;
  if (!bodyStart.exec(source)) return null;
  const open: number = bodyStart.lastIndex - 1;
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    const character: string = source[index];
    if (character === "{") depth += 1;
    else if (character === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  return null;
}

// A named evidence test whose body has been emptied still carries its title and
// still reports green, so title presence alone is not evidence of anything. The
// body must contain at least one call expression once comments are removed.
function hasExecutableTestBody(source: string, title: string): boolean {
  const body: string | null = testCallbackBody(source, title);
  if (body === null) return false;
  const stripped: string = body
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
  return /[A-Za-z_$][\w$]*\s*\(/.test(stripped);
}

function hasFormalLemma(source: string, lemma: string): boolean {
  return new RegExp(`^lemma\\s+${escaped(lemma)}\\s*:`, "m").test(source);
}

function hasVerifiedResult(source: string, lemma: string): boolean {
  return new RegExp(
    `^\\s*${escaped(lemma)}\\s+\\([^\\n]*\\):\\s+verified\\b`,
    "m",
  ).test(source);
}

function hasBoundedFormalResult(source: string, obligation: string): boolean {
  return new RegExp(
    `^\\s*${escaped(obligation)}\\s+\\([^\\n]*\\):\\s+verified\\b`,
    "m",
  ).test(source);
}

function hasTlaDeclaration(source: string, obligation: string): boolean {
  return new RegExp(`^\\s*${escaped(obligation)}\\s*==`, "m").test(source);
}

function hasTlaConfiguredObligation(
  source: string,
  obligation: string,
): boolean {
  return new RegExp(
    `^\\s*(?:INVARIANT|PROPERTY)\\s+${escaped(obligation)}\\s*$`,
    "m",
  ).test(source);
}

function validateScenarioEvidence(
  label: string,
  manifest: any,
  evidence: any,
): any[] {
  if (evidence?.traces !== undefined) {
    throw new Error(`${label} must not contain the legacy traces array`);
  }
  if (
    evidence?.["@version"] !==
      "EP-SELECTED-SCENARIO-CONFORMANCE-EVIDENCE-v2" ||
    evidence?.method !== "bounded_selected_scenario_conformance"
  ) {
    throw new Error(
      `${label} must contain executed v2 selected-scenario conformance evidence`,
    );
  }
  if (
    typeof evidence?.toolchain?.tlc_jar_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(evidence.toolchain.tlc_jar_sha256) ||
    evidence?.toolchain?.bounded_checker_runtime !== "node"
  ) {
    throw new Error(`${label} has incomplete toolchain provenance`);
  }
  const scenarios = scenarioRows(evidence);
  const manifestScenarios = scenarioRows(manifest);
  if (scenarios.length !== manifestScenarios.length) {
    throw new Error(`${label} scenario count does not match the manifest`);
  }
  const manifestById = new Map(
    manifestScenarios.map((scenario: any) => [scenario.id, scenario]),
  );
  const seen = new Set<string>();
  for (const scenario of scenarios) {
    if (!nonEmpty(scenario?.id) || seen.has(scenario.id)) {
      throw new Error(`${label} has a missing or duplicate scenario id`);
    }
    seen.add(scenario.id);
    const planned: any = manifestById.get(scenario.id);
    if (
      !planned ||
      scenario.claim_id !== planned.claim_id ||
      scenario.model !== planned.model ||
      scenario.adapter !== planned.adapter ||
      scenario.scenario !== planned.scenario ||
      scenario.kind !== planned.kind ||
      scenario.matched !== true
    ) {
      throw new Error(`${label} scenario ${scenario.id} is not manifest-bound`);
    }
  }
  const summary = evidence?.summary;
  const sound = scenarios.filter(
    (scenario: any) => scenario.kind === "sound",
  ).length;
  const negative = scenarios.filter(
    (scenario: any) =>
      scenario.kind === "paired_negative_control" &&
      scenario.formal?.status === "counterexample_detected" &&
      scenario.runtime?.steps?.at(-1)?.accepted === false &&
      scenario.control_semantics ===
        "paired_formal_counterexample_runtime_refusal",
  ).length;
  const integerFields = [
    summary?.scenarios,
    summary?.sound_scenarios,
    summary?.paired_negative_controls,
    summary?.required_model_actions,
    summary?.covered_model_actions,
    summary?.formal_mutation_operators,
  ];
  if (
    integerFields.some(
      (value) => !Number.isSafeInteger(value) || value < 0,
    ) ||
    summary.scenarios !== scenarios.length ||
    summary.sound_scenarios !== sound ||
    summary.paired_negative_controls !== negative ||
    summary.formal_mutation_operators !==
      manifestScenarios.filter(
        (scenario: any) => scenario.kind === "paired_negative_control",
      ).length
  ) {
    throw new Error(`${label} summary is missing or not re-derived`);
  }
  return scenarios;
}

function validateBoundedScenarioConformance(id: string, formal: any): void {
  const legacyFields = LEGACY_RUNTIME_EVIDENCE_FIELDS.filter(
    (field) => formal[field] !== undefined,
  );
  if (legacyFields.length > 0) {
    fail(
      id,
      `legacy bounded trace/refinement metadata is not accepted: ${legacyFields.join(", ")}`,
    );
  }
  const hasScenarioEvidence = nonEmpty(formal.scenario_evidence);
  const hasScenarioRunner = nonEmpty(formal.scenario_runner);
  const hasConformanceEvidence = nonEmpty(formal.conformance_evidence);
  const hasScenarioMetadata =
    formal.scenario_coverage !== undefined ||
    formal.covered_actions !== undefined ||
    formal.covered_obligations !== undefined;
  if (
    !hasScenarioEvidence &&
    !hasScenarioRunner &&
    !hasConformanceEvidence &&
    !hasScenarioMetadata
  ) {
    return;
  }
  if (
    !hasScenarioEvidence ||
    !hasScenarioRunner ||
    !hasConformanceEvidence
  ) {
    fail(
      id,
      "bounded selected-scenario evidence requires scenario_evidence, scenario_runner, and conformance_evidence together",
    );
    return;
  }
  if (formal.scenario_coverage !== "selected") {
    fail(
      id,
      "bounded scenario conformance requires scenario_coverage selected",
    );
  }
  if (!nonEmptyStringArray(formal.covered_actions)) {
    fail(
      id,
      "bounded scenario conformance requires non-empty covered_actions",
    );
  }
  if (!nonEmptyStringArray(formal.covered_obligations)) {
    fail(
      id,
      "bounded scenario conformance requires non-empty covered_obligations",
    );
  } else {
    const obligations = new Set(
      Array.isArray(formal.obligations) ? formal.obligations : [],
    );
    if (
      formal.covered_obligations.some(
        (obligation: string) => !obligations.has(obligation),
      )
    ) {
      fail(id, "covered_obligations must be a subset of obligations");
    }
  }
  if (!statesNoRefinementProof(formal.scope)) {
    fail(
      id,
      "selected scenario conformance must state that it is not a refinement proof",
    );
  }

  const scenarioFile = resolveFile(id, formal.scenario_evidence);
  const scenarioRunnerFile = resolveFile(id, formal.scenario_runner);
  const conformanceFile = resolveFile(id, formal.conformance_evidence);
  if (!scenarioFile || !scenarioRunnerFile || !conformanceFile) return;
  if (
    formal.scenario_runner !==
    "scripts/check-formal-runtime-traces.mjs"
  ) {
    fail(id, "scenario_runner must name the canonical executed runner");
  }
  const scenarioSource = parseStrictJson(
    fs.readFileSync(scenarioFile, "utf8"),
    formal.scenario_evidence,
  );
  const conformanceSource = parseStrictJson(
    fs.readFileSync(conformanceFile, "utf8"),
    formal.conformance_evidence,
  );
  if (scenarioSource?.traces !== undefined) {
    fail(id, `${formal.scenario_evidence} must not contain legacy traces`);
    return;
  }
  try {
    validateTraceManifest(scenarioSource);
  } catch (error) {
    fail(
      id,
      `${formal.scenario_evidence} is invalid: ${(error as Error).message}`,
    );
    return;
  }
  let conformedRows: any[];
  try {
    conformedRows = validateScenarioEvidence(
      formal.conformance_evidence,
      scenarioSource,
      conformanceSource,
    );
  } catch (error) {
    fail(id, (error as Error).message);
    return;
  }
  const matching = scenarioRows(scenarioSource).filter(
    (scenario: any) =>
      scenario.claim_id === id && scenario.model === formal.model,
  );
  const conformed = conformedRows.filter(
    (scenario: any) =>
      scenario.claim_id === id &&
      scenario.model === formal.model &&
      scenario.matched === true,
  );
  if (
    matching.length < 2 ||
    !matching.some((scenario: any) => scenario.kind === "sound") ||
    !matching.some(
      (scenario: any) => scenario.kind === "paired_negative_control",
    )
  ) {
    fail(
      id,
      `${formal.scenario_evidence} requires one sound scenario and one paired negative control for ${id}`,
    );
  }
  if (
    conformed.length < 2 ||
    !conformed.some(
      (scenario: any) =>
        scenario.kind === "sound" && scenario.formal?.status === "matched",
    ) ||
    !conformed.some(
      (scenario: any) =>
        scenario.kind === "paired_negative_control" &&
        scenario.formal?.status === "counterexample_detected" &&
        scenario.runtime?.steps?.at(-1)?.accepted === false &&
        scenario.control_semantics ===
          "paired_formal_counterexample_runtime_refusal",
    )
  ) {
    fail(
      id,
      `${formal.conformance_evidence} requires one matched sound scenario and one paired negative control for ${id}`,
    );
  }
  const planned =
    scenarioConformancePlan.get(formal.model) ?? new Set<string>();
  planned.add(id);
  scenarioConformancePlan.set(formal.model, planned);
}

function planTest(
  id: string,
  executionSpec: any,
  suitePath: string | null = null,
): void {
  if (
    !executionSpec ||
    !["vitest", "node-test"].includes(executionSpec.runner)
  ) {
    fail(id, "execution must name runner vitest or node-test");
    return;
  }
  const testFile = resolveFile(id, executionSpec.file);
  if (!testFile) return;
  const source = fs.readFileSync(testFile, "utf8");
  if (!nonEmpty(executionSpec.title)) {
    fail(id, `${executionSpec.file} execution needs an exact title`);
    return;
  }
  if (!hasExactTestTitle(source, executionSpec.title)) {
    const suiteName = suitePath ? path.basename(suitePath) : "";
    const suiteDriven =
      suiteName && source.includes(suiteName) && source.includes("v.id");
    if (!suiteDriven)
      fail(
        id,
        `${executionSpec.file} has no exact or suite-driven test title: ${executionSpec.title}`,
      );
  } else if (!hasExecutableTestBody(source, executionSpec.title)) {
    fail(
      id,
      `${executionSpec.file} names ${executionSpec.title} but its body executes nothing`,
    );
  }
  const key = `${executionSpec.runner}\0${executionSpec.file}`;
  const planned = executionPlan.get(key) ?? {
    runner: executionSpec.runner,
    file: executionSpec.file,
    titles: new Set(),
  };
  planned.titles.add(executionSpec.title);
  executionPlan.set(key, planned);
}

function planCrossLanguage(
  id: string,
  suite: string,
  caseId: string,
  expect: any,
): void {
  const key: string = suite;
  const planned: Map<string, any> = crossLanguageCases.get(key) ?? new Map();
  planned.set(caseId, { id, expect });
  crossLanguageCases.set(key, planned);
}

function runChecked(
  command: string,
  commandArgs: string[],
  options: any,
  label: string,
): string {
  const run = spawnSync(command, commandArgs, {
    cwd: options.cwd ?? ROOT,
    encoding: "utf8",
    env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
    maxBuffer: 32 * 1024 * 1024,
    timeout: EXECUTION_TIMEOUT_MS,
  });
  if (run.status !== 0) {
    throw new Error(
      `${label} failed (${run.status}):\n${run.stdout || ""}${run.stderr || ""}`,
    );
  }
  return run.stdout as string;
}

// Running a whole test file and calling every planned title "passed" is not a
// binding: a renamed, removed, or never-registered evidence test leaves the file
// green. Both observers below run one file per process (so the runtime stays
// close to the previous whole-file execution) but return the machine-readable
// per-test outcome the runner actually reported, keyed by test title.
function observeVitestFile(file: string): Map<string, string> {
  const reportDirectory: string = fs.mkdtempSync(
    path.join(os.tmpdir(), "ep-security-case-"),
  );
  const reportFile: string = path.join(reportDirectory, "vitest.json");
  try {
    runChecked(
      "npm",
      [
        "exec",
        "vitest",
        "--",
        "run",
        file,
        "--reporter=json",
        "--outputFile",
        reportFile,
      ],
      {},
      `vitest ${file}`,
    );
    if (!fs.existsSync(reportFile))
      throw new Error(`vitest ${file} produced no machine-readable report`);
    let report: any;
    try {
      report = JSON.parse(fs.readFileSync(reportFile, "utf8"));
    } catch (error) {
      throw new Error(
        `vitest ${file} report is unreadable: ${(error as any).message}`,
      );
    }
    const observed: Map<string, string> = new Map();
    for (const suite of report.testResults ?? [])
      for (const assertion of suite.assertionResults ?? []) {
        if (nonEmpty(assertion.title))
          observed.set(assertion.title, assertion.status);
        if (nonEmpty(assertion.fullName))
          observed.set(assertion.fullName, assertion.status);
      }
    return observed;
  } finally {
    fs.rmSync(reportDirectory, { recursive: true, force: true });
  }
}

function observeNodeTestFile(file: string): Map<string, string> {
  const stdout: string = runChecked(
    process.execPath,
    [
      "--import",
      path.join(ROOT, "scripts", "ts-loader", "register.mjs"),
      "--test",
      "--test-reporter=tap",
      file,
    ],
    {},
    `node:test ${file}`,
  );
  const observed: Map<string, string> = new Map();
  for (const line of stdout.split("\n")) {
    const point = /^\s*(not )?ok\s+\d+\s+-\s+(.*)$/.exec(line);
    if (!point) continue;
    let name: string = point[2];
    let status: string = point[1] ? "failed" : "passed";
    const directive = /\s+#\s+(SKIP|TODO)\b.*$/i.exec(name);
    if (directive) {
      name = name.slice(0, directive.index);
      status = directive[1].toUpperCase() === "SKIP" ? "skipped" : "todo";
    }
    observed.set(name.trim().replace(/\\([\\#])/g, "$1"), status);
  }
  return observed;
}

function executePlannedTests(): void {
  for (const planned of [...executionPlan.values()].sort((a: any, b: any) =>
    a.file.localeCompare(b.file),
  )) {
    const observed: Map<string, string> =
      planned.runner === "vitest"
        ? observeVitestFile(planned.file)
        : observeNodeTestFile(planned.file);
    const titles: string[] = [...planned.titles].sort();
    const unexecuted: string[] = [];
    const notPassed: string[] = [];
    const skipped: string[] = [];
    for (const title of titles) {
      const status: string | undefined = observed.get(title);
      if (status === undefined) unexecuted.push(title);
      else if (status === "skipped" || status === "pending" || status === "todo")
        skipped.push(`${title} (${status})`);
      else if (status !== "passed") notPassed.push(`${title} (${status})`);
    }
    if (unexecuted.length)
      throw new Error(
        `${planned.runner} ${planned.file}: the run reported no test with these exact evidence titles, so the claim is unbound:\n  - ${unexecuted.join("\n  - ")}`,
      );
    if (notPassed.length)
      throw new Error(
        `${planned.runner} ${planned.file}: named evidence tests did not pass:\n  - ${notPassed.join("\n  - ")}`,
      );
    // Runner-level skips are environment gated (for example an absent Postgres
    // URL). They are reported so a reviewer can see which named evidence did
    // not execute in this environment.
    if (skipped.length)
      console.error(
        `SECURITY CASE: WARNING ${planned.runner} ${planned.file} skipped named evidence:\n  - ${skipped.join("\n  - ")}`,
      );
    executionEvidence.push({
      runner: planned.runner,
      file: planned.file,
      titles,
      result: "passed",
    });
  }
}

function executeCrossLanguage(): void {
  const implementations: any[] = [
    {
      language: "javascript",
      command: process.execPath,
      args: (suite: string) => ["conformance/runners/run-js.mjs", suite],
      cwd: ROOT,
    },
    {
      language: "python",
      command: "python3",
      args: (suite: string) => ["conformance/runners/run_py.py", suite],
      cwd: ROOT,
    },
    {
      language: "go",
      command: "go",
      args: (suite: string) => ["run", "./cmd/conformance", suite],
      cwd: path.join(ROOT, "packages", "go-verify"),
    },
  ];
  for (const [suite, cases] of [...crossLanguageCases.entries()].sort(
    ([a], [b]: [string, any]) => a.localeCompare(b),
  )) {
    const suiteAbsolute: string = path.resolve(ROOT, suite);
    const suiteFile: string = path.basename(suiteAbsolute);
    const suiteDocument: any = parseStrictJson(
      fs.readFileSync(suiteAbsolute, "utf8"),
      `invalid conformance suite ${suite}`,
    );
    const executionFile: string = executionSuiteFile(suiteFile);
    const executionAbsolute: string =
      executionFile === suiteFile
        ? suiteAbsolute
        : path.join(path.dirname(suiteAbsolute), executionFile);
    evidenceFiles.add(path.relative(ROOT, executionAbsolute));
    const executionDocument: any =
      executionFile === suiteFile
        ? suiteDocument
        : parseStrictJson(
            fs.readFileSync(executionAbsolute, "utf8"),
            `invalid conformance execution suite ${executionFile}`,
          );
    const contract: any = buildSuiteContract(
      suiteFile,
      suiteDocument,
      executionDocument,
    );
    const languages: string[] = [];
    for (const implementation of implementations) {
      const stdout: string = runChecked(
        implementation.command,
        implementation.args(executionAbsolute),
        { cwd: implementation.cwd },
        `${implementation.language} conformance ${suite}`,
      );
      const results: any = parseStrictJson(
        stdout,
        `${implementation.language} emitted invalid JSON for ${suite}`,
      );
      if (!Array.isArray(results))
        throw new Error(
          `${implementation.language} emitted a non-array result for ${suite}`,
        );
      const byId: any = validateResultRows(contract, results);
      for (const result of results) {
        const comparison: any = compareResultRow(contract, result);
        if (!comparison.ok) {
          throw new Error(
            `${implementation.language} emitted ${comparison.detail} for ${suite}#${result.id}`,
          );
        }
      }
      for (const [caseId, ref] of cases) {
        if (!byId.has(caseId))
          throw new Error(
            `${implementation.language} omitted ${suite}#${caseId}`,
          );
        const result = byId.get(caseId);
        if (
          typeof ref.expect.valid === "boolean" &&
          result.valid !== ref.expect.valid
        ) {
          throw new Error(
            `${implementation.language} returned ${result.valid} for ${suite}#${caseId}; expected ${ref.expect.valid}`,
          );
        }
      }
      languages.push(implementation.language);
    }
    executionEvidence.push({
      runner: "cross-language",
      suite,
      cases: [...cases.keys()].sort(),
      languages,
      result: "passed",
    });
  }
}

function executeBoundedFormal(): void {
  for (const planned of [...boundedFormalPlan.values()].sort((a: any, b: any) =>
    a.runner.localeCompare(b.runner),
  )) {
    const stdout: string = runChecked(
      process.execPath,
      [planned.runner, "--json"],
      {},
      `bounded formal checker ${planned.runner}`,
    );
    const result: any = parseStrictJson(
      stdout,
      `${planned.runner} emitted invalid JSON`,
    );
    if (
      result?.verified !== true ||
      result?.method !== "bounded_exhaustive_state_exploration"
    ) {
      throw new Error(
        `${planned.runner} did not report a verified bounded exploration`,
      );
    }
    for (const obligation of planned.obligations) {
      const row = result.obligations?.[obligation];
      if (
        row?.verified !== true ||
        row?.counterexample !== null ||
        row?.mutation_counterexample === null ||
        row?.mutation_counterexample === undefined
      ) {
        throw new Error(
          `${planned.runner} did not verify ${obligation} with a mutation counterexample`,
        );
      }
    }
    executionEvidence.push({
      runner: "bounded-formal",
      file: planned.runner,
      obligations: [...planned.obligations].sort(),
      result: "passed",
    });
  }
}

function executeScenarioConformance(): void {
  if (scenarioConformancePlan.size === 0) return;
  const stdout: string = runChecked(
    process.execPath,
    [
      "scripts/check-formal-runtime-traces.mjs",
      "--check",
      "--json",
    ],
    {},
    "bounded selected-scenario conformance",
  );
  const result: any = parseStrictJson(
    stdout,
    "selected-scenario conformance runner emitted invalid JSON",
  );
  const manifestPath = path.join(
    ROOT,
    "formal",
    "runtime-scenarios.v2.json",
  );
  const manifest: any = parseStrictJson(
    fs.readFileSync(manifestPath, "utf8"),
    "selected-scenario manifest",
  );
  validateTraceManifest(manifest);
  const executedScenarios = validateScenarioEvidence(
    "selected-scenario runner output",
    manifest,
    result,
  );
  const scenarioCount = result.summary.scenarios;
  if (
    scenarioCount < 2 ||
    result.summary.paired_negative_controls < 1
  ) {
    throw new Error(
      "scenario conformance runner did not report executed v2 sound and paired-negative scenarios",
    );
  }
  for (const [model, claims] of scenarioConformancePlan) {
    for (const claim of claims) {
      const matching = executedScenarios.filter(
        (scenario: any) =>
          scenario.claim_id === claim &&
          scenario.model === model &&
          scenario.matched === true,
      );
      if (
        matching.length < 2 ||
        !matching.some(
          (scenario: any) =>
            scenario.kind === "sound" &&
            scenario.formal?.status === "matched",
        ) ||
        !matching.some(
          (scenario: any) =>
            scenario.kind === "paired_negative_control" &&
            scenario.formal?.status === "counterexample_detected" &&
            scenario.runtime?.steps?.at(-1)?.accepted === false &&
            scenario.control_semantics ===
              "paired_formal_counterexample_runtime_refusal",
        )
      ) {
        throw new Error(
          `${claim}: selected-scenario conformance lacks a sound scenario and paired negative control`,
        );
      }
    }
  }
  executionEvidence.push({
    runner: "bounded-selected-scenario-conformance",
    file: "scripts/check-formal-runtime-traces.mjs",
    claims: [
      ...new Set(
        [...scenarioConformancePlan.values()].flatMap((claims) => [...claims]),
      ),
    ].sort(),
    scenarios: scenarioCount,
    paired_negative_controls:
      result.summary.paired_negative_controls,
    result: "passed",
  });
}

let sourceCase: any;
try {
  sourceCase = parseStrictJson(
    fs.readFileSync(SOURCE, "utf8"),
    "security case source",
  );
} catch (error) {
  console.error(
    `SECURITY CASE: cannot parse ${SOURCE}: ${(error as any).message}`,
  );
  process.exit(2);
}

if (sourceCase["@version"] !== "EP-SECURITY-CASE-SOURCE-v2")
  fail("source", "unexpected @version");
if (!Array.isArray(sourceCase.claims) || sourceCase.claims.length === 0)
  fail("source", "claims must be non-empty");
if (
  !sourceCase.release_artifacts ||
  typeof sourceCase.release_artifacts !== "object"
)
  fail("source", "release_artifacts must be an object");

const seenClaims: Set<string> = new Set();
for (const claim of sourceCase.claims ?? []) {
  const id: string = claim?.claim_id ?? "(missing claim_id)";
  if (!nonEmpty(claim?.claim_id)) fail(id, "claim_id is required");
  if (seenClaims.has(id)) fail(id, "duplicate claim_id");
  seenClaims.add(id);
  if (!nonEmpty(claim?.statement)) fail(id, "statement is required");
  if (
    !Array.isArray(claim?.acceptance_roots) ||
    claim.acceptance_roots.length === 0 ||
    claim.acceptance_roots.some((v) => !nonEmpty(v))
  )
    fail(id, "acceptance_roots must contain non-empty strings");
  if (
    !Array.isArray(claim?.assumptions) ||
    claim.assumptions.length === 0 ||
    claim.assumptions.some((v) => !nonEmpty(v))
  )
    fail(id, "assumptions must be explicit non-empty strings");
  if (
    !Array.isArray(claim?.exclusions) ||
    claim.exclusions.length === 0 ||
    claim.exclusions.some((v) => !nonEmpty(v))
  )
    fail(id, "exclusions must be explicit non-empty strings");

  if (
    !Array.isArray(claim?.enforcement_path) ||
    claim.enforcement_path.length === 0
  )
    fail(id, "enforcement_path must name at least one exact code symbol");
  for (const step of claim.enforcement_path ?? []) {
    const stepFile = resolveFile(id, step.file);
    if (
      !stepFile ||
      !nonEmpty(step.symbol) ||
      !["javascript", "python", "go"].includes(step.language)
    ) {
      fail(id, "every enforcement_path step needs language, file, and symbol");
      continue;
    }
    if (
      !hasNamedDeclaration(
        fs.readFileSync(stepFile, "utf8"),
        step.language,
        step.symbol,
      )
    ) {
      fail(
        id,
        `${step.file} has no exact ${step.language} declaration ${step.symbol}`,
      );
    }
  }

  if (
    !Array.isArray(claim?.implementations) ||
    claim.implementations.length === 0
  )
    fail(id, "at least one implementation is required");
  for (const implementation of claim.implementations ?? []) {
    const implementationFile = resolveFile(id, implementation.file);
    if (!implementationFile) continue;
    if (implementation.language === "javascript") {
      if (!nonEmpty(implementation.export)) {
        fail(
          id,
          `javascript implementation ${implementation.file} needs export`,
        );
        continue;
      }
      try {
        const module: any = await import(
          `${pathToFileURL(implementationFile).href}?security-case=${encodeURIComponent(id)}`
        );
        if (typeof module[implementation.export] !== "function")
          fail(
            id,
            `${implementation.file} has no callable named export ${implementation.export}`,
          );
      } catch (error) {
        fail(
          id,
          `cannot import ${implementation.file}: ${(error as any).message}`,
        );
      }
    } else if (
      implementation.language === "python" ||
      implementation.language === "go"
    ) {
      if (
        !nonEmpty(implementation.symbol) ||
        !hasNamedDeclaration(
          fs.readFileSync(implementationFile, "utf8"),
          implementation.language,
          implementation.symbol,
        )
      ) {
        fail(
          id,
          `${implementation.file} has no exact ${implementation.language} declaration ${implementation.symbol}`,
        );
      }
    } else {
      fail(id, `unknown implementation language: ${implementation.language}`);
    }
  }

  const coverage: any = claim.language_coverage;
  for (const language of ["javascript", "python", "go"]) {
    const entry: any = coverage?.[language];
    if (
      !entry ||
      !["covered", "gap", "not_applicable"].includes(entry.status)
    ) {
      fail(
        id,
        `language_coverage.${language} must explicitly be covered, gap, or not_applicable`,
      );
    } else if (entry.status === "covered") {
      resolveFile(id, entry.evidence);
    } else if (!nonEmpty(entry.reason)) {
      fail(
        id,
        `language_coverage.${language}.${entry.status} requires a reason`,
      );
    }
  }

  if (!Array.isArray(claim?.vectors) || claim.vectors.length < 2)
    fail(id, "at least one positive and one negative vector are required");
  const polarities: Set<string> = new Set();
  for (const vectorRef of claim.vectors ?? []) {
    polarities.add(vectorRef.polarity);
    if (!["positive", "negative"].includes(vectorRef.polarity))
      fail(id, "vector polarity must be positive or negative");
    if (vectorRef.polarity === "positive" && vectorRef.expect?.valid !== true)
      fail(id, `${vectorRef.case_id} positive vector must expect valid:true`);
    if (vectorRef.polarity === "negative" && vectorRef.expect?.valid !== false)
      fail(id, `${vectorRef.case_id} negative vector must expect valid:false`);
    const suiteFile = resolveFile(id, vectorRef.suite);
    if (!suiteFile) continue;
    let suite;
    try {
      suite = parseStrictJson(
        fs.readFileSync(suiteFile, "utf8"),
        `vector suite ${vectorRef.suite}`,
      );
    } catch (error) {
      fail(
        id,
        `cannot parse vector suite ${vectorRef.suite}: ${error.message}`,
      );
      continue;
    }
    const matching = (suite.vectors ?? []).filter(
      (vector) => vector?.id === vectorRef.case_id,
    );
    if (matching.length !== 1) {
      fail(
        id,
        `${vectorRef.suite} must contain exactly one vector id ${vectorRef.case_id}; found ${matching.length}`,
      );
      continue;
    }
    if (!deepSubset(matching[0].expect, vectorRef.expect)) {
      fail(
        id,
        `${vectorRef.suite}#${vectorRef.case_id} expectation does not match ${JSON.stringify(vectorRef.expect)}`,
      );
    }
    const executionSpec = vectorRef.execution ?? matching[0].execution;
    if (executionSpec?.runner === "cross-language") {
      planCrossLanguage(
        id,
        vectorRef.suite,
        vectorRef.case_id,
        vectorRef.expect,
      );
    } else {
      planTest(id, executionSpec, vectorRef.suite);
    }
  }
  if (!polarities.has("positive") || !polarities.has("negative"))
    fail(id, "vectors must contain both positive and negative polarity");

  if (!Array.isArray(claim?.tests) || claim.tests.length === 0)
    fail(id, "at least one exact test is required");
  for (const testRef of claim.tests ?? []) {
    const testFile = resolveFile(id, testRef.file);
    if (!testFile) continue;
    if (
      !nonEmpty(testRef.title) ||
      !hasExactTestTitle(fs.readFileSync(testFile, "utf8"), testRef.title)
    ) {
      fail(id, `${testRef.file} has no exact test title: ${testRef.title}`);
    }
    planTest(id, {
      runner: testRef.runner,
      file: testRef.file,
      title: testRef.title,
    });
  }

  if (
    claim.operational_evidence !== undefined &&
    !Array.isArray(claim.operational_evidence)
  )
    fail(id, "operational_evidence must be an array when present");
  for (const artifact of claim.operational_evidence ?? []) {
    const artifactFile = resolveFile(id, artifact.file);
    if (!artifactFile) continue;
    const source = fs.readFileSync(artifactFile, "utf8");
    if (
      !Array.isArray(artifact.contains) ||
      artifact.contains.length === 0 ||
      artifact.contains.some((value) => !nonEmpty(value))
    ) {
      fail(
        id,
        `${artifact.file} operational evidence needs exact non-empty contains strings`,
      );
      continue;
    }
    for (const exact of artifact.contains)
      if (!source.includes(exact))
        fail(
          id,
          `${artifact.file} does not contain exact operational evidence: ${exact}`,
        );
  }

  if (!Array.isArray(claim?.formal) || claim.formal.length === 0)
    fail(id, "formal status must be explicit");
  for (const formal of claim.formal ?? []) {
    if (formal.status === "not_modeled") {
      if (!nonEmpty(formal.gap))
        fail(id, "not_modeled formal evidence requires a gap statement");
      continue;
    }
    if (!["verified", "partial"].includes(formal.status)) {
      fail(id, `unknown formal status: ${formal.status}`);
      continue;
    }
    if (!FORMAL_METHODS.has(formal.method)) {
      fail(
        id,
        `formal method must be one of ${[...FORMAL_METHODS].join(", ")}`,
      );
      continue;
    }
    if (
      formal.method === "symbolic_protocol_analysis" &&
      [...LEGACY_RUNTIME_EVIDENCE_FIELDS, ...SCENARIO_CONFORMANCE_FIELDS].some(
        (field) => formal[field] !== undefined,
      )
    ) {
      fail(
        id,
        "runtime scenario conformance metadata is only valid for bounded formal methods",
      );
    }
    if (
      formal.method === "symbolic_protocol_analysis" &&
      formal.status === "partial"
    ) {
      if (!nonEmpty(formal.covered_statement)) {
        fail(
          id,
          "partial symbolic protocol analysis requires a non-empty covered_statement",
        );
      }
      if (!nonEmpty(formal.unmodeled_statement)) {
        fail(
          id,
          "partial symbolic protocol analysis requires a non-empty unmodeled_statement",
        );
      }
    }
    const modelFile = resolveFile(id, formal.model);
    const runnerFile = resolveFile(id, formal.runner);
    const resultFile = resolveFile(id, formal.result_evidence);
    if (!modelFile || !runnerFile || !resultFile) continue;
    const modelSource = fs.readFileSync(modelFile, "utf8");
    const runnerSource = fs.readFileSync(runnerFile, "utf8");
    const resultSource = fs.readFileSync(resultFile, "utf8");
    const modelSha256 = crypto
      .createHash("sha256")
      .update(fs.readFileSync(modelFile))
      .digest("hex");
    const runnerSha256 = crypto
      .createHash("sha256")
      .update(fs.readFileSync(runnerFile))
      .digest("hex");
    if (!resultSource.includes(`Model SHA-256: ${modelSha256}`))
      fail(
        id,
        `${formal.result_evidence} is not bound to the current ${formal.model} bytes`,
      );
    if (!resultSource.includes(`Runner SHA-256: ${runnerSha256}`))
      fail(
        id,
        `${formal.result_evidence} is not bound to the current ${formal.runner} bytes`,
      );
    if (formal.method === "bounded_exhaustive_state_exploration") {
      if (formal.status !== "partial") {
        fail(
          id,
          "bounded exhaustive formal evidence must remain status partial",
        );
      }
      if (
        !Array.isArray(formal.obligations) ||
        formal.obligations.length === 0 ||
        formal.obligations.some((obligation) => !nonEmpty(obligation)) ||
        new Set(formal.obligations).size !== formal.obligations.length
      ) {
        fail(
          id,
          "bounded exhaustive formal evidence requires unique named obligations",
        );
      }
      for (const obligation of formal.obligations ?? []) {
        if (
          !modelSource.includes(`'${obligation}'`) &&
          !modelSource.includes(`"${obligation}"`)
        ) {
          fail(
            id,
            `${formal.model} does not declare exact obligation ${obligation}`,
          );
        }
        if (!runnerSource.includes(`${obligation}:`)) {
          fail(
            id,
            `${formal.runner} does not execute exact obligation ${obligation}`,
          );
        }
        if (!hasBoundedFormalResult(resultSource, obligation)) {
          fail(
            id,
            `${formal.result_evidence} has no verified bounded result for ${obligation}`,
          );
        }
      }
      if (
        !nonEmpty(formal.scope) ||
        !formal.scope.toLowerCase().includes("bounded") ||
        !formal.scope.toLowerCase().includes("same-team")
      ) {
        fail(
          id,
          "bounded exhaustive formal evidence requires explicit bounded and same-team scope",
        );
      }
      const key = path.relative(ROOT, runnerFile);
      const planned = boundedFormalPlan.get(key) ?? {
        runner: key,
        obligations: new Set(),
      };
      for (const obligation of formal.obligations ?? []) {
        planned.obligations.add(obligation);
      }
      boundedFormalPlan.set(key, planned);
      validateBoundedScenarioConformance(id, formal);
      continue;
    }
    if (formal.method === "bounded_tla_model_checking") {
      if (formal.status !== "partial") {
        fail(
          id,
          "bounded TLA+ formal evidence must remain status partial without an implementation refinement proof",
        );
      }
      if (
        !Array.isArray(formal.obligations) ||
        formal.obligations.length === 0 ||
        formal.obligations.some((obligation) => !nonEmpty(obligation)) ||
        new Set(formal.obligations).size !== formal.obligations.length
      ) {
        fail(
          id,
          "bounded TLA+ formal evidence requires unique named obligations",
        );
      }
      for (const obligation of formal.obligations ?? []) {
        if (!hasTlaDeclaration(modelSource, obligation)) {
          fail(
            id,
            `${formal.model} does not declare exact TLA+ obligation ${obligation}`,
          );
        }
        if (!hasTlaConfiguredObligation(runnerSource, obligation)) {
          fail(
            id,
            `${formal.runner} does not configure exact TLA+ obligation ${obligation}`,
          );
        }
        if (!hasBoundedFormalResult(resultSource, obligation)) {
          fail(
            id,
            `${formal.result_evidence} has no verified bounded result for ${obligation}`,
          );
        }
      }
      if (
        !resultSource.includes(
          "Result: Model checking completed. No error has been found.",
        )
      ) {
        fail(
          id,
          `${formal.result_evidence} has no clean TLC completion result`,
        );
      }
      if (
        !nonEmpty(formal.scope) ||
        !formal.scope.toLowerCase().includes("bounded") ||
        !formal.scope.toLowerCase().includes("same-team") ||
        !statesNoRefinementProof(formal.scope)
      ) {
        fail(
          id,
          "bounded TLA+ evidence requires explicit bounded, same-team, and no-refinement scope",
        );
      }
      validateBoundedScenarioConformance(id, formal);
      continue;
    }
    if (!nonEmpty(formal.lemma) || !hasFormalLemma(modelSource, formal.lemma))
      fail(id, `${formal.model} has no exact lemma ${formal.lemma}`);
    if (!runnerSource.includes(formal.lemma))
      fail(id, `${formal.runner} does not execute exact lemma ${formal.lemma}`);
    if (!hasVerifiedResult(resultSource, formal.lemma))
      fail(
        id,
        `${formal.result_evidence} has no verified result for ${formal.lemma}`,
      );
    if (!nonEmpty(formal.scope))
      fail(id, `${formal.lemma} requires an explicit scope boundary`);
  }

  if (
    !Array.isArray(claim.release_artifacts) ||
    claim.release_artifacts.length === 0
  )
    fail(id, "claim must bind at least one release artifact");
  for (const artifactId of claim.release_artifacts ?? []) {
    if (!sourceCase.release_artifacts?.[artifactId])
      fail(id, `unknown release artifact ${artifactId}`);
  }
}

if (errors.length) {
  console.error(
    `SECURITY CASE: FAIL (${errors.length} problem${errors.length === 1 ? "" : "s"})`,
  );
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

if (validateOnly) {
  console.log(
    `SECURITY CASE: METADATA OK (${sourceCase.claims.length} claims validated)`,
  );
  process.exit(0);
}

if (execute) {
  try {
    executeBoundedFormal();
    executeScenarioConformance();
    executeCrossLanguage();
    executePlannedTests();
  } catch (error) {
    console.error(`SECURITY CASE: EXECUTION FAIL\n${(error as any).message}`);
    process.exit(1);
  }
}

const fileHashes: Array<{ path: string; sha256: string }> = [...evidenceFiles]
  .sort()
  .map((relative: string) => {
    const bytes: Buffer = fs.readFileSync(path.join(ROOT, relative));
    return {
      path: relative,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    };
  });
const evidenceBundleSha256: string = crypto
  .createHash("sha256")
  .update(
    fileHashes
      .map(
        ({ path: relative, sha256 }: { path: string; sha256: string }) =>
          `${relative}\0${sha256}\n`,
      )
      .join(""),
  )
  .digest("hex");

const releaseArtifacts: Record<string, any> = {};
for (const [artifactId, definition] of Object.entries(
  sourceCase.release_artifacts ?? {},
).sort(([a], [b]: [string, any]) => a.localeCompare(b))) {
  const def = definition as any;
  if (def.kind === "npm") {
    const artifact: any = verifyReproduciblePackage(def.path);
    releaseArtifacts[artifactId] = {
      kind: "npm-tarball",
      package: artifact.name,
      version: artifact.version,
      filename: artifact.filename,
      sha256: artifact.sha256,
      file_count: artifact.fileCount,
    };
  } else if (def.kind === "content-addressed-evidence-bundle") {
    releaseArtifacts[artifactId] = {
      kind: def.kind,
      filename: "security-case-evidence.v1",
      sha256: evidenceBundleSha256,
      file_count: fileHashes.length,
    };
  } else {
    throw new Error(`unsupported release artifact kind: ${def.kind}`);
  }
}

const resolvedClaims: any[] = sourceCase.claims.map((claim: any) => ({
  ...claim,
  release_artifact_hashes: claim.release_artifacts.map(
    (artifactId: string) => ({
      artifact_id: artifactId,
      sha256: releaseArtifacts[artifactId].sha256,
    }),
  ),
}));
const resolved: any = {
  "@version": "EP-SECURITY-CASE-RESOLVED-v2",
  source: "security/claims.v1.json",
  evidence_bundle_sha256: evidenceBundleSha256,
  claim_count: resolvedClaims.length,
  evidence_file_count: fileHashes.length,
  execution: {
    required: true,
    status: execute ? "passed" : "not_executed",
    evidence: execute
      ? executionEvidence.sort((a, b) =>
          JSON.stringify(a).localeCompare(JSON.stringify(b)),
        )
      : [],
  },
  attestation_policy:
    "GitHub artifact attestation over this exact JSON is required on protected-branch and release runs.",
  release_artifacts: releaseArtifacts,
  claims: resolvedClaims,
  evidence_files: fileHashes,
};
const serialized: string = `${JSON.stringify(resolved, null, 2)}\n`;

if (emitPath) {
  const target: string = path.resolve(ROOT, emitPath);
  if (target !== ROOT && !target.startsWith(`${ROOT}${path.sep}`))
    throw new Error(`emit path escapes repository: ${emitPath}`);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, serialized);
} else if (fs.existsSync(DEFAULT_RESOLVED)) {
  const checkedIn: string = fs.readFileSync(DEFAULT_RESOLVED, "utf8");
  if (checkedIn !== serialized) {
    console.error(
      "SECURITY CASE: FAIL (security/security-case.json is stale; run npm run security-case:emit)",
    );
    process.exit(1);
  }
}

const artifactSummary: string = Object.entries(releaseArtifacts)
  .map(([id, artifact]: [string, any]) => `${id}=sha256:${artifact.sha256}`)
  .join(", ");
console.log(
  `SECURITY CASE: OK (${resolved.claim_count} executable claims, ${resolved.evidence_file_count} hashed evidence files, execution=${resolved.execution.status})`,
);
console.log(`RELEASE BINDINGS: ${artifactSummary}`);
