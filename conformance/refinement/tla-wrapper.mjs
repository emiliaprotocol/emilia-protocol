// SPDX-License-Identifier: Apache-2.0
// Generated from tla-wrapper.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync, } from "node:fs";
import os from "node:os";
import path from "node:path";
function tlaScalar(value) {
    if (typeof value === "boolean")
        return value ? "TRUE" : "FALSE";
    if (typeof value === "number")
        return String(value);
    return JSON.stringify(value);
}
function traceModuleName(traceId) {
    return `Trace_${traceId.replace(/[^A-Za-z0-9_]/gu, "_")}`;
}
function sourceModuleName(modelPath) {
    return path.basename(modelPath, ".tla");
}
function configPreamble(configSource) {
    const lines = configSource.split(/\r?\n/u);
    const firstDirective = lines.findIndex((line) => /^\s*(?:SPECIFICATION|INIT|NEXT|INVARIANT|PROPERTY|CHECK_DEADLOCK)\b/u.test(line));
    return (firstDirective < 0 ? lines : lines.slice(0, firstDirective))
        .join("\n")
        .trim();
}
function projectionClauses(trace, model) {
    const clauses = [];
    const offset = trace.formal_prefix.length;
    for (const [index, step] of trace.steps.entries()) {
        if (trace.kind === "unsafe_mutation" && index === trace.steps.length - 1)
            continue;
        const expected = Object.entries(step.projection)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([projection, value]) => `(${model.projections[projection]}) = ${tlaScalar(value)}`);
        clauses.push(`  /\\ tracePc = ${offset + index + 1} => (${expected.join(" /\\ ")})`);
    }
    return clauses;
}
function mutationDefinition(trace, model) {
    if (!trace.mutation)
        return "";
    if (trace.mutation.defined_in_model)
        return "";
    const assignments = trace.mutation.assignments ?? {};
    const assigned = new Set(Object.keys(assignments));
    const changes = Object.entries(assignments)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([variable, value]) => `  /\\ ${variable}' = ${tlaScalar(value)}`);
    const unchanged = model.variables.filter((variable) => !assigned.has(variable));
    if (unchanged.length > 0) {
        changes.push(`  /\\ UNCHANGED <<${unchanged.join(", ")}>>`);
    }
    return [
        `${trace.mutation.operator} ==`,
        `  /\\ ${trace.mutation.precondition}`,
        ...changes,
        "",
    ].join("\n");
}
function buildModule(trace, model) {
    const moduleName = traceModuleName(trace.id);
    const baseName = sourceModuleName(trace.model);
    const formalActions = [
        ...trace.formal_prefix.map((action) => model.actions[action] ?? action),
        ...trace.steps.map((step, index) => trace.kind === "unsafe_mutation" && index === trace.steps.length - 1
            ? trace.mutation.operator
            : (model.actions[step.operator] ?? step.operator)),
    ];
    const stepDefinitions = formalActions.map((action, index) => {
        return [
            `TraceStep${index + 1} ==`,
            `  /\\ tracePc = ${index}`,
            `  /\\ ${action}`,
            `  /\\ tracePc' = ${index + 1}`,
            "",
        ].join("\n");
    });
    const projection = projectionClauses(trace, model);
    return [
        `-------------------- MODULE ${moduleName} --------------------`,
        `EXTENDS ${baseName}`,
        "",
        "VARIABLE tracePc",
        "traceVars == <<vars, tracePc>>",
        "",
        mutationDefinition(trace, model),
        "TraceInit ==",
        "  /\\ Init",
        "  /\\ tracePc = 0",
        "",
        ...stepDefinitions,
        "TraceNext ==",
        ...formalActions.map((_, index) => `  \\/ TraceStep${index + 1}`),
        `  \\/ /\\ tracePc = ${formalActions.length}`,
        "     /\\ UNCHANGED vars",
        "     /\\ tracePc' = tracePc",
        "",
        "TraceProjection ==",
        ...(projection.length > 0 ? projection : ["  TRUE"]),
        "",
        "TraceSpec ==",
        "  /\\ TraceInit",
        "  /\\ [][TraceNext]_traceVars",
        "  /\\ WF_traceVars(TraceNext)",
        "",
        `TraceCompletes == <> (tracePc = ${formalActions.length})`,
        "",
        "=============================================================",
        "",
    ].join("\n");
}
function buildConfig(trace, sourceConfig) {
    const directives = [
        configPreamble(sourceConfig),
        "SPECIFICATION TraceSpec",
        "CHECK_DEADLOCK FALSE",
        ...(trace.kind === "sound" ? ["INVARIANT TraceProjection"] : []),
        ...trace.obligations.map((obligation) => `INVARIANT ${obligation}`),
        "PROPERTY TraceCompletes",
    ].filter(Boolean);
    return `${directives.join("\n\n")}\n`;
}
export function runFormalTrace(root, trace, model, tlcJar) {
    const temp = mkdtempSync(path.join(os.tmpdir(), "ep-refinement-"));
    try {
        const moduleName = traceModuleName(trace.id);
        const baseName = sourceModuleName(trace.model);
        const moduleFile = path.join(temp, `${moduleName}.tla`);
        const configFile = path.join(temp, `${moduleName}.cfg`);
        copyFileSync(path.join(root, trace.model), path.join(temp, `${baseName}.tla`));
        writeFileSync(moduleFile, buildModule(trace, model), "utf8");
        writeFileSync(configFile, buildConfig(trace, readFileSync(path.join(root, model.config), "utf8")), "utf8");
        const run = spawnSync("java", [
            "-Xmx2G",
            "-jar",
            tlcJar,
            "-workers",
            "1",
            "-config",
            `${moduleName}.cfg`,
            `${moduleName}.tla`,
        ], {
            cwd: temp,
            encoding: "utf8",
            env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
            maxBuffer: 32 * 1024 * 1024,
            timeout: 300_000,
        });
        const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
        if (trace.kind === "sound") {
            if (run.status !== 0 ||
                !output.includes("Model checking completed. No error has been found.")) {
                throw new Error(`${trace.id}: forced formal trace failed\n${output}`);
            }
            return { status: "matched", obligation: null };
        }
        const obligation = trace.mutation?.obligation ?? "";
        const detected = output.includes(`Invariant ${obligation} is violated.`) ||
            output.includes(`Invariant ${obligation} is violated`);
        if (!detected) {
            throw new Error(`${trace.id}: unsafe mutation did not falsify ${obligation}\n${output}`);
        }
        return { status: "counterexample_detected", obligation };
    }
    finally {
        rmSync(temp, { recursive: true, force: true });
    }
}
