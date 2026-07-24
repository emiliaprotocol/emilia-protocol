#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from harness.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from "node:crypto";
import { existsSync, readFileSync, realpathSync, writeFileSync, } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { getRuntimeAdapter } from "./adapters/index.mjs";
import { canonicalProjection, validateTraceManifest, } from "./schema.mjs";
import { runFormalTrace } from "./tla-wrapper.mjs";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const manifestPath = path.join(root, "formal", "runtime-traces.v1.json");
const evidencePath = path.join(root, "formal", "results", "formal-runtime-refinement.v1.json");
const executableEntryPoints = Object.freeze([
    "scripts/check-formal-runtime-traces.mjs",
]);
const generatedRuntimeGovernance = Object.freeze([
    "package.json",
    "package-lock.json",
    "scripts/build-standalone-runtimes.mjs",
    "scripts/standalone-runtime-targets.mjs",
]);
const harnessSources = Object.freeze([
    "conformance/refinement/types.mts",
    "conformance/refinement/schema.mts",
    "conformance/refinement/tla-wrapper.mts",
    "conformance/refinement/harness.mts",
    "conformance/refinement/adapters/index.mts",
]);
const adapterSources = Object.freeze({
    "action-escrow": "conformance/refinement/adapters/action-escrow.mts",
    aec: "conformance/refinement/adapters/aec.mts",
    "consequence-lifecycle": "conformance/refinement/adapters/consequence-lifecycle.mts",
    "composed-trust-lifecycle": "conformance/refinement/adapters/composed-trust-lifecycle.mts",
    grace: "conformance/refinement/adapters/grace-curtailment.mts",
    "mobile-continuity": "conformance/refinement/adapters/mobile-continuity.mts",
    "mobile-enrollment": "conformance/refinement/adapters/mobile-enrollment.mts",
    "model-to-matter": "conformance/refinement/adapters/model-to-matter.mts",
    "network-witness": "conformance/refinement/adapters/network-witness.mts",
    revocation: "conformance/refinement/adapters/revocation.mts",
});
function parseJson(file) {
    return JSON.parse(readFileSync(file, "utf8"));
}
function sha256(file) {
    return crypto.createHash("sha256").update(readFileSync(file)).digest("hex");
}
function canonicalize(value) {
    if (Array.isArray(value))
        return value.map(canonicalize);
    if (value !== null && typeof value === "object") {
        return Object.fromEntries(Object.entries(value)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([key, child]) => [key, canonicalize(child)]));
    }
    return value;
}
function canonicalJson(value) {
    return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}
function containedFile(relative) {
    const absolute = path.resolve(root, relative);
    if (absolute !== root && !absolute.startsWith(`${root}${path.sep}`)) {
        throw new Error(`refinement evidence path escapes repository: ${relative}`);
    }
    if (!existsSync(absolute))
        throw new Error(`refinement evidence file missing: ${relative}`);
    return absolute;
}
function sourceForCompanion(relative) {
    const candidate = relative.endsWith(".mjs")
        ? relative.slice(0, -4) + ".mts"
        : relative.endsWith(".js")
            ? relative.slice(0, -3) + ".ts"
            : null;
    return candidate && existsSync(path.join(root, candidate)) ? candidate : null;
}
function executableImports(relative) {
    const source = readFileSync(containedFile(relative), "utf8");
    const imports = new Set();
    const pattern = /(?:import\s+(?:[^'"]*?\s+from\s+)?|export\s+[^'"]*?\s+from\s+|import\s*\()\s*['"]([^'"]+)['"]/gu;
    for (const match of source.matchAll(pattern))
        imports.add(match[1]);
    return [...imports];
}
function resolveRepositoryImport(importer, specifier) {
    if (specifier.startsWith("node:") ||
        (!specifier.startsWith(".") &&
            !specifier.startsWith("@emilia-protocol/"))) {
        return null;
    }
    const importerAbsolute = containedFile(importer);
    let resolved;
    try {
        resolved = specifier.startsWith(".")
            ? path.resolve(path.dirname(importerAbsolute), specifier)
            : fileURLToPath(import.meta.resolve(specifier, pathToFileURL(importerAbsolute).href));
        resolved = realpathSync(resolved);
    }
    catch (error) {
        throw new Error(`${importer}: cannot resolve governed runtime import ${specifier}: ${error.message}`);
    }
    if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
        throw new Error(`${importer}: governed runtime import resolves outside repository: ${specifier}`);
    }
    return path.relative(root, resolved);
}
function executableImportClosure(entries) {
    const closure = new Set();
    const pending = [...entries];
    while (pending.length > 0) {
        const relative = pending.pop();
        if (closure.has(relative))
            continue;
        containedFile(relative);
        closure.add(relative);
        const source = sourceForCompanion(relative);
        if (source)
            closure.add(source);
        if (!relative.endsWith(".js") && !relative.endsWith(".mjs"))
            continue;
        for (const specifier of executableImports(relative)) {
            const imported = resolveRepositoryImport(relative, specifier);
            if (imported && !closure.has(imported))
                pending.push(imported);
        }
    }
    return closure;
}
function normalizedSteps(steps) {
    return steps.map((step) => ({
        operator: step.operator,
        accepted: step.accepted,
        projection: canonicalProjection(step.projection),
    }));
}
function assertRuntimeMatches(trace, runtime) {
    if (runtime.scenario !== trace.scenario) {
        throw new Error(`${trace.id}: adapter returned scenario ${runtime.scenario}; expected ${trace.scenario}`);
    }
    const actual = normalizedSteps(runtime.steps);
    const expected = normalizedSteps(trace.steps);
    if (canonicalJson(actual) !== canonicalJson(expected)) {
        throw new Error(`${trace.id}: runtime projection does not match the governed formal projection` +
            `\nexpected ${canonicalJson(expected)}actual ${canonicalJson(actual)}`);
    }
    if (trace.kind === "unsafe_mutation" &&
        actual[actual.length - 1]?.accepted !== false) {
        throw new Error(`${trace.id}: runtime accepted the unsafe mutation`);
    }
    return actual;
}
function collectInputs(manifest) {
    const files = new Set([
        "formal/runtime-traces.v1.json",
        ...harnessSources,
        ...generatedRuntimeGovernance,
        ...executableImportClosure(executableEntryPoints),
    ]);
    for (const [model, contract] of Object.entries(manifest.models)) {
        files.add(model);
        files.add(contract.config);
    }
    for (const trace of manifest.traces) {
        const adapterSource = adapterSources[trace.adapter];
        if (!adapterSource)
            throw new Error(`no governed source for adapter ${trace.adapter}`);
        files.add(adapterSource);
        trace.runtime_sources.forEach((file) => files.add(file));
    }
    return [...files].sort().map((relative) => ({
        path: relative,
        sha256: sha256(containedFile(relative)),
    }));
}
async function runRuntimeTraces(manifest) {
    const results = [];
    for (const trace of [...manifest.traces].sort((left, right) => left.id.localeCompare(right.id))) {
        const runtime = await getRuntimeAdapter(trace.adapter)(trace.scenario);
        results.push({
            id: trace.id,
            claim_id: trace.claim_id,
            kind: trace.kind,
            steps: assertRuntimeMatches(trace, runtime),
        });
    }
    return {
        traces: results.length,
        sound_traces: results.filter((trace) => trace.kind === "sound").length,
        unsafe_mutations_rejected: results.filter((trace) => trace.kind === "unsafe_mutation" &&
            trace.steps.at(-1)?.accepted === false).length,
        claims: [...new Set(results.map((trace) => trace.claim_id))].sort(),
        results,
    };
}
export async function runRuntimeTraceConformance() {
    return runRuntimeTraces(validateTraceManifest(parseJson(manifestPath)));
}
async function buildEvidence(manifest, tlcJar) {
    const runtime = await runRuntimeTraces(manifest);
    const runtimeById = new Map(runtime.results.map((trace) => [trace.id, trace]));
    const traces = [];
    for (const trace of [...manifest.traces].sort((left, right) => left.id.localeCompare(right.id))) {
        const steps = runtimeById.get(trace.id)?.steps;
        if (!steps)
            throw new Error(`${trace.id}: runtime trace result is missing`);
        const formal = runFormalTrace(root, trace, manifest.models[trace.model], tlcJar);
        traces.push({
            id: trace.id,
            claim_id: trace.claim_id,
            kind: trace.kind,
            model: trace.model,
            adapter: trace.adapter,
            scenario: trace.scenario,
            formal,
            runtime: { status: "matched", steps },
            matched: true,
        });
    }
    const transitionCompleteModels = Object.entries(manifest.models)
        .filter(([, model]) => model.required_actions.length > 0)
        .map(([model]) => model)
        .sort();
    const requiredTransitions = transitionCompleteModels.reduce((total, model) => total + manifest.models[model].required_actions.length, 0);
    return {
        "@version": "EP-FORMAL-RUNTIME-REFINEMENT-EVIDENCE-v1",
        method: "bounded_selected_trace_refinement",
        inputs: collectInputs(manifest),
        traces,
        summary: {
            traces: traces.length,
            sound_traces: traces.filter((trace) => trace.kind === "sound").length,
            unsafe_mutations_detected: traces.filter((trace) => trace.kind === "unsafe_mutation" &&
                trace.formal.status === "counterexample_detected" &&
                trace.runtime.steps.at(-1)?.accepted === false).length,
            claims: [...new Set(traces.map((trace) => trace.claim_id))].sort(),
            models: [...new Set(traces.map((trace) => trace.model))].sort(),
            required_transitions: requiredTransitions,
            covered_transitions: requiredTransitions,
            transition_complete_models: transitionCompleteModels,
        },
        limitations: manifest.limitations,
    };
}
export async function runFormalRuntimeRefinement(options = {}) {
    const manifest = validateTraceManifest(parseJson(manifestPath));
    const prior = existsSync(evidencePath)
        ? parseJson(evidencePath)
        : null;
    if (!options.tlcJar) {
        throw new Error("formal runtime refinement requires --tlc-jar or TLA2TOOLS_JAR; committed verdicts are never trusted as their own oracle");
    }
    const evidence = await buildEvidence(manifest, options.tlcJar);
    const rendered = canonicalJson(evidence);
    if (options.check) {
        if (!prior)
            throw new Error("committed refinement evidence is missing");
        const committed = canonicalJson(prior);
        if (rendered !== committed) {
            throw new Error("formal runtime refinement evidence drift; run sync:formal-runtime-traces");
        }
    }
    if (options.emit)
        writeFileSync(evidencePath, rendered, "utf8");
    return evidence;
}
function readArg(name) {
    const index = process.argv.indexOf(name);
    return index >= 0 ? (process.argv[index + 1] ?? null) : null;
}
const invokedAsScript = process.argv[1] &&
    import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) {
    try {
        const evidence = await runFormalRuntimeRefinement({
            tlcJar: readArg("--tlc-jar"),
            emit: process.argv.includes("--emit"),
            check: process.argv.includes("--check"),
        });
        if (process.argv.includes("--json")) {
            process.stdout.write(canonicalJson(evidence));
        }
        else {
            console.log(`FORMAL RUNTIME REFINEMENT: PASS — ${evidence.summary.traces} traces, ` +
                `${evidence.summary.unsafe_mutations_detected} unsafe mutations detected, ` +
                `${evidence.summary.claims.length} claims`);
        }
    }
    catch (error) {
        console.error(`FORMAL RUNTIME REFINEMENT: FAIL\n${error.message}`);
        process.exitCode = 1;
    }
}
