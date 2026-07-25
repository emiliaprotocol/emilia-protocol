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
const manifestPath = path.join(root, "formal", "runtime-scenarios.v2.json");
const evidencePath = path.join(root, "formal", "results", "formal-runtime-scenario-conformance.v2.json");
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
    "aec-execution-fleet-assurance": "conformance/refinement/adapters/aec-execution-fleet-assurance.mts",
    "consequence-lifecycle": "conformance/refinement/adapters/consequence-lifecycle.mts",
    "composed-trust-lifecycle": "conformance/refinement/adapters/composed-trust-lifecycle.mts",
    "durable-consumption-owner": "conformance/refinement/adapters/durable-consumption-owner.mts",
    "conservation-authority": "conformance/refinement/adapters/five-claim-bridge.mjs",
    "outcome-binding": "conformance/refinement/adapters/five-claim-bridge.mjs",
    "authority-document-proof-join": "conformance/refinement/adapters/five-claim-bridge.mjs",
    "authority-program": "conformance/refinement/adapters/five-claim-bridge.mjs",
    "receipt-program": "conformance/refinement/adapters/five-claim-bridge.mjs",
    grace: "conformance/refinement/adapters/grace-curtailment.mts",
    "mobile-continuity": "conformance/refinement/adapters/mobile-continuity.mts",
    "mobile-enrollment": "conformance/refinement/adapters/mobile-enrollment.mts",
    "model-to-matter": "conformance/refinement/adapters/model-to-matter.mts",
    "network-witness": "conformance/refinement/adapters/network-witness.mts",
    "evidence-challenge-lifecycle": "conformance/refinement/adapters/evidence-challenge-lifecycle.mts",
    "reliance-pinned-profile": "conformance/refinement/adapters/reliance-pinned-profile.mts",
    revocation: "conformance/refinement/adapters/revocation.mts",
    "two-claim-assurance": "conformance/refinement/adapters/two-claim-assurance.mts",
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
    if (trace.kind === "paired_negative_control" &&
        actual[actual.length - 1]?.accepted !== false) {
        throw new Error(`${trace.id}: runtime accepted the paired negative control`);
    }
    return actual;
}
function collectInputs(manifest) {
    const files = new Set([
        "formal/runtime-scenarios.v2.json",
        ...harnessSources,
        ...generatedRuntimeGovernance,
        ...executableImportClosure(executableEntryPoints),
    ]);
    for (const [model, contract] of Object.entries(manifest.models)) {
        files.add(model);
        if (contract.config)
            files.add(contract.config);
        if (contract.runner)
            files.add(contract.runner);
    }
    for (const trace of manifest.scenarios) {
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
    for (const trace of [...manifest.scenarios].sort((left, right) => left.id.localeCompare(right.id))) {
        const adapterResult = await getRuntimeAdapter(trace.adapter)(trace.scenario);
        const relation = adapterResult.relation;
        if (relation) {
            const fields = [...relation.fields].sort();
            if (fields.length === 0 ||
                new Set(fields).size !== fields.length ||
                fields.some((field) => !Object.hasOwn(relation.formal_projection, field) ||
                    !Object.hasOwn(relation.runtime_projection, field) ||
                    !Object.is(relation.formal_projection[field], relation.runtime_projection[field]))) {
                throw new Error(`${trace.id}: formal/runtime relation did not match`);
            }
        }
        results.push({
            id: trace.id,
            claim_id: trace.claim_id,
            kind: trace.kind,
            steps: assertRuntimeMatches(trace, adapterResult),
            ...(relation ? { relation } : {}),
        });
    }
    return {
        scenarios: results.length,
        sound_scenarios: results.filter((trace) => trace.kind === "sound").length,
        paired_negative_controls_rejected: results.filter((trace) => trace.kind === "paired_negative_control" &&
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
    const scenarios = [];
    for (const trace of [...manifest.scenarios].sort((left, right) => left.id.localeCompare(right.id))) {
        const steps = runtimeById.get(trace.id)?.steps;
        if (!steps)
            throw new Error(`${trace.id}: runtime trace result is missing`);
        const formal = runFormalTrace(root, trace, manifest.models[trace.model], tlcJar);
        const runtimeResult = runtimeById.get(trace.id);
        scenarios.push({
            id: trace.id,
            claim_id: trace.claim_id,
            kind: trace.kind,
            model: trace.model,
            adapter: trace.adapter,
            scenario: trace.scenario,
            formal,
            runtime: { status: "matched", steps },
            ...(runtimeResult?.relation
                ? {
                    relation: {
                        status: "matched",
                        ...runtimeResult.relation,
                        fields: [...runtimeResult.relation.fields].sort(),
                    },
                }
                : {}),
            ...(trace.kind === "paired_negative_control"
                ? {
                    control_semantics: "paired_formal_counterexample_runtime_refusal",
                }
                : {}),
            matched: true,
        });
    }
    const actionCompleteModels = Object.entries(manifest.models)
        .filter(([, model]) => model.required_actions.length > 0)
        .map(([model]) => model)
        .sort();
    const requiredModelActions = actionCompleteModels.reduce((total, model) => total + manifest.models[model].required_actions.length, 0);
    return {
        "@version": "EP-SELECTED-SCENARIO-CONFORMANCE-EVIDENCE-v2",
        method: "bounded_selected_scenario_conformance",
        toolchain: {
            tlc_jar_sha256: sha256(tlcJar),
            bounded_checker_runtime: "node",
        },
        inputs: collectInputs(manifest),
        scenarios,
        summary: {
            scenarios: scenarios.length,
            sound_scenarios: scenarios.filter((scenario) => scenario.kind === "sound").length,
            paired_negative_controls: scenarios.filter((scenario) => scenario.kind === "paired_negative_control" &&
                scenario.formal.status === "counterexample_detected" &&
                scenario.runtime.steps.at(-1)?.accepted === false).length,
            claims: [...new Set(scenarios.map((scenario) => scenario.claim_id))].sort(),
            models: [...new Set(scenarios.map((scenario) => scenario.model))].sort(),
            required_model_actions: requiredModelActions,
            covered_model_actions: requiredModelActions,
            action_complete_models: actionCompleteModels,
            formal_mutation_operators: manifest.scenarios.filter((scenario) => scenario.kind === "paired_negative_control").length,
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
        throw new Error("selected-scenario conformance requires --tlc-jar or TLA2TOOLS_JAR; committed verdicts are never trusted as their own oracle");
    }
    const evidence = await buildEvidence(manifest, options.tlcJar);
    const rendered = canonicalJson(evidence);
    if (options.check) {
        if (!prior)
            throw new Error("committed refinement evidence is missing");
        const committed = canonicalJson(prior);
        if (rendered !== committed) {
            throw new Error("selected-scenario conformance evidence drift; run sync:formal-traces");
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
            console.log(`SELECTED-SCENARIO CONFORMANCE: PASS — ${evidence.summary.scenarios} scenarios, ` +
                `${evidence.summary.paired_negative_controls} paired negative controls, ` +
                `${evidence.summary.claims.length} claims`);
        }
    }
    catch (error) {
        console.error(`SELECTED-SCENARIO CONFORMANCE: FAIL\n${error.message}`);
        process.exitCode = 1;
    }
}
