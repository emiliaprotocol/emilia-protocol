#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from generate-proof-stats.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Regenerates lib/proof-stats.json from ground truth or checks it in CI.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
const check = process.argv.includes("--check");
const reportDir = mkdtempSync(join(tmpdir(), "ep-proof-stats-"));
const reportPath = join(reportDir, "vitest.json");
const execution = spawnSync("npx", [
    "vitest",
    "run",
    "--silent",
    // Proof-stat measurement runs the complete integration inventory, including
    // tests that launch real git, archive, and protocol-check subprocesses.
    // Bound worker fan-out and give each case an explicit integration budget so
    // CPU starvation cannot turn Vitest's five-second unit default into a false
    // governed-evidence failure. The run still fails closed on any timeout.
    "--maxWorkers=4",
    "--testTimeout=60000",
    "--hookTimeout=60000",
    "--reporter=json",
    `--outputFile=${reportPath}`,
], {
    encoding: "utf8",
    maxBuffer: 1e9,
});
if (execution.error)
    throw execution.error;
if (!existsSync(reportPath)) {
    throw new Error(`Vitest did not write its JSON report:\n${execution.stderr || execution.stdout}`);
}
const j = JSON.parse(readFileSync(reportPath, "utf8"));
rmSync(reportDir, { recursive: true, force: true });
if (execution.status !== 0) {
    console.error("PROOF STATS: FAIL — the measured test run did not pass");
    for (const result of j.testResults
        .filter((item) => item.status === "failed")
        .slice(0, 20)) {
        console.error(result.name);
        for (const assertion of result.assertionResults
            .filter((item) => item.status === "failed")
            .slice(0, 10)) {
            console.error(`  ${assertion.fullName}`);
            for (const message of assertion.failureMessages.slice(0, 2))
                console.error(`  ${message.split("\n")[0]}`);
        }
    }
    process.exit(1);
}
const liveSecurityCase = spawnSync(process.execPath, [
    "--import",
    "./scripts/ts-loader/register.mjs",
    "scripts/verify-security-case.mjs",
    "--execute",
], {
    encoding: "utf8",
    maxBuffer: 1e9,
});
if (liveSecurityCase.error)
    throw liveSecurityCase.error;
if (liveSecurityCase.status !== 0) {
    throw new Error(`The live machine-verifiable security case failed:\n${liveSecurityCase.stderr || liveSecurityCase.stdout}`);
}
const cfg = readFileSync("formal/ep_handshake.cfg", "utf8");
const composedLifecycleCfg = readFileSync("formal/ep_composed_trust_lifecycle.cfg", "utf8");
const als = readFileSync("formal/ep_relations.als", "utf8");
const fedAls = readFileSync("formal/ep_federation.als", "utf8");
const quorumAls = readFileSync("formal/ep_quorum.als", "utf8");
const delegationAls = readFileSync("formal/ep_delegation.als", "utf8");
const redTeam = readFileSync("docs/conformance/RED_TEAM_CASES.md", "utf8");
const tamarinSummary = readFileSync("formal/tamarin/results/ep_reliance_composed.summary.txt", "utf8");
const conformance = JSON.parse(readFileSync("conformance/conformance-manifest.json", "utf8"));
const external = JSON.parse(readFileSync("conformance/external/rust-cleanroom-jdieselny.v1.json", "utf8"));
const securityCase = JSON.parse(readFileSync("security/security-case.json", "utf8"));
const claimSource = JSON.parse(readFileSync("security/claims.v1.json", "utf8"));
const scenarioConformanceBytes = readFileSync("formal/results/formal-runtime-scenario-conformance.v2.json");
const scenarioConformance = JSON.parse(scenarioConformanceBytes.toString("utf8"));
const tamarinVerifiedRows = [
    ...tamarinSummary.matchAll(/^\s{2}\S.*\((all-traces|exists-trace)\):\s+verified\b.*$/gm),
];
const tamarinVerified = tamarinVerifiedRows.length;
const tamarinAllTraceObligations = tamarinVerifiedRows.filter((match) => match[1] === "all-traces").length;
const tamarinExistsTraceWitnesses = tamarinVerifiedRows.filter((match) => match[1] === "exists-trace").length;
const tamarinCounterexamples = (tamarinSummary.match(/^\s{2}\S.*:\s+falsified\s+-\s+found trace\b.*$/gm) || []).length;
const tamarinVersion = tamarinSummary.match(/^Tamarin:\s+(.+)$/m)?.[1];
const tamarinModelHashes = [
    ...tamarinSummary.matchAll(/^Model SHA-256:\s+([a-f0-9]{64})$/gm),
].map((match) => match[1]);
const tamarinRunnerHash = tamarinSummary.match(/^Runner SHA-256:\s+([a-f0-9]{64})$/m)?.[1];
const currentTamarinModelHashes = [
    "formal/tamarin/ep_reliance_composed.spthy",
    "formal/tamarin/ep_six_claim_composed.spthy",
].map((file) => createHash("sha256").update(readFileSync(file)).digest("hex"));
const currentTamarinRunnerHash = createHash("sha256")
    .update(readFileSync("formal/tamarin/run-composed.sh"))
    .digest("hex");
if (!tamarinVersion ||
    tamarinModelHashes.length !== 2 ||
    !isDeepStrictEqual(tamarinModelHashes, currentTamarinModelHashes) ||
    tamarinRunnerHash !== currentTamarinRunnerHash ||
    tamarinVerified === 0 ||
    tamarinAllTraceObligations === 0 ||
    tamarinExistsTraceWitnesses === 0 ||
    tamarinCounterexamples === 0) {
    throw new Error("The composed Tamarin proof summary is incomplete or not bound to the current model and runner bytes");
}
if (securityCase.execution?.status !== "passed") {
    throw new Error("The machine-verifiable security case is not passing");
}
if (scenarioConformance["@version"] !==
    "EP-SELECTED-SCENARIO-CONFORMANCE-EVIDENCE-v2" ||
    scenarioConformance.method !== "bounded_selected_scenario_conformance" ||
    !Array.isArray(scenarioConformance.scenarios) ||
    scenarioConformance.scenarios.length === 0 ||
    !scenarioConformance.scenarios.every((scenario) => scenario.matched === true) ||
    scenarioConformance.summary?.paired_negative_controls < 1 ||
    !Number.isSafeInteger(scenarioConformance.summary?.required_model_actions) ||
    scenarioConformance.summary.required_model_actions < 1 ||
    scenarioConformance.summary.covered_model_actions !==
        scenarioConformance.summary.required_model_actions ||
    !Array.isArray(scenarioConformance.summary?.action_complete_models) ||
    scenarioConformance.summary.action_complete_models.length < 1) {
    throw new Error("The formal runtime selected-scenario conformance evidence is missing or incomplete");
}
if (!conformance.implementations?.every((item) => item.relationship === "one_team_port")) {
    throw new Error("Reference verifier relationship is not uniformly one_team_port");
}
if (external.conformance?.status !== "pass") {
    throw new Error("The pinned external implementation does not report conformance pass");
}
const FORMAL_EVIDENCE_CATEGORIES = Object.freeze([
    "verifiedFormalObligations",
    "boundedRuntimeTraced",
    "boundedFormalEvidence",
    "partialSymbolicCoverage",
    "executableOperationalEvidence",
]);
function classifyFormalEvidence(formal) {
    if (formal.length > 0 &&
        formal.every((entry) => entry.status === "verified")) {
        return "verifiedFormalObligations";
    }
    if (formal.some((entry) => entry.status === "partial" &&
        entry.method?.startsWith("bounded_") &&
        entry.scenario_coverage === "selected" &&
        Array.isArray(entry.covered_actions) &&
        entry.covered_actions.length > 0 &&
        Array.isArray(entry.covered_obligations) &&
        entry.covered_obligations.length > 0 &&
        typeof entry.scenario_evidence === "string" &&
        entry.scenario_evidence.length > 0 &&
        typeof entry.scenario_runner === "string" &&
        entry.scenario_runner.length > 0 &&
        typeof entry.conformance_evidence === "string" &&
        entry.conformance_evidence.length > 0)) {
        return "boundedRuntimeTraced";
    }
    if (formal.some((entry) => entry.status === "partial" &&
        [
            "bounded_tla_model_checking",
            "bounded_exhaustive_state_exploration",
        ].includes(entry.method))) {
        return "boundedFormalEvidence";
    }
    if (formal.some((entry) => entry.status === "partial" || entry.status === "verified")) {
        return "partialSymbolicCoverage";
    }
    return "executableOperationalEvidence";
}
const formalEvidenceCoverage = Object.fromEntries(FORMAL_EVIDENCE_CATEGORIES.map((category) => [
    category,
    { count: 0, claimIds: [] },
]));
for (const claim of claimSource.claims ?? []) {
    const category = classifyFormalEvidence(claim.formal ?? []);
    formalEvidenceCoverage[category].count += 1;
    formalEvidenceCoverage[category].claimIds.push(claim.claim_id);
}
for (const category of FORMAL_EVIDENCE_CATEGORIES) {
    formalEvidenceCoverage[category].claimIds.sort();
}
const classifiedClaimCount = FORMAL_EVIDENCE_CATEGORIES.reduce((total, category) => total + formalEvidenceCoverage[category].count, 0);
if (classifiedClaimCount !== claimSource.claims?.length ||
    classifiedClaimCount !== securityCase.claim_count) {
    throw new Error("The formal evidence taxonomy does not cover the complete security claim inventory");
}
const recordedRuntimeTracedClaims = formalEvidenceCoverage.boundedRuntimeTraced.claimIds;
const executedRuntimeTracedClaims = [
    ...scenarioConformance.summary.claims,
].sort();
if (!isDeepStrictEqual(recordedRuntimeTracedClaims, executedRuntimeTracedClaims)) {
    throw new Error("Bounded runtime-traced claim metadata does not match the executed selected-scenario evidence");
}
const stats = {
    generatedAt: new Date().toISOString(),
    tests: {
        total: j.numTotalTests,
        files: j.testResults.length,
        policy: "all platform-applicable cases must pass; platform-specific cases may skip",
    },
    tla: {
        invariants: (cfg.match(/^INVARIANT/gm) || []).length,
        composedLifecycleInvariants: (composedLifecycleCfg.match(/^INVARIANT/gm) || []).length,
        checker: "TLC 2.19",
    },
    formalScenarioConformance: {
        method: scenarioConformance.method,
        models: scenarioConformance.summary.models.length,
        claims: scenarioConformance.summary.claims.length,
        scenarios: scenarioConformance.summary.scenarios,
        soundScenarios: scenarioConformance.summary.sound_scenarios,
        pairedNegativeControls: scenarioConformance.summary.paired_negative_controls,
        requiredModelActions: scenarioConformance.summary.required_model_actions,
        coveredModelActions: scenarioConformance.summary.covered_model_actions,
        actionCompleteModels: scenarioConformance.summary.action_complete_models.length,
        formalMutationOperators: scenarioConformance.summary.formal_mutation_operators,
        evidenceSha256: createHash("sha256")
            .update(scenarioConformanceBytes)
            .digest("hex"),
        boundary: "selected model/runtime scenarios under explicit projection relations; not a mechanized implementation refinement proof",
    },
    formalEvidenceCoverage,
    alloy: {
        // facts: the core relational model (ep_relations). assertions: total across
        // ALL FOUR models that execute headless in CI (ep_relations + ep_federation
        // + ep_quorum + ep_delegation, via formal/AlloyCheck.java in alloy.yml). The
        // count was ep_relations+ep_federation only before ep_quorum/ep_delegation
        // were CI-gated; docs state it as a floor, so widening it needs no doc edit.
        facts: (als.match(/^fact/gm) || []).length,
        assertions: (als.match(/^assert/gm) || []).length +
            (fedAls.match(/^assert/gm) || []).length +
            (quorumAls.match(/^assert/gm) || []).length +
            (delegationAls.match(/^assert/gm) || []).length,
        version: "6.2.0 (CI)",
    },
    tamarin: {
        model: "EP-RELIANCE-COMPOSED-v2 + EP-SIX-CLAIM-COMPOSED-v1",
        models: 2,
        verifiedObligations: tamarinVerified,
        allTraceObligations: tamarinAllTraceObligations,
        existsTraceWitnesses: tamarinExistsTraceWitnesses,
        deliberatelyUnsafeCounterexamples: tamarinCounterexamples,
        version: tamarinVersion,
        modelSha256: tamarinModelHashes[0],
        focusedModelSha256: tamarinModelHashes[1],
    },
    securityCase: {
        status: securityCase.execution.status,
        claims: securityCase.claim_count,
        evidenceFiles: securityCase.evidence_file_count,
        evidenceBundleSha256: securityCase.evidence_bundle_sha256,
    },
    conformance: {
        suites: conformance.totals.suites,
        vectors: conformance.totals.vectors,
        referencePorts: conformance.totals.implementations,
        relationship: "same_team_ports",
    },
    externalImplementation: {
        language: external.implementation.language,
        vectors: external.conformance.vectors,
        hostilityCases: external.hostility.structured_cases + external.hostility.raw_parser_cases,
        strictCleanRoomAcceptance: external.construction_evidence.strict_clean_room_acceptance,
    },
    redTeamCases: (redTeam.match(/^### /gm) || []).length,
};
if (check) {
    const current = JSON.parse(readFileSync("lib/proof-stats.json", "utf8"));
    const measured = { ...stats };
    /** @type {Record<string, unknown>} */
    const recorded = { ...current };
    delete measured.generatedAt;
    delete recorded.generatedAt;
    if (!isDeepStrictEqual(measured, recorded)) {
        console.error("PROOF STATS: FAIL — lib/proof-stats.json does not match the executed suite");
        console.error(JSON.stringify({ recorded, measured }, null, 2));
        console.error("\nFix: run `npm run sync:proof-stats` and commit lib/proof-stats.json.");
        console.error("(Docs state the count as a floor, so no doc edits are needed — only this one file.)");
        process.exitCode = 1;
    }
    else {
        console.log(`PROOF STATS: PASS (${stats.tests.total} test cases, ${stats.tests.files} files; ${stats.tamarin.verifiedObligations} verified Tamarin lemmas; ${stats.securityCase.claims} executable security claims; ${stats.conformance.vectors} conformance vectors; ${stats.externalImplementation.hostilityCases} external hostility cases)`);
    }
}
else {
    writeFileSync("lib/proof-stats.json", `${JSON.stringify(stats, null, 2)}\n`);
    console.log(stats);
}
