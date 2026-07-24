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
const cfg = readFileSync("formal/ep_handshake.cfg", "utf8");
const als = readFileSync("formal/ep_relations.als", "utf8");
const fedAls = readFileSync("formal/ep_federation.als", "utf8");
const quorumAls = readFileSync("formal/ep_quorum.als", "utf8");
const delegationAls = readFileSync("formal/ep_delegation.als", "utf8");
const redTeam = readFileSync("docs/conformance/RED_TEAM_CASES.md", "utf8");
const tamarinSummary = readFileSync("formal/tamarin/results/ep_reliance_composed.summary.txt", "utf8");
const conformance = JSON.parse(readFileSync("conformance/conformance-manifest.json", "utf8"));
const external = JSON.parse(readFileSync("conformance/external/rust-cleanroom-jdieselny.v1.json", "utf8"));
const securityCase = JSON.parse(readFileSync("security/security-case.json", "utf8"));
const refinementBytes = readFileSync("formal/results/formal-runtime-refinement.v1.json");
const refinement = JSON.parse(refinementBytes.toString("utf8"));
const verifiedTamarinSection = tamarinSummary.match(/Verified obligations:\n([\s\S]*?)\n\nDeliberately unsafe comparison obligations:/)?.[1];
const unsafeTamarinSection = tamarinSummary.match(/Deliberately unsafe comparison obligations:\n([\s\S]*?)\n\nThe first counterexample/)?.[1];
if (!verifiedTamarinSection || !unsafeTamarinSection) {
    throw new Error("Unable to parse the composed Tamarin proof summary");
}
const tamarinVerified = (verifiedTamarinSection.match(/:\s+verified\b/g) || []).length;
const tamarinCounterexamples = (unsafeTamarinSection.match(/:\s+falsified\s+-\s+found trace\b/g) || []).length;
const tamarinVersion = tamarinSummary.match(/^Tamarin:\s+(.+)$/m)?.[1];
const tamarinModelSha256 = tamarinSummary.match(/^Model SHA-256:\s+([a-f0-9]{64})$/m)?.[1];
if (!tamarinVersion ||
    !tamarinModelSha256 ||
    tamarinVerified === 0 ||
    tamarinCounterexamples === 0) {
    throw new Error("The composed Tamarin proof summary is incomplete");
}
if (securityCase.execution?.status !== "passed") {
    throw new Error("The machine-verifiable security case is not passing");
}
if (refinement["@version"] !== "EP-FORMAL-RUNTIME-REFINEMENT-EVIDENCE-v1" ||
    refinement.method !== "bounded_selected_trace_refinement" ||
    !Array.isArray(refinement.traces) ||
    refinement.traces.length === 0 ||
    !refinement.traces.every((trace) => trace.matched === true) ||
    refinement.summary?.unsafe_mutations_detected < 1) {
    throw new Error("The formal runtime refinement evidence is missing or incomplete");
}
if (!conformance.implementations?.every((item) => item.relationship === "one_team_port")) {
    throw new Error("Reference verifier relationship is not uniformly one_team_port");
}
if (external.conformance?.status !== "pass") {
    throw new Error("The pinned external implementation does not report conformance pass");
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
        checker: "TLC 2.19",
    },
    formalRefinement: {
        method: refinement.method,
        models: refinement.summary.models.length,
        claims: refinement.summary.claims.length,
        traces: refinement.summary.traces,
        soundTraces: refinement.summary.sound_traces,
        unsafeMutationsDetected: refinement.summary.unsafe_mutations_detected,
        evidenceSha256: createHash("sha256").update(refinementBytes).digest("hex"),
        boundary: "selected traces; not a mechanized implementation refinement proof",
    },
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
        model: "EP-RELIANCE-COMPOSED-v2",
        verifiedObligations: tamarinVerified,
        deliberatelyUnsafeCounterexamples: tamarinCounterexamples,
        version: tamarinVersion,
        modelSha256: tamarinModelSha256,
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
        console.log(`PROOF STATS: PASS (${stats.tests.total} test cases, ${stats.tests.files} files; ${stats.tamarin.verifiedObligations} composed Tamarin obligations; ${stats.securityCase.claims} executable security claims; ${stats.conformance.vectors} conformance vectors; ${stats.externalImplementation.hostilityCases} external hostility cases)`);
    }
}
else {
    writeFileSync("lib/proof-stats.json", `${JSON.stringify(stats, null, 2)}\n`);
    console.log(stats);
}
