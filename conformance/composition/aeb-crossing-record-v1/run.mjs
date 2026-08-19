// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP-AEB-CROSSING-RECORD-v1 carrier-neutral composition runner.
 *
 * This runner executes the EMILIA reference implementation. An external run
 * is a reproduction of these pinned checks, not an independent implementation
 * or proof that every authority format has a conformant mapping.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS, AEB_CROSSING_RECORD_VERSION, BCR_CROSSING_MAPPING_PROFILE, WIMSE_OAUTH_CROSSING_MAPPING_PROFILE, issueAebCrossingRecord, mapBcrCrossingAuthority, mapWimseOAuthCrossingAuthority, verifyAebCrossingRecord, } from "../../../packages/verify/aeb-crossing-record.js";
import { canonicalizeAeb } from "../../../packages/verify/aeb-adapter-contract.js";
import { loadDefaultAgilityMldsaBackend } from "../../../packages/verify/pq-signature-agility.js";
export const PROFILE = "EP-AEB-CROSSING-RECORD-COMPOSITION-v1";
const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PATH = resolve(HERE, "report.reference.json");
const NOW = "2026-08-19T05:00:00Z";
const ED_PRIVATE_JWK = {
    crv: "Ed25519",
    d: "EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y",
    x: "c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI",
    kty: "OKP",
};
const ED_PUBLIC_JWK = {
    crv: "Ed25519",
    x: "c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI",
    kty: "OKP",
};
const edPrivate = crypto.createPrivateKey({
    key: ED_PRIVATE_JWK,
    format: "jwk",
});
const edPublic = crypto.createPublicKey({ key: ED_PUBLIC_JWK, format: "jwk" });
const edPublicSpki = edPublic
    .export({ type: "spki", format: "der" })
    .toString("base64url");
const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x41));
const pqPublic = Buffer.from(pqPair.publicKey).toString("base64url");
const mldsaBackend = await loadDefaultAgilityMldsaBackend();
assert.ok(mldsaBackend, "real ML-DSA-65 backend must be available");
const SIGNERS = [
    { alg: "Ed25519", key_id: "crossing-ed", private_key: edPrivate },
    { alg: "ML-DSA-65", key_id: "crossing-pq", private_key: pqPair.secretKey },
];
const VERIFICATION_KEYS = [
    { alg: "Ed25519", key_id: "crossing-ed", public_key: edPublicSpki },
    { alg: "ML-DSA-65", key_id: "crossing-pq", public_key: pqPublic },
];
const ACTION = Object.freeze({
    caid: "caid:1:finance.vendor-account-change.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    action_digest: `sha256:${"11".repeat(32)}`,
});
const BOUNDARY = Object.freeze({
    relying_party_id: "rp:example-finance",
    audience: "erp:vendor-master",
    executor_id: "executor:erp-production",
    state_domain_id: "state-domain:finance-primary",
});
const REQUIREMENTS = Object.freeze({
    admission_digest: `sha256:${"22".repeat(32)}`,
    review_digest: `sha256:${"33".repeat(32)}`,
});
const ADMIT_AXES = {
    native_verification: "VERIFIED",
    rp_acceptance: "ACCEPTED",
    action_relation: "EXACT_MATCH",
    status: "CURRENT",
    replay: "FRESH",
    admission: "ADMIT",
    custody: "RESERVED",
    provider_commitment: "NOT_INVOKED",
    observed_effect: "NOT_OBSERVED",
    retry: "NOT_APPLICABLE",
    reconciliation: "NOT_APPLICABLE",
    reason_codes: [],
};
function sorted(value) {
    if (Array.isArray(value))
        return value.map(sorted);
    if (value !== null && typeof value === "object") {
        return Object.fromEntries(Object.keys(value)
            .sort()
            .map((key) => [key, sorted(value[key])]));
    }
    return value;
}
function sha256(value) {
    // This is a public conformance-report digest, never a credential or password hash.
    return `sha256:${crypto.hash("sha256", value, "hex")}`;
}
function wimseAuthority() {
    const result = mapWimseOAuthCrossingAuthority({
        native_verification: "VERIFIED",
        rp_acceptance: "ACCEPTED",
        authorization_server: "https://as.example",
        subject: "spiffe://example/agent/accounting",
        token_id: "txn-token-123",
        token_digest: `sha256:${"aa".repeat(32)}`,
        mapping_profile_digest: `sha256:${"ab".repeat(32)}`,
        constraints_digest: `sha256:${"ac".repeat(32)}`,
        status: {
            value: "CURRENT",
            checked_at: NOW,
            source_head_digest: `sha256:${"ad".repeat(32)}`,
        },
        validity: {
            not_before: "2026-08-19T04:55:00Z",
            not_after: "2026-08-19T05:05:00Z",
        },
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    return result.authority;
}
function bcrAuthority() {
    const result = mapBcrCrossingAuthority({
        native_verification: "VERIFIED",
        rp_acceptance: "ACCEPTED",
        issuer: "authority:finance-controller",
        subject: "agent:accounting-17",
        capability_id: "capability:vendor-master-7",
        generation: 3,
        receipt_digest: `sha256:${"ba".repeat(32)}`,
        mapping_profile_digest: `sha256:${"bb".repeat(32)}`,
        constraints_digest: `sha256:${"bc".repeat(32)}`,
        status: {
            value: "CURRENT",
            checked_at: NOW,
            source_head_digest: `sha256:${"bd".repeat(32)}`,
        },
        validity: {
            not_before: "2026-08-19T04:50:00Z",
            not_after: "2026-08-19T05:10:00Z",
        },
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    return result.authority;
}
async function issue(nativeAuthority = wimseAuthority(), overrides = {}) {
    return issueAebCrossingRecord({
        record_id: "crossing:finance:0001",
        operation_id: "operation:vendor-master:0001",
        issued_at: NOW,
        native_authority: nativeAuthority,
        action: ACTION,
        boundary: BOUNDARY,
        requirements: REQUIREMENTS,
        admission_reference: {
            state: "PRESENT",
            digest: `sha256:${"88".repeat(32)}`,
        },
        lifecycle_records: {
            evaluation_digest: `sha256:${"ee".repeat(32)}`,
            consumption_digest: `sha256:${"99".repeat(32)}`,
            provider_entry_digest: null,
        },
        evaluated_evidence_digests: [
            `sha256:${"66".repeat(32)}`,
            `sha256:${"77".repeat(32)}`,
        ],
        configuration_digests: [
            `sha256:${"44".repeat(32)}`,
            `sha256:${"55".repeat(32)}`,
        ],
        referee: ADMIT_AXES,
        ...overrides,
    }, {
        signing_keys: [...SIGNERS],
        deterministic: true,
        mldsaBackend,
    });
}
async function verify(value, keys = VERIFICATION_KEYS) {
    return verifyAebCrossingRecord(value, {
        verification_keys: [...keys],
        mldsaBackend,
    });
}
function result(id, category, passed, expected, observed) {
    return { id, category, passed, expected, observed };
}
async function refusedIssue(nativeAuthority, overrides) {
    try {
        await issue(nativeAuthority, overrides);
        return "issued";
    }
    catch (error) {
        return error instanceof Error ? error.message : "unknown_error";
    }
}
export async function buildReferenceReport() {
    const cases = [];
    const wimse = wimseAuthority();
    const bcr = bcrAuthority();
    cases.push(result("MAPPING-WIMSE-OAUTH", "mapping", wimse.mapping_profile_id === WIMSE_OAUTH_CROSSING_MAPPING_PROFILE, WIMSE_OAUTH_CROSSING_MAPPING_PROFILE, {
        mapping_profile: wimse.mapping_profile_id,
        replay_unit: wimse.replay_unit,
    }));
    cases.push(result("MAPPING-BCR", "mapping", bcr.mapping_profile_id === BCR_CROSSING_MAPPING_PROFILE, BCR_CROSSING_MAPPING_PROFILE, { mapping_profile: bcr.mapping_profile_id, replay_unit: bcr.replay_unit }));
    cases.push(result("OPEN-SET-SHARED-CONTRACT", "mapping", JSON.stringify(Object.keys(wimse).sort()) ===
        JSON.stringify(Object.keys(bcr).sort()) &&
        wimse.authority_instance_digest !== bcr.authority_instance_digest, "same projection keys; different native authority instance", {
        same_keys: JSON.stringify(Object.keys(wimse).sort()) ===
            JSON.stringify(Object.keys(bcr).sort()),
        different_instances: wimse.authority_instance_digest !== bcr.authority_instance_digest,
    }));
    const record = await issue(wimse);
    const verified = await verify(record);
    cases.push(result("HYBRID-OFFLINE-VERIFICATION", "positive", verified.verified && verified.execution_authorizing === false, "verified evidence; never fresh authority", {
        verified: verified.verified,
        execution_authorizing: verified.execution_authorizing,
        algorithms: record.signatures.map((signature) => signature.alg),
    }));
    const bcrRecord = await issue(bcr, { record_id: "crossing:finance:0002" });
    const bcrVerified = await verify(bcrRecord);
    cases.push(result("ONE-VERIFIER-MULTIPLE-NATIVE-SYSTEMS", "positive", bcrVerified.verified &&
        verified.verified &&
        record.body.contract_digest !== bcrRecord.body.contract_digest, "both verify under one record contract without native equivalence", {
        wimse_verified: verified.verified,
        bcr_verified: bcrVerified.verified,
        records_differ: record.body.contract_digest !== bcrRecord.body.contract_digest,
    }));
    for (const [id, mutate, expected] of [
        [
            "ACTION-SUBSTITUTION",
            (value) => {
                value.body.action.action_digest = `sha256:${"01".repeat(32)}`;
            },
            "contract_digest_mismatch",
        ],
        [
            "REPLAY-UNIT-SUBSTITUTION",
            (value) => {
                value.body.native_authority.replay_unit = `sha256:${"02".repeat(32)}`;
            },
            "contract_digest_mismatch",
        ],
        [
            "MAPPING-PROFILE-SUBSTITUTION",
            (value) => {
                value.body.native_authority.mapping_profile_digest = `sha256:${"03".repeat(32)}`;
            },
            "contract_digest_mismatch",
        ],
    ]) {
        const changed = structuredClone(record);
        mutate(changed);
        const check = await verify(changed);
        cases.push(result(id, "hostile", check.verified === false && check.reason === expected, expected, { verified: check.verified, reason: check.reason }));
    }
    const stripped = structuredClone(record);
    stripped.signatures = stripped.signatures.filter((signature) => signature.alg === "Ed25519");
    const stripping = await verify(stripped);
    cases.push(result("HYBRID-STRIPPING", "hostile", !stripping.verified && stripping.reason === "hybrid_leg_missing", "hybrid_leg_missing", { verified: stripping.verified, reason: stripping.reason }));
    const other = crypto.generateKeyPairSync("ed25519");
    const wrongSpki = other.publicKey
        .export({ type: "spki", format: "der" })
        .toString("base64url");
    const wrongKey = await verify(record, [
        { alg: "Ed25519", key_id: "crossing-ed", public_key: wrongSpki },
        VERIFICATION_KEYS[1],
    ]);
    cases.push(result("WRONG-RELYING-PARTY-KEY", "hostile", !wrongKey.verified && wrongKey.reason === "signature_invalid", "signature_invalid", { verified: wrongKey.verified, reason: wrongKey.reason }));
    const staleAuthority = wimseAuthority();
    staleAuthority.status = { ...staleAuthority.status, value: "STALE" };
    const stale = await issue(staleAuthority, {
        admission_reference: { state: "NOT_APPLICABLE", digest: null },
        lifecycle_records: {
            evaluation_digest: `sha256:${"ee".repeat(32)}`,
            consumption_digest: null,
            provider_entry_digest: null,
        },
        referee: {
            ...ADMIT_AXES,
            status: "STALE",
            admission: "REFUSE",
            custody: "UNRESERVED",
            reason_codes: ["status_stale"],
        },
    });
    const staleCheck = await verify(stale);
    cases.push(result("STALE-REMAINS-STALE", "boundary", staleCheck.verified &&
        stale.body.referee.status === "STALE" &&
        stale.body.referee.admission === "REFUSE", "STALE plus REFUSE", {
        verified: staleCheck.verified,
        status: stale.body.referee.status,
        admission: stale.body.referee.admission,
    }));
    const missing = await issue(wimse, {
        admission_reference: { state: "MISSING", digest: null },
        lifecycle_records: {
            evaluation_digest: `sha256:${"ee".repeat(32)}`,
            consumption_digest: null,
            provider_entry_digest: null,
        },
        referee: {
            ...ADMIT_AXES,
            admission: "INDETERMINATE",
            custody: "INDETERMINATE",
            retry: "REFUSE",
            reconciliation: "REQUIRED",
        },
    });
    const missingCheck = await verify(missing);
    cases.push(result("MISSING-ADMISSION-IS-NONAUTHORIZING", "boundary", missingCheck.verified &&
        missing.body.admission_reference.state === "MISSING" &&
        missing.body.referee.admission === "INDETERMINATE", "MISSING plus INDETERMINATE", {
        verified: missingCheck.verified,
        admission_reference: missing.body.admission_reference.state,
        admission: missing.body.referee.admission,
    }));
    const narrowed = await issue(wimse, {
        admission_reference: { state: "NOT_APPLICABLE", digest: null },
        lifecycle_records: {
            evaluation_digest: `sha256:${"ee".repeat(32)}`,
            consumption_digest: null,
            provider_entry_digest: null,
        },
        referee: {
            ...ADMIT_AXES,
            admission: "REFUSE",
            custody: "UNRESERVED",
            retry: "REQUIRES_NEW_ADMISSION",
        },
    });
    const narrowedCheck = await verify(narrowed);
    cases.push(result("LOCAL-NARROWING-ALLOWED", "boundary", narrowedCheck.verified &&
        narrowed.body.native_authority.rp_acceptance === "ACCEPTED" &&
        narrowed.body.referee.admission === "REFUSE", "native ACCEPTED may become local REFUSE", {
        verified: narrowedCheck.verified,
        native: narrowed.body.native_authority.rp_acceptance,
        admission: narrowed.body.referee.admission,
    }));
    const rejected = wimseAuthority();
    rejected.rp_acceptance = "REJECTED";
    const broadened = await refusedIssue(rejected, {});
    cases.push(result("LOCAL-BROADENING-REFUSED", "hostile", broadened === "authority_broadened", "authority_broadened", { issue_result: broadened }));
    const carrier = await verify({ ...record, carrier: { type: "AAC" } });
    cases.push(result("CARRIER-INJECTION-REFUSED", "hostile", !carrier.verified && carrier.reason === "malformed_record", "malformed_record", { verified: carrier.verified, reason: carrier.reason }));
    const base = {
        "@version": "AEB-CROSSING-RECORD-REFERENCE-REPORT-v1",
        profile: PROFILE,
        record_version: AEB_CROSSING_RECORD_VERSION,
        required_algorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        mappings: [
            WIMSE_OAUTH_CROSSING_MAPPING_PROFILE,
            BCR_CROSSING_MAPPING_PROFILE,
        ],
        cases,
        passed: cases.every((entry) => entry.passed),
        known_limits: [
            "This run exercises the EMILIA reference implementation; it is not an independent implementation.",
            "A verified crossing record is evidence of a past boundary decision and never authorizes another action.",
            "The two mappings share a projection contract and verifier; they do not claim native semantic equivalence.",
            "A passing report does not prove every authority format is supported, IETF adoption, certification, or production deployment.",
        ],
    };
    return { ...base, results_digest: sha256(canonicalizeAeb(base)) };
}
export async function runProfile(runner = {
    name: "EMILIA reference runner",
    affiliation: "EMILIA Protocol",
    revision: "aeb-crossing-record-v1",
    executed_at: NOW,
}) {
    const reference = await buildReferenceReport();
    return {
        ...reference,
        runner,
        reproduction_statement: `${runner.name} (${runner.affiliation}) reproduced ${reference.cases.filter((entry) => entry.passed).length}/${reference.cases.length} EMILIA carrier-neutral crossing-record checks at ${runner.revision}. This is a reproduction of the EMILIA reference implementation, not an independent implementation, IETF adoption, certification, or employer endorsement.`,
    };
}
function argument(name) {
    const index = process.argv.indexOf(name);
    return index === -1 ? undefined : process.argv[index + 1];
}
if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const report = await runProfile({
        name: argument("--runner-name") ?? "EMILIA reference runner",
        affiliation: argument("--runner-affiliation") ?? "EMILIA Protocol",
        revision: argument("--runner-revision") ?? "aeb-crossing-record-v1",
        executed_at: argument("--executed-at") ?? NOW,
    });
    const output = argument("--output");
    if (process.argv.includes("--write-reference")) {
        writeFileSync(REFERENCE_PATH, `${JSON.stringify(sorted(await buildReferenceReport()), null, 2)}\n`, "utf8");
    }
    if (output)
        writeFileSync(resolve(output), `${JSON.stringify(sorted(report), null, 2)}\n`, "utf8");
    else
        process.stdout.write(`${JSON.stringify(sorted(report), null, 2)}\n`);
    if (!report.passed)
        process.exitCode = 1;
}
