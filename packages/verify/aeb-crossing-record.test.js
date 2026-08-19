// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-crossing-record.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS, AEB_CROSSING_RECORD_VERSION, BCR_CROSSING_MAPPING_PROFILE, WIMSE_OAUTH_CROSSING_MAPPING_PROFILE, issueAebCrossingRecord, mapBcrCrossingAuthority, mapWimseOAuthCrossingAuthority, verifyAebCrossingRecord, } from "./dist/aeb-crossing-record.js";
import { digestAebTyped } from "./dist/aeb-adapter-contract.js";
import { loadDefaultAgilityMldsaBackend } from "./dist/pq-signature-agility.js";
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
const NOW = "2026-08-19T05:00:00Z";
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
const CONFIGURATION_DIGESTS = Object.freeze([
    `sha256:${"44".repeat(32)}`,
    `sha256:${"55".repeat(32)}`,
]);
const EVALUATED_EVIDENCE_DIGESTS = Object.freeze([
    `sha256:${"66".repeat(32)}`,
    `sha256:${"77".repeat(32)}`,
]);
const ADMISSION_DIGEST = `sha256:${"88".repeat(32)}`;
const CONSUMPTION_DIGEST = `sha256:${"99".repeat(32)}`;
const SIGNERS = [
    { alg: "Ed25519", key_id: "crossing-ed", private_key: edPrivate },
    { alg: "ML-DSA-65", key_id: "crossing-pq", private_key: pqPair.secretKey },
];
const VERIFICATION_KEYS = [
    { alg: "Ed25519", key_id: "crossing-ed", public_key: edPublicSpki },
    { alg: "ML-DSA-65", key_id: "crossing-pq", public_key: pqPublic },
];
const ADMIT_AXES = Object.freeze({
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
});
function wimseAuthority() {
    const mapped = mapWimseOAuthCrossingAuthority({
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
    assert.equal(mapped.ok, true, JSON.stringify(mapped));
    return mapped.authority;
}
function bcrAuthority() {
    const mapped = mapBcrCrossingAuthority({
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
    assert.equal(mapped.ok, true, JSON.stringify(mapped));
    return mapped.authority;
}
async function issue(authority = wimseAuthority(), overrides = {}) {
    return issueAebCrossingRecord({
        record_id: "crossing:finance:0001",
        operation_id: "operation:vendor-master:0001",
        issued_at: NOW,
        native_authority: authority,
        action: ACTION,
        boundary: BOUNDARY,
        requirements: REQUIREMENTS,
        admission_reference: { state: "PRESENT", digest: ADMISSION_DIGEST },
        lifecycle_records: {
            evaluation_digest: `sha256:${"ee".repeat(32)}`,
            consumption_digest: CONSUMPTION_DIGEST,
            provider_entry_digest: null,
        },
        evaluated_evidence_digests: EVALUATED_EVIDENCE_DIGESTS,
        configuration_digests: CONFIGURATION_DIGESTS,
        referee: ADMIT_AXES,
        ...overrides,
    }, {
        signing_keys: [...SIGNERS],
        deterministic: true,
        mldsaBackend,
    });
}
async function verify(record) {
    return verifyAebCrossingRecord(record, {
        verification_keys: [...VERIFICATION_KEYS],
        mldsaBackend,
    });
}
test("both native mappings emit one carrier-neutral authority contract", () => {
    const wimse = wimseAuthority();
    const bcr = bcrAuthority();
    assert.equal(wimse.mapping_profile_id, WIMSE_OAUTH_CROSSING_MAPPING_PROFILE);
    assert.equal(bcr.mapping_profile_id, BCR_CROSSING_MAPPING_PROFILE);
    assert.deepEqual(Object.keys(wimse).sort(), Object.keys(bcr).sort());
    assert.notEqual(wimse.authority_instance_digest, bcr.authority_instance_digest);
    assert.notEqual(wimse.replay_unit, bcr.replay_unit);
});
test("replay-unit derivation is byte-stable for the same native authority", () => {
    assert.equal(wimseAuthority().replay_unit, wimseAuthority().replay_unit);
    assert.equal(bcrAuthority().replay_unit, bcrAuthority().replay_unit);
    assert.equal(wimseAuthority().replay_unit, digestAebTyped({
        authorization_server: "https://as.example",
        token_id: "txn-token-123",
    }, `${WIMSE_OAUTH_CROSSING_MAPPING_PROFILE}:replay-unit`));
});
test("a hybrid crossing record verifies offline under caller-pinned keys", async () => {
    const record = await issue();
    assert.equal(record["@version"], AEB_CROSSING_RECORD_VERSION);
    assert.deepEqual(record.body.signature_profile.required_algorithms, AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS);
    assert.deepEqual(record.signatures.map((signature) => signature.alg), AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS);
    const result = await verify(record);
    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.checks.signature_set, true);
    assert.equal(result.checks.contract_digest, true);
    assert.equal(result.execution_authorizing, false);
});
test("different native authority systems produce different records accepted by the same verifier", async () => {
    const wimse = await issue(wimseAuthority());
    const bcr = await issue(bcrAuthority(), {
        record_id: "crossing:finance:0002",
    });
    assert.notDeepEqual(wimse.body.native_authority, bcr.body.native_authority);
    assert.notEqual(wimse.body.contract_digest, bcr.body.contract_digest);
    assert.equal((await verify(wimse)).verified, true);
    assert.equal((await verify(bcr)).verified, true);
});
test("signature stripping and algorithm-set narrowing both refuse", async () => {
    const record = await issue();
    const stripped = structuredClone(record);
    stripped.signatures = stripped.signatures.filter((signature) => signature.alg === "Ed25519");
    assert.equal((await verify(stripped)).reason, "hybrid_leg_missing");
    const narrowed = structuredClone(record);
    narrowed.body.signature_profile.required_algorithms = ["Ed25519"];
    narrowed.signatures = narrowed.signatures.filter((signature) => signature.alg === "Ed25519");
    assert.equal((await verify(narrowed)).reason, "algorithm_set_mismatch");
});
test("action, replay-unit, and mapping-profile substitution refuse", async () => {
    const record = await issue();
    for (const mutate of [
        (value) => {
            value.body.action.action_digest = `sha256:${"01".repeat(32)}`;
        },
        (value) => {
            value.body.native_authority.replay_unit = `sha256:${"02".repeat(32)}`;
        },
        (value) => {
            value.body.native_authority.mapping_profile_digest = `sha256:${"03".repeat(32)}`;
        },
    ]) {
        const changed = structuredClone(record);
        mutate(changed);
        const result = await verify(changed);
        assert.equal(result.verified, false);
        assert.ok(["contract_digest_mismatch", "signature_invalid"].includes(result.reason ?? ""), result.reason ?? "");
    }
});
test("stale native status remains STALE and cannot be flattened into an admitted result", async () => {
    const authority = wimseAuthority();
    authority.status = { ...authority.status, value: "STALE" };
    const staleRefusal = await issue(authority, {
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
    assert.equal((await verify(staleRefusal)).verified, true);
    assert.equal(staleRefusal.body.referee.status, "STALE");
    await assert.rejects(() => issue(authority), /status_inconsistent/);
});
test("an admitted crossing requires a PRESENT admission reference and consumption record", async () => {
    await assert.rejects(() => issue(wimseAuthority(), {
        admission_reference: { state: "MISSING", digest: null },
    }), /admission_reference_invalid/);
    await assert.rejects(() => issue(wimseAuthority(), {
        lifecycle_records: {
            evaluation_digest: `sha256:${"ee".repeat(32)}`,
            consumption_digest: null,
            provider_entry_digest: null,
        },
    }), /consumption_record_required/);
});
test("a review can report MISSING admission evidence only as non-authorizing uncertainty", async () => {
    const review = await issue(wimseAuthority(), {
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
            reason_codes: [],
        },
    });
    const result = await verify(review);
    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(review.body.admission_reference.state, "MISSING");
    assert.equal(review.body.referee.admission, "INDETERMINATE");
});
test("local refusal may narrow accepted native authority", async () => {
    const refused = await issue(wimseAuthority(), {
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
    assert.equal((await verify(refused)).verified, true);
});
test("the boundary cannot broaden rejected native authority into ADMIT", async () => {
    const authority = wimseAuthority();
    authority.rp_acceptance = "REJECTED";
    await assert.rejects(() => issue(authority), /authority_broadened/);
});
test("wrong relying-party key and malformed input refuse without throwing", async () => {
    const record = await issue();
    const other = crypto.generateKeyPairSync("ed25519");
    const wrongSpki = other.publicKey
        .export({ type: "spki", format: "der" })
        .toString("base64url");
    const result = await verifyAebCrossingRecord(record, {
        verification_keys: [
            { alg: "Ed25519", key_id: "crossing-ed", public_key: wrongSpki },
            VERIFICATION_KEYS[1],
        ],
        mldsaBackend,
    });
    assert.equal(result.verified, false);
    assert.equal(result.reason, "signature_invalid");
    const malformed = await verify({ nope: true });
    assert.equal(malformed.verified, false);
    assert.equal(malformed.reason, "malformed_record");
});
test("carrier fields are outside the closed signed record contract", async () => {
    const record = await issue();
    const withCarrier = { ...record, carrier: { type: "AAC" } };
    const result = await verify(withCarrier);
    assert.equal(result.verified, false);
    assert.equal(result.reason, "malformed_record");
});
