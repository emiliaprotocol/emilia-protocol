// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * AIC x EP-AEB-CROSSING-RECORD-v1 deterministic composition runner.
 *
 * The native AIC verifier remains authoritative for AIC-JWT or AIC-X509
 * validation. This runner starts from that verifier's result, checks the
 * relying party's pinned issuer and principal binding, and records the local
 * boundary decision. It does not turn an AIC credential or a crossing record
 * into reusable execution authority.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { AIC_JWT_JKT_CROSSING_MAPPING_PROFILE, AIC_JWT_SVID_PROJECTION_VERSION, AIC_X509_SPKI_CROSSING_MAPPING_PROFILE, mapAicJwtJktCrossingAuthority, mapAicX509SpkiCrossingAuthority, projectAicJwtToStrictJwtSvid, } from "../../../packages/verify/aeb-aic-crossing-adapter.js";
import { AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS, AEB_CROSSING_RECORD_VERSION, issueAebCrossingRecord, verifyAebCrossingRecord, } from "../../../packages/verify/aeb-crossing-record.js";
import { canonicalizeAeb } from "../../../packages/verify/aeb-adapter-contract.js";
import { loadDefaultAgilityMldsaBackend } from "../../../packages/verify/pq-signature-agility.js";
export const PROFILE = "EP-AIC-AEB-CROSSING-COMPOSITION-v0.1";
const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PATH = resolve(HERE, "report.reference.json");
const SOURCE_LOCK = JSON.parse(readFileSync(resolve(HERE, "source-lock.json"), "utf8"));
const MAPPING_PROFILE = JSON.parse(readFileSync(resolve(HERE, "mapping-profile.json"), "utf8"));
const MAPPING_PROFILE_DIGEST = `sha256:${crypto.hash("sha256", canonicalizeAeb(MAPPING_PROFILE), "hex")}`;
const NOW = "2026-08-26T19:00:00Z";
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
const edPrivate = crypto.createPrivateKey({ key: ED_PRIVATE_JWK, format: "jwk" });
const edPublic = crypto.createPublicKey({ key: ED_PUBLIC_JWK, format: "jwk" });
const edPublicSpki = edPublic
    .export({ type: "spki", format: "der" })
    .toString("base64url");
const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x41));
const pqPublic = Buffer.from(pqPair.publicKey).toString("base64url");
const mldsaBackend = await loadDefaultAgilityMldsaBackend();
assert.ok(mldsaBackend, "real ML-DSA-65 backend must be available");
const SIGNERS = [
    { alg: "Ed25519", key_id: "aic-crossing-ed", private_key: edPrivate },
    { alg: "ML-DSA-65", key_id: "aic-crossing-pq", private_key: pqPair.secretKey },
];
const VERIFICATION_KEYS = [
    { alg: "Ed25519", key_id: "aic-crossing-ed", public_key: edPublicSpki },
    { alg: "ML-DSA-65", key_id: "aic-crossing-pq", public_key: pqPublic },
];
const ISSUER_PIN = `sha256:${"a1".repeat(32)}`;
const JKT = "J".repeat(43);
const SPKI = "S".repeat(43);
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
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
    }
    return value;
}
function sha256(value) {
    return `sha256:${crypto.hash("sha256", value, "hex")}`;
}
function result(id, category, passed, expected, observed) {
    return { id, category, passed, expected, observed };
}
function jktInput(overrides = {}) {
    return {
        native_verification: "VERIFIED",
        native_typ: "aic+jwt",
        issuer: "https://issuer.example",
        subject: "spiffe://example.org/agent/accounting",
        artifact_id: "aic-jwt:agent-accounting:17",
        artifact_digest: `sha256:${"b1".repeat(32)}`,
        issuer_trust_anchor_digest: ISSUER_PIN,
        trusted_issuer_trust_anchor_digests: [ISSUER_PIN],
        mapping_profile_digest: MAPPING_PROFILE_DIGEST,
        constraints_digest: `sha256:${"b3".repeat(32)}`,
        principal_binding: {
            kind: "RFC7638_JKT",
            hash_alg: "jkt",
            claimed_key_hash: JKT,
            presented_key_hash: JKT,
        },
        status: {
            value: "CURRENT",
            checked_at: NOW,
            source_head_digest: `sha256:${"b4".repeat(32)}`,
        },
        validity: {
            not_before: "2026-08-26T18:55:00Z",
            not_after: "2026-08-26T19:05:00Z",
        },
        ...overrides,
    };
}
function x509Input(overrides = {}) {
    return {
        native_verification: "VERIFIED",
        native_type: "AIC-X509",
        issuer: "https://ca.example",
        subject: "spiffe://example.org/agent/accounting",
        artifact_id: "aic-x509:agent-accounting:17",
        artifact_digest: `sha256:${"c1".repeat(32)}`,
        issuer_trust_anchor_digest: ISSUER_PIN,
        trusted_issuer_trust_anchor_digests: [ISSUER_PIN],
        mapping_profile_digest: MAPPING_PROFILE_DIGEST,
        constraints_digest: `sha256:${"c3".repeat(32)}`,
        certificate_serial: "01A7",
        principal_binding: {
            kind: "X509_SPKI",
            hash_alg: "sha-256",
            claimed_key_hash: SPKI,
            presented_key_hash: SPKI,
        },
        status: {
            value: "CURRENT",
            checked_at: NOW,
            source_head_digest: `sha256:${"c4".repeat(32)}`,
        },
        validity: {
            not_before: "2026-08-26T18:55:00Z",
            not_after: "2026-08-26T19:05:00Z",
        },
        ...overrides,
    };
}
function mapJkt(input = jktInput()) {
    const mapped = mapAicJwtJktCrossingAuthority(input);
    assert.equal(mapped.ok, true, JSON.stringify(mapped));
    return mapped.authority;
}
function mapX509(input = x509Input()) {
    const mapped = mapAicX509SpkiCrossingAuthority(input);
    assert.equal(mapped.ok, true, JSON.stringify(mapped));
    return mapped.authority;
}
async function issue(authority, recordId) {
    return issueAebCrossingRecord({
        record_id: recordId,
        operation_id: `operation:${recordId}`,
        issued_at: NOW,
        native_authority: authority,
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
    }, { signing_keys: [...SIGNERS], deterministic: true, mldsaBackend });
}
async function verify(value) {
    return verifyAebCrossingRecord(value, {
        verification_keys: [...VERIFICATION_KEYS],
        mldsaBackend,
    });
}
export async function buildReferenceReport() {
    const cases = [];
    const jkt = mapJkt();
    const x509 = mapX509();
    const jktRecord = await issue(jkt, "crossing:aic:jkt:0001");
    const jktCheck = await verify(jktRecord);
    cases.push(result("AIC-JWT-JKT-CROSSING", "positive", jkt.mapping_profile_id === AIC_JWT_JKT_CROSSING_MAPPING_PROFILE
        && jktCheck.verified
        && jktCheck.execution_authorizing === false, "RFC7638 jkt maps, receipt verifies, and remains non-authorizing", {
        mapping_profile: jkt.mapping_profile_id,
        verified: jktCheck.verified,
        execution_authorizing: jktCheck.execution_authorizing,
        algorithms: jktRecord.signatures.map((entry) => entry.alg),
    }));
    const x509Record = await issue(x509, "crossing:aic:x509:0001");
    const x509Check = await verify(x509Record);
    cases.push(result("AIC-X509-SPKI-CROSSING", "positive", x509.mapping_profile_id === AIC_X509_SPKI_CROSSING_MAPPING_PROFILE
        && x509Check.verified
        && x509Check.execution_authorizing === false, "X.509 SPKI maps, receipt verifies, and remains non-authorizing", {
        mapping_profile: x509.mapping_profile_id,
        verified: x509Check.verified,
        execution_authorizing: x509Check.execution_authorizing,
        algorithms: x509Record.signatures.map((entry) => entry.alg),
    }));
    cases.push(result("NATIVE-BINDINGS-REMAIN-DISTINCT", "mapping", jkt.mapping_profile_id !== x509.mapping_profile_id
        && jkt.native_profile !== x509.native_profile
        && jkt.authority_instance_digest !== x509.authority_instance_digest, "RFC7638 jkt and X.509 SPKI are separate native profiles and instances", {
        jkt_profile: jkt.mapping_profile_id,
        x509_profile: x509.mapping_profile_id,
        profiles_differ: jkt.mapping_profile_id !== x509.mapping_profile_id,
        instances_differ: jkt.authority_instance_digest !== x509.authority_instance_digest,
    }));
    const mismatch = mapAicJwtJktCrossingAuthority(jktInput({
        principal_binding: {
            kind: "RFC7638_JKT",
            hash_alg: "jkt",
            claimed_key_hash: JKT,
            presented_key_hash: "K".repeat(43),
        },
    }));
    cases.push(result("PRINCIPAL-BINDING-MISMATCH", "hostile", !mismatch.ok && mismatch.reason === "aic_principal_binding_mismatch", "aic_principal_binding_mismatch", { ok: mismatch.ok, reason: mismatch.ok ? null : mismatch.reason }));
    const untrusted = mapAicX509SpkiCrossingAuthority(x509Input({
        trusted_issuer_trust_anchor_digests: [`sha256:${"a2".repeat(32)}`],
    }));
    cases.push(result("UNTRUSTED-ISSUER", "hostile", !untrusted.ok && untrusted.reason === "aic_issuer_untrusted", "aic_issuer_untrusted", { ok: untrusted.ok, reason: untrusted.ok ? null : untrusted.reason }));
    const confused = mapAicJwtJktCrossingAuthority({
        ...jktInput(),
        native_typ: "JWT",
    });
    cases.push(result("NATIVE-TYPE-CONFUSION", "hostile", !confused.ok && confused.reason === "aic_native_type_confusion", "aic_native_type_confusion", { ok: confused.ok, reason: confused.ok ? null : confused.reason }));
    const failed = mapAicJwtJktCrossingAuthority(jktInput({
        native_verification: "FAILED",
    }));
    const indeterminate = mapAicX509SpkiCrossingAuthority(x509Input({
        native_verification: "INDETERMINATE",
    }));
    cases.push(result("NATIVE-VERIFICATION-REFUSAL", "hostile", !failed.ok && failed.reason === "aic_native_verification_failed"
        && !indeterminate.ok
        && indeterminate.reason === "aic_native_verification_indeterminate", "FAILED and INDETERMINATE both refuse", {
        failed: failed.ok ? null : failed.reason,
        indeterminate: indeterminate.ok ? null : indeterminate.reason,
    }));
    const projectionInput = {
        source: jktInput(),
        purpose: "WORKLOAD_IDENTITY_ONLY",
        audience: ["spiffe://example.org/workload-api"],
        issued_at: 1787770500,
        not_before: 1787770500,
        expires_at: 1787770800,
        token_id: "jwt-svid:aic-projection:0001",
        projected_algorithm: "ES256",
        projected_key_id: "jwt-svid-key-2026-08",
        has_constraints: true,
        delegation_mode: "representative",
        has_delegation_assertion: true,
        confirmation_key_present: true,
    };
    const projected = projectAicJwtToStrictJwtSvid(projectionInput);
    cases.push(result("STRICT-JWT-SVID-PROJECTION", "positive", projected.ok
        && projected.projection["@version"] === AIC_JWT_SVID_PROJECTION_VERSION
        && projected.projection.protected_header.typ === "JWT"
        && typeof projected.projection.payload.aud === "string"
        && projected.projection.new_signature_required
        && projected.projection.compact_token === null
        && projected.projection.authorization_decision === false, "new typ=JWT TBS projection with one aud and no authority", projected.ok ? {
        version: projected.projection["@version"],
        typ: projected.projection.protected_header.typ,
        audience: projected.projection.payload.aud,
        new_signature_required: projected.projection.new_signature_required,
        compact_token: projected.projection.compact_token,
        authorization_decision: projected.projection.authorization_decision,
        omitted_source_members: projected.projection.omitted_source_members,
    } : { reason: projected.reason }));
    const multipleAudience = projectAicJwtToStrictJwtSvid({
        ...projectionInput,
        audience: ["spiffe://example.org/a", "spiffe://example.org/b"],
    });
    cases.push(result("JWT-SVID-MULTIPLE-AUDIENCE-REFUSED", "hostile", !multipleAudience.ok
        && multipleAudience.reason === "jwt_svid_single_audience_required", "jwt_svid_single_audience_required", {
        ok: multipleAudience.ok,
        reason: multipleAudience.ok ? null : multipleAudience.reason,
    }));
    const semanticLoss = projectAicJwtToStrictJwtSvid({
        ...projectionInput,
        purpose: "AIC_AUTHORITY",
    });
    cases.push(result("JWT-SVID-AUTHORITY-SEMANTIC-LOSS", "hostile", !semanticLoss.ok && semanticLoss.reason === "aic_jwt_svid_semantic_loss", "aic_jwt_svid_semantic_loss", { ok: semanticLoss.ok, reason: semanticLoss.ok ? null : semanticLoss.reason }));
    const base = {
        "@version": "AIC-AEB-CROSSING-REFERENCE-REPORT-v0.1",
        profile: PROFILE,
        crossing_record_version: AEB_CROSSING_RECORD_VERSION,
        required_algorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        mappings: [
            AIC_JWT_JKT_CROSSING_MAPPING_PROFILE,
            AIC_X509_SPKI_CROSSING_MAPPING_PROFILE,
        ],
        jwt_svid_projection: AIC_JWT_SVID_PROJECTION_VERSION,
        source_lock: SOURCE_LOCK,
        source_lock_digest: sha256(canonicalizeAeb(SOURCE_LOCK)),
        mapping_profile_digest: sha256(canonicalizeAeb(MAPPING_PROFILE)),
        cases,
        passed: cases.every((entry) => entry.passed),
        known_limits: [
            "This run exercises the EMILIA reference adapter and crossing-record implementation; it is not an independent implementation of AIC-JWT, AIC-X509, or JWT-SVID.",
            "The adapter consumes a native verifier result; it does not reimplement AIC signature, certificate-path, delegation, capability, constraint, or status validation.",
            "RFC 7638 JWK thumbprints and X.509 SPKI hashes remain separate native mappings and are never treated as interchangeable proof.",
            "The strict JWT-SVID output is an unsigned typ=JWT projection requiring a new JWT-SVID signature; changing a native aic+jwt header would invalidate its source signature.",
            "The JWT-SVID projection preserves bounded workload identity fields only; it deliberately does not preserve AIC authority, delegation, constraint, confirmation-key, or full capability semantics.",
            "A verified crossing record is evidence of one past relying-party boundary decision and never authorizes another action.",
            "Passing these checks does not establish IETF adoption, certification, production deployment, independent interoperability, or employer endorsement.",
        ],
    };
    return { ...base, results_digest: sha256(canonicalizeAeb(base)) };
}
export async function runProfile(runner = {
    name: "EMILIA reference runner",
    affiliation: "EMILIA Protocol",
    revision: "aic-aeb-crossing-v0.1",
    executed_at: NOW,
}) {
    const reference = await buildReferenceReport();
    const passed = reference.cases.filter((entry) => entry.passed).length;
    return {
        ...reference,
        runner,
        reproduction_statement: `${runner.name} (${runner.affiliation}) reproduced ${passed}/${reference.cases.length} AIC crossing checks at ${runner.revision}. This is a reproduction of the EMILIA reference composition, not independent AIC or JWT-SVID interoperability, IETF adoption, certification, or employer endorsement.`,
    };
}
function argument(name) {
    const index = process.argv.indexOf(name);
    return index === -1 ? undefined : process.argv[index + 1];
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const deterministicReference = sorted(await buildReferenceReport());
    if (process.argv.includes("--check")) {
        assert.deepEqual(deterministicReference, JSON.parse(readFileSync(REFERENCE_PATH, "utf8")), "AIC crossing output changed; inspect the semantic delta before deliberately re-pinning report.reference.json");
    }
    const report = await runProfile({
        name: argument("--runner-name") ?? "EMILIA reference runner",
        affiliation: argument("--runner-affiliation") ?? "EMILIA Protocol",
        revision: argument("--runner-revision") ?? "aic-aeb-crossing-v0.1",
        executed_at: argument("--executed-at") ?? NOW,
    });
    const output = argument("--output");
    if (process.argv.includes("--write-reference")) {
        writeFileSync(REFERENCE_PATH, `${JSON.stringify(deterministicReference, null, 2)}\n`, "utf8");
    }
    if (output) {
        writeFileSync(resolve(output), `${JSON.stringify(sorted(report), null, 2)}\n`, "utf8");
    }
    else {
        process.stdout.write(`${JSON.stringify(sorted(report), null, 2)}\n`);
    }
    if (!report.passed)
        process.exitCode = 1;
}
