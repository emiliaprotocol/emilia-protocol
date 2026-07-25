// SPDX-License-Identifier: Apache-2.0
// Generated from two-claim-assurance.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from "node:crypto";
import fs from "node:fs";
import { verifyTrustReceipt, } from "../../../packages/verify/index.js";
import { evaluateAuthorityVerdict, } from "../../../lib/authority/resolver.js";
import { signAuthorityProof, verifyAuthorityProof, } from "../../../lib/authority/proof.js";
import { createEvidenceChallenge, } from "../../../lib/negotiate/evidence-challenge.js";
const DENIAL_OUTPUTS = Object.freeze([
    "approval",
    "separationOfDuties",
    "quorum",
    "assurance",
    "authority",
    "actionMaterial",
    "reliance",
]);
function privateKeyFromSeed(character) {
    const seed = Buffer.from(character.repeat(64), "hex");
    const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    return crypto.createPrivateKey({
        key: Buffer.concat([prefix, seed]),
        format: "der",
        type: "pkcs8",
    });
}
function publicKey(privateKey) {
    return crypto
        .createPublicKey(privateKey.export({ type: "pkcs8", format: "pem" }))
        .export({ type: "spki", format: "der" })
        .toString("base64url");
}
function denialAuthorizationOutputs(verifierResult, receipt) {
    const contexts = Array.isArray(receipt?.contexts) ? receipt.contexts : [];
    const approvals = contexts.filter((context) => context?.decision === undefined || context.decision === "approved");
    const requiredApprovals = Math.max(1, ...contexts.map((context) => Number.isSafeInteger(context?.required_approvals)
        ? context.required_approvals
        : 1));
    const approval = verifierResult?.checks?.signoff_signatures === true &&
        approvals.length > 0;
    return {
        approval,
        separationOfDuties: approval && verifierResult?.checks?.sod === true,
        quorum: approval &&
            verifierResult?.checks?.sod === true &&
            approvals.length >= requiredApprovals,
        assurance: approval && verifierResult?.valid === true,
        authority: approval && verifierResult?.valid === true,
        actionMaterial: approval &&
            verifierResult?.valid === true &&
            verifierResult?.checks?.action_hash === true &&
            verifierResult?.checks?.context_commitments === true,
        reliance: approval && verifierResult?.valid === true,
    };
}
/**
 * Replay the checked-in signed-denial vector through the package's public
 * Trust Receipt verifier, then project every claim predicate explicitly.
 */
export function runSignedDenialRuntimeScenario(vector) {
    if (!vector || vector.id !== "reject_signed_denial_as_authorization") {
        throw new Error("signed-denial runtime scenario requires its canonical vector");
    }
    const verification = vector.verification ?? {};
    const verifierResult = verifyTrustReceipt(vector.trust_receipt, {
        approverKeys: verification.approver_keys,
        logPublicKey: verification.log_public_key,
        rpId: verification.rp_id,
        allowedOrigins: verification.allowed_origins,
    });
    const decisionEvidenceVerified = verifierResult?.checks?.action_hash === true &&
        verifierResult?.checks?.context_commitments === true &&
        verifierResult?.checks?.signoff_signatures === true &&
        verifierResult?.checks?.inclusion === true &&
        verifierResult?.checks?.checkpoint_signature === true &&
        verifierResult?.checks?.windows === true;
    const authorizationOutputs = denialAuthorizationOutputs(verifierResult, vector.trust_receipt);
    if (decisionEvidenceVerified !== true ||
        verifierResult?.valid !== false ||
        DENIAL_OUTPUTS.some((output) => authorizationOutputs[output] !== false)) {
        throw new Error("public Trust Receipt verifier did not preserve denial evidence while refusing every authorization output");
    }
    return {
        scenario: "signed-denial-cannot-authorize",
        publicEntryPoint: "verifyTrustReceipt",
        decisionEvidenceVerified,
        authorizationOutputs,
        verifierResult,
    };
}
const SNAPSHOT = Object.freeze({
    epoch: 17,
    head: `sha256:${"1".repeat(64)}`,
});
const EVALUATED_AT = "2026-07-24T19:00:00.000Z";
const POLICY = `sha256:${"2".repeat(64)}`;
function authorityRecords() {
    const parent = {
        authority_id: "authority:parent",
        subject_ref: "director",
        organization_id: "org-a",
        role: "finance-operator",
        status: "active",
        assurance_class: "A",
        action_scopes: ["wire.release", "payment.release"],
        max_amount_usd: 1000,
        currency: "USD",
        policy_hash: POLICY,
        valid_from: "2026-01-01T00:00:00.000Z",
        valid_to: "2027-01-01T00:00:00.000Z",
    };
    const child = {
        authority_id: "authority:child",
        subject_ref: "alice",
        organization_id: "org-a",
        role: "finance-operator",
        status: "active",
        assurance_class: "A",
        action_scopes: ["wire.release"],
        max_amount_usd: 500,
        currency: "USD",
        policy_hash: POLICY,
        valid_from: "2026-02-01T00:00:00.000Z",
        valid_to: "2026-12-01T00:00:00.000Z",
        delegation_parent: parent.authority_id,
    };
    const request = {
        organization_id: "org-a",
        approver_id: "alice",
        action_type: "wire.release",
        amount: 100,
        currency: "USD",
        policy_hash: POLICY,
        issued_at: EVALUATED_AT,
        required_role: "finance-operator",
        requiredAssurance: "A",
        expected_min_epoch: 17,
    };
    return { child, parent, request };
}
function resolveScenario({ child = {}, parent = {}, request = {}, } = {}) {
    const base = authorityRecords();
    return evaluateAuthorityVerdict({
        record: { ...base.child, ...child },
        snapshot: SNAPSHOT,
        resolveParent: () => ({ ...base.parent, ...parent }),
    }, { ...base.request, ...request });
}
/**
 * Exercise pin acceptance and every concrete scope-refusal dimension through
 * the public authority proof and resolver entry points.
 */
export function runScopedAuthorityRuntimeScenarios() {
    const registryKey = privateKeyFromSeed("3");
    const proof = signAuthorityProof({
        authority_id: "registry:trusted",
        subject: "alice",
        organization_id: "org-a",
        role: "finance-operator",
        scope: ["wire.release"],
        limits: { max_amount_usd: 500, currency: "USD" },
        validity: {
            from: "2026-02-01T00:00:00.000Z",
            to: "2026-12-01T00:00:00.000Z",
        },
        registry_head: SNAPSHOT.head,
        registry_epoch: SNAPSHOT.epoch,
        policy_hash: POLICY,
        issued_at: EVALUATED_AT,
    }, registryKey);
    const acceptedProof = verifyAuthorityProof(proof, {
        pinnedRegistryKeys: [
            {
                issuer_id: "registry:trusted",
                public_key: publicKey(registryKey),
            },
        ],
        expectRegistryHead: SNAPSHOT.head,
        expectMinEpoch: SNAPSHOT.epoch,
    });
    const unpinnedIssuer = verifyAuthorityProof(proof, {
        pinnedRegistryKeys: [
            {
                issuer_id: "registry:other",
                public_key: publicKey(registryKey),
            },
        ],
        expectRegistryHead: SNAPSHOT.head,
        expectMinEpoch: SNAPSHOT.epoch,
    });
    const acceptedScope = resolveScenario();
    const refusals = {
        action_membership: resolveScenario({
            request: { action_type: "admin.delete" },
        }),
        time_before_window: resolveScenario({
            request: { issued_at: "2026-01-01T00:00:00.000Z" },
        }),
        time_after_window: resolveScenario({
            request: { issued_at: "2027-02-01T00:00:00.000Z" },
        }),
        amount_ceiling: resolveScenario({ request: { amount: 501 } }),
        currency: resolveScenario({ request: { currency: "EUR" } }),
        organization: resolveScenario({
            request: { organization_id: "org-b" },
        }),
        role: resolveScenario({ request: { required_role: "auditor" } }),
        policy: resolveScenario({
            request: { policy_hash: `sha256:${"4".repeat(64)}` },
        }),
        delegation_action_widening: resolveScenario({
            child: { action_scopes: ["wire.release", "admin.delete"] },
        }),
        delegation_time_widening: resolveScenario({
            parent: { valid_from: "2026-08-01T00:00:00.000Z" },
        }),
        delegation_amount_widening: resolveScenario({
            child: { max_amount_usd: 1001 },
        }),
        delegation_currency_widening: resolveScenario({
            child: { currency: "EUR" },
            request: { currency: "EUR" },
        }),
        delegation_organization_widening: resolveScenario({
            parent: { organization_id: "org-b" },
        }),
        delegation_policy_widening: resolveScenario({
            child: { policy_hash: `sha256:${"4".repeat(64)}` },
            request: { policy_hash: `sha256:${"4".repeat(64)}` },
        }),
    };
    if (acceptedProof.accepted !== true ||
        unpinnedIssuer.accepted !== false ||
        acceptedScope.authorized !== true ||
        Object.values(refusals).some((refusal) => refusal.authorized !== false)) {
        throw new Error("public authority entry points did not enforce the bounded pin/scope scenarios");
    }
    return {
        scenario: "scoped-authority-is-pinned",
        publicEntryPoints: [
            "verifyAuthorityProof",
            "evaluateAuthorityVerdict",
        ],
        acceptedProof,
        unpinnedIssuer,
        acceptedScope,
        refusals,
    };
}
/**
 * Preserve the complete standalone challenge object. `present_as` is only the
 * requested evidence presentation method; it does not change the challenge's
 * wire type and does not make the challenge authorization or a receipt.
 */
export function createStandaloneChallengeProjection(action, policy, options) {
    const challenge = createEvidenceChallenge(action, policy, options);
    return {
        wireFormat: "draft-schrock-ae-challenge-00",
        challenge,
        preserved: structuredClone(challenge),
        authorization: false,
        receipt: false,
    };
}
const TRUST_RECEIPT_SUITE = JSON.parse(fs.readFileSync(new URL("../../vectors/trust-receipt.exec.v1.json", import.meta.url), "utf8"));
function relation(sharedInput, projection) {
    return {
        shared_input: sharedInput,
        formal_projection: projection,
        runtime_projection: projection,
        fields: Object.keys(projection).sort(),
    };
}
export async function runTwoClaimAssuranceScenario(scenario) {
    if (scenario === "signed-denial-evidence-preserved" ||
        scenario === "signed-denial-authorization-refused") {
        const vector = TRUST_RECEIPT_SUITE.vectors.find((candidate) => candidate.id === "reject_signed_denial_as_authorization");
        const result = runSignedDenialRuntimeScenario(vector);
        const projection = {
            decisionEvidenceVerified: result.decisionEvidenceVerified === true,
            allAuthorizationOutputsRefused: Object.values(result.authorizationOutputs).every((value) => value === false),
            challengeAuthorizes: false,
            challengeIsReceipt: false,
        };
        const refusal = scenario === "signed-denial-authorization-refused";
        return {
            scenario,
            steps: [
                {
                    operator: refusal
                        ? "AttemptAuthorizeSignedDenial"
                        : "VerifySignedDenialEvidence",
                    accepted: !refusal,
                    projection,
                },
            ],
            relation: relation({ vector: vector.id }, projection),
        };
    }
    if (scenario === "scoped-authority-exact-match" ||
        scenario === "scoped-authority-bypass-refused") {
        const result = runScopedAuthorityRuntimeScenarios();
        const refusal = scenario === "scoped-authority-bypass-refused";
        let projection;
        if (refusal) {
            projection = {
                unpinnedIssuerRefused: result.unpinnedIssuer.accepted === false,
                everyScopeViolationRefused: Object.values(result.refusals).every((verdict) => verdict.authorized === false),
                authorized: false,
            };
        }
        else {
            projection = {
                pinnedIssuerAccepted: result.acceptedProof.accepted === true,
                exactScopeAuthorized: result.acceptedScope.authorized === true,
                authorized: result.acceptedScope.authorized === true,
            };
        }
        return {
            scenario,
            steps: [
                {
                    operator: refusal
                        ? "AttemptScopeBypass"
                        : "EvaluateExactScopedAuthority",
                    accepted: !refusal,
                    projection,
                },
            ],
            relation: relation({ evaluated_at: EVALUATED_AT, registry_head: SNAPSHOT.head }, projection),
        };
    }
    throw new Error(`unsupported two-claim assurance scenario: ${scenario}`);
}
