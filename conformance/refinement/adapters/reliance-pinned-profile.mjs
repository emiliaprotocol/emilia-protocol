// SPDX-License-Identifier: Apache-2.0
// Generated from reliance-pinned-profile.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from "node:crypto";
import { SOUND_RELIANCE_STATE, evaluateRelianceState, } from "../../../formal/reliance-pinned-profile.model.mjs";
import { signAuthorityProof } from "../../../lib/authority/proof.js";
import { evaluateReliance } from "../../../packages/verify/dist/reliance.js";
const NOW = Date.parse("2026-07-07T00:00:00.000Z");
const POLICY_HASH = `sha256:${"7".repeat(64)}`;
const REGISTRY_HEAD = `sha256:${"1".repeat(64)}`;
function deterministicEd25519(seedByte) {
    const der = Buffer.concat([
        Buffer.from("302e020100300506032b657004220420", "hex"),
        Buffer.alloc(32, seedByte),
    ]);
    const privateKey = crypto.createPrivateKey({
        key: der,
        format: "der",
        type: "pkcs8",
    });
    const publicKey = crypto
        .createPublicKey(privateKey)
        .export({ type: "spki", format: "der" })
        .toString("base64url");
    return { privateKey, publicKey };
}
const APPROVER_KEY = deterministicEd25519(1);
const LOG_KEY = deterministicEd25519(2);
const REGISTRY_KEY = deterministicEd25519(3);
const UNTRUSTED_KEY = deterministicEd25519(4);
function canonicalize(value) {
    if (value === null || value === undefined)
        return JSON.stringify(value);
    if (Array.isArray(value)) {
        return `[${value.map(canonicalize).join(",")}]`;
    }
    if (typeof value === "object") {
        return `{${Object.keys(value)
            .sort()
            .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
            .join(",")}}`;
    }
    return JSON.stringify(value);
}
function sha256Hex(value) {
    return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}
function leafHash(value) {
    return crypto
        .createHash("sha256")
        .update(Buffer.concat([Buffer.from([0]), Buffer.from(value, "utf8")]))
        .digest("hex");
}
function hashPair(left, right) {
    return crypto
        .createHash("sha256")
        .update(Buffer.concat([
        Buffer.from([1]),
        Buffer.from(left, "utf8"),
        Buffer.from(right, "utf8"),
    ]))
        .digest("hex");
}
function buildReceipt() {
    const action = {
        ep_version: "1.0",
        action_type: "wire.release",
        organization_id: "acme",
        target: {
            system: "treasury.example",
            resource: "wire/refinement",
        },
        parameters: { amount: "50000.00", currency: "USD" },
        initiator: "ep:entity:scenario-agent",
        policy_id: "ep:policy:wires@v1",
        requested_at: "2026-06-09T17:21:04Z",
    };
    const actionHash = `sha256:${sha256Hex(canonicalize(action))}`;
    const context = {
        ep_version: "1.0",
        context_type: "ep.signoff.v1",
        action_hash: actionHash,
        policy_id: "ep:policy:wires@v1",
        policy_hash: POLICY_HASH,
        initiator: action.initiator,
        required_approvals: 1,
        issued_at: "2026-06-09T17:21:05Z",
        expires_at: "2026-08-09T17:36:05Z",
        approver: "ep:approver:scenario-cfo",
        approver_index: 1,
        nonce: "reliance-scenario-approval",
        decision: "approved",
    };
    const contextDigest = sha256Hex(canonicalize(context));
    const receipt = {
        receipt_id: "ep:receipt:scenario-reliance",
        action,
        action_hash: actionHash,
        contexts: [context],
        signoffs: [
            {
                context_hash: `sha256:${contextDigest}`,
                signature: crypto
                    .sign(null, Buffer.from(contextDigest, "hex"), APPROVER_KEY.privateKey)
                    .toString("base64url"),
                key_class: "B",
                approver_key_id: "ep:key:scenario-cfo#1",
                signed_at: "2026-06-09T17:24:40Z",
            },
        ],
        consumption: {
            nonce: "reliance-scenario-consumption",
            state: "COMMITTED",
            committed_at: "2026-06-09T17:25:02Z",
        },
    };
    const leaf = leafHash(canonicalize(receipt));
    const siblingOne = sha256Hex("scenario-other-leaf");
    const siblingTwo = sha256Hex("scenario-other-subtree");
    const root = hashPair(hashPair(leaf, siblingOne), siblingTwo);
    const checkpoint = {
        tree_size: 4,
        root_hash: `sha256:${root}`,
        log_key_id: "ep:log:scenario#1",
        merkle_alg: "EP-MERKLE-v2",
    };
    const logSignature = crypto
        .sign(null, crypto
        .createHash("sha256")
        .update(canonicalize(checkpoint), "utf8")
        .digest(), LOG_KEY.privateKey)
        .toString("base64url");
    receipt.log_proof = {
        alg: "EP-MERKLE-v2",
        leaf_hash: `sha256:${leaf}`,
        leaf_index: 0,
        inclusion_path: [
            { hash: siblingOne, position: "right" },
            { hash: siblingTwo, position: "right" },
        ],
        checkpoint: { ...checkpoint, log_signature: logSignature },
    };
    return receipt;
}
const SCENARIOS = Object.freeze({
    "reliance-all-pinned": {
        obligation: null,
        expectedVerdict: "rely",
        operator: "AcceptPinnedReliance",
    },
    "reliance-profile-refused": {
        obligation: "PinnedProfileRequired",
        expectedVerdict: "do_not_rely_no_profile",
        operator: "RefuseUnpinnedProfile",
    },
    "reliance-signed-material-refused": {
        obligation: "SignedMaterialRequired",
        expectedVerdict: "do_not_rely_unsigned",
        operator: "RefuseUnsignedMaterial",
    },
    "reliance-assurance-refused": {
        obligation: "AssuranceRequired",
        expectedVerdict: "do_not_rely_no_class_a",
        operator: "RefuseInsufficientAssurance",
    },
    "reliance-organization-authority-refused": {
        obligation: "OrganizationAuthorityRequired",
        expectedVerdict: "do_not_rely_authority_organization_mismatch",
        operator: "RefuseOrganizationAuthorityMismatch",
    },
    "reliance-registry-head-refused": {
        obligation: "ExactRegistryHeadRequired",
        expectedVerdict: "do_not_rely_registry_unavailable",
        operator: "RefuseRegistryHeadMismatch",
    },
    "reliance-registry-epoch-refused": {
        obligation: "RegistryEpochFloorOrdered",
        expectedVerdict: "do_not_rely_registry_unavailable",
        operator: "RefuseRegistryEpochRollback",
    },
    "reliance-policy-refused": {
        obligation: "PolicyRequired",
        expectedVerdict: "do_not_rely_policy_mismatch",
        operator: "RefuseUnpinnedPolicy",
    },
    "reliance-revocation-authentication-refused": {
        obligation: "AuthenticatedRevocationRequired",
        expectedVerdict: "do_not_rely_stale_revocation",
        operator: "RefuseUnauthenticatedRevocationState",
    },
    "reliance-revocation-freshness-refused": {
        obligation: "FreshRevocationRequired",
        expectedVerdict: "do_not_rely_stale_revocation",
        operator: "RefuseStaleRevocationState",
    },
    "reliance-issuer-refused": {
        obligation: "IssuerRequired",
        expectedVerdict: "do_not_rely_untrusted_issuer",
        operator: "RefuseUnpinnedIssuer",
    },
    "reliance-consumed-refused": {
        obligation: "UnconsumedStateRequired",
        expectedVerdict: "do_not_rely_already_consumed",
        operator: "RefuseConsumedAuthorization",
    },
});
function abstractStateFor(obligation) {
    const state = {
        ...SOUND_RELIANCE_STATE,
    };
    const fields = {
        PinnedProfileRequired: "profile_pinned",
        SignedMaterialRequired: "signed_material_valid",
        AssuranceRequired: "assurance_satisfied",
        OrganizationAuthorityRequired: "organization_authority_matches",
        ExactRegistryHeadRequired: "registry_head_exact",
        PolicyRequired: "policy_accepted",
        AuthenticatedRevocationRequired: "revocation_authenticated",
        FreshRevocationRequired: "revocation_fresh",
        IssuerRequired: "issuer_pinned",
        UnconsumedStateRequired: "authorization_unconsumed",
    };
    if (obligation === "RegistryEpochFloorOrdered") {
        state.minimum_registry_epoch = state.registry_epoch + 1;
    }
    else if (obligation) {
        state[fields[obligation]] = false;
    }
    return state;
}
function assembleRuntimeInput(obligation) {
    const receipt = buildReceipt();
    const action = {
        action_type: "wire.release",
        amount: 50000,
        currency: "USD",
        organization_id: "acme",
        policy_hash: POLICY_HASH,
        action_hash: receipt.action_hash,
    };
    const profile = {
        "@type": "EP-RELIANCE-PROFILE-v1",
        required_assurance: "signed",
        required_authority: true,
        max_revocation_staleness_sec: 300,
        accepted_registry_keys: [
            {
                issuer_id: "auth_cfo",
                organization_id: "acme",
                public_key: REGISTRY_KEY.publicKey,
                min_epoch: 17,
                registry_head: REGISTRY_HEAD,
            },
        ],
        accepted_issuer_keys: [LOG_KEY.publicKey],
        accepted_policy_hashes: [POLICY_HASH],
        required_evidence: [
            "receipt",
            "authority_proof",
            "revocation_freshness",
            "consumption_proof",
        ],
    };
    const proofArgs = {
        authority_id: "auth_cfo",
        subject: "ep:approver:scenario-cfo",
        organization_id: "acme",
        role: "cfo",
        scope: ["wire.release"],
        limits: { max_amount_usd: 50000, currency: "USD" },
        validity: {
            from: "2026-01-01T00:00:00.000Z",
            to: "2027-01-01T00:00:00.000Z",
        },
        revocation: {
            status: "not_revoked",
            checked_at: "2026-07-06T23:59:00.000Z",
        },
        registry_head: REGISTRY_HEAD,
        registry_epoch: 17,
        policy_hash: POLICY_HASH,
        issued_at: "2026-07-06T23:59:00.000Z",
    };
    const opts = {
        approverKeys: {
            "ep:key:scenario-cfo#1": {
                approver_id: "ep:approver:scenario-cfo",
                public_key: APPROVER_KEY.publicKey,
                key_class: "B",
                valid_from: "2026-01-01T00:00:00Z",
                valid_to: "2027-01-01T00:00:00Z",
            },
        },
        logPublicKey: LOG_KEY.publicKey,
        rpId: "www.emiliaprotocol.ai",
        allowedOrigins: ["https://www.emiliaprotocol.ai"],
        isConsumed: () => false,
    };
    let revocationState = {
        checked_at: "2026-07-06T23:58:00.000Z",
    };
    switch (obligation) {
        case null:
            break;
        case "PinnedProfileRequired":
            delete profile["@type"];
            break;
        case "SignedMaterialRequired":
            receipt.signoffs[0].signature = crypto
                .sign(null, Buffer.from("00".repeat(32), "hex"), UNTRUSTED_KEY.privateKey)
                .toString("base64url");
            break;
        case "AssuranceRequired":
            profile.required_assurance = "class_a";
            profile.required_evidence.push("class_a_or_quorum");
            break;
        case "OrganizationAuthorityRequired":
            proofArgs.organization_id = "attacker-org";
            break;
        case "ExactRegistryHeadRequired":
            profile.accepted_registry_keys[0].registry_head =
                `sha256:${"2".repeat(64)}`;
            break;
        case "RegistryEpochFloorOrdered":
            profile.accepted_registry_keys[0].min_epoch = 18;
            break;
        case "PolicyRequired":
            profile.accepted_policy_hashes = [`sha256:${"9".repeat(64)}`];
            break;
        case "AuthenticatedRevocationRequired":
            revocationState = {
                target: {},
                statement: {},
            };
            break;
        case "FreshRevocationRequired":
            proofArgs.revocation.checked_at = "2026-01-01T00:00:00.000Z";
            break;
        case "IssuerRequired":
            profile.accepted_issuer_keys = [UNTRUSTED_KEY.publicKey];
            break;
        case "UnconsumedStateRequired":
            opts.isConsumed = () => true;
            break;
        default:
            throw new Error(`unsupported reliance obligation: ${obligation}`);
    }
    return {
        input: {
            action,
            receipt,
            authority_proof: signAuthorityProof(proofArgs, REGISTRY_KEY.privateKey),
            revocation_state: revocationState,
            consumption: { consumed: false },
            relying_party_profile: profile,
            now: NOW,
        },
        opts,
    };
}
function assertRuntime(condition, message) {
    if (!condition) {
        throw new Error(`reliance runtime bridge failed: ${message}`);
    }
}
function relation(sharedInput, formalProjection, runtimeProjection) {
    const fields = Object.keys(formalProjection).sort();
    assertRuntime(fields.length > 0 &&
        fields.every((field) => Object.hasOwn(runtimeProjection, field) &&
            Object.is(formalProjection[field], runtimeProjection[field])), "formal/runtime projections differ");
    return {
        shared_input: sharedInput,
        formal_projection: formalProjection,
        runtime_projection: runtimeProjection,
        fields,
    };
}
export async function runReliancePinnedProfileScenario(scenario) {
    const contract = SCENARIOS[scenario];
    if (!contract) {
        throw new Error(`unsupported pinned reliance scenario: ${scenario}`);
    }
    const sharedInput = abstractStateFor(contract.obligation);
    const formal = evaluateRelianceState(sharedInput);
    const { input, opts } = assembleRuntimeInput(contract.obligation);
    const runtime = evaluateReliance(input, opts);
    assertRuntime(runtime.verdict === contract.expectedVerdict, `${scenario} returned ${runtime.verdict}, expected ${contract.expectedVerdict}`);
    assertRuntime(runtime.rely === formal.accepted, `${scenario} disagreed with the bounded reliance model`);
    assertRuntime(formal.failed_obligation === contract.obligation, `${scenario} did not isolate ${contract.obligation}`);
    const failedObligation = contract.obligation ?? "none";
    const formalProjection = {
        accepted: formal.accepted,
        failedObligation,
    };
    const runtimeProjection = {
        accepted: runtime.rely === true,
        failedObligation: runtime.rely === true ? "none" : failedObligation,
    };
    return {
        scenario,
        steps: [
            {
                operator: contract.operator,
                accepted: runtime.rely === true,
                projection: {
                    relianceVerdict: runtime.verdict,
                    failedObligation,
                },
            },
        ],
        relation: relation(sharedInput, formalProjection, runtimeProjection),
    };
}
