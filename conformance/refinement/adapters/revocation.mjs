// SPDX-License-Identifier: Apache-2.0
// Generated from revocation.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from "node:crypto";
import { REVOCATION_VERSION, isRevoked, verifyRevocation, } from "../../../packages/verify/revocation.js";
import { canonicalize } from "../../../packages/verify/index.js";
const TARGET = Object.freeze({
    target_type: "receipt",
    target_id: "rcpt_refinement_001",
    action_hash: `sha256:${"a".repeat(64)}`,
});
const REVOKER_ID = "ep:revoker:refinement";
const EFFECTIVE_AT = "2026-06-20T12:00:00.000Z";
const FUTURE_AT = "2026-06-21T12:00:00.000Z";
const DECISION_TIME = "2026-06-20T12:00:00.000Z";
const LATER_DECISION_TIME = "2036-06-20T12:00:00.000Z";
function deterministicEd25519Fixture() {
    // RFC 8032 section 7.1, test vector 1. This is a public test key only.
    const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc4" + "4449c5697b326919703bac031cae7f60", "hex");
    const publicKeyDer = Buffer.from("302a300506032b6570032100" +
        "d75a980182b10ab7d54bfed3c964073a" +
        "0ee172f3daa62325af021a68f707511a", "hex");
    const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    return {
        privateKey: crypto.createPrivateKey({
            key: Buffer.concat([pkcs8Prefix, seed]),
            format: "der",
            type: "pkcs8",
        }),
        publicKeyB64u: publicKeyDer.toString("base64url"),
    };
}
function assertRuntime(condition, message) {
    if (!condition)
        throw new Error(`revocation refinement failed: ${message}`);
}
function revokerKeyId(publicKeyB64u) {
    return `ep:revoker-key:sha256:${crypto
        .createHash("sha256")
        .update(Buffer.from(publicKeyB64u, "base64url"))
        .digest("hex")}`;
}
function buildStatement(privateKey, publicKeyB64u, revokedAt) {
    const signedFields = {
        "@version": REVOCATION_VERSION,
        action_hash: TARGET.action_hash,
        reason: "authority withdrawn",
        revoked_at: revokedAt,
        revoker_id: REVOKER_ID,
        target_id: TARGET.target_id,
        target_type: TARGET.target_type,
    };
    return {
        ...signedFields,
        proof: {
            algorithm: "Ed25519",
            revoker_key_id: revokerKeyId(publicKeyB64u),
            public_key: publicKeyB64u,
            signature_b64u: crypto
                .sign(null, Buffer.from(canonicalize(signedFields), "utf8"), privateKey)
                .toString("base64url"),
        },
    };
}
function projection(now, revoked, lastRevocationVerdict) {
    return {
        now,
        revoked,
        lastRevocationVerdict,
    };
}
export async function runRevocationScenario(scenario) {
    if (!["revocation-effective-terminal", "revocation-future-refused"].includes(scenario)) {
        throw new Error(`unsupported revocation refinement scenario: ${scenario}`);
    }
    const { privateKey, publicKeyB64u } = deterministicEd25519Fixture();
    const revokerKeys = {
        [REVOKER_ID]: {
            public_key: publicKeyB64u,
            key_id: revokerKeyId(publicKeyB64u),
        },
    };
    if (scenario === "revocation-future-refused") {
        const futureStatement = buildStatement(privateKey, publicKeyB64u, FUTURE_AT);
        const refused = verifyRevocation(TARGET, futureStatement, {
            revokerKeys,
            now: DECISION_TIME,
        });
        assertRuntime(!refused.valid &&
            refused.checks.effective_at_or_before_T === false &&
            !isRevoked(TARGET, [futureStatement], {
                revokerKeys,
                now: DECISION_TIME,
            }), "future revocation was accepted before its effective instant");
        return {
            scenario,
            steps: [
                {
                    operator: "AdvanceTimeToOne",
                    accepted: true,
                    projection: projection(1, false, "none"),
                },
                {
                    operator: "RefuseTerminalRevocation(RevFutureA, TargetA)",
                    accepted: false,
                    projection: projection(1, false, "refused"),
                },
            ],
        };
    }
    const statement = buildStatement(privateKey, publicKeyB64u, EFFECTIVE_AT);
    const effective = verifyRevocation(TARGET, statement, {
        revokerKeys,
        now: DECISION_TIME,
    });
    assertRuntime(effective.valid &&
        isRevoked(TARGET, [statement], {
            revokerKeys,
            now: DECISION_TIME,
        }), `effective revocation was refused: ${effective.errors.join("; ")}`);
    const stillEffective = verifyRevocation(TARGET, statement, {
        revokerKeys,
        maxAgeSeconds: 1,
        now: LATER_DECISION_TIME,
    });
    assertRuntime(stillEffective.valid &&
        isRevoked(TARGET, [statement], {
            revokerKeys,
            maxAgeSeconds: 1,
            now: LATER_DECISION_TIME,
        }), "terminal revocation aged out under a later trusted decision time");
    return {
        scenario,
        steps: [
            {
                operator: "AdvanceTimeToOne",
                accepted: true,
                projection: projection(1, false, "none"),
            },
            {
                operator: "AcceptTerminalRevocation(RevGoodA, TargetA)",
                accepted: true,
                projection: projection(1, true, "accepted"),
            },
            {
                operator: "AdvanceTimeToMax",
                accepted: true,
                projection: projection(4, true, "accepted"),
            },
        ],
    };
}
