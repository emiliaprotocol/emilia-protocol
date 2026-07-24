// SPDX-License-Identifier: Apache-2.0
// Generated from action-escrow.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { ACTION_ESCROW_PROFILE_VERSION, computeActionEscrowReleaseBindingMomentDigest, computeActionEscrowResolutionNonce, createActionEscrowKernel, } from "../../../packages/gate/dist/action-escrow.js";
import { canonicalize, hashCanonical, } from "../../../packages/gate/dist/execution-binding.js";
const EXACT_CAID = "caid:exact-action";
const digest = (character) => `sha256:${character.repeat(64)}`;
const AGREEMENT_DIGEST = digest("a");
const BINDING_DIGEST = digest("b");
const RELEASE_ACTION_DIGEST = digest("c");
const EVIDENCE_DIGEST = digest("d");
const FIXED_NOW = "2026-07-17T12:00:00.000Z";
const PARTIES = Object.freeze([
    Object.freeze({ party_id: "ep:principal:client", role: "client" }),
    Object.freeze({ party_id: "ep:principal:contractor", role: "contractor" }),
]);
const PROFILE = Object.freeze({
    "@version": ACTION_ESCROW_PROFILE_VERSION,
    profile_id: "contractor-milestone-release",
    provider_id: "provider.refinement",
    required_acceptance_party_ids: Object.freeze(PARTIES.map(({ party_id: partyId }) => partyId)),
    required_release_approver_party_ids: Object.freeze(PARTIES.map(({ party_id: partyId }) => partyId)),
    prohibit_self_approval: false,
});
const PROFILE_DIGEST = `sha256:${hashCanonical(PROFILE)}`;
const RELEASE_ACTION_TEMPLATE = Object.freeze({
    action_type: "escrow.milestone.release",
    action_escrow_profile_digest: PROFILE_DIGEST,
    agreement_id: "agreement-refinement-01",
    agreement_digest: AGREEMENT_DIGEST,
    milestone_id: "milestone-01",
    amount: "18400.00",
    currency: "USD",
    destination_id: "custody-destination-refinement",
    payee_id: "ep:principal:contractor",
    custodian_provider: "licensed-custodian.refinement",
    custodian_environment: "sandbox",
    custodian_transaction_id: "provider-transaction-refinement-001",
    custodian_milestone_id: "provider-milestone-refinement-001",
    document_sha256: digest("4"),
    material_terms_sha256: digest("5"),
    completion_evidence_sha256: EVIDENCE_DIGEST,
    amendment_version: 1,
});
function durableCasStore() {
    const values = new Map();
    return {
        durable: true,
        atomicExpectedRevisionCas: true,
        linearizableReads: true,
        monotonicRevisions: true,
        nonExpiring: true,
        async read(key) {
            const current = values.get(key);
            return current ? { ...current } : null;
        },
        async compareAndSwap(key, expectedRevision, value) {
            const current = values.get(key);
            const currentRevision = current?.revision ?? null;
            if (currentRevision !== expectedRevision) {
                return { applied: false, revision: currentRevision };
            }
            const revision = expectedRevision === null ? 0 : expectedRevision + 1;
            values.set(key, { revision, value });
            return { applied: true, revision };
        },
        latestRecord() {
            const envelope = [...values.values()].at(-1);
            return envelope
                ? JSON.parse(envelope.value)
                : null;
        },
    };
}
function common(idempotencyKey, overrides = {}) {
    return {
        agreement_digest: AGREEMENT_DIGEST,
        document_action_binding_digest: BINDING_DIGEST,
        milestone_id: "milestone-01",
        release_action_digest: RELEASE_ACTION_DIGEST,
        parties: PARTIES,
        profile: PROFILE,
        idempotency_key: idempotencyKey,
        ...overrides,
    };
}
function bindingArtifact() {
    return {
        kind: "document_action_binding",
        agreement_digest: AGREEMENT_DIGEST,
        document_action_binding_digest: BINDING_DIGEST,
        milestone_id: "milestone-01",
        release_action_digest: RELEASE_ACTION_DIGEST,
    };
}
function acceptanceArtifact(partyId) {
    return {
        kind: "e_sign_acceptance",
        party_id: partyId,
        principal_key_id: `key:${partyId}`,
        agreement_digest: AGREEMENT_DIGEST,
        document_action_binding_digest: BINDING_DIGEST,
    };
}
function milestoneEvidence() {
    return {
        kind: "milestone_evidence",
        evidence_digest: EVIDENCE_DIGEST,
        submitter_party_id: "ep:principal:contractor",
        observed_at: "2026-07-17T11:59:00.000Z",
    };
}
function resolutionBindingInput() {
    return {
        agreement_digest: AGREEMENT_DIGEST,
        document_action_binding_digest: BINDING_DIGEST,
        milestone_id: "milestone-01",
        release_action_digest: RELEASE_ACTION_DIGEST,
        profile_digest: PROFILE_DIGEST,
        evidence_digest: EVIDENCE_DIGEST,
        release_action_template: RELEASE_ACTION_TEMPLATE,
    };
}
function resolution(partyId) {
    const binding = resolutionBindingInput();
    return {
        profile: "EP-RESOLUTION-v1",
        signoff: {
            context: {
                principal: partyId,
                principal_key_id: `key:${partyId}`,
                initiator: "ep:principal:contractor",
                envelope_hash: computeActionEscrowReleaseBindingMomentDigest(binding),
                action_hash: RELEASE_ACTION_DIGEST,
                nonce: computeActionEscrowResolutionNonce(binding, partyId),
                issued_at: FIXED_NOW,
                expires_at: "2026-07-17T12:05:00.000Z",
                resolution: { outcome: "approved", selected_option: 0 },
            },
        },
    };
}
function fundingStatement() {
    return {
        statement_type: "funding",
        status: "funded",
        statement_digest: digest("e"),
    };
}
function releaseStatement(providerIdempotencyKey) {
    return {
        statement_type: "release",
        status: "released",
        statement_digest: digest("f"),
        provider_idempotency_key: providerIdempotencyKey,
    };
}
function verifierBindings(expected) {
    return {
        agreement_digest: expected.agreement_digest,
        document_action_binding_digest: expected.document_action_binding_digest,
        milestone_id: expected.milestone_id,
        release_action_digest: expected.release_action_digest,
        parties_digest: expected.parties_digest,
        profile_digest: expected.profile_digest,
    };
}
function defaultVerifiers() {
    return {
        async verifyDocumentActionBinding(artifact, expected) {
            if (artifact?.kind !== "document_action_binding")
                return { valid: false };
            return {
                valid: true,
                verification_digest: digest("1"),
                document_digest: digest("4"),
                agreement_id: "agreement-refinement-01",
                binding_id: "binding-refinement-01",
                release_action_template: {
                    ...RELEASE_ACTION_TEMPLATE,
                    action_escrow_profile_digest: expected.profile_digest,
                    agreement_digest: expected.agreement_digest,
                    milestone_id: expected.milestone_id,
                },
                ...verifierBindings(expected),
                agreement_digest: artifact.agreement_digest,
                document_action_binding_digest: artifact.document_action_binding_digest,
                milestone_id: artifact.milestone_id,
                release_action_digest: artifact.release_action_digest,
            };
        },
        async verifyAgreementAcceptance(artifact, expected) {
            if (artifact?.kind !== "e_sign_acceptance")
                return { valid: false };
            return {
                valid: true,
                acceptance_digest: digest(artifact.party_id.endsWith("client") ? "2" : "3"),
                party_id: artifact.party_id,
                principal_key_id: artifact.principal_key_id,
                ...verifierBindings(expected),
                agreement_digest: artifact.agreement_digest,
                document_action_binding_digest: artifact.document_action_binding_digest,
            };
        },
        async verifyMilestoneEvidence(artifact, expected) {
            if (artifact?.kind !== "milestone_evidence")
                return { valid: false };
            return {
                valid: true,
                evidence_digest: artifact.evidence_digest,
                submitter_party_id: artifact.submitter_party_id,
                observed_at: artifact.observed_at,
                ...verifierBindings(expected),
            };
        },
        async verifyResolutionReceipt(artifact, expected) {
            const context = artifact?.signoff?.context ?? {};
            const outcome = context.resolution?.outcome;
            const party = expected.parties.find(({ party_id: partyId }) => partyId === context.principal);
            const valid = artifact?.profile === "EP-RESOLUTION-v1" &&
                context.envelope_hash === expected.binding_moment_digest &&
                context.initiator === expected.expected_initiator &&
                context.nonce === expected.expected_nonce &&
                context.resolution?.selected_option ===
                    expected.expected_selected_option &&
                expected.evaluation_time === FIXED_NOW;
            return {
                valid,
                authorizes_action: valid && outcome === "approved",
                outcome,
                party_id: context.principal,
                party_role: party?.role,
                principal_key_id: context.principal_key_id,
                nonce: context.nonce,
                issued_at: context.issued_at,
                expires_at: context.expires_at,
                evidence_digest: expected.evidence_digest,
                ...verifierBindings(expected),
            };
        },
        async verifyProviderStatement(statement, expected) {
            return {
                valid: statement?.valid !== false,
                authenticated: statement?.authenticated !== false,
                statement_type: statement?.statement_type,
                status: statement?.status,
                statement_digest: statement?.statement_digest,
                provider_id: expected.provider_id,
                ...verifierBindings(expected),
                ...(expected.provider_transaction_id === undefined
                    ? {}
                    : {
                        provider_transaction_id: expected.provider_transaction_id,
                        provider_milestone_id: expected.provider_milestone_id,
                        amount: expected.amount,
                        currency: expected.currency,
                        destination_id: expected.destination_id,
                    }),
                ...(statement?.provider_idempotency_key === undefined
                    ? {}
                    : {
                        provider_idempotency_key: statement.provider_idempotency_key,
                    }),
                ...(expected.provider_request_digest === undefined
                    ? {}
                    : {
                        provider_request_digest: expected.provider_request_digest,
                    }),
                ...(statement?.override_bindings ?? {}),
            };
        },
        async verifyStateCommand() {
            return { valid: false, authorizes_command: false };
        },
    };
}
function assertRuntime(condition, message) {
    if (!condition)
        throw new Error(`action escrow refinement failed: ${message}`);
}
function projection(aeState, aeReleaseCount, aeDuplicateRefused) {
    return {
        aeState,
        aeMilestoneCaid: EXACT_CAID,
        aeReleaseCount,
        aeDuplicateRefused,
    };
}
async function prepareRelease(kernel) {
    let result = (await kernel.create(common("create", {
        document_action_binding: bindingArtifact(),
    })));
    assertRuntime(result.ok && result.state === "draft", "create was refused");
    result = (await kernel.beginAcceptance(common("begin-acceptance")));
    assertRuntime(result.ok && result.state === "awaiting_acceptance", "acceptance opening was refused");
    for (const party of PARTIES) {
        result = (await kernel.acceptAgreement(common(`accept-${party.role}`, {
            party_id: party.party_id,
            agreement_acceptance: acceptanceArtifact(party.party_id),
        })));
        assertRuntime(result.ok, `agreement acceptance failed for ${party.role}`);
    }
    assertRuntime(result.state === "effective", "agreement did not become effective");
    result = (await kernel.requestFunding(common("request-funding")));
    assertRuntime(result.ok && result.state === "awaiting_funding", "funding request was refused");
    result = (await kernel.recordFunding(common("record-funding", {
        provider_statement: fundingStatement(),
    })));
    assertRuntime(result.ok && result.state === "funded", "funding evidence was refused");
    result = (await kernel.submitMilestone(common("submit-milestone", {
        milestone_evidence: milestoneEvidence(),
    })));
    assertRuntime(result.ok && result.state === "milestone_submitted", "exact milestone evidence was refused");
    for (const party of PARTIES) {
        const approval = (await kernel.approveRelease(common(`approve-${party.role}`, {
            party_id: party.party_id,
            resolution: resolution(party.party_id),
        })));
        assertRuntime(approval.ok && approval.state === "milestone_submitted", `release approval failed for ${party.role}`);
    }
}
export async function runActionEscrowScenario(scenario) {
    if (!["escrow-release-once", "escrow-duplicate-release-refused"].includes(scenario)) {
        throw new Error(`unsupported action escrow refinement scenario: ${scenario}`);
    }
    const store = durableCasStore();
    let releaseCalls = 0;
    let getReleaseCalls = 0;
    let observedReservedState = false;
    const provider = {
        async release(request) {
            releaseCalls += 1;
            observedReservedState =
                store.latestRecord()?.state === "release_reserved";
            return {
                authenticated: true,
                statement: releaseStatement(request.idempotency_key),
            };
        },
        async getRelease(request) {
            getReleaseCalls += 1;
            return {
                authenticated: true,
                statement: releaseStatement(request.idempotency_key),
            };
        },
    };
    const kernel = createActionEscrowKernel({
        store,
        provider,
        profilesById: { [PROFILE.profile_id]: PROFILE },
        now: () => FIXED_NOW,
        ...defaultVerifiers(),
    });
    assertRuntime(kernel.ready, `kernel configuration refused: ${kernel.configuration.reason}`);
    await prepareRelease(kernel);
    const steps = [
        {
            operator: "SubmitExactMilestone",
            accepted: true,
            projection: projection("milestone_exact", 0, false),
        },
    ];
    const released = (await kernel.release(common("release-operation")));
    assertRuntime(observedReservedState, "provider did not observe the durable release reservation");
    assertRuntime(released.ok &&
        released.code === "release_committed" &&
        released.state === "released" &&
        releaseCalls === 1 &&
        getReleaseCalls === 1, "the exact milestone was not released exactly once");
    steps.push({
        operator: "ReserveEscrowRelease",
        accepted: true,
        projection: projection("release_reserved", 0, false),
    }, {
        operator: "ReleaseEscrow",
        accepted: true,
        projection: projection("released", 1, false),
    });
    if (scenario === "escrow-duplicate-release-refused") {
        const duplicate = (await kernel.release(common("release-operation-replay")));
        assertRuntime(!duplicate.ok &&
            duplicate.code === "release_already_applied" &&
            duplicate.state === "released" &&
            releaseCalls === 1 &&
            getReleaseCalls === 1, "duplicate release was not refused before provider reinvocation");
        steps.push({
            operator: "AttemptDuplicateEscrowRelease",
            accepted: false,
            projection: projection("released", 1, true),
        });
    }
    return { scenario, steps };
}
