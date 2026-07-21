// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Model-to-Matter: a frontier-model proposal may reach a physical executor only
// after six signed evidence legs satisfy the executor's profile.
//
//   node examples/model-to-matter/demo.mjs
//
// This demonstration uses opaque commitments and synthetic identities. It does
// not contain a biological sequence, operate laboratory equipment, or claim to
// perform biological screening.
import crypto from 'node:crypto';
import { M2M_EVIDENCE_TYPES, buildModelToMatterGraph, createModelToMatterAction, createModelToMatterExecutor, createModelToMatterProfile, modelToMatterActionDigest, signModelToMatterEffect, signModelToMatterEvidence, verifyModelToMatterEffect, } from '../../lib/frontier/model-to-matter.js';
import { createDurableChallengeStore } from '../../packages/gate/challenge-store.js';
import { createDurableConsumptionStore, createMemoryBackend } from '../../packages/gate/store.js';
const NOW = '2026-07-11T16:00:00Z';
const EVIDENCE_EXPIRES = '2026-07-11T16:10:00Z';
const digest = (label) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const keyPair = () => crypto.generateKeyPairSync('ed25519').privateKey;
const publicKey = (privateKey) => crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
const issuerKeys = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, keyPair()]));
const executorKey = keyPair();
const action = createModelToMatterAction({
    action_type: 'science.bio.experiment.execute.1',
    model: {
        provider: 'example-frontier-lab',
        model_id: 'frontier-bio-model-2026-07',
        manifest_digest: digest('model-manifest'),
        harness_digest: digest('agent-harness'),
        safeguards_digest: digest('deployment-safeguards'),
    },
    experiment: {
        protocol_digest: digest('synthetic-benign-protocol'),
        materials_commitment: digest('opaque-materials'),
        expected_effects_digest: digest('approved-effect-criteria'),
    },
    principal: {
        organization_id: 'org:example-research-institute',
        principal_id: 'researcher:alice',
    },
    executor: {
        executor_id: 'cloud-lab:example',
        facility_id: 'facility:demo-01',
    },
    purpose: { code: 'defensive-research', jurisdiction: 'US' },
    destination_digest: digest('approved-destination'),
    requested_at: '2026-07-11T15:58:00Z',
    max_executions: 1,
});
const acceptedIssuers = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, [{
            issuer_id: `issuer:${type}`,
            public_key: publicKey(issuerKeys[type]),
        }]]));
const profile = createModelToMatterProfile({
    profile_id: 'ep:m2m:frontier-bio-research:v1',
    accepted_issuers: acceptedIssuers,
});
function claimsFor(type) {
    const claims = {
        model_attestation: {
            provider: action.model.provider,
            model_id: action.model.model_id,
            manifest_digest: action.model.manifest_digest,
            harness_digest: action.model.harness_digest,
            safeguards_digest: action.model.safeguards_digest,
        },
        safety_case_attestation: {
            manifest_digest: action.model.manifest_digest,
            harness_digest: action.model.harness_digest,
            safeguards_digest: action.model.safeguards_digest,
            safety_case_digest: digest('model-safety-case'),
            assessment: 'acceptable',
        },
        institutional_authority: {
            organization_id: action.principal.organization_id,
            principal_id: action.principal.principal_id,
            action_type: action.action_type,
            purpose_code: action.purpose.code,
            decision: 'allow',
        },
        biosafety_review: {
            protocol_digest: action.experiment.protocol_digest,
            materials_commitment: action.experiment.materials_commitment,
            facility_id: action.executor.facility_id,
            decision: 'approve',
        },
        domain_screening: {
            materials_commitment: action.experiment.materials_commitment,
            destination_digest: action.destination_digest,
            screening_profile_digest: digest('screening-policy'),
            decision: 'pass',
        },
        human_authorization: {
            approver_id: 'person:responsible-investigator',
            decision: 'approve',
            assurance_class: 'class_a',
        },
    };
    return claims[type];
}
function signEvidence(type, privateKey = issuerKeys[type]) {
    return signModelToMatterEvidence({
        evidence_type: type,
        action_digest: modelToMatterActionDigest(action),
        issuer_id: `issuer:${type}`,
        issued_at: '2026-07-11T15:59:00Z',
        expires_at: EVIDENCE_EXPIRES,
        claims: claimsFor(type),
    }, privateKey);
}
const evidence = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, signEvidence(type)]));
const allEvidence = () => M2M_EVIDENCE_TYPES.map((type) => evidence[type]);
const actionClearanceBackend = createMemoryBackend();
function executorFor(challengeStore, revokedEvidenceDigests = new Set()) {
    return createModelToMatterExecutor({
        profile,
        challengeStore,
        clearanceStore: createDurableConsumptionStore(actionClearanceBackend),
        revocationProvider: async () => new Set(revokedEvidenceDigests),
        allowEphemeralState: true,
        now: () => Date.parse(NOW),
    });
}
async function evaluateOnce(label, artifacts, revokedEvidenceDigests = new Set()) {
    const challengeStore = createDurableChallengeStore(createMemoryBackend());
    const executor = executorFor(challengeStore, revokedEvidenceDigests);
    const challenge = await executor.issueChallenge(action, {
        nonce: `model-to-matter-${label.replaceAll(' ', '-')}`,
    });
    return executor.evaluate({
        action,
        challenge,
        graph: buildModelToMatterGraph(action, artifacts),
    });
}
console.log('\nMODEL-TO-MATTER: frontier proposal -> physical executor\n');
console.log(`STRUCTURE PASS  action is well-formed (${modelToMatterActionDigest(action).slice(0, 27)}...)`);
console.log('                Structural validity is not permission to execute.\n');
const rows = [];
const missing = await evaluateOnce('missing-screening', allEvidence().filter((artifact) => artifact.evidence_type !== 'domain_screening'));
rows.push(['screening evidence absent', missing.verdict, 'do_not_execute_missing_evidence']);
const attackerKey = keyPair();
const unpinned = allEvidence().map((artifact) => artifact.evidence_type === 'domain_screening'
    ? signEvidence('domain_screening', attackerKey) : artifact);
const laundered = await evaluateOnce('issuer-laundering', unpinned);
rows.push(['screening issuer key substituted', laundered.verdict, 'do_not_execute_unverifiable']);
const revoked = await evaluateOnce('revoked-human', allEvidence(), new Set([evidence.human_authorization.signature.evidence_digest]));
rows.push(['human authorization revoked', revoked.verdict, 'do_not_execute_stale_evidence']);
const mutationBackend = createMemoryBackend();
const mutationChallengeStore = createDurableChallengeStore(mutationBackend);
const mutationExecutor = executorFor(mutationChallengeStore);
const mutationChallenge = await mutationExecutor.issueChallenge(action, {
    nonce: 'model-to-matter-action-mutation',
});
const mutatedAction = createModelToMatterAction({
    ...structuredClone(action),
    destination_digest: digest('substituted-destination'),
});
const mutationResult = await mutationExecutor.evaluate({
    action: mutatedAction,
    challenge: mutationChallenge,
    graph: buildModelToMatterGraph(action, allEvidence()),
});
rows.push(['destination changed after challenge', mutationResult.verdict, 'do_not_execute_action_mismatch']);
const backend = createMemoryBackend();
const challengeStore = createDurableChallengeStore(backend);
const executor = executorFor(challengeStore);
const challenge = await executor.issueChallenge(action, {
    nonce: 'model-to-matter-one-time-clearance',
});
const graph = buildModelToMatterGraph(action, allEvidence());
const presentations = await Promise.all([0, 1].map(() => executor.evaluate({
    action,
    challenge,
    graph,
})));
// Exactly one of the two concurrent presentations against this single-use
// challenge is guaranteed to clear (see evaluateRegisteredModelToMatterPresentation's
// atomic challenge/action consumption); the other is refused. The type-checker
// can't see that store-level invariant, so narrow explicitly.
const cleared = /** @type {typeof presentations[number]} */ (presentations.find((result) => result.verdict === 'clear_to_execute'));
const refused = presentations.find((result) => result.verdict === 'do_not_execute_refused');
rows.push(['first concurrent presentation', cleared?.verdict, 'clear_to_execute']);
rows.push(['duplicate concurrent presentation', refused?.verdict, 'do_not_execute_refused']);
const effect = signModelToMatterEffect({
    action,
    clearance: cleared,
    executor_id: action.executor.executor_id,
    executed_at: '2026-07-11T16:01:00Z',
    status: 'completed',
    observed_effect_digest: digest('opaque-observed-result'),
}, executorKey);
const effectResult = verifyModelToMatterEffect(effect, {
    expectedAction: action,
    expectedClearanceReplayDigest: cleared.replay_digest,
    pinnedExecutorKeys: [{ executor_id: action.executor.executor_id, public_key: publicKey(executorKey) }],
});
rows.push(['executor effect statement', effectResult.accepted ? 'accepted' : effectResult.reason, 'accepted']);
const tamperedEffect = verifyModelToMatterEffect({ ...effect, status: 'failed' }, {
    expectedAction: action,
    expectedClearanceReplayDigest: cleared.replay_digest,
    pinnedExecutorKeys: [{ executor_id: action.executor.executor_id, public_key: publicKey(executorKey) }],
});
rows.push(['tampered effect statement', tamperedEffect.accepted ? 'accepted' : tamperedEffect.reason, 'digest_mismatch']);
for (const [label, actual] of rows) {
    const prefix = actual === 'clear_to_execute' || actual === 'accepted' ? 'CLEAR ' : 'REFUSE';
    console.log(`${prefix.padEnd(7)} ${label.padEnd(42)} -> ${actual}`);
}
const ok = rows.every(([, actual, expected]) => actual === expected);
console.log(`\n${ok ? 'OK' : 'FAILED'}: one exact action cleared once; every missing, substituted, revoked, mutated, replayed, or tampered path refused.`);
console.log('Boundary: the effect receipt proves what the pinned executor signed, not independent physical truth.\n');
process.exit(ok ? 0 : 1);
