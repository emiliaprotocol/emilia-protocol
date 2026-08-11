#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from human-authorization-binding-vector.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Human-authorization binding vector — B1..B7 from
// draft-schrock-human-authorization-binding, deterministic.
// Run: node examples/binding/human-authorization-binding-vector.mjs
import crypto from 'node:crypto';
import { canonicalize } from '../../packages/verify/index.js';
const canon = (o) => Buffer.from(canonicalize(o), 'utf8');
const digest = (o) => 'sha256:' + crypto.createHash('sha256').update(canon(o)).digest('hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const keyPair = (label) => {
    const seed = crypto.createHash('sha256').update(label).digest();
    const privateKey = crypto.createPrivateKey({
        key: Buffer.concat([PKCS8, seed]),
        format: 'der',
        type: 'pkcs8',
    });
    const publicKey = crypto.createPublicKey(privateKey)
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    return { privateKey, publicKey };
};
const approver = keyPair('ep:binding-vector:approver:v2');
const directory = keyPair('ep:binding-vector:directory:v2');
const discoveredDirectory = keyPair('ep:binding-vector:discovered-directory:v2');
const ACTION_DIGEST = 'sha256:' + 'a'.repeat(64);
const NOW = 1786464000;
const enrollmentPayload = {
    typ: 'approver_enrollment',
    subject: 'ops-lead@example.com',
    subject_kind: 'human',
    subject_key: approver.publicKey,
    issuer: 'directory:operations',
    valid_from: NOW - 3600,
    valid_until: NOW + 3600,
    status: 'active',
};
const enrollment = {
    payload: enrollmentPayload,
    sig: crypto.sign(null, canon(enrollmentPayload), directory.privateKey).toString('base64url'),
    issuer_key: directory.publicKey,
};
const rolePayload = {
    typ: 'principal_role_binding',
    delegating_principal: 'service:release-orchestrator',
    terminal_authority: 'org:operations',
    per_action_approver: 'ops-lead@example.com',
    logical_agent: 'agent:release-manager',
    workload_instance: 'spiffe://example.test/release-manager/instance-7',
    oauth_client: 'client:release-manager',
    executor: 'service:deployment-gate',
    target_tool: 'tool:deploy-model',
    valid_from: NOW - 3600,
    valid_until: NOW + 3600,
};
const roleEvidence = {
    payload: rolePayload,
    sig: crypto.sign(null, canon(rolePayload), directory.privateKey).toString('base64url'),
    issuer_key: directory.publicKey,
};
// The authorization artifact (stand-in for an EP receipt; verifies under its own rules)
const payload = { typ: 'authorization_receipt', action_digest: ACTION_DIGEST, approver: 'ops-lead@example.com' };
export const artifact = {
    payload,
    sig: crypto.sign(null, canon(payload), approver.privateKey).toString('base64url'),
    approver_key: approver.publicKey,
    approver_enrollment: enrollment,
};
const ARTIFACT_DIGEST = digest(artifact);
// A host record (capsule/permit-shaped) binding it BY REFERENCE
export const host = {
    typ: 'agent-action-capsule', action_digest: ACTION_DIGEST, outcome: 'executed',
    human_authorization_ref: { digest: ARTIFACT_DIGEST, format: 'ep-receipt' },
    principal_role_evidence: roleEvidence,
};
export function verifyBinding(hostRec, art, policy = {}) {
    const checks = {
        b1_digest: false,
        artifact_sig: false,
        b2_action: false,
        b3_accepted_issuer: false,
        b5_consistent_forms: true,
        b6_approver_attribution: false,
        b7_role_non_equivalence: false,
    };
    const ref = hostRec?.human_authorization_ref;
    if (!ref?.digest || !art)
        return { verified: false, accepted: false, checks }; // B4: absence fails closed
    checks.b1_digest = digest(art) === ref.digest;
    try {
        const k = crypto.createPublicKey({ key: Buffer.from(art.approver_key, 'base64url'), type: 'spki', format: 'der' });
        checks.artifact_sig = crypto.verify(null, canon(art.payload), k, Buffer.from(art.sig, 'base64url'));
    }
    catch {
        checks.artifact_sig = false;
    }
    checks.b2_action = art.payload?.action_digest === hostRec.action_digest;
    if (hostRec.human_authorization !== undefined) {
        checks.b5_consistent_forms = digest(hostRec.human_authorization) === ref.digest;
    }
    const enrolled = art.approver_enrollment;
    try {
        const issuerKey = enrolled?.issuer_key;
        const enrollmentKey = crypto.createPublicKey({
            key: Buffer.from(issuerKey, 'base64url'),
            type: 'spki',
            format: 'der',
        });
        const enrollmentSignatureValid = crypto.verify(null, canon(enrolled.payload), enrollmentKey, Buffer.from(enrolled.sig, 'base64url'));
        checks.b3_accepted_issuer = enrollmentSignatureValid
            && (policy.pinnedEnrollmentIssuerKeys ?? []).includes(issuerKey);
        checks.b6_approver_attribution = enrollmentSignatureValid
            && enrolled.payload?.subject_kind === 'human'
            && enrolled.payload?.subject === art.payload?.approver
            && enrolled.payload?.subject_key === art.approver_key
            && enrolled.payload?.status === 'active'
            && enrolled.payload?.valid_from <= (policy.now ?? NOW)
            && enrolled.payload?.valid_until > (policy.now ?? NOW)
            && (!policy.expectedApprover || enrolled.payload?.subject === policy.expectedApprover);
    }
    catch {
        checks.b3_accepted_issuer = false;
        checks.b6_approver_attribution = false;
    }
    try {
        const roles = hostRec.principal_role_evidence;
        const roleIssuerKey = roles?.issuer_key;
        const roleKey = crypto.createPublicKey({
            key: Buffer.from(roleIssuerKey, 'base64url'),
            type: 'spki',
            format: 'der',
        });
        const roleSignatureValid = crypto.verify(null, canon(roles.payload), roleKey, Buffer.from(roles.sig, 'base64url'));
        const expectedRoles = policy.requiredRoles ?? {};
        checks.b7_role_non_equivalence = roleSignatureValid
            && (policy.pinnedRoleIssuerKeys ?? []).includes(roleIssuerKey)
            && roles.payload?.valid_from <= (policy.now ?? NOW)
            && roles.payload?.valid_until > (policy.now ?? NOW)
            && Object.entries(expectedRoles).every(([name, value]) => roles.payload?.[name] === value);
    }
    catch {
        checks.b7_role_non_equivalence = false;
    }
    const verified = checks.b1_digest && checks.artifact_sig
        && checks.b2_action && checks.b5_consistent_forms;
    return {
        verified,
        accepted: verified && checks.b3_accepted_issuer
            && checks.b6_approver_attribution && checks.b7_role_non_equivalence,
        checks,
    };
}
// Positive: verified + accepted with pinned issuer
const acceptancePolicy = {
    pinnedEnrollmentIssuerKeys: [directory.publicKey],
    expectedApprover: 'ops-lead@example.com',
    pinnedRoleIssuerKeys: [directory.publicKey],
    requiredRoles: {
        delegating_principal: 'service:release-orchestrator',
        terminal_authority: 'org:operations',
        per_action_approver: 'ops-lead@example.com',
        logical_agent: 'agent:release-manager',
        workload_instance: 'spiffe://example.test/release-manager/instance-7',
        oauth_client: 'client:release-manager',
        executor: 'service:deployment-gate',
        target_tool: 'tool:deploy-model',
    },
    now: NOW,
};
const pos = verifyBinding(host, artifact, acceptancePolicy);
if (!pos.accepted)
    throw new Error('positive failed: ' + JSON.stringify(pos.checks));
// B1: tampered artifact no longer hashes to the reference
const tampered = { ...artifact, payload: { ...payload, approver: 'mallory' } };
if (verifyBinding(host, tampered, acceptancePolicy).verified)
    throw new Error('B1 not enforced');
// B2: genuine artifact for a DIFFERENT action is invalid, not weak
const otherPayload = { ...payload, action_digest: 'sha256:' + 'b'.repeat(64) };
const other = {
    ...artifact,
    payload: otherPayload,
    sig: crypto.sign(null, canon(otherPayload), approver.privateKey).toString('base64url'),
};
const hostOther = { ...host, human_authorization_ref: { digest: digest(other), format: 'ep-receipt' } };
if (verifyBinding(hostOther, other, acceptancePolicy).verified)
    throw new Error('B2 not enforced');
// B3: discovered verification material is not a relying-party trust decision.
const discoveredEnrollment = {
    payload: enrollmentPayload,
    sig: crypto.sign(null, canon(enrollmentPayload), discoveredDirectory.privateKey).toString('base64url'),
    issuer_key: discoveredDirectory.publicKey,
};
const discoveredArtifact = { ...artifact, approver_enrollment: discoveredEnrollment };
const discoveredHost = {
    ...host,
    human_authorization_ref: { digest: digest(discoveredArtifact), format: 'ep-receipt' },
};
const un = verifyBinding(discoveredHost, discoveredArtifact, acceptancePolicy);
if (!un.verified || un.accepted)
    throw new Error('B3 not enforced');
// B4: absent binding is absence of evidence
if (verifyBinding({ ...host, human_authorization_ref: undefined }, artifact, acceptancePolicy).verified) {
    throw new Error('B4 not enforced');
}
// B5: embedded and referenced forms cannot tell two different stories.
const inconsistentHost = {
    ...host,
    human_authorization: { ...artifact, payload: { ...payload, approver: 'mallory' } },
};
if (verifyBinding(inconsistentHost, artifact, acceptancePolicy).verified) {
    throw new Error('B5 not enforced');
}
// B6: a name and a valid self-signature do not establish named-human identity.
const { approver_enrollment: _omittedEnrollment, ...selfAsserted } = artifact;
const selfAssertedHost = {
    ...host,
    human_authorization_ref: { digest: digest(selfAsserted), format: 'ep-receipt' },
};
const selfAssertedResult = verifyBinding(selfAssertedHost, selfAsserted, acceptancePolicy);
if (!selfAssertedResult.verified || selfAssertedResult.accepted) {
    throw new Error('B6 self-asserted identity not refused');
}
// B6: a valid signing key enrolled to one human cannot be relabeled as another.
const relabeledPayload = { ...payload, approver: 'finance-lead@example.com' };
const relabeled = {
    ...artifact,
    payload: relabeledPayload,
    sig: crypto.sign(null, canon(relabeledPayload), approver.privateKey).toString('base64url'),
};
const relabeledHost = {
    ...host,
    human_authorization_ref: { digest: digest(relabeled), format: 'ep-receipt' },
};
const relabeledResult = verifyBinding(relabeledHost, relabeled, acceptancePolicy);
if (!relabeledResult.verified || relabeledResult.accepted) {
    throw new Error('B6 enrolled-subject substitution not refused');
}
// B7: a terminal authority cannot be silently substituted for the per-action approver.
const collapsedRolePayload = {
    ...rolePayload,
    per_action_approver: rolePayload.terminal_authority,
};
const collapsedRoleEvidence = {
    payload: collapsedRolePayload,
    sig: crypto.sign(null, canon(collapsedRolePayload), directory.privateKey).toString('base64url'),
    issuer_key: directory.publicKey,
};
const collapsedRoleResult = verifyBinding({ ...host, principal_role_evidence: collapsedRoleEvidence }, artifact, acceptancePolicy);
if (!collapsedRoleResult.verified || collapsedRoleResult.accepted) {
    throw new Error('B7 terminal-authority/approver collapse not refused');
}
console.error('BINDING VECTOR OK — B1 digest, B2 action, B3 discovery!=trust, '
    + 'B4 fail-closed absence, B5 consistency, B6 authoritative approver attribution, '
    + 'and B7 role non-equivalence enforced');
