// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * AADP -01 and EP Authorization Bundle composition profile.
 *
 * The AADP side is an explicitly bounded draft-derived lifecycle model. It is
 * not onedoor. The EP side executes the repository verifier.
 */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION, deriveAadpEpAuthorizationArtifact, matchAadpAuthorizationArtifact, verifyAadpEpAuthorizationArtifact, } from '../../../packages/verify/aadp-authorization-artifact.js';
import { canonicalizeAeb, digestAeb } from '../../../packages/verify/aeb-adapter-contract.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE_LOCK_BYTES = readFileSync(new URL('./source-lock.json', import.meta.url));
const SOURCE_LOCK = JSON.parse(SOURCE_LOCK_BYTES.toString('utf8'));
const SOURCE_LOCK_FILE_SHA256 = `sha256:${crypto.createHash('sha256')
    .update(SOURCE_LOCK_BYTES)
    .digest('hex')}`;
const MAPPING = JSON.parse(readFileSync(new URL('./mapping-profile.json', import.meta.url), 'utf8'));
const VERIFY_PACKAGE = JSON.parse(readFileSync(new URL('../../../packages/verify/package.json', import.meta.url), 'utf8'));
const VECTORS = JSON.parse(readFileSync(new URL('../../vectors/authorization-bundle.v1.json', import.meta.url), 'utf8'));
const FIXTURE = VECTORS.cases.find((entry) => entry.id === 'valid-non-oauth-native-binding');
export const PROFILE = 'AADP-EP-AUTHORIZATION-COMPOSITION-v0.1';
const SOURCE_RE = /^[A-Za-z_][A-Za-z0-9_.:-]*$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AADP_SOURCES = new Set(['scheduler', 'rule', 'llm', 'ui', 'undo', 'system']);
const BASE_REQUEST = Object.freeze({
    protocol: 'aadp/0.1',
    request_id: '0a5f2c3e-1b7e-4f2a-9c1d-6b0f9e2a77c1',
    action_type: FIXTURE.expected_action.action_type,
    params: Object.freeze({
        initiator: FIXTURE.expected_action.initiator,
        ...FIXTURE.expected_action.parameters,
    }),
    source: 'llm',
    rationale: 'settle the source-pinned synthetic invoice',
    session_id: 'sess-aadp-ep-001',
    cost_eur: '125.50',
    created_at: '2026-08-24T16:00:00Z',
    parent_id: null,
});
const VERIFIER = Object.freeze({
    profile: AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION,
    artifact_profile: 'EP-AUTHORIZATION-BUNDLE-v1',
    implementation: Object.freeze({
        id: 'pkg:npm/%40emilia-protocol/verify',
        version: VERIFY_PACKAGE.version,
        digest: `sha256:${SOURCE_LOCK.emilia.runtime_files.find((entry) => entry.path === 'packages/verify/src/authorization-bundle.ts').sha256}`,
    }),
});
function dataRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return null;
    try {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null)
            return null;
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const keys = Reflect.ownKeys(descriptors);
        if (keys.some((key) => typeof key !== 'string'))
            return null;
        const record = Object.create(null);
        for (const key of keys) {
            const descriptor = descriptors[key];
            if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))
                return null;
            record[key] = descriptor.value;
        }
        return record;
    }
    catch {
        return null;
    }
}
function validInstant(value) {
    return typeof value === 'string'
        && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)
        && Number.isFinite(Date.parse(value));
}
function validWireRequest(value) {
    const request = dataRecord(value);
    if (!request
        || request.protocol !== 'aadp/0.1'
        || typeof request.request_id !== 'string'
        || !UUID_RE.test(request.request_id)
        || typeof request.action_type !== 'string'
        || !SOURCE_RE.test(request.action_type)
        || dataRecord(request.params) === null
        || !AADP_SOURCES.has(request.source)
        || typeof request.rationale !== 'string'
        || request.rationale.length === 0
        || !validInstant(request.created_at))
        return false;
    if (Object.hasOwn(request, 'approval_ref')
        && (typeof request.approval_ref !== 'string' || request.approval_ref.length === 0))
        return false;
    return true;
}
function aadpAction(request) {
    return { action_type: request.action_type, params: request.params };
}
function bundleOptions(overrides = {}) {
    return {
        now: FIXTURE.now,
        audience: FIXTURE.audience,
        approverKeys: FIXTURE.approver_keys,
        expectedApprovers: FIXTURE.expected_approvers,
        acceptedKeyClasses: FIXTURE.accepted_key_classes,
        currentPolicy: FIXTURE.current_policy,
        expectedAuthorizationInstance: FIXTURE.expected_authorization_instance,
        expectedAuthorizationBinding: FIXTURE.expected_authorization_binding,
        requireAuthorizationBinding: true,
        ...overrides,
    };
}
function profileInput({ request = BASE_REQUEST, bundle = FIXTURE.bundle, mapping = MAPPING, verifier = VERIFIER, options = bundleOptions(), } = {}) {
    return {
        bundle,
        aadpAction: aadpAction(request),
        mapping,
        verifier,
        bundleOptions: options,
    };
}
function sameCanonical(left, right) {
    try {
        return canonicalizeAeb(left) === canonicalizeAeb(right);
    }
    catch {
        return false;
    }
}
function requestWith(requestId, overrides = {}) {
    return {
        ...BASE_REQUEST,
        request_id: requestId,
        params: { ...BASE_REQUEST.params },
        ...overrides,
    };
}
function responseBase(request, verdict, reason, evidenceId) {
    return {
        protocol: 'aadp/0.1',
        request_id: request.request_id,
        verdict,
        reason,
        detail: '',
        nominal_tier: 3,
        effective_tier: 3,
        evidence_id: evidenceId,
    };
}
function wireOutcome(wireResponse, ok, epInputObserved) {
    return {
        ok,
        pdp_reachable: true,
        wire_response: wireResponse,
        wire_verdict: wireResponse.verdict,
        reason: wireResponse.reason,
        ep_input_observed: epInputObserved,
    };
}
function unreachableOutcome(reason, epInputObserved = true) {
    return {
        ok: false,
        pdp_reachable: false,
        wire_response: null,
        wire_verdict: null,
        reason,
        ep_input_observed: epInputObserved,
    };
}
function malformedOutcome(value, evidenceId) {
    const requestId = dataRecord(value)?.request_id;
    const response = {
        protocol: 'aadp/0.1',
        verdict: 'deny',
        reason: 'malformed',
        detail: '',
        nominal_tier: 3,
        effective_tier: 3,
        evidence_id: evidenceId,
    };
    if (typeof requestId === 'string' && UUID_RE.test(requestId))
        response.request_id = requestId;
    return wireOutcome(response, false, false);
}
class AadpDraftLifecycle {
    approvals = new Map();
    permits = new Map();
    reports = new Map();
    nextApproval = 1;
    nextPermit = 1;
    nextEvidence = 1;
    evidenceId() {
        return `evidence:${this.nextEvidence++}`;
    }
    propose(request, hook) {
        if (!validWireRequest(request)) {
            return malformedOutcome(request, this.evidenceId());
        }
        const parsed = matchAadpAuthorizationArtifact(hook, hook);
        if (parsed.verdict !== 'MATCH') {
            return wireOutcome(responseBase(request, 'deny', 'x-emilia.authorization_artifact_malformed', this.evidenceId()), false, true);
        }
        const approvalId = `approval:${this.nextApproval++}`;
        this.approvals.set(approvalId, {
            state: 'pending',
            action: structuredClone(aadpAction(request)),
            hook: structuredClone(parsed.artifact),
        });
        return wireOutcome({
            ...responseBase(request, 'propose', 'tier_confirm', this.evidenceId()),
            approval_id: approvalId,
        }, false, true);
    }
    approve(approvalId) {
        const approval = this.approvals.get(approvalId);
        if (!approval || approval.state !== 'pending') {
            return { ok: false, reason: 'approval_not_pending' };
        }
        approval.state = 'approved';
        return { ok: true };
    }
    decide({ request, presentedHook, verifiedHook, localPolicy = 'PERMIT', killSwitch = false, }) {
        // AADP -01 evaluates the kill switch first. This branch deliberately does
        // not inspect the presented or independently derived EP objects.
        if (killSwitch === true) {
            if (!validWireRequest(request)) {
                return malformedOutcome(request, this.evidenceId());
            }
            return wireOutcome(responseBase(request, 'deny', 'kill_switch', this.evidenceId()), false, false);
        }
        if (!validWireRequest(request)) {
            return malformedOutcome(request, this.evidenceId());
        }
        if (localPolicy !== 'PERMIT') {
            return wireOutcome(responseBase(request, 'deny', 'default_deny', this.evidenceId()), false, false);
        }
        let profileVerdict;
        let profileReasons;
        let expectedArtifact;
        try {
            const verified = dataRecord(verifiedHook);
            if (!verified)
                return unreachableOutcome('native_authorization_artifact_unavailable');
            profileVerdict = verified.verdict;
            profileReasons = verified.reasons;
            expectedArtifact = verified.artifact;
        }
        catch {
            return unreachableOutcome('native_authorization_artifact_unavailable');
        }
        if (profileVerdict === 'INDETERMINATE') {
            const reason = Array.isArray(profileReasons) && typeof profileReasons[0] === 'string'
                ? profileReasons[0]
                : 'native_authorization_artifact_unavailable';
            return unreachableOutcome(reason);
        }
        if (profileVerdict !== 'VERIFIED') {
            return wireOutcome(responseBase(request, 'deny', 'x-emilia.authorization_artifact_refused', this.evidenceId()), false, true);
        }
        const hookMatch = matchAadpAuthorizationArtifact(presentedHook, expectedArtifact);
        if (hookMatch.verdict === 'INDETERMINATE') {
            return unreachableOutcome(hookMatch.reason ?? 'native_authorization_artifact_unavailable');
        }
        if (hookMatch.verdict !== 'MATCH') {
            return wireOutcome(responseBase(request, 'deny', 'x-emilia.authorization_artifact_mismatch', this.evidenceId()), false, true);
        }
        const approvalRef = request.approval_ref;
        const approval = typeof approvalRef === 'string' ? this.approvals.get(approvalRef) : null;
        if (!approval || approval.state !== 'approved'
            || !sameCanonical(approval.action, aadpAction(request))
            || !sameCanonical(approval.hook, hookMatch.artifact)) {
            return wireOutcome({
                ...responseBase(request, 'propose', 'tier_confirm', this.evidenceId()),
                approval_id: `approval:${this.nextApproval}`,
            }, false, true);
        }
        approval.state = 'executed';
        const permitId = `permit:${this.nextPermit++}`;
        const providerKey = `aadp-provider:${crypto.createHash('sha256')
            .update(`AADP-PROVIDER-IDEMPOTENCY-v1\u0000${permitId}`, 'utf8')
            .digest('hex')}`;
        this.permits.set(permitId, {
            state: 'issued',
            action: structuredClone(aadpAction(request)),
            provider_key: providerKey,
            artifact_digest: hookMatch.artifact?.artifact_digest,
        });
        return {
            ...wireOutcome({
                ...responseBase(request, 'permit', 'passed', this.evidenceId()),
                permit_id: permitId,
                obligations: [{ type: 'report_result', required: true }],
            }, true, true),
            permit_id: permitId,
            provider_idempotency_key: providerKey,
        };
    }
    report(permitId, outcome) {
        const permit = this.permits.get(permitId);
        if (!permit || permit.state !== 'issued') {
            return { ok: false, reason: 'permit_not_reportable' };
        }
        if (!['success', 'failure', 'timeout', 'not_attempted'].includes(outcome)) {
            return { ok: false, reason: 'report_outcome_unknown' };
        }
        permit.state = 'reported';
        this.reports.set(permitId, { outcome });
        return {
            ok: true,
            outcome,
            wire_response: {
                protocol: 'aadp/0.1',
                accepted: true,
                evidence_id: this.evidenceId(),
            },
        };
    }
}
function derive(overrides = {}) {
    return deriveAadpEpAuthorizationArtifact(profileInput(overrides));
}
function preparedFlow() {
    const verified = derive();
    if (verified.verdict !== 'VERIFIED')
        throw new Error(JSON.stringify(verified));
    const flow = new AadpDraftLifecycle();
    const proposed = flow.propose(BASE_REQUEST, verified.artifact);
    const approvalId = proposed.wire_response?.approval_id;
    if (proposed.wire_verdict !== 'propose'
        || typeof approvalId !== 'string'
        || !flow.approve(approvalId).ok) {
        throw new Error('failed to prepare AADP reference approval');
    }
    const request = requestWith('1a5f2c3e-1b7e-4f2a-9c1d-6b0f9e2a77c2', {
        approval_ref: approvalId,
    });
    return { flow, verified, approvalId, request };
}
function check(id, claim, actual, predicate) {
    const passed = predicate(actual);
    return { id, claim, passed, actual };
}
function observedProxy(value, onObserved) {
    return new Proxy(dataRecord(value) ?? {}, {
        get(target, property, receiver) {
            onObserved();
            return Reflect.get(target, property, receiver);
        },
        getPrototypeOf(target) {
            onObserved();
            return Reflect.getPrototypeOf(target);
        },
        ownKeys(target) {
            onObserved();
            return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor(target, property) {
            onObserved();
            return Reflect.getOwnPropertyDescriptor(target, property);
        },
    });
}
export function runComposition() {
    const checks = [];
    const positive = preparedFlow();
    const permitted = positive.flow.decide({
        request: positive.request,
        presentedHook: positive.verified.artifact,
        verifiedHook: positive.verified,
    });
    checks.push(check('AADP-EP-01', 'natively verified and satisfied EP evidence can support one AADP permit', {
        artifact_digest: positive.verified.artifact.artifact_digest,
        native_verification: positive.verified.native_verification,
        evidence_satisfaction: positive.verified.evidence_satisfaction,
        source_action_digest: positive.verified.artifact.action_mapping.source_action_digest,
        mapped_action_digest: positive.verified.artifact.action_mapping.mapped_action_digest,
        wire_verdict: permitted.wire_verdict,
    }, (value) => value.wire_verdict === 'permit'
        && value.native_verification === 'VERIFIED'
        && value.evidence_satisfaction === 'SATISFIED'
        && value.source_action_digest === digestAeb(aadpAction(BASE_REQUEST))
        && /^sha256:[0-9a-f]{64}$/.test(value.mapped_action_digest)
        && /^sha256:[0-9a-f]{64}$/.test(value.artifact_digest)));
    const changedAction = requestWith('2a5f2c3e-1b7e-4f2a-9c1d-6b0f9e2a77c3', {
        params: { ...BASE_REQUEST.params, amount_minor: 999_999 },
    });
    const substituted = derive({ request: changedAction });
    checks.push(check('AADP-EP-02', 'material AADP action substitution is refused by native EP verification', {
        verdict: substituted.verdict,
        reasons: substituted.reasons,
    }, (value) => value.verdict === 'REFUSE' && value.reasons.includes('action_mismatch')));
    const tamperedBundle = structuredClone(FIXTURE.bundle);
    tamperedBundle.contexts[0].audience = 'https://attacker.example';
    const tampered = derive({ bundle: tamperedBundle });
    checks.push(check('AADP-EP-03', 'tampered EP artifact bytes cannot support a permit', {
        verdict: tampered.verdict,
        native_verification: tampered.native_verification,
        evidence_satisfaction: tampered.evidence_satisfaction,
        reasons: tampered.reasons,
    }, (value) => value.verdict === 'REFUSE'
        && value.native_verification === 'REFUSED'
        && value.evidence_satisfaction === 'REFUSE'));
    const unpinned = derive({ options: bundleOptions({ approverKeys: {} }) });
    checks.push(check('AADP-EP-04', 'self-presented or unpinned approver keys are refused', {
        verdict: unpinned.verdict,
        reasons: unpinned.reasons,
    }, (value) => value.verdict === 'REFUSE' && value.reasons.includes('approver_keys_missing')));
    const wrongAudience = derive({ options: bundleOptions({ audience: 'https://other.example' }) });
    checks.push(check('AADP-EP-05', 'wrong AADP relying-party audience is refused', {
        verdict: wrongAudience.verdict,
        reasons: wrongAudience.reasons,
    }, (value) => value.verdict === 'REFUSE' && value.reasons.includes('context_audience_mismatch')));
    const noMapper = derive({ mapping: null });
    checks.push(check('AADP-EP-06', 'unavailable action mapping does not run EP verification', {
        verdict: noMapper.verdict,
        native_verification: noMapper.native_verification,
        evidence_satisfaction: noMapper.evidence_satisfaction,
        reasons: noMapper.reasons,
    }, (value) => value.verdict === 'INDETERMINATE'
        && value.native_verification === 'NOT_RUN'
        && value.evidence_satisfaction === 'NOT_EVALUATED'
        && value.reasons.includes('aadp_action_mapping_unavailable')));
    const policyUnavailable = derive({
        options: bundleOptions({
            currentPolicy: { ...FIXTURE.current_policy, unavailable: true },
        }),
    });
    checks.push(check('AADP-EP-07', 'unavailable current EP policy preserves native verification but not satisfaction', {
        verdict: policyUnavailable.verdict,
        native_verification: policyUnavailable.native_verification,
        evidence_satisfaction: policyUnavailable.evidence_satisfaction,
        reasons: policyUnavailable.reasons,
    }, (value) => value.verdict === 'INDETERMINATE'
        && value.native_verification === 'VERIFIED'
        && value.evidence_satisfaction === 'INDETERMINATE'
        && value.reasons.includes('current_policy_unavailable_or_stale')));
    const profileSubstitution = preparedFlow();
    const changedHook = {
        ...profileSubstitution.verified.artifact,
        action_mapping: {
            ...profileSubstitution.verified.artifact.action_mapping,
            mapping_profile: 'https://attacker.example/mapping-v1',
        },
    };
    const profileResult = profileSubstitution.flow.decide({
        request: profileSubstitution.request,
        presentedHook: changedHook,
        verifiedHook: profileSubstitution.verified,
    });
    checks.push(check('AADP-EP-08', 'presenter-selected mapping-profile substitution is refused', profileResult, (value) => value.wire_verdict === 'deny'
        && value.reason === 'x-emilia.authorization_artifact_mismatch'));
    const missingHook = verifyAadpEpAuthorizationArtifact(undefined, profileInput());
    checks.push(check('AADP-EP-09', 'missing required hook is refused', {
        verdict: missingHook.verdict,
        reasons: missingHook.reasons,
    }, (value) => value.verdict === 'REFUSE'
        && value.reasons.includes('authorization_artifact_malformed')));
    const frozen = preparedFlow();
    const frozenResult = frozen.flow.decide({
        request: frozen.request,
        approvalRef: frozen.approvalId,
        presentedHook: frozen.verified.artifact,
        verifiedHook: frozen.verified,
        killSwitch: true,
    });
    checks.push(check('AADP-EP-10', 'a valid EP artifact cannot overrule an AADP kill switch', frozenResult, (value) => value.wire_verdict === 'deny'
        && value.reason === 'kill_switch'
        && value.ep_input_observed === false));
    const replay = preparedFlow();
    const first = replay.flow.decide({
        request: replay.request,
        presentedHook: replay.verified.artifact,
        verifiedHook: replay.verified,
    });
    const second = replay.flow.decide({
        request: requestWith('3a5f2c3e-1b7e-4f2a-9c1d-6b0f9e2a77c4', {
            approval_ref: replay.approvalId,
        }),
        presentedHook: replay.verified.artifact,
        verifiedHook: replay.verified,
    });
    checks.push(check('AADP-EP-11', 'AADP approval remains single-use even while evidence remains satisfied', {
        first: first.wire_verdict,
        second: second.wire_verdict,
        second_reason: second.reason,
        permits: replay.flow.permits.size,
    }, (value) => value.first === 'permit'
        && value.second === 'propose'
        && value.second_reason === 'tier_confirm'
        && value.permits === 1));
    checks.push(check('AADP-EP-12', 'permit and provider keys remain separate from the artifact digest', {
        permit_id: first.permit_id,
        provider_idempotency_key: first.provider_idempotency_key,
        artifact_digest: replay.verified.artifact.artifact_digest,
    }, (value) => value.permit_id !== value.provider_idempotency_key
        && value.permit_id !== value.artifact_digest
        && value.provider_idempotency_key !== value.artifact_digest));
    const timeout = replay.flow.report(first.permit_id, 'timeout');
    const retry = replay.flow.decide({
        request: requestWith('4a5f2c3e-1b7e-4f2a-9c1d-6b0f9e2a77c5', {
            approval_ref: replay.approvalId,
        }),
        presentedHook: replay.verified.artifact,
        verifiedHook: replay.verified,
    });
    checks.push(check('AADP-EP-13', 'unknown provider outcome is reported and does not reopen approval', {
        report: timeout.outcome,
        retry: retry.wire_verdict,
        retry_reason: retry.reason,
        permits: replay.flow.permits.size,
    }, (value) => value.report === 'timeout'
        && value.retry === 'propose'
        && value.retry_reason === 'tier_confirm'
        && value.permits === 1));
    const sourceA = derive();
    const sourceB = derive({
        request: requestWith('5a5f2c3e-1b7e-4f2a-9c1d-6b0f9e2a77c6', { source: 'ui' }),
    });
    checks.push(check('AADP-EP-14', 'AADP source metadata is informational and cannot change the hook', {
        first: sourceA.artifact,
        second: sourceB.artifact,
    }, (value) => sameCanonical(value.first, value.second)));
    const debitAccount = derive({
        request: requestWith('6a5f2c3e-1b7e-4f2a-9c1d-6b0f9e2a77c7', {
            params: { ...BASE_REQUEST.params, debit_account: 'acct:attacker-controlled' },
        }),
    });
    checks.push(check('AADP-EP-15', 'an undeclared debit_account material parameter refuses before EP verification', {
        verdict: debitAccount.verdict,
        native_verification: debitAccount.native_verification,
        evidence_satisfaction: debitAccount.evidence_satisfaction,
        reasons: debitAccount.reasons,
    }, (value) => value.verdict === 'REFUSE'
        && value.native_verification === 'NOT_RUN'
        && value.evidence_satisfaction === 'NOT_EVALUATED'
        && value.reasons.includes('aadp_action_material_fields_unmapped:debit_account')));
    const implementationSubstitution = preparedFlow();
    const implementationChangedHook = structuredClone(implementationSubstitution.verified.artifact);
    implementationChangedHook.action_mapping.implementation.digest = `sha256:${'f'.repeat(64)}`;
    implementationChangedHook.action_mapping.resolver.digest = `sha256:${'d'.repeat(64)}`;
    implementationChangedHook.action_mapping.resolver.configuration_digest =
        `sha256:${'e'.repeat(64)}`;
    const implementationResult = implementationSubstitution.flow.decide({
        request: implementationSubstitution.request,
        presentedHook: implementationChangedHook,
        verifiedHook: implementationSubstitution.verified,
    });
    checks.push(check('AADP-EP-16', 'mapping implementation and resolver substitution are refused', implementationResult, (value) => value.wire_verdict === 'deny'
        && value.reason === 'x-emilia.authorization_artifact_mismatch'));
    for (const [id, label, hostileValue] of [
        ['AADP-EP-17', 'malformed', { verdict: 'REFUSE', artifact: null, reasons: ['malformed'] }],
        ['AADP-EP-18', 'unavailable', { verdict: 'INDETERMINATE', artifact: null, reasons: ['unavailable'] }],
        ['AADP-EP-19', 'stale', policyUnavailable],
    ]) {
        const compound = preparedFlow();
        let observed = false;
        const frozenHostile = compound.flow.decide({
            request: compound.request,
            presentedHook: undefined,
            verifiedHook: observedProxy(hostileValue, () => { observed = true; }),
            killSwitch: true,
        });
        checks.push(check(id, `AADP kill switch wins before ${label} EP input is observed`, {
            wire_verdict: frozenHostile.wire_verdict,
            reason: frozenHostile.reason,
            ep_input_observed: observed,
        }, (value) => value.wire_verdict === 'deny'
            && value.reason === 'kill_switch'
            && value.ep_input_observed === false));
    }
    const unreachable = preparedFlow();
    const unreachableDecision = unreachable.flow.decide({
        request: unreachable.request,
        presentedHook: policyUnavailable.artifact,
        verifiedHook: policyUnavailable,
    });
    let malformedObserved = false;
    const malformedDecision = unreachable.flow.decide({
        request: { protocol: 'aadp/0.1' },
        presentedHook: undefined,
        verifiedHook: observedProxy(policyUnavailable, () => { malformedObserved = true; }),
    });
    checks.push(check('AADP-EP-20', 'unavailable verification produces no invented AADP wire verdict', {
        pdp_reachable: unreachableDecision.pdp_reachable,
        wire_response: unreachableDecision.wire_response,
        reason: unreachableDecision.reason,
        malformed_wire_verdict: malformedDecision.wire_verdict,
        malformed_reason: malformedDecision.reason,
        malformed_ep_input_observed: malformedObserved,
    }, (value) => value.pdp_reachable === false
        && value.wire_response === null
        && value.reason === 'current_policy_unavailable_or_stale'
        && value.malformed_wire_verdict === 'deny'
        && value.malformed_reason === 'malformed'
        && value.malformed_ep_input_observed === false));
    checks.push(check('AADP-EP-21', 'native verification, EP satisfaction, and AADP authorization remain separate', {
        native_verification: positive.verified.native_verification,
        evidence_satisfaction: positive.verified.evidence_satisfaction,
        authorization_decision: positive.verified.authorization_decision,
        aadp_wire_verdict: permitted.wire_verdict,
    }, (value) => value.native_verification === 'VERIFIED'
        && value.evidence_satisfaction === 'SATISFIED'
        && value.authorization_decision === false
        && value.aadp_wire_verdict === 'permit'));
    const allLockedHashes = [
        SOURCE_LOCK.aadp.text.sha256,
        ...SOURCE_LOCK.onedoor.inspected_files.map((entry) => entry.sha256),
        ...SOURCE_LOCK.emilia.runtime_files.map((entry) => entry.sha256),
    ];
    const lockedBytes = canonicalizeAeb(SOURCE_LOCK);
    checks.push(check('AADP-EP-22', 'the deterministic report binds every source-locked hash', {
        source_lock_file_sha256: SOURCE_LOCK_FILE_SHA256,
        source_lock_canonical_digest: digestAeb(SOURCE_LOCK),
        hashes: allLockedHashes,
        all_hashes_bound: allLockedHashes.every((hash) => lockedBytes.includes(hash)),
    }, (value) => /^sha256:[0-9a-f]{64}$/.test(value.source_lock_file_sha256)
        && /^sha256:[0-9a-f]{64}$/.test(value.source_lock_canonical_digest)
        && value.hashes.length >= 6
        && value.all_hashes_bound === true));
    const passed = checks.filter((entry) => entry.passed).length;
    const report = {
        profile: PROFILE,
        source_basis: {
            source_lock: SOURCE_LOCK,
            source_lock_file_sha256: SOURCE_LOCK_FILE_SHA256,
            source_lock_canonical_digest: digestAeb(SOURCE_LOCK),
            aadp: {
                draft: SOURCE_LOCK.aadp.draft,
                implementation_kind: 'draft-derived-bounded-lifecycle-model',
                wire_fixture_kind: 'draft-01-valid-json-projection',
            },
            ep: {
                artifact: 'EP-AUTHORIZATION-BUNDLE-v1',
                implementation_kind: 'repository-runtime',
            },
            onedoor: {
                revision: SOURCE_LOCK.onedoor.revision,
                executed: false,
                note: 'exact locked bytes are hash-verified; implementation not executed by this runner',
            },
        },
        claim_boundary: {
            authorization_artifact_is_authority: false,
            aadp_re_evaluation_required: true,
            aadp_approval_single_use: true,
            aadp_wire_indeterminate_verdict_defined: false,
            aadp_permit_is_provider_idempotency_key: false,
            exactly_once_physical_effect_claimed: false,
            independent_aadp_implementation_claimed: false,
            interoperability_claimed: false,
            adoption_claimed: false,
        },
        summary: { passed, total: checks.length },
        passed: passed === checks.length,
        checks,
    };
    report.report_digest = digestAeb(report);
    return report;
}
function main() {
    const report = runComposition();
    const referencePath = `${HERE}/report.reference.json`;
    if (process.argv.includes('--emit')) {
        writeFileSync(referencePath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    }
    if (process.argv.includes('--check')) {
        const reference = JSON.parse(readFileSync(referencePath, 'utf8'));
        if (!sameCanonical(report, reference)) {
            throw new Error('AADP x EP report differs from report.reference.json');
        }
    }
    if (!report.passed)
        throw new Error(JSON.stringify(report, null, 2));
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1])
    main();
