// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const FIXED_AT = '2026-08-04T22:00:00Z';
const SUITE = 'EP-COMPOSITION-CROSS-SLOT-CONFORMANCE-v1';
const COMPOSITION_REVISION = 'draft-mih-sato-agent-accountability-composition-00';
const CAPSULE_REVISION = 'draft-mih-scitt-agent-action-capsule-02';
const RESULT_STATUSES = new Set([
    'pass',
    'fail',
    'not_evaluated',
    'unsupported',
    'indeterminate',
]);
export const NEGATIVE_IDS = Object.freeze([
    'COMP-BIND-01',
    'COMP-BIND-02',
    'COMP-BIND-03',
    'COMP-BIND-04',
    'COMP-BIND-05',
    'COMP-BIND-06',
    'COMP-BASIS-01',
    'COMP-BASIS-02',
    'COMP-RESULT-01',
    'COMP-RESULT-02',
    'COMP-JOIN-01',
    'COMP-JOIN-02',
    'COMP-UNKNOWN-01',
]);
function sortJson(value) {
    if (Array.isArray(value))
        return value.map(sortJson);
    if (value !== null && typeof value === 'object') {
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key])]));
    }
    return value;
}
function canonical(value) {
    return JSON.stringify(sortJson(value));
}
function sha256(value) {
    return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}
function fileDigest(path) {
    return sha256(readFileSync(resolve(ROOT, path)));
}
function clone(value) {
    return structuredClone(value);
}
function artifact(value) {
    const bytes = Buffer.from(canonical(value));
    return {
        media_type: 'application/json',
        bytes_b64u: bytes.toString('base64url'),
        sha256: sha256(bytes),
    };
}
const ACTION = Object.freeze({
    action_type: 'payment.release.1',
    amount: '250000.00',
    currency: 'USD',
    beneficiary_account: `sha256:${'42'.repeat(32)}`,
    payment_instruction_id: 'payment:acme:2026-08-04:0001',
});
const ACTION_ARTIFACT = artifact(ACTION);
const ACTION_DIGEST = ACTION_ARTIFACT.sha256;
const OTHER_ACTION_DIGEST = sha256(Buffer.from(canonical({ ...ACTION, amount: '999999.00' })));
const DIGEST_CONTEXT = Object.freeze({
    profile: 'draft-schrock-canonical-action-identifier-01',
    action_type: ACTION.action_type,
    canonicalization: 'RFC8785',
    hash: 'sha-256',
    representation: 'lowercase-hex',
    projection: 'caid.payment.release.1',
});
function slot(name, profile, nativePayload) {
    const nativeArtifact = artifact(nativePayload);
    return {
        slot: name,
        native_identifier: `${profile}:${name}:001`,
        profile,
        profile_revision: profile,
        serialization_suite: 'jcs-sha256',
        artifact: nativeArtifact,
        native_result: 'pass',
        native_detail: nativePayload,
        subject: {
            action_digest: ACTION_DIGEST,
            digest_context: clone(DIGEST_CONTEXT),
        },
        additional_bindings: [
            {
                purpose: 'exact_action',
                context: 'ep:composition:exact-action:v1',
                digest: ACTION_DIGEST,
                understood: true,
                required: true,
            },
        ],
        fields: {
            amount: { value: ACTION.amount, basis: 'USD-major-units' },
            event_time: { value: FIXED_AT, basis: 'gate-evaluation-time' },
        },
    };
}
function buildBaseBundle() {
    const slots = {
        can: slot('can', 'draft-schrock-action-evidence-boundary-03', {
            authorization: 'AUTHORIZED',
            admission: 'CONSUMED',
            action_digest: ACTION_DIGEST,
        }),
        who: slot('who', 'draft-schrock-ep-authorization-evidence-chain-05', {
            evidence_satisfaction: 'SATISFIED',
            principal_linkage: 'RESOLVED',
            action_digest: ACTION_DIGEST,
        }),
        what: slot('what', CAPSULE_REVISION, {
            class_1: 'pass',
            class_2: 'not_evaluated',
            verdict: 'executed',
            effect_mode: 'confirmed',
            action_digest: ACTION_DIGEST,
        }),
        audit: slot('audit', 'draft-schrock-ep-outcome-binding-00', {
            outcome: 'OBSERVED_AS_REQUESTED',
            source: 'INDEPENDENT_OBSERVER',
            action_digest: ACTION_DIGEST,
        }),
    };
    const names = Object.keys(slots);
    for (let index = 0; index < names.length; index += 1) {
        const name = names[index];
        const target = names[(index + 1) % names.length];
        slots[name].protected_cross_reference = {
            target_slot: target,
            artifact_digest: slots[target].artifact.sha256,
        };
    }
    return {
        bundle_profile: 'agent-accountability-composition-conformance-v1',
        bundle_id: 'composition-v1-four-slot-positive-001',
        composition_revision: {
            name: COMPOSITION_REVISION,
            revision: '00',
            source_commit: '4b159115bae7aa4273783c9340f9729a08377992',
            sha256: 'sha256:3649831a2908fdee5cf11015965d24711f67e89bffdce193220d2bd50925919f',
        },
        subject: {
            action_file: 'embedded:subject.action',
            action: ACTION,
            action_artifact: ACTION_ARTIFACT,
            action_digest: ACTION_DIGEST,
            digest_context: clone(DIGEST_CONTEXT),
        },
        slots,
        mappings: [],
        policy: {
            required_binding_purposes: ['exact_action'],
            required_profiles: Object.values(slots).map((entry) => entry.profile),
            supported_profiles: Object.values(slots).map((entry) => entry.profile),
        },
        reporting: {
            native_results_separate: true,
            composition_overrides_native: false,
            reported_native_results: Object.fromEntries(Object.entries(slots).map(([name, entry]) => [name, entry.native_result])),
        },
    };
}
const NEGATIVES = [
    {
        id: 'COMP-BIND-01',
        title: 'Different action bytes retain the positive subject digest',
        expectedTerminal: 'fail',
        expectedCheck: 'subject.action_bytes',
        mutate(bundle) {
            const changed = { ...bundle.subject.action, amount: '999999.00' };
            bundle.subject.action = changed;
            bundle.subject.action_artifact = artifact(changed);
        },
    },
    {
        id: 'COMP-BIND-02',
        title: 'A slot uses an incompatible action projection',
        expectedTerminal: 'indeterminate',
        expectedCheck: 'join.digest_context',
        mutate(bundle) {
            bundle.slots.who.subject.digest_context.projection = 'vendor-private-payment-v9';
        },
    },
    {
        id: 'COMP-BIND-03',
        title: 'Raw digest bytes are substituted for declared lowercase hexadecimal',
        expectedTerminal: 'fail',
        expectedCheck: 'join.digest_representation',
        mutate(bundle) {
            bundle.slots.what.subject.digest_context.representation = 'raw-bytes';
        },
    },
    {
        id: 'COMP-BIND-04',
        title: 'A protected cross-reference names different adjacent-slot bytes',
        expectedTerminal: 'fail',
        expectedCheck: 'join.protected_cross_reference',
        mutate(bundle) {
            bundle.slots.audit.protected_cross_reference.artifact_digest = OTHER_ACTION_DIGEST;
        },
    },
    {
        id: 'COMP-BIND-05',
        title: 'An additional binding omits its declared context',
        expectedTerminal: 'fail',
        expectedCheck: 'join.additional_binding_context',
        mutate(bundle) {
            delete bundle.slots.can.additional_bindings[0].context;
        },
    },
    {
        id: 'COMP-BIND-06',
        title: 'An unknown optional binding remains readable but cannot satisfy required policy',
        expectedTerminal: 'unsupported',
        expectedCheck: 'policy.binding_semantics',
        mutate(bundle) {
            bundle.slots.who.additional_bindings.push({
                purpose: 'vendor_future_binding',
                context: 'vendor:future:v1',
                digest: ACTION_DIGEST,
                understood: false,
                required: false,
            });
            bundle.policy.required_binding_purposes.push('vendor_future_binding');
        },
        repair(bundle) {
            bundle.slots.who.additional_bindings.at(-1).understood = true;
        },
    },
    {
        id: 'COMP-BASIS-01',
        title: 'A joined amount has no declared basis',
        expectedTerminal: 'indeterminate',
        expectedCheck: 'join.field_basis',
        mutate(bundle) {
            delete bundle.slots.audit.fields.amount.basis;
        },
    },
    {
        id: 'COMP-BASIS-02',
        title: 'Two amounts use incompatible bases without a pinned mapping',
        expectedTerminal: 'indeterminate',
        expectedCheck: 'join.field_mapping',
        mutate(bundle) {
            bundle.slots.who.fields.amount.basis = 'USD-minor-units';
        },
    },
    {
        id: 'COMP-RESULT-01',
        title: 'Native and join results are collapsed into one aggregate boolean',
        expectedTerminal: 'fail',
        expectedCheck: 'report.result_separation',
        mutate(bundle) {
            bundle.reporting.native_results_separate = false;
        },
    },
    {
        id: 'COMP-RESULT-02',
        title: 'Composition is allowed to overwrite a native profile result',
        expectedTerminal: 'fail',
        expectedCheck: 'report.result_preservation',
        mutate(bundle) {
            bundle.reporting.composition_overrides_native = true;
        },
    },
    {
        id: 'COMP-JOIN-01',
        title: 'Individually readable slot records refer to different exact actions',
        expectedTerminal: 'fail',
        expectedCheck: 'join.exact_action',
        mutate(bundle) {
            bundle.slots.who.subject.action_digest = OTHER_ACTION_DIGEST;
        },
    },
    {
        id: 'COMP-JOIN-02',
        title: 'A not-evaluated native slot is relabeled as a verifier failure',
        expectedTerminal: 'fail',
        expectedCheck: 'report.not_evaluated_preservation',
        mutate(bundle) {
            bundle.slots.what.native_result = 'not_evaluated';
            bundle.reporting.reported_native_results.what = 'fail';
        },
        repair(bundle) {
            bundle.reporting.reported_native_results.what = 'not_evaluated';
        },
    },
    {
        id: 'COMP-UNKNOWN-01',
        title: 'An unknown required profile is treated as accepted',
        expectedTerminal: 'unsupported',
        expectedCheck: 'policy.required_profile',
        mutate(bundle) {
            bundle.policy.required_profiles.push('urn:example:unknown-required-profile');
        },
    },
];
const JOIN_CHECK_IDS = Object.freeze([
    'bundle.artifact_bytes',
    'subject.action_bytes',
    'join.digest_context',
    'join.digest_representation',
    'join.protected_cross_reference',
    'join.additional_binding_context',
    'policy.binding_semantics',
    'join.field_basis',
    'join.field_mapping',
    'report.result_separation',
    'report.result_preservation',
    'join.exact_action',
    'report.not_evaluated_preservation',
    'policy.required_profile',
]);
function expectedNativeResults(bundle) {
    return Object.fromEntries(Object.entries(bundle.slots).map(([name, entry]) => [
        name,
        entry.native_result,
    ]));
}
function expectedJoinResults(expectedCheck, expectedTerminal) {
    const expected = Object.fromEntries(JOIN_CHECK_IDS.map((id) => [
        id,
        id === expectedCheck ? expectedTerminal : 'pass',
    ]));
    if (expectedCheck === 'join.field_basis') {
        expected['join.field_mapping'] = 'not_evaluated';
    }
    return expected;
}
function caseDefinition(value) {
    return {
        ...value,
        expected_native_results: expectedNativeResults(value.bundle),
        expected_join_results: expectedJoinResults(value.expected_check, value.expected_terminal),
    };
}
export function buildCatalog() {
    const positive = caseDefinition({
        id: 'COMP-POSITIVE-01',
        title: 'One exact action threads through CAN, WHO, WHAT, and AUDIT',
        pair_id: null,
        variant: 'positive',
        expected_terminal: 'pass',
        expected_check: 'composition.complete',
        bundle: buildBaseBundle(),
    });
    const cases = [positive];
    for (const definition of NEGATIVES) {
        const negativeBundle = buildBaseBundle();
        definition.mutate(negativeBundle);
        const repairedBundle = definition.repair
            ? clone(negativeBundle)
            : buildBaseBundle();
        definition.repair?.(repairedBundle);
        cases.push(caseDefinition({
            id: definition.id,
            title: definition.title,
            pair_id: definition.id,
            variant: 'negative',
            expected_terminal: definition.expectedTerminal,
            expected_check: definition.expectedCheck,
            bundle: negativeBundle,
        }));
        cases.push(caseDefinition({
            id: `${definition.id}.condition_removed`,
            title: `${definition.title} — condition removed`,
            pair_id: definition.id,
            variant: 'condition_removed',
            expected_terminal: 'pass',
            expected_check: 'composition.complete',
            bundle: repairedBundle,
        }));
    }
    return cases;
}
function check(id, status, detail) {
    return { id, status, detail };
}
function verifyArtifactBytes(bundle) {
    const failures = [];
    for (const [name, entry] of Object.entries(bundle.slots)) {
        const bytes = Buffer.from(entry.artifact.bytes_b64u, 'base64url');
        if (sha256(bytes) !== entry.artifact.sha256)
            failures.push(name);
    }
    return check('bundle.artifact_bytes', failures.length === 0 ? 'pass' : 'fail', failures.length === 0 ? 'all native artifact bytes match their pinned digests'
        : `artifact digest mismatch: ${failures.join(',')}`);
}
function verifySubjectBytes(bundle) {
    const bytes = Buffer.from(bundle.subject.action_artifact.bytes_b64u, 'base64url');
    const actual = sha256(bytes);
    const contentMatches = bytes.equals(Buffer.from(canonical(bundle.subject.action)));
    return check('subject.action_bytes', actual === bundle.subject.action_digest && contentMatches ? 'pass' : 'fail', 'supplied action bytes must match both the visible action and pinned digest');
}
function verifyDigestContext(bundle) {
    const compatibleContext = (value) => {
        const copy = clone(value);
        delete copy.representation;
        return canonical(copy);
    };
    const expected = compatibleContext(bundle.subject.digest_context);
    const incompatible = Object.values(bundle.slots).filter((entry) => compatibleContext(entry.subject.digest_context) !== expected);
    return check('join.digest_context', incompatible.length === 0 ? 'pass' : 'indeterminate', incompatible.length === 0 ? 'all slots declare the same digest context'
        : 'at least one slot uses an incompatible profile or action projection');
}
function verifyRepresentation(bundle) {
    const expected = bundle.subject.digest_context.representation;
    const mismatch = Object.values(bundle.slots).some((entry) => entry.subject.digest_context.representation !== expected);
    return check('join.digest_representation', mismatch ? 'fail' : 'pass', mismatch ? 'declared digest representations differ' : 'digest representation matches');
}
function verifyCrossReferences(bundle) {
    let mismatch = false;
    for (const entry of Object.values(bundle.slots)) {
        const ref = entry.protected_cross_reference;
        if (!bundle.slots[ref.target_slot]
            || bundle.slots[ref.target_slot].artifact.sha256 !== ref.artifact_digest) {
            mismatch = true;
        }
    }
    return check('join.protected_cross_reference', mismatch ? 'fail' : 'pass', mismatch ? 'protected cross-reference does not identify supplied target bytes'
        : 'all protected cross-references match supplied target bytes');
}
function verifyAdditionalBindingContext(bundle) {
    const incomplete = Object.values(bundle.slots).flatMap((entry) => entry.additional_bindings).some((binding) => typeof binding.purpose !== 'string'
        || typeof binding.context !== 'string'
        || typeof binding.digest !== 'string');
    return check('join.additional_binding_context', incomplete ? 'fail' : 'pass', incomplete ? 'an additional binding is missing purpose, context, or digest'
        : 'additional bindings carry complete declared context');
}
function verifyBindingSemantics(bundle) {
    const bindings = Object.values(bundle.slots).flatMap((entry) => entry.additional_bindings);
    const required = bundle.policy.required_binding_purposes;
    const uninterpretedRequired = required.some((purpose) => {
        const matches = bindings.filter((binding) => binding.purpose === purpose);
        return matches.length === 0 || matches.every((binding) => binding.understood !== true);
    });
    return {
        ...check('policy.binding_semantics', uninterpretedRequired ? 'unsupported' : 'pass', uninterpretedRequired
            ? 'binding is structurally readable but cannot satisfy policy requiring understood semantics'
            : 'every policy-required binding purpose has understood semantics'),
        binding_state: uninterpretedRequired ? 'present_uninterpreted' : 'understood',
    };
}
function verifyFieldBasis(bundle) {
    const missing = Object.values(bundle.slots).some((entry) => Object.values(entry.fields).some((field) => typeof field.basis !== 'string' || field.basis.length === 0));
    return check('join.field_basis', missing ? 'indeterminate' : 'pass', missing ? 'joined field basis is absent' : 'joined fields declare their bases');
}
function verifyFieldMapping(bundle, fieldBasis) {
    if (fieldBasis.status !== 'pass') {
        return check('join.field_mapping', 'not_evaluated', 'field mapping was not evaluated because a joined field lacks a declared basis');
    }
    const amountBases = [...new Set(Object.values(bundle.slots).map((entry) => entry.fields.amount.basis))];
    if (amountBases.length <= 1)
        return check('join.field_mapping', 'pass', 'joined amount bases match');
    const mapped = bundle.mappings.some((mapping) => {
        const pair = new Set([mapping.from_basis, mapping.to_basis]);
        return amountBases.every((basis) => pair.has(basis));
    });
    return check('join.field_mapping', mapped ? 'pass' : 'indeterminate', mapped ? 'incompatible bases have a pinned mapping' : 'incompatible bases lack a pinned mapping');
}
function verifyResultSeparation(bundle) {
    return check('report.result_separation', bundle.reporting.native_results_separate === true ? 'pass' : 'fail', 'native slot and cross-slot results must remain separately named');
}
function verifyResultPreservation(bundle) {
    return check('report.result_preservation', bundle.reporting.composition_overrides_native === false ? 'pass' : 'fail', 'composition must not upgrade, weaken, or overwrite a native result');
}
function verifyExactActionJoin(bundle) {
    const mismatch = Object.values(bundle.slots).some((entry) => entry.subject.action_digest !== bundle.subject.action_digest);
    return check('join.exact_action', mismatch ? 'fail' : 'pass', mismatch ? 'populated slots do not identify the same exact action'
        : 'all populated slots identify the same exact action');
}
function verifyNotEvaluatedPreservation(bundle) {
    const mismatch = Object.entries(bundle.slots).some(([name, entry]) => (entry.native_result === 'not_evaluated'
        && bundle.reporting.reported_native_results[name] !== 'not_evaluated'));
    return check('report.not_evaluated_preservation', mismatch ? 'fail' : 'pass', mismatch ? 'not_evaluated native result was relabeled as a verifier failure'
        : 'not_evaluated native results remain not_evaluated');
}
function verifyRequiredProfiles(bundle) {
    const supported = new Set(bundle.policy.supported_profiles);
    const unknown = bundle.policy.required_profiles.filter((profile) => !supported.has(profile));
    return check('policy.required_profile', unknown.length === 0 ? 'pass' : 'unsupported', unknown.length === 0 ? 'all required profiles are supported'
        : `unsupported required profiles: ${unknown.join(',')}`);
}
function terminalStatus(results) {
    const statuses = results.map((entry) => entry.status);
    for (const candidate of ['fail', 'unsupported', 'indeterminate', 'not_evaluated']) {
        if (statuses.includes(candidate))
            return candidate;
    }
    return 'pass';
}
function divergenceFor(id, bundle) {
    const slots = Object.entries(bundle.slots);
    const base = (field, expected, actual, expectedBasis = null, actualBasis = null) => ({
        field,
        expected: expected ?? null,
        actual: actual ?? null,
        expected_basis: expectedBasis ?? null,
        actual_basis: actualBasis ?? null,
    });
    switch (id) {
        case 'bundle.artifact_bytes': {
            const mismatch = slots.find(([, entry]) => (sha256(Buffer.from(entry.artifact.bytes_b64u, 'base64url')) !== entry.artifact.sha256));
            return base(`slots.${mismatch?.[0] ?? 'unknown'}.artifact.sha256`, mismatch?.[1].artifact.sha256, mismatch ? sha256(Buffer.from(mismatch[1].artifact.bytes_b64u, 'base64url')) : null, 'declared artifact digest', 'digest recomputed from supplied bytes');
        }
        case 'subject.action_bytes':
            return base('subject.action_digest', bundle.subject.action_digest, sha256(Buffer.from(canonical(bundle.subject.action))), canonical(bundle.subject.digest_context), canonical(bundle.subject.digest_context));
        case 'join.digest_context': {
            const expected = canonical(bundle.subject.digest_context);
            const mismatch = slots.find(([, entry]) => canonical(entry.subject.digest_context) !== expected);
            return base(`slots.${mismatch?.[0] ?? 'unknown'}.subject.digest_context`, bundle.subject.digest_context, mismatch?.[1].subject.digest_context, 'subject digest context', 'slot digest context');
        }
        case 'join.digest_representation': {
            const expected = bundle.subject.digest_context.representation;
            const mismatch = slots.find(([, entry]) => entry.subject.digest_context.representation !== expected);
            return base(`slots.${mismatch?.[0] ?? 'unknown'}.subject.digest_context.representation`, expected, mismatch?.[1].subject.digest_context.representation, 'subject digest representation', 'slot digest representation');
        }
        case 'join.protected_cross_reference': {
            const mismatch = slots.find(([, entry]) => (!bundle.slots[entry.protected_cross_reference.target_slot]
                || bundle.slots[entry.protected_cross_reference.target_slot].artifact.sha256
                    !== entry.protected_cross_reference.artifact_digest));
            const target = mismatch?.[1].protected_cross_reference.target_slot;
            return base(`slots.${mismatch?.[0] ?? 'unknown'}.protected_cross_reference.artifact_digest`, target ? bundle.slots[target]?.artifact.sha256 : null, mismatch?.[1].protected_cross_reference.artifact_digest, 'supplied target artifact bytes', `protected reference to ${target ?? 'unknown target'}`);
        }
        case 'join.additional_binding_context': {
            const owner = slots.find(([, entry]) => entry.additional_bindings.some((binding) => typeof binding.purpose !== 'string'
                || typeof binding.context !== 'string'
                || typeof binding.digest !== 'string'));
            const binding = owner?.[1].additional_bindings.find((value) => typeof value.purpose !== 'string'
                || typeof value.context !== 'string'
                || typeof value.digest !== 'string');
            return base(`slots.${owner?.[0] ?? 'unknown'}.additional_bindings`, ['purpose', 'context', 'digest'], binding, 'required binding members', 'supplied binding members');
        }
        case 'policy.binding_semantics': {
            const required = bundle.policy.required_binding_purposes.find((purpose) => (slots.flatMap(([, entry]) => entry.additional_bindings)
                .filter((binding) => binding.purpose === purpose)
                .every((binding) => binding.understood !== true)));
            return base('policy.required_binding_purposes', 'understood semantics', 'present_uninterpreted', required, required);
        }
        case 'join.field_basis': {
            const owner = slots.find(([, entry]) => Object.values(entry.fields).some((field) => typeof field.basis !== 'string' || field.basis.length === 0));
            const fieldName = owner && Object.entries(owner[1].fields).find(([, field]) => typeof field.basis !== 'string' || field.basis.length === 0)?.[0];
            return base(`slots.${owner?.[0] ?? 'unknown'}.fields.${fieldName ?? 'unknown'}.basis`, 'declared basis', null, 'comparison prerequisite', null);
        }
        case 'join.field_mapping': {
            const actual = Object.fromEntries(slots.map(([name, entry]) => [name, entry.fields.amount.basis]));
            return base('slots.*.fields.amount.basis', 'same basis or digest-pinned mapping', actual, 'declared comparison basis', 'supplied per-slot bases');
        }
        case 'report.result_separation':
            return base('reporting.native_results_separate', true, bundle.reporting.native_results_separate);
        case 'report.result_preservation':
            return base('reporting.composition_overrides_native', false, bundle.reporting.composition_overrides_native);
        case 'join.exact_action': {
            const mismatch = slots.find(([, entry]) => entry.subject.action_digest !== bundle.subject.action_digest);
            return base(`slots.${mismatch?.[0] ?? 'unknown'}.subject.action_digest`, bundle.subject.action_digest, mismatch?.[1].subject.action_digest, canonical(bundle.subject.digest_context), mismatch ? canonical(mismatch[1].subject.digest_context) : null);
        }
        case 'report.not_evaluated_preservation': {
            const mismatch = slots.find(([name, entry]) => (entry.native_result === 'not_evaluated'
                && bundle.reporting.reported_native_results[name] !== 'not_evaluated'));
            return base(`reporting.reported_native_results.${mismatch?.[0] ?? 'unknown'}`, 'not_evaluated', mismatch ? bundle.reporting.reported_native_results[mismatch[0]] : null, 'native slot result', 'composition report');
        }
        case 'policy.required_profile': {
            const supported = new Set(bundle.policy.supported_profiles);
            const unknown = bundle.policy.required_profiles.find((profile) => !supported.has(profile));
            return base('policy.required_profiles', bundle.policy.supported_profiles, unknown, 'implementation-supported profiles', 'required profile');
        }
        default:
            return base(id, 'pass', 'non-pass');
    }
}
export function evaluateCase(item) {
    try {
        const fieldBasis = verifyFieldBasis(item.bundle);
        const results = [
            verifyArtifactBytes(item.bundle),
            verifySubjectBytes(item.bundle),
            verifyDigestContext(item.bundle),
            verifyRepresentation(item.bundle),
            verifyCrossReferences(item.bundle),
            verifyAdditionalBindingContext(item.bundle),
            verifyBindingSemantics(item.bundle),
            fieldBasis,
            verifyFieldMapping(item.bundle, fieldBasis),
            verifyResultSeparation(item.bundle),
            verifyResultPreservation(item.bundle),
            verifyExactActionJoin(item.bundle),
            verifyNotEvaluatedPreservation(item.bundle),
            verifyRequiredProfiles(item.bundle),
        ];
        const primary = results.find((entry) => entry.status !== 'pass');
        for (const result of results) {
            if (result.status !== 'pass' && result.status !== 'not_evaluated') {
                result.divergence = divergenceFor(result.id, item.bundle);
            }
        }
        const invalidVocabulary = results.find((entry) => !RESULT_STATUSES.has(entry.status));
        if (invalidVocabulary)
            throw new Error(`invalid result vocabulary: ${invalidVocabulary.status}`);
        const nativeResults = Object.entries(item.bundle.slots).map(([name, entry]) => ({
            slot: name,
            profile: entry.profile,
            artifact_digest: entry.artifact.sha256,
            native_result: entry.native_result,
            reported_result: item.bundle.reporting.reported_native_results[name],
        }));
        return {
            '@version': 'EP-COMPOSITION-CROSS-SLOT-RESULT-v1',
            case_id: item.id,
            pair_id: item.pair_id,
            variant: item.variant,
            native_results: nativeResults,
            join_results: results,
            primary_check: primary?.id ?? 'composition.complete',
            terminal: terminalStatus(results),
            binding_state: results.find((entry) => entry.id === 'policy.binding_semantics')?.binding_state,
            crashed: false,
        };
    }
    catch (error) {
        return {
            '@version': 'EP-COMPOSITION-CROSS-SLOT-RESULT-v1',
            case_id: item.id,
            pair_id: item.pair_id,
            variant: item.variant,
            native_results: [],
            join_results: [],
            primary_check: 'composition.internal_error',
            terminal: 'fail',
            crashed: true,
            internal_error: error instanceof Error ? error.message : String(error),
        };
    }
}
function sourceManifest() {
    const sources = [
        'examples/composition/cross-slot-conformance-v1/run.mts',
        'examples/composition/caid-aec-aeb-capsule-v1/bundle.json',
    ].map((path) => ({ path, sha256: fileDigest(path) }));
    return {
        '@version': 'EP-COMPOSITION-CROSS-SLOT-MANIFEST-v1',
        suite: SUITE,
        status: 'candidate-emilia-conformance-harness',
        generated_at: FIXED_AT,
        composition: {
            revision: COMPOSITION_REVISION,
            url: 'https://www.ietf.org/archive/id/draft-mih-sato-agent-accountability-composition-00.txt',
            sha256: 'sha256:3649831a2908fdee5cf11015965d24711f67e89bffdce193220d2bd50925919f',
        },
        profiled_what: {
            revision: CAPSULE_REVISION,
            url: 'https://www.ietf.org/archive/id/draft-mih-scitt-agent-action-capsule-02.txt',
            sha256: 'sha256:493428486c85e03624bc1d90e8265b072b98265b93b7bd50d55824688a1802d8',
        },
        implementation_sources: sources,
        delivery: {
            positive_four_slot_vectors: 1,
            negative_condition_pairs: NEGATIVE_IDS.length,
            total_cases: 1 + (NEGATIVE_IDS.length * 2),
        },
        freeze_rule: 'requires matching reports from two implementations maintained by different parties',
    };
}
export function runSuite() {
    const cases = buildCatalog();
    const results = cases.map(evaluateCase);
    const reportResults = results.map((result, index) => {
        const item = cases[index];
        const inputArtifactDigests = {
            action: item.bundle.subject.action_artifact.sha256,
            ...Object.fromEntries(Object.entries(item.bundle.slots).map(([name, entry]) => [
                name,
                entry.artifact.sha256,
            ])),
        };
        return {
            ...result,
            input_artifact_digests: inputArtifactDigests,
            native_results: result.native_results.map((entry) => ({
                ...entry,
                expected_result: item.expected_native_results[entry.slot],
            })),
            join_results: result.join_results.map((entry) => ({
                ...entry,
                expected_result: item.expected_join_results[entry.id],
            })),
        };
    });
    const checks = cases.map((item, index) => {
        const result = reportResults[index];
        const nativeResultsMatch = result.native_results.every((entry) => entry.native_result === entry.expected_result);
        const joinResultsMatch = result.join_results.every((entry) => entry.status === entry.expected_result);
        return {
            id: item.id,
            pair_id: item.pair_id,
            variant: item.variant,
            expected_terminal: item.expected_terminal,
            expected_check: item.expected_check,
            actual_terminal: result.terminal,
            actual_check: result.primary_check,
            terminal_match: result.terminal === item.expected_terminal,
            check_match: result.primary_check === item.expected_check,
            native_results_match: nativeResultsMatch,
            join_results_match: joinResultsMatch,
            no_crash: result.crashed === false && result.internal_error === undefined,
            passed: result.terminal === item.expected_terminal
                && result.primary_check === item.expected_check
                && nativeResultsMatch
                && joinResultsMatch
                && result.crashed === false
                && result.internal_error === undefined,
        };
    });
    const manifest = sourceManifest();
    const manifestDigest = sha256(canonical(manifest));
    const bundle = {
        '@version': SUITE,
        manifest_digest: manifestDigest,
        result_vocabulary: [...RESULT_STATUSES],
        cases: cases.map((item) => ({
            id: item.id,
            title: item.title,
            pair_id: item.pair_id,
            variant: item.variant,
            expected_terminal: item.expected_terminal,
            expected_check: item.expected_check,
            expected_native_results: item.expected_native_results,
            expected_join_results: item.expected_join_results,
            input: item.bundle,
        })),
    };
    const reportBody = {
        '@version': 'EP-COMPOSITION-CROSS-SLOT-RUN-REPORT-v1',
        implementation: 'emilia-js-cross-slot-candidate',
        implementation_version: '1.0.0',
        implementation_revision: manifest.implementation_sources[0].sha256,
        implementation_owner: 'EMILIA Protocol',
        generated_at: FIXED_AT,
        manifest_digest: manifestDigest,
        bundle_digest: sha256(canonical(bundle)),
        passed: checks.every((entry) => entry.passed),
        case_count: cases.length,
        negative_pair_count: NEGATIVE_IDS.length,
        checks,
        results: reportResults,
        independence: {
            same_team: true,
            external_confirmation: false,
            claim: 'candidate cross-slot conformance execution, not an independent freeze',
        },
    };
    const report = {
        ...reportBody,
        report_digest: sha256(canonical(reportBody)),
    };
    return { manifest, bundle, report };
}
function emitArtifacts(run) {
    const files = [
        ['manifest.json', run.manifest],
        ['bundle.json', run.bundle],
        ['report.emilia-js.json', run.report],
        ['external-report.template.json', {
                '@version': 'EP-COMPOSITION-CROSS-SLOT-EXTERNAL-REPORT-v1',
                status: 'AWAITING_INDEPENDENT_RUN',
                implementation: null,
                implementation_owner: null,
                implementation_revision: null,
                manifest_digest: run.report.manifest_digest,
                bundle_digest: run.report.bundle_digest,
                report_digest: null,
                per_case_results: null,
                known_shared_dependencies: null,
                execution_date: null,
                toolchain: null,
                signed_by: null,
            }],
    ];
    for (const [name, value] of files) {
        writeFileSync(resolve(HERE, name), `${JSON.stringify(value, null, 2)}\n`);
    }
    const checksums = files.map(([name]) => (`${fileDigest(relative(ROOT, resolve(HERE, name))).slice(7)}  ${name}`)).join('\n');
    writeFileSync(resolve(HERE, 'CHECKSUMS.sha256'), `${checksums}\n`);
}
function main() {
    const run = runSuite();
    for (const item of run.report.checks) {
        process.stdout.write(`${item.passed ? 'PASS' : 'FAIL'} ${item.id}\n`);
    }
    process.stdout.write(`${run.report.passed ? 'CROSS-SLOT CONFORMANCE PASS' : 'CROSS-SLOT CONFORMANCE FAIL'} — `
        + `${run.report.case_count} cases, ${run.report.negative_pair_count} paired controls\n`);
    if (process.argv.includes('--emit')) {
        emitArtifacts(run);
        process.stdout.write(`wrote candidate artifacts under ${relative(ROOT, HERE)}\n`);
    }
    if (!run.report.passed)
        process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
    main();
