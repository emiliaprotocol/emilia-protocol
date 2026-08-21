// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
// Product configuration for the EMILIA Consequence Firewall. This is not a
// new receipt, authorization token, or standards format. It compiles an
// owner's plain-language selections into the existing Action Control Manifest.
import { createDefaultActionControlManifest, toActionControl, validateActionControlManifest, } from './action-control-manifest.js';
export const PROTECTION_PLAN_VERSION = 'EMILIA-PROTECTION-PLAN-v1';
export const PROTECTION_COVERAGE_STATES = Object.freeze([
    'protected',
    'connector_required',
    'observation_only',
    'not_protected',
    'verification_required',
]);
const EXTRA_ACTIONS = Object.freeze({
    'delete-files': Object.freeze({
        id: 'filesystem.delete',
        label: 'Delete files',
        action_type: 'filesystem.delete',
        risk: 'high',
        receipt_required: true,
        assurance_class: 'class_a',
        match: Object.freeze({ protocol: 'local_agent', tool: 'delete_files' }),
        why: 'Deletes user-selected files or folders. The target set and deletion mode must be bound before mutation.',
        execution_binding: Object.freeze({
            required_fields: Object.freeze([
                'action_type',
                'device_id',
                'target_set_digest',
                'recursive',
                'deletion_mode',
            ]),
        }),
    }),
    'control-machines': Object.freeze({
        id: 'machine.command',
        label: 'Control machines',
        action_type: 'machine.command',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'quorum',
        match: Object.freeze({ protocol: 'local_gateway', tool: 'execute_machine_command' }),
        why: 'Commands equipment or infrastructure. The device, command, parameters, and operating window must be bound before provider entry.',
        execution_binding: Object.freeze({
            required_fields: Object.freeze([
                'action_type',
                'device_id',
                'command_type',
                'command_digest',
                'operating_window',
            ]),
        }),
    }),
});
const BASE_ACTIONS = createDefaultActionControlManifest({ includePassThrough: false }).actions;
const BASE_BY_ID = new Map();
for (const action of BASE_ACTIONS)
    BASE_BY_ID.set(action.id, action);
function preset(id, label, consequence, actionControlId, assuranceFloor, connectorKind, connectorLabel, extraAction = null) {
    const action = extraAction ? toActionControl(extraAction) : BASE_BY_ID.get(actionControlId);
    if (!action)
        throw new TypeError(`protection_action_control_missing:${actionControlId}`);
    return Object.freeze({
        id,
        label,
        consequence,
        action_type: action.action_type,
        action_control_id: action.id,
        assurance_floor: assuranceFloor,
        connector: Object.freeze({ required: true, kind: connectorKind, label: connectorLabel }),
        action: Object.freeze(structuredClone(action)),
    });
}
export const PROTECTION_PRESETS = Object.freeze([
    preset('spend-money', 'Spend money', 'Money leaves an account or stored balance.', 'money_movement.release', 'class_a', 'payment_boundary', 'Payment API or agent-tool connector'),
    preset('delete-files', 'Delete files', 'Files or folders are destroyed or made unavailable.', 'filesystem.delete', 'class_a', 'managed_filesystem', 'Managed-folder or agent-filesystem connector', EXTRA_ACTIONS['delete-files']),
    preset('change-access', 'Change account access', 'A person or agent gains broader privileges.', 'permissions.admin_change', 'quorum', 'identity_boundary', 'Identity or SaaS administration connector'),
    preset('publish-code', 'Publish or deploy code', 'Software changes a live service or production environment.', 'production.deploy', 'quorum', 'deployment_boundary', 'Source-control or deployment connector'),
    preset('send-sensitive-data', 'Send sensitive data', 'Private records leave their system of record.', 'data.bulk_export', 'class_a', 'data_boundary', 'Database, storage, or export connector'),
    preset('control-machines', 'Control machines', 'A command changes physical equipment or infrastructure.', 'machine.command', 'quorum', 'machine_boundary', 'Equipment gateway or appliance connector', EXTRA_ACTIONS['control-machines']),
]);
const PRESET_BY_ID = new Map(PROTECTION_PRESETS.map((entry) => [entry.id, entry]));
const ASSURANCE_RANK = { class_a: 1, quorum: 2 };
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
function clone(value) {
    return structuredClone(value);
}
function strictInstant(value) {
    if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
        throw new TypeError('protection_created_at_invalid');
    }
    const normalized = new Date(value).toISOString();
    if (normalized !== value)
        throw new TypeError('protection_created_at_invalid');
    return normalized;
}
function requestedAssurance(value, floor) {
    const requested = value === undefined ? floor : value;
    if (requested !== 'class_a' && requested !== 'quorum') {
        throw new TypeError('protection_assurance_invalid');
    }
    if (ASSURANCE_RANK[requested] < ASSURANCE_RANK[floor]) {
        throw new TypeError('protection_assurance_below_floor');
    }
    return requested;
}
export function createProtectionPlan({ planId, ownerLabel = 'Local owner', createdAt = new Date().toISOString(), selections, }) {
    if (typeof planId !== 'string' || !SAFE_ID.test(planId)) {
        throw new TypeError('protection_plan_id_invalid');
    }
    if (typeof ownerLabel !== 'string' || ownerLabel.length < 1 || ownerLabel.length > 160) {
        throw new TypeError('protection_owner_label_invalid');
    }
    if (!Array.isArray(selections) || selections.length === 0) {
        throw new TypeError('protection_selection_required');
    }
    const seen = new Set();
    const compiled = selections.map((selection) => {
        if (!selection || typeof selection !== 'object' || Array.isArray(selection)) {
            throw new TypeError('protection_selection_invalid');
        }
        if (Object.keys(selection).some((key) => !['presetId', 'assuranceClass'].includes(key))) {
            throw new TypeError('protection_selection_invalid');
        }
        const selectedPreset = PRESET_BY_ID.get(selection.presetId);
        if (!selectedPreset)
            throw new TypeError('protection_preset_unknown');
        if (seen.has(selectedPreset.id))
            throw new TypeError('protection_preset_duplicate');
        seen.add(selectedPreset.id);
        const assuranceClass = requestedAssurance(selection.assuranceClass, selectedPreset.assurance_floor);
        const action = clone(selectedPreset.action);
        action.assurance_class = assuranceClass;
        return {
            selection: {
                preset_id: selectedPreset.id,
                label: selectedPreset.label,
                consequence: selectedPreset.consequence,
                action_type: selectedPreset.action_type,
                assurance_class: assuranceClass,
                connector: clone(selectedPreset.connector),
            },
            action,
        };
    });
    const manifest = createDefaultActionControlManifest({
        service: {
            name: `${ownerLabel} EMILIA Consequence Firewall`,
            issuer: `urn:emilia:local-owner:${planId}`,
            manifest_url: `urn:emilia:local-plan:${planId}`,
        },
        includePassThrough: false,
    });
    manifest.actions = compiled.map((entry) => entry.action);
    const validation = validateActionControlManifest(manifest);
    if (!validation.ok) {
        throw new TypeError(`protection_manifest_invalid:${validation.errors.join('|')}`);
    }
    return Object.freeze({
        '@version': PROTECTION_PLAN_VERSION,
        plan_id: planId,
        owner: Object.freeze({ label: ownerLabel }),
        created_at: strictInstant(createdAt),
        selections: Object.freeze(compiled.map((entry) => Object.freeze(entry.selection))),
        action_control_manifest: Object.freeze(manifest),
        authority: Object.freeze({
            status: 'unsigned_owner_draft',
            limitation: 'A selection is not authority. The owner must review and pin the plan before an owning connector may enforce it.',
        }),
        activation: Object.freeze({
            status: 'not_active',
            limitation: 'Selection creates configuration only. Protection begins only after owner pinning, owning-connector installation, and a verified active refusal probe earn gated coverage.',
        }),
    });
}
export function evaluateProtectionCoverage(plan, verifiedCoverage = null) {
    if (!plan || plan['@version'] !== PROTECTION_PLAN_VERSION || !Array.isArray(plan.selections)) {
        throw new TypeError('protection_plan_invalid');
    }
    const trusted = verifiedCoverage?.accepted === true
        && verifiedCoverage?.verification === 'verified'
        && Array.isArray(verifiedCoverage?.surfaces);
    const actions = plan.selections.map((selection) => {
        if (!trusted) {
            return { preset_id: selection.preset_id, action_type: selection.action_type, state: 'verification_required', reason: 'verified_coverage_required' };
        }
        const surface = verifiedCoverage.surfaces.find((candidate) => candidate?.action_family === selection.action_type);
        if (!surface) {
            return { preset_id: selection.preset_id, action_type: selection.action_type, state: 'connector_required', reason: 'protected_surface_not_found' };
        }
        if (surface.state === 'gated' && surface.refusal_probe_verified === true) {
            return { preset_id: selection.preset_id, action_type: selection.action_type, state: 'protected', reason: 'attested_gate_and_refusal_probe' };
        }
        if (surface.state === 'witness_only') {
            return { preset_id: selection.preset_id, action_type: selection.action_type, state: 'observation_only', reason: 'traffic_observed_enforcement_unproven' };
        }
        if (surface.state === 'ungated') {
            return { preset_id: selection.preset_id, action_type: selection.action_type, state: 'not_protected', reason: 'surface_ungated' };
        }
        return { preset_id: selection.preset_id, action_type: selection.action_type, state: 'verification_required', reason: surface.state === 'stale' ? 'coverage_stale' : 'coverage_unknown' };
    });
    const protectedCount = actions.filter((entry) => entry.state === 'protected').length;
    const overall = protectedCount === actions.length && actions.length > 0
        ? 'protected'
        : (protectedCount > 0 ? 'partial' : 'not_active');
    return Object.freeze({
        overall,
        protected_actions: protectedCount,
        selected_actions: actions.length,
        actions: Object.freeze(actions.map((entry) => Object.freeze(entry))),
    });
}
export default {
    PROTECTION_PLAN_VERSION,
    PROTECTION_COVERAGE_STATES,
    PROTECTION_PRESETS,
    createProtectionPlan,
    evaluateProtectionCoverage,
};
//# sourceMappingURL=protection-plan.js.map