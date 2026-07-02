// SPDX-License-Identifier: Apache-2.0
//
// EP Action Control Manifest: the missing control-plane waist between agent
// runtimes, receipt formats, transparency logs, and system-of-record adapters.
//
// A receipt proves an authorization event. This manifest tells an executor
// when a receipt is required, what assurance tier is required, which material
// fields must be observed from the system of record, and what evidence must be
// emitted after the effect boundary.

import { HIGH_RISK_ACTION_PACKS, DEFAULT_PASS_THROUGH_ACTIONS } from './action-packs.js';

export const ACTION_CONTROL_MANIFEST_VERSION = 'EP-ACTION-CONTROL-MANIFEST-v0.2';
export const ACTION_CONTROL_SCHEMA_URL = 'https://www.emiliaprotocol.ai/docs/schemas/agent-action-control-manifest-v0.2.schema.json';
export const ACTION_CONTROL_CONFORMANCE_LEVEL = 'EG-1';

const RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical']);
const ASSURANCE_CLASSES = new Set(['software', 'class_a', 'quorum']);
const ENFORCEMENT_POINTS = new Set(['pre_execution', 'pre_effect_commit']);

export const ACTION_CONTROL_DEFAULTS = Object.freeze({
  decision_point: 'pre_effect_commit',
  missing_receipt: 'refuse',
  invalid_receipt: 'refuse',
  stale_receipt: 'refuse',
  replay: 'one_time_consumption',
  evidence_log: 'strict',
});

export const ACTION_CONTROL_EVIDENCE_PROFILES = Object.freeze({
  authorization_receipt: 'EP-RECEIPT-v1',
  execution_attestation: 'EP-EXECUTION-ATTESTATION-v1',
  reliance_packet: 'EP-RELIANCE-PACKET-v1',
  transparency: 'SCITT-compatible Signed Statement',
});

export const ACTION_CONTROL_CONFORMANCE_CHECKS = Object.freeze([
  'missing_receipt_refused',
  'software_on_classA_refused',
  'execution_drift_refused',
  'valid_classA_runs',
  'replay_refused',
  'tampered_refused',
  'execution_proof_binds',
  'reliance_packet_rely',
]);

function cloneJson(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function normalizeRisk(risk) {
  return RISK_LEVELS.has(risk) ? risk : 'high';
}

function normalizeAssurance(value) {
  return ASSURANCE_CLASSES.has(value) ? value : 'software';
}

function defaultControlForAction(action) {
  const requiredFields = action.execution_binding?.required_fields || [];
  if (!action.receipt_required) {
    return {
      enforcement_point: 'none',
      authorization_receipt: { required: false },
      evidence_output: { audit_event: true },
    };
  }
  return {
    enforcement_point: 'pre_effect_commit',
    status: 428,
    challenge_header: 'Receipt-Required',
    proof_header: 'X-EMILIA-Receipt',
    authorization_receipt: {
      required: true,
      profile: 'EP-RECEIPT-v1',
      signature: 'Ed25519 over RFC 8785 canonical JSON',
      verifier: 'offline',
    },
    replay: {
      mode: 'one_time_consumption',
      receipt_id_required: true,
    },
    execution_binding: {
      required: true,
      source: 'system_of_record',
      required_fields: [...requiredFields],
    },
    transparency: {
      mode: 'registerable',
      profile: 'SCITT Signed Statement',
      required: false,
    },
    evidence_output: {
      audit_event: true,
      execution_attestation: true,
      reliance_packet: true,
      blocked_attempts: true,
    },
  };
}

export function toActionControl(action) {
  const out = {
    id: action.id,
    label: action.label || action.description || action.id,
    action_type: action.action_type,
    risk: normalizeRisk(action.risk || (action.receipt_required ? 'high' : 'low')),
    receipt_required: !!action.receipt_required,
    assurance_class: normalizeAssurance(action.assurance_class),
    max_age_sec: action.max_age_sec || 900,
    match: cloneJson(action.match || {}),
    why: action.why || action.description || null,
    control: cloneJson(action.control || defaultControlForAction(action)),
    conformance: {
      level: ACTION_CONTROL_CONFORMANCE_LEVEL,
      checks: [...ACTION_CONTROL_CONFORMANCE_CHECKS],
      ...(action.conformance || {}),
    },
  };
  if (action.quorum) out.quorum = cloneJson(action.quorum);
  return out;
}

export function createDefaultActionControlManifest({
  service = {},
  includePassThrough = true,
  extraActions = [],
} = {}) {
  const actions = [
    ...HIGH_RISK_ACTION_PACKS.map(toActionControl),
    ...(includePassThrough ? DEFAULT_PASS_THROUGH_ACTIONS.map(toActionControl) : []),
    ...extraActions.map(toActionControl),
  ];
  return {
    '@version': ACTION_CONTROL_MANIFEST_VERSION,
    '$schema': ACTION_CONTROL_SCHEMA_URL,
    profile: 'emilia.action-control',
    service: {
      name: service.name || 'EMILIA Gate default action controls',
      issuer: service.issuer || 'https://www.emiliaprotocol.ai',
      manifest_url: service.manifest_url || 'https://www.emiliaprotocol.ai/.well-known/agent-action-control.json',
      ...service,
    },
    defaults: { ...ACTION_CONTROL_DEFAULTS },
    evidence_profiles: { ...ACTION_CONTROL_EVIDENCE_PROFILES },
    actions,
  };
}

function selectorMatches(match = {}, selector = {}) {
  if (!match || typeof match !== 'object') return false;
  return Object.entries(match).every(([k, v]) => selector[k] === v);
}

export function findActionControl(manifest, selector = {}) {
  if (!manifest || !Array.isArray(manifest.actions)) return null;
  return manifest.actions.find((action) => {
    if (selector.action_type && action.action_type === selector.action_type) return true;
    return selectorMatches(action.match, selector);
  }) || null;
}

export function validateActionControlManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { ok: false, errors: ['manifest must be an object'] };
  }
  if (manifest['@version'] !== ACTION_CONTROL_MANIFEST_VERSION) {
    errors.push(`@version must be ${ACTION_CONTROL_MANIFEST_VERSION}`);
  }
  if (manifest.profile !== 'emilia.action-control') {
    errors.push('profile must be emilia.action-control');
  }
  if (!manifest.service || typeof manifest.service !== 'object') {
    errors.push('service object is required');
  }
  if (!manifest.defaults || typeof manifest.defaults !== 'object') {
    errors.push('defaults object is required');
  }
  if (!Array.isArray(manifest.actions) || manifest.actions.length === 0) {
    errors.push('actions must be a non-empty array');
  }
  for (const [idx, action] of (manifest.actions || []).entries()) {
    const prefix = `actions[${idx}]`;
    if (!action || typeof action !== 'object') {
      errors.push(`${prefix} must be an object`);
      continue;
    }
    if (!action.id || typeof action.id !== 'string') errors.push(`${prefix}.id is required`);
    if (!action.action_type || typeof action.action_type !== 'string') errors.push(`${prefix}.action_type is required`);
    if (!action.match || typeof action.match !== 'object') errors.push(`${prefix}.match is required`);
    if (typeof action.receipt_required !== 'boolean') errors.push(`${prefix}.receipt_required must be boolean`);
    if (!RISK_LEVELS.has(action.risk)) errors.push(`${prefix}.risk must be low|medium|high|critical`);
    if (!ASSURANCE_CLASSES.has(action.assurance_class)) errors.push(`${prefix}.assurance_class must be software|class_a|quorum`);
    if (action.receipt_required) {
      if (!Number.isFinite(action.max_age_sec) || action.max_age_sec <= 0) errors.push(`${prefix}.max_age_sec must be positive`);
      const control = action.control;
      if (!control || typeof control !== 'object') {
        errors.push(`${prefix}.control is required when receipt_required=true`);
        continue;
      }
      if (!ENFORCEMENT_POINTS.has(control.enforcement_point)) {
        errors.push(`${prefix}.control.enforcement_point must be pre_execution or pre_effect_commit`);
      }
      if (control.status !== 428) errors.push(`${prefix}.control.status must be 428`);
      if (control.authorization_receipt?.required !== true) errors.push(`${prefix}.control.authorization_receipt.required must be true`);
      if (control.authorization_receipt?.profile !== 'EP-RECEIPT-v1') errors.push(`${prefix}.control.authorization_receipt.profile must be EP-RECEIPT-v1`);
      if (control.authorization_receipt?.verifier !== 'offline') errors.push(`${prefix}.control.authorization_receipt.verifier must be offline`);
      if (control.replay?.mode !== 'one_time_consumption') errors.push(`${prefix}.control.replay.mode must be one_time_consumption`);
      if (control.replay?.receipt_id_required !== true) errors.push(`${prefix}.control.replay.receipt_id_required must be true`);
      const fields = control.execution_binding?.required_fields;
      if (control.execution_binding?.required !== true) errors.push(`${prefix}.control.execution_binding.required must be true`);
      if (control.execution_binding?.source !== 'system_of_record') errors.push(`${prefix}.control.execution_binding.source must be system_of_record`);
      if (!Array.isArray(fields) || fields.length === 0 || fields.some((f) => typeof f !== 'string' || !f)) {
        errors.push(`${prefix}.control.execution_binding.required_fields must be a non-empty string array`);
      }
      if (control.evidence_output?.execution_attestation !== true) errors.push(`${prefix}.control.evidence_output.execution_attestation must be true`);
      if (control.evidence_output?.reliance_packet !== true) errors.push(`${prefix}.control.evidence_output.reliance_packet must be true`);
      if (action.conformance?.level !== ACTION_CONTROL_CONFORMANCE_LEVEL) errors.push(`${prefix}.conformance.level must be ${ACTION_CONTROL_CONFORMANCE_LEVEL}`);
    }
  }
  return { ok: errors.length === 0, errors };
}

export default {
  ACTION_CONTROL_MANIFEST_VERSION,
  ACTION_CONTROL_SCHEMA_URL,
  ACTION_CONTROL_CONFORMANCE_LEVEL,
  ACTION_CONTROL_DEFAULTS,
  ACTION_CONTROL_EVIDENCE_PROFILES,
  ACTION_CONTROL_CONFORMANCE_CHECKS,
  toActionControl,
  createDefaultActionControlManifest,
  findActionControl,
  validateActionControlManifest,
};
