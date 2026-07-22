// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ACTION_CONTROL_ACQUISITION_ACTION_TYPES,
  ACTION_CONTROL_MANIFEST_VERSION,
  createDefaultActionControlManifest,
  findActionControl,
  resolveActionControl,
  validateActionControlManifest,
} from '../packages/gate/src/action-control-manifest.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const readJson = (rel) => JSON.parse(readFileSync(resolve(HERE, '..', rel), 'utf8'));

describe('EP Action Control Manifest v0.2', () => {
  it('validates the default gate control manifest', () => {
    const manifest = createDefaultActionControlManifest();
    const report = validateActionControlManifest(manifest);
    expect(report).toEqual({ ok: true, errors: [] });
    expect(manifest['@version']).toBe(ACTION_CONTROL_MANIFEST_VERSION);
    expect(findActionControl(manifest, { protocol: 'mcp', tool: 'release_payment' })?.action_type).toBe('payment.release');
  });

  it('publishes a valid well-known control manifest', () => {
    const manifest = readJson('public/.well-known/agent-action-control.json');
    const report = validateActionControlManifest(manifest, { requireAcquisition: true });
    expect(report).toEqual({ ok: true, errors: [] });
    expect(['agent-action-control', 'emilia.action-control']).toContain(manifest.profile);
  });

  it('publishes a closed, backwards-compatible acquisition schema extension', () => {
    const schema = readJson('public/docs/schemas/agent-action-control-manifest-v0.2.schema.json');
    expect(schema.$defs.control.properties.authorization).toEqual({
      $ref: '#/$defs/authorization',
    });
    expect(schema.$defs.control.properties.execution_binding.properties.caid_selector)
      .toMatchObject({
        type: 'object',
        required: ['field'],
        additionalProperties: false,
      });
    expect(schema.$defs.authorization).toMatchObject({
      type: 'object',
      required: ['authorization_endpoint', 'flow'],
      additionalProperties: false,
      properties: {
        authorization_endpoint: {
          type: 'string',
          format: 'uri',
        },
        flow: {
          const: 'EP-APPROVAL-v1',
        },
      },
    });
    expect(schema.$defs.control.required || []).not.toContain('authorization');
  });

  it('advertises the control manifest from ep-trust discovery', () => {
    const trust = readJson('public/.well-known/ep-trust.json');
    expect(trust.agent_action_control_url).toBe('https://www.emiliaprotocol.ai/.well-known/agent-action-control.json');
  });

  it('covers every receipt-required action in the public v0.1 Action Risk Manifest', () => {
    const riskManifest = readJson('public/.well-known/agent-actions.json');
    const controlManifest = readJson('public/.well-known/agent-action-control.json');
    const missing = riskManifest.actions
      .filter((action) => action.receipt_required)
      .filter((action) => !findActionControl(controlManifest, action.match || { action_type: action.action_type }))
      .map((action) => action.id);
    expect(missing).toEqual([]);
  });

  it('requires system-of-record execution binding for every public guarded action', () => {
    const manifest = readJson('public/.well-known/agent-action-control.json');
    for (const action of manifest.actions.filter((a) => a.receipt_required)) {
      expect(action.control.enforcement_point).toBe('pre_effect_commit');
      expect(action.control.authorization_receipt).toMatchObject({
        required: true,
        profile: 'EP-RECEIPT-v1',
        verifier: 'offline',
      });
      expect(action.control.replay).toEqual({
        mode: 'one_time_consumption',
        receipt_id_required: true,
      });
      expect(action.control.execution_binding).toMatchObject({
        required: true,
        source: 'system_of_record',
      });
      expect(action.control.execution_binding.required_fields).toContain('action_type');
      expect(action.control.execution_binding.required_fields.length).toBeGreaterThan(1);
      if (ACTION_CONTROL_ACQUISITION_ACTION_TYPES.includes(action.action_type)) {
        expect(action.control.authorization).toEqual({
          authorization_endpoint: 'https://www.emiliaprotocol.ai/api/v1/approvals',
          flow: 'EP-APPROVAL-v1',
        });
        expect(action.control.execution_binding.caid_selector).toEqual({ field: 'action_caid' });
      } else {
        expect(action.control.authorization).toBeUndefined();
      }
      expect(action.control.evidence_output).toMatchObject({
        audit_event: true,
        execution_attestation: true,
        reliance_packet: true,
        blocked_attempts: true,
      });
    }
  });

  it('can enforce the acquisition extension without breaking legacy v0.2 validation', () => {
    const manifest = createDefaultActionControlManifest();
    expect(validateActionControlManifest(manifest, { requireAcquisition: true })).toEqual({
      ok: true,
      errors: [],
    });

    const legacy = structuredClone(manifest);
    delete legacy.actions.find((action) => ACTION_CONTROL_ACQUISITION_ACTION_TYPES.includes(action.action_type))
      .control.authorization;
    expect(validateActionControlManifest(legacy)).toEqual({ ok: true, errors: [] });
    expect(validateActionControlManifest(legacy, { requireAcquisition: true }).errors)
      .toContain('actions[0].control.authorization is required for acquisition conformance');
  });

  it('advertises acquisition only for action types in the closed reference registry', () => {
    const manifest = readJson('public/.well-known/agent-action-control.json');
    const advertised = manifest.actions
      .filter((action) => action.control?.authorization)
      .map((action) => action.action_type);
    expect(new Set(advertised)).toEqual(new Set(ACTION_CONTROL_ACQUISITION_ACTION_TYPES));
    expect(advertised).toEqual(['payment.release', 'payment.release']);

    const unsupported = createDefaultActionControlManifest();
    const action = unsupported.actions.find((candidate) => candidate.action_type !== 'payment.release'
      && candidate.receipt_required);
    action.control.authorization = {
      authorization_endpoint: 'https://www.emiliaprotocol.ai/api/v1/approvals',
      flow: 'EP-APPROVAL-v1',
    };
    expect(validateActionControlManifest(unsupported).errors)
      .toContain('actions[1].control.authorization is advertised for an unsupported acquisition action_type');
  });

  it('strictly validates an acquisition descriptor whenever one is present', () => {
    const cases = [
      {
        mutate: (authorization) => { authorization.flow = 'EP-APPROVAL-v0'; },
        error: 'actions[0].control.authorization.flow must be EP-APPROVAL-v1',
      },
      {
        mutate: (authorization) => { authorization.authorization_endpoint = 'http://approvals.example.test/v1'; },
        error: 'actions[0].control.authorization.authorization_endpoint must be an absolute HTTPS URL without credentials, query, or fragment',
      },
      {
        mutate: (authorization) => { authorization.untrusted_hint = 'skip-human-review'; },
        error: 'actions[0].control.authorization must contain only authorization_endpoint and flow',
      },
    ];

    for (const { mutate, error } of cases) {
      const manifest = createDefaultActionControlManifest();
      const authorization = manifest.actions.find((action) => action.receipt_required).control.authorization;
      mutate(authorization);
      expect(validateActionControlManifest(manifest).errors).toContain(error);
    }
  });

  it('rejects malformed or open CAID selectors instead of weakening exact-action binding', () => {
    for (const selector of [
      { field: 'action_caid', fallback: 'receipt_id' },
      { field: '__proto__' },
      { field: '' },
      'action_caid',
    ]) {
      const manifest = createDefaultActionControlManifest();
      manifest.actions[0].control.execution_binding.caid_selector = selector;
      expect(validateActionControlManifest(manifest).errors).toContain(
        'actions[0].control.execution_binding.caid_selector must select one safe action field',
      );
    }
  });

  it('requires a complete unambiguous transport selector and treats action_type as an added constraint', () => {
    const manifest = createDefaultActionControlManifest();

    expect(findActionControl(manifest, { action_type: 'payment.release' })).toBeNull();
    expect(findActionControl(manifest, { protocol: 'mcp' })).toBeNull();
    expect(findActionControl(manifest, {
      action_type: 'payment.release',
      protocol: 'mcp',
      tool: 'release_payment',
      manifestUrl: 'https://service.example/.well-known/agent-action-control.json',
    })?.id).toBe('money_movement.release');

    expect(findActionControl(manifest, {
      action_type: 'payment.release',
      protocol: 'mcp',
      tool: 'delete_repository',
    })).toBeNull();
    expect(findActionControl(manifest, {
      action_type: 'repository.delete',
      protocol: 'mcp',
      tool: 'release_payment',
    })).toBeNull();
    expect(findActionControl(manifest, {
      action_type: 'payment.release',
      protocol: 'a2a',
    })).toBeNull();
  });

  it('rejects duplicate ids and every pair of selectors one request could satisfy', () => {
    const manifest = createDefaultActionControlManifest();
    const duplicate = structuredClone(manifest.actions[0]);
    duplicate.match = { ...duplicate.match, route: '/also-matches' };
    manifest.actions.push(duplicate);
    const report = validateActionControlManifest(manifest);
    expect(report.ok).toBe(false);
    expect(report.errors.join('\n')).toMatch(/duplicates actions\[0\]\.id/);
    expect(report.errors.join('\n')).toMatch(/match overlaps/);

    const resolution = resolveActionControl(manifest, {
      ...manifest.actions[0].match,
      route: '/also-matches',
    });
    expect(resolution.status).toBe('ambiguous');
  });
});
