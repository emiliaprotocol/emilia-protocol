// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ACTION_CONTROL_MANIFEST_VERSION,
  createDefaultActionControlManifest,
  findActionControl,
  validateActionControlManifest,
} from '../packages/gate/action-control-manifest.js';

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
    const report = validateActionControlManifest(manifest);
    expect(report).toEqual({ ok: true, errors: [] });
    expect(manifest.profile).toBe('emilia.action-control');
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
      expect(action.control.evidence_output).toMatchObject({
        audit_event: true,
        execution_attestation: true,
        reliance_packet: true,
        blocked_attempts: true,
      });
    }
  });
});
