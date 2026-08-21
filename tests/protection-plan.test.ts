// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  PROTECTION_PLAN_VERSION,
  PROTECTION_PRESETS,
  createProtectionPlan,
  evaluateProtectionCoverage,
} from '../packages/gate/src/protection-plan.js';
import { validateActionControlManifest } from '../packages/gate/src/action-control-manifest.js';

const CREATED_AT = '2026-08-20T12:00:00.000Z';

describe('EMILIA consumer protection plan', () => {
  it('offers a closed, plain-language set of consequential actions', () => {
    expect(PROTECTION_PRESETS.map((preset) => preset.id)).toEqual([
      'spend-money',
      'delete-files',
      'change-access',
      'publish-code',
      'send-sensitive-data',
      'control-machines',
    ]);
    expect(PROTECTION_PRESETS.every((preset) => preset.connector.required)).toBe(true);
  });

  it('builds a valid Gate manifest for only the actions the owner selects', () => {
    const plan = createProtectionPlan({
      planId: 'personal-laptop',
      ownerLabel: 'Iman',
      createdAt: CREATED_AT,
      selections: [
        { presetId: 'spend-money' },
        { presetId: 'delete-files' },
      ],
    });

    expect(plan['@version']).toBe(PROTECTION_PLAN_VERSION);
    expect(plan.authority.status).toBe('unsigned_owner_draft');
    expect(plan.activation.status).toBe('not_active');
    expect(plan.action_control_manifest.service).toEqual({
      name: 'Iman EMILIA Consequence Firewall',
      issuer: 'urn:emilia:local-owner:personal-laptop',
      manifest_url: 'urn:emilia:local-plan:personal-laptop',
    });
    expect(plan.selections.map((selection) => selection.action_type)).toEqual([
      'payment.release',
      'filesystem.delete',
    ]);
    expect(plan.action_control_manifest.actions.map((action) => action.action_type)).toEqual([
      'payment.release',
      'filesystem.delete',
    ]);
    expect(validateActionControlManifest(plan.action_control_manifest)).toEqual({
      ok: true,
      errors: [],
    });
  });

  it.each([
    [{ planId: 'empty', selections: [] }, 'protection_selection_required'],
    [{ planId: 'unknown', selections: [{ presetId: 'invented' }] }, 'protection_preset_unknown'],
    [{ planId: 'extra-field', selections: [{ presetId: 'spend-money', activate: true }] }, 'protection_selection_invalid'],
    [{
      planId: 'duplicate',
      selections: [{ presetId: 'spend-money' }, { presetId: 'spend-money' }],
    }, 'protection_preset_duplicate'],
  ])('refuses malformed or ambiguous selections', (input, reason) => {
    expect(() => createProtectionPlan({ ...input, createdAt: CREATED_AT } as any)).toThrow(reason);
  });

  it('allows stronger approval but refuses lowering a preset assurance floor', () => {
    const stronger = createProtectionPlan({
      planId: 'strong-spend',
      createdAt: CREATED_AT,
      selections: [{ presetId: 'spend-money', assuranceClass: 'quorum' }],
    });
    expect(stronger.selections[0].assurance_class).toBe('quorum');

    expect(() => createProtectionPlan({
      planId: 'weak-deploy',
      createdAt: CREATED_AT,
      selections: [{ presetId: 'publish-code', assuranceClass: 'class_a' }],
    })).toThrow('protection_assurance_below_floor');
  });

  it('does not turn a user selection or passive observation into a protection claim', () => {
    const plan = createProtectionPlan({
      planId: 'coverage-check',
      createdAt: CREATED_AT,
      selections: [
        { presetId: 'spend-money' },
        { presetId: 'delete-files' },
        { presetId: 'send-sensitive-data' },
      ],
    });

    const coverage = evaluateProtectionCoverage(plan, {
      accepted: true,
      verification: 'verified',
      surfaces: [
        {
          action_family: 'payment.release',
          state: 'gated',
          refusal_probe_verified: true,
        },
        {
          action_family: 'data.export',
          state: 'witness_only',
          refusal_probe_verified: false,
        },
      ],
    });

    expect(coverage.overall).toBe('partial');
    expect(coverage.actions).toEqual([
      expect.objectContaining({ preset_id: 'spend-money', state: 'protected' }),
      expect.objectContaining({ preset_id: 'delete-files', state: 'connector_required' }),
      expect.objectContaining({ preset_id: 'send-sensitive-data', state: 'observation_only' }),
    ]);
  });

  it('requires verifier output before crediting even a gated-looking surface', () => {
    const plan = createProtectionPlan({
      planId: 'unverified-coverage',
      createdAt: CREATED_AT,
      selections: [{ presetId: 'spend-money' }],
    });

    const coverage = evaluateProtectionCoverage(plan, {
      accepted: false,
      verification: 'unverified',
      surfaces: [{
        action_family: 'payment.release',
        state: 'gated',
        refusal_probe_verified: true,
      }],
    });

    expect(coverage.overall).toBe('not_active');
    expect(coverage.actions[0].state).toBe('verification_required');
  });
});
