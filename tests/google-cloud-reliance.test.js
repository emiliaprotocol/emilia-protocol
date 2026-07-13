// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  EXACT_ACTION,
  LAB_VERSION,
  runGoogleCloudRelianceLab,
} from '../examples/google-cloud-reliance/demo.mjs';

describe('External Reliance Lab for Google Cloud-shaped mutations', () => {
  it('refuses every bad presentation, executes the exact quorum case once, and refuses replay', async () => {
    const result = await runGoogleCloudRelianceLab();

    expect(result['@version']).toBe(LAB_VERSION);
    expect(result.local_controls.iam.verdict).toBe('allow');
    expect(result.local_controls.model_armor.verdict).toBe('allow');
    expect(result.relying_party_requirement.action).toEqual(EXACT_ACTION);
    expect(result.relying_party_requirement.mcp_tool).toBe('set_iam_policy');
    expect(result.executor_call_count).toBe(1);

    const byId = Object.fromEntries(result.cases.map((item) => [item.id, item]));
    for (const id of [
      'local-controls-allow-but-evidence-missing',
      'single-approver-cannot-fill-two-person-rule',
      'receipt-for-viewer-cannot-grant-owner',
      'tampered-receipt-refused',
      'accepted-receipt-replay-refused',
    ]) {
      expect(byId[id].verdict, id).toBe('refuse');
      expect(byId[id].executor_called, id).toBe(false);
      expect(byId[id].reason, id).toBeTruthy();
    }

    const accepted = byId['exact-quorum-evidence-runs-once'];
    expect(accepted.verdict).toBe('rely');
    expect(accepted.executor_called).toBe(true);
    expect(accepted.reliance_verdict).toBe('rely');
    expect(accepted.execution_binds_authorization).toBe(true);
  });

  it('keeps the material GCP mutation fields explicit in the relying-party requirement', async () => {
    const result = await runGoogleCloudRelianceLab();
    expect(result.relying_party_requirement.exact_fields).toEqual([
      'action_type', 'resource', 'member', 'role',
    ]);
    expect(result.relying_party_requirement.assurance_class).toBe('quorum');
    expect(result.relying_party_requirement.one_time_consumption).toBe(true);
  });
});
