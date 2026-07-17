// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  RSL_CLEARANCE_DEMO_VERSION,
  runRslMediaClearanceDemo,
} from '../examples/rsl-media-clearance/demo.mjs';
import {
  assessRslMediaEvaluation,
  RSL_MEDIA_NORMALIZED_VERSION,
} from '../examples/rsl-media-clearance/profile.mjs';

describe('RSL-MEDIA declaration to EMILIA clearance reference', () => {
  it('executes one exact use and refuses mutation, out-of-scope use, replay, absence, prohibition, and staleness', async () => {
    const result = await runRslMediaClearanceDemo();
    expect(result['@version']).toBe(RSL_CLEARANCE_DEMO_VERSION);
    expect(result.executor_call_count).toBe(1);
    expect(result.concurrent_executor_call_count).toBe(1);

    const byId = Object.fromEntries(result.cases.map((item) => [item.id, item]));
    expect(byId['exact-use-executes-once']).toMatchObject({
      verdict: 'execute',
      receipt_valid: true,
      grant_composition_valid: true,
      declaration_binding_valid: true,
    });
    expect(byId['replay-refused']).toMatchObject({
      verdict: 'refuse',
      reason: 'clearance_replay_refused',
    });
    expect(byId['independently-issued-same-action-refused']).toMatchObject({
      verdict: 'refuse',
      reason: 'clearance_replay_refused',
    });
    expect(byId['concurrent-independent-receipts-admit-one']).toMatchObject({
      verdict: 'refuse',
      reason: 'clearance_replay_refused',
      executed_count: 1,
      refused_count: 1,
    });
    expect(byId['mutated-signed-action-refused'].verdict).toBe('refuse');
    expect(byId['valid-signature-outside-grant-terms-refused']).toMatchObject({
      verdict: 'refuse',
      reason: 'constraints_mismatch',
      receipt_valid: true,
    });
    expect(byId['prohibited-declaration-refused']).toMatchObject({
      verdict: 'refuse',
      reason: 'refuse_prohibited_use',
    });
    expect(byId['absent-declaration-refused']).toMatchObject({
      verdict: 'refuse',
      reason: 'refuse_no_declaration',
    });
    expect(byId['stale-declaration-refused']).toMatchObject({
      verdict: 'refuse',
      reason: 'refuse_stale_declaration',
    });
    expect(byId['changed-declaration-refused']).toMatchObject({
      verdict: 'refuse',
      reason: 'refuse_declaration_grant_mismatch',
    });
  });

  it('publishes every required honesty boundary in the result', async () => {
    const result = await runRslMediaClearanceDemo();
    expect(result.notice.join(' ')).toContain('not endorsed by RSL Media');
    expect(result.notice.join(' ')).toContain('must not be used for production');
    expect(result.notice.join(' ')).toContain('not a real mobile ceremony');
    expect(result.notice.join(' ')).toContain('does not establish rights ownership');
  });

  it('rejects impossible declaration timestamps instead of normalizing them', () => {
    const result = assessRslMediaEvaluation({
      profile: RSL_MEDIA_NORMALIZED_VERSION,
      trusted_source: true,
      source_document_digest:
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      operative: true,
      status: 'active',
      conflict_free: true,
      subject: 'identity',
      subject_is_minor: false,
      usage_decision: 'clearance_required',
      usage_token: 'media:ai-generate',
      isrd: 'RSL-0000-0042-7',
      allowed_terms: {},
      current_through: '2026-02-30T00:00:00Z',
    }, { now: '2026-02-28T00:00:00Z' });
    expect(result).toMatchObject({
      eligible: false,
      verdict: 'refuse_stale_declaration',
    });
  });
});
