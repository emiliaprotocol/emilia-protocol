// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  WORKS_WORKFLOW_REVISION_INITIAL,
  validateAssignmentCommand,
  validateNotificationRead,
  validateSelectProposal,
  validateWorkspaceCommand,
} from '../lib/works/workflow-model.ts';

const IDEM = 'works-command-0001';

describe('Works operating workflow browser contract', () => {
  it('pins legacy records to revision zero and accepts exact workspace commands', () => {
    expect(WORKS_WORKFLOW_REVISION_INITIAL).toBe(0);
    expect(validateWorkspaceCommand({
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    })).toEqual({ ok: true, value: {
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    } });
  });

  it('rejects missing CAS/idempotency fields and unknown request material', () => {
    expect(validateWorkspaceCommand({ command: 'close_job', record_id: 'job-one' }))
      .toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateWorkspaceCommand({
      command: 'close_job', record_id: 'job-one', expected_revision: 0,
      idempotency_key: IDEM, owner_entity_id: 'attacker',
    })).toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateWorkspaceCommand({
      command: 'close_job', record_id: 'job-one', expected_revision: -1, idempotency_key: IDEM,
    })).toMatchObject({ ok: false, code: 'invalid_expected_revision' });
  });

  it('requires explicit scope, acceptance criteria, and external terms for selection', () => {
    expect(validateSelectProposal({
      proposal_id: 'proposal-one', expected_revision: 0, idempotency_key: IDEM,
      scope: 'Implement the bounded refund workflow.',
      acceptance_criteria: ['Hostile refund test passes', 'Buyer can inspect delivery evidence'],
      terms: 'Commercial terms agreed externally on 2026-09-07.',
    })).toMatchObject({ ok: true, value: { proposal_id: 'proposal-one', expected_revision: 0 } });
    expect(validateSelectProposal({
      proposal_id: 'proposal-one', expected_revision: 0, idempotency_key: IDEM,
      scope: 'Work', acceptance_criteria: [], terms: 'External',
    })).toMatchObject({ ok: false, code: 'invalid_acceptance_criteria' });
  });

  it('bounds command-specific delivery, change, and cancellation evidence', () => {
    expect(validateAssignmentCommand({
      command: 'submit_delivery', expected_revision: 1, idempotency_key: IDEM,
      delivery_url: 'https://example.com/delivery/1', summary: 'Ready for buyer review.',
    })).toMatchObject({ ok: true, value: { command: 'submit_delivery' } });
    expect(validateAssignmentCommand({
      command: 'submit_delivery', expected_revision: 1, idempotency_key: IDEM,
      delivery_url: 'javascript:alert(1)', summary: 'Unsafe URL.',
    })).toMatchObject({ ok: false, code: 'invalid_delivery_url' });
    expect(validateAssignmentCommand({
      command: 'submit_delivery', expected_revision: 1, idempotency_key: IDEM,
      delivery_url: 'https://user:secret@example.com/report', summary: 'Unsafe credentials.',
    })).toMatchObject({ ok: false, code: 'invalid_delivery_url' });
    expect(validateAssignmentCommand({
      command: 'request_changes', expected_revision: 2, idempotency_key: IDEM,
    })).toMatchObject({ ok: false, code: 'invalid_summary' });
    expect(validateAssignmentCommand({
      command: 'cancel', expected_revision: 2, idempotency_key: IDEM,
    })).toMatchObject({ ok: false, code: 'invalid_reason' });
  });

  it('requires CAS and idempotency for notification reads', () => {
    expect(validateNotificationRead({ expected_revision: 0, idempotency_key: IDEM }))
      .toEqual({ ok: true, value: { expected_revision: 0, idempotency_key: IDEM } });
    expect(validateNotificationRead({ expected_revision: 0 }))
      .toMatchObject({ ok: false, code: 'invalid_command' });
  });
});
