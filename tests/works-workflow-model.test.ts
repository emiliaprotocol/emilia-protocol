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

  it('rejects unsupported workspace commands, identifiers and idempotency keys', () => {
    const base = { expected_revision: 0, idempotency_key: IDEM };
    expect(validateWorkspaceCommand(null)).toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateWorkspaceCommand({ ...base, command: 'publish_everything', record_id: 'job-one' }))
      .toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateWorkspaceCommand({ ...base, command: 'close_job', record_id: '../job' }))
      .toMatchObject({ ok: false, code: 'invalid_record_id' });
    expect(validateWorkspaceCommand({ ...base, command: 'close_job', record_id: 'job-one', idempotency_key: 'short' }))
      .toMatchObject({ ok: false, code: 'invalid_idempotency_key' });
  });

  it('bounds every selection field and trims the accepted agreement', () => {
    const valid = {
      proposal_id: 'proposal-one', expected_revision: 0, idempotency_key: IDEM,
      scope: '  Bounded work  ', acceptance_criteria: ['  Evidence attached  '], terms: '  External terms  ',
    };
    expect(validateSelectProposal(valid)).toEqual({ ok: true, value: {
      ...valid, scope: 'Bounded work', acceptance_criteria: ['Evidence attached'], terms: 'External terms',
    } });
    for (const [override, code] of [
      [{ proposal_id: '../proposal' }, 'invalid_proposal_id'],
      [{ expected_revision: 1.5 }, 'invalid_expected_revision'],
      [{ scope: ' ' }, 'invalid_scope'],
      [{ terms: 'x'.repeat(8_001) }, 'invalid_terms'],
      [{ acceptance_criteria: 'not-an-array' }, 'invalid_acceptance_criteria'],
      [{ acceptance_criteria: Array(33).fill('criterion') }, 'invalid_acceptance_criteria'],
      [{ acceptance_criteria: [''] }, 'invalid_acceptance_criteria'],
      [{ extra_authority: true }, 'invalid_selection'],
    ] as const) {
      expect(validateSelectProposal({ ...valid, ...override }), JSON.stringify(override))
        .toMatchObject({ ok: false, code });
    }
  });

  it('rejects command-specific evidence on the wrong lifecycle transition', () => {
    const base = { expected_revision: 1, idempotency_key: IDEM };
    expect(validateAssignmentCommand(null)).toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateAssignmentCommand({ ...base, command: 'execute_agent' }))
      .toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateAssignmentCommand({ ...base, command: 'builder_confirm', delivery_url: 'https://example.com' }))
      .toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateAssignmentCommand({ ...base, command: 'builder_confirm', summary: 'not supported' }))
      .toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateAssignmentCommand({ ...base, command: 'builder_confirm', reason: 'not supported' }))
      .toMatchObject({ ok: false, code: 'invalid_command' });
    expect(validateAssignmentCommand({ ...base, command: 'submit_delivery',
      delivery_url: 'not-a-url', summary: 'Evidence' }))
      .toMatchObject({ ok: false, code: 'invalid_delivery_url' });
    expect(validateAssignmentCommand({ ...base, command: 'submit_delivery',
      delivery_url: 'https://example.com/report', summary: ' ' }))
      .toMatchObject({ ok: false, code: 'invalid_summary' });
    expect(validateAssignmentCommand({ ...base, command: 'cancel', reason: 'x'.repeat(2_001) }))
      .toMatchObject({ ok: false, code: 'invalid_reason' });
    expect(validateAssignmentCommand({ ...base, command: 'builder_confirm', expected_revision: 1.5 }))
      .toMatchObject({ ok: false, code: 'invalid_expected_revision' });
  });

  it('validates CAS and idempotency independently on notification reads', () => {
    expect(validateNotificationRead({ expected_revision: -1, idempotency_key: IDEM }))
      .toMatchObject({ ok: false, code: 'invalid_expected_revision' });
    expect(validateNotificationRead({ expected_revision: 0, idempotency_key: 'unsafe key' }))
      .toMatchObject({ ok: false, code: 'invalid_idempotency_key' });
  });
});
