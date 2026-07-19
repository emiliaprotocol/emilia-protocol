// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { RELEASE_LOCK_ENDPOINTS } from './api';
import {
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
  DEMO_RELEASE_LOCK,
  selectMaterialQuestions,
} from './demo-fixture';
import {
  buildAmendedDemoState,
  initialDemoState,
} from './demo-store';
import { buildActionMirrorBindings } from './digests';

describe('Release Lock deterministic demo contract', () => {
  it('keeps the expected backend calls centralized', () => {
    expect(RELEASE_LOCK_ENDPOINTS).toEqual({
      create: '',
      exchange: '/invitations/exchange',
      exchangePairing: '/pairings/exchange',
      get: expect.any(Function),
      registerOptions: expect.any(Function),
      registerVerify: expect.any(Function),
      resolutionOptions: expect.any(Function),
      resolutionSubmit: expect.any(Function),
      createPairing: expect.any(Function),
      evidence: expect.any(Function),
      participantEvidence: expect.any(Function),
      stageDraw: expect.any(Function),
      amend: expect.any(Function),
    });
    expect(RELEASE_LOCK_ENDPOINTS.get('lock/id')).toBe('/lock%2Fid/view');
    expect(RELEASE_LOCK_ENDPOINTS.evidence('lock/id')).toBe('/lock%2Fid/evidence');
  });

  it('selects three stable material questions for each distinct ceremony', () => {
    const coQuestions = selectMaterialQuestions(
      DEMO_RELEASE_LOCK,
      CEREMONY_CO_ACCEPTANCE,
    );
    const drawQuestions = selectMaterialQuestions(
      DEMO_RELEASE_LOCK,
      CEREMONY_DRAW_RELEASE,
    );

    expect(coQuestions.map(({ id }) => id)).toEqual([
      'co_price',
      'co_document',
      'co_scope',
    ]);
    expect(drawQuestions.map(({ id }) => id)).toEqual([
      'draw_payees',
      'draw_completion',
      'draw_waiver',
    ]);
  });

  it('binds ceremony, prompts, answers, and the exact action digest', async () => {
    const questions = selectMaterialQuestions(
      DEMO_RELEASE_LOCK,
      CEREMONY_DRAW_RELEASE,
    );
    const answers = Object.fromEntries(
      questions.map((question) => [question.id, question.correct_value]),
    );

    const first = await buildActionMirrorBindings({
      lock: DEMO_RELEASE_LOCK,
      ceremony: CEREMONY_DRAW_RELEASE,
      questions,
      answers,
    });
    const second = await buildActionMirrorBindings({
      lock: DEMO_RELEASE_LOCK,
      ceremony: CEREMONY_DRAW_RELEASE,
      questions,
      answers,
    });

    expect(first).toEqual(second);
    expect(first.ceremony).toBe(CEREMONY_DRAW_RELEASE);
    expect(first.action_digest).toBe(
      DEMO_RELEASE_LOCK.ceremonies[CEREMONY_DRAW_RELEASE].digest,
    );
    expect(first.prompt_set_digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(first.answer_digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(first.prompt_set_digest).not.toBe(first.answer_digest);
  });

  it('invalidates both ceremonies and their eligibility on amendment', () => {
    const complete = initialDemoState();
    complete.created = true;
    complete.enrolled = { contractor: true, customer: true };
    complete.ceremonies[CEREMONY_CO_ACCEPTANCE] = {
      status: 'CO_ACCEPTED',
      approvals: { contractor: { id: 'co-c' }, customer: { id: 'co-u' } },
      completed_at: '2026-07-17T16:31:00.000Z',
    };
    complete.ceremonies[CEREMONY_DRAW_RELEASE] = {
      status: 'DRAW_RELEASE',
      approvals: { contractor: { id: 'draw-c' }, customer: { id: 'draw-u' } },
      completed_at: '2026-08-28T20:18:00.000Z',
    };
    complete.milestone = {
      status: 'evidence_ready',
      evidence_available: true,
      recorded_at: '2026-08-28T19:55:00.000Z',
    };
    complete.release_instruction = {
      status: 'eligible_not_executed',
      eligible: true,
      executed: false,
    };
    complete.evidence_ready = true;

    const amended = buildAmendedDemoState(complete);

    expect(amended.lock.version.number).toBe(2);
    expect(amended.lock.ceremonies[CEREMONY_CO_ACCEPTANCE].digest)
      .not.toBe(complete.lock.ceremonies[CEREMONY_CO_ACCEPTANCE].digest);
    expect(amended.lock.ceremonies[CEREMONY_DRAW_RELEASE].digest)
      .not.toBe(complete.lock.ceremonies[CEREMONY_DRAW_RELEASE].digest);
    expect(amended.ceremonies[CEREMONY_CO_ACCEPTANCE]).toMatchObject({
      status: 'pending',
      approvals: { contractor: null, customer: null },
    });
    expect(amended.ceremonies[CEREMONY_DRAW_RELEASE]).toMatchObject({
      status: 'locked_until_milestone',
      approvals: { contractor: null, customer: null },
    });
    expect(amended.release_instruction).toMatchObject({
      status: 'blocked',
      eligible: false,
    });
    expect(amended.evidence_ready).toBe(false);
    expect(amended.amendment.invalidated_ceremonies).toEqual([
      'CO_ACCEPTED',
      'DRAW_RELEASE',
    ]);
  });
});
