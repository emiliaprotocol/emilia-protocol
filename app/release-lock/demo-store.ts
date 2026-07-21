// SPDX-License-Identifier: Apache-2.0

import {
  buildDemoLock,
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
  DEMO_RELEASE_LOCK,
} from './demo-fixture';

export const DEMO_STATE_KEY = 'emilia_release_lock_demo_v2';
export const DEMO_STATE_EVENT = 'emilia-release-lock-demo-change';

const APPROVAL_TIMES: Record<string, Record<string, string>> = {
  [CEREMONY_CO_ACCEPTANCE]: {
    customer: '2026-07-17T16:28:00.000Z',
    contractor: '2026-07-17T16:31:00.000Z',
  },
  [CEREMONY_DRAW_RELEASE]: {
    customer: '2026-08-28T20:14:00.000Z',
    contractor: '2026-08-28T20:18:00.000Z',
  },
};

function initialCeremonies(): Record<string, any> {
  return {
    [CEREMONY_CO_ACCEPTANCE]: {
      status: 'pending',
      approvals: {
        contractor: null,
        customer: null,
      },
      completed_at: null,
    },
    [CEREMONY_DRAW_RELEASE]: {
      status: 'locked_until_milestone',
      approvals: {
        contractor: null,
        customer: null,
      },
      completed_at: null,
    },
  };
}

export function initialDemoState(): Record<string, any> {
  return {
    lock: DEMO_RELEASE_LOCK,
    created: false,
    enrolled: {
      contractor: false,
      customer: false,
    },
    ceremonies: initialCeremonies(),
    milestone: {
      status: 'not_ready',
      evidence_available: false,
      recorded_at: null,
    },
    release_instruction: {
      status: 'blocked',
      eligible: false,
      executed: false,
    },
    evidence_ready: false,
    amendment: null,
  };
}

function mergeCeremonyState(parsed: any, ceremony: string): any {
  const fallback = initialCeremonies()[ceremony];
  return {
    ...fallback,
    ...parsed?.ceremonies?.[ceremony],
    approvals: {
      ...fallback.approvals,
      ...parsed?.ceremonies?.[ceremony]?.approvals,
    },
  };
}

export function readDemoState(): Record<string, any> {
  if (typeof window === 'undefined') return initialDemoState();
  try {
    const stored = window.localStorage.getItem(DEMO_STATE_KEY);
    if (!stored) return initialDemoState();
    const parsed = JSON.parse(stored);
    return {
      ...initialDemoState(),
      ...parsed,
      enrolled: { ...initialDemoState().enrolled, ...parsed.enrolled },
      ceremonies: {
        [CEREMONY_CO_ACCEPTANCE]: mergeCeremonyState(parsed, CEREMONY_CO_ACCEPTANCE),
        [CEREMONY_DRAW_RELEASE]: mergeCeremonyState(parsed, CEREMONY_DRAW_RELEASE),
      },
      milestone: { ...initialDemoState().milestone, ...parsed.milestone },
      release_instruction: {
        ...initialDemoState().release_instruction,
        ...parsed.release_instruction,
      },
    };
  } catch {
    return initialDemoState();
  }
}

function writeDemoState(next: Record<string, any>): Record<string, any> {
  if (typeof window === 'undefined') return next;
  window.localStorage.setItem(DEMO_STATE_KEY, JSON.stringify(next));
  window.dispatchEvent(new CustomEvent(DEMO_STATE_EVENT, { detail: next }));
  return next;
}

export function resetDemoState(): Record<string, any> {
  return writeDemoState(initialDemoState());
}

export function createDemoReleaseLock(input?: Record<string, unknown>): Record<string, any> {
  return writeDemoState({
    ...initialDemoState(),
    created: true,
    lock: buildDemoLock(input),
  });
}

export function enrollDemoCredential(role: string): Record<string, any> {
  const current = readDemoState();
  return writeDemoState({
    ...current,
    enrolled: {
      ...current.enrolled,
      [role]: true,
    },
  });
}

export function recordDemoApproval(ceremony: string, role: string, bindings: any): Record<string, any> {
  const current = readDemoState();
  const currentCeremony = current.ceremonies[ceremony];
  const approval = {
    ceremony,
    role,
    credential_id: `demo-passkey-${role}-01`,
    approved_at: APPROVAL_TIMES[ceremony][role],
    action_digest: bindings.action_digest,
    prompt_set_digest: bindings.prompt_set_digest || null,
    answer_digest: bindings.answer_digest || null,
    demo_credential: true,
  };
  const approvals = { ...currentCeremony.approvals, [role]: approval };
  const complete = Boolean(approvals.contractor && approvals.customer);
  const ceremonyState = {
    ...currentCeremony,
    status: complete ? current.lock.ceremonies[ceremony].code : 'pending',
    approvals,
    completed_at: complete ? APPROVAL_TIMES[ceremony].contractor : null,
  };
  const ceremonies = {
    ...current.ceremonies,
    [ceremony]: ceremonyState,
  };
  const drawComplete = ceremonies[CEREMONY_DRAW_RELEASE].status === 'DRAW_RELEASE';

  return writeDemoState({
    ...current,
    ceremonies,
    release_instruction: {
      status: drawComplete ? 'eligible_not_executed' : 'blocked',
      eligible: drawComplete,
      executed: false,
    },
    evidence_ready: drawComplete,
  });
}

export function advanceDemoMilestone(): Record<string, any> {
  const current = readDemoState();
  if (current.ceremonies[CEREMONY_CO_ACCEPTANCE].status !== 'CO_ACCEPTED') {
    throw new Error('Both CO_ACCEPTED approvals are required before milestone evidence.');
  }

  return writeDemoState({
    ...current,
    milestone: {
      status: 'evidence_ready',
      evidence_available: true,
      recorded_at: '2026-08-28T19:55:00.000Z',
    },
    ceremonies: {
      ...current.ceremonies,
      [CEREMONY_DRAW_RELEASE]: {
        ...current.ceremonies[CEREMONY_DRAW_RELEASE],
        status: 'pending',
      },
    },
  });
}

export function buildAmendedDemoState(current: Record<string, any>): Record<string, any> {
  const amendedLock = {
    ...current.lock,
    status: 'awaiting_co_acceptance',
    document: {
      reference: 'MSKR-CO-02.pdf · amended v2',
      digest: 'sha256:cec835c491422a4770bb4d5b1c60fa9ea9518778bc0c965f264f20b3afedc970',
    },
    version: {
      ...current.lock.version,
      number: 2,
      label: 'Immutable version 2',
      created_at: '2026-08-28T20:24:00.000Z',
      digest: 'sha256:369e708b15f6983736b5b105a7387881c4797361fe195d64f20b0f6931488e36',
    },
    ceremonies: {
      ...current.lock.ceremonies,
      [CEREMONY_CO_ACCEPTANCE]: {
        ...current.lock.ceremonies[CEREMONY_CO_ACCEPTANCE],
        digest: 'sha256:1099f97d8e1dae49037e004142a3edc6ed7c96f1f9e5de4fd1daf102cd8108a5',
      },
      [CEREMONY_DRAW_RELEASE]: {
        ...current.lock.ceremonies[CEREMONY_DRAW_RELEASE],
        digest: 'sha256:37736d304ac50614a0060d59590f3ce016ed6637b7fb9a245ad3d606a59768e5',
      },
    },
  };

  return {
    ...initialDemoState(),
    created: current.created,
    enrolled: current.enrolled,
    lock: amendedLock,
    amendment: {
      prior_version: current.lock.version.number,
      new_version: 2,
      invalidated_at: '2026-08-28T20:24:00.000Z',
      invalidated_ceremonies: ['CO_ACCEPTED', 'DRAW_RELEASE'],
    },
  };
}

export function amendDemoReleaseLock(): Record<string, any> {
  return writeDemoState(buildAmendedDemoState(readDemoState()));
}

export function subscribeToDemoState(callback: (state: any) => void): () => void {
  if (typeof window === 'undefined') return () => {};

  const onCustomEvent = (event: CustomEvent) => callback(event.detail || readDemoState());
  const onStorage = (event: StorageEvent) => {
    if (event.key === DEMO_STATE_KEY) callback(readDemoState());
  };

  window.addEventListener(DEMO_STATE_EVENT, onCustomEvent as EventListener);
  window.addEventListener('storage', onStorage);
  return () => {
    window.removeEventListener(DEMO_STATE_EVENT, onCustomEvent as EventListener);
    window.removeEventListener('storage', onStorage);
  };
}

export function buildDemoEvidencePackage(): Record<string, any> {
  const state = readDemoState();
  const co = state.ceremonies[CEREMONY_CO_ACCEPTANCE];
  const draw = state.ceremonies[CEREMONY_DRAW_RELEASE];

  return {
    format: state.lock.evidence.format,
    demo: true,
    no_real_money_movement: true,
    lock_id: state.lock.id,
    exact_version: state.lock.version,
    co_acceptance: {
      code: co.status,
      authority: 'change_order_acceptance_only',
      payment_authority: false,
      action_digest: state.lock.ceremonies[CEREMONY_CO_ACCEPTANCE].digest,
      document: state.lock.document,
      scope_summary: state.lock.scope_summary,
      price: state.lock.amount,
      schedule_effect: state.lock.schedule_effect,
      approvals: co.approvals,
    },
    draw_release: {
      code: draw.status,
      action_digest: state.lock.ceremonies[CEREMONY_DRAW_RELEASE].digest,
      draw: state.lock.draw,
      approvals: draw.approvals,
    },
    milestone: state.milestone,
    release_instruction: state.release_instruction,
    amendment: state.amendment,
    refusals: state.lock.refusals,
    package_digest: state.lock.evidence.package_digest,
    boundaries: {
      funds_held_by_emilia: false,
      workmanship_judged_by_emilia: false,
      legal_enforceability_proven: false,
      comprehension_proven: false,
      biometric_identity_proven: false,
      coercion_absence_proven: false,
      device_bound_hardware_claimed: false,
    },
  };
}
