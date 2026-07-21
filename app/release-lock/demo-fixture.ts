// SPDX-License-Identifier: Apache-2.0

export const DEMO_LOCK_ID = 'rl_demo_kitchen_milestone_01';
export const DEMO_CUSTOMER_CAPABILITY = 'demo-customer-maple-47';
export const DEMO_CONTRACTOR_CAPABILITY = 'demo-contractor-northline-21';
export const CEREMONY_CO_ACCEPTANCE = 'co_acceptance';
export const CEREMONY_DRAW_RELEASE = 'draw_release';

const DEFAULT_EXPIRATION = '2026-08-15T23:59:00-07:00';

const CHANGE_ORDER_PRICE = Object.freeze({
  minor_units: 1250000,
  currency: 'USD',
  display: '$12,500.00',
});

const DRAW_AMOUNT = Object.freeze({
  minor_units: 1250000,
  currency: 'USD',
  display: '$12,500.00',
});

const CO_QUESTIONS = [
  {
    id: 'co_price',
    field: 'Change-order price',
    prompt: 'What price change does this exact change order record?',
    correct_value: '$12,500.00 USD',
    options: ['$1,250.00 USD', '$12,500.00 USD', '$25,000.00 USD'],
  },
  {
    id: 'co_document',
    field: 'Document',
    prompt: 'Which exact change-order document is being accepted?',
    correct_value: 'MSKR-CO-02.pdf · final v1',
    options: [
      'MSKR-CO-01.pdf · archived',
      'MSKR-CO-02.pdf · final v1',
      'MSKR-CO-02.pdf · draft v2',
    ],
  },
  {
    id: 'co_schedule',
    field: 'Schedule effect',
    prompt: 'What schedule effect is included in this version?',
    correct_value: 'Adds 3 working days · target completion Aug 28, 2026',
    options: [
      'No schedule change',
      'Adds 3 working days · target completion Aug 28, 2026',
      'Adds 10 calendar days · target completion Sep 4, 2026',
    ],
  },
  {
    id: 'co_scope',
    field: 'Scope',
    prompt: 'Which added item is included in the accepted scope?',
    correct_value: 'Approved pantry pull-out change order',
    options: [
      'Countertop stone fabrication',
      'Primary bathroom vanity',
      'Approved pantry pull-out change order',
    ],
  },
  {
    id: 'co_project',
    field: 'Project',
    prompt: 'Which project does this change order belong to?',
    correct_value: 'Maple Street Kitchen Renovation',
    options: [
      'Maple Street Kitchen Renovation',
      'Maple Street Primary Bathroom',
      'Northline Cabinet Showroom',
    ],
  },
];

const DRAW_QUESTIONS = [
  {
    id: 'draw_amount',
    field: 'Draw amount',
    prompt: 'What exact draw amount is being approved?',
    correct_value: '$12,500.00 USD',
    options: ['$10,800.00 USD', '$12,500.00 USD', '$15,200.00 USD'],
  },
  {
    id: 'draw_id',
    field: 'Draw ID',
    prompt: 'Which draw identifier is bound to this release?',
    correct_value: 'DRAW-04',
    options: ['DRAW-03', 'DRAW-04', 'CO-02'],
  },
  {
    id: 'draw_payees',
    field: 'Payees',
    prompt: 'Which payee allocation is named in this draw?',
    correct_value: 'Northline $10,800.00 · Alder Millwork $1,700.00',
    options: [
      'Northline $12,500.00',
      'Northline $10,800.00 · Alder Millwork $1,700.00',
      'Alder Millwork $12,500.00',
    ],
  },
  {
    id: 'draw_completion',
    field: 'Completion evidence',
    prompt: 'Which completion evidence set is bound to this draw?',
    correct_value: 'MSKR-M4-completion.zip · final',
    options: [
      'MSKR-M3-completion.zip · superseded',
      'MSKR-M4-completion.zip · final',
      'MSKR-M4-completion.zip · draft',
    ],
  },
  {
    id: 'draw_waiver',
    field: 'Lien waiver',
    prompt: 'Which lien-waiver evidence is bound to this draw?',
    correct_value: 'MSKR-DRAW-04-waivers.pdf · conditional',
    options: [
      'MSKR-DRAW-03-waivers.pdf · final',
      'MSKR-DRAW-04-waivers.pdf · conditional',
      'No lien-waiver evidence',
    ],
  },
];

export const DEMO_RELEASE_LOCK = Object.freeze({
  id: DEMO_LOCK_ID,
  status: 'awaiting_co_acceptance',
  project: 'Maple Street Kitchen Renovation',
  title: 'Cabinet installation and change order 02',
  scope_summary:
    'Install lower and upper cabinets, fit the island panels, complete hardware alignment, '
    + 'and include the approved pantry pull-out change order.',
  schedule_effect: 'Adds 3 working days · target completion Aug 28, 2026',
  amount: CHANGE_ORDER_PRICE,
  document: {
    reference: 'MSKR-CO-02.pdf · final v1',
    digest: 'sha256:a2a5f4fc84e26bd935e04698525be9a99b43b54d47eb38d34ff74c92b2aa5f40',
  },
  expiration: DEFAULT_EXPIRATION,
  contacts: {
    contractor: {
      role: 'Contractor',
      display_name: 'Maya Chen',
      verified_handle: 'maya@northline.example',
    },
    customer: {
      role: 'Customer',
      display_name: 'Jordan Lee',
      verified_handle: 'jordan@maplestreet.example',
    },
  },
  version: {
    number: 1,
    label: 'Immutable version 1',
    created_at: '2026-07-17T16:20:00.000Z',
    digest: 'sha256:41a934b3a947283597ed6a4d0c5b4354dcedda0a39adb3b8108b2d808a5a717d',
  },
  ceremonies: {
    [CEREMONY_CO_ACCEPTANCE]: {
      id: CEREMONY_CO_ACCEPTANCE,
      code: 'CO_ACCEPTED',
      round: 1,
      label: 'Change-order acceptance',
      digest: 'sha256:41f0d63d22e07cdef978ef951d375ac16ca55a53df05658f0f2ad233ed8f40aa',
      pairing_phrase: 'CEDAR 47',
      question_pool: CO_QUESTIONS,
    },
    [CEREMONY_DRAW_RELEASE]: {
      id: CEREMONY_DRAW_RELEASE,
      code: 'DRAW_RELEASE',
      round: 2,
      label: 'Draw release',
      digest: 'sha256:875a6af419886feabf9826c292a515cc54a4289c069066e7cec301ee447c33d3',
      pairing_phrase: 'MAPLE 82',
      question_pool: DRAW_QUESTIONS,
    },
  },
  draw: {
    id: 'DRAW-04',
    amount: DRAW_AMOUNT,
    payees: [
      {
        name: 'Northline Kitchen & Bath LLC',
        amount: '$10,800.00',
      },
      {
        name: 'Alder Millwork Supply Co.',
        amount: '$1,700.00',
      },
    ],
    completion_evidence: {
      reference: 'MSKR-M4-completion.zip · final',
      digest: 'sha256:3c060c6f8bbf3adba582e2aab251362ecda51fbc8268cfa74590186f95d35dbc',
    },
    lien_waiver_evidence: {
      reference: 'MSKR-DRAW-04-waivers.pdf · conditional',
      digest: 'sha256:978694ba42c6a4bfc3c0dd9789a4846d851c22cac743e32476db8a822111398e',
    },
    custodian: 'Owner-selected project custodian',
    instruction:
      'Mark DRAW-04 for $12,500.00 USD eligible for the named payee allocation only after '
      + 'both DRAW_RELEASE approvals bind to this exact draw and evidence set.',
  },
  refusals: [
    {
      id: 'mutation',
      title: 'Mutation refused',
      detail: 'DRAW-04 amount changed from $12,500.00 to $15,200.00',
      reason: 'draw_release_digest_mismatch',
    },
    {
      id: 'replay',
      title: 'Replay refused',
      detail: 'Consumed DRAW_RELEASE approval presented a second time',
      reason: 'resolution_nonce_consumed',
    },
    {
      id: 'substitution',
      title: 'Role substitution refused',
      detail: 'Customer credential presented for the contractor seat',
      reason: 'credential_role_mismatch',
    },
    {
      id: 'amendment',
      title: 'Amendment invalidates both',
      detail: 'A new immutable version clears CO_ACCEPTED and DRAW_RELEASE',
      reason: 'superseded_version',
    },
  ],
  evidence: {
    package_digest: 'sha256:e540e114eead1fecffb9cde4699b73425239a60bb28a3581df7db53345f02665',
    format: 'EMILIA-RELEASE-LOCK-EVIDENCE-v1',
  },
});

function normalizeText(value: unknown, fallback: string): string {
  const normalized = String(value ?? '').trim();
  return normalized || fallback;
}

interface AmountValue {
  minor_units: number;
  currency: string;
  display: string;
}

function amountValue(amount: unknown, currency: string, fallback: AmountValue): AmountValue {
  const numeric = Number(amount);
  if (!Number.isFinite(numeric)) return fallback;
  return {
    minor_units: Math.round(numeric * 100),
    currency,
    display: new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
    }).format(numeric),
  };
}

export function buildDemoLock(input?: Record<string, unknown>): any {
  const inputData = input || {};
  const currency = normalizeText(inputData.currency, DEMO_RELEASE_LOCK.amount.currency).toUpperCase();
  const coAmount = amountValue(inputData.amount, currency, DEMO_RELEASE_LOCK.amount);
  const drawAmount = amountValue(inputData.draw_amount, currency, DEMO_RELEASE_LOCK.draw.amount);

  return {
    ...DEMO_RELEASE_LOCK,
    project: normalizeText(inputData.project, DEMO_RELEASE_LOCK.project),
    title: normalizeText(inputData.title, DEMO_RELEASE_LOCK.title),
    scope_summary: normalizeText(inputData.scope_summary, DEMO_RELEASE_LOCK.scope_summary),
    schedule_effect: normalizeText(inputData.schedule_effect, DEMO_RELEASE_LOCK.schedule_effect),
    amount: coAmount,
    document: {
      reference: normalizeText(inputData.document_reference, DEMO_RELEASE_LOCK.document.reference),
      digest: normalizeText(inputData.document_digest, DEMO_RELEASE_LOCK.document.digest),
    },
    expiration: normalizeText(inputData.expiration, DEMO_RELEASE_LOCK.expiration),
    draw: {
      ...DEMO_RELEASE_LOCK.draw,
      id: normalizeText(inputData.draw_id, DEMO_RELEASE_LOCK.draw.id),
      amount: drawAmount,
      payees: [
        {
          name: normalizeText(inputData.payee_one, DEMO_RELEASE_LOCK.draw.payees[0].name),
          amount: normalizeText(inputData.payee_one_amount, DEMO_RELEASE_LOCK.draw.payees[0].amount),
        },
        {
          name: normalizeText(inputData.payee_two, DEMO_RELEASE_LOCK.draw.payees[1].name),
          amount: normalizeText(inputData.payee_two_amount, DEMO_RELEASE_LOCK.draw.payees[1].amount),
        },
      ],
      completion_evidence: {
        reference: normalizeText(
          inputData.completion_evidence_reference,
          DEMO_RELEASE_LOCK.draw.completion_evidence.reference,
        ),
        digest: normalizeText(
          inputData.completion_evidence_digest,
          DEMO_RELEASE_LOCK.draw.completion_evidence.digest,
        ),
      },
      lien_waiver_evidence: {
        reference: normalizeText(
          inputData.lien_waiver_reference,
          DEMO_RELEASE_LOCK.draw.lien_waiver_evidence.reference,
        ),
        digest: normalizeText(
          inputData.lien_waiver_digest,
          DEMO_RELEASE_LOCK.draw.lien_waiver_evidence.digest,
        ),
      },
      custodian: normalizeText(inputData.custodian, DEMO_RELEASE_LOCK.draw.custodian),
      instruction: normalizeText(
        inputData.recipient_instruction,
        DEMO_RELEASE_LOCK.draw.instruction,
      ),
    },
    contacts: {
      contractor: {
        ...DEMO_RELEASE_LOCK.contacts.contractor,
        verified_handle: normalizeText(
          inputData.contractor_handle,
          DEMO_RELEASE_LOCK.contacts.contractor.verified_handle,
        ),
      },
      customer: {
        ...DEMO_RELEASE_LOCK.contacts.customer,
        verified_handle: normalizeText(
          inputData.customer_handle,
          DEMO_RELEASE_LOCK.contacts.customer.verified_handle,
        ),
      },
    },
  };
}

function seededRank(seed: string, value: string): number {
  let hash = 2166136261;
  const text = `${seed}:${value}`;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

export function selectMaterialQuestions(
  lock?: any,
  ceremony?: string,
  count?: number,
): any[] {
  const lockData = lock || DEMO_RELEASE_LOCK;
  const ceremonyKey = ceremony || CEREMONY_CO_ACCEPTANCE;
  const limit = count || 3;
  const definition = lockData.ceremonies[ceremonyKey];
  return [...definition.question_pool]
    .sort((left: any, right: any) => (
      seededRank(definition.digest, left.id) - seededRank(definition.digest, right.id)
    ))
    .slice(0, limit);
}

export function releaseLockFormDefaults(): Record<string, unknown> {
  return {
    project: DEMO_RELEASE_LOCK.project,
    title: DEMO_RELEASE_LOCK.title,
    scope_summary: DEMO_RELEASE_LOCK.scope_summary,
    schedule_effect: DEMO_RELEASE_LOCK.schedule_effect,
    amount: '12500.00',
    currency: DEMO_RELEASE_LOCK.amount.currency,
    document_reference: DEMO_RELEASE_LOCK.document.reference,
    document_digest: DEMO_RELEASE_LOCK.document.digest,
    expiration: '2026-08-15T23:59',
    draw_id: DEMO_RELEASE_LOCK.draw.id,
    draw_amount: '12500.00',
    payee_one: DEMO_RELEASE_LOCK.draw.payees[0].name,
    payee_one_amount: DEMO_RELEASE_LOCK.draw.payees[0].amount,
    payee_two: DEMO_RELEASE_LOCK.draw.payees[1].name,
    payee_two_amount: DEMO_RELEASE_LOCK.draw.payees[1].amount,
    completion_evidence_reference: DEMO_RELEASE_LOCK.draw.completion_evidence.reference,
    completion_evidence_digest: DEMO_RELEASE_LOCK.draw.completion_evidence.digest,
    lien_waiver_reference: DEMO_RELEASE_LOCK.draw.lien_waiver_evidence.reference,
    lien_waiver_digest: DEMO_RELEASE_LOCK.draw.lien_waiver_evidence.digest,
    custodian: DEMO_RELEASE_LOCK.draw.custodian,
    recipient_instruction: DEMO_RELEASE_LOCK.draw.instruction,
    contractor_handle: DEMO_RELEASE_LOCK.contacts.contractor.verified_handle,
    customer_handle: DEMO_RELEASE_LOCK.contacts.customer.verified_handle,
  };
}
