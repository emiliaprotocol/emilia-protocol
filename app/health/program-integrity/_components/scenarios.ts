// SPDX-License-Identifier: Apache-2.0

interface Stage {
  id: string;
  label: string;
  description: string;
}

export const STAGES: Stage[] = [
  {
    id: 'bind',
    label: 'Bind exact action',
    description: 'Canonicalize every material field into one CAID.',
  },
  {
    id: 'verify',
    label: 'Verify policy',
    description: 'Check authority, signoff, authorization, and destination.',
  },
  {
    id: 'reserve',
    label: 'Bound capability',
    description: 'Issue at most one tightly scoped execution right.',
  },
  {
    id: 'submit',
    label: 'Submit once',
    description: 'Call the existing executor with the bound action.',
  },
  {
    id: 'reconcile',
    label: 'Resolve outcome',
    description: 'Authenticate provider evidence before any next action.',
  },
  {
    id: 'seal',
    label: 'Seal evidence',
    description: 'Preserve a portable packet for outside review.',
  },
];

const ACTION_CAID =
  'caid:1:health.medi-cal.hospice-claim-payment.1:jcs-sha256:_gaImSfYxk3C1BAqP2t3_bYhoHLb1FbGdvh8uk9jM28';
const DESTINATION_MISMATCH_CAID =
  'caid:1:health.medi-cal.hospice-claim-payment.1:jcs-sha256:wXcsyN3_SxaS5xeYe5Owb10NCbcQDdB_2BqW9Ges0lQ';
const MEMBER_REF = `member:sha256:${'1'.repeat(64)}`;
const AUTHORIZATION_FORM_DIGEST = `sha256:${'2'.repeat(64)}`;
const AUTHORITY_PROOF_DIGEST = `sha256:${'4'.repeat(64)}`;
const PAYMENT_DESTINATION_DIGEST = `sha256:${'6'.repeat(64)}`;
const CHANGED_PAYMENT_DESTINATION_DIGEST = `sha256:${'8'.repeat(64)}`;
const POLICY_HASH = `sha256:${'7'.repeat(64)}`;

interface ScenarioField {
  id: string;
  label: string;
  value: string | number;
  displayValue?: string;
  authorizedValue?: string;
  authorizedDisplayValue?: string;
  state: 'match' | 'mismatch';
}

interface Check {
  id: string;
  label: string;
  evidence: string;
  status: 'pass' | 'fail';
}

interface Capability {
  state: string;
  scope: string;
  budget: string;
  uses: string;
  expiry: string;
  token: string;
}

interface Execution {
  initial: string;
  replay: string;
  reconciliation: string;
  final: string;
}

interface Packet {
  version: string;
  policy: string;
  challenge: string;
  verifier: string;
  fixture: boolean;
  phi: boolean;
  decision: string;
  action_caid: string;
  receipt_digest: string | null;
  capability: string;
  executor_outcome: string;
  evidence_head: string;
}

interface Scenario {
  id: string;
  shortLabel: string;
  label: string;
  summary: string;
  initialVerdict: string;
  finalState: string;
  tone: 'authorized' | 'refused' | 'indeterminate';
  caid: string;
  receiptCaid: string | null;
  fields: ScenarioField[];
  checks: Check[];
  capability: Capability;
  execution: Execution;
  stageNotes: string[];
  packet: Packet;
}

const BASE_FIELDS: ScenarioField[] = [
  {
    id: '@version',
    label: 'Action schema',
    value: 'EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v1',
    state: 'match',
  },
  {
    id: 'profile_id',
    label: 'Reliance profile',
    value: 'medi-cal.hospice-integrity.v1',
    state: 'match',
  },
  {
    id: 'action_type',
    label: 'Action type',
    value: 'health.medi-cal.hospice-claim-payment.1',
    state: 'match',
  },
  {
    id: 'organization_id',
    label: 'Organization (synthetic)',
    value: 'org:ca-dhcs',
    state: 'match',
  },
  {
    id: 'provider_npi',
    label: 'Provider NPI (synthetic)',
    value: '1234567890',
    state: 'match',
  },
  {
    id: 'member_ref',
    label: 'Member reference (pseudonymous)',
    value: MEMBER_REF,
    displayValue: 'member:sha256:1111…1111',
    state: 'match',
  },
  {
    id: 'service_period_start',
    label: 'Service period start',
    value: '2026-07-01',
    state: 'match',
  },
  {
    id: 'service_period_end',
    label: 'Service period end',
    value: '2026-07-15',
    state: 'match',
  },
  {
    id: 'amount',
    label: 'Claim amount',
    value: '1250.00',
    state: 'match',
  },
  {
    id: 'currency',
    label: 'Currency',
    value: 'USD',
    state: 'match',
  },
  {
    id: 'authorization_form_digest',
    label: 'Authorization form digest',
    value: AUTHORIZATION_FORM_DIGEST,
    displayValue: 'sha256:2222…2222',
    state: 'match',
  },
  {
    id: 'payment_destination_digest',
    label: 'Payment destination commitment',
    value: PAYMENT_DESTINATION_DIGEST,
    displayValue: 'sha256:6666…6666',
    state: 'match',
  },
  {
    id: 'reviewer_id',
    label: 'Named reviewer',
    value: 'reviewer:integrity-17',
    state: 'match',
  },
  {
    id: 'authority_proof_digest',
    label: 'Reviewer authority proof',
    value: AUTHORITY_PROOF_DIGEST,
    displayValue: 'sha256:4444…4444',
    state: 'match',
  },
  {
    id: 'policy_id',
    label: 'Pinned policy',
    value: 'policy:dhcs-hospice-payment',
    state: 'match',
  },
  {
    id: 'policy_version',
    label: 'Policy version',
    value: 1,
    state: 'match',
  },
  {
    id: 'policy_hash',
    label: 'Policy body digest',
    value: POLICY_HASH,
    displayValue: 'sha256:7777…7777',
    state: 'match',
  },
];

const PASSING_CHECKS: Check[] = [
  {
    id: 'standing',
    label: 'Provider standing',
    evidence: 'Signed enrollment snapshot · active',
    status: 'pass',
  },
  {
    id: 'authorization',
    label: 'Verified authorization',
    evidence: 'Form digest present and verifier accepted',
    status: 'pass',
  },
  {
    id: 'binding',
    label: 'Action / authorization binding',
    evidence: 'Receipt CAID equals proposed-action CAID',
    status: 'pass',
  },
  {
    id: 'destination',
    label: 'Payment destination binding',
    evidence: 'Authorized destination equals executor destination',
    status: 'pass',
  },
  {
    id: 'reviewer',
    label: 'Named human signoff',
    evidence: 'Program integrity reviewer · device-bound',
    status: 'pass',
  },
  {
    id: 'window',
    label: 'Service and approval window',
    evidence: 'Within policy-valid time bounds',
    status: 'pass',
  },
];

const PACKET_BASE: Omit<Packet, 'decision' | 'action_caid' | 'receipt_digest' | 'capability' | 'executor_outcome' | 'evidence_head'> = {
  version: 'emilia.program-integrity.packet.v1',
  policy: 'policy:dhcs-hospice-payment@1',
  challenge: 'chlg_syn_20260723_1430_00421',
  verifier: 'offline-compatible',
  fixture: true,
  phi: false,
};

export const SCENARIOS: Scenario[] = [
  {
    id: 'valid',
    shortLabel: 'Valid authorization',
    label: 'Exact authorization',
    summary: 'Every material field matches. One bounded release is authorized.',
    initialVerdict: 'AUTHORIZED',
    finalState: 'EXECUTED ONCE',
    tone: 'authorized',
    caid: ACTION_CAID,
    receiptCaid: ACTION_CAID,
    fields: BASE_FIELDS,
    checks: PASSING_CHECKS,
    capability: {
      state: 'CONSUMED',
      scope: 'One claim release · exact CAID',
      budget: 'USD 1,250.00 maximum',
      uses: '1 of 1 consumed',
      expiry: '2026-07-23 14:36 UTC',
      token: 'cap_syn_71B9…C201',
    },
    execution: {
      initial: 'Provider accepted the exact bound action.',
      replay: 'REFUSED · capability already consumed',
      reconciliation: 'Authenticated executor receipt: EXECUTED',
      final: 'The same capability cannot release a second payment.',
    },
    stageNotes: [
      'Seventeen exact-action fields canonicalized.',
      '6 of 6 policy checks passed.',
      'One-use, amount-bounded capability issued.',
      'Executor accepted the bound request.',
      'Authenticated outcome: EXECUTED.',
      'Authorization and outcome evidence sealed.',
    ],
    packet: {
      ...PACKET_BASE,
      decision: 'authorized',
      action_caid: ACTION_CAID,
      receipt_digest: `sha256:${'9'.repeat(64)}`,
      capability: 'cap_syn_71B9…C201',
      executor_outcome: 'executed',
      evidence_head: `sha256:${'a'.repeat(64)}`,
    },
  },
  {
    id: 'missing-authorization',
    shortLabel: 'Missing authorization',
    label: 'Authorization evidence absent',
    summary: 'The exact action is well formed, but required authorization evidence is absent. Execution is refused before provider entry.',
    initialVerdict: 'DO NOT EXECUTE',
    finalState: 'REFUSED',
    tone: 'refused',
    caid: ACTION_CAID,
    receiptCaid: null,
    fields: BASE_FIELDS,
    checks: PASSING_CHECKS.map((check) =>
      check.id === 'authorization'
        ? {
            ...check,
            evidence: 'Required authorization evidence is absent',
            status: 'fail' as const,
          }
        : check,
    ),
    capability: {
      state: 'NOT ISSUED',
      scope: 'Refused before execution authority',
      budget: 'USD 0.00 available',
      uses: '0 of 0',
      expiry: 'Not applicable',
      token: 'not-issued',
    },
    execution: {
      initial: 'Executor was never called.',
      replay: 'REFUSED · no authorization or capability exists',
      reconciliation: 'Not required · no provider submission occurred',
      final: 'Fresh, exact authorization is required before any protected effect.',
    },
    stageNotes: [
      'Seventeen exact-action fields canonicalized.',
      'Required authorization evidence missing.',
      'No execution capability issued.',
      'Executor call suppressed.',
      'No external outcome to reconcile.',
      'Refusal evidence sealed for review.',
    ],
    packet: {
      ...PACKET_BASE,
      decision: 'do_not_execute',
      action_caid: ACTION_CAID,
      receipt_digest: null,
      capability: 'not-issued',
      executor_outcome: 'not_called',
      evidence_head: `sha256:${'f'.repeat(64)}`,
    },
  },
  {
    id: 'mismatch',
    shortLabel: 'Changed destination',
    label: 'Authorization mismatch',
    summary: 'The proposed destination differs from the approved action. Execution is refused.',
    initialVerdict: 'DO NOT EXECUTE',
    finalState: 'REFUSED',
    tone: 'refused',
    caid: DESTINATION_MISMATCH_CAID,
    receiptCaid: ACTION_CAID,
    fields: BASE_FIELDS.map((field) =>
      field.id === 'payment_destination_digest'
        ? {
            ...field,
            value: CHANGED_PAYMENT_DESTINATION_DIGEST,
            displayValue: 'sha256:8888…8888',
            authorizedValue: PAYMENT_DESTINATION_DIGEST,
            authorizedDisplayValue: 'Authorized commitment: sha256:6666…6666',
            state: 'mismatch' as const,
          }
        : field,
    ),
    checks: PASSING_CHECKS.map((check) => {
      if (check.id === 'binding') {
        return {
          ...check,
          evidence: 'Receipt CAID does not equal proposed-action CAID',
          status: 'fail' as const,
        };
      }
      if (check.id === 'destination') {
        return {
          ...check,
          evidence: 'Executor destination differs from authorized destination',
          status: 'fail' as const,
        };
      }
      return check;
    }),
    capability: {
      state: 'NOT ISSUED',
      scope: 'Refused before execution authority',
      budget: 'USD 0.00 available',
      uses: '0 of 0',
      expiry: 'Not applicable',
      token: 'not-issued',
    },
    execution: {
      initial: 'Executor was never called.',
      replay: 'REFUSED · no valid capability exists',
      reconciliation: 'Not required · no external submission occurred',
      final: 'A destination change requires a new exact authorization.',
    },
    stageNotes: [
      'Changed destination produced a different CAID.',
      '2 binding checks failed closed.',
      'No execution capability issued.',
      'Executor call suppressed.',
      'No external outcome to reconcile.',
      'Refusal evidence sealed for review.',
    ],
    packet: {
      ...PACKET_BASE,
      decision: 'do_not_execute',
      action_caid: DESTINATION_MISMATCH_CAID,
      receipt_digest: `sha256:${'b'.repeat(64)}`,
      capability: 'not-issued',
      executor_outcome: 'not_called',
      evidence_head: `sha256:${'c'.repeat(64)}`,
    },
  },
  {
    id: 'timeout',
    shortLabel: 'Provider timeout',
    label: 'Unknown provider outcome',
    summary: 'The provider does not answer. EMILIA refuses a blind retry and reconciles evidence.',
    initialVerdict: 'INDETERMINATE',
    finalState: 'RECONCILED · NOT EXECUTED',
    tone: 'indeterminate',
    caid: ACTION_CAID,
    receiptCaid: ACTION_CAID,
    fields: BASE_FIELDS,
    checks: PASSING_CHECKS,
    capability: {
      state: 'CLOSED AFTER RECONCILIATION',
      scope: 'One claim release · exact CAID',
      budget: 'USD 1,250.00 maximum',
      uses: '0 confirmed executions',
      expiry: '2026-07-23 14:36 UTC',
      token: 'cap_syn_9AC4…881E',
    },
    execution: {
      initial: 'Submission timed out; effect is initially unknown.',
      replay: 'REFUSED · blind replay could duplicate payment',
      reconciliation: 'Authenticated executor evidence: NOT EXECUTED',
      final: 'Capability closed. Any retry requires a fresh policy decision.',
    },
    stageNotes: [
      'Seventeen exact-action fields canonicalized.',
      '6 of 6 policy checks passed.',
      'One-use, amount-bounded capability reserved.',
      'Timeout recorded as INDETERMINATE.',
      'Authenticated query proved NOT EXECUTED.',
      'Indeterminate and reconciliation evidence sealed.',
    ],
    packet: {
      ...PACKET_BASE,
      decision: 'authorized',
      action_caid: ACTION_CAID,
      receipt_digest: `sha256:${'d'.repeat(64)}`,
      capability: 'cap_syn_9AC4…881E',
      executor_outcome: 'indeterminate_then_reconciled_not_executed',
      evidence_head: `sha256:${'e'.repeat(64)}`,
    },
  },
];
