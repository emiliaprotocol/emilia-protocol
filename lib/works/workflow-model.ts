// SPDX-License-Identifier: Apache-2.0
//
// Browser-safe EMILIA Works operating-workflow contract. Database owner UUIDs,
// idempotency digests, and authorization material deliberately never appear in
// these DTOs.

export const WORKS_WORKFLOW_REVISION_INITIAL = 0;

export const WORKS_LISTING_STATES = Object.freeze(['active', 'paused', 'archived'] as const);
export const WORKS_JOB_STATES = Object.freeze(['open', 'closed', 'assigned'] as const);
export const WORKS_PROPOSAL_STATES = Object.freeze(['submitted', 'declined', 'selected'] as const);
export const WORKS_ASSIGNMENT_STATES = Object.freeze([
  'proposed',
  'confirmed',
  'declined',
  'delivery_submitted',
  'changes_requested',
  'completed',
  'cancelled',
] as const);
export const WORKS_VIEWER_ROLES = Object.freeze(['buyer', 'builder', 'both'] as const);

export type WorksListingState = (typeof WORKS_LISTING_STATES)[number];
export type WorksJobState = (typeof WORKS_JOB_STATES)[number];
export type WorksProposalState = (typeof WORKS_PROPOSAL_STATES)[number];
export type WorksAssignmentState = (typeof WORKS_ASSIGNMENT_STATES)[number];
export type WorksViewerRole = (typeof WORKS_VIEWER_ROLES)[number];

export type WorksWorkflowState<T extends string> = {
  state: T;
  revision: number;
  updated_at: string | null;
};

export type WorksAssignmentSnapshot = {
  job: Record<string, unknown>;
  proposal: Record<string, unknown>;
};

export type WorksAssignment = {
  assignment_id: string;
  job_id: string;
  proposal_id: string;
  builder_id: string;
  listing_id: string | null;
  state: WorksAssignmentState;
  revision: number;
  scope: string;
  acceptance_criteria: string[];
  /** A human-readable reference only. Commercial terms are agreed externally. */
  terms: string;
  frozen: WorksAssignmentSnapshot;
  delivery: null | { url: string; summary: string; submitted_at: string };
  outcome: null | { accepted_at: string; summary: string | null };
  history: Array<{
    actor_role: 'buyer' | 'builder';
    command: 'proposal_selected' | WorksAssignmentCommand;
    revision: number;
    at: string;
    summary: string | null;
    reason: string | null;
    delivery: null | { url: string; summary: string; submitted_at: string };
  }>;
  created_at: string;
  updated_at: string;
};

export type WorksNotification = {
  notification_id: string;
  kind: 'proposal_received' | 'proposal_declined' | 'proposal_selected'
    | 'assignment_confirmed' | 'assignment_declined' | 'delivery_submitted'
    | 'changes_requested' | 'completion_accepted' | 'assignment_cancelled';
  resource_type: 'proposal' | 'assignment';
  resource_id: string;
  created_at: string;
  read_at: string | null;
  revision: number;
};

export type WorksWorkspaceDto = {
  viewer: { display_name: string | null; role: WorksViewerRole };
  profiles: Array<Record<string, unknown>>;
  listings: Array<{ record: Record<string, unknown>; workflow: WorksWorkflowState<WorksListingState> }>;
  jobs: Array<{ record: Record<string, unknown>; workflow: WorksWorkflowState<WorksJobState> }>;
  submitted_proposals: Array<{
    record: Record<string, unknown>;
    workflow: WorksWorkflowState<WorksProposalState>;
  }>;
  received_proposals: Array<{
    job: Record<string, unknown>;
    record: Record<string, unknown>;
    workflow: WorksWorkflowState<WorksProposalState>;
  }>;
  assignments: Array<{ viewer_role: Exclude<WorksViewerRole, 'both'>; assignment: WorksAssignment }>;
  notifications: WorksNotification[];
};

export type WorksWorkspaceCommand =
  | 'pause_listing'
  | 'archive_listing'
  | 'reactivate_listing'
  | 'close_job'
  | 'reopen_job'
  | 'decline_proposal';

export type WorksAssignmentCommand =
  | 'builder_confirm'
  | 'builder_decline'
  | 'submit_delivery'
  | 'request_changes'
  | 'accept_completion'
  | 'cancel';

export type WorksCommandBase = {
  expected_revision: number;
  idempotency_key: string;
};

export type WorksWorkspaceCommandInput = WorksCommandBase & {
  command: WorksWorkspaceCommand;
  record_id: string;
};

export type WorksSelectProposalInput = WorksCommandBase & {
  proposal_id: string;
  scope: string;
  acceptance_criteria: string[];
  terms: string;
};

export type WorksAssignmentCommandInput = WorksCommandBase & {
  command: WorksAssignmentCommand;
  delivery_url?: string;
  summary?: string;
  reason?: string;
};

export type WorksNotificationReadInput = WorksCommandBase;

export type WorksWriteResult<T> = {
  ok: true;
  replayed: boolean;
  resource: T;
};

export type WorkflowValidationError = { ok: false; code: string; detail: string };
export type WorkflowValidationResult<T> = { ok: true; value: T } | WorkflowValidationError;

const WORKS_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const MAX_TEXT = 8_000;
const MAX_CRITERIA = 32;

function error(code: string, detail: string): WorkflowValidationError {
  return { ok: false, code, detail };
}

function plain(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

function boundedText(value: unknown, max = MAX_TEXT): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= max ? trimmed : null;
}

function secureHttpsUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 600 || /[\s\\]/.test(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname.length > 0
      && url.username.length === 0 && url.password.length === 0;
  } catch {
    return false;
  }
}

function base(value: Record<string, unknown>): WorkflowValidationError | null {
  if (!Number.isSafeInteger(value.expected_revision) || (value.expected_revision as number) < 0) {
    return error('invalid_expected_revision', 'expected_revision must be a non-negative integer');
  }
  if (typeof value.idempotency_key !== 'string' || !IDEMPOTENCY_KEY.test(value.idempotency_key)) {
    return error('invalid_idempotency_key', 'idempotency_key must be 16-128 safe characters');
  }
  return null;
}

export function validateWorkspaceCommand(value: unknown): WorkflowValidationResult<WorksWorkspaceCommandInput> {
  if (!plain(value) || !exactKeys(value, ['command', 'record_id', 'expected_revision', 'idempotency_key'])) {
    return error('invalid_command', 'workspace command fields are invalid');
  }
  if (!(WORKS_WORKSPACE_COMMANDS as readonly unknown[]).includes(value.command)) {
    return error('invalid_command', 'workspace command is not supported');
  }
  if (typeof value.record_id !== 'string' || !WORKS_ID.test(value.record_id)) {
    return error('invalid_record_id', 'record_id must be a valid Works id');
  }
  const invalidBase = base(value);
  if (invalidBase) return invalidBase;
  return { ok: true, value: value as WorksWorkspaceCommandInput };
}

export function validateSelectProposal(value: unknown): WorkflowValidationResult<WorksSelectProposalInput> {
  if (!plain(value) || !exactKeys(value, [
    'proposal_id', 'expected_revision', 'idempotency_key', 'scope', 'acceptance_criteria', 'terms',
  ])) return error('invalid_selection', 'proposal selection fields are invalid');
  if (typeof value.proposal_id !== 'string' || !WORKS_ID.test(value.proposal_id)) {
    return error('invalid_proposal_id', 'proposal_id must be a valid Works id');
  }
  const invalidBase = base(value);
  if (invalidBase) return invalidBase;
  const scope = boundedText(value.scope);
  const terms = boundedText(value.terms);
  if (!scope) return error('invalid_scope', 'scope is required and must be at most 8000 characters');
  if (!terms) return error('invalid_terms', 'terms is required and must be at most 8000 characters');
  if (!Array.isArray(value.acceptance_criteria)
    || value.acceptance_criteria.length === 0
    || value.acceptance_criteria.length > MAX_CRITERIA) {
    return error('invalid_acceptance_criteria', 'acceptance_criteria must contain 1-32 items');
  }
  const criteria = value.acceptance_criteria.map((item) => boundedText(item, 1_000));
  if (criteria.some((item) => item === null)) {
    return error('invalid_acceptance_criteria', 'each acceptance criterion must be 1-1000 characters');
  }
  return {
    ok: true,
    value: {
      proposal_id: value.proposal_id,
      expected_revision: value.expected_revision as number,
      idempotency_key: value.idempotency_key as string,
      scope,
      acceptance_criteria: criteria as string[],
      terms,
    },
  };
}

export function validateAssignmentCommand(value: unknown): WorkflowValidationResult<WorksAssignmentCommandInput> {
  if (!plain(value) || !exactKeys(
    value,
    ['command', 'expected_revision', 'idempotency_key'],
    ['delivery_url', 'summary', 'reason'],
  )) return error('invalid_command', 'assignment command fields are invalid');
  if (!(WORKS_ASSIGNMENT_COMMANDS as readonly unknown[]).includes(value.command)) {
    return error('invalid_command', 'assignment command is not supported');
  }
  const invalidBase = base(value);
  if (invalidBase) return invalidBase;
  const command = value.command as WorksAssignmentCommand;
  if (command === 'submit_delivery') {
    if (!secureHttpsUrl(value.delivery_url)) {
      return error('invalid_delivery_url', 'delivery_url must be an https URL');
    }
    if (!boundedText(value.summary)) return error('invalid_summary', 'delivery summary is required');
  } else if (Object.hasOwn(value, 'delivery_url')) {
    return error('invalid_command', 'delivery_url is supported only for submit_delivery');
  }
  if (command === 'request_changes' && !boundedText(value.summary)) {
    return error('invalid_summary', 'change-request summary is required');
  }
  if (command === 'cancel' && !boundedText(value.reason, 2_000)) {
    return error('invalid_reason', 'cancellation reason is required');
  }
  if (command !== 'submit_delivery' && command !== 'request_changes'
    && command !== 'accept_completion' && Object.hasOwn(value, 'summary')) {
    return error('invalid_command', 'summary is not supported for this command');
  }
  if (command !== 'cancel' && Object.hasOwn(value, 'reason')) {
    return error('invalid_command', 'reason is supported only for cancel');
  }
  return {
    ok: true,
    value: {
      command,
      expected_revision: value.expected_revision as number,
      idempotency_key: value.idempotency_key as string,
      ...(typeof value.delivery_url === 'string' ? { delivery_url: value.delivery_url } : {}),
      ...(typeof value.summary === 'string' ? { summary: value.summary.trim() } : {}),
      ...(typeof value.reason === 'string' ? { reason: value.reason.trim() } : {}),
    },
  };
}

export function validateNotificationRead(value: unknown): WorkflowValidationResult<WorksNotificationReadInput> {
  if (!plain(value) || !exactKeys(value, ['expected_revision', 'idempotency_key'])) {
    return error('invalid_command', 'notification read fields are invalid');
  }
  const invalidBase = base(value);
  return invalidBase || { ok: true, value: value as WorksNotificationReadInput };
}

export const WORKS_WORKSPACE_COMMANDS = Object.freeze([
  'pause_listing', 'archive_listing', 'reactivate_listing',
  'close_job', 'reopen_job', 'decline_proposal',
] as const satisfies readonly WorksWorkspaceCommand[]);

export const WORKS_ASSIGNMENT_COMMANDS = Object.freeze([
  'builder_confirm', 'builder_decline', 'submit_delivery',
  'request_changes', 'accept_completion', 'cancel',
] as const satisfies readonly WorksAssignmentCommand[]);
