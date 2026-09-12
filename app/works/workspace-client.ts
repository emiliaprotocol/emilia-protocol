// SPDX-License-Identifier: Apache-2.0
import {
  validWorksId, validateBuilder, validateListing, validateOpportunity, validateSubmission,
  type BuilderRecord, type ListingRecord, type OpportunityRecord, type SubmissionRecord,
} from '@/lib/works/model';
import {
  WORKS_ASSIGNMENT_STATES, WORKS_ASSIGNMENT_COMMANDS, WORKS_JOB_STATES, WORKS_LISTING_STATES, WORKS_PROPOSAL_STATES, WORKS_VIEWER_ROLES,
  validateWorkspaceCommand, validateSelectProposal, validateAssignmentCommand, validateNotificationRead,
  type WorksAssignment, type WorksNotification, type WorksWorkflowState, type WorksListingState,
  type WorksJobState, type WorksProposalState, type WorksViewerRole,
  type WorksWorkspaceCommandInput, type WorksSelectProposalInput, type WorksAssignmentCommandInput, type WorksNotificationReadInput,
} from '@/lib/works/workflow-model';

export type ListingView = { record: ListingRecord; workflow: WorksWorkflowState<WorksListingState> };
export type JobView = { record: OpportunityRecord; workflow: WorksWorkflowState<WorksJobState> };
export type ProposalView = { record: SubmissionRecord; workflow: WorksWorkflowState<WorksProposalState> };
export type ReceivedProposal = ProposalView & { job: OpportunityRecord };
export type AssignmentView = { viewer_role: 'buyer' | 'builder'; assignment: WorksAssignment };
export type WorkspaceData = {
  viewer: { display_name: string | null; role: WorksViewerRole };
  profiles: BuilderRecord[]; listings: ListingView[]; jobs: JobView[];
  submitted_proposals: ProposalView[]; received_proposals: ReceivedProposal[];
  assignments: AssignmentView[]; notifications: WorksNotification[];
};

function invalid(): never { throw new Error('workspace_response_invalid'); }
const notificationId = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function text(value: unknown, max = 8000): value is string { return typeof value === 'string' && value.trim().length > 0 && value.length <= max; }
function date(value: unknown): value is string { return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)); }
function array(value: unknown): unknown[] { if (!Array.isArray(value) || value.length > 1000) invalid(); return value; }
function state<T extends string>(value: unknown, values: readonly T[]): WorksWorkflowState<T> {
  if (!object(value) || !values.includes(value.state as T) || !Number.isSafeInteger(value.revision)
    || (value.revision as number) < 0 || (value.updated_at !== null && !date(value.updated_at))) invalid();
  return { state: value.state as T, revision: value.revision as number, updated_at: value.updated_at as string | null };
}
function record<T>(value: unknown, validator: (raw: unknown) => { ok: true; record: T } | { ok: false }): T {
  const checked = validator(value);
  if (!checked.ok || (object(value) && value.example === true)) invalid();
  return checked.record;
}
function secureUrl(value: unknown): value is string {
  if (!text(value, 600)) return false;
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password; } catch { return false; }
}
function deliveryView(value: unknown): WorksAssignment['delivery'] {
  if (value === null) return null;
  if (!object(value) || !secureUrl(value.url) || !text(value.summary) || !date(value.submitted_at)) invalid();
  return { url: value.url, summary: value.summary, submitted_at: value.submitted_at };
}

export function projectAssignment(value: unknown): WorksAssignment {
  if (!object(value) || !validWorksId(value.assignment_id) || !validWorksId(value.job_id) || !validWorksId(value.proposal_id)
    || !validWorksId(value.builder_id) || (value.listing_id !== null && !validWorksId(value.listing_id))
    || !WORKS_ASSIGNMENT_STATES.includes(value.state as never) || !Number.isSafeInteger(value.revision) || (value.revision as number) < 0
    || !text(value.scope) || !text(value.terms) || !object(value.frozen) || !date(value.created_at) || !date(value.updated_at)) invalid();
  const criteria = array(value.acceptance_criteria);
  if (criteria.length < 1 || criteria.length > 32 || criteria.some(item => !text(item, 1000))) invalid();
  const job = record(value.frozen.job, validateOpportunity);
  const proposal = record(value.frozen.proposal, validateSubmission);
  if (job.opportunity_id !== value.job_id || proposal.submission_id !== value.proposal_id || proposal.opportunity_id !== value.job_id
    || proposal.builder_id !== value.builder_id || (proposal.listing_id ?? null) !== value.listing_id) invalid();
  const delivery = deliveryView(value.delivery);
  let outcome: WorksAssignment['outcome'] = null;
  if (value.outcome !== null) {
    if (!object(value.outcome) || !date(value.outcome.accepted_at) || (value.outcome.summary !== null && !text(value.outcome.summary))) invalid();
    outcome = { accepted_at: value.outcome.accepted_at, summary: value.outcome.summary as string | null };
  }
  if ((value.state === 'delivery_submitted' || value.state === 'completed') && !delivery) invalid();
  if (value.state === 'completed' && !outcome) invalid();
  let previousRevision = -1;
  const history: WorksAssignment['history'] = array(value.history).map(item => {
    if (!object(item) || (item.actor_role !== 'buyer' && item.actor_role !== 'builder')
      || (item.command !== 'proposal_selected' && !WORKS_ASSIGNMENT_COMMANDS.includes(item.command as never))
      || !Number.isSafeInteger(item.revision) || (item.revision as number) <= previousRevision || (item.revision as number) > (value.revision as number)
      || !date(item.at) || (item.summary !== null && !text(item.summary)) || (item.reason !== null && !text(item.reason, 2000))) invalid();
    previousRevision = item.revision as number;
    return { actor_role: item.actor_role, command: item.command as WorksAssignment['history'][number]['command'], revision: item.revision as number,
      at: item.at, summary: item.summary as string | null, reason: item.reason as string | null, delivery: deliveryView(item.delivery) };
  });
  if (!history.length || previousRevision !== value.revision) invalid();
  return {
    assignment_id: value.assignment_id, job_id: value.job_id, proposal_id: value.proposal_id, builder_id: value.builder_id,
    listing_id: value.listing_id as string | null, state: value.state as WorksAssignment['state'], revision: value.revision as number,
    scope: value.scope, terms: value.terms, acceptance_criteria: criteria as string[], frozen: { job: { ...job }, proposal: { ...proposal } },
    delivery, outcome, history, created_at: value.created_at, updated_at: value.updated_at,
  };
}
export function projectAssignmentView(value: unknown, id?: string): AssignmentView {
  if (!object(value) || (value.viewer_role !== 'buyer' && value.viewer_role !== 'builder')) invalid();
  const assignment = projectAssignment(value.assignment);
  if (id && assignment.assignment_id !== id) invalid();
  return { viewer_role: value.viewer_role, assignment };
}

const notificationKinds = ['proposal_received', 'proposal_declined', 'proposal_selected', 'assignment_confirmed', 'assignment_declined', 'delivery_submitted', 'changes_requested', 'completion_accepted', 'assignment_cancelled'];
export function projectWorkspace(value: unknown): WorkspaceData {
  if (!object(value) || !object(value.viewer) || !WORKS_VIEWER_ROLES.includes(value.viewer.role as never)
    || (value.viewer.display_name !== null && !text(value.viewer.display_name, 200))) invalid();
  const proposals = (rows: unknown): ProposalView[] => array(rows).map(item => {
    if (!object(item)) invalid();
    return { record: record(item.record, validateSubmission), workflow: state(item.workflow, WORKS_PROPOSAL_STATES) };
  });
  return {
    viewer: { display_name: value.viewer.display_name as string | null, role: value.viewer.role as WorksViewerRole },
    profiles: array(value.profiles).map(item => record(item, validateBuilder)),
    listings: array(value.listings).map(item => {
      if (!object(item)) invalid();
      return { record: record(item.record, validateListing), workflow: state(item.workflow, WORKS_LISTING_STATES) };
    }),
    jobs: array(value.jobs).map(item => {
      if (!object(item)) invalid();
      return { record: record(item.record, validateOpportunity), workflow: state(item.workflow, WORKS_JOB_STATES) };
    }),
    submitted_proposals: proposals(value.submitted_proposals),
    received_proposals: array(value.received_proposals).map(item => {
      if (!object(item)) invalid();
      const proposal = record(item.record, validateSubmission); const job = record(item.job, validateOpportunity);
      if (proposal.opportunity_id !== job.opportunity_id) invalid();
      return { record: proposal, job, workflow: state(item.workflow, WORKS_PROPOSAL_STATES) };
    }),
    assignments: array(value.assignments).map(item => projectAssignmentView(item)),
    notifications: array(value.notifications).map(item => {
      if (!object(item) || !text(item.notification_id, 128) || !notificationId.test(item.notification_id) || !notificationKinds.includes(item.kind as string)
        || (item.resource_type !== 'proposal' && item.resource_type !== 'assignment') || !validWorksId(item.resource_id)
        || !Number.isSafeInteger(item.revision) || (item.revision as number) < 0
        || !date(item.created_at) || (item.read_at !== null && !date(item.read_at))) invalid();
      return { notification_id: item.notification_id, kind: item.kind as WorksNotification['kind'], resource_type: item.resource_type,
        resource_id: item.resource_id, created_at: item.created_at, read_at: item.read_at as string | null, revision: item.revision as number };
    }),
  };
}

const privateOptions = { cache: 'no-store', credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer' } as const;
function responseError(response: Response): Error {
  return new Error(response.status === 401 || response.status === 403 ? 'workspace_signin_required'
    : response.status === 409 ? 'workspace_conflict'
      : response.status === 429 ? 'workspace_rate_limited' : 'workspace_unavailable');
}
async function readPrivate(url: string, signal: AbortSignal): Promise<unknown> {
  signal.throwIfAborted();
  const response = await fetch(url, { method: 'GET', ...privateOptions, signal });
  signal.throwIfAborted();
  if (!response.ok) throw responseError(response);
  const body: unknown = await response.json(); signal.throwIfAborted(); return body;
}
export async function loadWorkspace(signal: AbortSignal): Promise<WorkspaceData> { return projectWorkspace(await readPrivate('/api/works/workspace', signal)); }
export async function loadAssignment(id: string, signal: AbortSignal): Promise<AssignmentView> {
  if (!validWorksId(id)) throw new Error('workspace_input_invalid');
  return projectAssignmentView(await readPrivate(`/api/works/assignments/${id}`, signal), id);
}

export type WorkflowIntent = Readonly<{
  kind: 'workspace' | 'select' | 'assignment'; id: string;
  body: WorksWorkspaceCommandInput | WorksSelectProposalInput | WorksAssignmentCommandInput;
}>;
export function prepareWorkflowIntent(kind: WorkflowIntent['kind'], id: string, input: unknown): WorkflowIntent {
  if (!validWorksId(id)) throw new Error('workspace_input_invalid');
  const checked = kind === 'workspace' ? validateWorkspaceCommand(input) : kind === 'select' ? validateSelectProposal(input) : validateAssignmentCommand(input);
  if (!checked.ok) throw new Error('workspace_input_invalid');
  if ('delivery_url' in checked.value && !secureUrl(checked.value.delivery_url)) throw new Error('workspace_input_invalid');
  if (kind === 'workspace' && (checked.value as WorksWorkspaceCommandInput).record_id !== id) throw new Error('workspace_input_invalid');
  if (kind === 'select' && (checked.value as WorksSelectProposalInput).proposal_id !== id) throw new Error('workspace_input_invalid');
  const body = JSON.parse(JSON.stringify(checked.value)) as WorkflowIntent['body'];
  if ('acceptance_criteria' in body) Object.freeze(body.acceptance_criteria);
  return Object.freeze({ kind, id, body: Object.freeze(body) });
}

const commandTargets = {
  pause_listing: { collection: 'listings', state: 'paused' }, archive_listing: { collection: 'listings', state: 'archived' },
  reactivate_listing: { collection: 'listings', state: 'active' }, close_job: { collection: 'opportunities', state: 'closed' },
  reopen_job: { collection: 'opportunities', state: 'open' }, decline_proposal: { collection: 'submissions', state: 'declined' },
} as const;
const assignmentTargets = {
  builder_confirm: 'confirmed', builder_decline: 'declined', submit_delivery: 'delivery_submitted',
  request_changes: 'changes_requested', accept_completion: 'completed', cancel: 'cancelled',
} as const;
export type CommandConfirmation = { replayed: boolean; assignment: WorksAssignment | null };
export function projectCommandConfirmation(value: unknown, intent: WorkflowIntent): CommandConfirmation {
  if (!object(value) || value.ok !== true || typeof value.replayed !== 'boolean' || !object(value.resource)) invalid();
  if (intent.kind === 'workspace') {
    const command = intent.body as WorksWorkspaceCommandInput; const expected = commandTargets[command.command];
    const workflow = state(value.resource.workflow, [expected.state]);
    if (value.resource.record_id !== intent.id || value.resource.collection !== expected.collection
      || workflow.revision !== command.expected_revision + 1) invalid();
    return { replayed: value.replayed, assignment: null };
  }
  const assignment = projectAssignment(value.resource);
  if (intent.kind === 'select') {
    const expected = intent.body as WorksSelectProposalInput;
    if (assignment.proposal_id !== intent.id || assignment.state !== 'proposed' || assignment.scope !== expected.scope
      || assignment.terms !== expected.terms || JSON.stringify(assignment.acceptance_criteria) !== JSON.stringify(expected.acceptance_criteria)) invalid();
  } else {
    const expected = intent.body as WorksAssignmentCommandInput;
    if (assignment.assignment_id !== intent.id || assignment.state !== assignmentTargets[expected.command]
      || assignment.revision !== expected.expected_revision + 1) invalid();
    if (expected.command === 'submit_delivery' && (assignment.delivery?.url !== expected.delivery_url || assignment.delivery?.summary !== expected.summary)) invalid();
    if (expected.command === 'accept_completion' && (assignment.outcome?.summary ?? '') !== (expected.summary ?? '')) invalid();
  }
  return { replayed: value.replayed, assignment };
}
export async function sendWorkflowIntent(intent: WorkflowIntent, signal: AbortSignal): Promise<CommandConfirmation> {
  // Re-validate the exact frozen input; redirects never carry the session elsewhere.
  prepareWorkflowIntent(intent.kind, intent.id, intent.body);
  signal.throwIfAborted();
  const url = intent.kind === 'workspace' ? '/api/works/workspace/commands'
    : intent.kind === 'select' ? '/api/works/assignments' : `/api/works/assignments/${intent.id}/commands`;
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(intent.body), ...privateOptions, signal });
  signal.throwIfAborted();
  if (!response.ok) throw responseError(response);
  const body: unknown = await response.json(); signal.throwIfAborted();
  return projectCommandConfirmation(body, intent);
}

export type NotificationReadIntent = Readonly<{ id: string; body: Readonly<WorksNotificationReadInput> }>;
export type NotificationReadConfirmation = { notification_id: string; read_at: string; revision: number; replayed: boolean };

export function prepareNotificationRead(id: string, input: unknown): NotificationReadIntent {
  const checked = validateNotificationRead(input);
  if (!notificationId.test(id) || !checked.ok) throw new Error('workspace_input_invalid');
  return Object.freeze({ id, body: Object.freeze({ expected_revision: checked.value.expected_revision, idempotency_key: checked.value.idempotency_key }) });
}
export function projectNotificationRead(value: unknown, intent: NotificationReadIntent): NotificationReadConfirmation {
  if (!object(value) || value.ok !== true || typeof value.replayed !== 'boolean' || !object(value.resource)) invalid();
  const resource = value.resource;
  if (resource.notification_id !== intent.id || !date(resource.read_at) || !Number.isSafeInteger(resource.revision)
    || resource.revision !== intent.body.expected_revision + 1) invalid();
  return { notification_id: intent.id, read_at: resource.read_at, revision: resource.revision as number, replayed: value.replayed };
}
export async function sendNotificationRead(intent: NotificationReadIntent, signal: AbortSignal): Promise<NotificationReadConfirmation> {
  prepareNotificationRead(intent.id, intent.body);
  signal.throwIfAborted();
  const response = await fetch(`/api/works/workspace/notifications/${intent.id}/read`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(intent.body), ...privateOptions, signal,
  });
  signal.throwIfAborted();
  if (!response.ok) throw responseError(response);
  const body: unknown = await response.json(); signal.throwIfAborted();
  return projectNotificationRead(body, intent);
}
/** Apply a confirmed read only to the loaded version that produced its request. */
export function applyNotificationRead(workspace: WorkspaceData, result: NotificationReadConfirmation): WorkspaceData {
  const matches = workspace.notifications.filter(item => item.notification_id === result.notification_id);
  if (matches.length !== 1 || matches[0].revision !== result.revision - 1 || matches[0].read_at !== null) return workspace;
  return { ...workspace, notifications: workspace.notifications.map(item => item.notification_id === result.notification_id
    ? { ...item, read_at: result.read_at, revision: result.revision } : item) };
}

/** The server owns the session and authorization; no account secret enters browser storage. */
export function createWorkspaceFence() {
  let generation = 0; let controller: AbortController | null = null;
  const cancel = () => { generation++; controller?.abort(); controller = null; };
  return { cancel, begin() { cancel(); const current = generation; const next = new AbortController(); controller = next;
    return { signal: next.signal, isCurrent: () => current === generation && !next.signal.aborted }; } };
}

export function workspaceMessage(error: unknown): string {
  const code = error instanceof Error ? error.message : '';
  if (code === 'workspace_signin_required') return 'Sign in to the account that owns this work. Your session may have expired.';
  if (code === 'workspace_conflict') return 'This record changed, or this request conflicts with an earlier one. Reload the workspace before making another decision.';
  if (code === 'workspace_rate_limited') return 'Too many requests. Wait a moment and try again.';
  if (code === 'workspace_input_invalid') return 'Check the required fields and review the details before continuing.';
  return 'We could not confirm the latest record. Do not assume a request failed or repeat it with new details. Retry the same reviewed request, or reload to check.';
}
