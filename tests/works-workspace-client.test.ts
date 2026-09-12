// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createWorkspaceFence, loadAssignment, loadWorkspace, prepareWorkflowIntent, projectAssignment,
  projectCommandConfirmation, projectWorkspace, sendWorkflowIntent, prepareNotificationRead,
  projectNotificationRead, sendNotificationRead, applyNotificationRead } from '../app/works/workspace-client';
import { createSubmissionAttemptTracker, eligibleSubmissionChoice, sendOrCheckSubmission } from '../app/works/SubmissionForm';

const stamp = '2026-09-07T17:00:00.000Z';
const job = { opportunity_id: 'job-refunds', kind: 'problem', title: 'Review refunds', description: 'Prepare a queue. Do not issue refunds.', posted_by: 'Finance team', contact_route: 'mailto:finance@example.com', claims: [] };
const builder = { builder_id: 'builder-first', kind: 'person', name: 'Builder', contact_route: 'mailto:builder@example.com', affiliations: [] };
const listing = { listing_id: 'agent-first', builder_id: builder.builder_id, kind: 'agent', name: 'Refund agent', summary: 'Reviews refunds', status: 'active', supported_tasks: ['review'], interfaces: ['HTTP'], operating_constraints: ['No payments'] };
const proposal = { submission_id: 'proposal-first', opportunity_id: job.opportunity_id, builder_id: builder.builder_id, listing_id: listing.listing_id, proposal: 'We will prepare the queue.', team: [] };
const assignment = {
  assignment_id: 'assignment-first', job_id: job.opportunity_id, proposal_id: proposal.submission_id, builder_id: builder.builder_id, listing_id: listing.listing_id,
  state: 'proposed', revision: 0, scope: 'Prepare the queue only.', acceptance_criteria: ['Every exception has a source.'], terms: 'Terms agreed separately.',
  frozen: { job, proposal }, delivery: null, outcome: null, created_at: stamp, updated_at: stamp,
  history: [{ actor_role: 'buyer', command: 'proposal_selected', revision: 0, at: stamp, summary: null, reason: null, delivery: null }],
};
const workflow = (state = 'open', revision = 0) => ({ state, revision, updated_at: null });
const workspace = {
  viewer: { display_name: 'Finance team', role: 'both' }, profiles: [builder], listings: [{ record: listing, workflow: workflow('active') }],
  jobs: [{ record: job, workflow: workflow() }], submitted_proposals: [{ record: proposal, workflow: workflow('submitted') }],
  received_proposals: [{ record: proposal, job, workflow: workflow('submitted') }], assignments: [{ assignment, viewer_role: 'buyer' }], notifications: [],
};
const signal = () => new AbortController().signal;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const workspaceIntent = () => prepareWorkflowIntent('workspace', job.opportunity_id, { command: 'close_job', record_id: job.opportunity_id, expected_revision: 0, idempotency_key: 'review-request-123456' });
const workspaceResult = { ok: true, replayed: false, resource: { collection: 'opportunities', record_id: job.opportunity_id, workflow: { state: 'closed', revision: 1, updated_at: stamp } } };
vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
afterEach(() => vi.unstubAllGlobals());

describe('private workspace DTO projection', () => {
  it('preserves notification revisions and refuses missing or invalid revisions', () => {
    const notification = { notification_id: '8375631f-2faa-4d91-a681-9cc782d12345', kind: 'proposal_received', resource_type: 'proposal', resource_id: proposal.submission_id,
      created_at: stamp, read_at: null, revision: 0 };
    expect(projectWorkspace({ ...workspace, notifications: [notification] }).notifications[0].revision).toBe(0);
    for (const revision of [undefined, -1, 0.5, '0']) {
      expect(() => projectWorkspace({ ...workspace, notifications: [{ ...notification, revision }] })).toThrow('workspace_response_invalid');
    }
    expect(() => projectWorkspace({ ...workspace, notifications: [{ ...notification, notification_id: '../another-record' }] })).toThrow('workspace_response_invalid');
  });
  it('projects current records without internal account data or ownership secrets', () => {
    const result = projectWorkspace({ ...workspace, api_key: 'secret-value', jobs: [{ record: { ...job, owner_entity_id: 'private-owner' }, workflow: workflow() }] });
    expect(result.jobs[0].record).toMatchObject(job);
    expect(result.assignments[0].assignment.scope).toBe(assignment.scope);
    expect(JSON.stringify(result)).not.toMatch(/secret-value|private-owner|owner_entity_id/);
  });
  it.each([null, {}, { ...workspace, viewer: { role: 'admin', display_name: 'Admin' } }, { ...workspace, listings: null },
    { ...workspace, jobs: [{ record: job, workflow: workflow('open', -1) }] },
    { ...workspace, jobs: [{ record: job, workflow: workflow('approved') }] },
    { ...workspace, jobs: [{ record: { ...job, example: true }, workflow: workflow() }] },
    { ...workspace, received_proposals: [{ record: { ...proposal, opportunity_id: 'another-job' }, job, workflow: workflow('submitted') }] },
    { ...workspace, assignments: [{ assignment, viewer_role: 'admin' }] }])('rejects malformed or mis-scoped workspace records: %j', value => {
    expect(() => projectWorkspace(value)).toThrow('workspace_response_invalid');
  });
  it('requires real delivery and owner acceptance evidence before displaying completion', () => {
    expect(() => projectAssignment({ ...assignment, state: 'completed' })).toThrow();
    expect(() => projectAssignment({ ...assignment, state: 'delivery_submitted', delivery: { url: 'javascript:alert(1)', summary: 'Done', submitted_at: stamp } })).toThrow();
    expect(() => projectAssignment({ ...assignment, frozen: { job: { ...job, opportunity_id: 'other-job' }, proposal } })).toThrow();
    const completed = projectAssignment({ ...assignment, state: 'completed', delivery: { url: 'https://example.com/report', summary: 'Queue delivered.', submitted_at: stamp }, outcome: { accepted_at: stamp, summary: 'Reviewed all exceptions.' } });
    expect(completed.outcome?.summary).toBe('Reviewed all exceptions.');
  });
  it('uses only session-authenticated same-origin reads, and rejects a different assignment ID', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(json(workspace)).mockResolvedValueOnce(json({ viewer_role: 'buyer', assignment }));
    vi.stubGlobal('fetch', fetcher);
    await loadWorkspace(signal());
    await expect(loadAssignment('different-assignment', signal())).rejects.toThrow('workspace_response_invalid');
    expect(fetcher.mock.calls[0][0]).toBe('/api/works/workspace');
    expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' });
    expect(fetcher.mock.calls[0][1].headers).toBeUndefined();
  });
  it.each([401, 403, 404, 409, 429, 503])('never turns HTTP %i into a misleading empty workspace', async status => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({ detail: 'private server detail' }, status)));
    await expect(loadWorkspace(signal())).rejects.toThrow(/^workspace_(signin_required|conflict|rate_limited|unavailable)$/);
  });
});

describe('signed-in proposal choices', () => {
  it('limits choices to the session-owned builder and its active listings', () => {
    const projected = projectWorkspace(workspace);
    expect(eligibleSubmissionChoice(projected, builder.builder_id, listing.listing_id)).toBe(true);
    expect(eligibleSubmissionChoice(projected, builder.builder_id, '')).toBe(true);
    expect(eligibleSubmissionChoice(projected, 'foreign-builder', listing.listing_id)).toBe(false);
    expect(eligibleSubmissionChoice(projected, builder.builder_id, 'foreign-agent')).toBe(false);
    projected.listings[0].workflow.state = 'paused';
    expect(eligibleSubmissionChoice(projected, builder.builder_id, listing.listing_id)).toBe(false);
    projected.listings[0].workflow.state = 'active'; projected.listings[0].record.builder_id = 'foreign-builder';
    expect(eligibleSubmissionChoice(projected, builder.builder_id, listing.listing_id)).toBe(false);
  });
  it('does not confirm a private send after its account context was cancelled during decoding', async () => {
    const payload = createSubmissionAttemptTracker().prepare({ opportunityId: job.opportunity_id, builderId: builder.builder_id,
      listingId: listing.listing_id, proposal: proposal.proposal, team: '', visibility: 'private' }, () => proposal.submission_id);
    const controller = new AbortController(); const response = json({ collection: 'submissions', record: payload });
    vi.spyOn(response, 'json').mockImplementationOnce(async () => { controller.abort(); return { collection: 'submissions', record: payload }; });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));
    await expect(sendOrCheckSubmission(payload, null, false, controller.signal)).rejects.toThrow();
  });
});

describe('reviewed workflow requests', () => {
  it('freezes the reviewed payload and does not mint a fresh ID after a lost response', async () => {
    const intent = workspaceIntent(); const original = JSON.stringify(intent.body);
    const fetcher = vi.fn().mockRejectedValueOnce(new TypeError('Lost response'))
      .mockResolvedValueOnce(json({ ...workspaceResult, replayed: true }));
    vi.stubGlobal('fetch', fetcher);
    await expect(sendWorkflowIntent(intent, signal())).rejects.toThrow('Lost response');
    expect(await sendWorkflowIntent(intent, signal())).toEqual({ replayed: true, assignment: null });
    expect(fetcher.mock.calls.map(call => call[1].body)).toEqual([original, original]);
    expect(Object.isFrozen(intent.body)).toBe(true);
  });
  it.each([{}, { ok: true }, { ...workspaceResult, replayed: 'false' },
    { ...workspaceResult, resource: { ...workspaceResult.resource, record_id: 'other-job' } },
    { ...workspaceResult, resource: { ...workspaceResult.resource, collection: 'listings' } },
    { ...workspaceResult, resource: { ...workspaceResult.resource, workflow: workflow('closed', 2) } },
    { ...workspaceResult, resource: { ...workspaceResult.resource, workflow: workflow('open', 1) } }])('does not treat malformed or mismatched success as confirmation: %j', value => {
    expect(() => projectCommandConfirmation(value, workspaceIntent())).toThrow();
  });
  it('requires the proposed assignment to match the reviewed scope, terms and criteria', () => {
    const intent = prepareWorkflowIntent('select', proposal.submission_id, { proposal_id: proposal.submission_id, expected_revision: 0, idempotency_key: 'select-request-123456', scope: assignment.scope, acceptance_criteria: assignment.acceptance_criteria, terms: assignment.terms });
    expect(projectCommandConfirmation({ ok: true, replayed: false, resource: assignment }, intent).assignment?.assignment_id).toBe(assignment.assignment_id);
    for (const change of [{ scope: 'Different scope' }, { terms: 'Different terms' }, { acceptance_criteria: ['Different criterion'] }, { state: 'confirmed' }]) {
      expect(() => projectCommandConfirmation({ ok: true, replayed: false, resource: { ...assignment, ...change } }, intent)).toThrow();
    }
  });
  it('binds submitted delivery and completion review to the exact command and next revision', () => {
    const intent = prepareWorkflowIntent('assignment', assignment.assignment_id, { command: 'submit_delivery', expected_revision: 1, idempotency_key: 'deliver-request-123456', delivery_url: 'https://example.com/report', summary: 'Queue delivered.' });
    const delivery = { url: 'https://example.com/report', summary: 'Queue delivered.', submitted_at: stamp };
    const delivered = { ...assignment, state: 'delivery_submitted', revision: 2, delivery, history: [...assignment.history,
      { actor_role: 'builder', command: 'submit_delivery', revision: 2, at: stamp, summary: 'Queue delivered.', reason: null, delivery }] };
    expect(projectCommandConfirmation({ ok: true, replayed: false, resource: delivered }, intent).assignment?.revision).toBe(2);
    expect(() => projectCommandConfirmation({ ok: true, replayed: false, resource: { ...delivered, delivery: { ...delivered.delivery, summary: 'Different content' } } }, intent)).toThrow();
  });
  it('refuses a delivery URL containing a username or password before sending it', () => {
    expect(() => prepareWorkflowIntent('assignment', assignment.assignment_id, { command: 'submit_delivery', expected_revision: 1, idempotency_key: 'deliver-request-123456', delivery_url: 'https://user:secret@example.com/report', summary: 'Queue delivered.' })).toThrow('workspace_input_invalid');
  });
  it.each(['read', 'write'])('does not restore a late %s result after abort during body decoding', async mode => {
    const controller = new AbortController(); const response = json(mode === 'read' ? workspace : workspaceResult);
    vi.spyOn(response, 'json').mockImplementationOnce(async () => { controller.abort(); return mode === 'read' ? workspace : workspaceResult; });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));
    await expect(mode === 'read' ? loadWorkspace(controller.signal) : sendWorkflowIntent(workspaceIntent(), controller.signal)).rejects.toThrow();
  });
  it('invalidates earlier requests on clear, refresh and a later command', () => {
    const fence = createWorkspaceFence(); const first = fence.begin(); const second = fence.begin();
    expect(first.signal.aborted).toBe(true); expect(first.isCurrent()).toBe(false); expect(second.isCurrent()).toBe(true);
    fence.cancel(); expect(second.isCurrent()).toBe(false);
  });
});

describe('explicit notification read requests', () => {
  const id = '8375631f-2faa-4d91-a681-9cc782d12345';
  const otherId = '8375631f-2faa-4d91-a681-9cc782d12346';
  const intent = () => prepareNotificationRead(id, { expected_revision: 0, idempotency_key: 'mark-read-request-12345' });
  const result = { ok: true, replayed: false, resource: { notification_id: id, read_at: stamp, revision: 1 } };

  it('sends only the exact frozen notification, revision and retry key over the session route', async () => {
    const pending = intent();
    const fetcher = vi.fn().mockRejectedValueOnce(new Error('Lost response')).mockResolvedValueOnce(json({ ...result, replayed: true }));
    vi.stubGlobal('fetch', fetcher);
    await expect(sendNotificationRead(pending, signal())).rejects.toThrow('Lost response');
    await expect(sendNotificationRead(pending, signal())).resolves.toMatchObject({ ...result.resource, replayed: true });
    expect(Object.isFrozen(pending.body)).toBe(true);
    expect(fetcher.mock.calls[0][0]).toBe(`/api/works/workspace/notifications/${id}/read`);
    expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    expect(fetcher.mock.calls[0][1].body).toBe(fetcher.mock.calls[1][1].body);
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual(pending.body);
  });

  it.each([null, {}, { ...result, ok: false }, { ...result, replayed: 'true' },
    { ...result, resource: { ...result.resource, notification_id: otherId } },
    { ...result, resource: { ...result.resource, read_at: null } },
    { ...result, resource: { ...result.resource, read_at: 'not-a-time' } },
    { ...result, resource: { ...result.resource, revision: 0 } },
    { ...result, resource: { ...result.resource, revision: 2 } },
  ])('never claims a read for malformed or mismatched success: %j', value => {
    expect(() => projectNotificationRead(value, intent())).toThrow('workspace_response_invalid');
  });

  it.each([401, 403, 404, 409, 429, 503])('keeps an HTTP %i failure unconfirmed', async status => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(result, status)));
    await expect(sendNotificationRead(intent(), signal())).rejects.toThrow(/^workspace_/);
  });

  it('does not confirm an aborted response after body decoding', async () => {
    const controller = new AbortController(); const response = json(result);
    vi.spyOn(response, 'json').mockImplementation(async () => { controller.abort(); return result; });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
    await expect(sendNotificationRead(intent(), controller.signal)).rejects.toThrow();
  });

  it('rejects unsafe IDs and extra or invalid request fields before fetch', () => {
    expect(() => prepareNotificationRead('../foreign-account', { expected_revision: 0, idempotency_key: 'mark-read-request-12345' })).toThrow('workspace_input_invalid');
    expect(() => prepareNotificationRead(id, { expected_revision: -1, idempotency_key: 'mark-read-request-12345' })).toThrow('workspace_input_invalid');
    expect(() => prepareNotificationRead(id, { expected_revision: 0, idempotency_key: 'mark-read-request-12345', read_at: stamp })).toThrow('workspace_input_invalid');
  });

  it('updates only the matching loaded revision and never regresses or invents a notification', () => {
    const notification = { notification_id: id, kind: 'proposal_received' as const, resource_type: 'proposal' as const, resource_id: proposal.submission_id,
      created_at: stamp, read_at: null, revision: 0 };
    const original = projectWorkspace({ ...workspace, notifications: [notification, { ...notification, notification_id: otherId }] });
    const confirmation = projectNotificationRead(result, intent());
    const updated = applyNotificationRead(original, confirmation);
    expect(original.notifications[0].read_at).toBeNull();
    expect(updated.notifications[0]).toMatchObject({ read_at: stamp, revision: 1 });
    expect(updated.notifications[1]).toBe(original.notifications[1]);
    expect(applyNotificationRead({ ...original, notifications: [] }, confirmation).notifications).toEqual([]);
    const newer = { ...updated, notifications: [{ ...updated.notifications[0], revision: 3 }] };
    expect(applyNotificationRead(newer, confirmation)).toBe(newer);
  });
});
