// SPDX-License-Identifier: Apache-2.0
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi, afterEach } from 'vitest';
import WorkspacePage from '../app/works/workspace/page';
import Workspace from '../app/works/workspace/Workspace';
import NotificationRow from '../app/works/workspace/NotificationRow';
import AssignmentPage from '../app/works/assignments/[id]/page';
import { AssignmentRecord, availableAssignmentCommands } from '../app/works/assignments/[id]/Assignment';
import { projectAssignment } from '../app/works/workspace-client';
import { readFileSync } from 'node:fs';

vi.mock('next/navigation', () => ({ notFound: () => { throw new Error('WORKS_NOT_FOUND'); } }));
afterEach(() => vi.unstubAllEnvs());

describe('private workspace entry', () => {
  it('gates the workspace and renders no private record before a session check', async () => {
    vi.stubEnv('WORKS_V0', '0');
    expect(() => WorkspacePage()).toThrow('WORKS_NOT_FOUND');
    vi.stubEnv('WORKS_V0', '1');
    const html = renderToStaticMarkup(WorkspacePage());
    expect(html).toContain('main-content');
    expect(html).toContain('Your work, in one place.');
    expect(html).toContain('/works/account');
    expect(html).not.toContain('type="password"');
  });
  it('does not turn an unrequested workspace into fake empty records', () => {
    const html = renderToStaticMarkup(createElement(Workspace));
    expect(html).toContain('Open workspace');
    expect(html).not.toContain('No jobs yet');
    expect(html).not.toContain('No assignments yet');
    expect(html).toContain('does not grant an agent access');
  });
});

describe('workspace notification actions', () => {
  const notification = { notification_id: '8375631f-2faa-4d91-a681-9cc782d12345', kind: 'proposal_received' as const,
    resource_type: 'proposal' as const, resource_id: 'proposal-first', created_at: '2026-09-07T17:00:00.000Z', read_at: null, revision: 0 };
  it('shows an explicit unread action without marking anything on render', () => {
    const confirmed = vi.fn(); const reload = vi.fn();
    const html = renderToStaticMarkup(createElement(NotificationRow, { notification, onConfirmed: confirmed, onReload: reload }));
    expect(html).toContain('New proposal received'); expect(html).toContain('Unread'); expect(html).toContain('Mark as read');
    expect(html).toContain('/works/submissions/proposal-first'); expect(html).not.toContain('Marked as read');
    expect(confirmed).not.toHaveBeenCalled(); expect(reload).not.toHaveBeenCalled();
  });
  it('shows a server-confirmed read time instead of another write button', () => {
    const html = renderToStaticMarkup(createElement(NotificationRow, { notification: { ...notification, read_at: '2026-09-07T17:05:00.000Z', revision: 1 }, onConfirmed: vi.fn(), onReload: vi.fn() }));
    expect(html).toContain('Marked as read'); expect(html).not.toContain('>Mark as read<');
    expect(html).toContain('2026-09-07T17:05:00.000Z');
  });
  it('retains retry intent across section switches and cancels stale completions', () => {
    const row = readFileSync(new URL('../app/works/workspace/NotificationRow.tsx', import.meta.url), 'utf8');
    const workspace = readFileSync(new URL('../app/works/workspace/Workspace.tsx', import.meta.url), 'utf8');
    expect(row).toContain('if (!intent.current) intent.current = prepareNotificationRead');
    expect(row).toContain('sendNotificationRead(intent.current, request.signal)');
    expect(row).toContain('if (request.isCurrent()) onConfirmed(result)');
    expect(row).toContain('return () => fence.cancel()');
    expect(row).toContain('Retry marking as read');
    expect(workspace).toContain("hidden={tab !== 'updates'}");
    expect(workspace).toContain('applyNotificationRead(current, result)');
    expect(workspace).toContain('unread updates');
  });
  it('keeps mobile update actions readable with full-width touch targets and wrapping content', () => {
    const css = readFileSync(new URL('../app/works/workspace/workspace.module.css', import.meta.url), 'utf8');
    expect(css).toContain('.meta{font-size:16px');
    expect(css).toContain('.notificationActions{display:grid;grid-template-columns:1fr}');
    expect(css).toContain('.notificationActions>*{width:100%}');
    expect(css).toContain('min-height:48px');
    expect(css).toContain('overflow-wrap:anywhere');
  });
});

describe('assignment review boundaries', () => {
  it('shows only role-appropriate decisions and closes terminal records', () => {
    expect(availableAssignmentCommands('builder', 'proposed')).toEqual(['builder_confirm', 'builder_decline']);
    expect(availableAssignmentCommands('buyer', 'proposed')).toEqual(['cancel']);
    expect(availableAssignmentCommands('builder', 'confirmed')).toContain('submit_delivery');
    expect(availableAssignmentCommands('builder', 'changes_requested')).toContain('submit_delivery');
    expect(availableAssignmentCommands('buyer', 'delivery_submitted')).toEqual(['accept_completion', 'request_changes', 'cancel']);
    expect(availableAssignmentCommands('builder', 'delivery_submitted')).not.toContain('accept_completion');
    for (const state of ['completed', 'cancelled', 'declined'] as const) {
      expect(availableAssignmentCommands('buyer', state)).toEqual([]);
      expect(availableAssignmentCommands('builder', state)).toEqual([]);
    }
  });
  it('does not SSR a private assignment and rejects unsafe identifiers', async () => {
    vi.stubEnv('WORKS_V0', '1');
    const html = renderToStaticMarkup(await AssignmentPage({ params: Promise.resolve({ id: 'assignment-first' }) }));
    expect(html).toContain('Open assignment'); expect(html).not.toContain('Frozen scope');
    await expect(AssignmentPage({ params: Promise.resolve({ id: '../private-record' }) })).rejects.toThrow('WORKS_NOT_FOUND');
  });
  it('keeps requested changes and cancellation reasons visible after reload without upgrading them to ratings', () => {
    const stamp = '2026-09-07T17:00:00.000Z';
    const job = { opportunity_id: 'job-refunds', kind: 'problem', title: 'Refund review', description: 'Prepare only.', posted_by: 'Buyer', contact_route: 'mailto:buyer@example.com', claims: [] };
    const proposal = { submission_id: 'proposal-first', opportunity_id: job.opportunity_id, builder_id: 'builder-first', listing_id: null, proposal: 'We can prepare a queue.', team: [] };
    const assignment = projectAssignment({ assignment_id: 'assignment-first', job_id: job.opportunity_id, proposal_id: proposal.submission_id, builder_id: proposal.builder_id, listing_id: null,
      state: 'cancelled', revision: 2, scope: 'Prepare the queue.', terms: 'Agreed outside EMILIA.', acceptance_criteria: ['Each exception has a source.'], frozen: { job, proposal },
      created_at: stamp, updated_at: stamp, delivery: null, outcome: null, history: [
        { actor_role: 'buyer', command: 'request_changes', revision: 1, at: stamp, summary: 'Add the missing sources.', reason: null, delivery: null },
        { actor_role: 'buyer', command: 'cancel', revision: 2, at: stamp, summary: null, reason: 'Project no longer needed.', delivery: null },
      ] });
    const html = renderToStaticMarkup(createElement(AssignmentRecord, { view: { assignment, viewer_role: 'builder' } }));
    expect(html).toContain('Add the missing sources.'); expect(html).toContain('Project no longer needed.');
    expect(html).toContain('Original proposal'); expect(html).not.toContain('Certified');
  });
  it('clears private details on hide and retains a reviewed idempotency key rather than an account secret', () => {
    for (const file of ['../app/works/workspace/Workspace.tsx', '../app/works/assignments/[id]/Assignment.tsx']) {
      const source = readFileSync(new URL(file, import.meta.url), 'utf8');
      expect(source).toContain("document.visibilityState === 'hidden'");
      expect(source).toContain("window.addEventListener('pagehide', leave)");
      expect(source).not.toMatch(/localStorage|sessionStorage|type="password"|console\./);
    }
    const review = readFileSync(new URL('../app/works/workspace/CommandReview.tsx', import.meta.url), 'utf8');
    expect(review).toContain('sendWorkflowIntent(intent, request.signal)');
    expect(review).not.toContain('randomUUID');
    expect(review).toContain('if (!consent || busy');
    expect(review).toContain('Retry this exact request');
    expect(review).toContain('Check the latest record');
  });
});
