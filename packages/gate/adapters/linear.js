// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Linear System-of-Record adapter.
 * Guards issue deletion, bulk delete, and team deletion so they never reach
 * Linear without a receipt bound to THIS resource. Client injected.
 */
import { createAdapter, manifestFromPack, hashCanonical } from './_kit.js';

export const LINEAR_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'linear.issue.delete', label: 'Delete issue', action_type: 'linear.issue.delete',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'linear', tool: 'delete_issue' },
    why: 'Destroys an issue. Bind the issue id.',
    execution_binding: { required_fields: ['action_type', 'issue_id'] },
  }),
  Object.freeze({
    id: 'linear.issue.bulk_delete', label: 'Bulk delete issues', action_type: 'linear.issue.bulk_delete',
    risk: 'critical', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'linear', tool: 'bulk_delete_issues' },
    why: 'Mass-destroys issues. Bind the exact query.',
    execution_binding: { required_fields: ['action_type', 'team', 'query_hash'] },
  }),
  Object.freeze({
    id: 'linear.team.delete', label: 'Delete team', action_type: 'linear.team.delete',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'linear', tool: 'delete_team' },
    why: 'Deletes a team and its issues. Quorum.',
    execution_binding: { required_fields: ['action_type', 'team_id'] },
  }),
]);

const OPS = {
  'issue.delete': {
    selector: { protocol: 'linear', tool: 'delete_issue' },
    observed: (p) => ({ action_type: 'linear.issue.delete', issue_id: p.issue_id }),
    perform: (c, p) => c.deleteIssue({ issueId: p.issue_id }),
  },
  'issue.bulk_delete': {
    selector: { protocol: 'linear', tool: 'bulk_delete_issues' },
    observed: (p) => ({ action_type: 'linear.issue.bulk_delete', team: p.team, query_hash: hashCanonical(String(p.query || '').trim()) }),
    perform: (c, p) => c.bulkDeleteIssues({ team: p.team, query: p.query }),
  },
  'team.delete': {
    selector: { protocol: 'linear', tool: 'delete_team' },
    observed: (p) => ({ action_type: 'linear.team.delete', team_id: p.team_id }),
    perform: (c, p) => c.deleteTeam({ teamId: p.team_id }),
  },
};

const adapter = createAdapter({ system: 'linear', ops: OPS });
export const LINEAR_OPS = adapter.OPS;
export function createLinearManifest(extra = []) { return manifestFromPack(LINEAR_ACTION_PACK, extra); }
export function guardLinearMutation(gate, client, args) { return adapter.guard(gate, client, args); }
export default { LINEAR_ACTION_PACK, LINEAR_OPS, createLinearManifest, guardLinearMutation };
