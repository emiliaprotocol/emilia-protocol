// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Jira System-of-Record adapter.
 * Guards bulk issue delete, project delete, and permission grants so they never
 * reach Jira without a receipt bound to THIS resource. Client injected.
 */
import { createAdapter, manifestFromPack, hashCanonical } from './_kit.js';

export const JIRA_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'jira.issue.bulk_delete', label: 'Bulk delete issues', action_type: 'jira.issue.bulk_delete',
    risk: 'critical', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'jira', tool: 'bulk_delete_issues' },
    why: 'Mass-destroys issues. Bind the exact JQL.',
    execution_binding: { required_fields: ['action_type', 'project', 'jql_hash'] },
  }),
  Object.freeze({
    id: 'jira.project.delete', label: 'Delete project', action_type: 'jira.project.delete',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'jira', tool: 'delete_project' },
    why: 'Deletes a project and its issues. Quorum.',
    execution_binding: { required_fields: ['action_type', 'project_key'] },
  }),
  Object.freeze({
    id: 'jira.permission.grant', label: 'Grant permission', action_type: 'jira.permission.grant',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'jira', tool: 'grant_permission' },
    why: 'Changes who can act. Quorum + bind project/principal/role.',
    execution_binding: { required_fields: ['action_type', 'project', 'principal', 'role'] },
  }),
]);

const OPS = {
  'issue.bulk_delete': {
    selector: { protocol: 'jira', tool: 'bulk_delete_issues' },
    observed: (p) => ({ action_type: 'jira.issue.bulk_delete', project: p.project, jql_hash: hashCanonical(String(p.jql || '').trim()) }),
    perform: (c, p) => c.bulkDeleteIssues({ project: p.project, jql: p.jql }),
  },
  'project.delete': {
    selector: { protocol: 'jira', tool: 'delete_project' },
    observed: (p) => ({ action_type: 'jira.project.delete', project_key: p.project_key }),
    perform: (c, p) => c.deleteProject({ projectKey: p.project_key }),
  },
  'permission.grant': {
    selector: { protocol: 'jira', tool: 'grant_permission' },
    observed: (p) => ({ action_type: 'jira.permission.grant', project: p.project, principal: p.principal, role: p.role }),
    perform: (c, p) => c.grantPermission({ project: p.project, principal: p.principal, role: p.role }),
  },
};

const adapter = createAdapter({ system: 'jira', ops: OPS });
export const JIRA_OPS = adapter.OPS;
export function createJiraManifest(extra = []) { return manifestFromPack(JIRA_ACTION_PACK, extra); }
export function guardJiraMutation(gate, client, args) { return adapter.guard(gate, client, args); }
export default { JIRA_ACTION_PACK, JIRA_OPS, createJiraManifest, guardJiraMutation };
