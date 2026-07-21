// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — GitHub System-of-Record adapter.
 *
 * "Install this before your agent can touch production GitHub." Wraps destructive
 * Octokit operations so the mutation NEVER reaches GitHub without a valid,
 * sufficiently-assured, non-replayed human/quorum receipt bound to THIS repo —
 * and on success returns a reliance packet proving exactly what was authorized
 * and what executed.
 *
 *   import { Octokit } from '@octokit/rest';
 *   import { createGate } from '@emilia-protocol/gate';
 *   import { createGithubManifest, guardGithubMutation } from '@emilia-protocol/gate/adapters/github';
 *
 *   const gate = createGate({ manifest: createGithubManifest(), trustedKeys: [ISSUER], store: sharedConsumptionStore });
 *   const octokit = new Octokit({ auth });
 *   await guardGithubMutation(gate, octokit, {
 *     op: 'repo.delete', params: { owner, repo }, receipt,  // throws if no valid receipt
 *   });
 *
 * The receipt's claim must carry the same owner/repo (and username/permission or
 * branch) as the call — a receipt for repo A cannot authorize deleting repo B.
 */
import { createAdapter, manifestFromPack } from './_kit.js';
export const GITHUB_ACTION_PACK = Object.freeze([
    Object.freeze({
        id: 'github.repo.delete',
        label: 'GitHub repo delete',
        action_type: 'github.repo.delete',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'class_a',
        match: { protocol: 'github', tool: 'delete_repo' },
        why: 'Destroys a repository and its history. Bind owner/repo to a named human approval.',
        execution_binding: { required_fields: ['action_type', 'owner', 'repo'] },
    }),
    Object.freeze({
        id: 'github.permission.change',
        label: 'GitHub permission change',
        action_type: 'github.permission.change',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'quorum',
        match: { protocol: 'github', tool: 'update_collaborator_permission' },
        why: 'Changes who can act on the repo. Privilege change deserves the two-person rule.',
        execution_binding: { required_fields: ['action_type', 'owner', 'repo', 'username', 'permission'] },
    }),
    Object.freeze({
        id: 'github.branch_protection.remove',
        label: 'GitHub branch-protection removal',
        action_type: 'github.branch_protection.remove',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'class_a',
        match: { protocol: 'github', tool: 'delete_branch_protection' },
        why: 'Removes the guard rails on a protected branch.',
        execution_binding: { required_fields: ['action_type', 'owner', 'repo', 'branch'] },
    }),
]);
const OPS = {
    'repo.delete': {
        selector: { protocol: 'github', tool: 'delete_repo' },
        observed: (p) => ({ action_type: 'github.repo.delete', owner: p.owner, repo: p.repo }),
        perform: (octokit, p) => octokit.repos.delete({ owner: p.owner, repo: p.repo }),
    },
    'permission.change': {
        selector: { protocol: 'github', tool: 'update_collaborator_permission' },
        observed: (p) => ({
            action_type: 'github.permission.change',
            owner: p.owner, repo: p.repo, username: p.username, permission: p.permission,
        }),
        perform: (octokit, p) => octokit.repos.addCollaborator({
            owner: p.owner, repo: p.repo, username: p.username, permission: p.permission,
        }),
    },
    'branch_protection.remove': {
        selector: { protocol: 'github', tool: 'delete_branch_protection' },
        observed: (p) => ({ action_type: 'github.branch_protection.remove', owner: p.owner, repo: p.repo, branch: p.branch }),
        perform: (octokit, p) => octokit.repos.deleteBranchProtection({ owner: p.owner, repo: p.repo, branch: p.branch }),
    },
};
const adapter = createAdapter({ system: 'github', ops: OPS });
export const GITHUB_OPS = adapter.OPS;
/** Build an action-risk manifest for the GitHub destructive ops (plus any extras). */
export function createGithubManifest(extraActions = []) {
    return manifestFromPack(GITHUB_ACTION_PACK, extraActions);
}
/**
 * Guard a destructive GitHub mutation behind the gate. The call never reaches
 * GitHub unless a valid, sufficiently-assured, non-replayed receipt bound to
 * THIS repo is present.
 * @param {object} gate     a gate built with createGithubManifest()
 * @param {object} octokit  an Octokit-like client (@octokit/rest or compatible)
 * @param {object} o
 * @param {string} o.op     'repo.delete' | 'permission.change' | 'branch_protection.remove'
 * @param {object} o.params { owner, repo, [username], [permission], [branch] }
 * @param {object} o.receipt the EMILIA receipt authorizing THIS exact op
 * @returns {Promise<{ result:any, reliance:object, execution:object }>}
 * @throws  Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the call never reaches GitHub
 */
export function guardGithubMutation(gate, octokit, args) {
    return adapter.guard(gate, octokit, args);
}
export default { GITHUB_ACTION_PACK, GITHUB_OPS, createGithubManifest, guardGithubMutation };
//# sourceMappingURL=github.js.map