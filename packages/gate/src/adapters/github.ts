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
import {
  canonicalActuatorObject,
  createAdapter,
  hashCanonical,
  manifestFromPack,
} from './_kit.js';
import { executeWithGateAllowance } from '../allowance.js';

const GITHUB_WORKFLOW_ALLOWANCE_ACTION = 'github.workflow.dispatch.production';
const GITHUB_WORKFLOW_ALLOWANCE_UNIT = 'DISPATCH';
const GITHUB_DEPLOYMENT_ALLOWANCE_ACTION = 'github.environment.enter.production';
const GITHUB_DEPLOYMENT_ALLOWANCE_UNIT = 'ADMISSION';
const GITHUB_SHA = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const GITHUB_REF = /^refs\/(?:heads|tags)\/[A-Za-z0-9._/-]{1,240}$/;
const GITHUB_WORKFLOW = /^(?:\.github\/workflows\/)?[A-Za-z0-9._/-]{1,240}$/;

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
const githubAllowanceConnectors = new WeakMap<object, {
  octokit: any;
  connectorInstanceId: string;
}>();

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

/** Digest the closed workflow-dispatch input object without disclosing it in the allowance. */
export function githubWorkflowInputsDigest(inputs = {}) {
  return `sha256:${hashCanonical(inputs)}`;
}

/** Bind an Octokit client to the installation identity returned by a trusted provider probe. */
export async function createGithubAllowanceConnector({
  octokit,
}: {
  octokit?: any;
} = {}) {
  if (!octokit?.actions || typeof octokit.actions.createWorkflowDispatch !== 'function'
      || typeof octokit.request !== 'function') {
    throw new TypeError('createGithubAllowanceConnector requires an Octokit workflow-dispatch client');
  }
  const response = await octokit.request('GET /installation');
  const installationId = response?.data?.id;
  if (!Number.isSafeInteger(installationId) || installationId <= 0) {
    throw new TypeError('GitHub installation identity probe returned an invalid installation');
  }
  const connectorInstanceId = `github:installation:${installationId}`;
  const connector = Object.freeze({});
  githubAllowanceConnectors.set(connector, { octokit, connectorInstanceId });
  return connector;
}

/**
 * Bind a deployment-protection client to the GitHub App installation that
 * authenticated the provider probe.  The resulting opaque connector is the
 * only object accepted by the deployment admission function.
 */
export async function createGithubDeploymentProtectionConnector({
  octokit,
}: {
  octokit?: any;
} = {}) {
  if (typeof octokit?.request !== 'function') {
    throw new TypeError('createGithubDeploymentProtectionConnector requires an Octokit request client');
  }
  const response = await octokit.request('GET /installation');
  const installationId = response?.data?.id;
  if (!Number.isSafeInteger(installationId) || installationId <= 0) {
    throw new TypeError('GitHub installation identity probe returned an invalid installation');
  }
  const connectorInstanceId = `github:installation:${installationId}`;
  const connector = Object.freeze({});
  githubAllowanceConnectors.set(connector, { octokit, connectorInstanceId });
  return connector;
}

function githubDeploymentParameters(params) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new TypeError('guardGithubDeploymentProtectionRule requires deployment params');
  }
  for (const field of ['owner', 'repo', 'environment', 'workflow', 'ref', 'sha', 'event']) {
    if (typeof params[field] !== 'string' || params[field].length === 0) {
      throw new TypeError(`guardGithubDeploymentProtectionRule requires params.${field}`);
    }
  }
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(params.owner)
      || !/^[A-Za-z0-9_.-]{1,100}$/.test(params.repo)
      || !/^[A-Za-z0-9_.:/-]{1,255}$/.test(params.environment)
      || !GITHUB_WORKFLOW.test(params.workflow)
      || !GITHUB_REF.test(params.ref)
      || !GITHUB_SHA.test(params.sha)
      || !/^[A-Za-z0-9_.:-]{1,100}$/.test(params.event)
      || !Number.isSafeInteger(params.repositoryId) || params.repositoryId < 1
      || !Number.isSafeInteger(params.runId) || params.runId < 1) {
    throw new TypeError('guardGithubDeploymentProtectionRule deployment params are invalid');
  }
  return canonicalActuatorObject({
    owner: params.owner,
    repo: params.repo,
    repositoryId: params.repositoryId,
    environment: params.environment,
    workflow: params.workflow,
    ref: params.ref,
    sha: params.sha,
    event: params.event,
    runId: params.runId,
  });
}

/**
 * Approve one GitHub workflow run's admission to one named environment under
 * a signed Gate allowance. Authority is reserved and consumed before GitHub's
 * approval endpoint is entered. An uncertain callback response is therefore
 * INDETERMINATE and cannot be blindly retried under a new operation id.
 */
export function guardGithubDeploymentProtectionRule({
  connector,
  params,
  operationId,
  ...allowanceOptions
}) {
  const configured = githubAllowanceConnectors.get(connector);
  if (!configured) {
    throw new TypeError('guardGithubDeploymentProtectionRule requires a configured GitHub deployment connector');
  }
  const input = githubDeploymentParameters(params);
  const action = {
    action_type: GITHUB_DEPLOYMENT_ALLOWANCE_ACTION,
    repository: `${input.owner}/${input.repo}`,
    repository_id: input.repositoryId,
    environment: input.environment,
    workflow: input.workflow,
    ref: input.ref,
    sha: input.sha,
    event: input.event,
    run_id: input.runId,
    decision: 'approved',
    amount: 1,
    currency: GITHUB_DEPLOYMENT_ALLOWANCE_UNIT,
    operation_id: operationId,
  };
  return executeWithGateAllowance({
    ...allowanceOptions,
    expected: {
      ...(allowanceOptions.expected || {}),
      connector_id: configured.connectorInstanceId,
    },
    action,
    operationId,
    executeAction: async (verifiedAction) => {
      const separator = verifiedAction.repository.indexOf('/');
      const response = await configured.octokit.request(
        'POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule',
        {
          owner: verifiedAction.repository.slice(0, separator),
          repo: verifiedAction.repository.slice(separator + 1),
          run_id: verifiedAction.run_id,
          environment_name: verifiedAction.environment,
          state: 'approved',
          comment: "EMILIA authorized this workflow run's admission to this environment.",
        },
      );
      if (response?.status !== 204) throw new Error('github_deployment_review_outcome_indeterminate');
      return response;
    },
  });
}

/**
 * Dispatch one specifically bound production workflow under a signed Gate
 * allowance. The Octokit client and GitHub credential remain in the caller's
 * process; this path exposes no generic GitHub mutation.
 */
export function guardGithubAllowanceMutation({
  connector,
  params,
  operationId,
  ...allowanceOptions
}) {
  const configured = githubAllowanceConnectors.get(connector);
  if (!configured) throw new TypeError('guardGithubAllowanceMutation requires a configured GitHub allowance connector');
  const { octokit, connectorInstanceId } = configured;
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new TypeError('guardGithubAllowanceMutation requires workflow dispatch params');
  }
  for (const field of ['owner', 'repo', 'workflow', 'ref']) {
    if (typeof params[field] !== 'string' || params[field].length === 0) {
      throw new TypeError(`guardGithubAllowanceMutation requires params.${field}`);
    }
  }
  if (params.inputs !== undefined
      && (params.inputs === null || typeof params.inputs !== 'object' || Array.isArray(params.inputs))) {
    throw new TypeError('guardGithubAllowanceMutation params.inputs must be an object');
  }
  const input = canonicalActuatorObject({
    owner: params.owner,
    repo: params.repo,
    workflow: params.workflow,
    ref: params.ref,
    inputs: params.inputs || {},
  });
  const action = {
    action_type: GITHUB_WORKFLOW_ALLOWANCE_ACTION,
    repository: `${input.owner}/${input.repo}`,
    workflow: input.workflow,
    ref: input.ref,
    inputs_digest: githubWorkflowInputsDigest(input.inputs),
    workflow_inputs: input.inputs,
    amount: 1,
    currency: GITHUB_WORKFLOW_ALLOWANCE_UNIT,
    operation_id: operationId,
  };
  return executeWithGateAllowance({
    ...allowanceOptions,
    expected: {
      ...(allowanceOptions.expected || {}),
      connector_id: connectorInstanceId,
    },
    action,
    operationId,
    executeAction: (verifiedAction) => {
      const separator = verifiedAction.repository.indexOf('/');
      return octokit.actions.createWorkflowDispatch({
        owner: verifiedAction.repository.slice(0, separator),
        repo: verifiedAction.repository.slice(separator + 1),
        workflow_id: verifiedAction.workflow,
        ref: verifiedAction.ref,
        inputs: verifiedAction.workflow_inputs,
      });
    },
  });
}

export default {
  GITHUB_ACTION_PACK,
  GITHUB_OPS,
  createGithubManifest,
  guardGithubMutation,
  githubWorkflowInputsDigest,
  createGithubAllowanceConnector,
  guardGithubAllowanceMutation,
  createGithubDeploymentProtectionConnector,
  guardGithubDeploymentProtectionRule,
};
