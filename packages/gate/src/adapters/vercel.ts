// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Vercel System-of-Record adapter.
 * Guards promote-to-production, project delete, and env/secret changes so they
 * never reach Vercel without a receipt bound to THIS project. Client injected
 * (the Vercel REST client or a thin wrapper).
 */
import { createAdapter, manifestFromPack, hashCanonical } from './_kit.js';

export const SECRET_VALUE_BINDING_VERSION = 'EP-VERCEL-SECRET-VALUE-v1';

/** Digest an exact secret value for receipt binding; callers must never log it. */
export function secretValueDigest(value) {
  return hashCanonical({
    version: SECRET_VALUE_BINDING_VERSION,
    value,
  });
}

export const VERCEL_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'vercel.deploy.promote', label: 'Promote to production', action_type: 'vercel.deploy.promote',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'vercel', tool: 'promote_deployment' },
    why: 'Changes live production. Quorum for the prod cutover.',
    execution_binding: { required_fields: ['action_type', 'project', 'deployment_id'] },
  }),
  Object.freeze({
    id: 'vercel.project.delete', label: 'Delete project', action_type: 'vercel.project.delete',
    risk: 'critical', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'vercel', tool: 'delete_project' },
    why: 'Destroys a project and its deployments. Bind the project.',
    execution_binding: { required_fields: ['action_type', 'project'] },
  }),
  Object.freeze({
    id: 'vercel.env.set', label: 'Set env / secret', action_type: 'vercel.env.set',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'vercel', tool: 'upsert_env' },
    why: 'Changes production secrets/config. Bind project+key+target.',
    execution_binding: {
      required_fields: [
        'action_type', 'project', 'key', 'target', 'secret_value_digest', 'secret_value_version',
      ],
    },
  }),
]);

const OPS = {
  'deploy.promote': {
    selector: { protocol: 'vercel', tool: 'promote_deployment' },
    observed: (p) => ({ action_type: 'vercel.deploy.promote', project: p.project, deployment_id: p.deployment_id }),
    perform: (c, p) => c.promoteDeployment({ project: p.project, deploymentId: p.deployment_id }),
  },
  'project.delete': {
    selector: { protocol: 'vercel', tool: 'delete_project' },
    observed: (p) => ({ action_type: 'vercel.project.delete', project: p.project }),
    perform: (c, p) => c.deleteProject({ project: p.project }),
  },
  'env.set': {
    selector: { protocol: 'vercel', tool: 'upsert_env' },
    observed: (p) => ({
      action_type: 'vercel.env.set',
      project: p.project,
      key: p.key,
      target: p.target,
      secret_value_digest: secretValueDigest(p.value),
      secret_value_version: SECRET_VALUE_BINDING_VERSION,
    }),
    actuator: (p, observed) => ({ ...observed, value: p.value }),
    perform: (c, p) => c.upsertEnv({ project: p.project, key: p.key, value: p.value, target: p.target }),
  },
};

const adapter = createAdapter({ system: 'vercel', ops: OPS });
export const VERCEL_OPS = adapter.OPS;
export function createVercelManifest(extra = []) { return manifestFromPack(VERCEL_ACTION_PACK, extra); }
export function guardVercelMutation(gate, client, args) { return adapter.guard(gate, client, args); }
export default {
  VERCEL_ACTION_PACK,
  VERCEL_OPS,
  SECRET_VALUE_BINDING_VERSION,
  secretValueDigest,
  createVercelManifest,
  guardVercelMutation,
};
