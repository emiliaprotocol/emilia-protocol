// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Kubernetes System-of-Record adapter.
 *
 * "Install this before your agent can touch the cluster." Guards the operations
 * that take a cluster down or hand it away — namespace delete, workload delete,
 * RBAC binding, secret delete — so they never reach the API server without a
 * receipt bound to THIS namespace/resource. Client is injected (a @kubernetes/
 * client-node wrapper or compatible).
 */
import { createAdapter, manifestFromPack } from '../../adapters/_kit.js';

export const K8S_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'k8s.namespace.delete', label: 'Delete namespace', action_type: 'k8s.namespace.delete',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'k8s', tool: 'delete_namespace' },
    why: 'Deletes an entire namespace and everything in it. Quorum.',
    execution_binding: { required_fields: ['action_type', 'namespace'] },
  }),
  Object.freeze({
    id: 'k8s.workload.delete', label: 'Delete workload', action_type: 'k8s.workload.delete',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'k8s', tool: 'delete_workload' },
    why: 'Deletes a deployment/statefulset/job. Bind namespace+kind+name.',
    execution_binding: { required_fields: ['action_type', 'namespace', 'kind', 'name'] },
  }),
  Object.freeze({
    id: 'k8s.rbac.bind', label: 'RBAC binding', action_type: 'k8s.rbac.bind',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'k8s', tool: 'create_role_binding' },
    why: 'Grants cluster permissions. Privilege change → two-person rule.',
    execution_binding: { required_fields: ['action_type', 'subject', 'role', 'namespace'] },
  }),
  Object.freeze({
    id: 'k8s.secret.delete', label: 'Delete secret', action_type: 'k8s.secret.delete',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'k8s', tool: 'delete_secret' },
    why: 'Destroys a secret. Bind namespace+name.',
    execution_binding: { required_fields: ['action_type', 'namespace', 'name'] },
  }),
]);

const OPS = {
  'namespace.delete': {
    selector: { protocol: 'k8s', tool: 'delete_namespace' },
    observed: (p) => ({ action_type: 'k8s.namespace.delete', namespace: p.namespace }),
    perform: (c, p) => c.deleteNamespace({ namespace: p.namespace }),
  },
  'workload.delete': {
    selector: { protocol: 'k8s', tool: 'delete_workload' },
    observed: (p) => ({ action_type: 'k8s.workload.delete', namespace: p.namespace, kind: p.kind, name: p.name }),
    perform: (c, p) => c.deleteWorkload({ namespace: p.namespace, kind: p.kind, name: p.name }),
  },
  'rbac.bind': {
    selector: { protocol: 'k8s', tool: 'create_role_binding' },
    observed: (p) => ({ action_type: 'k8s.rbac.bind', subject: p.subject, role: p.role, namespace: p.namespace }),
    perform: (c, p) => c.createRoleBinding({ subject: p.subject, role: p.role, namespace: p.namespace }),
  },
  'secret.delete': {
    selector: { protocol: 'k8s', tool: 'delete_secret' },
    observed: (p) => ({ action_type: 'k8s.secret.delete', namespace: p.namespace, name: p.name }),
    perform: (c, p) => c.deleteSecret({ namespace: p.namespace, name: p.name }),
  },
};

const adapter = createAdapter({ system: 'k8s', ops: OPS });
export const K8S_OPS = adapter.OPS;
export function createK8sManifest(extraActions = []) { return manifestFromPack(K8S_ACTION_PACK, extraActions); }
export function guardK8sMutation(gate, client, args) { return adapter.guard(gate, client, args); }
export default { K8S_ACTION_PACK, K8S_OPS, createK8sManifest, guardK8sMutation };
