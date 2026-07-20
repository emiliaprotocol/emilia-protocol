// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Google Cloud System-of-Record adapter.
 *
 * "Install this before your agent can change cloud permissions or delete a
 * project." Guards the high-blast-radius GCP operations — IAM policy set,
 * service-account key create, project delete, storage bucket delete — so they
 * never reach GCP without a receipt bound to THIS resource/member/role. Client
 * is injected (the @google-cloud SDKs or a thin wrapper).
 */
import { createAdapter, manifestFromPack } from './_kit.js';
export const GCP_ACTION_PACK = Object.freeze([
    Object.freeze({
        id: 'gcp.iam.set_policy', label: 'GCP IAM set policy', action_type: 'gcp.iam.set_policy',
        risk: 'critical', receipt_required: true, assurance_class: 'quorum',
        match: { protocol: 'gcp', tool: 'set_iam_policy' },
        why: 'Grants cloud permissions. Bind resource+member+role; quorum.',
        execution_binding: { required_fields: ['action_type', 'resource', 'member', 'role'] },
    }),
    Object.freeze({
        id: 'gcp.sa_key.create', label: 'GCP service-account key create', action_type: 'gcp.sa_key.create',
        risk: 'critical', receipt_required: true, assurance_class: 'class_a',
        match: { protocol: 'gcp', tool: 'create_service_account_key' },
        why: 'Mints long-lived cloud credentials. Bind the service account.',
        execution_binding: { required_fields: ['action_type', 'service_account'] },
    }),
    Object.freeze({
        id: 'gcp.project.delete', label: 'GCP project delete', action_type: 'gcp.project.delete',
        risk: 'critical', receipt_required: true, assurance_class: 'quorum',
        match: { protocol: 'gcp', tool: 'delete_project' },
        why: 'Deletes an entire project. Quorum.',
        execution_binding: { required_fields: ['action_type', 'project'] },
    }),
    Object.freeze({
        id: 'gcp.storage.bucket_delete', label: 'GCP bucket delete', action_type: 'gcp.storage.bucket_delete',
        risk: 'high', receipt_required: true, assurance_class: 'class_a',
        match: { protocol: 'gcp', tool: 'delete_bucket' },
        why: 'Destroys a storage bucket and its objects. Bind the bucket.',
        execution_binding: { required_fields: ['action_type', 'bucket'] },
    }),
]);
const OPS = {
    'iam.set_policy': {
        selector: { protocol: 'gcp', tool: 'set_iam_policy' },
        observed: (p) => ({ action_type: 'gcp.iam.set_policy', resource: p.resource, member: p.member, role: p.role }),
        perform: (c, p) => c.setIamPolicy({ resource: p.resource, member: p.member, role: p.role }),
    },
    'sa_key.create': {
        selector: { protocol: 'gcp', tool: 'create_service_account_key' },
        observed: (p) => ({ action_type: 'gcp.sa_key.create', service_account: p.service_account }),
        perform: (c, p) => c.createServiceAccountKey({ service_account: p.service_account }),
    },
    'project.delete': {
        selector: { protocol: 'gcp', tool: 'delete_project' },
        observed: (p) => ({ action_type: 'gcp.project.delete', project: p.project }),
        perform: (c, p) => c.deleteProject({ project: p.project }),
    },
    'storage.bucket_delete': {
        selector: { protocol: 'gcp', tool: 'delete_bucket' },
        observed: (p) => ({ action_type: 'gcp.storage.bucket_delete', bucket: p.bucket }),
        perform: (c, p) => c.deleteBucket({ bucket: p.bucket }),
    },
};
const adapter = createAdapter({ system: 'gcp', ops: OPS });
export const GCP_OPS = adapter.OPS;
export function createGcpManifest(extraActions = []) { return manifestFromPack(GCP_ACTION_PACK, extraActions); }
export function guardGcpMutation(gate, client, args) { return adapter.guard(gate, client, args); }
export default { GCP_ACTION_PACK, GCP_OPS, createGcpManifest, guardGcpMutation };
//# sourceMappingURL=gcp.js.map