// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Terraform System-of-Record adapter.
 *
 * "Install this before your agent can destroy infrastructure." Guards the
 * irreversible Terraform operations — destroy, state rm, workspace delete — so
 * they never run without a receipt bound to THIS workspace/plan. The destroy
 * plan is bound by hash, so an approved small destroy cannot be swapped for a
 * full teardown. Runner is injected (a `terraform`/`tofu` CLI wrapper or Cloud
 * API client).
 */
import { createAdapter, manifestFromPack } from '../../adapters/_kit.js';

export const TERRAFORM_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'terraform.apply.destroy', label: 'Terraform destroy', action_type: 'terraform.apply.destroy',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'terraform', tool: 'destroy' },
    why: 'Tears down real infrastructure. Bind the workspace + plan hash; quorum.',
    execution_binding: { required_fields: ['action_type', 'workspace', 'plan_hash'] },
  }),
  Object.freeze({
    id: 'terraform.state.rm', label: 'Terraform state rm', action_type: 'terraform.state.rm',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'terraform', tool: 'state_rm' },
    why: 'Detaches a resource from state (orphans real infra). Bind workspace+address.',
    execution_binding: { required_fields: ['action_type', 'workspace', 'address'] },
  }),
  Object.freeze({
    id: 'terraform.workspace.delete', label: 'Terraform workspace delete', action_type: 'terraform.workspace.delete',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'terraform', tool: 'workspace_delete' },
    why: 'Deletes a workspace and its state. Bind the workspace.',
    execution_binding: { required_fields: ['action_type', 'workspace'] },
  }),
]);

const OPS = {
  'apply.destroy': {
    selector: { protocol: 'terraform', tool: 'destroy' },
    observed: (p) => ({ action_type: 'terraform.apply.destroy', workspace: p.workspace, plan_hash: p.plan_hash }),
    perform: (r, p) => r.destroy({ workspace: p.workspace, plan_hash: p.plan_hash }),
  },
  'state.rm': {
    selector: { protocol: 'terraform', tool: 'state_rm' },
    observed: (p) => ({ action_type: 'terraform.state.rm', workspace: p.workspace, address: p.address }),
    perform: (r, p) => r.stateRm({ workspace: p.workspace, address: p.address }),
  },
  'workspace.delete': {
    selector: { protocol: 'terraform', tool: 'workspace_delete' },
    observed: (p) => ({ action_type: 'terraform.workspace.delete', workspace: p.workspace }),
    perform: (r, p) => r.workspaceDelete({ workspace: p.workspace }),
  },
};

const adapter = createAdapter({ system: 'terraform', ops: OPS });
export const TERRAFORM_OPS = adapter.OPS;
export function createTerraformManifest(extraActions = []) { return manifestFromPack(TERRAFORM_ACTION_PACK, extraActions); }
export function guardTerraformMutation(gate, runner, args) { return adapter.guard(gate, runner, args); }
export default { TERRAFORM_ACTION_PACK, TERRAFORM_OPS, createTerraformManifest, guardTerraformMutation };
