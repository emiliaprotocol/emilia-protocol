// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Salesforce System-of-Record adapter.
 * Guards bulk record delete, data export, and permission-set assignment so they
 * never reach Salesforce without a receipt bound to THIS object. Client injected.
 */
import { createAdapter, manifestFromPack, hashCanonical } from '../../adapters/_kit.js';

export const SALESFORCE_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'salesforce.records.bulk_delete', label: 'Bulk delete records', action_type: 'salesforce.records.bulk_delete',
    risk: 'critical', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'salesforce', tool: 'bulk_delete' },
    why: 'Mass-destroys CRM records. Bind object + the exact SOQL.',
    execution_binding: { required_fields: ['action_type', 'object', 'soql_hash'] },
  }),
  Object.freeze({
    id: 'salesforce.data.export', label: 'Bulk data export', action_type: 'salesforce.data.export',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'salesforce', tool: 'export' },
    why: 'Exfiltrates CRM data. Bind object + recipient.',
    execution_binding: { required_fields: ['action_type', 'object', 'recipient'] },
  }),
  Object.freeze({
    id: 'salesforce.permission_set.assign', label: 'Assign permission set', action_type: 'salesforce.permission_set.assign',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'salesforce', tool: 'assign_permission_set' },
    why: 'Grants privileges. Quorum + bind user + permission set.',
    execution_binding: { required_fields: ['action_type', 'user', 'permission_set'] },
  }),
]);

const OPS = {
  'records.bulk_delete': {
    selector: { protocol: 'salesforce', tool: 'bulk_delete' },
    observed: (p) => ({ action_type: 'salesforce.records.bulk_delete', object: p.object, soql_hash: hashCanonical(String(p.soql || '').trim()) }),
    actuator: (p, observed) => ({ ...observed, soql: p.soql }),
    perform: (c, p) => c.bulkDelete({ object: p.object, soql: p.soql }),
  },
  'data.export': {
    selector: { protocol: 'salesforce', tool: 'export' },
    observed: (p) => ({ action_type: 'salesforce.data.export', object: p.object, recipient: p.recipient }),
    perform: (c, p) => c.export({ object: p.object, recipient: p.recipient }),
  },
  'permission_set.assign': {
    selector: { protocol: 'salesforce', tool: 'assign_permission_set' },
    observed: (p) => ({ action_type: 'salesforce.permission_set.assign', user: p.user, permission_set: p.permission_set }),
    perform: (c, p) => c.assignPermissionSet({ user: p.user, permissionSet: p.permission_set }),
  },
};

const adapter = createAdapter({ system: 'salesforce', ops: OPS });
export const SALESFORCE_OPS = adapter.OPS;
export function createSalesforceManifest(extra = []) { return manifestFromPack(SALESFORCE_ACTION_PACK, extra); }
export function guardSalesforceMutation(gate, client, args) { return adapter.guard(gate, client, args); }
export default { SALESFORCE_ACTION_PACK, SALESFORCE_OPS, createSalesforceManifest, guardSalesforceMutation };
