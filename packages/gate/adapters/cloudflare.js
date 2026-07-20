// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Cloudflare System-of-Record adapter.
 * Guards DNS record delete, zone delete, and WAF/firewall disable so they never
 * reach Cloudflare without a receipt bound to THIS zone. Client injected.
 */
import { createAdapter, manifestFromPack } from './_kit.js';

/**
 * @typedef {object} CloudflareClient
 * @property {(input: {zone: string, recordId: string}) => any} deleteDnsRecord
 * @property {(input: {zone: string}) => any} deleteZone
 * @property {(input: {zone: string, ruleId: string, enabled: boolean}) => any} setFirewallRule
 */

export const CLOUDFLARE_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'cloudflare.dns.delete', label: 'Delete DNS record', action_type: 'cloudflare.dns.delete',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'cloudflare', tool: 'delete_dns_record' },
    why: 'Removing DNS can take a service offline or enable takeover. Bind zone+record.',
    execution_binding: { required_fields: ['action_type', 'zone', 'record_id'] },
  }),
  Object.freeze({
    id: 'cloudflare.zone.delete', label: 'Delete zone', action_type: 'cloudflare.zone.delete',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'cloudflare', tool: 'delete_zone' },
    why: 'Deletes an entire zone. Quorum.',
    execution_binding: { required_fields: ['action_type', 'zone'] },
  }),
  Object.freeze({
    id: 'cloudflare.firewall.disable', label: 'Disable firewall rule', action_type: 'cloudflare.firewall.disable',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'cloudflare', tool: 'set_firewall_rule' },
    why: 'Disabling WAF/firewall opens the perimeter. Quorum + bind zone+rule.',
    execution_binding: { required_fields: ['action_type', 'zone', 'rule_id'] },
  }),
]);

const OPS = {
  'dns.delete': {
    selector: { protocol: 'cloudflare', tool: 'delete_dns_record' },
    /** @param {{zone: string, record_id: string}} p */
    observed: (p) => ({ action_type: 'cloudflare.dns.delete', zone: p.zone, record_id: p.record_id }),
    /**
     * @param {CloudflareClient} c
     * @param {{zone: string, record_id: string}} p
     */
    perform: (c, p) => c.deleteDnsRecord({ zone: p.zone, recordId: p.record_id }),
  },
  'zone.delete': {
    selector: { protocol: 'cloudflare', tool: 'delete_zone' },
    /** @param {{zone: string}} p */
    observed: (p) => ({ action_type: 'cloudflare.zone.delete', zone: p.zone }),
    /**
     * @param {CloudflareClient} c
     * @param {{zone: string}} p
     */
    perform: (c, p) => c.deleteZone({ zone: p.zone }),
  },
  'firewall.disable': {
    selector: { protocol: 'cloudflare', tool: 'set_firewall_rule' },
    /** @param {{zone: string, rule_id: string}} p */
    observed: (p) => ({ action_type: 'cloudflare.firewall.disable', zone: p.zone, rule_id: p.rule_id }),
    /**
     * @param {CloudflareClient} c
     * @param {{zone: string, rule_id: string}} p
     */
    perform: (c, p) => c.setFirewallRule({ zone: p.zone, ruleId: p.rule_id, enabled: false }),
  },
};

const adapter = createAdapter({ system: 'cloudflare', ops: OPS });
export const CLOUDFLARE_OPS = adapter.OPS;
/** @param {object[]} extra */
export function createCloudflareManifest(extra = []) { return manifestFromPack(CLOUDFLARE_ACTION_PACK, extra); }
export function guardCloudflareMutation(gate, client, args) { return adapter.guard(gate, client, args); }
export default { CLOUDFLARE_ACTION_PACK, CLOUDFLARE_OPS, createCloudflareManifest, guardCloudflareMutation };
