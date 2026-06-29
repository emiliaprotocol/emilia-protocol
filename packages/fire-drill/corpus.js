// SPDX-License-Identifier: Apache-2.0
/**
 * A representative sample of common MCP server tool surfaces, modeled on the
 * publicly-documented tools of widely-used servers. This is a SAMPLE for the
 * Report's computed figure — not the whole ecosystem. Point `corpus.mjs` at a
 * directory of real manifests to compute the index over a larger corpus.
 *
 * Each entry is { name, manifest } where manifest is an MCP-style { tools }.
 */
export const REPRESENTATIVE_CORPUS = [
  {
    name: 'filesystem',
    manifest: { tools: [{ name: 'read_file' }, { name: 'write_file' }, { name: 'list_directory' }, { name: 'delete_file', description: 'delete a file from disk' }, { name: 'move_file' }] },
  },
  {
    name: 'github',
    manifest: { tools: [{ name: 'get_repo' }, { name: 'create_issue' }, { name: 'delete_repository', description: 'delete a repo' }, { name: 'add_collaborator', description: 'grant access' }] },
  },
  {
    name: 'postgres',
    manifest: { tools: [{ name: 'query', description: 'run a read query' }, { name: 'execute_sql', description: 'run arbitrary SQL including DELETE and DROP' }] },
  },
  {
    name: 'stripe',
    manifest: { tools: [{ name: 'list_charges' }, { name: 'create_payout', description: 'pay out funds' }, { name: 'refund_charge', description: 'refund a charge' }] },
  },
  {
    name: 'shopify',
    manifest: { tools: [{ name: 'get_product' }, { name: 'delete_product', description: 'remove a product' }, { name: 'cancel_order', description: 'cancel a customer order' }] },
  },
  {
    name: 'slack',
    manifest: { tools: [{ name: 'post_message' }, { name: 'list_channels' }, { name: 'delete_message', description: 'delete a message' }] },
  },
  {
    name: 'google-drive',
    manifest: { tools: [{ name: 'search_files' }, { name: 'export_file', description: 'export and download a document' }, { name: 'delete_file' }] },
  },
  {
    name: 'aws',
    manifest: { tools: [{ name: 'describe_instances' }, { name: 'attach_user_policy', description: 'grant IAM permissions' }, { name: 'delete_user' }] },
  },
  {
    name: 'notion',
    manifest: { tools: [{ name: 'search' }, { name: 'create_page' }, { name: 'delete_block', description: 'delete content' }] },
  },
  {
    name: 'weather (read-only)',
    manifest: { tools: [{ name: 'get_forecast' }, { name: 'get_alerts' }, { name: 'list_stations' }] },
  },
];

export default { REPRESENTATIVE_CORPUS };
