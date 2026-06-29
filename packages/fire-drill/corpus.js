// SPDX-License-Identifier: Apache-2.0
/**
 * A representative sample of common MCP server tool surfaces, modeled on the
 * publicly-documented tools of widely-used open-source servers. Each entry
 * links to the real repository (a legitimate backlink) and carries a slug for
 * its public result page. This is a STATIC assessment of the documented tool
 * surface — not a live scan of a specific deployment and not a vulnerability
 * claim. Point `corpus.mjs <dir>` at real manifests to compute over more.
 *
 * Each entry: { slug, name, repo, manifest } where manifest is MCP-style { tools }.
 */
export const REPRESENTATIVE_CORPUS = [
  {
    slug: 'filesystem', name: 'Filesystem (reference)', repo: 'https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem',
    manifest: { tools: [{ name: 'read_file' }, { name: 'write_file' }, { name: 'list_directory' }, { name: 'delete_file', description: 'delete a file from disk' }, { name: 'move_file' }] },
  },
  {
    slug: 'github', name: 'GitHub', repo: 'https://github.com/github/github-mcp-server',
    manifest: { tools: [{ name: 'get_repo' }, { name: 'create_issue' }, { name: 'delete_repository', description: 'delete a repo' }, { name: 'add_collaborator', description: 'grant repo access' }] },
  },
  {
    slug: 'postgres', name: 'Postgres (reference)', repo: 'https://github.com/modelcontextprotocol/servers/tree/main/src/postgres',
    manifest: { tools: [{ name: 'query', description: 'run a read query' }, { name: 'execute_sql', description: 'run arbitrary SQL including DELETE and DROP' }] },
  },
  {
    slug: 'stripe', name: 'Stripe Agent Toolkit', repo: 'https://github.com/stripe/agent-toolkit',
    manifest: { tools: [{ name: 'list_charges' }, { name: 'create_payout', description: 'pay out funds' }, { name: 'create_refund', description: 'refund a charge' }] },
  },
  {
    slug: 'aws', name: 'AWS MCP', repo: 'https://github.com/awslabs/mcp',
    manifest: { tools: [{ name: 'describe_instances' }, { name: 'attach_user_policy', description: 'grant IAM permissions' }, { name: 'delete_user' }] },
  },
  {
    slug: 'slack', name: 'Slack (reference)', repo: 'https://github.com/modelcontextprotocol/servers/tree/main/src/slack',
    manifest: { tools: [{ name: 'post_message' }, { name: 'list_channels' }, { name: 'delete_message', description: 'delete a message' }] },
  },
  {
    slug: 'google-drive', name: 'Google Drive (reference)', repo: 'https://github.com/modelcontextprotocol/servers/tree/main/src/gdrive',
    manifest: { tools: [{ name: 'search_files' }, { name: 'export_file', description: 'export and download a document' }, { name: 'delete_file' }] },
  },
  {
    slug: 'notion', name: 'Notion', repo: 'https://github.com/makenotion/notion-mcp-server',
    manifest: { tools: [{ name: 'search' }, { name: 'create_page' }, { name: 'delete_block', description: 'delete content' }] },
  },
  {
    slug: 'cloudflare', name: 'Cloudflare', repo: 'https://github.com/cloudflare/mcp-server-cloudflare',
    manifest: { tools: [{ name: 'list_zones' }, { name: 'delete_dns_record', description: 'remove a DNS record' }, { name: 'purge_cache' }] },
  },
  {
    slug: 'weather', name: 'Weather (read-only reference)', repo: 'https://github.com/modelcontextprotocol/servers',
    manifest: { tools: [{ name: 'get_forecast' }, { name: 'get_alerts' }, { name: 'list_stations' }] },
  },
];

export default { REPRESENTATIVE_CORPUS };
