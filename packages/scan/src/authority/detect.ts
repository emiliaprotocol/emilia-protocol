// SPDX-License-Identifier: Apache-2.0

import type { AuthorityInventory, AuthoritySignal } from './types.js';

const SHELL_SERVER = /(shell|exec|command|bash|osascript|terminal|process|spawn|run_)/i;
const EGRESS_SERVER = /(fetch|http|browse|scrape|crawl|request|curl|web)/i;
const INFRA_SERVER = /(apply_migration|execute_sql|deploy|delete_branch|pause_project|restore|merge_branch|reset_branch|create_project|delete_project)/i;

function signal(
  id: string,
  severity: AuthoritySignal['severity'],
  title: string,
  observed: unknown,
  why: string,
  doesNotProve: string,
): AuthoritySignal {
  return {
    id,
    severity,
    title,
    observed,
    why,
    does_not_prove: doesNotProve,
  };
}

export function detectAuthoritySignals(inventory: AuthorityInventory): AuthoritySignal[] {
  const out: AuthoritySignal[] = [];
  const active = inventory.servers.filter((server) => !server.disabled);

  const credentialServers = active.filter((server) => (
    server.env.some((entry) => entry.secret)
    || server.header_secrets.some((entry) => entry.secret)
  ));
  if (credentialServers.length) {
    out.push(signal(
      'CRED-01',
      'high',
      'Credentials are supplied to MCP servers from configuration',
      credentialServers.map((server) => ({
        server: server.name,
        source: server.source,
        secret_keys: [...server.env, ...server.header_secrets]
          .filter((entry) => entry.secret)
          .map((entry) => ({ key: entry.key, class: entry.class })),
      })),
      'A credential in configuration may let a process act within that credential\'s valid scope, subject to provider-side controls.',
      'That the credential is valid, in scope, unrotated, or sufficient for any particular operation.',
    ));
  }

  if (inventory.credential_files.length) {
    out.push(signal(
      'CRED-02',
      'high',
      'Ambient credential files are present in the home directory',
      inventory.credential_files,
      'An agent with the same file-read authority may be able to reach these files without that access appearing as a dedicated tool call.',
      'That an agent can read them, has read them, or that credentials inside are current.',
    ));
  }

  const secretEnvFiles = inventory.env_files.filter((file) => file.secrets.length);
  if (secretEnvFiles.length) {
    out.push(signal(
      'CRED-03',
      'medium',
      'Secret-bearing environment files are present in the scanned project scope',
      secretEnvFiles.map((file) => ({
        path: file.path,
        keys: file.secrets.map((entry) => entry.key),
      })),
      'Project environment files often sit within the directory an agent is asked to inspect.',
      'That any value is live, grants production authority, or was read by an agent.',
    ));
  }

  const shellServers = active.filter((server) => (
    SHELL_SERVER.test(server.name)
    || SHELL_SERVER.test(String(server.command ?? ''))
    || server.args.some((argument) => SHELL_SERVER.test(argument))
  ));
  if (shellServers.length) {
    out.push(signal(
      'SHELL-01',
      'critical',
      'Configured MCP servers appear shell-capable',
      shellServers.map((server) => ({
        server: server.name,
        transport: server.transport,
        source: server.source,
      })),
      'A shell-capable path may reach authority outside narrowly declared tool surfaces.',
      'The actual server tool surface, exploitability, or that a shell action was invoked.',
    ));
  }

  const registryLaunches = active.filter((server) => (
    /^(npx|uvx|pipx|bunx)$/.test(String(server.command ?? ''))
  ));
  if (registryLaunches.length) {
    out.push(signal(
      'EXEC-01',
      'medium',
      'MCP servers are launched through package-runner commands',
      registryLaunches.map((server) => ({
        server: server.name,
        command: server.command,
        package: server.args.find((argument) => !argument.startsWith('-')) ?? null,
      })),
      'Unpinned package-runner configuration can execute code that changes as registry contents change.',
      'That a package is unpinned, malicious, or fetched on every launch.',
    ));
  }

  const networkServers = active.filter((server) => (
    server.transport !== 'stdio' || EGRESS_SERVER.test(server.name)
  ));
  if (networkServers.length) {
    out.push(signal(
      'EGRESS-01',
      'medium',
      'Network-reaching server configuration is present',
      networkServers.map((server) => ({
        server: server.name,
        transport: server.transport,
        host: server.url_host,
      })),
      'A configured outbound path can turn local access into communication with another system.',
      'That data left the machine, the endpoint is untrusted, or the configured path is reachable now.',
    ));
  }

  const infrastructureServers = active.filter((server) => (
    INFRA_SERVER.test(server.name)
    || /supabase|vercel|aws|gcp|kube|terraform|stripe/i.test(server.name)
  ));
  if (infrastructureServers.length) {
    out.push(signal(
      'INFRA-01',
      'critical',
      'Configured servers appear capable of infrastructure or financial operations',
      infrastructureServers.map((server) => ({
        server: server.name,
        transport: server.transport,
        source: server.source,
      })),
      'These integrations may expose consequential operations without passing through a shell-specific control.',
      'Which project, tenant, environment, account, or operation is reachable.',
    ));
  }

  const writablePermissionFiles = inventory.permissions
    .filter((permission) => permission.writable_by_current_process)
    .map((permission) => permission.source);
  if (writablePermissionFiles.length) {
    out.push(signal(
      'BYPASS-01',
      'high',
      'Agent permission files are writable by the current process',
      writablePermissionFiles,
      'An agent running with the same operating-system identity may be able to rewrite a control stored in these files.',
      'That an agent runs with the same identity, can reach these paths, or modified them.',
    ));
  }

  const permissionFiles = inventory.permissions.map((permission) => permission.source);
  const totalAllow = inventory.permissions.reduce((count, permission) => count + permission.allow.length, 0);
  const totalDeny = inventory.permissions.reduce((count, permission) => count + permission.deny.length, 0);
  if (totalAllow > 0 && totalDeny === 0) {
    out.push(signal(
      'BYPASS-02',
      'medium',
      'Permission declarations contain allows and no explicit denials',
      { allow_rules: totalAllow, deny_rules: 0, sources: permissionFiles },
      'An allow-only declaration expands unattended execution without documenting an explicit local denial.',
      'That the allows are inappropriate or that another policy layer does not deny the same operation.',
    ));
  }

  const wildcardRules: Array<{ source: string; rule: string }> = [];
  for (const permission of inventory.permissions) {
    for (const rule of permission.allow) {
      if (/^Bash\(.*:\*\)$/.test(rule)) wildcardRules.push({ source: permission.source, rule });
    }
  }
  if (wildcardRules.length) {
    out.push(signal(
      'WILDCARD-01',
      'medium',
      'Shell permissions are declared by prefix wildcard',
      wildcardRules.slice(0, 25),
      'A prefix grant can admit arguments beyond the example that motivated the rule.',
      'That any particular expansion is dangerous or that the rule is effective at runtime.',
    ));
  }

  return out;
}

export function severityRank(severity: AuthoritySignal['severity']): number {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity];
}
