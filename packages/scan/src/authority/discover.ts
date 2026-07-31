// SPDX-License-Identifier: Apache-2.0
//
// Passive discovery only: reads bounded configuration files, launches no
// process, opens no network connection, and never unlocks a keychain.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { strictJsonGate } from '@emilia-protocol/verify/strict-json';
import {
  describeEnv,
  describeSecret,
  redactText,
  sanitizeArgs,
  sanitizeForReport,
} from './redact.js';
import type {
  AuthorityInventory,
  ConfigCandidate,
  ConfigSource,
  CredentialFile,
  DeclaredServer,
  DiscoveryOptions,
  EnvFile,
  PermissionDeclaration,
} from './types.js';

const MAX_CONFIG_BYTES = 8 * 1024 * 1024;
const MAX_ENV_BYTES = 1024 * 1024;
const MAX_ENV_FILES = 200;

interface ReadResult {
  ok: boolean;
  value?: Record<string, unknown>;
  bytes?: number;
  status?: ConfigSource['status'];
  format?: string;
}

function reportPath(value: string, home: string): string {
  const resolvedHome = path.resolve(home);
  const resolvedValue = path.resolve(value);
  if (resolvedValue === resolvedHome) return '~';
  if (resolvedValue.startsWith(`${resolvedHome}${path.sep}`)) {
    return `~${resolvedValue.slice(resolvedHome.length)}`;
  }
  return resolvedValue;
}

function exists(value: string): boolean {
  try {
    fs.statSync(value);
    return true;
  } catch {
    return false;
  }
}

function writableByCurrentProcess(value: string): boolean {
  try {
    fs.accessSync(value, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function readJson(file: string): ReadResult {
  if (path.extname(file).toLowerCase() !== '.json') {
    return {
      ok: false,
      status: 'unsupported_format',
      format: path.extname(file).slice(1) || 'unknown',
    };
  }
  try {
    const stat = fs.statSync(file);
    if (stat.size > MAX_CONFIG_BYTES) return { ok: false, status: 'too_large' };
    const raw = fs.readFileSync(file, 'utf8');
    const gate = strictJsonGate(raw);
    if (!gate.ok) return { ok: false, status: 'malformed' };
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, status: 'malformed' };
    }
    return {
      ok: true,
      value: parsed as Record<string, unknown>,
      bytes: Buffer.byteLength(raw, 'utf8'),
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') return { ok: false, status: 'absent' };
    if (code === 'EACCES' || code === 'EPERM') return { ok: false, status: 'unreadable' };
    return { ok: false, status: 'malformed' };
  }
}

export function configCandidates(options: DiscoveryOptions = {}): ConfigCandidate[] {
  const home = path.resolve(options.home ?? os.homedir());
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const support = options.applicationSupport
    ?? path.join(home, 'Library', 'Application Support');
  const user: ConfigCandidate[] = [
    { runtime: 'claude-code', scope: 'user', file: path.join(home, '.claude', 'settings.json') },
    { runtime: 'claude-code', scope: 'user', file: path.join(home, '.claude', 'settings.local.json') },
    { runtime: 'claude-code', scope: 'user', file: path.join(home, '.claude', '.mcp.json') },
    { runtime: 'claude-code', scope: 'user', file: path.join(home, '.mcp.json') },
    { runtime: 'claude-code', scope: 'user', file: path.join(home, '.claude.json') },
    { runtime: 'claude-desktop', scope: 'user', file: path.join(support, 'Claude', 'claude_desktop_config.json') },
    { runtime: 'cursor', scope: 'user', file: path.join(home, '.cursor', 'mcp.json') },
    { runtime: 'codex', scope: 'user', file: path.join(home, '.codex', 'config.toml') },
    { runtime: 'vscode', scope: 'user', file: path.join(support, 'Code', 'User', 'mcp.json') },
    { runtime: 'windsurf', scope: 'user', file: path.join(home, '.codeium', 'windsurf', 'mcp_config.json') },
  ];
  const managed = options.managedCandidates ?? [
    { runtime: 'claude-code', scope: 'managed', file: '/Library/Application Support/ClaudeCode/managed-settings.json' },
    { runtime: 'claude-code', scope: 'managed', file: '/etc/claude-code/managed-settings.json' },
  ];
  const project: ConfigCandidate[] = [];
  let directory = cwd;
  for (let depth = 0; depth < 8; depth += 1) {
    project.push(
      { runtime: 'claude-code', scope: 'project', file: path.join(directory, '.mcp.json') },
      { runtime: 'claude-code', scope: 'project', file: path.join(directory, '.claude', 'settings.json') },
      { runtime: 'claude-code', scope: 'project', file: path.join(directory, '.claude', 'settings.local.json') },
      { runtime: 'cursor', scope: 'project', file: path.join(directory, '.cursor', 'mcp.json') },
    );
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  const seen = new Set<string>();
  return [...managed, ...user, ...project].filter((candidate) => {
    const key = path.resolve(candidate.file);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function safeHost(value: string): string {
  try {
    return new URL(value).host;
  } catch {
    return '(unparseable)';
  }
}

function normalizeServers(
  parsed: Record<string, unknown>,
  home: string,
): Array<Omit<DeclaredServer, 'source' | 'runtime' | 'scope'>> {
  const out: Array<Omit<DeclaredServer, 'source' | 'runtime' | 'scope'>> = [];
  const push = (rawName: string, rawDeclaration: unknown): void => {
    if (!rawDeclaration || typeof rawDeclaration !== 'object' || Array.isArray(rawDeclaration)) return;
    const declaration = rawDeclaration as Record<string, unknown>;
    const hasTransport = ['command', 'url', 'type', 'args'].some((key) => key in declaration);
    if (!hasTransport) return;
    out.push({
      name: String(sanitizeForReport(rawName, 'server_name')),
      transport: typeof declaration.url === 'string'
        ? String(declaration.type ?? 'http')
        : String(declaration.type ?? 'stdio'),
      command: typeof declaration.command === 'string'
        ? String(sanitizeForReport(declaration.command, 'command'))
        : null,
      args: sanitizeArgs(declaration.args),
      url_host: typeof declaration.url === 'string' ? safeHost(declaration.url) : null,
      disabled: declaration.disabled === true || declaration.enabled === false,
      env: describeEnv(declaration.env),
      header_secrets: describeEnv(declaration.headers),
    });
  };

  const mcpServers = parsed.mcpServers;
  if (mcpServers && typeof mcpServers === 'object' && !Array.isArray(mcpServers)) {
    for (const [name, declaration] of Object.entries(mcpServers)) push(name, declaration);
  }
  const reserved = new Set([
    'mcpServers', 'permissions', 'enabledPlugins', 'projects', 'hooks',
    'extraKnownMarketplaces', 'oauthAccount', 'restrictions', 'compliance_taints',
  ]);
  for (const [name, declaration] of Object.entries(parsed)) {
    if (!reserved.has(name)) push(name, declaration);
  }

  const projects = parsed.projects;
  if (projects && typeof projects === 'object' && !Array.isArray(projects)) {
    for (const [projectPath, rawProject] of Object.entries(projects)) {
      if (!rawProject || typeof rawProject !== 'object' || Array.isArray(rawProject)) continue;
      const project = rawProject as Record<string, unknown>;
      const servers = project.mcpServers;
      if (!servers || typeof servers !== 'object' || Array.isArray(servers)) continue;
      for (const [name, declaration] of Object.entries(servers)) {
        const before = out.length;
        push(name, declaration);
        for (let index = before; index < out.length; index += 1) {
          out[index].project_scope = reportPath(projectPath, home);
        }
      }
    }
  }
  return out;
}

function normalizePermissions(
  parsed: Record<string, unknown>,
  home: string,
): Omit<PermissionDeclaration, 'source' | 'scope' | 'writable_by_current_process'> | null {
  const raw = parsed.permissions;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const permissions = raw as Record<string, unknown>;
  const list = (key: string): string[] => (
    Array.isArray(permissions[key])
      ? (permissions[key] as unknown[]).map((rule) => redactText(String(rule)))
      : []
  );
  return {
    allow: list('allow'),
    deny: list('deny'),
    ask: list('ask'),
    default_mode: typeof permissions.defaultMode === 'string'
      ? String(sanitizeForReport(permissions.defaultMode, 'default_mode'))
      : null,
    additional_directories: Array.isArray(permissions.additionalDirectories)
      ? permissions.additionalDirectories.map((entry) => reportPath(redactText(String(entry)), home))
      : [],
  };
}

export function credentialFiles(home = os.homedir()): CredentialFile[] {
  const candidates: Array<[string, string]> = [
    ['aws_credentials', path.join(home, '.aws', 'credentials')],
    ['aws_config', path.join(home, '.aws', 'config')],
    ['gh_hosts', path.join(home, '.config', 'gh', 'hosts.yml')],
    ['npmrc', path.join(home, '.npmrc')],
    ['docker_config', path.join(home, '.docker', 'config.json')],
    ['kube_config', path.join(home, '.kube', 'config')],
    ['gcloud_credentials', path.join(home, '.config', 'gcloud', 'application_default_credentials.json')],
    ['stripe_config', path.join(home, '.config', 'stripe', 'config.toml')],
    ['pypirc', path.join(home, '.pypirc')],
    ['netrc', path.join(home, '.netrc')],
    ['ssh_dir', path.join(home, '.ssh')],
  ];
  return candidates
    .filter(([, file]) => exists(file))
    .map(([kind, file]) => {
      let size: number | null = null;
      try {
        size = fs.statSync(file).size;
      } catch {
        // Presence is the only signal.
      }
      return { kind, path: reportPath(file, home), size };
    });
}

function envFileSecrets(file: string): EnvFile['secrets'] {
  let raw = '';
  try {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink() || stat.size > MAX_ENV_BYTES) return [];
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  const out: EnvFile['secrets'] = [];
  for (const line of raw.split('\n')) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const value = match[2].trim().replace(/^["']|["']$/g, '');
    const descriptor = describeSecret(match[1], value);
    if (descriptor.secret) {
      out.push({
        key: descriptor.key,
        class: descriptor.class,
        scheme: descriptor.scheme,
        length: descriptor.length,
      });
    }
  }
  return out;
}

export function envFiles(cwd: string, home: string, maxDepth = 3): EnvFile[] {
  const found: EnvFile[] = [];
  const skip = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'vendor', '.venv', 'Library']);
  const walk = (directory: string, depth: number): void => {
    if (depth > maxDepth || found.length >= MAX_ENV_FILES) return;
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (skip.has(entry.name) || (entry.name.startsWith('.') && entry.name !== '.config')) continue;
        walk(path.join(directory, entry.name), depth + 1);
      } else if (/^\.env(\..+)?$/.test(entry.name)) {
        const file = path.join(directory, entry.name);
        found.push({ path: reportPath(file, home), secrets: envFileSecrets(file) });
      }
    }
  };
  walk(path.resolve(cwd), 0);
  return found;
}

export function discoverAuthority(options: DiscoveryOptions = {}): AuthorityInventory {
  const home = path.resolve(options.home ?? os.homedir());
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const sources: ConfigSource[] = [];
  const servers: DeclaredServer[] = [];
  const permissions: PermissionDeclaration[] = [];

  for (const candidate of configCandidates({ ...options, home, cwd })) {
    const result = readJson(candidate.file);
    if (!result.ok || !result.value) {
      sources.push({
        ...candidate,
        file: reportPath(candidate.file, home),
        status: result.status ?? 'unreadable',
        ...(result.format ? { format: result.format } : {}),
      });
      continue;
    }
    const source = reportPath(candidate.file, home);
    sources.push({
      ...candidate,
      file: source,
      status: 'read',
      bytes: result.bytes,
      top_level_keys: Object.keys(result.value).slice(0, 40),
    });
    for (const server of normalizeServers(result.value, home)) {
      servers.push({
        ...server,
        source,
        runtime: candidate.runtime,
        scope: candidate.scope,
      });
    }
    const declaration = normalizePermissions(result.value, home);
    if (declaration) {
      permissions.push({
        source,
        scope: candidate.scope,
        writable_by_current_process: writableByCurrentProcess(candidate.file),
        ...declaration,
      });
    }
  }

  return {
    sources,
    servers,
    permissions,
    credential_files: credentialFiles(home),
    env_files: envFiles(cwd, home, options.maxEnvDepth ?? 3),
  };
}
