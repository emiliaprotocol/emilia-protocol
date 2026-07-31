// SPDX-License-Identifier: Apache-2.0
//
// Passive discovery only: scanner code reads bounded configuration files,
// launches no configured server or child process, opens no network connection,
// and never unlocks a keychain.

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
const MAX_SCAN_DIRECTORIES = 2_000;
const MAX_DIRECTORY_ENTRIES = 5_000;

interface ReadResult {
  ok: boolean;
  value?: Record<string, unknown>;
  bytes?: number;
  status?: ConfigSource['status'];
  format?: string;
}

interface BoundedReadResult {
  ok: boolean;
  raw?: string;
  bytes?: number;
  status: ConfigSource['status'];
}

interface EnvDiscovery {
  files: EnvFile[];
  limitations: string[];
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

function readBoundedRegularFile(file: string, maxBytes: number): BoundedReadResult {
  let descriptor: number | null = null;
  try {
    const linkStat = fs.lstatSync(file);
    if (linkStat.isSymbolicLink()) return { ok: false, status: 'symlink' };
    if (!linkStat.isFile()) return { ok: false, status: 'unreadable' };
    if (linkStat.size > maxBytes) return { ok: false, status: 'too_large' };

    const noFollow = typeof fs.constants.O_NOFOLLOW === 'number'
      ? fs.constants.O_NOFOLLOW
      : 0;
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
    const openedStat = fs.fstatSync(descriptor);
    if (!openedStat.isFile()) return { ok: false, status: 'unreadable' };
    if (openedStat.size > maxBytes) return { ok: false, status: 'too_large' };

    const raw = fs.readFileSync(descriptor, 'utf8');
    if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
      return { ok: false, status: 'too_large' };
    }
    return {
      ok: true,
      raw,
      bytes: Buffer.byteLength(raw, 'utf8'),
      status: 'read',
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') return { ok: false, status: 'absent' };
    if (code === 'ELOOP') return { ok: false, status: 'symlink' };
    if (code === 'EACCES' || code === 'EPERM') return { ok: false, status: 'unreadable' };
    return { ok: false, status: 'unreadable' };
  } finally {
    if (descriptor !== null) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // The scan remains fail-closed even if descriptor cleanup reports an error.
      }
    }
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
  const fileResult = readBoundedRegularFile(file, MAX_CONFIG_BYTES);
  if (!fileResult.ok || fileResult.raw === undefined) {
    return { ok: false, status: fileResult.status };
  }
  try {
    const raw = fileResult.raw;
    const gate = strictJsonGate(raw);
    if (!gate.ok) return { ok: false, status: 'malformed' };
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, status: 'malformed' };
    }
    return {
      ok: true,
      value: parsed as Record<string, unknown>,
      bytes: fileResult.bytes,
    };
  } catch {
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
  const fileResult = readBoundedRegularFile(file, MAX_ENV_BYTES);
  if (!fileResult.ok || fileResult.raw === undefined) return [];
  const raw = fileResult.raw;
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

function discoverEnvFiles(cwd: string, home: string, maxDepth = 3): EnvDiscovery {
  const found: EnvFile[] = [];
  const limitations = new Set<string>([
    `environment-file search is bounded to depth ${maxDepth}, ${MAX_ENV_FILES} files, `
      + `${MAX_SCAN_DIRECTORIES} directories, and ${MAX_DIRECTORY_ENTRIES} entries per directory`,
  ]);
  const skip = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'vendor', '.venv', 'Library']);
  let directoriesVisited = 0;
  const walk = (directory: string, depth: number): void => {
    if (depth > maxDepth) return;
    if (found.length >= MAX_ENV_FILES) {
      limitations.add(`environment-file discovery reached its ${MAX_ENV_FILES}-file limit; additional files may be omitted`);
      return;
    }
    if (directoriesVisited >= MAX_SCAN_DIRECTORIES) {
      limitations.add(`environment-file discovery reached its ${MAX_SCAN_DIRECTORIES}-directory limit; additional directories may be omitted`);
      return;
    }

    let handle: fs.Dir | null = null;
    try {
      handle = fs.opendirSync(directory);
      directoriesVisited += 1;
    } catch {
      return;
    }

    try {
      let entriesVisited = 0;
      let entry: fs.Dirent | null;
      while ((entry = handle.readSync()) !== null) {
        entriesVisited += 1;
        if (entriesVisited > MAX_DIRECTORY_ENTRIES) {
          limitations.add(
            `environment-file discovery reached the ${MAX_DIRECTORY_ENTRIES}-entry limit in ${reportPath(directory, home)}; additional entries may be omitted`,
          );
          break;
        }
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          if (skip.has(entry.name) || (entry.name.startsWith('.') && entry.name !== '.config')) continue;
          walk(path.join(directory, entry.name), depth + 1);
        } else if (/^\.env(\..+)?$/.test(entry.name)) {
          if (found.length >= MAX_ENV_FILES) {
            limitations.add(`environment-file discovery reached its ${MAX_ENV_FILES}-file limit; additional files may be omitted`);
            break;
          }
          const file = path.join(directory, entry.name);
          found.push({ path: reportPath(file, home), secrets: envFileSecrets(file) });
        }
      }
    } finally {
      handle.closeSync();
    }
  };
  walk(path.resolve(cwd), 0);
  return {
    files: found.sort((left, right) => left.path.localeCompare(right.path)),
    limitations: [...limitations].sort(),
  };
}

export function envFiles(cwd: string, home: string, maxDepth = 3): EnvFile[] {
  return discoverEnvFiles(cwd, home, maxDepth).files;
}

export function discoverAuthority(options: DiscoveryOptions = {}): AuthorityInventory {
  const home = path.resolve(options.home ?? os.homedir());
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const sources: ConfigSource[] = [];
  const servers: DeclaredServer[] = [];
  const permissions: PermissionDeclaration[] = [];
  const environment = discoverEnvFiles(cwd, home, options.maxEnvDepth ?? 3);

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
    env_files: environment.files,
    limitations: environment.limitations,
  };
}
