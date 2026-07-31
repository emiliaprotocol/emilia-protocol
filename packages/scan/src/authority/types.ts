// SPDX-License-Identifier: Apache-2.0

export interface SecretDescriptor {
  secret: boolean;
  class: string | null;
  key: string;
  length: number;
  prefix_class: string | null;
  evidence: 'key_name' | 'value_shape' | 'entropy' | null;
  scheme: string | null;
}

export interface ConfigCandidate {
  runtime: string;
  scope: 'managed' | 'user' | 'project';
  file: string;
}

export interface ConfigSource extends ConfigCandidate {
  status: 'absent' | 'read' | 'unreadable' | 'malformed' | 'unsupported_format' | 'too_large';
  bytes?: number;
  format?: string;
  top_level_keys?: string[];
}

export interface DeclaredServer {
  name: string;
  transport: string;
  command: string | null;
  args: string[];
  url_host: string | null;
  disabled: boolean;
  env: SecretDescriptor[];
  header_secrets: SecretDescriptor[];
  project_scope?: string;
  source: string;
  runtime: string;
  scope: ConfigCandidate['scope'];
}

export interface PermissionDeclaration {
  source: string;
  scope: ConfigCandidate['scope'];
  writable_by_current_process: boolean;
  allow: string[];
  deny: string[];
  ask: string[];
  default_mode: string | null;
  additional_directories: string[];
}

export interface CredentialFile {
  kind: string;
  path: string;
  size: number | null;
}

export interface EnvFile {
  path: string;
  secrets: Array<Pick<SecretDescriptor, 'key' | 'class' | 'scheme' | 'length'>>;
}

export interface AuthorityInventory {
  sources: ConfigSource[];
  servers: DeclaredServer[];
  permissions: PermissionDeclaration[];
  credential_files: CredentialFile[];
  env_files: EnvFile[];
}

export interface AuthoritySignal {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  observed: unknown;
  why: string;
  does_not_prove: string;
}

export interface OperationVisibility {
  total: 0;
  mutating: 0;
  read_only: 0;
  unknown: 0;
  coverage: {
    computable: false;
    reason: string;
  };
}

export interface AuthorityScanResult {
  version: string;
  inventory: AuthorityInventory;
  signals: AuthoritySignal[];
  summary: OperationVisibility;
}

export interface DiscoveryOptions {
  cwd?: string;
  home?: string;
  applicationSupport?: string;
  managedCandidates?: ConfigCandidate[];
  maxEnvDepth?: number;
}
