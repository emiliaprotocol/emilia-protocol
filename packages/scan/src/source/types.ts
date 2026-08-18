// SPDX-License-Identifier: Apache-2.0

import type { Classification } from '../index.js';

export type SourceFramework = 'mcp' | 'langchain' | 'vercel-ai' | 'genkit' | 'python-tool' | 'java-tool' | 'tool-call';

export interface SourceEvidence {
  name: string;
  file: string;
  line: number;
  language: string;
  framework: SourceFramework;
  parser_version: string;
  confidence: 'high' | 'medium';
  file_sha256: string;
  registration_sha256: string;
  classification_before: Classification['decision'];
  classification_after: Classification['decision'];
  classification: Classification;
}

export interface DynamicRegistration {
  file: string;
  line: number;
  language: string;
  framework: SourceFramework;
  parser_version: string;
  reason: 'non_literal_action_name';
  file_sha256: string;
  registration_sha256: string;
}

export interface CompositionFinding {
  id: string;
  severity: 'critical' | 'high';
  title: string;
  affected_actions: string[];
  only_tightens: true;
  reason: string;
  does_not_prove: string;
}

export interface SourceBaselineAction {
  name: string;
  source_evidence: Pick<SourceEvidence,
    'file' | 'line' | 'framework' | 'parser_version' | 'file_sha256' | 'registration_sha256'> | null;
  proposed_control: {
    decision: Classification['decision'];
    receipt_required: boolean;
    assurance_class: string | null;
    category: string | null;
  };
}

export interface SourceDiscoveryBaseline {
  '@version': 'EP-SOURCE-DISCOVERY-BASELINE-v1';
  parser_version: string;
  claim_boundary: string;
  actions: SourceBaselineAction[];
}

export interface SourceDiscoveryReport {
  version: 'EP-SOURCE-DISCOVERY-v1';
  parser_version: string;
  scan_digest: string;
  files: Array<{ file: string; bytes: number; sha256: string }>;
  actions: SourceEvidence[];
  unresolved_dynamic_registrations: DynamicRegistration[];
  composition_findings: CompositionFinding[];
  skipped: Array<{ file: string; reason: string }>;
  proposed_manifest: SourceDiscoveryBaseline;
  limitations: string[];
  claim_boundary: string;
}

export interface SourceDiscoveryOptions {
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  maxDepth?: number;
}

export interface SourceDiscoveryDiff {
  version: 'EP-SOURCE-DISCOVERY-DIFF-v1';
  current_scan_digest: string;
  new_actions: string[];
  removed_actions: string[];
  changed_source_actions: string[];
  unresolved_dynamic_registrations: number;
  composition_findings: string[];
  duplicate_registration_names: string[];
  requires_review: boolean;
  claim_boundary: string;
}
