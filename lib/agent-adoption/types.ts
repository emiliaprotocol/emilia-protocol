// SPDX-License-Identifier: Apache-2.0

export type AgentSourceKind = 'github' | 'mcp' | 'a2a' | 'local';
export type Sha256Digest = `sha256:${string}`;

export type SyntheticJobTemplateId =
  | 'job_vendor_intake_v1'
  | 'job_compute_batch_v1'
  | 'job_document_route_v1';
export type SyntheticAllowanceTemplateId =
  | 'allowance_cautious_v1'
  | 'allowance_balanced_v1'
  | 'allowance_stretch_v1';

/** The complete and only caller-controlled Agent Adoption input surface. */
export type AgentCandidateInput = Readonly<{
  label: string;
  source_kind: AgentSourceKind;
  source_url?: string;
  agent_key_thumbprint?: Sha256Digest;
  job_template_id: SyntheticJobTemplateId;
  allowance_template_id: SyntheticAllowanceTemplateId;
}>;

export type AgentCandidate = Readonly<{
  '@version': 'EP-AGENT-ADOPTION-CANDIDATE-v1';
  label: string;
  source_kind: AgentSourceKind;
  source_url?: string;
  agent_key_thumbprint?: Sha256Digest;
  job_template_id: SyntheticJobTemplateId;
  allowance_template_id: SyntheticAllowanceTemplateId;
}>;

export type SyntheticJobTemplate = Readonly<{
  '@version': 'EP-AGENT-ADOPTION-JOB-TEMPLATE-v1';
  template_id: SyntheticJobTemplateId;
  display_name: string;
  environment: 'synthetic';
  network_egress: 'forbidden';
  external_side_effects: 'forbidden';
  allowed_action_types: readonly string[];
  allowed_targets: readonly string[];
  max_actions: number;
  max_concurrency: number;
}>;

export type SyntheticAllowanceTemplate = Readonly<{
  '@version': 'EP-AGENT-ADOPTION-ALLOWANCE-TEMPLATE-v1';
  template_id: SyntheticAllowanceTemplateId;
  unit: 'synthetic_credit';
  total: number;
  max_per_action: number;
  max_actions: number;
  validity_seconds: number;
  transferable: false;
  redeemable: false;
  real_world_value: false;
}>;

export type AgentAdoptionClaimBoundaries = Readonly<{
  scope: 'synthetic_no_egress_demonstration';
  real_money: 'not_used_or_represented';
  provider_credentials: 'not_collected_or_used';
  civil_identity: 'not_verified_or_claimed';
  certification: 'not_issued_or_claimed';
  marketplace: 'not_offered_or_claimed';
  production_execution: 'not_authorized_or_claimed';
  source_metadata: 'url_is_metadata_only_never_fetched';
}>;

export type OperatingConstraints = Readonly<{
  environment: 'synthetic';
  network_egress: 'forbidden';
  external_side_effects: 'forbidden';
  allowed_action_types: readonly string[];
  allowed_targets: readonly string[];
  max_actions: number;
  max_concurrency: number;
  validity_seconds: number;
}>;

export type OperatingBond = Readonly<{
  '@version': 'EP-OPERATING-BOND-v1';
  candidate: AgentCandidate;
  candidate_digest: Sha256Digest;
  job: SyntheticJobTemplate;
  allowance: SyntheticAllowanceTemplate;
  constraints: OperatingConstraints;
  claim_boundaries: AgentAdoptionClaimBoundaries;
}>;

export type PublicOperatingBondProjection = Readonly<{
  '@version': 'EP-OPERATING-BOND-PUBLIC-v1';
  bond_digest: Sha256Digest;
  candidate_digest: Sha256Digest;
  candidate: Readonly<{
    label: string;
    source_kind: AgentSourceKind;
  }>;
  operating_limits: Readonly<{
    job_template_id: SyntheticJobTemplateId;
    allowance_template_id: SyntheticAllowanceTemplateId;
    environment: 'synthetic';
    network_egress: 'forbidden';
    allowed_action_types: readonly string[];
    max_actions: number;
    max_concurrency: number;
    validity_seconds: number;
    allowance_unit: 'synthetic_credit';
    allowance_total: number;
    allowance_max_per_action: number;
  }>;
  claim_boundaries: AgentAdoptionClaimBoundaries;
}>;

export type OperatingBondResult = Readonly<{
  candidate: AgentCandidate;
  candidate_digest: Sha256Digest;
  bond: OperatingBond;
  bond_digest: Sha256Digest;
  public_projection: PublicOperatingBondProjection;
}>;

export type AgentAdoptionInputErrorCode =
  | 'invalid_json_domain'
  | 'unknown_field'
  | 'missing_field'
  | 'invalid_label'
  | 'invalid_source_kind'
  | 'invalid_source_url'
  | 'invalid_agent_key_thumbprint'
  | 'unknown_job_template'
  | 'unknown_allowance_template';
