export interface ActionRiskPack {
  id: string;
  label?: string;
  action_type?: string;
  risk?: string;
  receipt_required: boolean;
  assurance_class?: string;
  match: Record<string, string>;
  why?: string;
  execution_binding?: { required_fields: string[] };
  [key: string]: unknown;
}

export const HIGH_RISK_ACTION_PACKS: readonly ActionRiskPack[];
export const DEFAULT_PASS_THROUGH_ACTIONS: readonly ActionRiskPack[];
export function createDefaultActionRiskManifest(args?: {
  includePassThrough?: boolean;
  extraActions?: readonly Record<string, unknown>[];
}): { '@version': string; actions: Record<string, unknown>[] };
