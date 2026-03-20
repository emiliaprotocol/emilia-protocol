/**
 * EP Handshake — Policy loading, validation, and resolution.
 *
 * Provides JSON Schema-style validation (dependency-free), DB loading from
 * handshake_policies table, smart resolution by key/version/ID, and claim
 * checking against policy requirements.
 *
 * @license Apache-2.0
 */

// ── Policy Schema Definition ────────────────────────────────────────────────

/**
 * Structural schema describing the expected shape of policy rules.
 * Used for documentation and as the reference for validatePolicyRules().
 */
export const POLICY_SCHEMA = {
  type: 'object',
  properties: {
    required_parties: {
      type: 'object',
      patternProperties: {
        '.*': {
          type: 'object',
          properties: {
            required_claims: { type: 'array', items: { type: 'string' } },
            minimum_assurance: { type: 'string', enum: ['low', 'medium', 'substantial', 'high'] },
          },
          required: ['required_claims', 'minimum_assurance'],
        },
      },
    },
    binding: {
      type: 'object',
      properties: {
        payload_hash_required: { type: 'boolean' },
        nonce_required: { type: 'boolean' },
        expiry_minutes: { type: 'number' },
      },
      required: ['payload_hash_required', 'nonce_required', 'expiry_minutes'],
    },
    storage: {
      type: 'object',
      properties: {
        store_raw_payload: { type: 'boolean' },
        store_normalized_claims: { type: 'boolean' },
      },
      required: ['store_raw_payload', 'store_normalized_claims'],
    },
  },
  required: ['required_parties', 'binding', 'storage'],
};

const VALID_ASSURANCE_VALUES = new Set(['low', 'medium', 'substantial', 'high']);

// ── Validation ──────────────────────────────────────────────────────────────

/**
 * Validate policy rules against the schema.
 * Returns { valid: boolean, errors: string[] }.
 */
export function validatePolicyRules(rules) {
  const errors = [];

  if (rules === null || rules === undefined || typeof rules !== 'object' || Array.isArray(rules)) {
    return { valid: false, errors: ['rules must be a non-null object'] };
  }

  // ── required_parties ──────────────────────────────────────────────────
  if (!('required_parties' in rules)) {
    errors.push('missing required field: required_parties');
  } else if (typeof rules.required_parties !== 'object' || rules.required_parties === null || Array.isArray(rules.required_parties)) {
    errors.push('required_parties must be a non-null object');
  } else {
    for (const [role, def] of Object.entries(rules.required_parties)) {
      const prefix = `required_parties.${role}`;
      if (typeof def !== 'object' || def === null || Array.isArray(def)) {
        errors.push(`${prefix} must be a non-null object`);
        continue;
      }
      if (!('required_claims' in def)) {
        errors.push(`${prefix}: missing required field: required_claims`);
      } else if (!Array.isArray(def.required_claims)) {
        errors.push(`${prefix}.required_claims must be an array`);
      } else {
        for (let i = 0; i < def.required_claims.length; i++) {
          if (typeof def.required_claims[i] !== 'string') {
            errors.push(`${prefix}.required_claims[${i}] must be a string`);
          }
        }
      }
      if (!('minimum_assurance' in def)) {
        errors.push(`${prefix}: missing required field: minimum_assurance`);
      } else if (typeof def.minimum_assurance !== 'string') {
        errors.push(`${prefix}.minimum_assurance must be a string`);
      } else if (!VALID_ASSURANCE_VALUES.has(def.minimum_assurance)) {
        errors.push(`${prefix}.minimum_assurance must be one of: low, medium, substantial, high`);
      }
    }
  }

  // ── binding ───────────────────────────────────────────────────────────
  if (!('binding' in rules)) {
    errors.push('missing required field: binding');
  } else if (typeof rules.binding !== 'object' || rules.binding === null || Array.isArray(rules.binding)) {
    errors.push('binding must be a non-null object');
  } else {
    const b = rules.binding;
    if (!('payload_hash_required' in b)) {
      errors.push('binding: missing required field: payload_hash_required');
    } else if (typeof b.payload_hash_required !== 'boolean') {
      errors.push('binding.payload_hash_required must be a boolean');
    }
    if (!('nonce_required' in b)) {
      errors.push('binding: missing required field: nonce_required');
    } else if (typeof b.nonce_required !== 'boolean') {
      errors.push('binding.nonce_required must be a boolean');
    }
    if (!('expiry_minutes' in b)) {
      errors.push('binding: missing required field: expiry_minutes');
    } else if (typeof b.expiry_minutes !== 'number') {
      errors.push('binding.expiry_minutes must be a number');
    }
  }

  // ── storage ───────────────────────────────────────────────────────────
  if (!('storage' in rules)) {
    errors.push('missing required field: storage');
  } else if (typeof rules.storage !== 'object' || rules.storage === null || Array.isArray(rules.storage)) {
    errors.push('storage must be a non-null object');
  } else {
    const s = rules.storage;
    if (!('store_raw_payload' in s)) {
      errors.push('storage: missing required field: store_raw_payload');
    } else if (typeof s.store_raw_payload !== 'boolean') {
      errors.push('storage.store_raw_payload must be a boolean');
    }
    if (!('store_normalized_claims' in s)) {
      errors.push('storage: missing required field: store_normalized_claims');
    } else if (typeof s.store_normalized_claims !== 'boolean') {
      errors.push('storage.store_normalized_claims must be a boolean');
    }
  }

  return { valid: errors.length === 0, errors };
}

// ── DB Loading ──────────────────────────────────────────────────────────────

/**
 * Load a policy by key and version from handshake_policies table.
 * Returns the policy row or null if not found.
 */
export async function loadPolicy(supabase, policyKey, version) {
  let query = supabase
    .from('handshake_policies')
    .select('*')
    .eq('policy_key', policyKey);

  if (version !== undefined && version !== null) {
    query = query.eq('version', version);
  } else {
    query = query.eq('status', 'active').order('version', { ascending: false }).limit(1);
  }

  const { data, error } = await query.maybeSingle();

  if (error) {
    throw new Error(`Failed to load policy: ${error.message}`);
  }

  return data || null;
}

/**
 * Load a policy by its primary ID.
 */
export async function loadPolicyById(supabase, policyId) {
  const { data, error } = await supabase
    .from('handshake_policies')
    .select('*')
    .eq('policy_id', policyId)
    .maybeSingle();

  if (error) {
    throw new Error(`Failed to load policy by ID: ${error.message}`);
  }

  return data || null;
}

/**
 * Smart resolver: loads a policy by the most specific identifier available.
 *   - If policy_id is provided, loads by ID.
 *   - If policy_key + policy_version provided, loads by key+version.
 *   - If only policy_key, loads the latest active version.
 */
export async function resolvePolicy(supabase, { policy_key, policy_version, policy_id }) {
  if (policy_id) {
    return loadPolicyById(supabase, policy_id);
  }
  if (policy_key) {
    return loadPolicy(supabase, policy_key, policy_version ?? null);
  }
  return null;
}

// ── Policy Helpers ──────────────────────────────────────────────────────────

/**
 * Given a policy with rules.required_parties, return the set of role names
 * that are required for the policy's mode.
 */
export function getRequiredPartiesForMode(policy) {
  if (!policy || !policy.rules || !policy.rules.required_parties) {
    return [];
  }
  return Object.keys(policy.rules.required_parties);
}

/**
 * Check whether normalized claims satisfy the policy requirements for a
 * given role.
 *
 * @param {Record<string, unknown>} normalizedClaims — the claims presented
 * @param {{ required_claims: string[], minimum_assurance?: string }} policyRequirements
 * @returns {{ satisfied: boolean, missing: string[] }}
 */
export function checkClaimsAgainstPolicy(normalizedClaims, policyRequirements) {
  if (!policyRequirements || !Array.isArray(policyRequirements.required_claims)) {
    return { satisfied: true, missing: [] };
  }

  const claims = normalizedClaims || {};
  const missing = [];

  for (const claim of policyRequirements.required_claims) {
    if (!(claim in claims) || claims[claim] === undefined || claims[claim] === null) {
      missing.push(claim);
    }
  }

  return { satisfied: missing.length === 0, missing };
}
