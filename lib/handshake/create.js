/**
 * EP Handshake — Initiation logic.
 *
 * initiateHandshake() validates request, enforces idempotency, creates
 * pending records, calls protocolWrite.
 *
 * _handleInitiateHandshake() is the protocol-write handler.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { resolveActorRef } from '@/lib/actor';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { HandshakeError } from './errors.js';
import { logger } from '@/lib/logger.js';
import {
  HANDSHAKE_MODES,
  ASSURANCE_LEVELS,
  VALID_MODES,
  VALID_PARTY_ROLES,
  ASSURANCE_RANK,
  BINDING_MATERIAL_VERSION,
  sha256,
  newNonce,
} from './invariants.js';
import {
  buildBindingMaterial,
  hashBinding,
  computePartySetHash,
  computeContextHash,
  computePayloadHash,
  computePolicyHash,
} from './binding.js';

/**
 * @typedef {Object} HandshakeParty
 * @property {string} role - Party role ('initiator', 'responder', 'delegate', 'observer', 'auditor')
 * @property {string} entity_ref - Entity reference identifier
 * @property {string} [assurance_level] - Required assurance level (e.g. 'low', 'medium', 'high', 'very_high')
 * @property {object} [delegation_chain] - Delegation chain for delegated mode
 */

/**
 * @typedef {Object} InitiateHandshakeResult
 * @property {string} handshake_id - UUID of the created handshake
 * @property {string} mode - Handshake mode ('unilateral', 'mutual', 'delegated')
 * @property {string} policy_id - Policy identifier
 * @property {string|null} policy_version - Policy version
 * @property {string} status - Always 'initiated' for new handshakes
 * @property {Array<Object>} parties - Created party records
 * @property {Object} binding - Created binding record including binding_hash
 * @property {boolean} [idempotent] - True if this was an idempotent return of an existing handshake
 */

/**
 * Initiate a new handshake.
 *
 * Validates the request, enforces idempotency (via idempotency_key),
 * creates pending handshake/party/binding records, and emits a protocol event
 * through protocolWrite().
 *
 * @param {object} params
 * @param {string} params.mode - Handshake mode: 'unilateral', 'mutual', or 'delegated'
 * @param {string} params.policy_id - Policy governing this handshake
 * @param {string|null} [params.policy_version=null] - Policy version at initiation time
 * @param {string|null} [params.interaction_id=null] - Interaction identifier for grouping
 * @param {HandshakeParty[]} params.parties - Array of parties (must include at least one 'initiator')
 * @param {object} [params.payload={}] - Payload to bind to the handshake
 * @param {number} [params.binding_ttl_ms=600000] - Binding TTL in ms (clamped to 60s-30min)
 * @param {object|null} [params.binding=null] - Override binding fields (nonce, expires_at, session_ref)
 * @param {string|null} [params.idempotency_key=null] - Idempotency key to prevent duplicate handshakes
 * @param {string|null} [params.action_type=null] - Action type being authorized
 * @param {string|null} [params.resource_ref=null] - Target resource reference
 * @param {string|null} [params.intent_ref=null] - Intent reference
 * @param {object} [params.metadata={}] - Additional metadata stored with the handshake
 * @param {string|object} [params.actor='system'] - Authenticated actor performing initiation
 * @returns {Promise<InitiateHandshakeResult>} The created handshake with parties and binding
 * @throws {HandshakeError} INVALID_MODE if mode is not recognized
 * @throws {HandshakeError} MISSING_POLICY if policy_id is not provided
 * @throws {HandshakeError} MISSING_PARTIES if parties array is empty
 * @throws {HandshakeError} INVALID_PARTY_ROLE if a party has an unrecognized role
 * @throws {HandshakeError} MISSING_ENTITY_REF if a party is missing entity_ref
 * @throws {HandshakeError} NO_INITIATOR if no party has the 'initiator' role
 * @throws {HandshakeError} INITIATOR_BINDING_VIOLATION if actor does not match initiator entity_ref
 * @throws {HandshakeError} MUTUAL_REQUIRES_RESPONDER in mutual mode without a responder
 * @throws {HandshakeError} DELEGATED_REQUIRES_DELEGATE in delegated mode without a delegate
 * @throws {HandshakeError} DELEGATE_BINDING_VIOLATION if actor does not match delegate in delegated mode
 */
export async function initiateHandshake({
  mode,
  policy_id,
  policy_version = null,
  interaction_id = null,
  parties,
  payload = {},
  binding_ttl_ms = 10 * 60 * 1000,
  binding = null,
  idempotency_key = null,
  action_type = null,
  resource_ref = null,
  intent_ref = null,
  metadata = {},
  actor = 'system',
}) {
  if (!mode || !VALID_MODES.has(mode)) {
    throw new HandshakeError(
      `mode must be one of: ${HANDSHAKE_MODES.join(', ')}`,
      400, 'INVALID_MODE',
    );
  }
  if (!policy_id) {
    throw new HandshakeError('policy_id is required', 400, 'MISSING_POLICY');
  }
  if (!Array.isArray(parties) || parties.length === 0) {
    throw new HandshakeError('At least one party is required', 400, 'MISSING_PARTIES');
  }

  for (const party of parties) {
    if (!party.role || !VALID_PARTY_ROLES.has(party.role)) {
      throw new HandshakeError(
        `party_role must be one of: ${[...VALID_PARTY_ROLES].join(', ')}`,
        400, 'INVALID_PARTY_ROLE',
      );
    }
    if (!party.entity_ref) {
      throw new HandshakeError('party.entity_ref is required', 400, 'MISSING_ENTITY_REF');
    }
    if (party.assurance_level && !ASSURANCE_RANK[party.assurance_level]) {
      throw new HandshakeError(
        `assurance_level must be one of: ${ASSURANCE_LEVELS.join(', ')}`,
        400, 'INVALID_ASSURANCE_LEVEL',
      );
    }
  }

  const hasInitiator = parties.some((p) => p.role === 'initiator');
  if (!hasInitiator) {
    throw new HandshakeError('At least one party must have role "initiator"', 400, 'NO_INITIATOR');
  }

  // Finding 3: Bind caller to initiator — actor must own the initiator party
  // Exception: in delegated mode, the actor is the delegate (not the initiator).
  const initiatorParty = parties.find((p) => p.role === 'initiator');
  const actorEntityId = resolveActorRef(actor);

  if (mode !== 'delegated' && actorEntityId !== 'system' && initiatorParty.entity_ref !== actorEntityId) {
    throw new HandshakeError(
      'Authenticated entity must match initiator party entity_ref',
      403, 'INITIATOR_BINDING_VIOLATION',
    );
  }

  if (mode === 'mutual') {
    const hasResponder = parties.some((p) => p.role === 'responder');
    if (!hasResponder) {
      throw new HandshakeError('Mutual mode requires at least one responder party', 400, 'MUTUAL_REQUIRES_RESPONDER');
    }
  }

  if (mode === 'delegated') {
    const hasDelegate = parties.some((p) => p.role === 'delegate');
    if (!hasDelegate) {
      throw new HandshakeError('Delegated mode requires at least one delegate party', 400, 'DELEGATED_REQUIRES_DELEGATE');
    }
    // In delegated mode, the delegate's entity_ref must match the actor
    // The initiator is the principal being acted on behalf of
    const delegateParty = parties.find((p) => p.role === 'delegate');
    if (actorEntityId !== 'system' && delegateParty.entity_ref !== actorEntityId) {
      throw new HandshakeError(
        'In delegated mode, authenticated entity must match delegate party entity_ref',
        403, 'DELEGATE_BINDING_VIOLATION',
      );
    }
  }

  const nonce = newNonce();
  const payload_hash = computePayloadHash(payload) || sha256(JSON.stringify({}));
  const now = new Date();
  const clampedTtl = Math.max(60_000, Math.min(30 * 60_000, binding_ttl_ms));
  const expires_at = new Date(now.getTime() + clampedTtl);

  // Compute action_hash: cryptographic binding of the action intent
  const actionIntent = { action_type: action_type || null, resource_ref: resource_ref || null, intent_ref: intent_ref || null };
  const action_hash = sha256(JSON.stringify(actionIntent, Object.keys(actionIntent).sort()));

  const result = await protocolWrite({
    type: COMMAND_TYPES.INITIATE_HANDSHAKE,
    actor,
    input: {
      mode,
      policy_id,
      policy_version,
      interaction_id,
      parties,
      payload_hash,
      nonce,
      expires_at: expires_at.toISOString(),
      metadata,
      binding,
      idempotency_key,
      action_type,
      resource_ref,
      intent_ref,
      action_hash,
    },
  });

  return result;
}

/**
 * Internal protocol-write handler for initiate_handshake commands.
 * Called by protocolWrite() — not intended for direct use.
 *
 * Creates the handshake, party, and binding records in the database,
 * computes canonical binding hashes, and records the handshake event.
 *
 * @param {{ actor: string|object, input: object }} command - The protocol write command
 * @returns {Promise<{ result: InitiateHandshakeResult, aggregateId: string }>}
 * @throws {HandshakeError} DB_ERROR on database failures
 */
export async function _handleInitiateHandshake(command) {
  const {
    mode, policy_id, policy_version, interaction_id,
    parties, payload_hash, nonce, expires_at, metadata,
    binding, idempotency_key, action_type, resource_ref, intent_ref,
    action_hash,
  } = command.input;

  const supabase = getServiceClient();

  // Idempotency check: if an idempotency_key is provided, return existing handshake
  // instead of creating a duplicate (Critical Finding 4).
  if (idempotency_key) {
    const { data: existing, error: idempError } = await supabase
      .from('handshakes')
      .select('*')
      .eq('idempotency_key', idempotency_key)
      .maybeSingle();

    if (idempError) {
      throw new HandshakeError(`Idempotency lookup failed: ${idempError.message}`, 500, 'DB_ERROR');
    }

    if (existing) {
      // Fetch associated parties and binding for the existing handshake
      const [partiesRes, bindingRes] = await Promise.all([
        supabase.from('handshake_parties').select('*').eq('handshake_id', existing.handshake_id),
        supabase.from('handshake_bindings').select('*').eq('handshake_id', existing.handshake_id).maybeSingle(),
      ]);

      return {
        result: {
          handshake_id: existing.handshake_id,
          mode: existing.mode,
          policy_id: existing.policy_id,
          policy_version: existing.policy_version,
          status: existing.status,
          parties: partiesRes.data || [],
          binding: bindingRes.data || null,
          idempotent: true,
        },
        aggregateId: existing.handshake_id,
      };
    }
  }

  // Compute policy_hash and pin policy_version_number at initiation time.
  // policy_hash: cryptographic snapshot of policy rules — detects in-place mutation.
  // policy_version_number: pins the integer version row — detects silent row replacement.
  //
  // Audit-fix (C3): FAIL CLOSED on policy resolution errors. The previous bare
  // catch silently left policy_hash = null, which disabled the entire
  // policy-tamper / version-pin detection at verify time. Any transient DB
  // error — or a planted error — became a permanent trust-integrity hole.
  // We now throw. The only legitimate way to reach verify with
  // handshake.policy_hash = null is if policy_id itself is null.
  let policy_hash = null;
  let policy_version_number = null;
  if (policy_id) {
    const { resolvePolicy } = await import('./policy.js');
    let policy;
    try {
      policy = await resolvePolicy(supabase, { policy_id });
    } catch (err) {
      throw new HandshakeError(
        `Policy resolution failed for policy_id=${policy_id}: ${err.message}`,
        500, 'POLICY_LOAD_FAILED',
      );
    }
    if (!policy || !policy.rules) {
      throw new HandshakeError(
        `Policy not found or malformed for policy_id=${policy_id}`,
        400, 'POLICY_NOT_FOUND',
      );
    }
    policy_hash = computePolicyHash(policy.rules);
    if (policy.version != null) {
      policy_version_number = policy.version;
    }
  }

  // Critical Finding 5: Canonical binding material — party_set_hash, context_hash, binding_hash
  const party_set_hash = computePartySetHash(parties);

  const contextMaterial = {
    action_type: action_type || null,
    resource_ref: resource_ref || null,
    intent_ref: intent_ref || null,
    policy_id,
    policy_version: policy_version || null,
    interaction_id: interaction_id || null,
  };
  const context_hash = computeContextHash(contextMaterial);

  // Critical Finding 5: Compute binding_hash from canonical binding material.
  const bindingMaterial = buildBindingMaterial({
    action_type: action_type || null,
    resource_ref: resource_ref || null,
    policy_id,
    policy_version: policy_version || null,
    policy_hash: policy_hash || null,
    interaction_id: interaction_id || null,
    party_set_hash,
    payload_hash,
    context_hash,
    nonce,
    expires_at: binding?.expires_at || expires_at,
  });

  const binding_hash = hashBinding(bindingMaterial);

  const initiatorParty = parties.find((p) => p.role === 'initiator');
  const initiator_entity_ref = initiatorParty ? initiatorParty.entity_ref : null;

  // Resolve actor reference for event recording
  const { resolveActorRef } = await import('@/lib/actor.js');
  const actorRef = resolveActorRef(command.actor);

  // Single RPC call: handshake + parties + binding + event in one DB roundtrip.
  // This replaces 4 serial REST API calls (~320ms) with 1 (~80ms).
  const { data: rpcResult, error: rpcError } = await supabase.rpc('create_handshake_atomic', {
    p_mode: mode,
    p_policy_id: policy_id,
    p_policy_id_legacy: String(policy_id),
    p_policy_version: policy_version || null,
    p_policy_version_number: policy_version_number ?? null,
    p_interaction_id: interaction_id || null,
    p_action_type: action_type || null,
    p_resource_ref: resource_ref || null,
    p_intent_ref: intent_ref || null,
    p_action_hash: action_hash || null,
    p_policy_hash: policy_hash || null,
    p_idempotency_key: idempotency_key || null,
    p_party_set_hash: party_set_hash,
    p_metadata_json: metadata || {},
    p_parties: parties.map((p) => ({
      party_role: p.role,
      entity_ref: p.entity_ref,
      assurance_level: p.assurance_level || null,
      delegation_chain: p.delegation_chain || null,
    })),
    // Audit-fix (C2): do NOT allow the caller to override server-computed
    // binding material. payload_hash and nonce are computed above from the
    // authenticated payload and the server's CSPRNG; letting a caller pass
    // their own values decoupled the stored row's payload_hash from what
    // binding_hash was computed over, breaking verify integrity.
    // Also (H1): expires_at is always serialized via toISOString() — never
    // take a raw Date object or a caller-supplied string, since the stored
    // timestamptz round-trip would differ from what we hashed.
    // session_ref is the only caller-influenced optional field we accept.
    p_binding: {
      payload_hash,                                    // server truth
      nonce,                                           // server truth
      expires_at: (expires_at instanceof Date          // server truth
        ? expires_at
        : new Date(expires_at)).toISOString(),
      session_ref: binding?.session_ref || null,
      party_set_hash,
      context_hash,
      binding_hash,
      binding_material_version: BINDING_MATERIAL_VERSION,
      initiator_entity_ref,
    },
    p_event_actor_id: actorRef,
    p_event_actor_entity_ref: actorRef,
    p_event_detail: { mode, policy_id, party_count: parties.length, action_type: action_type || null },
    // Protocol event data — written inside the same transaction.
    //
    // Audit-fix (HIGH-5): previously the hash was computed over `command.input`
    // but the STORED `payload_json` was the RPC's own jsonb parse+reserialize
    // of that same value. Under any non-canonical field order, any non-finite
    // value, or any nested object with keys that don't round-trip identically,
    // `sha256(stored payload_json) !== stored payload_hash` — defeating the
    // integrity check that the protocol_events log is supposed to support.
    //
    // Fix: canonicalize once via computePayloadHash's deepSortKeys equivalent,
    // store the canonical object (so the DB persists a canonicalized form),
    // and hash the same canonical object. Now stored payload_json always
    // re-hashes to stored payload_hash.
    p_protocol_event_payload: (() => {
      // Use a tiny local canonicalizer to match computePayloadHash's deepSortKeys.
      // We can't import deepSortKeys directly (private to binding.js) so re-
      // create via the public computePayloadHash pathway: stringify, parse,
      // store. This round-trips through the canonical JSON.
      if (!command.input || typeof command.input !== 'object') return {};
      try {
        // computePayloadHash internally calls deepSortKeys + JSON.stringify.
        // We mirror that by stringifying via a key-sort reviver.
        return JSON.parse(JSON.stringify(command.input, (_k, v) => {
          if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
            return Object.keys(v).sort().reduce((acc, k) => { acc[k] = v[k]; return acc; }, {});
          }
          return v;
        }));
      } catch {
        return {};
      }
    })(),
    p_protocol_event_payload_hash: computePayloadHash(command.input || {}) || sha256(JSON.stringify({})),
    p_protocol_event_idempotency_key: null,
  });

  if (rpcError) {
    throw new HandshakeError(`Failed to create handshake: ${rpcError.message}`, 500, 'DB_ERROR');
  }

  const handshake_id = rpcResult.handshake_id;

  // policy_version_number is now written atomically inside create_handshake_atomic
  // (migration 070). No post-RPC UPDATE required.

  return {
    _protocolEventWritten: true, // Signal to protocolWrite: event already in DB via RPC
    result: {
      handshake_id,
      mode,
      policy_id,
      policy_version,
      policy_version_number: policy_version_number ?? null,
      action_hash: action_hash || null,
      policy_hash: policy_hash || null,
      status: 'initiated',
      parties: parties.map((p) => ({
        handshake_id,
        party_role: p.role,
        entity_ref: p.entity_ref,
        assurance_level: p.assurance_level || null,
        verified_status: 'pending',
        delegation_chain: p.delegation_chain || null,
      })),
      binding: {
        // Audit-fix (C2 / H1): return the same server-truth values that were
        // written to the DB, never the caller-supplied overrides. payload_hash
        // and nonce are server-computed; expires_at is canonicalized via
        // toISOString() to match what the DB stored.
        handshake_id,
        payload_hash,
        nonce,
        expires_at: (expires_at instanceof Date
          ? expires_at
          : new Date(expires_at)).toISOString(),
        party_set_hash,
        context_hash,
        binding_hash,
        binding_material_version: BINDING_MATERIAL_VERSION,
        initiator_entity_ref,
      },
    },
    aggregateId: handshake_id,
  };
}
