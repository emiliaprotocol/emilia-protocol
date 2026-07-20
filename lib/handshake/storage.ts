/**
 * EP Handshake — Centralized Supabase data access layer.
 *
 * All DB I/O for handshake tables is routed through this module.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { HandshakeError } from './errors.js';

// ── Read Operations ──────────────────────────────────────────────────────────

export async function fetchHandshake(handshakeId, columns = '*') {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('handshakes')
    .select(columns)
    .eq('handshake_id', handshakeId)
    .maybeSingle();

  if (error) {
    throw new HandshakeError(`Failed to fetch handshake: ${error.message}`, 500, 'DB_ERROR');
  }
  return data;
}

export async function fetchParties(handshakeId) {
  const supabase = getServiceClient();
  const res = await supabase.from('handshake_parties').select('*').eq('handshake_id', handshakeId);
  return res.data || [];
}

export async function fetchPresentations(handshakeId) {
  const supabase = getServiceClient();
  const res = await supabase.from('handshake_presentations').select('*').eq('handshake_id', handshakeId);
  return res.data || [];
}

export async function fetchBinding(handshakeId) {
  const supabase = getServiceClient();
  const res = await supabase.from('handshake_bindings').select('*').eq('handshake_id', handshakeId).maybeSingle();
  return res.data || null;
}

export async function fetchResult(handshakeId) {
  const supabase = getServiceClient();
  const res = await supabase.from('handshake_results').select('*').eq('handshake_id', handshakeId).maybeSingle();
  return res.data || null;
}

export async function fetchPartyByRole(handshakeId, partyRole) {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('handshake_parties')
    .select('id, party_role')
    .eq('handshake_id', handshakeId)
    .eq('party_role', partyRole)
    .maybeSingle();

  if (error) {
    throw new HandshakeError(`Failed to fetch party: ${error.message}`, 500, 'DB_ERROR');
  }
  return data;
}

export async function fetchAuthority(issuerRef) {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('authorities')
    .select('authority_id, status, valid_from, valid_to')
    .eq('key_id', issuerRef)
    .maybeSingle();

  return { data, error };
}

// ── Write Operations ─────────────────────────────────────────────────────────

export async function insertHandshake(record) {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('handshakes')
    .insert(record)
    .select()
    .single();

  if (error) {
    throw new HandshakeError(`Failed to create handshake: ${error.message}`, 500, 'DB_ERROR');
  }
  return data;
}

export async function insertParties(records) {
  const supabase = getServiceClient();
  const { error } = await supabase
    .from('handshake_parties')
    .insert(records);

  if (error) {
    throw new HandshakeError(`Failed to create handshake parties: ${error.message}`, 500, 'DB_ERROR');
  }
}

export async function insertBinding(record) {
  const supabase = getServiceClient();
  const { error } = await supabase
    .from('handshake_bindings')
    .insert(record);

  if (error) {
    throw new HandshakeError(`Failed to create handshake binding: ${error.message}`, 500, 'DB_ERROR');
  }
}

export async function insertPresentation(record) {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('handshake_presentations')
    .insert(record)
    .select()
    .single();

  if (error) {
    throw new HandshakeError(`Failed to store presentation: ${error.message}`, 500, 'DB_ERROR');
  }
  return data;
}

export async function insertResult(record) {
  const supabase = getServiceClient();
  const { error } = await supabase
    .from('handshake_results')
    .insert(record);

  if (error) {
    throw new HandshakeError(`Failed to store handshake result: ${error.message}`, 500, 'DB_ERROR');
  }
}

export async function updateHandshakeStatus(handshakeId, updates, statusFilter = null) {
  const supabase = getServiceClient();
  let query = supabase
    .from('handshakes')
    .update(updates)
    .eq('handshake_id', handshakeId);

  if (statusFilter) {
    query = query.eq('status', statusFilter);
  }

  const { error } = await query;
  if (error) {
    throw new HandshakeError(`Failed to update handshake: ${error.message}`, 500, 'DB_ERROR');
  }
}

export async function updatePartyStatus(partyId, updates) {
  const supabase = getServiceClient();
  await supabase
    .from('handshake_parties')
    .update(updates)
    .eq('id', partyId);
}
