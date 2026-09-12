// SPDX-License-Identifier: Apache-2.0
import { validWorksId, validateBuilder, type BuilderRecord } from '@/lib/works/model';
import { readOwnedRecord, samePublication } from './join/owned-record';

/** Call only with profiles returned by the authenticated workspace, never a public directory. */
export function selectOwnedJoinProfile(profiles: readonly unknown[] | null, id: string): BuilderRecord {
  if (!profiles || !validWorksId(id)) throw new Error('join_profile_not_owned');
  const matches = profiles.filter(item => item && typeof item === 'object' && 'builder_id' in item && item.builder_id === id);
  if (matches.length !== 1) throw new Error('join_profile_not_owned');
  const raw = matches[0] as Record<string, unknown>;
  const checked = validateBuilder(raw);
  if (!checked.ok || raw.example === true) throw new Error('join_profile_not_owned');
  return checked.record;
}

/** Remove access secrets without losing the exact public intent of a possibly completed write. */
export function clearJoinCredentials<T extends { apiKey: string | null; keyCreatedHere: boolean; ownerId: string }>(progress: T): T & { accessCheckRequired: true } {
  return { ...progress, apiKey: progress.apiKey === null ? null : '', keyCreatedHere: false, ownerId: '', accessCheckRequired: true };
}

export async function confirmOwnedJoinResume(progress: { builderCreated: boolean; payloads: { builder: BuilderRecord } }, apiKey: string | null, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  // Unknown first writes are retried separately with their original ID. Confirmed
  // profiles must be owned by the current access before their listing can continue.
  if (!progress.builderCreated) return;
  const observed = await readOwnedRecord('builders', progress.payloads.builder.builder_id, apiKey, signal);
  signal.throwIfAborted();
  if (!samePublication('builders', progress.payloads.builder, observed)) throw new Error('The owned profile differs from the original preview. It was not changed.');
}
