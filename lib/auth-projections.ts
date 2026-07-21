/**
 * Authenticated-actor projections.
 *
 * Route handlers must not forward the complete authenticated entity row. This
 * module exposes the narrow identity and capability projections each caller
 * needs, keeping api_key_hash and future sensitive columns out of write paths.
 *
 * @license Apache-2.0
 */

/* eslint-disable ep-security/no-raw-auth-entity -- this file is the audited projection boundary */

/**
 * Shape of the authenticated entity row as produced by the (still-untyped)
 * Supabase/cloud authenticators. Real-world rows carry many more columns;
 * this module only ever reads the fields below, and the index signature
 * covers whatever else may be present so it is never dropped by structural
 * typing.
 */
export interface AuthEntityFields {
  id?: string;
  entity_id?: string;
  organization_id?: string;
  is_operator?: boolean;
  emilia_score?: unknown;
  public_key?: string | null;
  /** Arbitrary JSONB column; callers narrow with their own typeof/Array checks. */
  metadata?: any;
  display_name?: string;
  description?: string;
  entity_type?: string;
  [key: string]: unknown;
}

export type AuthEntity = string | AuthEntityFields | null | undefined;

/** The loose auth-result shape route handlers pass into these projections. */
export interface AuthLike {
  entity?: AuthEntity;
  [key: string]: unknown;
}

export interface AuthActor {
  id: string;
  entity_id: string;
}

export interface AuthObserveProfile {
  /** Arbitrary JSONB column; callers narrow with their own typeof/Array checks. */
  metadata: any;
  entity_id: string | undefined;
  organization_id: string | undefined;
  display_name: string | undefined;
  description: string | undefined;
  entity_type: string | undefined;
}

/**
 * public_key/emilia_score are only present when the source entity was an
 * object (see authEntityReceiptSubmitter) — the string-entity shortcut
 * returns just { id, entity_id }, matching the original untyped behavior.
 */
export interface AuthReceiptSubmitter {
  id: string;
  entity_id: string;
  emilia_score?: number;
  public_key?: string | null;
}

/**
 * Every function here accepts `unknown` for `auth`: callers across the repo
 * pass whatever authenticateRequest()/authenticateCloudRequest() produced,
 * and those authenticators are not themselves typed yet. This is the single
 * narrowing point — every function below reads `.entity` through this cast
 * rather than widening (or wrongly narrowing) its own public parameter type.
 */
function entityOf(auth: unknown): AuthEntity {
  return (auth as AuthLike | null | undefined)?.entity;
}

/** Resolve the stable protocol identity of an authenticated entity. */
export function authEntityId(auth: unknown): string {
  const e = entityOf(auth);
  if (typeof e === 'string') return e;
  return e?.entity_id || e?.id || '';
}

/** Resolve the database primary key of an authenticated entity. */
export function authEntityDbId(auth: unknown): string {
  const e = entityOf(auth);
  if (typeof e === 'string') return e;
  return e?.id || e?.entity_id || '';
}

/** Return the minimum actor shape required by canonical writers. */
export function authEntityActor(auth: unknown): AuthActor | null {
  const e = entityOf(auth);
  if (!e) return null;
  if (typeof e === 'string') return { id: e, entity_id: e };

  const id = e.id || e.entity_id || '';
  const entity_id = e.entity_id || e.id || '';
  return { id, entity_id };
}

/** Resolve the authenticated entity's organization without forwarding its row. */
export function authEntityOrganizationId(auth: unknown): string | null {
  const e = entityOf(auth);
  return typeof e === 'object' ? (e?.organization_id || null) : null;
}

/**
 * Return only the non-secret fields needed to classify a pilot observe key.
 * This keeps raw authenticated entity rows out of route authorization code.
 */
export function authEntityObserveProfile(auth: unknown): AuthObserveProfile | null {
  const e = entityOf(auth);
  if (!e || typeof e !== 'object' || Array.isArray(e)) return null;
  return {
    metadata: e.metadata,
    entity_id: e.entity_id,
    organization_id: e.organization_id,
    display_name: e.display_name,
    description: e.description,
    entity_type: e.entity_type,
  };
}

/** Resolve the reviewed operator bit without exposing the authenticated row. */
export function authEntityIsOperator(auth: unknown): boolean {
  const e = entityOf(auth);
  return typeof e === 'object' && e?.is_operator === true;
}

/** Resolve the score needed by the legacy needs compatibility path. */
export function authEntityScore(auth: unknown): number {
  const e = entityOf(auth);
  return typeof e === 'object' && Number.isFinite(e?.emilia_score as number) ? (e?.emilia_score as number) : 50;
}

/** Whitelisted submitter projection for the legacy receipt helper. */
export function authEntityReceiptSubmitter(auth: unknown): AuthReceiptSubmitter | null {
  const e = entityOf(auth);
  if (!e) return null;
  if (typeof e === 'string') return { id: e, entity_id: e };
  return {
    id: e.id || e.entity_id || '',
    entity_id: e.entity_id || e.id || '',
    emilia_score: Number.isFinite(e.emilia_score as number) ? (e.emilia_score as number) : 50,
    public_key: e.public_key || null,
  };
}
