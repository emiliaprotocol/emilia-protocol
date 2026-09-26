// SPDX-License-Identifier: Apache-2.0
/**
 * Opt-in Stripe refund recovery on the existing Proposal-to-Effect PostgreSQL
 * attempt store. The legacy Stripe adapter is intentionally unchanged.
 *
 * COMMITTED here means Stripe accepted creation of a refund object, not that
 * money has settled or that the refund's later status is successful.
 */
import crypto from 'node:crypto';
import { canonicalActuatorObject, hashCanonical, manifestFromPack } from './_kit.js';
import { STRIPE_ACTION_PACK } from './stripe.js';
import { verifyExecutionBinding } from '../execution-binding.js';
import {
  createProposalToEffectPostgresStore,
  type CreateProposalToEffectPostgresStoreOptions,
  type ProposalToEffectPostgresAttemptSnapshot,
  type ProposalToEffectPostgresStore,
} from '../proposal-to-effect-postgres.js';
import type {
  AuthenticatedProviderEvidenceBinding,
  ConsequenceAttemptBinding,
  ConsequenceAttemptOwnerHandle,
} from '../proposal-to-effect.js';

const PROFILE = 'EMILIA-STRIPE-REFUND-DURABLE-v1';
/**
 * The durable profile's own action type. Gate refuses a receipt whose signed
 * action_type differs from the resolved manifest entry, and both Stripe refund
 * paths bind action_type as a material execution field. A receipt minted for
 * this profile therefore cannot execute on the legacy guardStripeMutation()
 * refund path ('stripe.refund.create'), and a legacy refund receipt cannot
 * execute here.
 */
export const STRIPE_REFUND_DURABLE_ACTION_TYPE = 'stripe.refund.durable.create';
const ACTION_TYPE = STRIPE_REFUND_DURABLE_ACTION_TYPE;
const PROVIDER_ID = 'stripe';
const SELECTOR = Object.freeze({ protocol: 'stripe', tool: 'create_refund' });
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9:._/@-]{7,199}$/;
const PAYMENT_INTENT = /^pi_[A-Za-z0-9_]{1,240}$/;
const STRIPE_ACCOUNT = /^acct_[A-Za-z0-9_]{1,240}$/;
const REFUND_ID = /^re_[A-Za-z0-9_]{1,240}$/;
// The approval binds the connector namespace (tenant and environment) as well
// as the Stripe account and refund material, so one receipt cannot be spent
// under a second connector configuration whose attempt store does not fence it.
const REQUIRED_FIELDS = Object.freeze([
  'action_type', 'tenant_id', 'environment', 'provider_account_id',
  'payment_intent', 'amount', 'operation_id',
]);

type RefundParameters = {
  payment_intent: string;
  amount: number;
  operation_id: string;
};

type StripeRefundRecord = {
  id?: unknown;
  payment_intent?: unknown;
  amount?: unknown;
  created?: unknown;
  status?: unknown;
  metadata?: unknown;
};

type StripeClient = {
  accounts: { retrieve(): Promise<{ id?: unknown }> };
  refunds: {
    create(input: Record<string, unknown>, options: { idempotencyKey: string }): Promise<StripeRefundRecord>;
    list(input: { payment_intent: string; limit: number }): Promise<{ data?: unknown; has_more?: unknown }>;
  };
};

type GateRequirement = {
  receipt_required?: boolean; action_type?: string;
  execution_binding?: { required_fields?: string[] };
};

type Gate = {
  check(input: Record<string, unknown>): Promise<{
    allow?: boolean; reason?: string; requirement?: GateRequirement;
  }>;
  run(input: Record<string, unknown>, effect: (authorization: {
    allow?: boolean; requirement?: GateRequirement;
  }) => Promise<unknown>): Promise<{
    ok?: boolean; result?: unknown; authorization?: { reason?: string };
    packet?: unknown; execution?: unknown;
  }>;
};

// Recovery addresses the attempt by its deterministic binding through read(),
// so the store does not need lookup_attempt, which the exported PTE DDL lacks.
export type StripeRefundDurableStore = Pick<ProposalToEffectPostgresStore,
  'reserve' | 'transition' | 'reconcile' | 'read' | 'recover'
  | 'durable' | 'ownershipFenced' | 'compareAndSwap' | 'atomicEvidenceBinding'>;

export interface StripeRefundDurableConnector {
  readonly profile: typeof PROFILE;
  readonly account_id: string;
  readonly tenant_id: string;
  readonly environment: string;
}

type Configured = {
  stripe: StripeClient;
  gate: Gate;
  store: StripeRefundDurableStore;
  resolve_operation(reference: string): Promise<RefundParameters> | RefundParameters;
  account_id: string;
  tenant_id: string;
  environment: string;
  metadata_key: Buffer;
};

const connectors = new WeakMap<object, Configured>();

/**
 * Build a manifest whose refund receipt uses this profile's own action type
 * and binds the connector tenant and environment and the provider account as
 * well as the payment, amount, and operation. The direct adapter's older
 * manifest is intentionally not changed and is refused by this connector.
 */
export function createStripeDurableRefundManifest(extraActions = []) {
  const pack = STRIPE_ACTION_PACK.map((item) => item.id === 'stripe.refund.create'
    ? {
      ...item,
      // The selector stays the legacy refund selector on purpose. A legacy
      // guardStripeMutation() refund sent to this Gate still resolves a guarded
      // entry, never an unguarded pass-through, and is refused because its
      // receipt and observed action name the legacy action type.
      id: ACTION_TYPE,
      label: 'Stripe refund (durable recovery profile)',
      action_type: ACTION_TYPE,
      execution_binding: { required_fields: [...REQUIRED_FIELDS] },
    }
    : item);
  return manifestFromPack(pack, extraActions);
}

/** True only for a Gate requirement resolved from this profile's manifest entry. */
function durableRequirement(requirement: GateRequirement | undefined): boolean {
  const required = requirement?.execution_binding?.required_fields;
  return requirement?.receipt_required === true
    && requirement.action_type === ACTION_TYPE
    && Array.isArray(required)
    && REQUIRED_FIELDS.every((field) => required.includes(field));
}

function digest(value: unknown): `sha256:${string}` {
  return `sha256:${hashCanonical(value)}`;
}

function assertIdentifier(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
}

/**
 * Read each refund field from the business system's object exactly once into
 * a frozen snapshot, then validate only that snapshot. A getter, proxy, or
 * shared object whose values change between reads cannot put an unchecked
 * value on the wire, because nothing reads the source object again.
 */
function snapshotRefund(value: unknown): RefundParameters {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('trusted refund operation is invalid');
  }
  const source = value as Record<string, unknown>;
  const snapshot = Object.freeze({
    payment_intent: source.payment_intent,
    amount: source.amount,
    operation_id: source.operation_id,
  });
  if (typeof snapshot.payment_intent !== 'string' || !PAYMENT_INTENT.test(snapshot.payment_intent)
      || typeof snapshot.amount !== 'number' || !Number.isSafeInteger(snapshot.amount)
      || snapshot.amount <= 0
      || typeof snapshot.operation_id !== 'string' || !OPERATION_ID.test(snapshot.operation_id)) {
    throw new TypeError('trusted refund operation is invalid');
  }
  return snapshot as RefundParameters;
}

function context(config: Configured, p: RefundParameters) {
  const action = canonicalActuatorObject({
    action_type: ACTION_TYPE,
    tenant_id: config.tenant_id,
    environment: config.environment,
    provider_account_id: config.account_id,
    payment_intent: p.payment_intent,
    amount: p.amount,
    operation_id: p.operation_id,
  });
  const idempotencyKey = `emilia:stripe:refund:durable:v1:${hashCanonical({
    purpose: 'stripe.refund.create', tenant_id: config.tenant_id,
    provider_account_id: config.account_id, environment: config.environment,
    operation_id: p.operation_id,
  })}`;
  // Attempt identity is stable across fresh receipts and OAuth proofs. The
  // request digest pins every material/provider field before Stripe entry.
  const attemptId = `stripe-refund:${hashCanonical({
    tenant_id: config.tenant_id, account_id: config.account_id,
    environment: config.environment, operation_id: p.operation_id,
  })}`;
  const binding: ConsequenceAttemptBinding = {
    tenant_id: config.tenant_id,
    provider_id: PROVIDER_ID,
    provider_account_id: config.account_id,
    environment: config.environment,
    attempt_id: attemptId,
    request_digest: digest({
      profile: PROFILE, tenant_id: config.tenant_id, provider_id: PROVIDER_ID,
      account_id: config.account_id, environment: config.environment,
      action, idempotency_key: idempotencyKey,
    }),
  };
  // This is a local CAID profile over the exact Stripe refund material; it is
  // not a claim of a registered global Stripe action definition. The connector
  // namespace is carried by the attempt binding, not by the action identifier.
  const caidAction = {
    action_type: `${ACTION_TYPE}.1`, provider_account_id: config.account_id,
    payment_intent: p.payment_intent, amount: p.amount, operation_id: p.operation_id,
  };
  const caid = `caid:1:${ACTION_TYPE}.1:jcs-sha256:${Buffer.from(hashCanonical(caidAction), 'hex').toString('base64url')}`;
  const metadata = {
    emilia_operation_id: p.operation_id,
    emilia_request_digest: binding.request_digest,
    emilia_idempotency_key: idempotencyKey,
    emilia_origin_tag: crypto.createHmac('sha256', config.metadata_key)
      .update(PROFILE).update('\0').update(binding.request_digest)
      .digest('hex'),
  };
  return { action, binding, caid, idempotencyKey, metadata };
}

/** Deterministic PTE digests: no parallel journal or process-local binding map. */
export function stripeRefundAttemptDigests(binding: ConsequenceAttemptBinding) {
  if (binding.provider_id !== PROVIDER_ID || !STRIPE_ACCOUNT.test(binding.provider_account_id)
      || !/^stripe-refund:[0-9a-f]{64}$/.test(binding.attempt_id)
      || !/^sha256:[0-9a-f]{64}$/.test(binding.request_digest)) {
    throw new TypeError('Stripe refund attempt binding is invalid');
  }
  return {
    operation_digest: digest({ profile: PROFILE, attempt_id: binding.attempt_id }),
    action_digest: binding.request_digest,
    config_digest: digest({ profile: PROFILE, provider_id: PROVIDER_ID,
      account_id: binding.provider_account_id, environment: binding.environment }),
  };
}

/** Configure the existing PTE PostgreSQL machinery for this Stripe profile. */
export function createStripeRefundDurableStore(options: Omit<CreateProposalToEffectPostgresStoreOptions,
  'resolve_binding_digests' | 'authorize_recovery'> & {
    tenant_id: string;
    provider_account_id: string;
    environment: string;
    authorize_recovery(snapshot: ProposalToEffectPostgresAttemptSnapshot): Promise<boolean> | boolean;
  }): ProposalToEffectPostgresStore {
  assertIdentifier(options.tenant_id, 'tenant_id');
  assertIdentifier(options.environment, 'environment');
  if (!STRIPE_ACCOUNT.test(options.provider_account_id)) throw new TypeError('Stripe account is invalid');
  const { tenant_id, provider_account_id, environment, authorize_recovery, ...storeOptions } = options;
  return createProposalToEffectPostgresStore({
    ...storeOptions,
    resolve_binding_digests(binding) {
      if (binding.tenant_id !== tenant_id || binding.provider_account_id !== provider_account_id
          || binding.environment !== environment) {
        throw new TypeError('Stripe refund attempt namespace mismatch');
      }
      return stripeRefundAttemptDigests(binding);
    },
    async authorize_recovery(snapshot) {
      if (snapshot.tenant_id !== tenant_id || snapshot.provider_id !== PROVIDER_ID
          || snapshot.provider_account_id !== provider_account_id
          || snapshot.environment !== environment) return false;
      const digests = stripeRefundAttemptDigests(snapshot);
      if (snapshot.operation_digest !== digests.operation_digest
          || snapshot.action_digest !== digests.action_digest
          || snapshot.config_digest !== digests.config_digest) return false;
      return authorize_recovery(snapshot);
    },
  });
}

/**
 * The operation resolver must read the business system's immutable refund job,
 * not echo agent-supplied payment fields or mint an ID for each retry.
 */
export async function createStripeRefundDurableConnector(input: {
  stripe: StripeClient;
  gate: Gate;
  store: StripeRefundDurableStore;
  tenant_id: string;
  environment: string;
  /** Stable, server-only key; retain it for the full recovery window. */
  metadata_hmac_sha256_key: Uint8Array;
  resolve_operation(reference: string): Promise<RefundParameters> | RefundParameters;
}): Promise<StripeRefundDurableConnector> {
  if (!input?.stripe?.accounts || typeof input.stripe.accounts.retrieve !== 'function'
      || typeof input.stripe?.refunds?.create !== 'function'
      || typeof input.stripe.refunds.list !== 'function'
      || typeof input.gate?.check !== 'function' || typeof input.gate.run !== 'function'
      || typeof input.resolve_operation !== 'function'
      || !(input.metadata_hmac_sha256_key instanceof Uint8Array)
      || input.metadata_hmac_sha256_key.byteLength < 32
      || !input.store?.durable || !input.store.ownershipFenced
      || !input.store.compareAndSwap || !input.store.atomicEvidenceBinding
      || typeof input.store.reserve !== 'function' || typeof input.store.transition !== 'function'
      || typeof input.store.reconcile !== 'function' || typeof input.store.read !== 'function'
      || typeof input.store.recover !== 'function') {
    throw new TypeError('durable Stripe refund connector configuration is invalid');
  }
  assertIdentifier(input.tenant_id, 'tenant_id');
  assertIdentifier(input.environment, 'environment');
  const account = await input.stripe.accounts.retrieve();
  if (!STRIPE_ACCOUNT.test(String(account?.id ?? ''))) {
    throw new TypeError('Stripe account identity probe failed');
  }
  const connector = Object.freeze({
    profile: PROFILE, account_id: account.id as string,
    tenant_id: input.tenant_id, environment: input.environment,
  });
  connectors.set(connector, {
    ...input, account_id: connector.account_id,
    metadata_key: Buffer.from(input.metadata_hmac_sha256_key),
  });
  return connector;
}

/** A pre-reservation refusal: nothing was recorded and Stripe was not entered. */
class ResolveRefusal extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

async function resolve(connector: StripeRefundDurableConnector, reference: unknown) {
  const config = connectors.get(connector);
  if (!config) throw new ResolveRefusal('stripe_refund_connector_unconfigured');
  if (typeof reference !== 'string' || !IDENTIFIER.test(reference)) {
    throw new ResolveRefusal('refund_operation_reference_invalid');
  }
  let account: { id?: unknown } | undefined;
  try {
    account = await config.stripe.accounts.retrieve();
  } catch {
    throw new ResolveRefusal('stripe_account_probe_failed');
  }
  if (account?.id !== config.account_id) throw new ResolveRefusal('stripe_account_changed');
  let trusted: unknown;
  try {
    trusted = await config.resolve_operation(reference);
  } catch {
    throw new ResolveRefusal('refund_operation_unavailable');
  }
  // Copy, then validate the copy; a throwing getter or proxy trap refuses here.
  // Only the frozen snapshot is used from this point on.
  let p: RefundParameters;
  try {
    p = snapshotRefund(trusted);
  } catch {
    throw new ResolveRefusal('refund_operation_invalid');
  }
  return { config, p, ...context(config, p) };
}

async function resolveOrRefuse(connector: StripeRefundDurableConnector, reference: unknown) {
  try {
    return { resolved: await resolve(connector, reference) } as const;
  } catch (error) {
    if (error instanceof ResolveRefusal) return { refusal: error.reason } as const;
    throw error;
  }
}

type Resolved = Awaited<ReturnType<typeof resolve>>;

/** Provider refund fields, each read once from the provider object. */
type RefundView = Readonly<{
  id: unknown;
  payment_intent: unknown;
  amount: unknown;
  created: unknown;
  metadata: Readonly<Record<
    'emilia_operation_id' | 'emilia_request_digest' | 'emilia_idempotency_key' | 'emilia_origin_tag',
    unknown
  >> | null;
}>;

function refundView(record: unknown): RefundView | null {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const r = record as StripeRefundRecord;
  const rawMetadata = r.metadata;
  let metadata: RefundView['metadata'] = null;
  if (rawMetadata && typeof rawMetadata === 'object' && !Array.isArray(rawMetadata)) {
    const m = rawMetadata as Record<string, unknown>;
    metadata = Object.freeze({
      emilia_operation_id: m.emilia_operation_id,
      emilia_request_digest: m.emilia_request_digest,
      emilia_idempotency_key: m.emilia_idempotency_key,
      emilia_origin_tag: m.emilia_origin_tag,
    });
  }
  return Object.freeze({
    id: r.id, payment_intent: r.payment_intent, amount: r.amount, created: r.created, metadata,
  });
}

/**
 * True when a provider record carries any of this operation's identifying
 * metadata. Such a record that is not a complete positive match means the
 * provider view conflicts with the attempt, so it cannot support COMMITTED.
 */
function carriesOperationMetadata(view: RefundView | null, resolved: Resolved): boolean {
  const m = view?.metadata;
  if (!m) return false;
  return m.emilia_operation_id === resolved.p.operation_id
    || m.emilia_request_digest === resolved.binding.request_digest
    || m.emilia_idempotency_key === resolved.idempotencyKey
    || m.emilia_origin_tag === resolved.metadata.emilia_origin_tag;
}

function positiveRefundEvidence(
  view: RefundView | null, resolved: Resolved,
): AuthenticatedProviderEvidenceBinding | null {
  if (!view || typeof view.id !== 'string' || !REFUND_ID.test(view.id)
      || view.payment_intent !== resolved.p.payment_intent
      || view.amount !== resolved.p.amount
      || typeof view.created !== 'number' || !Number.isSafeInteger(view.created)
      || view.created <= 0 || view.created * 1000 > Date.now() + 300_000
      || !view.metadata) return null;
  const metadata = view.metadata;
  if (metadata.emilia_operation_id !== resolved.p.operation_id
      || metadata.emilia_request_digest !== resolved.binding.request_digest
      || metadata.emilia_idempotency_key !== resolved.idempotencyKey
      || metadata.emilia_origin_tag !== resolved.metadata.emilia_origin_tag) return null;
  const observedAt = new Date(view.created * 1000).toISOString();
  return {
    ...resolved.binding,
    operation_id: resolved.p.operation_id,
    caid: resolved.caid,
    action_digest: resolved.binding.request_digest,
    evidence_id: view.id,
    observed_at: observedAt,
    outcome: 'COMMITTED',
    evidence_digest: digest({
      profile: PROFILE, provider_id: PROVIDER_ID,
      account_id: resolved.config.account_id, id: view.id,
      payment_intent: view.payment_intent, amount: view.amount,
      created: view.created, metadata: resolved.metadata,
    }),
  };
}

type ProviderHoldReason =
  | 'provider_lookup_unavailable' | 'provider_lookup_incomplete'
  | 'provider_effect_conflicting' | 'provider_effect_ambiguous';

type ProviderView =
  | { outcome: 'match'; evidence: AuthenticatedProviderEvidenceBinding; record: unknown }
  | { outcome: 'absent' }
  | { outcome: 'held'; reason: ProviderHoldReason };

/**
 * One bounded Stripe list over this payment intent, classified by the rules
 * both recovery and the pre-create lookup use. Only an exact, uniquely tagged
 * refund on a complete page is a match; only a complete page with no refund
 * carrying any of this operation's metadata is absent. Everything else holds.
 */
async function inspectProviderRefunds(resolved: Resolved): Promise<ProviderView> {
  let page: { data?: unknown; has_more?: unknown };
  try {
    page = await resolved.config.stripe.refunds.list({ payment_intent: resolved.p.payment_intent, limit: 100 });
  } catch {
    return { outcome: 'held', reason: 'provider_lookup_unavailable' };
  }
  try {
    const data = page?.data;
    const hasMore = page?.has_more;
    if (!Array.isArray(data) || hasMore !== false) {
      return { outcome: 'held', reason: 'provider_lookup_incomplete' };
    }
    const records = Array.from(data as unknown[]);
    const views = records.map((record) => refundView(record));
    const evidence = views.map((view) => positiveRefundEvidence(view, resolved));
    if (views.some((view, index) => !evidence[index] && carriesOperationMetadata(view, resolved))) {
      return { outcome: 'held', reason: 'provider_effect_conflicting' };
    }
    const matches = evidence.flatMap((item, index) => item ? [index] : []);
    if (matches.length === 0) return { outcome: 'absent' };
    if (matches.length > 1) return { outcome: 'held', reason: 'provider_effect_ambiguous' };
    return { outcome: 'match', evidence: evidence[matches[0]!]!, record: records[matches[0]!] };
  } catch {
    // A page that cannot be read consistently is not a complete provider view.
    return { outcome: 'held', reason: 'provider_lookup_incomplete' };
  }
}

function attemptRef(binding: ConsequenceAttemptBinding, owner: ConsequenceAttemptOwnerHandle) {
  return { tenant_id: binding.tenant_id, attempt_id: binding.attempt_id, owner };
}

function attemptReference(binding: ConsequenceAttemptBinding) {
  return {
    tenant_id: binding.tenant_id, provider_id: binding.provider_id,
    provider_account_id: binding.provider_account_id, environment: binding.environment,
    attempt_id: binding.attempt_id, request_digest: binding.request_digest,
  };
}

/**
 * Read the attempt by its deterministic binding. This works on the exported
 * PTE DDL, which has no lookup_attempt function.
 */
async function readAttempt(store: StripeRefundDurableStore, binding: ConsequenceAttemptBinding) {
  const snapshot = await store.read(attemptReference(binding)).catch(() => null);
  if (!snapshot) return { found: false } as const;
  const expectedDigests = stripeRefundAttemptDigests(binding);
  if (snapshot.tenant_id !== binding.tenant_id || snapshot.provider_id !== binding.provider_id
      || snapshot.provider_account_id !== binding.provider_account_id
      || snapshot.environment !== binding.environment
      || snapshot.attempt_id !== binding.attempt_id
      || snapshot.request_digest !== binding.request_digest
      || snapshot.operation_digest !== expectedDigests.operation_digest
      || snapshot.action_digest !== expectedDigests.action_digest
      || snapshot.config_digest !== expectedDigests.config_digest) {
    return { found: true, matches: false } as const;
  }
  return { found: true, matches: true, snapshot } as const;
}

const hasEvidenceDigest = (snapshot: ProposalToEffectPostgresAttemptSnapshot) =>
  /^sha256:[0-9a-f]{64}$/.test(String(snapshot.evidence_digest ?? ''));

/**
 * The operation already has an attempt. Report what that attempt is, without
 * claiming an uncertainty that does not exist: a RELEASED attempt is closed
 * (Stripe was not entered), a COMMITTED one is done. Only a nonterminal or
 * unreadable attempt is reported as held.
 */
async function existingAttemptOutcome(store: StripeRefundDurableStore, binding: ConsequenceAttemptBinding) {
  const read = await readAttempt(store, binding);
  const snapshot = read.found && read.matches ? read.snapshot : null;
  if (snapshot?.state === 'RELEASED') {
    return { ok: false, state: 'REFUSED', reason: 'operation_closed_released' };
  }
  if (snapshot?.state === 'COMMITTED' && hasEvidenceDigest(snapshot)) {
    return { ok: false, state: 'COMMITTED', reason: 'operation_already_committed' };
  }
  if (snapshot?.state === 'ESCALATED') {
    return { ok: false, state: 'ESCALATED', reason: 'operation_escalated' };
  }
  return { ok: false, state: 'INDETERMINATE', reason: 'operation_already_reserved' };
}

async function markIndeterminate(store: StripeRefundDurableStore, binding: ConsequenceAttemptBinding, owner: ConsequenceAttemptOwnerHandle) {
  return store.transition({ ...attemptRef(binding, owner), expected_state: 'INVOKING', next_state: 'INDETERMINATE' });
}

async function commitVerified(
  store: StripeRefundDurableStore, binding: ConsequenceAttemptBinding,
  owner: ConsequenceAttemptOwnerHandle, evidence: AuthenticatedProviderEvidenceBinding,
) {
  return store.reconcile({
    ...attemptRef(binding, owner), expected_state: 'INDETERMINATE',
    next_state: 'COMMITTED', evidence,
  });
}

/**
 * At most one provider-entry attempt for a stable business operation on this
 * covered connector, assuming every mutation uses it, each Stripe account has
 * one owning tenant for this profile, and the durable PTE store is configured
 * correctly. An existing, uncertain or terminal attempt
 * never calls Stripe again, even with fresh receipts or after Stripe's
 * idempotency-key retention window.
 *
 * Before the first refunds.create for an operation, the connector lists the
 * payment intent's refunds under the recovery rules. A matching refund (for
 * example after the attempt row was lost to a restore) commits from that
 * refund without creating; a conflicting, ambiguous, incomplete or unavailable
 * view leaves the attempt INDETERMINATE without creating. The lookup is not
 * atomic with the create: two setups that lack each other's attempt row and
 * create at the same instant can both see no refund.
 */
export async function guardStripeRefundDurable(
  connector: StripeRefundDurableConnector,
  input: { operation_reference: string; receipt: unknown },
) {
  const outcome = await resolveOrRefuse(connector, input?.operation_reference);
  if ('refusal' in outcome) return { ok: false, state: 'REFUSED', reason: outcome.refusal };
  const { resolved } = outcome;
  const { config, p, action, binding, idempotencyKey, metadata } = resolved;
  let preflight: Awaited<ReturnType<Gate['check']>>;
  try {
    preflight = await config.gate.check({
      selector: SELECTOR, receipt: input?.receipt, observedAction: action,
      consumptionMode: 'none',
    });
  } catch {
    return { ok: false, state: 'REFUSED', reason: 'gate_check_failed' };
  }
  if (preflight?.allow !== true) {
    return { ok: false, state: 'REFUSED', reason: preflight?.reason || 'gate_refused' };
  }
  if (!durableRequirement(preflight.requirement)) {
    return { ok: false, state: 'REFUSED', reason: 'stripe_account_binding_profile_required' };
  }
  let reservation: Awaited<ReturnType<StripeRefundDurableStore['reserve']>>;
  try {
    reservation = await config.store.reserve(binding);
  } catch {
    return { ok: false, state: 'INDETERMINATE', reason: 'attempt_store_unavailable' };
  }
  if (!reservation.reserved) return existingAttemptOutcome(config.store, binding);
  const { owner } = reservation;
  if (!await config.store.transition({
    ...attemptRef(binding, owner), expected_state: 'RESERVED', next_state: 'INVOKING',
  }).catch(() => false)) {
    return { ok: false, state: 'INDETERMINATE', reason: 'attempt_transition_failed' };
  }
  let entered = false;
  let callbackOpen = true;
  let callbackClaimed = false;
  let foundExisting = false;
  let providerHold: ProviderHoldReason | null = null;
  let providerEvidence: AuthenticatedProviderEvidenceBinding | null = null;
  let gateResult: Awaited<ReturnType<Gate['run']>> | null = null;
  try {
    gateResult = await config.gate.run({
      selector: SELECTOR, receipt: input.receipt, observedAction: action,
    }, async (authorization) => {
      // A Gate implementation must not turn one reserved attempt into more
      // than one provider call, even if it invokes or resumes the callback
      // more than once.
      if (!callbackOpen) throw new Error('stripe_refund_provider_callback_closed');
      if (callbackClaimed) throw new Error('stripe_refund_provider_callback_already_claimed');
      callbackClaimed = true;
      if (authorization?.allow !== true || !durableRequirement(authorization.requirement)
          || verifyExecutionBinding({
            requirement: authorization.requirement,
            receipt: input.receipt,
            observedAction: action,
          }).ok !== true) {
        throw new Error('stripe_account_binding_profile_changed');
      }
      const account = await config.stripe.accounts.retrieve();
      if (!callbackOpen) throw new Error('stripe_refund_provider_callback_closed');
      if (account?.id !== config.account_id) throw new Error('stripe_account_changed');
      // The attempt row is the primary fence. If it was lost (a restore from an
      // older backup, or a second setup on this account), Stripe's idempotency
      // cache may have expired too, so look for this operation's refund first.
      const existing = await inspectProviderRefunds(resolved);
      if (!callbackOpen) throw new Error('stripe_refund_provider_callback_closed');
      if (existing.outcome === 'match') {
        foundExisting = true;
        providerEvidence = existing.evidence;
        return existing.record;
      }
      if (existing.outcome === 'held') {
        providerHold = existing.reason;
        throw new Error(existing.reason);
      }
      entered = true;
      const result = await config.stripe.refunds.create({
        payment_intent: p.payment_intent, amount: p.amount, metadata,
      }, { idempotencyKey });
      providerEvidence = positiveRefundEvidence(refundView(result), resolved);
      if (!providerEvidence) throw new Error('stripe_refund_response_unverified');
      return result;
    });
  } catch {
    // Even a known client exception can mean Stripe accepted the refund and
    // its response was lost. Do not retry or free the operation ID.
  } finally {
    callbackOpen = false;
  }
  if (!await markIndeterminate(config.store, binding, owner).catch(() => false)) {
    return { ok: false, state: 'INDETERMINATE', reason: 'attempt_freeze_failed' };
  }
  if (providerEvidence) {
    const committed = await commitVerified(config.store, binding, owner, providerEvidence).catch(() => false);
    if (committed) {
      return gateResult?.ok === true
        ? { ok: true, state: 'COMMITTED',
          ...(foundExisting ? { reason: 'provider_effect_already_present' } : {}),
          refund: gateResult.result ?? null,
          reliance: gateResult.packet ?? null, execution: gateResult.execution ?? null }
        : { ok: false, state: 'COMMITTED', reason: 'provider_created_gate_outcome_unknown' };
    }
    return { ok: false, state: 'INDETERMINATE', reason: 'attempt_commit_failed' };
  }
  // A held provider view means a refund for this operation may already exist.
  // Never release that attempt, whatever the Gate reported.
  if (providerHold) return { ok: false, state: 'INDETERMINATE', reason: providerHold };
  if (!entered && gateResult?.ok === false) {
    const released = await config.store.transition({
      ...attemptRef(binding, owner), expected_state: 'INDETERMINATE', next_state: 'RELEASED',
    }).catch(() => false);
    return { ok: false, state: released ? 'RELEASED' : 'INDETERMINATE',
      reason: gateResult.authorization?.reason || 'gate_refused' };
  }
  return { ok: false, state: 'INDETERMINATE', reason: entered
    ? 'stripe_refund_outcome_unknown' : 'provider_entry_unknown' };
}

/**
 * Recovery never calls refunds.create. A bounded list query supplies positive
 * evidence only if exactly one matching refund is found, no other listed refund
 * carries this operation's metadata, and the page is complete. Empty,
 * incomplete, unavailable, or conflicting results stay INDETERMINATE; none
 * proves NOT_COMMITTED.
 * The server-secret tag narrows accidental/external collision, but it can be
 * copied by an actor with access to both the Stripe metadata and refund-write
 * credentials. A matching object proves existence, not exclusive authorship.
 */
export async function reconcileStripeRefundDurable(
  connector: StripeRefundDurableConnector,
  operation_reference: string,
) {
  const outcome = await resolveOrRefuse(connector, operation_reference);
  if ('refusal' in outcome) return { ok: false, state: 'INDETERMINATE', reason: outcome.refusal };
  const { resolved } = outcome;
  const { config, binding } = resolved;
  const read = await readAttempt(config.store, binding);
  if (!read.found) return { ok: false, state: 'INDETERMINATE', reason: 'attempt_not_found_or_unavailable' };
  if (!read.matches) return { ok: false, state: 'INDETERMINATE', reason: 'attempt_binding_mismatch' };
  const { snapshot } = read;
  if (snapshot.state === 'COMMITTED') {
    return hasEvidenceDigest(snapshot)
      ? { ok: true, state: 'COMMITTED', reason: 'previously_verified' }
      : { ok: false, state: 'INDETERMINATE', reason: 'terminal_without_provider_evidence' };
  }
  if (snapshot.state === 'RELEASED' || snapshot.state === 'ESCALATED') {
    return { ok: false, state: snapshot.state, reason: 'attempt_terminal' };
  }
  // A live owner might still be entering Stripe; recovery must not steal it.
  if (!snapshot.lease_stale) {
    return { ok: false, state: 'INDETERMINATE', reason: 'attempt_owner_active' };
  }
  const recovered = await config.store.recover(attemptReference(binding))
    .catch(() => ({ recovered: false as const }));
  if (!recovered.recovered) {
    return { ok: false, state: 'INDETERMINATE', reason: 'attempt_recovery_refused' };
  }
  if (recovered.state === 'RESERVED') {
    // No provider entry occurred in RESERVED. Do not invent a provider result;
    // the operation remains held for an explicit owner decision.
    return { ok: false, state: 'RESERVED', reason: 'attempt_not_invoked' };
  }
  const view = await inspectProviderRefunds(resolved);
  if (view.outcome === 'held') return { ok: false, state: 'INDETERMINATE', reason: view.reason };
  if (view.outcome === 'absent') {
    return { ok: false, state: 'INDETERMINATE', reason: 'provider_effect_unproven' };
  }
  const committed = await commitVerified(config.store, binding, recovered.owner, view.evidence).catch(() => false);
  return committed
    ? { ok: true, state: 'COMMITTED', refund_id: view.evidence.evidence_id }
    : { ok: false, state: 'INDETERMINATE', reason: 'attempt_commit_failed' };
}

export default {
  STRIPE_REFUND_DURABLE_ACTION_TYPE,
  createStripeDurableRefundManifest,
  stripeRefundAttemptDigests,
  createStripeRefundDurableStore,
  createStripeRefundDurableConnector,
  guardStripeRefundDurable,
  reconcileStripeRefundDurable,
};
