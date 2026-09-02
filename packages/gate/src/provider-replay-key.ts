// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate - native provider replay-key derivation.
 *
 * WHAT THIS IS. Providers already expose a caller-chosen replay slot: Stripe's
 * Idempotency-Key, an ERC-3009 nonce, an ISO 20022 EndToEndId, an AWS
 * ClientToken, an MCP tools/call _meta member. Today callers fill those slots
 * with a random value. This module fills them with a value DERIVED from the
 * authorization instance, so the provider's own duplicate-detection engine
 * becomes a second consumer of that one authorization, and so any party
 * holding the authorization can recompute the provider's reference and join
 * the provider's own record to the authorization with no lookup table.
 *
 * WHAT THIS IS NOT. It asks no provider for a new signed record, no new
 * endpoint, and no protocol change. The provider treats the value as opaque;
 * nothing here compels a provider to recompute the derivation, and nothing
 * here claims a provider attests to anything. The scope limits are stated in
 * PROVIDER_CARRIAGE_TABLE row by row, including the rows where a provider's
 * retention window is shorter than a realistic authorization lifetime.
 *
 * FAIL-CLOSED. Every entry point returns { ok: false, reason } for malformed
 * or uncarryable input. It does not throw on bad input, and it never returns a
 * partial or best-effort key.
 *
 * NOT A SECRET. The HMAC key is the version label, not key material. Domain
 * separation is the only thing it buys. Any party holding the authorization
 * instance digest can recompute the key, which is the point: a reconciler must
 * be able to. Do not treat the derived value as a capability or a bearer
 * token, and do not derive it from anything you would not publish to the
 * provider.
 */
import crypto from 'node:crypto';

import { canonicalize } from './execution-binding.js';

/** Versioned derivation string. Changing any input rule changes this label. */
export const PROVIDER_REPLAY_KEY_VERSION = 'EP-PROVIDER-REPLAY-KEY-v1';

/** Versioned carriage table. Rows are added under a new label, never mutated. */
export const PROVIDER_CARRIAGE_TABLE_VERSION = 'EP-PROVIDER-REPLAY-CARRIAGE-v1';

/**
 * Version label for the derivation of an authorization INSTANCE digest from an
 * authorization artifact plus the one material action it authorizes.
 */
export const AUTHORIZATION_INSTANCE_VERSION = 'EP-AUTHORIZATION-INSTANCE-v1';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_STRING_RE = /^caid:1:[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(-[a-z0-9]+)*:[A-Za-z0-9_-]+$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)*\.[1-9][0-9]*$/;
const PROFILE_ACTION_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/;
const PROVIDER_ENV_RE = /^[A-Za-z0-9][A-Za-z0-9._:+/@~-]{0,127}$/;
const ATTEMPT_GROUP_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const SLOT_ID_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)*$/;
const PRINTABLE_ASCII_RE = /^[\x20-\x7e]*$/;

const MAX_ENCODED_LENGTH = 512;
const DEFAULT_MIN_ENTROPY_BITS = 96;

export type ProviderReplayKeyRefusal =
  | 'authorization_digest_invalid'
  | 'caid_invalid'
  | 'provider_env_invalid'
  | 'attempt_group_invalid'
  | 'slot_spec_invalid'
  | 'slot_id_invalid'
  | 'slot_charset_invalid'
  | 'slot_encoded_length_invalid'
  | 'slot_prefix_invalid'
  | 'slot_prefix_charset_violation'
  | 'slot_max_length_invalid'
  | 'slot_length_exceeds_max'
  | 'slot_capacity_insufficient'
  | 'slot_content_rule_violation'
  | 'derivation_input_uncanonicalizable';

export interface ProviderSlotSpec {
  /** Stable identifier of the carrier slot; enters the derivation preimage. */
  readonly slot_id: string;
  /** Characters the provider accepts in this slot. Order is significant. */
  readonly charset: string;
  /** Number of derived characters to emit (excludes any literal prefix). */
  readonly encoded_length: number;
  /** Total field length the provider accepts, prefix included. */
  readonly max_length: number;
  /** Literal prefix the provider or our own record format requires. */
  readonly prefix?: string;
  /** Whether the slot's charset also constrains the prefix. */
  readonly charset_applies_to_prefix?: boolean;
  /** Refuse below this many bits carried by the encoded portion. */
  readonly min_entropy_bits?: number;
  /** The final value must not start with any of these. */
  readonly forbid_leading?: readonly string[];
  /** The final value must not end with any of these. */
  readonly forbid_trailing?: readonly string[];
  /** The final value must not contain any of these. */
  readonly forbid_substrings?: readonly string[];
}

export interface ProviderReplayKeyInput {
  /** sha256:<hex> over the exact authorization instance. See authorizationInstanceDigest. */
  readonly authorization_digest: string;
  /** A full CAID string, or the registered action-type identifier of the action. */
  readonly caid: string;
  /** Provider environment: which account, network, region and mode this key lands in. */
  readonly provider_env: string;
  /**
   * Attempt group. The SAME group under the SAME authorization always yields the
   * SAME key, which is what makes a legitimate retry return the provider's stored
   * result. A different authorization always yields a different key regardless of
   * group. Changing the group under one authorization deliberately releases the
   * provider-side fence for that authorization and must be an explicit, recorded
   * operator act, never a default retry behaviour.
   */
  readonly attempt_group: string;
  readonly slot_spec: ProviderSlotSpec;
}

export interface ProviderReplayKeyResult {
  readonly ok: true;
  /** The value to place in the provider's slot, prefix included. */
  readonly key: string;
  readonly slot_id: string;
  /** Bits of the 256-bit MAC actually carried by the encoded portion. */
  readonly entropy_bits: number;
  readonly derivation: {
    readonly version: string;
    readonly authorization_digest: string;
    readonly caid: string;
    readonly provider_env: string;
    readonly attempt_group: string;
    readonly slot_id: string;
  };
}

export interface ProviderReplayKeyRefusalResult {
  readonly ok: false;
  readonly reason: ProviderReplayKeyRefusal;
  /** Human-readable detail. Safe to log; carries no secret material. */
  readonly detail: string;
}

export type ProviderReplayKeyOutcome =
  | ProviderReplayKeyResult
  | ProviderReplayKeyRefusalResult;

function refuse(
  reason: ProviderReplayKeyRefusal,
  detail: string,
): ProviderReplayKeyRefusalResult {
  return { ok: false, reason, detail };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * A CAID string, or a bare action identifier for actions a profile pins that
 * the public CAID registry does not define. Both shapes are accepted on
 * purpose: the Stripe adapter's `stripe.payout.create` is a profile-pinned
 * action identifier, not a registered CAID type, and refusing it would leave
 * the adapter on its old caller-supplied key.
 */
function validCaid(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) return false;
  if (value.startsWith('caid:')) return CAID_STRING_RE.test(value);
  return ACTION_TYPE_RE.test(value) || PROFILE_ACTION_RE.test(value);
}

function validateSlotSpec(
  slotSpec: unknown,
): { ok: true; spec: Required<Pick<ProviderSlotSpec, 'slot_id' | 'charset' | 'encoded_length' | 'max_length'>> & {
  prefix: string;
  minEntropyBits: number;
  forbidLeading: readonly string[];
  forbidTrailing: readonly string[];
  forbidSubstrings: readonly string[];
  charsetAppliesToPrefix: boolean;
} } | ProviderReplayKeyRefusalResult {
  if (!isPlainObject(slotSpec)) {
    return refuse('slot_spec_invalid', 'slot_spec must be a plain object');
  }
  const {
    slot_id: slotId,
    charset,
    encoded_length: encodedLength,
    max_length: maxLength,
    prefix = '',
    charset_applies_to_prefix: charsetAppliesToPrefix = false,
    min_entropy_bits: minEntropyBits = DEFAULT_MIN_ENTROPY_BITS,
    forbid_leading: forbidLeading = [],
    forbid_trailing: forbidTrailing = [],
    forbid_substrings: forbidSubstrings = [],
  } = slotSpec as Record<string, any>;

  if (typeof slotId !== 'string' || !SLOT_ID_RE.test(slotId) || slotId.length > 128) {
    return refuse('slot_id_invalid', 'slot_id must be a dotted lowercase identifier');
  }
  if (typeof charset !== 'string' || charset.length < 2 || charset.length > 128) {
    return refuse('slot_charset_invalid', 'charset must hold between 2 and 128 characters');
  }
  if (!PRINTABLE_ASCII_RE.test(charset)) {
    return refuse('slot_charset_invalid', 'charset must be printable ASCII');
  }
  if (new Set(charset).size !== charset.length) {
    return refuse('slot_charset_invalid', 'charset contains a repeated character');
  }
  if (!Number.isSafeInteger(encodedLength) || encodedLength < 1 || encodedLength > MAX_ENCODED_LENGTH) {
    return refuse('slot_encoded_length_invalid', `encoded_length must be an integer in 1..${MAX_ENCODED_LENGTH}`);
  }
  if (!Number.isSafeInteger(maxLength) || maxLength < 1 || maxLength > 4096) {
    return refuse('slot_max_length_invalid', 'max_length must be an integer in 1..4096');
  }
  if (typeof prefix !== 'string' || prefix.length > 128 || !PRINTABLE_ASCII_RE.test(prefix)) {
    return refuse('slot_prefix_invalid', 'prefix must be printable ASCII of at most 128 characters');
  }
  if (charsetAppliesToPrefix !== true && charsetAppliesToPrefix !== false) {
    return refuse('slot_spec_invalid', 'charset_applies_to_prefix must be a boolean');
  }
  if (charsetAppliesToPrefix) {
    const allowed = new Set(charset);
    for (const character of prefix) {
      if (!allowed.has(character)) {
        return refuse(
          'slot_prefix_charset_violation',
          `prefix character ${JSON.stringify(character)} is outside the slot charset`,
        );
      }
    }
  }
  if (prefix.length + encodedLength > maxLength) {
    return refuse(
      'slot_length_exceeds_max',
      `prefix (${prefix.length}) plus encoded_length (${encodedLength}) exceeds max_length (${maxLength})`,
    );
  }
  if (!Number.isSafeInteger(minEntropyBits) || minEntropyBits < 1 || minEntropyBits > 256) {
    return refuse('slot_spec_invalid', 'min_entropy_bits must be an integer in 1..256');
  }
  for (const [name, list] of [
    ['forbid_leading', forbidLeading],
    ['forbid_trailing', forbidTrailing],
    ['forbid_substrings', forbidSubstrings],
  ] as const) {
    if (!Array.isArray(list) || list.length > 32
      || list.some((entry) => typeof entry !== 'string' || entry.length === 0 || entry.length > 32)) {
      return refuse('slot_spec_invalid', `${name} must be an array of at most 32 short strings`);
    }
  }
  return {
    ok: true,
    spec: {
      slot_id: slotId,
      charset,
      encoded_length: encodedLength,
      max_length: maxLength,
      prefix,
      minEntropyBits,
      forbidLeading,
      forbidTrailing,
      forbidSubstrings,
      charsetAppliesToPrefix,
    },
  };
}

/**
 * Bits of the MAC a slot can actually carry: floor(length * log2(radix)),
 * capped at the 256 bits the MAC holds. Computed with integers so no float
 * rounding can inflate the answer past what the slot really carries.
 */
function carriedEntropyBits(radix: number, length: number): number {
  let capacity = 1n;
  const radixBig = BigInt(radix);
  for (let i = 0; i < length; i++) {
    capacity *= radixBig;
    if (capacity > 1n << 256n) return 256;
  }
  let bits = 0;
  let bound = 2n;
  while (bound <= capacity) {
    bits += 1;
    bound <<= 1n;
    if (bits >= 256) break;
  }
  return bits;
}

function encodeToCharset(macHex: string, charset: string, length: number): string {
  const radix = BigInt(charset.length);
  let modulus = 1n;
  for (let i = 0; i < length; i++) modulus *= radix;
  let value = BigInt(`0x${macHex}`) % modulus;
  const digits: string[] = [];
  for (let i = 0; i < length; i++) {
    digits.push(charset[Number(value % radix)]);
    value /= radix;
  }
  return digits.reverse().join('');
}

/**
 * Derive the value to place in a provider's caller-chosen replay slot.
 *
 * Same authorization instance + same attempt group + same slot => same key, on
 * any machine, offline, forever. Different authorization instance => different
 * key. Different slot => different key, so a value observed in one carrier can
 * never be replayed into another.
 */
export function deriveProviderReplayKey(
  input: ProviderReplayKeyInput,
): ProviderReplayKeyOutcome;
export function deriveProviderReplayKey(
  authorizationDigest: string,
  caid: string,
  providerEnv: string,
  attemptGroup: string,
  slotSpec: ProviderSlotSpec,
): ProviderReplayKeyOutcome;
export function deriveProviderReplayKey(
  first: ProviderReplayKeyInput | string,
  caidArg?: string,
  providerEnvArg?: string,
  attemptGroupArg?: string,
  slotSpecArg?: ProviderSlotSpec,
): ProviderReplayKeyOutcome {
  const args: Partial<ProviderReplayKeyInput> = typeof first === 'string'
    ? {
      authorization_digest: first,
      caid: caidArg,
      provider_env: providerEnvArg,
      attempt_group: attemptGroupArg,
      slot_spec: slotSpecArg,
    }
    : (isPlainObject(first) ? first as ProviderReplayKeyInput : {});

  const {
    authorization_digest: authorizationDigest,
    caid,
    provider_env: providerEnv,
    attempt_group: attemptGroup,
    slot_spec: slotSpec,
  } = args;

  if (typeof authorizationDigest !== 'string' || !DIGEST_RE.test(authorizationDigest)) {
    return refuse('authorization_digest_invalid', 'authorization_digest must match sha256:<64 lowercase hex>');
  }
  if (!validCaid(caid)) {
    return refuse('caid_invalid', 'caid must be a CAID string or a dotted lowercase action identifier');
  }
  if (typeof providerEnv !== 'string' || !PROVIDER_ENV_RE.test(providerEnv)) {
    return refuse('provider_env_invalid', 'provider_env must be 1..128 characters of [A-Za-z0-9._:+/-]');
  }
  if (typeof attemptGroup !== 'string' || !ATTEMPT_GROUP_RE.test(attemptGroup)) {
    return refuse('attempt_group_invalid', 'attempt_group must be 1..64 characters of [A-Za-z0-9._:-]');
  }
  const validated = validateSlotSpec(slotSpec);
  if (validated.ok !== true) return validated;
  const spec = validated.spec;

  const entropyBits = carriedEntropyBits(spec.charset.length, spec.encoded_length);
  if (entropyBits < spec.minEntropyBits) {
    return refuse(
      'slot_capacity_insufficient',
      `slot carries ${entropyBits} bits, below the ${spec.minEntropyBits} bits this slot requires`,
    );
  }

  let preimage: string;
  try {
    preimage = canonicalize({
      '@version': PROVIDER_REPLAY_KEY_VERSION,
      attempt_group: attemptGroup,
      authorization_digest: authorizationDigest,
      caid,
      provider_env: providerEnv,
      slot_id: spec.slot_id,
    });
  } catch {
    return refuse('derivation_input_uncanonicalizable', 'derivation inputs are not canonical JSON');
  }

  // Domain separation, not secrecy: the key is the public version label. See
  // the NOT A SECRET note at the top of this file.
  // codeql[js/insufficient-password-hash]
  const mac = crypto
    .createHmac('sha256', Buffer.from(PROVIDER_REPLAY_KEY_VERSION, 'utf8'))
    .update(Buffer.from(preimage, 'utf8'))
    .digest('hex');

  const key = `${spec.prefix}${encodeToCharset(mac, spec.charset, spec.encoded_length)}`;

  for (const forbidden of spec.forbidLeading) {
    if (key.startsWith(forbidden)) {
      return refuse('slot_content_rule_violation', `derived value starts with the forbidden sequence ${JSON.stringify(forbidden)}`);
    }
  }
  for (const forbidden of spec.forbidTrailing) {
    if (key.endsWith(forbidden)) {
      return refuse('slot_content_rule_violation', `derived value ends with the forbidden sequence ${JSON.stringify(forbidden)}`);
    }
  }
  for (const forbidden of spec.forbidSubstrings) {
    if (key.includes(forbidden)) {
      return refuse('slot_content_rule_violation', `derived value contains the forbidden sequence ${JSON.stringify(forbidden)}`);
    }
  }

  return {
    ok: true,
    key,
    slot_id: spec.slot_id,
    entropy_bits: entropyBits,
    derivation: {
      version: PROVIDER_REPLAY_KEY_VERSION,
      authorization_digest: authorizationDigest,
      caid,
      provider_env: providerEnv,
      attempt_group: attemptGroup,
      slot_id: spec.slot_id,
    },
  };
}

/**
 * Recompute and compare. This is what a reconciler runs against a value it read
 * out of a provider's own authenticated record: it establishes only that the
 * value recomputes from the authorization the reconciler holds. It establishes
 * nothing about whether the provider executed, accepted, or attested anything.
 */
export function matchesProviderReplayKey(
  candidate: unknown,
  input: ProviderReplayKeyInput,
): { ok: true } | { ok: false; reason: ProviderReplayKeyRefusal | 'replay_key_mismatch'; detail: string } {
  const derived = deriveProviderReplayKey(input);
  if (derived.ok !== true) return derived;
  if (typeof candidate !== 'string' || candidate.length !== derived.key.length) {
    return { ok: false, reason: 'replay_key_mismatch', detail: 'candidate is not a string of the derived length' };
  }
  const a = Buffer.from(candidate, 'utf8');
  const b = Buffer.from(derived.key, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'replay_key_mismatch', detail: 'candidate does not recompute from this authorization' };
  }
  return { ok: true };
}

/**
 * Bind an authorization artifact to the ONE material action it authorizes and
 * return the instance digest the derivation consumes.
 *
 * `material_action` must exclude any request-wrapper field (an operation id, a
 * request id, a timestamp). Excluding the wrapper is what makes a retry of one
 * action produce the same provider key; including it would mint a new provider
 * key per attempt and defeat the whole mechanism.
 */
export function authorizationInstanceDigest({
  authorization_digest: authorizationDigest,
  material_action: materialAction,
  profile,
}: {
  authorization_digest: string;
  material_action: unknown;
  profile: string;
}): { ok: true; digest: string } | { ok: false; reason: string; detail: string } {
  if (typeof authorizationDigest !== 'string' || !DIGEST_RE.test(authorizationDigest)) {
    return { ok: false, reason: 'authorization_digest_invalid', detail: 'authorization_digest must match sha256:<64 lowercase hex>' };
  }
  if (typeof profile !== 'string' || !PROFILE_ACTION_RE.test(profile) || profile.length > 256) {
    return { ok: false, reason: 'profile_invalid', detail: 'profile must be a dotted lowercase identifier' };
  }
  if (!isPlainObject(materialAction) || Object.keys(materialAction).length === 0) {
    return { ok: false, reason: 'material_action_invalid', detail: 'material_action must be a non-empty plain object' };
  }
  let canonical: string;
  try {
    canonical = canonicalize({
      '@version': AUTHORIZATION_INSTANCE_VERSION,
      authorization_digest: authorizationDigest,
      material_action: materialAction,
      profile,
    });
  } catch {
    return { ok: false, reason: 'material_action_uncanonicalizable', detail: 'material_action is not canonical JSON under the EP profile' };
  }
  // Content addressing, not credential storage.
  // codeql[js/insufficient-password-hash]
  const digest = crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
  return { ok: true, digest: `sha256:${digest}` };
}

// ---------------------------------------------------------------------------
// Slot specs
// ---------------------------------------------------------------------------

const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX_LOWER = '0123456789abcdef';
// SEPA restricts references and identifications to this Latin set. The full
// SEPA set also allows / - ? : ( ) . , ' + and space; the derivation uses the
// alphanumeric subset only, so a derived EndToEndId can never contain a '/'
// and can never trip the "must not contain //" or "must not start or end with
// /" content rules. See EPC132-08 section 1.4.
const SEPA_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export const MCP_META_REPLAY_KEY = 'ai.emiliaprotocol/authorization-replay-key';

export const PROVIDER_SLOT_SPECS = Object.freeze({
  /** MCP tools/call params._meta member. */
  'mcp.tools-call.meta': Object.freeze({
    slot_id: 'mcp.tools-call.meta',
    charset: BASE62,
    encoded_length: 43,
    max_length: 256,
    min_entropy_bits: 128,
  }) as ProviderSlotSpec,
  /** Stripe Idempotency-Key request header. */
  'stripe.idempotency-key': Object.freeze({
    slot_id: 'stripe.idempotency-key',
    charset: BASE62,
    encoded_length: 43,
    max_length: 255,
    prefix: 'ep1_',
    min_entropy_bits: 128,
  }) as ProviderSlotSpec,
  /** ERC-3009 bytes32 nonce, hex encoded with the 0x prefix. */
  'eip3009.nonce': Object.freeze({
    slot_id: 'eip3009.nonce',
    charset: HEX_LOWER,
    encoded_length: 64,
    max_length: 66,
    prefix: '0x',
    min_entropy_bits: 256,
  }) as ProviderSlotSpec,
  /** ISO 20022 EndToEndIdentification, Max35Text under the SEPA Latin set. */
  'iso20022.end-to-end-id': Object.freeze({
    slot_id: 'iso20022.end-to-end-id',
    charset: SEPA_ALNUM,
    encoded_length: 31,
    max_length: 35,
    prefix: 'EP1',
    charset_applies_to_prefix: true,
    min_entropy_bits: 128,
    forbid_leading: ['/'],
    forbid_trailing: ['/'],
    forbid_substrings: ['//'],
  }) as ProviderSlotSpec,
  /** AWS EC2 RunInstances ClientToken: up to 64 ASCII characters. */
  'aws.ec2.run-instances.client-token': Object.freeze({
    slot_id: 'aws.ec2.run-instances.client-token',
    charset: BASE62,
    encoded_length: 43,
    max_length: 64,
    prefix: 'ep1-',
    min_entropy_bits: 128,
  }) as ProviderSlotSpec,
  /**
   * EMILIA action-escrow provider release key. Not a third-party carrier: this
   * is our own record format, kept in the same derivation so the escrow key and
   * a carrier key are produced by one rule.
   */
  'ep.action-escrow.release': Object.freeze({
    slot_id: 'ep.action-escrow.release',
    charset: HEX_LOWER,
    encoded_length: 64,
    max_length: 256,
    prefix: 'ep-ae-release:',
    min_entropy_bits: 256,
  }) as ProviderSlotSpec,
});

// ---------------------------------------------------------------------------
// Carriage table
// ---------------------------------------------------------------------------

/**
 * Per-carrier facts an adapter needs before it puts a derived value in a slot.
 *
 * VERIFICATION RULE. Every field whose value is the literal string 'unverified'
 * was NOT confirmed from the provider's own documentation during the run that
 * wrote this table. Do not guess and do not fill one in from recollection.
 * Replace it only with text traced to a provider document you opened, and add
 * the locator to `sources`.
 */
export interface CarriageRow {
  readonly id: string;
  readonly carrier: string;
  readonly slot: string;
  readonly slot_spec: ProviderSlotSpec;
  /** Field length and charset as the provider states them. */
  readonly slot_length: string;
  readonly slot_charset: string;
  /** How long the provider keeps the key for duplicate detection. */
  readonly retention: string;
  /** What the key is unique within. */
  readonly scope: string;
  /** Whether a party on the dispatch path can rewrite the field. */
  readonly intermediary_rewrite: string;
  /** Where the value comes back in the provider's own authenticated record. */
  readonly echo: string;
  /** What the provider does on same key, different parameters. */
  readonly mismatch_behaviour: string;
  /** Documents opened while writing this row. */
  readonly sources: readonly string[];
  /** Anything an adapter author would otherwise get wrong. */
  readonly notes: string;
}

export const PROVIDER_CARRIAGE_TABLE: readonly CarriageRow[] = Object.freeze([
  Object.freeze({
    id: 'mcp.tools-call.meta',
    carrier: 'Model Context Protocol, tools/call request',
    slot: `params._meta["${MCP_META_REPLAY_KEY}"]`,
    slot_spec: PROVIDER_SLOT_SPECS['mcp.tools-call.meta'],
    slot_length: 'unverified: the specification sets no length bound on a _meta value; 256 is our own cap',
    slot_charset: 'JSON string. The KEY name grammar is specified: an optional reverse-DNS prefix ending in "/", then a name that begins and ends with [a-z0-9A-Z] and may contain - _ . between. Any prefix whose second label is "modelcontextprotocol" or "mcp" is reserved; "ai.emiliaprotocol/" is not reserved and is therefore usable by a third-party extension.',
    retention: 'unverified: the base protocol defines no idempotency or duplicate-detection mechanism at all, so any window is the individual server\'s, not the protocol\'s',
    scope: 'unverified: no scope is defined because no dedupe mechanism is defined. The protocol is explicitly stateless ("Servers MUST NOT rely on prior requests over the same connection"), so a server that dedupes must key on request content, not on connection identity.',
    intermediary_rewrite: 'unverified: the specification does not state whether a proxy or gateway must preserve third-party _meta members. Treat rewrite as possible.',
    echo: 'unverified: nothing in the base protocol requires a server to echo a request _meta member into its result _meta',
    mismatch_behaviour: 'not applicable: no duplicate-detection engine exists in the base protocol. A server adopting this key defines its own semantics.',
    sources: [
      'https://modelcontextprotocol.io/specification/draft/basic (opened 2026-09-02): sections "Statelessness" and "General fields / _meta", including the key-name grammar and reserved-prefix rules',
    ],
    notes: 'This is the one row with no compelled reader today. The MCP row is a PROPOSAL to servers, not a fence we can rely on. Say so; do not describe it as an enforcement point.',
  }),
  Object.freeze({
    id: 'stripe.idempotency-key',
    carrier: 'Stripe REST API, POST requests',
    slot: 'Idempotency-Key request header',
    slot_spec: PROVIDER_SLOT_SPECS['stripe.idempotency-key'],
    slot_length: 'Verified: "Idempotency keys are up to 255 characters long."',
    slot_charset: 'unverified: Stripe states no charset, only a length bound and a recommendation to use a V4 UUID "or another random string with enough entropy". Base62 plus an "ep1_" prefix is our conservative choice.',
    retention: 'Verified: "You can remove keys from the system automatically after they are at least 24 hours old. We generate a new request if a key is reused after the original is pruned." and "keys expire out of the system after 24 hours".',
    scope: 'Account scope verified: keys must be "sufficiently unique to unambiguously identify a single operation within your account over the last 24 hours". ENDPOINT scope unverified: neither page opened this run states that keys are partitioned per endpoint. Do not repeat the common claim that Stripe keys are scoped per endpoint until a Stripe document says so.',
    intermediary_rewrite: 'unverified: an HTTP proxy on the dispatch path could strip or replace the header and Stripe documents nothing about it. Our adapter sets it on the request it issues, which is the last hop we control.',
    echo: 'Two echoes, both verified. A replayed response carries the header "Idempotent-Replayed: true". Separately, a local identifier sent in `metadata` "appears in the metadata field of an object going out through a webhook, even if the webhook is generated later as part of reconciliation" - that is the join key inside Stripe\'s own signed event, and it is why the adapter echoes the derived value into metadata as well as the header.',
    mismatch_behaviour: 'Verified: "The idempotency layer compares incoming parameters to those of the original request and errors if they are not the same." Status 409 Conflict is documented for a request that conflicts with another using the same idempotent key.',
    sources: [
      'https://docs.stripe.com/api/idempotent_requests (opened 2026-09-02)',
      'https://docs.stripe.com/error-low-level (opened 2026-09-02), section "Idempotency"',
    ],
    notes: 'Stripe caches the result only after endpoint execution begins; a request that fails validation or races another request is not saved, so a retry is a fresh request. The 24 hour window is the whole of the provider-consumption claim on this rail. See PROVIDER_KEY_RETENTION_MEASUREMENT.',
  }),
  Object.freeze({
    id: 'eip3009.nonce',
    carrier: 'ERC-3009 transferWithAuthorization / receiveWithAuthorization',
    slot: 'bytes32 nonce, inside the EIP-712 signed struct',
    slot_spec: PROVIDER_SLOT_SPECS['eip3009.nonce'],
    slot_length: 'Verified: bytes32, exactly 32 bytes.',
    slot_charset: 'Verified: raw 32 bytes; any 256-bit value is admissible. The ERC describes nonces as "randomly generated 32-byte data unique to the authorizer\'s address" but the contract only checks prior use, so a derived value is admissible.',
    retention: 'Verified: permanent. `_authorizationStates[from][nonce] = true` is set on use and the ERC defines no pruning. Nonces do not expire; validAfter and validBefore bound the authorization, not the nonce record.',
    scope: 'Verified: per authorizer address per contract. The state is `mapping(address => mapping(bytes32 => bool)) internal _authorizationStates`.',
    intermediary_rewrite: 'Verified as impossible without invalidating the transfer: the nonce is a member of the EIP-712 typed struct the authorizer signs, so a relayer that alters it fails signature recovery ("EIP3009: invalid signature").',
    echo: 'Verified: `event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)`, and the public view `authorizationState(authorizer, nonce)`.',
    mismatch_behaviour: 'Verified: reuse reverts with "EIP3009: authorization is used". There is no stored-result replay; the second attempt fails outright.',
    sources: [
      'https://raw.githubusercontent.com/ethereum/ercs/master/ERCS/erc-3009.md (opened 2026-09-02): interface, rationale section "Unique Random Nonce, Instead of Sequential Nonce", and the reference implementation',
    ],
    notes: 'The strongest row by a wide margin: permanent retention, an authenticated echo, and an intermediary that cannot rewrite the field. It is also the row where the provider-side fence is a hard revert rather than a stored result, so the caller must distinguish "already executed" from "failed".',
  }),
  Object.freeze({
    id: 'iso20022.end-to-end-id',
    carrier: 'ISO 20022 pain.001.001.09 customer credit transfer initiation, SEPA profile',
    slot: 'CdtTrfTxInf/PmtId/EndToEndId',
    slot_spec: PROVIDER_SLOT_SPECS['iso20022.end-to-end-id'],
    slot_length: 'Verified: Type Max35Text, ISO Length 1..35, SEPA Length 1..35.',
    slot_charset: 'Verified: the SEPA Latin set is a-z A-Z 0-9 and / - ? : ( ) . , \' + and space. References and identifications additionally "must not start or end with a /" and "must not contain //". The derivation uses the alphanumeric subset only, so those two rules cannot be tripped.',
    retention: 'unverified: the implementation guidelines opened this run state no retention or duplicate-check window keyed on EndToEndId. A SEPA reject reason code AM05 "Duplication / Duplicate payment" exists, but the guidelines do not say which field a PSP keys it on or for how long. Do not claim banks dedupe on EndToEndId.',
    scope: 'unverified as an enforced uniqueness domain. The ISO definition is that the initiating party assigns it "to unambiguously identify the transaction", which is an instruction to the sender, not a uniqueness constraint the receiver enforces.',
    intermediary_rewrite: 'Rule verified, enforcement unverified: "This identification is passed on, unchanged, throughout the entire end-to-end chain." That is a scheme rule. Nothing opened this run says what happens when a PSP breaks it.',
    echo: 'Verified: pain.002.001.10 customer payment status report carries OrgnlEndToEndId, Max35Text, the original value returned unchanged.',
    mismatch_behaviour: 'unverified.',
    sources: [
      'EPC132-08 SEPA Credit Transfer Scheme Customer-to-PSP Implementation Guidelines 2025 V1.0 (PDF fetched and text-extracted 2026-09-02): section 1.4 Character Set, element 2.81 EndToEndId, element 3.15 OrgnlEndToEndId, reject reason code AM05',
    ],
    notes: 'The same document shows the counterexample the thesis needs to admit: the adjacent UETR field is typed UUIDv4Identifier with pattern [a-f0-9]{8}-...-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-... A derived value cannot be carried there. Where a rail mandates a named generator, this derivation does not apply.',
  }),
  Object.freeze({
    id: 'aws.ec2.run-instances.client-token',
    carrier: 'AWS EC2 RunInstances (and the other client-token idempotent EC2 actions)',
    slot: 'ClientToken request parameter',
    slot_spec: PROVIDER_SLOT_SPECS['aws.ec2.run-instances.client-token'],
    slot_length: 'Verified: "A client token is a unique, case-sensitive string of up to 64 ASCII characters."',
    slot_charset: 'Verified as ASCII, case-sensitive. No narrower restriction is stated; base62 with an "ep1-" prefix is inside it.',
    retention: 'unverified: the idempotency page opened this run states no expiry or pruning window for a client token.',
    scope: 'Verified: Regional or Zonal. "Requests are idempotent in each Region. However, you can use the same request, including the same client token, in a different Region." RunInstances is zonal when an Availability Zone is set explicitly or implicitly via SubnetId, regional otherwise. The provider_env for this row MUST therefore carry the account and the region, and the zone when the request pins one.',
    intermediary_rewrite: 'unverified, but the parameter is inside the SigV4-signed request, so an intermediary that alters it invalidates the signature. Treated as not rewritable in practice; AWS does not state it in these terms.',
    echo: 'unverified from the page opened this run: it does not say that the client token is returned in the response or recorded in CloudTrail. Do not claim a CloudTrail echo without opening a CloudTrail document.',
    mismatch_behaviour: 'Verified: "If you retry a successful request using the same client token, but one or more of the parameters are different, other than the Region or Availability Zone, the retry fails with an IdempotentParameterMismatch error."',
    sources: [
      'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html (opened 2026-09-02)',
    ],
    notes: 'Region and zone are excluded from the parameter comparison by design, so the same token in another region launches another instance. That is the opposite of a global fence and it is why provider_env must pin the region.',
  }),
]);

export function getCarriageRow(id: string): CarriageRow | null {
  return PROVIDER_CARRIAGE_TABLE.find((row) => row.id === id) || null;
}

// ---------------------------------------------------------------------------
// MCP tools/call carriage
// ---------------------------------------------------------------------------

/**
 * Derive the value for the MCP tools/call `_meta` member.
 *
 * The CAID covers the content of the call under CAID type tool.call.1: target,
 * tool and the complete argument object, with NO occurrence. The model-issued
 * call id is the attempt group instead. That split is what produces the three
 * server outcomes the thesis needs:
 *
 *   same call id retried              -> same key            -> stored result
 *   different call id, same content   -> different key,
 *                                        same content digest -> probable duplicate
 *   different content                 -> different key,
 *                                        different digest    -> fresh call
 *
 * `target` is the stable identity of the service that will execute the call.
 * Changing it changes the content digest and the key, which is the point: a
 * key minted for one target cannot be presented at another.
 */
export function deriveMcpToolCallReplayKey({
  authorization_digest: authorizationDigest,
  target,
  tool,
  args,
  call_id: callId,
  server_env: serverEnv,
}: {
  authorization_digest: string;
  target: string;
  tool: string;
  args: unknown;
  call_id: string;
  server_env: string;
}): (ProviderReplayKeyResult & { content_digest: string }) | ProviderReplayKeyRefusalResult {
  if (typeof target !== 'string' || target.length === 0 || target.length > 512) {
    return refuse('derivation_input_uncanonicalizable', 'target must be a non-empty string of at most 512 characters');
  }
  if (typeof tool !== 'string' || tool.length === 0 || tool.length > 512) {
    return refuse('derivation_input_uncanonicalizable', 'tool must be a non-empty string of at most 512 characters');
  }
  const instance = authorizationInstanceDigest({
    authorization_digest: authorizationDigest,
    profile: 'mcp.tools-call',
    material_action: {
      action_type: 'tool.call.1',
      args,
      target,
      tool,
    },
  });
  if (instance.ok !== true) {
    return refuse(
      instance.reason === 'authorization_digest_invalid'
        ? 'authorization_digest_invalid'
        : 'derivation_input_uncanonicalizable',
      instance.detail,
    );
  }
  const derived = deriveProviderReplayKey({
    authorization_digest: instance.digest,
    caid: 'tool.call.1',
    provider_env: serverEnv,
    attempt_group: callId,
    slot_spec: PROVIDER_SLOT_SPECS['mcp.tools-call.meta'],
  });
  if (derived.ok !== true) return derived;
  return { ...derived, content_digest: instance.digest };
}

export type McpReplayOutcome =
  | 'fresh'
  | 'stored_result'
  | 'in_flight_refused'
  | 'probable_duplicate_flagged'
  | 'key_content_mismatch_refused';

/**
 * The server half of the MCP row, as an in-memory ledger.
 *
 * This is what an MCP server that adopts the key would do before dispatch. It
 * is deliberately small and deliberately NOT a claim that any MCP server does
 * this today: the base protocol defines no duplicate detection at all, so this
 * ledger is a proposal in runnable form.
 *
 * `probable_duplicate_flagged` never silently dedupes. It reports; the caller
 * decides. Silently collapsing two distinct model calls with identical content
 * would drop a legitimate second effect.
 */
export function createMcpReplayLedger({ windowMs = 15 * 60 * 1000 } = {}) {
  const byKey = new Map<string, { contentDigest: string; at: number; result: unknown; state: 'in_flight' | 'complete' }>();
  const byContent = new Map<string, { key: string; at: number }[]>();

  function prune(now: number) {
    for (const [key, entry] of byKey) {
      if (now - entry.at > windowMs) byKey.delete(key);
    }
    for (const [digest, entries] of byContent) {
      const kept = entries.filter((entry) => now - entry.at <= windowMs);
      if (kept.length === 0) byContent.delete(digest);
      else byContent.set(digest, kept);
    }
  }

  return {
    windowMs,
    /** Decide what to do with an inbound call. Never throws. */
    evaluate({ key, contentDigest, now = Date.now() }: {
      key: string;
      contentDigest: string;
      now?: number;
    }): { outcome: McpReplayOutcome; reason: string; result?: unknown; priorKeys?: string[] } {
      if (typeof key !== 'string' || key.length === 0) {
        return { outcome: 'key_content_mismatch_refused', reason: 'replay key is missing or not a string' };
      }
      if (typeof contentDigest !== 'string' || !DIGEST_RE.test(contentDigest)) {
        return { outcome: 'key_content_mismatch_refused', reason: 'content digest is missing or malformed' };
      }
      prune(now);
      const existing = byKey.get(key);
      if (existing) {
        if (existing.contentDigest !== contentDigest) {
          return {
            outcome: 'key_content_mismatch_refused',
            reason: 'this replay key was already seen with different call content',
          };
        }
        if (existing.state === 'in_flight') {
          return { outcome: 'in_flight_refused', reason: 'a call under this replay key is still in flight' };
        }
        return { outcome: 'stored_result', reason: 'this exact call already completed under this replay key', result: existing.result };
      }
      const sameContent = byContent.get(contentDigest) || [];
      if (sameContent.length > 0) {
        return {
          outcome: 'probable_duplicate_flagged',
          reason: 'identical call content already arrived under a different replay key inside the window',
          priorKeys: sameContent.map((entry) => entry.key),
        };
      }
      return { outcome: 'fresh', reason: 'no prior call under this key or this content inside the window' };
    },
    begin({ key, contentDigest, now = Date.now() }: { key: string; contentDigest: string; now?: number }) {
      byKey.set(key, { contentDigest, at: now, result: null, state: 'in_flight' });
      const entries = byContent.get(contentDigest) || [];
      entries.push({ key, at: now });
      byContent.set(contentDigest, entries);
    },
    complete({ key, result, now = Date.now() }: { key: string; result: unknown; now?: number }) {
      const existing = byKey.get(key);
      if (!existing) return false;
      byKey.set(key, { ...existing, result, at: now, state: 'complete' });
      return true;
    },
  };
}

/**
 * THE MEASUREMENT THAT DECIDES THE THESIS.
 *
 * The mechanism has two halves. The JOIN half (a party holding the
 * authorization recomputes the provider's reference and joins the provider's
 * own record to it with no lookup table) holds for as long as the provider
 * keeps that record, which is normally forever. The CONSUMPTION half (the
 * provider's own duplicate-detection engine refuses a second effect under one
 * authorization) holds only while the provider still remembers the key.
 *
 * So the consumption half is true exactly when the authorization's usable
 * lifetime is shorter than the provider's key retention. Where it is not, the
 * mechanism is an adapter feature, not a fence.
 */
export const PROVIDER_KEY_RETENTION_MEASUREMENT = Object.freeze({
  '@version': 'EP-PROVIDER-REPLAY-RETENTION-MEASUREMENT-v1',
  measured_on: '2026-09-02',
  rows: Object.freeze([
    Object.freeze({
      id: 'stripe.idempotency-key',
      provider_retention_hours: 24,
      provider_retention_verified: true,
      provider_retention_quote: 'keys expire out of the system after 24 hours',
      verdict: 'join_only_beyond_24h',
      finding: 'A Gate allowance is issued with an expiry and is usually valid for days or weeks, and an action escrow release can sit reserved across a milestone. Any authorization whose usable life exceeds 24 hours outlives the Stripe fence. On this rail the provider consumes the authorization only inside a 24 hour window from the first request; after that a second dispatch under the same authorization reaches Stripe as a fresh request and only the EMILIA action fence stops it.',
    }),
    Object.freeze({
      id: 'eip3009.nonce',
      provider_retention_hours: null,
      provider_retention_verified: true,
      provider_retention_quote: '_authorizationStates[from][nonce] = true, with no pruning defined in the ERC',
      verdict: 'consumption_and_join',
      finding: 'Permanent on-chain state. The consumption half holds for any authorization lifetime.',
    }),
    Object.freeze({
      id: 'aws.ec2.run-instances.client-token',
      provider_retention_hours: 'unverified',
      provider_retention_verified: false,
      provider_retention_quote: 'unverified',
      verdict: 'unknown',
      finding: 'The AWS idempotency page states no expiry. Unknown is not the same as unbounded; do not assume either.',
    }),
    Object.freeze({
      id: 'iso20022.end-to-end-id',
      provider_retention_hours: 'unverified',
      provider_retention_verified: false,
      provider_retention_quote: 'unverified',
      verdict: 'join_only',
      finding: 'No duplicate check keyed on EndToEndId is documented in the guidelines opened this run, so there is no consumption half to measure. The echo in pain.002 OrgnlEndToEndId makes the join half real.',
    }),
    Object.freeze({
      id: 'mcp.tools-call.meta',
      provider_retention_hours: 'not applicable',
      provider_retention_verified: false,
      provider_retention_quote: 'not applicable',
      verdict: 'join_only',
      finding: 'The base protocol has no duplicate-detection engine to borrow. This row is a proposal to server authors, not a fence.',
    }),
  ]),
  verdict: 'MIXED, and adapter-feature on the money rail that matters most. One of five rows (ERC-3009) supports the consumption half for any authorization lifetime, because its state is permanent. Stripe supports it only inside 24 hours, which is shorter than a normal Gate allowance lifetime, so on Stripe the honest claim is: a second dispatch within 24 hours is refused by Stripe itself, and beyond 24 hours only the join half survives and the fence is ours alone. Two rows have no documented consumption engine at all. This satisfies kill condition (1) of the thesis for the Stripe rail as written: most authorizations outlive the provider retention, so on that rail this is an adapter feature and not a plate.',
});

export default {
  PROVIDER_REPLAY_KEY_VERSION,
  PROVIDER_CARRIAGE_TABLE_VERSION,
  AUTHORIZATION_INSTANCE_VERSION,
  MCP_META_REPLAY_KEY,
  PROVIDER_SLOT_SPECS,
  PROVIDER_CARRIAGE_TABLE,
  PROVIDER_KEY_RETENTION_MEASUREMENT,
  deriveProviderReplayKey,
  deriveMcpToolCallReplayKey,
  createMcpReplayLedger,
  matchesProviderReplayKey,
  authorizationInstanceDigest,
  getCarriageRow,
};
