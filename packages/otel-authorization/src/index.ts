// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/otel-authorization
 *
 * Build the `gen_ai.tool.authorization.*` attribute map for an OpenTelemetry
 * `execute_tool` span from a runtime's own approval decision, and set it on a
 * span.
 *
 * Scope, stated plainly and not more:
 *
 *   - This module produces SPAN ATTRIBUTES. Attributes are an observation the
 *     producer makes about its own decision. They are not an authorization, not
 *     a verification, and not evidence. A consumer that reads
 *     `authorization.status = auto_approved` learns what the producer said, not
 *     what is true.
 *   - `evidence.grade` is the producer's own classification of the evidence it
 *     holds. Nothing in the telemetry path checks it. It exists so that a
 *     self-attested span LOOKS self-attested to the backend that indexes it.
 *   - `evidence.digest`, `action.digest` and `policy.digest` are opaque
 *     references. No payload, no prompt, no argument object, no policy body and
 *     no approver identity is carried by this group.
 *
 * Dependencies: none. The module never imports `@opentelemetry/api` statically.
 * `setToolAuthorizationAttributes` accepts any object exposing the OTel `Span`
 * `setAttributes(map)` (or `setAttribute(k, v)`) surface, so an application that
 * already has `@opentelemetry/api` passes its active span in and an application
 * that does not passes its own recorder or nothing at all.
 *
 * Fail-closed behaviour: malformed input returns a refusal
 * (`{ ok: false, reason }`) naming the reason, and the span is left untouched.
 * It does not throw and it does not emit a partial or guessed attribute map.
 * A wrong authorization status on a span is worse than no status.
 */

export const OTEL_TOOL_AUTHORIZATION_VERSION = 'EMILIA-OTEL-TOOL-AUTHORIZATION-v0.1' as const;

/**
 * Per-action authorization status. The first six values are the per-action
 * authorization-status vocabulary carried into this group from the insurance
 * taxonomy work; the last three are the decision outcomes a boolean approval
 * slot can honestly produce. See CROSSWALK.md for the mapping onto the shipped
 * `standards/aiuc/incident-fields-v0` enum, which uses different value names.
 */
export const TOOL_AUTHORIZATION_STATUS = Object.freeze({
  /** A human authorization step ran and the executed action is inside its scope. */
  AUTHORIZED_IN_SCOPE: 'authorized_in_scope',
  /** A human authorization step ran, but the executed action falls outside what was authorized. */
  AUTHORIZED_OUT_OF_SCOPE: 'authorized_out_of_scope',
  /** A human authorized the action without holding the standing authority to do so. */
  AUTHORIZED_WITHOUT_STANDING: 'authorized_without_standing',
  /** No per-action step ran; the call proceeded under a prior standing grant. */
  STANDING_PREAUTHORIZATION: 'standing_preauthorization',
  /** No authorization step existed for this call at all. */
  NO_AUTHORIZATION_STEP: 'no_authorization_step',
  /** An authorization step existed and the call reached execution without completing it. */
  STEP_BYPASSED: 'step_bypassed',
  /** A non-human rule allowed the call; no human saw it. */
  AUTO_APPROVED: 'auto_approved',
  /** The call was refused before execution. */
  REJECTED: 'rejected',
  /** A human changed the arguments and authorized the changed call. */
  EDITED_THEN_APPROVED: 'edited_then_approved',
});

export const TOOL_AUTHORIZATION_STATUS_VALUES: readonly string[] = Object.freeze(
  Object.values(TOOL_AUTHORIZATION_STATUS),
);

/**
 * Producer-asserted class of the evidence behind the status.
 *
 *   self_attested            the emitting runtime asserts the decision; there is
 *                            no artifact another party can re-check.
 *   third_party_logged       a party other than the emitting runtime recorded the
 *                            decision and the record is retrievable by reference;
 *                            re-reading it requires trusting that party's store.
 *   independently_verifiable the producer names a digest, a format and a locator
 *                            for an artifact a party other than the producer can
 *                            check on its own, without trusting the producer's
 *                            runtime or storage.
 *
 * The grade is a claim. The telemetry pipeline does not verify it.
 */
export const EVIDENCE_GRADE = Object.freeze({
  SELF_ATTESTED: 'self_attested',
  THIRD_PARTY_LOGGED: 'third_party_logged',
  INDEPENDENTLY_VERIFIABLE: 'independently_verifiable',
});

export const EVIDENCE_GRADE_VALUES: readonly string[] = Object.freeze(Object.values(EVIDENCE_GRADE));

/** Registry attribute names, as proposed upstream. */
export const REGISTRY_ATTRIBUTE_KEYS = Object.freeze({
  status: 'gen_ai.tool.authorization.status',
  evidenceGrade: 'gen_ai.tool.authorization.evidence.grade',
  evidenceDigest: 'gen_ai.tool.authorization.evidence.digest',
  evidenceFormat: 'gen_ai.tool.authorization.evidence.format',
  evidenceLocator: 'gen_ai.tool.authorization.evidence.locator',
  actionDigest: 'gen_ai.tool.authorization.action.digest',
  policyDigest: 'gen_ai.tool.authorization.policy.digest',
});

/**
 * Vendor-prefixed fallback names, used until (and unless) the group is accepted
 * upstream. An attribute outside the registry is invisible to every consumer
 * that has not been told about it, so the default is the fallback namespace and
 * the registry names are opt-in.
 */
export const FALLBACK_ATTRIBUTE_KEYS = Object.freeze({
  status: 'emilia.tool.authorization.status',
  evidenceGrade: 'emilia.tool.authorization.evidence.grade',
  evidenceDigest: 'emilia.tool.authorization.evidence.digest',
  evidenceFormat: 'emilia.tool.authorization.evidence.format',
  evidenceLocator: 'emilia.tool.authorization.evidence.locator',
  actionDigest: 'emilia.tool.authorization.action.digest',
  policyDigest: 'emilia.tool.authorization.policy.digest',
});

export type AttributeNamespace = 'registry' | 'fallback' | 'both';

export interface ToolAuthorizationInput {
  status: string;
  evidence_grade: string;
  evidence_digest?: string | null;
  evidence_format?: string | null;
  evidence_locator?: string | null;
  action_digest?: string | null;
  policy_digest?: string | null;
}

export interface ToolAuthorizationAttributes {
  [key: string]: string;
}

export type BuildResult =
  | { ok: true; attributes: ToolAuthorizationAttributes; namespace: AttributeNamespace }
  | { ok: false; reason: string };

export interface BuildOptions {
  /** Which attribute namespace to emit. Defaults to 'fallback'. */
  namespace?: AttributeNamespace;
}

/**
 * Upper bound on any single attribute value. Digests and locators are opaque
 * references; a producer that tries to inline a payload here is refused rather
 * than truncated, so a consumer never sees a silently cut digest.
 */
const MAX_VALUE_LENGTH = 512;

/**
 * A colon-scoped opaque reference. This admits the digest and identifier forms
 * this repository already produces, and nothing that looks like a payload:
 *
 *   sha256:<hex>                                 a bare content digest
 *   receipt:sha256:<hex>                         bindExecutorAction output
 *   send_email:sha256:<hex>                      bindToolAction output
 *   caid:v1:tool.call.1:sha256:<base64url>       a CAID string
 *
 * A scope segment must lead, and every segment must be short and printable. A
 * value with no colon, with whitespace, or with JSON punctuation is refused, so
 * an inlined argument object or policy body cannot reach a digest attribute.
 */
const OPAQUE_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~+-]{0,63}(?::[A-Za-z0-9._~+/=-]{1,256}){1,4}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function refuse(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

/**
 * Reject anything that is not a short, single-line, printable ASCII token. Span
 * attributes leave the producing process; a newline or a control character here
 * is a log-injection primitive, and a non-ASCII value is a portability problem
 * across the backends that index these names.
 */
function checkOpaqueToken(value: unknown, field: string): string | { ok: false; reason: string } {
  if (typeof value !== 'string') return refuse(`${field}_not_a_string`);
  if (value.length === 0) return refuse(`${field}_empty`);
  if (value.length > MAX_VALUE_LENGTH) return refuse(`${field}_too_long`);
  if (value !== value.trim()) return refuse(`${field}_has_surrounding_whitespace`);
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return refuse(`${field}_not_printable_ascii`);
  }
  return value;
}

function isRefusal(v: unknown): v is { ok: false; reason: string } {
  return isPlainObject(v) && v.ok === false;
}

/**
 * Build the attribute map for one tool call.
 *
 * Returns a refusal, never a partial map, when:
 *   - the input is not an object;
 *   - `status` is not one of the nine registered values;
 *   - `evidence_grade` is not one of the three registered values;
 *   - any supplied reference is not a short, printable, single-line token;
 *   - `evidence_digest` or `action_digest` is not a recognisable digest or CAID;
 *   - `evidence_grade` is `independently_verifiable` without the digest, format
 *     and locator that make the artifact checkable by someone else. A grade
 *     above self_attested with nothing to check is the claim this group exists
 *     to prevent, so it is refused rather than downgraded.
 */
export function buildToolAuthorizationAttributes(
  input: unknown,
  options: BuildOptions = {},
): BuildResult {
  if (!isPlainObject(input)) return refuse('input_not_an_object');

  const namespace: AttributeNamespace = options.namespace ?? 'fallback';
  if (namespace !== 'registry' && namespace !== 'fallback' && namespace !== 'both') {
    return refuse('unknown_attribute_namespace');
  }

  const status = input.status;
  if (typeof status !== 'string') return refuse('status_not_a_string');
  if (!TOOL_AUTHORIZATION_STATUS_VALUES.includes(status)) return refuse('unknown_status_value');

  const grade = input.evidence_grade;
  if (typeof grade !== 'string') return refuse('evidence_grade_not_a_string');
  if (!EVIDENCE_GRADE_VALUES.includes(grade)) return refuse('unknown_evidence_grade_value');

  const optional: Array<[keyof typeof REGISTRY_ATTRIBUTE_KEYS, unknown, string]> = [
    ['evidenceDigest', input.evidence_digest, 'evidence_digest'],
    ['evidenceFormat', input.evidence_format, 'evidence_format'],
    ['evidenceLocator', input.evidence_locator, 'evidence_locator'],
    ['actionDigest', input.action_digest, 'action_digest'],
    ['policyDigest', input.policy_digest, 'policy_digest'],
  ];

  const resolved: Partial<Record<keyof typeof REGISTRY_ATTRIBUTE_KEYS, string>> = {
    status,
    evidenceGrade: grade,
  };

  for (const [slot, raw, field] of optional) {
    if (raw === undefined || raw === null) continue;
    const checked = checkOpaqueToken(raw, field);
    if (isRefusal(checked)) return checked;
    resolved[slot] = checked;
  }

  for (const [slot, field] of [
    ['evidenceDigest', 'evidence_digest'],
    ['actionDigest', 'action_digest'],
    ['policyDigest', 'policy_digest'],
  ] as const) {
    const value = resolved[slot];
    if (value === undefined) continue;
    if (!OPAQUE_REF_PATTERN.test(value)) {
      return refuse(`${field}_not_a_scoped_opaque_reference`);
    }
  }

  if (grade === EVIDENCE_GRADE.INDEPENDENTLY_VERIFIABLE) {
    if (!resolved.evidenceDigest) return refuse('independently_verifiable_without_evidence_digest');
    if (!resolved.evidenceFormat) return refuse('independently_verifiable_without_evidence_format');
    if (!resolved.evidenceLocator) return refuse('independently_verifiable_without_evidence_locator');
  }

  const attributes: ToolAuthorizationAttributes = {};
  const emitRegistry = namespace === 'registry' || namespace === 'both';
  const emitFallback = namespace === 'fallback' || namespace === 'both';
  for (const slot of Object.keys(REGISTRY_ATTRIBUTE_KEYS) as Array<keyof typeof REGISTRY_ATTRIBUTE_KEYS>) {
    const value = resolved[slot];
    if (value === undefined) continue;
    if (emitRegistry) attributes[REGISTRY_ATTRIBUTE_KEYS[slot]] = value;
    if (emitFallback) attributes[FALLBACK_ATTRIBUTE_KEYS[slot]] = value;
  }

  return { ok: true, attributes, namespace };
}

/** The minimum of the OpenTelemetry `Span` surface this module uses. */
export interface SpanLike {
  setAttributes?: (attributes: Record<string, unknown>) => unknown;
  setAttribute?: (key: string, value: unknown) => unknown;
}

export type SetResult =
  | { ok: true; attributes: ToolAuthorizationAttributes; written: boolean }
  | { ok: false; reason: string };

/**
 * Set the attribute map on a span-like object.
 *
 * `span` may be null or undefined: the attributes are still built and validated
 * and returned with `written: false`, so a caller with no tracer configured gets
 * the same refusal behaviour as one that has. A span that throws from
 * `setAttributes` is treated as a telemetry failure, never as an authorization
 * failure: the refusal is returned and the caller's control flow is unchanged.
 */
export function setToolAuthorizationAttributes(
  span: SpanLike | null | undefined,
  input: unknown,
  options: BuildOptions = {},
): SetResult {
  const built = buildToolAuthorizationAttributes(input, options);
  if (!built.ok) return built;
  if (!span) return { ok: true, attributes: built.attributes, written: false };

  try {
    if (typeof span.setAttributes === 'function') {
      span.setAttributes(built.attributes);
    } else if (typeof span.setAttribute === 'function') {
      for (const [key, value] of Object.entries(built.attributes)) span.setAttribute(key, value);
    } else {
      return refuse('span_has_no_attribute_setter');
    }
  } catch (error: any) {
    return refuse(`span_setter_threw:${typeof error?.message === 'string' ? error.message.slice(0, 80) : 'unknown'}`);
  }

  return { ok: true, attributes: built.attributes, written: true };
}

/**
 * Resolve the currently active OpenTelemetry span WITHOUT taking a dependency on
 * `@opentelemetry/api`. If the package is not installed, or the caller is not
 * inside a span, this returns null and emission becomes a no-op.
 *
 * `@opentelemetry/api` is an optional peer of this package. It is not in
 * `dependencies` and is not installed in this repository.
 */
export async function resolveActiveSpan(): Promise<SpanLike | null> {
  try {
    // The specifier is built at runtime on purpose: a literal would make the
    // optional peer a compile-time and bundler-time resolution target, which is
    // exactly the dependency this package refuses to take.
    const specifier = ['@opentelemetry', 'api'].join('/');
    const mod: any = await import(/* @vite-ignore */ specifier);
    const trace = mod?.trace ?? mod?.default?.trace;
    if (!trace || typeof trace.getActiveSpan !== 'function') return null;
    const span = trace.getActiveSpan();
    if (!span) return null;
    if (typeof span.setAttributes !== 'function' && typeof span.setAttribute !== 'function') return null;
    return span as SpanLike;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Runtime mappers
//
// Each mapper turns one runtime's own approval outcome into the attribute
// input. Where a runtime's approval slot is a boolean, the mapper produces
// auto_approved or rejected at grade self_attested and NOTHING ELSE. It does
// not invent a grade the runtime cannot support, and it does not report
// authorized_in_scope from a boolean, because a boolean does not carry the
// scope the value asserts.
// ---------------------------------------------------------------------------

export interface MapperEvidence {
  evidence_digest?: string | null;
  evidence_format?: string | null;
  evidence_locator?: string | null;
  action_digest?: string | null;
  policy_digest?: string | null;
}

export type MapResult =
  | { ok: true; input: ToolAuthorizationInput }
  | { ok: false; reason: string };

function withEvidence(
  status: string,
  grade: string,
  evidence: MapperEvidence | undefined,
): ToolAuthorizationInput {
  const out: ToolAuthorizationInput = { status, evidence_grade: grade };
  if (evidence) {
    if (evidence.evidence_digest != null) out.evidence_digest = evidence.evidence_digest;
    if (evidence.evidence_format != null) out.evidence_format = evidence.evidence_format;
    if (evidence.evidence_locator != null) out.evidence_locator = evidence.evidence_locator;
    if (evidence.action_digest != null) out.action_digest = evidence.action_digest;
    if (evidence.policy_digest != null) out.policy_digest = evidence.policy_digest;
  }
  return out;
}

/**
 * OpenAI Agents SDK. The runtime's own slot is a boolean: `needsApproval` marks
 * the tool, `state.approve(item)` / `state.reject(item)` resolves it, and no
 * approver, signature or scope travels with either call.
 *
 * `decision` is what the adapter did:
 *   'approve'            -> a valid action-bound receipt was consumed
 *   'reject'             -> refused, with a reason
 *   'approve_no_receipt' -> the host approved without EMILIA in the path
 *
 * `receiptBound` says whether an action-bound authorization artifact backed the
 * approval. Without one, the honest status is auto_approved at self_attested,
 * because the boolean cannot say who approved or what they saw.
 */
export function mapOpenAIAgentsDecision(
  decision: unknown,
  evidence?: MapperEvidence,
): MapResult {
  if (typeof decision !== 'string') return refuse('openai_agents_decision_not_a_string');
  switch (decision) {
    case 'approve':
      return {
        ok: true,
        input: withEvidence(
          TOOL_AUTHORIZATION_STATUS.AUTHORIZED_IN_SCOPE,
          EVIDENCE_GRADE.INDEPENDENTLY_VERIFIABLE,
          evidence,
        ),
      };
    case 'approve_no_receipt':
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.AUTO_APPROVED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    case 'reject':
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.REJECTED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    default:
      return refuse('unknown_openai_agents_decision');
  }
}

/**
 * LangGraph `HumanInTheLoopMiddleware` interrupt responses, as the EMILIA
 * adapter resolves them. This runtime is the one of the four whose slot is
 * richer than a boolean: it distinguishes accept from edit, which is the only
 * place `edited_then_approved` can be produced honestly.
 *
 * `decision` is the adapter's own `resolve()` outcome, `responseType` the
 * LangGraph response type ('accept' | 'edit' | 'ignore' | 'response').
 */
export function mapLangGraphDecision(
  decision: unknown,
  responseType: unknown,
  evidence?: MapperEvidence,
): MapResult {
  if (typeof decision !== 'string') return refuse('langgraph_decision_not_a_string');
  if (responseType != null && typeof responseType !== 'string') {
    return refuse('langgraph_response_type_not_a_string');
  }
  switch (decision) {
    case 'resume':
      if (responseType === 'edit') {
        return {
          ok: true,
          input: withEvidence(
            TOOL_AUTHORIZATION_STATUS.EDITED_THEN_APPROVED,
            EVIDENCE_GRADE.INDEPENDENTLY_VERIFIABLE,
            evidence,
          ),
        };
      }
      return {
        ok: true,
        input: withEvidence(
          TOOL_AUTHORIZATION_STATUS.AUTHORIZED_IN_SCOPE,
          EVIDENCE_GRADE.INDEPENDENTLY_VERIFIABLE,
          evidence,
        ),
      };
    case 'reject':
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.REJECTED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    case 'reauthorize':
      // The human edited the call and the authorization on hand covers the
      // pre-edit call. The executed action would be outside what was authorized,
      // which is exactly what authorized_out_of_scope names.
      return {
        ok: true,
        input: withEvidence(
          TOOL_AUTHORIZATION_STATUS.AUTHORIZED_OUT_OF_SCOPE,
          EVIDENCE_GRADE.SELF_ATTESTED,
          evidence,
        ),
      };
    case 'pass':
      // A non-authorizing human response ('ignore' / free-text 'response'). The
      // human was present but no authorization step resolved for this call.
      return {
        ok: true,
        input: withEvidence(
          TOOL_AUTHORIZATION_STATUS.NO_AUTHORIZATION_STEP,
          EVIDENCE_GRADE.SELF_ATTESTED,
          evidence,
        ),
      };
    default:
      return refuse('unknown_langgraph_decision');
  }
}

/**
 * LangChain tool wrapper. The slot is a boolean: the wrapped tool either runs or
 * refuses. `allowed` true with an action-bound receipt is authorized_in_scope;
 * `allowed` true without one is auto_approved at self_attested; false is
 * rejected.
 */
export function mapLangChainDecision(
  allowed: unknown,
  receiptBound: unknown,
  evidence?: MapperEvidence,
): MapResult {
  if (typeof allowed !== 'boolean') return refuse('langchain_allowed_not_a_boolean');
  if (typeof receiptBound !== 'boolean') return refuse('langchain_receipt_bound_not_a_boolean');
  if (!allowed) {
    return {
      ok: true,
      input: withEvidence(TOOL_AUTHORIZATION_STATUS.REJECTED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
    };
  }
  if (!receiptBound) {
    return {
      ok: true,
      input: withEvidence(TOOL_AUTHORIZATION_STATUS.AUTO_APPROVED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
    };
  }
  return {
    ok: true,
    input: withEvidence(
      TOOL_AUTHORIZATION_STATUS.AUTHORIZED_IN_SCOPE,
      EVIDENCE_GRADE.INDEPENDENTLY_VERIFIABLE,
      evidence,
    ),
  };
}

/**
 * MCP guard. `GUARD_DECISIONS` are allow | allow_with_signoff | deny, and the
 * guard additionally knows whether the call was classified irreversible.
 *
 *   allow on an irreversible tool with no receipt  -> no_authorization_step
 *   allow on a reversible tool                     -> auto_approved
 *   allow_with_signoff, receipt consumed           -> authorized_in_scope
 *   allow_with_signoff, no receipt presented       -> step_bypassed
 *   deny                                           -> rejected
 */
export function mapMcpGuardDecision(
  guardDecision: unknown,
  facts: unknown,
  evidence?: MapperEvidence,
): MapResult {
  if (typeof guardDecision !== 'string') return refuse('mcp_guard_decision_not_a_string');
  if (!isPlainObject(facts)) return refuse('mcp_guard_facts_not_an_object');
  const irreversible = facts.irreversible;
  const receiptConsumed = facts.receipt_consumed;
  if (typeof irreversible !== 'boolean') return refuse('mcp_guard_irreversible_not_a_boolean');
  if (typeof receiptConsumed !== 'boolean') return refuse('mcp_guard_receipt_consumed_not_a_boolean');

  switch (guardDecision) {
    case 'deny':
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.REJECTED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    case 'allow_with_signoff':
      if (receiptConsumed) {
        return {
          ok: true,
          input: withEvidence(
            TOOL_AUTHORIZATION_STATUS.AUTHORIZED_IN_SCOPE,
            EVIDENCE_GRADE.INDEPENDENTLY_VERIFIABLE,
            evidence,
          ),
        };
      }
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.STEP_BYPASSED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    case 'allow':
      if (receiptConsumed) {
        return {
          ok: true,
          input: withEvidence(
            TOOL_AUTHORIZATION_STATUS.AUTHORIZED_IN_SCOPE,
            EVIDENCE_GRADE.INDEPENDENTLY_VERIFIABLE,
            evidence,
          ),
        };
      }
      if (irreversible) {
        return {
          ok: true,
          input: withEvidence(
            TOOL_AUTHORIZATION_STATUS.NO_AUTHORIZATION_STEP,
            EVIDENCE_GRADE.SELF_ATTESTED,
            evidence,
          ),
        };
      }
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.AUTO_APPROVED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    default:
      return refuse('unknown_mcp_guard_decision');
  }
}

/**
 * Claude Code PreToolUse hook. Its slot is a three-valued permissionDecision
 * ('allow' | 'deny' | 'ask') and the EMILIA hook never emits 'allow': on a
 * matched high-risk call it emits 'ask' or 'deny'.
 *
 * 'ask' is not an authorization outcome. The hook has deferred the decision to a
 * human who has not answered yet, so there is no status to report for the call
 * and the mapper refuses rather than guessing. That refusal is deliberate: a
 * pending step recorded as auto_approved would be the exact false negative this
 * group exists to make visible.
 */
export function mapClaudeCodeHookDecision(
  permissionDecision: unknown,
  evidence?: MapperEvidence,
): MapResult {
  if (typeof permissionDecision !== 'string') return refuse('claude_code_decision_not_a_string');
  switch (permissionDecision) {
    case 'deny':
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.REJECTED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    case 'allow':
      return {
        ok: true,
        input: withEvidence(TOOL_AUTHORIZATION_STATUS.AUTO_APPROVED, EVIDENCE_GRADE.SELF_ATTESTED, evidence),
      };
    case 'ask':
      return refuse('claude_code_ask_is_not_a_resolved_authorization_status');
    default:
      return refuse('unknown_claude_code_permission_decision');
  }
}

// ---------------------------------------------------------------------------
// Adapter emission helper
// ---------------------------------------------------------------------------

export interface TelemetryOptions {
  /** Turn emission off entirely. Default true. */
  enabled?: boolean;
  /** An explicit span to write to. */
  span?: SpanLike | null;
  /** Resolve a span per call, given the adapter's context object. */
  spanFor?: (context: any) => SpanLike | null | undefined;
  /**
   * Fall back to the active `@opentelemetry/api` span when neither `span` nor
   * `spanFor` yields one. Default true; a no-op when the package is absent.
   */
  useActiveSpan?: boolean;
  /** 'registry' | 'fallback' | 'both'. Default 'fallback'. */
  namespace?: AttributeNamespace;
  /** Observe every emission, including refusals. Never affects control flow. */
  onEmit?: (result: SetResult, context: any) => void;
}

/**
 * Emit one mapped decision, honouring the caller's telemetry options.
 *
 * This never throws and never changes an adapter's authorization outcome. A
 * refusal from the mapper or the builder is reported through `onEmit` and
 * returned; the adapter keeps whatever decision it already made.
 */
export async function emitToolAuthorization(
  telemetry: TelemetryOptions | null | undefined,
  mapped: MapResult,
  context: any = {},
): Promise<SetResult> {
  const options = telemetry ?? {};
  if (options.enabled === false) return { ok: false, reason: 'telemetry_disabled' };
  if (!mapped || mapped.ok !== true) {
    const result: SetResult = { ok: false, reason: mapped?.ok === false ? mapped.reason : 'mapper_returned_no_input' };
    try { options.onEmit?.(result, context); } catch { /* telemetry never breaks the caller */ }
    return result;
  }

  let span: SpanLike | null | undefined = options.span ?? null;
  if (!span && typeof options.spanFor === 'function') {
    try { span = options.spanFor(context); } catch { span = null; }
  }
  if (!span && options.useActiveSpan !== false) {
    span = await resolveActiveSpan();
  }

  const result = setToolAuthorizationAttributes(span ?? null, mapped.input, { namespace: options.namespace });
  try { options.onEmit?.(result, context); } catch { /* telemetry never breaks the caller */ }
  return result;
}

const otelAuthorizationExports = {
  OTEL_TOOL_AUTHORIZATION_VERSION,
  TOOL_AUTHORIZATION_STATUS,
  TOOL_AUTHORIZATION_STATUS_VALUES,
  EVIDENCE_GRADE,
  EVIDENCE_GRADE_VALUES,
  REGISTRY_ATTRIBUTE_KEYS,
  FALLBACK_ATTRIBUTE_KEYS,
  buildToolAuthorizationAttributes,
  setToolAuthorizationAttributes,
  resolveActiveSpan,
  mapOpenAIAgentsDecision,
  mapLangGraphDecision,
  mapLangChainDecision,
  mapMcpGuardDecision,
  mapClaudeCodeHookDecision,
  emitToolAuthorization,
};

export default otelAuthorizationExports;
