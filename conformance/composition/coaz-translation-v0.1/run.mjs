// SPDX-License-Identifier: Apache-2.0
//
// Hostile COAZ/AuthZEN translation vector, v0.1.
//
// Demonstrates, executably, that a well-formed MCP-to-AuthZEN translation
// under the COAZ model can drop a consequential tool-call argument, so that
// two materially different source actions construct byte-identical AuthZEN
// Access Evaluation requests, and a PDP that decides on the constructed tuple
// returns a fully valid permit for both. It then demonstrates the close: the
// same translator additionally emitting a canonical action identifier (CAID)
// computed over the full typed source action in the request context, and a
// relying check at the enforcement boundary refusing the substituted action
// with a named reason. Refusals are returned values with reasons, never
// crashes.
//
// Sources are pinned in source-lock.json:
//   - COAZ Framework, Draft 1, 13 February 2026 (OpenID AuthZEN WG)
//   - COAZ-MCP binding, Draft 1, 13 February 2026 (OpenID AuthZEN WG)
//   - AuthZEN Authorization API 1.0 Final quotes reused from the fetch record
//     of caid/bindings/authzen-acta.md
//
// Status: source-pinned discussion artifact. The PDP below is a TOY: it
// decides on the tuple it is shown and stands in for any spec-conformant PDP.
// It is not any real PDP product, and this artifact does not show that any
// deployed translator, gateway, or PDP is lossy or vulnerable. It shows that
// the translation surface admits lossy mappings undetectably absent a content
// identifier. See README.md for the exact claim boundary.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { canonicalize, computeCaid, parseCaid, verifyCaid } from '../../../caid/impl/js/caid.mjs';

export const PROFILE = 'EP-COAZ-TRANSLATION-VECTOR-v0.1';

const REGISTRY = JSON.parse(
  readFileSync(new URL('../../../caid/registry/action-types.json', import.meta.url), 'utf8'),
);
export const DEFINITIONS = REGISTRY.types;
const ACTION_TYPE = 'payment.release.1';

// ---------------------------------------------------------------------------
// Expression resolution.
//
// The pinned mappings below use only two expression forms from the COAZ
// Framework's default contract: plain field selection ($token.sub,
// $params.arguments.amount, $params.name) and optional selection on the final
// segment ($token.?client_id), which yields absent when the key is missing.
// This resolver implements exactly those forms and refuses everything else.
// It is NOT a CEL evaluator and this file is NOT a conformance implementation
// of COAZ or COAZ-MCP.
// ---------------------------------------------------------------------------

const ABSENT = Symbol('absent');

function resolveExpression(expression, vars) {
  const optionalSplit = expression.split('.?');
  if (optionalSplit.length > 2) return { ok: false, reason: 'unsupported_expression' };
  const [plainPath, optionalKey] = optionalSplit;
  const segments = plainPath.split('.');
  if (segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(segment))) {
    return { ok: false, reason: 'unsupported_expression' };
  }
  let value = vars;
  for (const segment of segments) {
    if (typeof value !== 'object' || value === null || !(segment in value)) {
      // Plain field selection on a missing key is an evaluation error under
      // the framework's CEL default; a mapping error, and fail-closed.
      return { ok: false, reason: `expression_error:no_such_key:${segment}` };
    }
    value = value[segment];
  }
  if (optionalKey !== undefined) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(optionalKey)) {
      return { ok: false, reason: 'unsupported_expression' };
    }
    if (typeof value !== 'object' || value === null || !(optionalKey in value)) {
      return { ok: true, value: ABSENT };
    }
    value = value[optionalKey];
  }
  return { ok: true, value };
}

function resolveTemplate(template, vars) {
  if (typeof template === 'string') {
    if (template.startsWith('$$')) return { ok: true, value: template.slice(1) };
    if (template.startsWith('$')) return resolveExpression(template.slice(1), vars);
    return { ok: true, value: template };
  }
  if (Array.isArray(template)) {
    const out = [];
    for (const entry of template) {
      const resolved = resolveTemplate(entry, vars);
      if (!resolved.ok) return resolved;
      if (resolved.value !== ABSENT) out.push(resolved.value);
    }
    return { ok: true, value: out };
  }
  if (typeof template === 'object' && template !== null) {
    const out = {};
    for (const [key, entry] of Object.entries(template)) {
      const resolved = resolveTemplate(entry, vars);
      if (!resolved.ok) return resolved;
      if (resolved.value !== ABSENT) out[key] = resolved.value;
    }
    return { ok: true, value: out };
  }
  return { ok: true, value: template };
}

// ---------------------------------------------------------------------------
// The two pinned mappings.
// ---------------------------------------------------------------------------

// COAZ-MCP Draft 1, Section 7.2, quoted verbatim from the pinned source:
//   // tools/call  (applies when the tool declares no mapping)
//   { "evaluation": {
//       "subject": { "type": "identity", "id": "$token.sub" },
//       "context": { "agent": "$token.?client_id" },
//       "action": { "name": "tools/call" },
//       "resource": { "type": "tool", "id": "$params.name" } } }
export const DEFAULT_TOOLS_CALL_MAPPING = Object.freeze({
  evaluation: {
    subject: { type: 'identity', id: '$token.sub' },
    context: { agent: '$token.?client_id' },
    action: { name: 'tools/call' },
    resource: { type: 'tool', id: '$params.name' },
  },
});

// A declared mapping authored FOR THIS VECTOR in the style of the binding's
// Section 6 and Section 8 examples. It is well-formed under the binding's
// rules and maps exactly the fields a threshold policy consumes: amount,
// currency, and the instruction id. It does not map beneficiary_account.
// Nothing in the pinned framework or binding text rejects this mapping; the
// framework's expression contract explicitly allows a field to be omitted
// (absent), and no requirement makes the projection cover every argument.
export const DECLARED_RELEASE_PAYMENT_MAPPING = Object.freeze({
  evaluation: {
    subject: { type: 'identity', id: '$token.sub' },
    action: {
      name: 'release_payment',
      properties: {
        amount: '$params.arguments.amount',
        currency: '$params.arguments.currency',
      },
    },
    resource: { type: 'payment_instruction', id: '$params.arguments.payment_instruction_id' },
    context: { agent: '$token.?client_id' },
  },
});

export function translate(mapping, mcpCall, tokenClaims) {
  const envelopeKeys = Object.keys(mapping);
  if (envelopeKeys.length !== 1 || envelopeKeys[0] !== 'evaluation') {
    return { ok: false, reason: 'mapping_error:unsupported_envelope' };
  }
  const resolved = resolveTemplate(mapping.evaluation, {
    params: mcpCall.params,
    token: tokenClaims,
  });
  if (!resolved.ok) return { ok: false, reason: `mapping_error:${resolved.reason}` };
  const request = resolved.value;
  for (const required of ['subject', 'action', 'resource']) {
    if (!(required in request)) {
      return { ok: false, reason: `mapping_error:missing_required_field:${required}` };
    }
  }
  return { ok: true, request };
}

// ---------------------------------------------------------------------------
// The typed source action and the CAID-emitting translator (the close).
// ---------------------------------------------------------------------------

/**
 * The full typed source action: every caller-supplied argument, plus the
 * pinned action_type. Nothing is dropped here; lossiness, if any, happens in
 * the mapping, and the CAID is computed over this object, not the tuple.
 */
export function typedSourceAction(mcpCall) {
  return { action_type: ACTION_TYPE, ...mcpCall.params.arguments };
}

/**
 * Same translator, additionally computing a CAID over the full typed source
 * action and carrying it in the request context. Placement follows
 * caid/bindings/authzen-acta.md: context is the request-scoped bag under
 * AuthZEN Section 5.4, and the identifier adds no trust semantics to the
 * evaluation. When computeCaid refuses (for example a missing material field
 * of the registered type), the translation refuses with the named reason and
 * no request is constructed: fail-closed as a mapping error, never a crash.
 */
export function translateWithCaid(mapping, mcpCall, tokenClaims) {
  const action = typedSourceAction(mcpCall);
  const computed = computeCaid(action, { suite: 'jcs-sha256', definitions: DEFINITIONS });
  if (!computed.caid) {
    const refusals = computed.refusals ?? ['unspecified_refusal'];
    return { ok: false, reason: `caid_refused:${refusals[0]}`, refusals };
  }
  const translated = translate(mapping, mcpCall, tokenClaims);
  if (!translated.ok) return translated;
  const request = {
    ...translated.request,
    context: { ...(translated.request.context ?? {}), caid: computed.caid },
  };
  return { ok: true, request, caid: computed.caid, source_action: action };
}

// ---------------------------------------------------------------------------
// The toy PDP.
//
// Explicitly a toy: it decides on the tuple it is shown, and stands in for
// any spec-conformant PDP. Per AuthZEN Section 5.5 the decision is a boolean.
// It ignores context by design, exactly as a PDP with no context-aware policy
// would; the identifier carries no trust semantics and changes no evaluation
// behavior. No real PDP product is modeled or claimed vulnerable.
// ---------------------------------------------------------------------------

export function toyPdpDecide(request) {
  if (request?.subject?.id !== 'alice@example.com') return { decision: false };
  const action = request.action ?? {};
  const resource = request.resource ?? {};
  if (action.name === 'release_payment' && resource.type === 'payment_instruction') {
    const amount = action.properties?.amount;
    if (typeof amount !== 'string' || !/^\d+(\.\d+)?$/.test(amount)) return { decision: false };
    return { decision: Number(amount) <= 20000 };
  }
  if (action.name === 'tools/call' && resource.type === 'tool') {
    return { decision: resource.id === 'release_payment' };
  }
  return { decision: false };
}

// ---------------------------------------------------------------------------
// The relying check (the close, enforcement side).
//
// The relying party pinned the approved typed action at approval time. At the
// enforcement boundary it holds the observed source action, the presented
// context.caid, and the approved action. Every failure is a returned refusal
// with a named reason. The CAID proves content identity only; it confers no
// authorization and this check replaces no verifier.
// ---------------------------------------------------------------------------

function materialFieldNames(actionType) {
  const definition = DEFINITIONS.find((entry) => entry.action_type === actionType);
  if (!definition) return [];
  return [...definition.required_fields, ...(definition.optional_fields ?? [])]
    .map((field) => field.name);
}

export function relyingCheck({ observedAction, presentedCaid, approvedAction }) {
  if (parseCaid(presentedCaid).ok === false) {
    return { allowed: false, reason: 'caid_invalid:malformed_caid' };
  }
  const observed = verifyCaid(observedAction, presentedCaid, { definitions: DEFINITIONS });
  if (!observed.valid) {
    return { allowed: false, reason: `caid_invalid:${observed.reasons[0]}` };
  }
  const approved = computeCaid(approvedAction, { suite: 'jcs-sha256', definitions: DEFINITIONS });
  if (!approved.caid) {
    return { allowed: false, reason: `approved_action_invalid:${(approved.refusals ?? ['unspecified_refusal'])[0]}` };
  }
  if (presentedCaid !== approved.caid) {
    // Field attribution requires the approved action object, which this
    // boundary holds. The digest alone proves only inequality.
    const differing = materialFieldNames(approvedAction.action_type ?? '').filter(
      (name) => JSON.stringify(observedAction[name]) !== JSON.stringify(approvedAction[name]),
    );
    const suffix = differing.length > 0 ? differing.join(',') : 'content';
    return { allowed: false, reason: `caid_mismatch:${suffix}` };
  }
  return { allowed: true, reason: null };
}

// ---------------------------------------------------------------------------
// Byte identity, via the same RFC 8785 canonicalizer the CAID suite uses.
// ---------------------------------------------------------------------------

export function canonicalBytes(value) {
  const canonical = canonicalize(value);
  if (!canonical.ok) return { ok: false, refusals: canonical.refusals };
  return {
    ok: true,
    canonical: canonical.canonical,
    sha256: createHash('sha256').update(Buffer.from(canonical.canonical, 'utf8')).digest('hex'),
  };
}

// ---------------------------------------------------------------------------
// Corpus runner.
// ---------------------------------------------------------------------------

const TRANSLATORS = {
  default: (call, token) => translate(DEFAULT_TOOLS_CALL_MAPPING, call, token),
  declared: (call, token) => translate(DECLARED_RELEASE_PAYMENT_MAPPING, call, token),
  declared_caid: (call, token) => translateWithCaid(DECLARED_RELEASE_PAYMENT_MAPPING, call, token),
};

export function runCorpus(corpus) {
  const token = corpus.fixtures.token_claims;
  const byId = new Map();
  const results = [];
  let passed = 0;

  for (const entry of corpus.cases) {
    const call = corpus.fixtures[entry.call];
    const expect = entry.expect;
    const failures = [];
    const observations = {};

    const translated = TRANSLATORS[entry.translator](call, token);
    observations.constructed = translated.ok;
    if (translated.ok !== expect.constructed) {
      failures.push(`constructed=${translated.ok}, expected ${expect.constructed}`);
    }

    if (!translated.ok) {
      observations.reason = translated.reason;
      if (expect.reason !== undefined && translated.reason !== expect.reason) {
        failures.push(`reason=${translated.reason}, expected ${expect.reason}`);
      }
      observations.pdp_called = false;
      if (expect.pdp_called === false && observations.pdp_called !== false) {
        failures.push('pdp was called despite refused translation');
      }
    } else {
      const request = translated.request;
      observations.request = request;

      if (expect.request !== undefined) {
        const got = canonicalBytes(request);
        const want = canonicalBytes(expect.request);
        if (!got.ok || !want.ok || got.canonical !== want.canonical) {
          failures.push('constructed request differs from the pinned request');
        }
      }

      if (expect.tuple_identical_to !== undefined) {
        const reference = byId.get(expect.tuple_identical_to);
        const got = canonicalBytes(request);
        const ref = canonicalBytes(reference.observations.request);
        observations.tuple_bytes_sha256 = got.ok ? got.sha256 : null;
        observations.reference_tuple_bytes_sha256 = ref.ok ? ref.sha256 : null;
        if (!got.ok || !ref.ok || got.canonical !== ref.canonical) {
          failures.push('tuple is not byte-identical to the reference case');
        }
        const sourceGot = canonicalBytes(typedSourceAction(call));
        const sourceRef = canonicalBytes(
          typedSourceAction(corpus.fixtures[reference.entry.call]),
        );
        const sourcesIdentical = sourceGot.ok && sourceRef.ok
          && sourceGot.canonical === sourceRef.canonical;
        observations.source_actions_identical = sourcesIdentical;
        if (sourcesIdentical !== expect.source_identical_to_that_case_source) {
          failures.push('source-action identity did not match expectation');
        }
      }

      if (expect.context_caid !== undefined) {
        observations.context_caid = request.context?.caid ?? null;
        if (observations.context_caid !== expect.context_caid) {
          failures.push(`context.caid=${observations.context_caid}, expected ${expect.context_caid}`);
        }
      }

      const decision = toyPdpDecide(request);
      observations.pdp_decision = decision.decision;
      if (decision.decision !== expect.pdp_decision) {
        failures.push(`pdp_decision=${decision.decision}, expected ${expect.pdp_decision}`);
      }

      if (expect.relying_check !== undefined) {
        const approvedAction = typedSourceAction(corpus.fixtures[entry.approved_action_from]);
        const presentedCaid = entry.tamper_presented_caid ?? request.context?.caid;
        let check;
        try {
          check = relyingCheck({
            observedAction: translated.source_action ?? typedSourceAction(call),
            presentedCaid,
            approvedAction,
          });
        } catch (error) {
          check = { allowed: false, reason: `THREW:${error.message}` };
          failures.push('relying check threw instead of returning a refusal');
        }
        observations.relying_check = check;
        if (check.allowed !== expect.relying_check.allowed
          || check.reason !== expect.relying_check.reason) {
          failures.push(
            `relying_check=${JSON.stringify(check)}, expected ${JSON.stringify(expect.relying_check)}`,
          );
        }
        if (expect.caid_differs_from_approved === true) {
          const approved = computeCaid(approvedAction, { suite: 'jcs-sha256', definitions: DEFINITIONS });
          if (!approved.caid || approved.caid === request.context?.caid) {
            failures.push('expected the presented CAID to differ from the approved CAID');
          }
        }
      }
    }

    const record = { entry, observations, failures, passed: failures.length === 0 };
    byId.set(entry.id, record);
    results.push(record);
    if (record.passed) passed += 1;
  }

  return {
    '@profile': PROFILE,
    implementation_owner: 'EMILIA Protocol',
    independent_implementation: false,
    total: corpus.cases.length,
    passed_cases: passed,
    passed: passed === corpus.cases.length,
    results,
  };
}

// ---------------------------------------------------------------------------
// Demonstration entry point.
// ---------------------------------------------------------------------------

const isMain = process.argv[1]
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;

if (isMain) {
  const corpus = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
  const report = runCorpus(corpus);
  const width = 78;
  console.log('='.repeat(width));
  console.log(`Hostile COAZ/AuthZEN translation vector ${PROFILE}`);
  console.log('Sources pinned in source-lock.json; claim boundary in README.md');
  console.log('='.repeat(width));
  console.log('The PDP below is a toy: it decides on the tuple it is shown and stands in');
  console.log('for any spec-conformant PDP. No real PDP product is exercised or claimed');
  console.log('vulnerable.');
  console.log('-'.repeat(width));
  for (const [index, record] of report.results.entries()) {
    const o = record.observations;
    console.log(`${index + 1}. ${record.entry.id}  [${record.passed ? 'pass' : 'FAIL'}]`);
    if (!o.constructed) {
      console.log(`   translation refused, reason: ${o.reason} (PDP never called)`);
    } else {
      if (o.tuple_bytes_sha256) {
        console.log(`   tuple bytes sha256: ${o.tuple_bytes_sha256}`);
        console.log(`   identical to ${record.entry.expect.tuple_identical_to}: `
          + `${o.tuple_bytes_sha256 === o.reference_tuple_bytes_sha256}`
          + ` (source actions identical: ${o.source_actions_identical})`);
      }
      if (o.context_caid) console.log(`   context.caid: ${o.context_caid}`);
      console.log(`   toy PDP decision: ${o.pdp_decision}`);
      if (o.relying_check) {
        console.log(`   relying check: allowed=${o.relying_check.allowed}`
          + `${o.relying_check.reason ? `, reason=${o.relying_check.reason}` : ''}`);
      }
    }
    for (const failure of record.failures) console.log(`   FAIL: ${failure}`);
  }
  console.log('-'.repeat(width));
  console.log(`${report.passed_cases}/${report.total} cases passed.`);
  console.log('A PDP that decides on the translated tuple cannot distinguish these');
  console.log('source actions; the CAID in request context makes the substitution a');
  console.log('named refusal at the relying boundary, without changing the PDP.');
  if (!report.passed) process.exitCode = 1;
}
