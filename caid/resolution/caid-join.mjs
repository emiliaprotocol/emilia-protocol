// SPDX-License-Identifier: Apache-2.0
//
// The join between resolve-before-approve and CAID.
//
// computeResolvedCaid forms the Action Object AFTER the reference-typed
// arguments have been resolved, so the identifier the human approves
// commits to the resolved targets. verifyResolvedCaidAtDispatch runs the
// ordinary CAID verification AND the dispatch-time re-resolution, and
// refuses if either fails.
//
// The two checks are separate and stay separate. CAID says "this object
// recomputes to this identifier". The resolution check says "these
// references still resolve to what they resolved to at approval". Neither
// says the action is authorized; that is the receipt's job, in a different
// trust boundary.
//
// Fail-closed: both exports return reasons, never throw.

import { computeCaid, verifyCaid } from '../impl/js/caid.mjs';
import {
  BINDING_FIELD,
  checkResolvedReferencesAtDispatch,
  freezeResolvedReferences,
} from './resolve-before-approve.mjs';

function isPlainObject(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * computeResolvedCaid(actionType, args, {suite, definitions, spec, resolvers})
 *   -> {caid, digest, action, observed, report}
 *   -> {refusals: [string]}
 *
 * `action` is the Action Object to present for approval: the action type
 * plus the observed arguments plus the frozen resolution binding. `report`
 * carries the plaintext resolved identities for the approval surface to
 * DISPLAY - showing the label without the resolved identity is the
 * presentation half of the same bug.
 */
export async function computeResolvedCaid(actionType, args, options) {
  const opts = isPlainObject(options) ? options : {};
  const frozen = await freezeResolvedReferences(args, opts.spec, opts.resolvers);
  if (!frozen.ok) return { refusals: frozen.refusals };

  if (typeof actionType !== 'string') return { refusals: ['invalid_action_type'] };
  if (Object.prototype.hasOwnProperty.call(frozen.observed, 'action_type')) {
    // The action type is set by the caller of this function, not smuggled
    // in through tool arguments.
    return { refusals: ['invalid_action_type'] };
  }

  const action = { action_type: actionType, ...frozen.observed };
  const computed = computeCaid(action, { suite: opts.suite, definitions: opts.definitions });
  if (computed.refusals) return { refusals: computed.refusals };

  return {
    caid: computed.caid,
    digest: computed.digest,
    action: Object.freeze(action),
    observed: frozen.observed,
    report: frozen.report,
  };
}

/**
 * verifyResolvedCaidAtDispatch(action, caidString, {definitions, spec, resolvers})
 *   -> {valid: boolean, reasons: [string]}
 *
 * Reason order: the CAID reasons first (its own closed set, unchanged),
 * then the resolution refusals. A caller that only ran verifyCaid would
 * accept a swapped symlink, because the argument bytes are identical and
 * the CAID therefore still verifies. That is the point of running both.
 */
export async function verifyResolvedCaidAtDispatch(action, caidString, options) {
  const opts = isPlainObject(options) ? options : {};
  const caidResult = verifyCaid(action, caidString, { definitions: opts.definitions });
  const reasons = Array.isArray(caidResult.reasons) ? [...caidResult.reasons] : [];

  const resolution = await checkResolvedReferencesAtDispatch(action, opts.spec, opts.resolvers);
  if (!resolution.ok && Array.isArray(resolution.refusals)) reasons.push(...resolution.refusals);

  return { valid: reasons.length === 0, reasons };
}

export { BINDING_FIELD };
