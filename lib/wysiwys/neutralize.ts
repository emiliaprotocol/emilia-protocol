// SPDX-License-Identifier: Apache-2.0
/**
 * lib/wysiwys/neutralize — the WYSIWYS layer's hostile-text guard.
 *
 * The classification lives in @emilia-protocol/verify (hostile-text.ts) so the
 * free-text surface and this one can never disagree about what is dangerous.
 * What differs is the RESPONSE, and the difference is the whole design:
 *
 *   free text (initiator statement) → ESCAPE, because it must still be shown
 *   action fields (this module)     → REFUSE, because there is no legitimate
 *                                     reading of a bidi override inside an
 *                                     account identifier
 *
 * WHY REFUSE RATHER THAN NEUTRALIZE IN THE RENDERER. Neutralizing inside
 * renderValue() would change `display_hash` for any action containing such a
 * codepoint, which is a change to the frozen EP-WYSIWYS-RENDER-v1 profile and
 * requires a profile version bump, not an in-place edit. Refusing at input
 * leaves every existing receipt byte-identical, matches the project rule that
 * malformed or attacker input returns a refusal with a named reason, and closes
 * the spoof completely: an action that is refused never reaches the renderer.
 *
 * THE ATTACK THIS CLOSES. A `target_resource_id` of `acct-9931` followed by a
 * literal U+202E (RIGHT-TO-LEFT OVERRIDE) and then `live` renders to the
 * approver as `acct-9931evil`. (The codepoint is described rather than written
 * here on purpose: a source file that demonstrates the attack in a comment is
 * itself a review-time hazard, which the repository's own scanner flags.)
 * Both `action_hash` and `display_hash` cover
 * the hostile bytes, so verification passes and the display attestation is
 * "faithful" — the deception is purely visual, aimed at the human at the moment
 * of decision, which is precisely what WYSIWYS exists to prevent.
 */
import { scanHostileDeep, formatCodepoints } from '@emilia-protocol/verify';

/**
 * Every action field the WYSIWYS profile renders to a human. Kept in sync with
 * RENDER_FIELDS and POLICY_ROLLOUT_RENDER_FIELDS in ./render.ts — a field that
 * is rendered but missing here would be unguarded, so additions to either list
 * belong in both.
 */
export const RENDERED_ACTION_FIELDS: readonly string[] = Object.freeze([
  'action_type',
  'target_resource_id',
  'organization_id',
  'actor_id',
  'policy_id',
  'amount',
  'currency',
  'requested_at',
  'risk_flags',
  'executing_key_id',
  'rollout_policy_id',
  'rollout_policy_key',
  'rollout_policy_version',
  'rollout_policy_rules',
  'rollout_policy_mode',
  'rollout_policy_status',
  'rollout_environment',
  'rollout_strategy',
  'rollout_canary_pct',
  'rollout_metadata',
  'rollout_before_state',
  'rollout_after_state',
]);

export interface HostileFieldFinding {
  field: string;
  codepoints: number[];
}

/**
 * Scan the rendered fields of an action-shaped object for codepoints that can
 * misrepresent the rendering to a human.
 *
 * Scans only the fields the renderer actually reads: a hostile codepoint in a
 * field that is never displayed cannot deceive anyone, and refusing on it would
 * reject legitimate payloads for no security gain.
 *
 * @returns one finding per offending field, empty when the action is safe.
 */
export function findHostileRenderedFields(action: unknown): HostileFieldFinding[] {
  if (!action || typeof action !== 'object') return [];
  const source = action as Record<string, unknown>;
  const findings: HostileFieldFinding[] = [];
  for (const field of RENDERED_ACTION_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(source, field)) continue;
    const codepoints = scanHostileDeep(source[field]);
    if (codepoints.length) findings.push({ field, codepoints });
  }
  return findings;
}

/**
 * The fail-closed refusal an API route returns. Null when the action is safe.
 *
 * The detail names the field and the exact codepoints so an operator can see
 * what was rejected without the refusal itself echoing the hostile bytes back
 * into another display surface.
 */
export function hostileRenderedFieldRefusal(
  action: unknown,
): { status: number; code: string; detail: string } | null {
  const findings = findHostileRenderedFields(action);
  if (!findings.length) return null;
  const detail = findings
    .map((f) => `${f.field} (${formatCodepoints(f.codepoints)})`)
    .join('; ');
  return {
    status: 400,
    code: 'hostile_display_codepoints',
    detail:
      'Action fields rendered to a human approver must not contain bidirectional '
      + 'overrides, zero-width characters, or control characters, which can make the '
      + `rendering misrepresent the signed action: ${detail}`,
  };
}
