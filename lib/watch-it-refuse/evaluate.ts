// SPDX-License-Identifier: Apache-2.0
//
// Watch It Refuse — the real evaluation behind the /refuse demo.
//
// Every verdict on the page comes from the repo's shipped verification and
// enforcement code, run over synthetic demo artifacts:
//
//   - canonical action identity   -> caid/impl/js/caid.mjs computeCaid/verifyCaid
//                                    against caid/registry/action-types.json
//   - evidence sufficiency        -> lib/evidence/admissibility evaluateAdmissibility
//                                    (relying-party policy, classified verdict)
//   - receipt verification        -> @emilia-protocol/require-receipt verifyEmiliaReceipt
//   - assurance evaluation        -> @emilia-protocol/require-receipt evaluateReceiptAssurance
//   - execution-field binding     -> @emilia-protocol/gate verifyExecutionBinding
//   - enforcement + one-time use  -> @emilia-protocol/gate createTrustedActionFirewall check()
//
// DEMO BOUNDARY (load-bearing): nothing here executes any action. The demo
// issuer keypair is generated in-process at first use, namespaced
// "demo.watch-it-refuse", and is never a production or cloud issuer key. Every
// minted artifact carries a top-level `demo: true` AND a signed in-claim demo
// marker AND the demo issuer id, so it can never pass as production evidence.
// The demo ceremony earns only the 'software' assurance tier; production
// policies for actions like these pin class_a (device biometric) or quorum.

import crypto from 'node:crypto';

import { computeCaid, verifyCaid } from '@/caid/impl/js/caid.mjs';
import caidActionTypeRegistry from '@/caid/registry/action-types.json';
import { createTrustedActionFirewall, verifyExecutionBinding } from '@/packages/gate/index.js';
import {
  approvalActionHash,
  canonicalizeStrictJson,
  evaluateReceiptAssurance,
  findActionRequirement,
  isCanonicalizable,
  verifyEmiliaReceipt,
  ACTION_RISK_MANIFEST_VERSION,
} from '@/packages/require-receipt/index.js';
import { evaluateAdmissibility } from '@/lib/evidence/admissibility';

import {
  MAX_ACTION_TEXT_CHARS,
  WIR_ACTION_TYPES,
  WIR_ARCHETYPE_LABELS,
  buildActionObject,
  classifyActionText,
  type WirArchetype,
} from './classify';
import { plainReason } from './reasons';

export const DEMO_ISSUER_ID = 'demo.watch-it-refuse';
export const DEMO_NOTICE =
  'No action is performed. This demonstrates the authorization decision layer only.';
const DEMO_RECEIPT_NOTICE =
  'Demo authorization receipt minted by the Watch It Refuse public demo under the '
  + `"${DEMO_ISSUER_ID}" demo issuer. Not production evidence. No action was performed.`;
const CAID_SUITE = 'jcs-sha256';
const MAX_AGE_SEC = 900;

type Obj = Record<string, any>;

const REGISTRY_DEFINITIONS: Obj[] = (caidActionTypeRegistry as Obj).types as Obj[];

function registryDefinition(actionType: string): Obj | null {
  return REGISTRY_DEFINITIONS.find((entry) => entry.action_type === actionType) || null;
}

// ---------------------------------------------------------------------------
// Demo issuer — generated in-process, never persisted, never a production key.
// ---------------------------------------------------------------------------

type DemoIssuer = {
  issuerId: string;
  privateKey: crypto.KeyObject;
  publicKeyB64u: string;
};

let _demoIssuer: DemoIssuer | null = null;

export function getDemoIssuer(): DemoIssuer {
  if (!_demoIssuer) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    _demoIssuer = {
      issuerId: DEMO_ISSUER_ID,
      privateKey,
      publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
  }
  return _demoIssuer;
}

/**
 * Mint a demo EP-RECEIPT-v1 over the canonical action object. The signature is
 * Ed25519 over the same canonicalizeStrictJson(payload) bytes that
 * verifyEmiliaReceipt checks, signed by the in-process demo issuer key. Demo
 * marking: top-level `demo: true` + `demo_issuer`, and `demo: true` +
 * `demo_notice` INSIDE the signed claim (so stripping the marker breaks the
 * signature).
 */
export function mintDemoReceipt(actionObject: Obj, text: string): Obj {
  const issuer = getDemoIssuer();
  const payload: Obj = {
    receipt_id: `ep:receipt:${DEMO_ISSUER_ID}:${crypto.randomBytes(9).toString('base64url')}`,
    subject: 'agent:watch-it-refuse-demo',
    issuer: DEMO_ISSUER_ID,
    created_at: new Date().toISOString(),
    demo: true,
    claim: {
      ...actionObject,
      outcome: 'allow',
      approver: `ep:approver:${DEMO_ISSUER_ID}:visitor`,
      requested_text: text,
      demo: true,
      demo_notice: DEMO_RECEIPT_NOTICE,
    },
  };
  const value = crypto
    .sign(null, Buffer.from(canonicalizeStrictJson(payload), 'utf8'), issuer.privateKey)
    .toString('base64url');
  return {
    '@version': 'EP-RECEIPT-v1',
    demo: true,
    demo_issuer: DEMO_ISSUER_ID,
    payload,
    signature: { algorithm: 'Ed25519', value },
  };
}

// ---------------------------------------------------------------------------
// Demo gate manifest — one guarded entry per registry action type in the demo.
// ---------------------------------------------------------------------------

const ARCHETYPE_WHY: Readonly<Record<WirArchetype, string>> = Object.freeze({
  payment: 'Moves funds irreversibly once settled.',
  destructive: 'Destroys data that may not be recoverable.',
  communication: 'Cannot be unsent once delivered externally.',
  deployment: 'Changes live production behavior.',
  physical: 'Mutates the physical world through an actuator.',
  generic: 'A consequential action outside the reversible sandbox.',
});

export function buildWirManifest(): Obj {
  const seen = new Set<string>();
  const actions: Obj[] = [];
  for (const archetype of Object.keys(WIR_ACTION_TYPES) as WirArchetype[]) {
    const actionType = WIR_ACTION_TYPES[archetype];
    if (seen.has(actionType)) continue;
    seen.add(actionType);
    const def = registryDefinition(actionType);
    const requiredFields = Array.isArray(def?.required_fields)
      ? def.required_fields.map((field: Obj) => field.name)
      : [];
    actions.push({
      id: `wir.${actionType}`,
      label: WIR_ARCHETYPE_LABELS[archetype],
      action_type: actionType,
      // 'high' + 'software': the demo ceremony is an explicit click-through
      // that earns only the software tier; the manifest validator (correctly)
      // refuses software assurance for 'critical' actions, and this demo does
      // not pretend to a stronger ceremony than it runs.
      risk: 'high',
      receipt_required: true,
      assurance_class: 'software',
      match: { protocol: 'demo', tool: actionType },
      why: ARCHETYPE_WHY[archetype],
      execution_binding: {
        required_fields: ['action_type', ...requiredFields],
      },
    });
  }
  return { '@version': ACTION_RISK_MANIFEST_VERSION, actions };
}

// ---------------------------------------------------------------------------
// Relying-party evidence policy per archetype (never read from the bundle).
// ---------------------------------------------------------------------------

const RELIANCE_PURPOSES: Readonly<Record<WirArchetype, string>> = Object.freeze({
  payment: 'money_movement',
  destructive: 'data_destruction',
  communication: 'external_communication',
  deployment: 'production_change',
  physical: 'physical_actuation',
  generic: 'consequential_action',
});

function evidencePolicy(archetype: WirArchetype): Obj {
  return {
    policy_id: `wir:${archetype}:v1`,
    reliance_purpose: RELIANCE_PURPOSES[archetype],
    requirement: 'authorization_receipt',
    freshness_sec: { authorization_receipt: MAX_AGE_SEC },
    require_action_agreement: true,
  };
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export class WirInputError extends Error {
  code: string;
  status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function validateActionText(text: unknown): string {
  if (typeof text !== 'string') {
    throw new WirInputError('action_text_required', 'text must be a string describing the action');
  }
  // A lone surrogate is representable in JSON but outside the canonical JSON
  // profile every downstream hash runs on. Refuse it as a typed input error
  // (via the repo's own profile check) rather than letting a canonicalizer
  // throw later: typed 4xx, never a crash.
  if (!isCanonicalizable(text)) {
    throw new WirInputError('action_text_invalid', 'text must be well-formed Unicode');
  }
  const trimmed = text.trim().replace(/\s+/g, ' ');
  if (trimmed.length < 3) {
    throw new WirInputError('action_text_too_short', 'text must be at least 3 characters');
  }
  if (trimmed.length > MAX_ACTION_TEXT_CHARS) {
    throw new WirInputError('action_text_too_long', `text must be at most ${MAX_ACTION_TEXT_CHARS} characters`);
  }
  return trimmed;
}

function reasoned(code: unknown): { code: string | null; plain: string } {
  return { code: typeof code === 'string' ? code : null, plain: plainReason(code) };
}

function decisionSummary(decision: Obj): Obj {
  return {
    allow: decision.allow === true,
    status: decision.status ?? null,
    reason: reasoned(decision.reason),
    challenge: decision.challenge ?? null,
    receipt_required_header: decision.header ?? null,
    evidence_hash: decision.evidence?.hash ?? null,
    consumption_key: decision.evidence?.consumption_key ?? null,
  };
}

function admissibilitySummary(result: Obj): Obj {
  return {
    verdict: result.verdict,
    verdict_plain: plainReason(result.verdict),
    policy_id: result.policy_id,
    reliance_purpose: result.reliance_purpose,
    requirement: result.requirement,
    satisfied_by: result.satisfied_by,
    reasons: result.reasons,
    replay_digest: result.replay_digest,
    per_component: result.per_component,
  };
}

/**
 * Run the full Watch It Refuse evaluation for one typed action.
 *
 * Without `approve`: the refusal path — real CAID computation, real
 * evidence-sufficiency verdict over an EMPTY evidence bundle, and the real
 * gate refusal (HTTP 428 Receipt-Required challenge, typed reason).
 *
 * With `approve: true`: additionally mints a demo receipt under the demo
 * issuer and runs the full lifecycle — VERIFIED (verifyEmiliaReceipt) ->
 * MATCH (verifyCaid + verifyExecutionBinding) -> SATISFIED
 * (evaluateReceiptAssurance + admissibility) -> AUTHORIZED (gate check,
 * consuming the receipt) -> CONSUMED (a second check with the same receipt is
 * refused with the typed replay reason). Both gate checks run in this call
 * against the same consumption store, so the replay refusal is genuinely
 * computed, not narrated.
 */
export async function evaluateWatchItRefuse(
  { text, approve = false }: { text: string; approve?: boolean },
): Promise<Obj> {
  const cleanText = validateActionText(text);
  const archetype = classifyActionText(cleanText);
  const actionType = WIR_ACTION_TYPES[archetype];
  const definition = registryDefinition(actionType);
  const action = buildActionObject(archetype, cleanText);

  // Stage 2 — canonical action identity (real registry computation).
  const caidResult: Obj = computeCaid(action, {
    suite: CAID_SUITE,
    definitions: REGISTRY_DEFINITIONS,
  });
  const caid: string | null = caidResult.caid ?? null;
  const caidRefusals: string[] = Array.isArray(caidResult.refusals) ? caidResult.refusals : [];
  const actionDigest = approvalActionHash(action);

  // Stage 3 — what this archetype requires before execution.
  const manifest = buildWirManifest();
  const requirement = findActionRequirement(manifest, { action_type: actionType });
  const policy = evidencePolicy(archetype);
  const asOf = new Date().toISOString();

  // Stage 4 — evidence sufficiency over the evidence actually present: none.
  const evidenceCheck = evaluateAdmissibility(
    { action_digest: actionDigest, components: [] },
    policy,
    { as_of: asOf },
  );

  // Stage 5 — the enforcement decision itself. Fresh in-process gate per
  // evaluation; both the refusal and (on the approval path) the consume +
  // replay checks run against this same gate instance.
  const issuer = getDemoIssuer();
  const gate = createTrustedActionFirewall({
    manifest,
    trustedKeys: [issuer.publicKeyB64u],
    maxAgeSec: MAX_AGE_SEC,
    allowEphemeralStore: true,
    strictEvidence: true,
  });

  const refusalDecision = await gate.check({
    selector: { action_type: actionType },
    observedAction: action,
  });

  const base: Obj = {
    demo: true,
    notice: DEMO_NOTICE,
    evaluated_at: asOf,
    input: { text: cleanText },
    classification: {
      archetype,
      label: WIR_ARCHETYPE_LABELS[archetype],
      action_type: actionType,
      risk_class: definition?.risk_class ?? null,
      summary: definition?.summary ?? null,
    },
    identity: {
      caid,
      digest: caidResult.digest ?? null,
      suite: CAID_SUITE,
      refusals: caidRefusals.map((code) => reasoned(code)),
      action_object: action,
    },
    requirements: {
      receipt_required: requirement?.receipt_required === true,
      assurance_class: requirement?.assurance_class ?? null,
      max_age_sec: MAX_AGE_SEC,
      one_time_consumption: true,
      consumption_scope: 'ephemeral_per_evaluation',
      execution_binding_fields: requirement?.execution_binding?.required_fields ?? [],
      evidence_policy: policy,
      why: requirement?.why ?? null,
    },
    evidence_check: admissibilitySummary(evidenceCheck),
    refusal: decisionSummary(refusalDecision),
  };

  if (!approve) return base;

  // Demo approval path — mint under the demo issuer, then run the lifecycle.
  const receipt = mintDemoReceipt(action, cleanText);

  const verification = verifyEmiliaReceipt(receipt, {
    trustedKeys: [issuer.publicKeyB64u],
    action: actionType,
    maxAgeSec: MAX_AGE_SEC,
  });

  const caidCheck: Obj = caid
    ? verifyCaid(action, caid, { definitions: REGISTRY_DEFINITIONS })
    : { valid: false, reasons: ['not_evaluated:no_caid_issued'] };
  const binding = verifyExecutionBinding({ requirement, receipt, observedAction: action });

  const assurance = evaluateReceiptAssurance(receipt, requirement?.assurance_class ?? 'software', {});
  const presentAdmissibility = evaluateAdmissibility(
    {
      action_digest: actionDigest,
      components: [{
        type: 'authorization_receipt',
        label: 'demo authorization receipt',
        verified: verification.ok === true,
        action_digest: actionDigest,
        issued_at: receipt.payload.created_at,
        outcome: 'allow',
      }],
    },
    policy,
    { as_of: new Date().toISOString() },
  );

  const authorization = await gate.check({
    selector: { action_type: actionType },
    receipt,
    observedAction: action,
  });
  const replay = await gate.check({
    selector: { action_type: actionType },
    receipt,
    observedAction: action,
  });

  return {
    ...base,
    approval: {
      demo: true,
      ceremony: 'click_through_software_tier',
      ceremony_notice:
        'This demo approval is an explicit click-through earning the software assurance tier only. '
        + 'Production policies for actions like this pin class_a (device biometric) or quorum ceremonies.',
      receipt,
      stages: {
        verified: {
          ok: verification.ok === true,
          reason: reasoned(verification.ok ? 'allow' : `receipt_rejected:${verification.reason}`),
          detail: verification.detail ?? null,
          signer: verification.signer ?? null,
          receipt_id: verification.receipt_id ?? null,
        },
        match: {
          ok: caidCheck.valid === true && binding.ok === true,
          caid: {
            valid: caidCheck.valid === true,
            reasons: (caidCheck.reasons ?? []).map((code: string) => reasoned(code)),
          },
          execution_binding: binding,
        },
        satisfied: {
          ok: assurance.ok === true && presentAdmissibility.verdict === 'admissible',
          assurance: {
            ok: assurance.ok === true,
            have: assurance.have,
            need: assurance.need,
            reason: reasoned(assurance.reason),
          },
          admissibility: admissibilitySummary(presentAdmissibility),
        },
        authorized: decisionSummary(authorization),
        consumed: {
          // This proves only in-process consumption inside this synthetic
          // evaluation: the same receipt, presented again to the same
          // ephemeral gate instance, is refused. It is not a durable or
          // cross-request production consumption claim.
          consumed: authorization.allow === true && replay.allow !== true,
          replay_attempt: decisionSummary(replay),
        },
      },
    },
  };
}
