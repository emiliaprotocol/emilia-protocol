// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — independent re-performance verifier (EP-GATE-REPERFORMANCE-v1).
 *
 * The auditor's "trust nothing, recompute everything" tool. Re-performance is
 * the highest form of audit evidence: instead of reading the deployer's report
 * and believing it, the auditor takes the raw evidence entries and REDOES the
 * work — rebuilds the hash chain link by link and checks it with the evidence
 * log's own verifier, cryptographically re-verifies every receipt / signoff /
 * quorum document an entry carries, recomputes the decision counts from
 * scratch, and diffs those recomputed numbers against what a report pack
 * claims. Vendor logs assert; this recomputes.
 *
 * INDEPENDENCE BY CONSTRUCTION: counts are recomputed here from the raw
 * entries — this module deliberately does NOT import metering.js or any report
 * builder, so a bug in a report builder cannot hide from its own cross-check.
 * The only imports are the primitives being re-driven: the evidence log's real
 * verify() and the protocol verifiers (verifyEmiliaReceipt /
 * verifyWebAuthnSignoff / verifyQuorum).
 *
 * FAIL CLOSED everywhere:
 *   - one broken chain link fails the chain from that point — the remainder is
 *     not vouched for;
 *   - one failed re-verification is a NAMED failure ({hash, reason}), never
 *     absorbed into a pass count;
 *   - an entry that references a receipt but does not carry the verifiable
 *     material is counted `not_reverifiable` — never silently passed;
 *   - a reported pack of unknown @version is refused, never fuzzily matched.
 *
 * HONESTY BOUNDARY (carried inside the artifact): this SUPPORTS an auditor's
 * re-performance procedure. It does not conclude, opine, or certify — and it
 * cannot establish log COMPLETENESS (a chain rewritten in full, or entries
 * withheld before supply, is invisible from the entries alone; anchor the head
 * hash externally to close that), nor runtime freshness / one-time consumption
 * (properties of the moment of decision, not re-performable after the fact).
 *
 * Deterministic: pure over (entries, issuerKeys); time enters only through the
 * injectable `now` (generated_at). No sampling, no randomness.
 */
import crypto from 'node:crypto';
import { createEvidenceLog } from '../evidence.js';
import { validatePinnedQuorumPolicy, verifyEmiliaReceipt } from '@emilia-protocol/require-receipt';
import { verifyQuorum, verifyWebAuthnSignoff } from '@emilia-protocol/verify';

export const REPERFORMANCE_VERSION = 'EP-GATE-REPERFORMANCE-v1';

// Wire-format identifiers of the packs compareToReported() can cross-check.
// Restated locally — NOT imported from the builders — so this module remains a
// standalone auditor tool with zero dependency on the code it checks.
const USAGE_PACK_VERSION = 'EP-GATE-USAGE-v1';
const UNDERWRITER_PACK_VERSION = 'EP-GATE-UNDERWRITER-ATTESTATION-v1';

// A verifiable payload carried by an evidence entry (see collectMaterial below).
type CarriedMaterial = { type: string; doc: any; key?: any };

/** Deterministic key-sorted copy — output is byte-stable regardless of entry order. */
function sortedCounts(obj) {
  const out = {};
  for (const k of Object.keys(obj).sort()) out[k] = obj[k];
  return out;
}

/** The checks a verifier reported false, as one stable, named string. */
function failingChecks(checks) {
  const bad = Object.keys(checks || {}).filter((k) => checks[k] === false).sort();
  return bad.length ? bad.join('+') : 'unspecified';
}

/**
 * The verifiable payloads an entry CARRIES (not the verification RESULTS the
 * gate recorded about them — `tier_evidence` / `rejected` are the gate's own
 * conclusions and are deliberately ignored: re-performance trusts nothing the
 * gate concluded, only material it can re-verify itself).
 *
 * Recognized carriers:
 *   - entry.receipt                    full EP-RECEIPT-v1 document
 *   - entry.signoff / payload.signoff  WebAuthn device-signoff evidence,
 *     with the approver key at entry.approver_public_key or
 *     receipt.payload.approver_public_key
 *   - entry.quorum / payload.quorum    full EP-QUORUM-v1 document
 */
function collectMaterial(e) {
  const out: CarriedMaterial[] = [];
  const receipt = e.receipt;
  const payload = receipt && typeof receipt === 'object' && receipt.payload
    && typeof receipt.payload === 'object' ? receipt.payload : null;
  if (receipt !== undefined && receipt !== null) out.push({ type: 'receipt', doc: receipt });
  const signoff = e.signoff ?? payload?.signoff;
  if (signoff !== undefined && signoff !== null) {
    out.push({
      type: 'signoff',
      doc: signoff,
      key: e.approver_public_key ?? payload?.approver_public_key ?? null,
    });
  }
  const quorum = e.quorum ?? payload?.quorum;
  if (quorum !== undefined && quorum !== null) out.push({ type: 'quorum', doc: quorum });
  return out;
}

/**
 * Re-verify one carried payload. Returns null on pass, a NAMED reason on fail.
 * Freshness is intentionally not re-enforced (maxAgeSec: 0): it was a runtime
 * property of the decision moment and cannot be re-performed at audit time —
 * what IS re-performed is the cryptography (signature, issuer trust, action
 * binding, ceremony checks).
 */
function spkiFingerprint(value) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(value, 'base64url'), format: 'der', type: 'spki' });
    return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
  } catch { return null; }
}

function pinnedApproverEntry(approverKeys: Record<string, any> | null | undefined, approver: any, carriedKey: any = null) {
  if (!approverKeys || typeof approverKeys !== 'object' || Array.isArray(approverKeys)) return null;
  const candidates = Object.values(approverKeys).filter((entry) => entry && typeof entry === 'object'
    && entry.approver_id === approver && typeof entry.public_key === 'string');
  if (carriedKey) {
    const fingerprint = spkiFingerprint(carriedKey);
    const matches = candidates.filter((entry) => fingerprint && spkiFingerprint(entry.public_key) === fingerprint);
    return matches.length === 1 ? matches[0] : null;
  }
  return candidates.length === 1 ? candidates[0] : null;
}

function reverifyMaterial(m, {
  issuerKeys, action, rpId, allowedOrigins, approverKeys, quorumPolicy, quorumPolicies,
}) {
  if (m.type === 'receipt') {
    const r = verifyEmiliaReceipt(m.doc, {
      trustedKeys: issuerKeys, allowInlineKey: false, action, maxAgeSec: 0,
    });
    return r.ok ? null : `receipt:${r.reason}`;
  }
  if (m.type === 'signoff') {
    if (typeof rpId !== 'string' || !rpId || !Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
      return 'signoff:relying_party_scope_unpinned';
    }
    const approver = m.doc?.context?.approver;
    const entry = pinnedApproverEntry(approverKeys, approver, m.key);
    if (!entry) return 'signoff:approver_key_unpinned_or_ambiguous';
    const r = verifyWebAuthnSignoff(m.doc, entry.public_key, { rpId, allowedOrigins });
    return r.valid ? null : `signoff:${r.error ? `error:${r.error}` : `checks_failed:${failingChecks(r.checks)}`}`;
  }
  if (m.type === 'quorum') {
    if (typeof rpId !== 'string' || !rpId || !Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
      return 'quorum:relying_party_scope_unpinned';
    }
    const pinnedPolicy = (quorumPolicies && typeof quorumPolicies === 'object' ? quorumPolicies[action] : null)
      || quorumPolicy;
    const policy = validatePinnedQuorumPolicy(pinnedPolicy);
    if (!policy.ok) return `quorum:${policy.reason}`;
    const members = Array.isArray(m.doc?.members) ? m.doc.members.map((member) => {
      const entry = pinnedApproverEntry(
        approverKeys,
        member?.signoff?.context?.approver,
        member?.approver_public_key,
      );
      return entry ? { ...member, approver_public_key: entry.public_key } : null;
    }) : [];
    if (members.length === 0 || members.some((member) => !member)) return 'quorum:approver_key_unpinned_or_ambiguous';
    const r = verifyQuorum({ ...m.doc, policy: policy.policy, members }, { rpId, allowedOrigins });
    return r.valid ? null : `quorum:checks_failed:${failingChecks(r.checks)}`;
  }
  /* c8 ignore next */
  return `unknown_material:${m.type}`; // unreachable; fail closed regardless
}

/**
 * Re-perform the evidence: rebuild the chain, re-verify carried cryptographic
 * material, recompute the counts. Async because the chain is rebuilt through
 * the evidence log's own (async) record().
 *
 * The entries MUST be the complete log from genesis (`evidence.all()` or a
 * full export). A partial slice fails the chain (fail closed) because its
 * first link cannot chain from 'genesis'.
 *
 * Chain method — drives evidence.js's REAL verify(), twice over:
 *   1. every supplied entry body (its own seq/prev_hash included, its hash
 *      stripped) is re-recorded into a fresh createEvidenceLog(), which
 *      recomputes the canonical-JSON sha256 for that exact body; a recomputed
 *      hash that differs from the SUPPLIED hash is a tampered/forged entry —
 *      broken from that point;
 *   2. the rebuilt log's own verify() then walks the whole chain, catching
 *      link-level attacks the per-entry recompute cannot (a removed entry, or
 *      an entry rewritten WITH a consistently recomputed hash — its successor's
 *      prev_hash no longer matches).
 *
 * @param {Array<object>} entries  the full evidence log (evidence.all())
 * @param {object} [o]
 * @param {string[]} [o.issuerKeys=[]]  pinned base64url SPKI issuer keys, sourced
 *   by the AUDITOR out of band — never from the entries themselves
 * @param {number|function} [o.now=Date.now]  clock for generated_at (pin for determinism)
 * @param {object} [o.approverKeys={}] auditor-pinned identity-bound approver keys
 * @param {string|null} [o.rpId] bind carried WebAuthn assertions to this relying-party id
 * @param {string[]} [o.allowedOrigins=[]] exact accepted WebAuthn origins
 * @param {object} [o.quorumPolicy] auditor-pinned global organizational quorum rule
 * @param {object} [o.quorumPolicies] action_type -> auditor-pinned quorum rule
 * @returns {Promise<object>} EP-GATE-REPERFORMANCE-v1 document:
 *   { chain: {ok, entries, head}, receipts: {reverified, failed, not_reverifiable},
 *     counts: {allows, denies, replays_blocked, by_action_type}, ... }
 */
export async function reperformEvidence(entries: any[] = [], {
  issuerKeys = [],
  approverKeys = {},
  now = Date.now,
  rpId = null,
  allowedOrigins = [],
  quorumPolicy = null,
  quorumPolicies = {},
}: {
  issuerKeys?: string[];
  approverKeys?: Record<string, any>;
  now?: number | (() => number);
  rpId?: string | null;
  allowedOrigins?: string[];
  quorumPolicy?: any;
  quorumPolicies?: Record<string, any>;
} = {}) {
  if (!Array.isArray(entries)) {
    throw new Error('reperform: entries must be an array (evidence.all() or a full export)');
  }
  if (!Array.isArray(issuerKeys)) {
    throw new Error('reperform: issuerKeys must be an array of base64url SPKI issuer keys');
  }

  /* ------------------------------- chain -------------------------------- */
  const rebuilt = createEvidenceLog();
  let broken: { at: number | null; seq: number | null; reason: string | undefined } | null = null;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (!e || typeof e !== 'object' || Array.isArray(e)) { broken = { at: i, seq: null, reason: 'not_an_object' }; break; }
    const seq = Number.isInteger(e.seq) ? e.seq : null;
    if (seq === null) { broken = { at: i, seq: null, reason: 'missing_seq' }; break; }
    if (typeof e.prev_hash !== 'string' || e.prev_hash.length === 0) { broken = { at: i, seq, reason: 'missing_prev_hash' }; break; }
    if (typeof e.hash !== 'string' || e.hash.length === 0) { broken = { at: i, seq, reason: 'missing_hash' }; break; }
    // Re-record the EXACT supplied body (own seq/prev_hash override the fresh
    // log's defaults via the record() spread) so the recomputed hash is over
    // byte-identical canonical material.
    const { hash: suppliedHash, ...body } = e;
    const rec = await rebuilt.record(body);
    if (rec.hash !== suppliedHash) { broken = { at: i, seq, reason: 'hash_mismatch' }; break; }
  }
  // Drive the REAL evidence.js verifier over the rebuilt chain — the link walk
  // (prev_hash continuity from 'genesis') is its judgment, not a reimplementation.
  const rv = rebuilt.verify();
  if (!broken && !rv.ok) broken = { at: rv.at ?? null, seq: rv.at ?? null, reason: rv.reason };
  const chain = {
    ok: !broken,
    entries: entries.length,
    // A broken chain vouches for NO head — even a valid prefix's.
    head: !broken ? (rv.head ?? null) : null,
    ...(broken ? { broken_at: broken.at, broken_seq: broken.seq, reason: broken.reason } : {}),
  };

  /* ------------------- receipts + counts (from scratch) ------------------ */
  const receipts: {
    reverified: number;
    failed: { hash: string | null; reason: string }[];
    not_reverifiable: number;
    no_receipt_presented: number;
  } = { reverified: 0, failed: [], not_reverifiable: 0, no_receipt_presented: 0 };
  const warnings: { index: number; reason: string }[] = [];
  const byAction = Object.create(null);
  let allows = 0;
  let denies = 0;
  let replaysBlocked = 0;

  entries.forEach((e, index) => {
    if (!e || typeof e !== 'object' || Array.isArray(e)) { warnings.push({ index, reason: 'not_an_object' }); return; }
    if (typeof e.kind !== 'string' || e.kind.length === 0) { warnings.push({ index, reason: 'missing_kind' }); return; }

    // Counts: guarded decisions only ('not_guarded' pass-throughs ran without
    // the control; execution records are provenance, not enforcement). Fail
    // closed: only a literal `true` counts as an allow.
    if (e.kind === 'decision' && e.reason !== 'not_guarded') {
      if (e.allow === true) allows += 1; else denies += 1;
      if (e.reason === 'replay_refused') replaysBlocked += 1;
      const action = typeof e.action === 'string' && e.action ? e.action : 'unknown';
      byAction[action] = (byAction[action] || 0) + 1;
    }

    // Re-verification: any entry that carries material gets it re-verified;
    // ALL carried payloads must verify for the entry to count as reverified —
    // each failure is a named {hash, reason}, never absorbed.
    const hash = typeof e.hash === 'string' && e.hash ? e.hash : null;
    const material = collectMaterial(e);
    if (material.length > 0) {
      let allOk = true;
      for (const m of material) {
        const reason = reverifyMaterial(m, {
          issuerKeys,
          approverKeys,
          action: typeof e.action === 'string' && e.action ? e.action : null,
          rpId,
          allowedOrigins,
          quorumPolicy,
          quorumPolicies,
        });
        if (reason) { allOk = false; receipts.failed.push({ hash, reason }); }
      }
      if (allOk) receipts.reverified += 1;
      return;
    }
    // No material carried. A decision that REFERENCES a receipt (receipt_id
    // recorded) but does not carry it cannot be re-performed — surfaced as
    // not_reverifiable, never silently passed. A decision where no receipt was
    // presented at all (pass-through, receipt_required refusal) has nothing to
    // re-verify and is reported separately for transparency.
    if (e.kind === 'decision') {
      if (e.receipt_id !== null && e.receipt_id !== undefined) receipts.not_reverifiable += 1;
      else receipts.no_receipt_presented += 1;
    }
  });

  const nowMs = typeof now === 'function' ? now() : now;

  return {
    '@version': REPERFORMANCE_VERSION,
    product: 'EMILIA Gate',
    generated_at: new Date(nowMs).toISOString(),
    honesty: {
      reperforms:
        'Independent recomputation from the supplied evidence entries: the hash chain is rebuilt '
        + 'and checked with the evidence log\'s own verifier, carried receipt/signoff/quorum material '
        + 'is cryptographically re-verified against auditor-pinned issuer and identity-bound approver keys, '
        + 'WebAuthn scope, and organizational quorum policy; decision counts '
        + 'are recomputed from scratch without reference to any report builder.',
      does_not_establish: [
        'Completeness of the log: a chain rewritten in full, or entries withheld before they were supplied, is not detectable from the entries alone. Anchor the head hash externally to close this.',
        'Runtime freshness or one-time consumption: those were properties of the moment of decision and cannot be re-performed after the fact; cryptographic material is re-verified, runtime state is not.',
        'Issuer and approver key custody, enrollment, or identity proofing, which remain external trust roots the auditor supplies out of band.',
        'The business correctness or wisdom of any authorized action.',
      ],
      status: 'Support for an audit re-performance procedure. This document does not conclude, opine, or certify; any conclusion is the auditor\'s.',
    },
    input: {
      entries_supplied: entries.length,
      issuer_keys_pinned: issuerKeys.length,
      approver_keys_pinned: approverKeys && typeof approverKeys === 'object'
        ? Object.keys(approverKeys).length : 0,
      relying_party_scope_pinned: typeof rpId === 'string' && rpId.length > 0
        && Array.isArray(allowedOrigins) && allowedOrigins.length > 0,
      quorum_policies_pinned: (quorumPolicy ? 1 : 0)
        + (quorumPolicies && typeof quorumPolicies === 'object' ? Object.keys(quorumPolicies).length : 0),
      expects: 'the complete evidence log from genesis (evidence.all() or a full export)',
    },
    chain,
    receipts,
    counts: {
      allows,
      denies,
      replays_blocked: replaysBlocked,
      by_action_type: sortedCounts(byAction),
    },
    integrity_warnings: warnings,
  };
}

/** Extract the recomputed counts, fail closed on anything unrecognized. */
function countsFrom(recomputed) {
  if (!recomputed || typeof recomputed !== 'object') {
    throw new Error('compareToReported: recomputed must be the reperformEvidence result (or its counts)');
  }
  const c = recomputed['@version'] === REPERFORMANCE_VERSION ? recomputed.counts : recomputed;
  if (!c || typeof c !== 'object') {
    throw new Error('compareToReported: recomputed carries no counts');
  }
  for (const k of ['allows', 'denies', 'replays_blocked']) {
    if (!Number.isFinite(c[k]) || c[k] < 0) {
      throw new Error(`compareToReported: recomputed.${k} must be a finite number >= 0 — refusing to compare`);
    }
  }
  const by = c.by_action_type;
  return { ...c, by_action_type: by && typeof by === 'object' && !Array.isArray(by) ? by : {} };
}

/**
 * Diff recomputed counts against a reported pack — the auditor's tie-out.
 *
 * Accepts an EP-GATE-USAGE-v1 pack (meterUsage output or the signed-ready
 * buildUsageStatement body) or an EP-GATE-UNDERWRITER-ATTESTATION-v1 pack.
 * Only the OVERLAPPING NUMERIC fields are compared; an unknown pack @version
 * is refused (fail closed), never fuzzily matched. A reported field that is
 * missing or non-numeric is itself a named drift — a stripped pack can never
 * silently match.
 *
 * The comparison is meaningful only when the recomputation ran over exactly
 * the entries the reported pack was built from (same slice, same window);
 * scoping the slice is the auditor's procedure, not this function's.
 *
 * @param {object} recomputed  reperformEvidence() result (or its .counts)
 * @param {object} reportedPack  usage or underwriter pack
 * @returns {{match: boolean, pack_version: string, drift: Array<{field, reported, recomputed}>}}
 */
export function compareToReported(recomputed, reportedPack) {
  const counts = countsFrom(recomputed);
  if (!reportedPack || typeof reportedPack !== 'object') {
    throw new Error('compareToReported: reportedPack must be an object');
  }
  const version = reportedPack['@version'];
  const drift: { field: string; reported: any; recomputed: any }[] = [];
  const check = (field, reported, rec) => {
    if (!Number.isFinite(reported) || reported !== rec) {
      drift.push({ field, reported: reported === undefined ? null : reported, recomputed: rec });
    }
  };

  if (version === USAGE_PACK_VERSION) {
    check('allows', reportedPack.allows, counts.allows);
    check('denies', reportedPack.denies, counts.denies);
    check('replays_blocked', reportedPack.replays_blocked, counts.replays_blocked);
    check('protected_actions', reportedPack.protected_actions, counts.allows + counts.denies);
    const reportedBy = reportedPack.by_action_type;
    const byOk = reportedBy && typeof reportedBy === 'object' && !Array.isArray(reportedBy);
    const keys = new Set([
      ...Object.keys(counts.by_action_type),
      ...(byOk ? Object.keys(reportedBy) : []),
    ]);
    for (const k of [...keys].sort()) {
      // An absent key in a well-formed histogram means zero occurrences.
      const rep = byOk && reportedBy[k] !== undefined ? reportedBy[k] : 0;
      check(`by_action_type.${k}`, rep, counts.by_action_type[k] ?? 0);
    }
  } else if (version === UNDERWRITER_PACK_VERSION) {
    check('volume.guarded_decisions', reportedPack.volume?.guarded_decisions, counts.allows + counts.denies);
    check('volume.allowed', reportedPack.volume?.allowed, counts.allows);
    check('volume.denied', reportedPack.volume?.denied, counts.denies);
    check('denials.total', reportedPack.denials?.total, counts.denies);
    check('replay.attempts_blocked', reportedPack.replay?.attempts_blocked, counts.replays_blocked);
  } else {
    throw new Error(
      `compareToReported: unknown pack @version ${JSON.stringify(version ?? null)} — refusing to compare (fail closed)`,
    );
  }

  return { match: drift.length === 0, pack_version: version, drift };
}

export default { REPERFORMANCE_VERSION, reperformEvidence, compareToReported };
