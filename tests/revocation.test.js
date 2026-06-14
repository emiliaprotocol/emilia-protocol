// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import {
  buildRevocation,
  verifyRevocation,
  isRevoked,
  REVOCATION_VERSION,
} from "../lib/revocation/revocation.js";

import {
  canonicalize,
  generateEd25519KeyPair,
} from "../packages/issue/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(
    path.join(__dirname, "..", "conformance", "vectors", "revocation.v1.json"),
    "utf8",
  ),
);

const byId = (list, id) => list.find((v) => v.id === id);

// ── reference material ───────────────────────────────────────────────────────
// The target the relying party HOLDS (action A). Both target_id AND action_hash
// are part of the binding; a statement for action B must never revoke action A.
const TARGET_A = {
  target_type: "receipt",
  target_id: "rcpt_01J_A",
  action_hash: "sha256:" + "a".repeat(64),
};

// A DIFFERENT authorization (same type) — used for "bound to a different target".
const TARGET_B = {
  target_type: "receipt",
  target_id: "rcpt_01J_B",
  action_hash: "sha256:" + "b".repeat(64),
};

// Same target_id as A but a DIFFERENT action_hash — the revoke-A-presented-for-B
// case: a re-issued authorization with the same id but a different action.
const TARGET_A_OTHER_ACTION = {
  target_type: "receipt",
  target_id: "rcpt_01J_A",
  action_hash: "sha256:" + "c".repeat(64),
};

const REVOKER_ID = "ep:key:revoker#1";
const revokerKp = generateEd25519KeyPair();

/** The revoker signer: signs the canonical statement bytes with its own key. */
function revokerSigner(kp = revokerKp, revokerKeyId = REVOKER_ID) {
  return {
    revoker_key_id: revokerKeyId,
    privateKey: kp.privateKey,
    publicKeyB64u: kp.publicKeyB64u,
  };
}

/** Pinned revoker-key map the verifier trusts (identified-AND-pinned). */
function pinnedKeys(kp = revokerKp, revokerId = REVOKER_ID) {
  return { [revokerId]: { public_key: kp.publicKeyB64u } };
}

const REVOKED_AT = "2026-06-14T20:41:00.000Z";

/** A well-formed, validly-signed binding revocation for a given target. */
function freshStatement(target = TARGET_A, overrides = {}) {
  return buildRevocation({
    target,
    revoker_id: REVOKER_ID,
    revoked_at: REVOKED_AT,
    reason: "policy change — key compromise suspected",
    signer: revokerSigner(),
    ...overrides,
  });
}

/**
 * Re-sign a (possibly tampered/partial) statement over its OWN canonical bytes,
 * mirroring lib/revocation/revocation.js's revocationSignedPayload() EXACTLY, so
 * a negative exercises the INTENDED check rather than an incidental signature
 * break. Used by negatives that need a genuine signature over the bytes as
 * presented (e.g. unpinned/substituted key, missing revoked_at).
 */
function reSign(stmt, kp) {
  const payload = canonicalize({
    "@version": REVOCATION_VERSION,
    action_hash: stmt.action_hash ?? null,
    reason: stmt.reason ?? null,
    revoked_at: stmt.revoked_at ?? null,
    revoker_id: stmt.revoker_id ?? null,
    target_id: stmt.target_id ?? null,
    target_type: stmt.target_type ?? null,
  });
  const bytes = Buffer.from(payload, "utf8");
  const sig = crypto.sign(null, bytes, kp.privateKey).toString("base64url");
  return {
    ...stmt,
    proof: {
      ...(stmt.proof || {}),
      algorithm: "Ed25519",
      revoker_key_id: stmt.proof?.revoker_key_id ?? stmt.revoker_id ?? REVOKER_ID,
      signed_payload_b64u: bytes.toString("base64url"),
      signature_b64u: sig,
      public_key: kp.publicKeyB64u,
    },
  };
}

// ── version + assembly ───────────────────────────────────────────────────────

describe("EP-REVOCATION-v1 — version + assembly", () => {
  it("exposes the wire version", () => {
    expect(REVOCATION_VERSION).toBe("EP-REVOCATION-v1");
    expect(VECTORS.wire_tag).toBe("EP-REVOCATION-v1");
  });

  it("buildRevocation mints a complete, self-verifying binding statement", () => {
    const stmt = freshStatement();
    expect(stmt["@version"]).toBe("EP-REVOCATION-v1");
    expect(stmt.target_type).toBe(TARGET_A.target_type);
    expect(stmt.target_id).toBe(TARGET_A.target_id);
    expect(stmt.action_hash).toBe(TARGET_A.action_hash);
    expect(stmt.revoker_id).toBe(REVOKER_ID);
    expect(stmt.revoked_at).toBe(REVOKED_AT);
    expect(stmt.proof.algorithm).toBe("Ed25519");
    expect(typeof stmt.proof.signature_b64u).toBe("string");
    // round-trips through the verifier
    const r = verifyRevocation(TARGET_A, stmt, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
  });

  it("buildRevocation honesty gate refuses an incomplete target or missing inputs", () => {
    expect(() => buildRevocation({})).toThrow();
    expect(() =>
      buildRevocation({
        target: { target_type: "receipt", target_id: "x" }, // no action_hash
        revoker_id: REVOKER_ID,
        signer: revokerSigner(),
      }),
    ).toThrow();
    expect(() =>
      buildRevocation({ target: TARGET_A, signer: revokerSigner() }),
    ).toThrow(); // no revoker_id
    expect(() =>
      buildRevocation({ target: TARGET_A, revoker_id: REVOKER_ID }),
    ).toThrow(); // no signer
  });

  it("uses a custom revoker_key_id when supplied to the signer", () => {
    const stmt = buildRevocation({
      target: TARGET_A,
      revoker_id: REVOKER_ID,
      revoked_at: REVOKED_AT,
      signer: revokerSigner(revokerKp, "ep:key:revoker#custom"),
    });
    expect(stmt.proof.revoker_key_id).toBe("ep:key:revoker#custom");
  });

  it("buildRevocation defaults revoked_at to now when omitted", () => {
    const before = Date.now();
    const stmt = buildRevocation({
      target: TARGET_A,
      revoker_id: REVOKER_ID,
      signer: revokerSigner(),
    });
    const after = Date.now();
    const t = Date.parse(stmt.revoked_at);
    expect(t).toBeGreaterThanOrEqual(before);
    expect(t).toBeLessThanOrEqual(after);
  });
});

// ── must_reject vectors (each asserted by id) ────────────────────────────────

describe("EP-REVOCATION-v1 — must_reject vectors", () => {
  it("a_forged_signature -> revoker_signature_valid:false", () => {
    const v = byId(VECTORS.must_reject, "a_forged_signature");
    expect(v.expected.failing_check).toBe("revoker_signature_valid");

    // Genuine binding statement, then flip a byte in the signature -> a real
    // forgery (well-formed length, verifies nowhere) under the PINNED key.
    const stmt = freshStatement();
    const sigBuf = Buffer.from(stmt.proof.signature_b64u, "base64url");
    sigBuf[0] ^= 0xff;
    const forged = {
      ...stmt,
      proof: { ...stmt.proof, signature_b64u: sigBuf.toString("base64url") },
    };

    const r = verifyRevocation(TARGET_A, forged, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks[v.expected.failing_check]).toBe(false);
  });

  it("b_unpinned_revoker_key -> revoker_key_pinned:false", () => {
    const v = byId(VECTORS.must_reject, "b_unpinned_revoker_key");
    expect(v.expected.failing_check).toBe("revoker_key_pinned");

    // A structurally valid, validly-signed statement whose key is self-asserted:
    // the proof verifies under its OWN public_key, but revoker_id is NOT pinned.
    const stmt = freshStatement();

    // No registry at all.
    const r0 = verifyRevocation(TARGET_A, stmt, {});
    expect(r0.valid).toBe(false);
    expect(r0.checks.revoker_key_pinned).toBe(false);

    // Registry present but missing THIS revoker.
    const r1 = verifyRevocation(TARGET_A, stmt, {
      revokerKeys: { "ep:key:someone-else": { public_key: stmt.proof.public_key } },
    });
    expect(r1.valid).toBe(false);
    expect(r1.checks.revoker_key_pinned).toBe(false);
    // Never falls back to the self-asserted public_key.
  });

  it("c_wrong_pinned_key_substitution -> revoker_key_pinned:false", () => {
    const v = byId(VECTORS.must_reject, "c_wrong_pinned_key_substitution");
    expect(v.expected.failing_check).toBe("revoker_key_pinned");

    // revoker_id IS pinned, and the signature verifies under the key in the proof
    // — but that proof key is an ATTACKER key, not the one pinned for revoker_id.
    const attackerKp = generateEd25519KeyPair();
    const stmt = reSign(freshStatement(), attackerKp); // signed by attacker, key in proof

    const r = verifyRevocation(TARGET_A, stmt, {
      revokerKeys: pinnedKeys(), // pins the GENUINE revoker key, != attacker key
    });
    expect(r.valid).toBe(false);
    expect(r.checks.revoker_key_pinned).toBe(false);
  });

  it("d_bound_to_different_target_id -> target_bound:false", () => {
    const v = byId(VECTORS.must_reject, "d_bound_to_different_target_id");
    expect(v.expected.failing_check).toBe("target_bound");

    // A genuine, validly-signed revocation for TARGET_B, presented against the
    // target the verifier holds (TARGET_A). Replay/staple onto another auth.
    const stmtForB = freshStatement(TARGET_B);
    const r = verifyRevocation(TARGET_A, stmtForB, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.target_bound).toBe(false);
  });

  it("e_bound_to_different_action_hash -> target_bound:false", () => {
    const v = byId(VECTORS.must_reject, "e_bound_to_different_action_hash");
    expect(v.expected.failing_check).toBe("target_bound");

    // target_id MATCHES, but action_hash binds action A' (a re-issued auth with
    // the same id, different action). Revoking that must not revoke TARGET_A.
    const stmtOther = freshStatement(TARGET_A_OTHER_ACTION);
    const r = verifyRevocation(TARGET_A, stmtOther, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.target_bound).toBe(false);
  });

  it("f_wrong_version -> version:false", () => {
    const v = byId(VECTORS.must_reject, "f_wrong_version");
    expect(v.expected.failing_check).toBe("version");

    // Validly signed, exact binding — but a future/forked @version tag. We sign
    // the WRONG-version object's own SIGNED_FIELDS (which still pin @version to
    // the canonical tag via revocationSignedPayload), then mutate the top-level
    // @version, so this fails ONLY on the version gate.
    const stmt = freshStatement();
    const forked = { ...stmt, "@version": "EP-REVOCATION-v2" };
    const r = verifyRevocation(TARGET_A, forked, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.version).toBe(false);
  });

  it("g_tampered_fields_after_signing -> signature_binds_statement:false", () => {
    const v = byId(VECTORS.must_reject, "g_tampered_fields_after_signing");
    expect(v.expected.failing_check).toBe("signature_binds_statement");

    // Genuine statement, then edit revoked_at AND reason in the presented object
    // WITHOUT re-signing. The proof now signs DIFFERENT bytes than the verifier
    // recomputes from the presented fields.
    const stmt = freshStatement();
    const tampered = {
      ...stmt,
      revoked_at: "2099-01-01T00:00:00.000Z",
      reason: "attacker-edited reason",
    };
    const r = verifyRevocation(TARGET_A, tampered, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.signature_binds_statement).toBe(false);
  });

  it("h_missing_revoked_at -> revoked_at_present:false", () => {
    const v = byId(VECTORS.must_reject, "h_missing_revoked_at");
    expect(v.expected.failing_check).toBe("revoked_at_present");

    // Build a statement with revoked_at omitted, then sign over its OWN bytes
    // (revoked_at:null) so the ONLY failure is the missing anchor — not a
    // signature break.
    const base = {
      "@version": REVOCATION_VERSION,
      target_type: TARGET_A.target_type,
      target_id: TARGET_A.target_id,
      action_hash: TARGET_A.action_hash,
      revoker_id: REVOKER_ID,
      reason: "no anchor",
      // revoked_at intentionally absent
    };
    const stmt = reSign(base, revokerKp);
    const r = verifyRevocation(TARGET_A, stmt, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.revoked_at_present).toBe(false);
    // The signature itself is genuine over the presented (revoked_at-less) bytes:
    expect(r.checks.revoker_signature_valid).toBe(true);
    expect(r.checks.signature_binds_statement).toBe(true);
  });

  it("i_stale_beyond_freshness_window -> freshness:false (only with opts.maxAgeSeconds)", () => {
    const v = byId(VECTORS.must_reject, "i_stale_beyond_freshness_window");
    expect(v.expected.failing_check).toBe("freshness");

    // Genuine, validly-signed, exactly-bound statement whose revoked_at is older
    // than the demanded window relative to opts.now.
    const stmt = freshStatement();
    const r = verifyRevocation(TARGET_A, stmt, {
      revokerKeys: pinnedKeys(),
      maxAgeSeconds: 3600,
      now: "2026-06-15T20:41:00.000Z", // 24h after revoked_at
    });
    expect(r.valid).toBe(false);
    expect(r.checks.freshness).toBe(false);
    // Every OTHER gating check passed — the rejection is freshness alone.
    for (const [k, val] of Object.entries(r.checks)) {
      if (k !== "freshness") expect(val, `check ${k}`).toBe(true);
    }

    // The SAME statement is accepted when no window is demanded (freshness vacuous).
    const rNoWindow = verifyRevocation(TARGET_A, stmt, { revokerKeys: pinnedKeys() });
    expect(rNoWindow.valid).toBe(true);
  });
});

// ── must_accept vectors (each asserted by id) ────────────────────────────────

describe("EP-REVOCATION-v1 — must_accept vectors", () => {
  it("z_well_formed_binding_revocation -> valid:true (and isRevoked true)", () => {
    const v = byId(VECTORS.must_accept, "z_well_formed_binding_revocation");
    expect(v.expected.valid).toBe(true);

    const stmt = freshStatement();
    const r = verifyRevocation(TARGET_A, stmt, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
    for (const [k, val] of Object.entries(r.checks)) {
      expect(val, `check ${k}`).toBe(true);
    }
    expect(isRevoked(TARGET_A, [stmt], { revokerKeys: pinnedKeys() })).toBe(true);

    // Within a generous freshness window it is still accepted.
    const rFresh = verifyRevocation(TARGET_A, stmt, {
      revokerKeys: pinnedKeys(),
      maxAgeSeconds: 86_400 * 7,
      now: "2026-06-15T20:41:00.000Z",
    });
    expect(rFresh.valid).toBe(true);
  });

  it("z2_is_revoked_true_among_unrelated -> valid:true among unrelated statements", () => {
    const v = byId(VECTORS.must_accept, "z2_is_revoked_true_among_unrelated");
    expect(v.expected.valid).toBe(true);

    const matching = freshStatement(TARGET_A);
    const unrelatedById = freshStatement(TARGET_B); // valid, different target_id
    const unrelatedByAction = freshStatement(TARGET_A_OTHER_ACTION); // valid, different action_hash

    // The matching statement is NOT first and NOT alone.
    const bag = [unrelatedById, unrelatedByAction, matching];
    expect(isRevoked(TARGET_A, bag, { revokerKeys: pinnedKeys() })).toBe(true);

    // Each unrelated statement on its own does NOT revoke TARGET_A.
    expect(isRevoked(TARGET_A, [unrelatedById], { revokerKeys: pinnedKeys() })).toBe(false);
    expect(isRevoked(TARGET_A, [unrelatedByAction], { revokerKeys: pinnedKeys() })).toBe(false);

    // But each DOES revoke its own target (sanity: they are genuinely valid).
    expect(isRevoked(TARGET_B, [unrelatedById], { revokerKeys: pinnedKeys() })).toBe(true);
    expect(isRevoked(TARGET_A_OTHER_ACTION, [unrelatedByAction], { revokerKeys: pinnedKeys() })).toBe(true);
  });
});

// ── isRevoked aggregate edge cases ───────────────────────────────────────────

describe("EP-REVOCATION-v1 — isRevoked aggregate", () => {
  it("false for a non-array, empty bag, or all-invalid bag", () => {
    expect(isRevoked(TARGET_A, undefined, { revokerKeys: pinnedKeys() })).toBe(false);
    expect(isRevoked(TARGET_A, null, { revokerKeys: pinnedKeys() })).toBe(false);
    expect(isRevoked(TARGET_A, [], { revokerKeys: pinnedKeys() })).toBe(false);
    // One unpinned + one wrong-target: neither valid -> false.
    const unpinned = freshStatement(TARGET_A); // valid sig but no pin supplied
    const wrongTarget = freshStatement(TARGET_B);
    expect(isRevoked(TARGET_A, [unpinned, wrongTarget], {})).toBe(false);
  });
});

// ── fail-closed robustness (no throws on hostile input) ──────────────────────

describe("EP-REVOCATION-v1 — fail-closed robustness", () => {
  it("rejects a null/absent statement without throwing", () => {
    const r = verifyRevocation(TARGET_A, null, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.revoker_signature_valid).toBe(false);
  });

  it("rejects when no target is handed to the verifier", () => {
    const stmt = freshStatement();
    const r = verifyRevocation(null, stmt, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.target_bound).toBe(false);
  });

  it("rejects an unknown target_type", () => {
    const weird = { target_type: "policy", target_id: "x", action_hash: TARGET_A.action_hash };
    const stmt = reSign(
      { ...freshStatement(), target_type: "policy", target_id: "x" },
      revokerKp,
    );
    const r = verifyRevocation(weird, stmt, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.target_bound).toBe(false);
  });

  it("rejects a statement with no proof block (missing signature/key)", () => {
    const stmt = freshStatement();
    const { proof, ...noProof } = stmt;
    void proof;
    const r = verifyRevocation(TARGET_A, noProof, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.revoker_signature_valid).toBe(false);
  });

  it("does not throw on a non-canonicalizable signed field (BigInt) — fails closed", () => {
    const stmt = freshStatement();
    // A BigInt cannot be JSON-serialized by canonicalize(); recomputed bytes go
    // null and no signature can verify. Must fail closed, not crash.
    const hostile = { ...stmt, reason: 10n };
    let r;
    expect(() => {
      r = verifyRevocation(TARGET_A, hostile, { revokerKeys: pinnedKeys() });
    }).not.toThrow();
    expect(r.valid).toBe(false);
  });

  it("malformed revoked_at (not RFC 3339) fails revoked_at_present", () => {
    const base = { ...freshStatement(), revoked_at: "not-a-date" };
    const stmt = reSign(base, revokerKp);
    const r = verifyRevocation(TARGET_A, stmt, { revokerKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.revoked_at_present).toBe(false);
  });

  it("freshness is vacuous when maxAgeSeconds is unset, and honors default now", () => {
    // A statement freshly minted at NOW passes a tight window using the default
    // wall-clock now (opts.now omitted).
    const stmt = buildRevocation({
      target: TARGET_A,
      revoker_id: REVOKER_ID,
      signer: revokerSigner(),
    });
    const r = verifyRevocation(TARGET_A, stmt, {
      revokerKeys: pinnedKeys(),
      maxAgeSeconds: 3600, // now defaults to Date.now()
    });
    expect(r.valid).toBe(true);
  });

  it("accepts a Date object as opts.now", () => {
    const stmt = freshStatement();
    const r = verifyRevocation(TARGET_A, stmt, {
      revokerKeys: pinnedKeys(),
      maxAgeSeconds: 86_400 * 7,
      now: new Date("2026-06-15T20:41:00.000Z"),
    });
    expect(r.valid).toBe(true);
  });
});

// ── catalogue parity: EVERY vector id is asserted by name ─────────────────────

describe("EP-REVOCATION-v1 — catalogue parity", () => {
  // The set of ids this suite asserts by name above. Keep in lockstep with the
  // it() blocks; the parity test below proves it covers the whole catalogue.
  const ASSERTED = new Set([
    "a_forged_signature",
    "b_unpinned_revoker_key",
    "c_wrong_pinned_key_substitution",
    "d_bound_to_different_target_id",
    "e_bound_to_different_action_hash",
    "f_wrong_version",
    "g_tampered_fields_after_signing",
    "h_missing_revoked_at",
    "i_stale_beyond_freshness_window",
    "z_well_formed_binding_revocation",
    "z2_is_revoked_true_among_unrelated",
  ]);

  it("every must_reject + must_accept vector id is asserted by name", () => {
    const catalogue = [
      ...VECTORS.must_reject.map((v) => v.id),
      ...VECTORS.must_accept.map((v) => v.id),
    ];
    for (const id of catalogue) {
      expect(ASSERTED.has(id), `vector "${id}" must be asserted by name`).toBe(true);
    }
    // And the suite asserts no phantom ids that are not in the catalogue.
    for (const id of ASSERTED) {
      expect(catalogue.includes(id), `asserted id "${id}" must exist in the catalogue`).toBe(true);
    }
    expect(catalogue.length).toBe(ASSERTED.size);
  });

  it("the catalogue matches the documented vector ids exactly", () => {
    expect(VECTORS.must_reject.map((v) => v.id)).toEqual([
      "a_forged_signature",
      "b_unpinned_revoker_key",
      "c_wrong_pinned_key_substitution",
      "d_bound_to_different_target_id",
      "e_bound_to_different_action_hash",
      "f_wrong_version",
      "g_tampered_fields_after_signing",
      "h_missing_revoked_at",
      "i_stale_beyond_freshness_window",
    ]);
    expect(VECTORS.must_accept.map((v) => v.id)).toEqual([
      "z_well_formed_binding_revocation",
      "z2_is_revoked_true_among_unrelated",
    ]);
  });
});
