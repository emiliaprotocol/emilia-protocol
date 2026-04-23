# EP Post-Quantum Migration Plan

**Status:** v1 (Apr 2026).
**Target:** `binding_material_version` = 2 (PQ-enabled, hybrid).
**Not urgent. Important.** Federal and financial buyers will begin asking by 2027; the migration path needs to exist well before they ask.

---

## 1. What's at risk

EP today uses two primitives that are quantum-breakable in the classical sense:

- **SHA-256** for all binding hashes, policy hashes, party set hashes, payload hashes, and event hash chains.
- **ECDSA (secp256k1/p256)** for authority signatures and blockchain anchors.

SHA-256 is weakened by Grover's algorithm (√2 speedup), which drops its effective security from 128 bits to 64 bits — borderline acceptable, not catastrophic. ECDSA is completely broken by Shor's algorithm on a sufficiently large quantum computer. **ECDSA is the actual risk.**

The most realistic threat is **"harvest now, decrypt later"** (HNDL): an adversary records current EP bindings and authority signatures today, waits for a practical cryptographically-relevant quantum computer (CRQC), and then retroactively forges authority signatures to alter the historical trust record. EP's anchor layer partially mitigates this (L2 anchors have their own PQ migration path), but the authority signatures and any ECDSA-backed receipt attestations are vulnerable until rotated to PQ primitives.

**No urgency for production today.** A CRQC doesn't exist yet and the most aggressive public estimates put it at 10-15 years out. But the migration path must be published so federal and FI buyers can cite it in procurement.

---

## 2. Migration principle: hybrid, not swap

A swap from ECDSA to a PQ signature scheme (e.g., CRYSTALS-Dilithium, SPHINCS+) has one critical failure mode: if the new scheme turns out to be broken (post-selection bias in NIST's process remains a live concern for some candidates), the protocol has no fallback.

EP MUST migrate to **hybrid signatures**: every authority signature in the PQ-enabled protocol produces both a classical ECDSA signature AND a PQ signature, both of which must be valid. Verifiers check both. A verifier in a pre-PQ world checks only the ECDSA signature; a PQ-era verifier checks both.

The hybrid phase is expected to last **10+ years**. Only after multiple independent PQ primitives have survived sustained cryptanalysis and one has been durably standardized will EP consider dropping the classical half.

---

## 3. Target PQ primitives (candidate, subject to NIST revisions)

### 3.1. Signatures
- **Primary**: ML-DSA (formerly CRYSTALS-Dilithium) — NIST FIPS 204. Balanced performance, reasonable key sizes, selected as the primary lattice-based NIST standard.
- **Backup (stateless-hash)**: SLH-DSA (formerly SPHINCS+) — NIST FIPS 205. Much larger signatures, but conservative: only relies on hash function security (which is itself partially vulnerable to Grover, but with a √2 penalty, not full break).

Both are specified. Authority signing MUST support both; the choice is a per-authority config flag. Canonical verifier implementations MUST accept either.

### 3.2. Hashes
- **SHA-256 remains the default** for the binding envelope. SHA-256 is acceptable against Grover for the medium term. For critical-action bindings, operators MAY opt into SHA3-512 or BLAKE3 for defense against unknown structural weaknesses in SHA-2. The canonical binding's `binding_material_version` carries the hash choice.

### 3.3. Anchors
- **Blockchain anchors** depend on the L2 chain's own PQ migration. EP does not prescribe the chain's PQ roadmap; if the chain does not migrate, EP moves to a different chain or adds a secondary PQ anchor alongside.
- **Hash chains** (handshake_events parent_event_hash) remain SHA-256 for v2; the hash chain is a belt on top of signatures, not the trust anchor.

---

## 4. `binding_material_version` = 2 spec

v1 (current):
```
{
  action_type, resource_ref, policy_id, policy_version, policy_hash,
  interaction_id, party_set_hash, payload_hash, context_hash,
  nonce, expires_at, binding_material_version = 1
}
```

v2 (PQ-enabled, hybrid):
```
{
  action_type, resource_ref, policy_id, policy_version, policy_hash,
  interaction_id, party_set_hash, payload_hash, context_hash,
  nonce, expires_at, binding_material_version = 2,

  // NEW in v2:
  hash_algo: "sha256" | "sha3-512" | "blake3",   // default sha256
  signature_algos: ["ecdsa-p256", "ml-dsa-65"],  // both required for hybrid validity
  authority_binding_hash: "<hash of authority set ref>"  // PQ-safe commitment to trust anchors
}
```

- `signature_algos` is an array, not a single value. Verifiers MUST validate every signature in the array. Missing any is a binding failure.
- `authority_binding_hash` pins the trust anchor set at bind time. Cross-cert changes between bind and verify fail the binding.
- v1 bindings remain verifiable indefinitely. Verifiers MUST continue to accept v1; they are NOT deprecated retroactively. The `binding_material_version` field is the branching gate.

### 4.1. Downgrade-attack resistance: transcript-hash commitment

The hybrid construction above is only secure if every individual signature commits to the full `signature_algos` array AND the `binding_material_version`. Otherwise an attacker can strip the PQ signature and present the binding to a verifier as a v1-style single-classical-signature binding — the verifier accepts the (real, valid) ECDSA signature and never notices the declared PQ requirement was removed.

**Rule**: each signer, when producing their signature, MUST sign over the **transcript hash**:

```
transcript = SHA-256(
  canonical_binding_material  ||
  binding_material_version    ||
  canonical_serialize(signature_algos sorted alphabetically)  ||
  authority_binding_hash
)
```

The signer signs `transcript`, not just the canonical binding. Verifiers reconstruct `transcript` from the presented binding and verify each signature against it. Stripping a signature from the array changes the transcript hash; every remaining signature is now a signature over a non-matching transcript and fails verification. This is the TLS 1.3 lesson applied to EP bindings.

Verifiers MUST reject any v2 binding presented with a subset of the declared `signature_algos`. Adding `COMPOSED_ALGO_MISMATCH` as a binding failure reason. A conformance test MUST exercise the stripping path.

---

## 5. Migration phases

### Phase 0 (now, v1): prepare
- Publish this document. ✓ (this doc)
- Ensure `binding_material_version` is already on the hash envelope. ✓ (it is)
- Ensure the canonical binding fields list is extensible without breaking v1 consumers. ✓ (it is — adding new fields requires a version bump, which is the right pattern)

### Phase 1 (12-18 months out, v1.1): library readiness
- Integrate a vetted ML-DSA implementation (liboqs, or a Rust crate with constant-time guarantees). Do not hand-roll.
- Integrate a vetted SLH-DSA implementation as backup.
- Add `signatures[]` field to `authority_attestations` at the DB level (migration N+1). No change to binding_material yet.
- Add `--sign-hybrid` flag to `scripts/sign-authority.js` that produces both ECDSA and ML-DSA. Run in dual-sign mode for internal use; external verifiers ignore.

### Phase 2 (2-3 years, v2.0): hybrid protocol
- Bump `binding_material_version` to 2 by default in `lib/handshake/invariants.js`.
- Add `validateHybridSignatures` to verify.js; require both classical and PQ to be valid.
- Publish v2 conformance test suite. Any conformant verifier that rejects v2 bindings cannot claim PQ readiness.
- Federation cross-certs must include both classical and PQ public keys. Existing cross-certs grandfathered; new ones MUST be hybrid.

### Phase 3 (5-7 years, v2.1): PQ-required
- Deprecate pure-classical bindings. New bindings MUST be hybrid. Authority table entries with only ECDSA keys are marked `pq_missing`; they continue to verify existing bindings but cannot sign new ones.
- Publish migration scripts for operators to re-sign their long-lived attestations with hybrid signatures.

### Phase 3.5: "Classical sunset" contingency

If ECDSA is broken during the hybrid era (plausible — CRQC may arrive before Phase 4), the hybrid protocol still protects v2+ bindings: each v2 binding requires a PQ signature that the attacker cannot forge, so forging the ECDSA half alone doesn't produce a valid binding. However, **v1 bindings (single ECDSA signature) become retroactively forgeable**. An attacker can produce a convincing v1 binding that claims to come from a trusted authority at a past date.

To defend this, EP maintainers MUST produce a **PQ-signed checkpoint over historical v1 roots** during Phase 1 or Phase 2 — before any CRQC exists. The checkpoint commits the Merkle root of every anchored v1 binding at Phase 1+2 cutover time using ML-DSA (and/or SLH-DSA). A forged v1 binding produced after a classical break must be either (a) included in the pre-break checkpoint, which requires the attacker to have forged it pre-break (contradiction), or (b) excluded from the checkpoint, in which case it is rejected by any verifier aware of the sunset.

**Operational requirement**: the classical-sunset checkpoint must be produced and published at the latest by the end of Phase 2, mirrored to at least two independent archives (Software Heritage, Internet Archive, a neutral foundation's archival node), and re-signed annually with the then-current PQ primitives.

Without this checkpoint, the entire v1 historical log loses evidentiary value the moment ECDSA falls. With it, v1 retains evidentiary value for everything produced before the checkpoint cutoff.

### Phase 4 (10+ years, v3.0 — only if PQ primitives hold): classical drop
- Conditional on cryptographic community consensus that both ML-DSA and SLH-DSA (or their successors) have survived real cryptanalysis.
- Drop ECDSA verification. v1 bindings in historical logs remain readable but are no longer trusted as fresh evidence.
- This step MUST NOT be taken unilaterally by any single operator; it requires a federation-wide decision with maintainer-set majority.

---

## 6. What operators must do now

- **Nothing urgent.** v1 is fine for years.
- **But**: when building new integrations, ensure your signature verification is abstracted behind a function, not inlined. The migration hurts in code that calls ECDSA directly.
- **Plan for larger signatures.** ML-DSA-65 signatures are ~3.3KB (vs ~70 bytes for ECDSA). If you have tight bandwidth budgets on the wire format, adjust accordingly. SLH-DSA is 17-49KB depending on parameter set — this is why it's backup, not default.
- **Document where keys live.** Every authority key with a classical-only signature today will need a parallel PQ key by Phase 2. The ops side of that — HSM support for ML-DSA, key ceremony updates, hardware procurement — has a real lead time.

---

## 7. What operators MUST NOT do

- Do NOT attempt to swap ECDSA for ML-DSA directly. This is an attractive "just rip the bandaid off" approach that has two problems: it breaks every existing integration in one flag flip, and it leaves the protocol with zero fallback if ML-DSA is ever broken.
- Do NOT claim "PQ-safe" status without the hybrid construction. A pure-PQ protocol is not more secure than a hybrid one; it is strictly less, because the attacker only needs to break the PQ primitive, not both.
- Do NOT design new features that make PQ migration harder. Any new signed artifact added to the protocol between now and Phase 2 should be designed with `signature_algos[]` as a first-class field, not as a single `signature` field.

---

## 8. Cross-reference

- Authority key management: `AUTHORITY-GOVERNANCE.md` — maintainer HSM policy will need PQ-capable hardware by Phase 2.
- Federation: `FEDERATION-SEMANTICS.md` — cross-certs include PQ keys by Phase 2.
- Conformance: the conformance test suite will bump in lockstep with protocol versions.
