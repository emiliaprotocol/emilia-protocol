# Transparency-Layer Design — Consistency Proofs + Witness Cosignatures for the Trust-Receipt Log

**Status:** Design (accepted threat, staged fix). Optional experimental scaffold shipped alongside.
**Audit finding:** MED-HIGH — "The trust-receipt log has no transparency mechanism."
**Owner:** EP protocol / verify.
**Related standards:** RFC 6962 (Certificate Transparency), RFC 9162 (CT 2.0), IETF SCITT (Transparency Service / Registration Policy), the Sigsum/Go-checkpoint witness-cosignature model.
**Non-goal of this doc:** re-architecting the Merkle-v2 leaf/branch construction (owned separately). This layer sits *above* the tree and constrains the *log operator*.

---

## 1. The threat, precisely

EP's offline verifier establishes six properties for a Trust Receipt
(`packages/verify/index.js`, `verifyTrustReceipt`, Step 5 at
`packages/verify/index.js:911-935`). Two of those — `inclusion` and
`checkpoint_signature` — are the *only* things standing between a relying party
and the log operator. Today they reduce to **"the operator's signed word about a
single point in time."** That is exactly the party the transparency layer must
constrain, and it is currently unconstrained in three concrete ways.

### 1.1 Single-signer checkpoint — no independent attestation

A checkpoint is `{ log_key_id, root_hash, tree_size, log_signature }`
(documented at `packages/verify/index.js:464-465`; produced in the fixture at
`packages/verify/trust-receipt.test.js:129`). Verification is a single Ed25519
check against **one** pinned log key:

```
// packages/verify/index.js:921-932
if (logPublicKey && lp.checkpoint.log_signature) {
  const signedCheckpoint = { ...lp.checkpoint };
  delete signedCheckpoint.log_signature;
  checks.checkpoint_signature = verifyEd25519OverDigest(
    String(lp.checkpoint.log_signature).replace(/^b64u:/, ''),
    sha256Bytes(canonicalize(signedCheckpoint)),
    logPublicKey,
  );
}
```

The operator holds `log_key`. Nothing else co-attests the checkpoint. If the key
is compromised or the operator is malicious, a valid `log_signature` can be
minted over **any** `(root_hash, tree_size)` pair the operator likes.

### 1.2 No consistency proof between checkpoints — undetectable equivocation / split view

There is no notion of "checkpoint B is an append-only extension of checkpoint A"
anywhere in the verify packages. `grep -riE
'consistency|witness|cosign|gossip|split-view|equivocat' packages/verify/
go-verify/ python-verify/` returns **zero** functional hits (only an unrelated
`inconsistency` mention in a doc comment at `packages/verify/index.d.ts:190`).

Consequence: a malicious operator can maintain **two forked histories** and
present each to a different audience. Verifier A is shown a tree in which
receipt R was committed; verifier B is shown a same-size or larger tree in which
R never existed (or was replaced). Both trees are internally valid — each has a
correctly-signed checkpoint and a correct inclusion proof for whatever the
operator wants that verifier to believe. Because no verifier ever demands proof
that one checkpoint *extends* another, the fork is invisible offline. This is
the classic **split-view / equivocation** attack that RFC 6962 consistency
proofs exist to make detectable.

### 1.3 Empty `inclusion_path` accepted as a single-leaf tree

`verifyMerkleAnchor` (`packages/verify/index.js:235-250`) walks the proof steps
and returns `current === expectedRoot`. With an **empty** `inclusion_path`, the
loop body never runs and it collapses to `leafHash === expectedRoot`:

```
// packages/verify/index.js:242-249
let current = leafHash;
for (const step of proof) { ... }   // skipped when proof == []
return current === expectedRoot;
```

Step 5 reaches this whenever `Array.isArray(lp.inclusion_path)` is true
(`packages/verify/index.js:913`) — and `[]` **is** an array. So an operator can
publish a checkpoint whose `root_hash` equals a single receipt's `leaf_hash`
(`root_hash = leaf_hash`, `tree_size = 1`), sign it, and the receipt verifies
against a **degenerate one-leaf tree** with no siblings and no witnesses. This
is the cheapest form of the §1.1/§1.2 attack: a per-receipt tree of size 1 has
no history to be consistent with and nothing to gossip, so it *maximally*
reduces the log to "the operator's signature." Strict mode requires
`inclusion_path` to be *present* (`packages/verify/index.js:671-674`) but not
*non-empty*, so it does not close this.

### 1.4 Net effect

`inclusion proof + one operator signature ≈ the operator's word`. This directly
undercuts EP's headline offline/trustless claim *against the single party the
claim most needs to bind* — the log operator. A relying party who verifies a
receipt "fully offline, no EP infrastructure" today is still trusting the
operator not to equivocate. The audit is correct to rate this MED-HIGH.

---

## 2. The fix

Four mechanisms, layered. (a) and (c) are cheap and local to the verifier; (b)
is the decisive control against equivocation; (d) is operational hardening.

### 2.1 (a) RFC 6962-style checkpoint CONSISTENCY proofs

Add an append-only proof between any two checkpoints of the same log. A
consistency proof between `(oldRoot, oldSize)` and `(newRoot, newSize)` proves
that the newer tree is a **prefix-preserving extension** of the older one —
nothing already committed was removed or rewritten (RFC 6962 §2.1.2, RFC 9162
§2.1.4).

- **Verifier:** `verifyCheckpointConsistency(oldRoot, oldSize, newRoot, newSize,
  proof)` — shipped as an experimental standalone module in this PR
  (`packages/verify/consistency.js`), using the same EP-MERKLE-v2
  domain-separated branch hash (`0x01 || left || right`) as `hashPairV2` in
  `index.js` so proofs compose with the existing v2 inclusion proofs.
- **What it buys:** if a relying party pins *any* prior honest checkpoint (or
  obtains one from a witness / gossip peer), it can demand that every later
  checkpoint be consistent with it. A forked history cannot produce a valid
  consistency proof to a checkpoint it forked away from — the fork becomes
  detectable with pure math, offline. This is the primitive that makes §1.2
  detectable rather than invisible.
- **Wire format (proposed):** add to `log_proof`:
  ```jsonc
  "consistency": {
    "from": { "tree_size": 1024, "root_hash": "sha256:...", "log_signature": "b64u:..." },
    "proof": ["sha256:...", "sha256:..."]   // ordered RFC 6962 nodes
  }
  ```
  `from` is a previously-published, signed checkpoint (ideally one the verifier
  or a witness already holds). `proof` verifies `from → checkpoint`.

### 2.2 (b) WITNESS cosignature model — the decisive control against split-view

Consistency proofs prove append-only **relative to a checkpoint the verifier
trusts**; they do not, by themselves, stop an operator who shows *every* verifier
its own private consistent chain. The fix for equivocation is **independent
witnesses**.

- **Model (Sigsum / Go-checkpoint / IETF Networking):** N independent witness
  operators each (i) hold the log's public key, (ii) receive each new
  checkpoint, (iii) verify it is consistent with the last checkpoint *they*
  cosigned, and (iv) emit a cosignature over the checkpoint. A witness will only
  ever cosign **one** checkpoint per tree size, because it enforces consistency
  against its own view. Therefore, if the operator equivocates (two checkpoints
  at the same or overlapping size that are not consistent), it cannot get the
  **same** witness to cosign both.
- **Verifier rule:** require `≥ k` distinct valid witness cosignatures (k-of-N)
  on the checkpoint, in addition to the operator's `log_signature`. A split view
  now requires corrupting ≥ k independent witnesses simultaneously, not just the
  operator's one key.
- **Wire format (proposed):** add to `checkpoint`:
  ```jsonc
  "witness_cosignatures": [
    { "witness_key_id": "ep:witness:a#1", "signature": "b64u:..." },
    { "witness_key_id": "ep:witness:b#1", "signature": "b64u:..." }
  ]
  ```
  Each cosignature is Ed25519 over the **same** canonical checkpoint bytes the
  operator signed (`canonicalize({log_key_id, root_hash, tree_size})`), against a
  witness key the verifier pins the same way it pins `logPublicKey`. A verifier
  is configured with a witness set + threshold `k`.

### 2.3 (c) Reject empty / degenerate inclusion paths

Independent of (a)/(b), the verifier must stop treating `inclusion_path === []`
as a valid single-leaf tree (§1.3). Proposed rule for a *future, additive*
strict-plus mode (not a silent change to the frozen Section 6.3 checks):

- Reject `inclusion_path.length === 0` **unless** `checkpoint.tree_size === 1`
  **and** that size-1 checkpoint carries the required witness cosignatures. A
  size-1 tree is legitimate only for the very first entry; requiring witnesses
  removes its value as an equivocation shortcut.
- More conservatively for high-assurance receipts: **require a non-empty
  inclusion path** (i.e. `tree_size ≥ 2`), forcing every anchored receipt to
  live in a shared tree with real siblings and a real history.

This is a behavioral change to acceptance criteria and therefore belongs behind
an opt-in flag / new check name, not inside the existing `checks.inclusion`.

### 2.4 (d) Gossip and checkpoint pinning

Operational layer that makes (a)/(b) effective in practice:

- **Checkpoint pinning:** relying parties persist the highest checkpoint they
  have verified (per log) and refuse any later checkpoint that is not consistent
  with it (uses (a)). This gives *each* verifier a personal append-only guarantee
  even without witnesses.
- **Gossip:** verifiers, witnesses, and monitors exchange checkpoints
  out-of-band (e.g. a public checkpoint feed, or piggy-backed on unrelated
  traffic). If any two participants ever hold two inconsistent checkpoints for
  the same log, the fork is exposed. Gossip turns a *local* pin into a *global*
  equivocation detector.
- **Monitors:** long-running third parties that fetch every checkpoint, verify
  consistency, and raise an alarm on any gap or fork (the CT "monitor" role).

---

## 3. Recommended minimum viable design (what to ship first)

Ship in this order; each step is independently valuable and additive.

1. **MVP-1 — Consistency-proof verify (this PR, experimental):**
   `verifyCheckpointConsistency()` lands standalone in
   `packages/verify/consistency.js` with tests. Not wired into the main verifier
   yet. This gives tooling, witnesses, and monitors the primitive immediately and
   lets us pin checkpoints (§2.4) in relying-party code with zero risk to the
   frozen Section 6.3 algorithm.

2. **MVP-2 — Require witness cosignatures on high-assurance receipts:** add
   `witness_cosignatures` to the checkpoint and a `k-of-N` witness check to an
   **opt-in** verifier mode (`opts.witnessKeys`, `opts.witnessThreshold`),
   surfaced as a new check name (e.g. `checks.witness_quorum`) — never a silent
   reinterpretation of `checkpoint_signature`. Gate it on assurance tier so
   low-stakes receipts are unaffected during rollout. **This is the decisive
   control** and is the reason (b) is prioritized over (c)/(d) once the primitive
   from MVP-1 exists.

3. **MVP-3 — Reject degenerate inclusion paths** (§2.3) behind the same opt-in
   high-assurance mode, once witnesses are available to legitimize the rare
   real size-1 case.

4. **MVP-4 — Gossip / monitor tooling** (§2.4): a checkpoint feed + a monitor
   that verifies consistency continuously. Operational, not on the verifier's
   critical path.

**Rationale for the ordering:** consistency verify (MVP-1) is the reusable
primitive everything else needs and carries no behavioral risk, so it ships
first. Witness cosignatures (MVP-2) are what actually defeat equivocation, so
they are the first *enforcement* change. Empty-path rejection (MVP-3) depends on
witnesses to avoid breaking the legitimate first-entry case. Gossip (MVP-4) is
defense-in-depth that amplifies the earlier layers.

---

## 4. Migration path

- **Additive, versioned, opt-in.** The frozen Section 6.3 `checks`
  (`packages/verify/index.js:797-805`) are **not** renamed or reinterpreted. New
  guarantees appear as *new* checks and *new* opt-in verifier options, exactly
  like `strict` mode (`packages/verify/index.js:964-969`) and the advisory
  `attestation` report were added.
- **Backward compatibility.** Receipts without `consistency` /
  `witness_cosignatures` continue to verify under the existing checks. A relying
  party opts into the stronger guarantees by pinning a witness set + threshold;
  until then behavior is unchanged. "Receipts verify forever" is preserved.
- **Issuer rollout.** (1) Stand up N witnesses and a checkpoint feed. (2) Issuer
  starts emitting `consistency` proofs and gathering witness cosignatures. (3)
  High-assurance policies flip on `witnessThreshold` and empty-path rejection.
  (4) Monitors run continuously. Each stage is independently deployable.
- **Ownership note.** MVP-2/3 touch `verifyTrustReceipt`, which is owned by the
  Merkle-v2 track. This doc + MVP-1 are the additive, non-conflicting first step;
  wiring is a follow-up coordinated with that owner.

---

## 5. Standards mapping (credibility)

| EP mechanism | Standard / prior art | Notes |
| --- | --- | --- |
| Merkle inclusion proof | RFC 6962 §2.1.1 / RFC 9162 §2.1.3 | Already present (`verifyMerkleAnchor`). |
| Checkpoint consistency proof | **RFC 6962 §2.1.2 / RFC 9162 §2.1.4** | Implemented in `consistency.js` (this PR). |
| Signed checkpoint / signed tree head | RFC 6962 STH; Sigsum/Go "checkpoint" | EP `checkpoint` + `log_signature`. |
| Witness cosignatures (k-of-N) | Sigsum witness model; Go-checkpoint cosigned notes; IETF witness drafts | Proposed §2.2. Defeats split-view. |
| Gossip / monitors | RFC 6962 gossip; CT monitors | Proposed §2.4. |
| Transparency Service as a whole | **IETF SCITT** (Transparency Service, Registration Policy, Receipt) | EP's log is a SCITT-style Transparency Service; a witness-cosigned, consistency-proven checkpoint is a stronger SCITT Receipt. See `docs/EP-RECEIPT-SCITT-PROFILE.md`. |

Positioning: EP already claims a SCITT-aligned receipt profile. SCITT's value
proposition is a *verifiable, non-equivocating* Transparency Service; without
consistency proofs + witnesses, EP's log meets the *format* but not the
*non-equivocation* bar. This design closes that gap and lets EP say — credibly,
to a DoD auditor — that the offline verifier constrains the log operator with
the same mechanisms CT uses to constrain CAs.

---

## 6. Appendix — experimental scaffold shipped with this design

`packages/verify/consistency.js` (EXPERIMENTAL, not wired into
`verifyTrustReceipt`):

- `verifyCheckpointConsistency(oldRoot, oldSize, newRoot, newSize, proof)` —
  RFC 6962 §2.1.2 verifier over EP-MERKLE-v2 branch hashing; fail-closed on
  malformed input; accepts `sha256:`-prefixed hashes.
- `buildConsistencyProof(m, n, leaves)` / `merkleRoot(leaves)` — reference
  prover + root for tests, tooling, and witnesses.

Tests: `packages/verify/consistency.test.js` (run `node --test
consistency.test.js`) — exhaustive round-trip for all `1 ≤ m ≤ n ≤ 16`, plus
explicit **rejection** of a rewritten prefix (split-view), tampered proof nodes,
wrong old root, and malformed inputs.

The module is intentionally **not** re-exported from `packages/verify/index.js`
and **not** added to the `package.json` test script — it is design-stage
reference code, gated behind the MVP-2 coordination described in §4.
