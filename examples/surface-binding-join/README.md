# The two-row join, runnable

Possession proven live in the channel; authorization carried as evidence bound to
the action. Each row proven on its own terms, joined by digest equality, never
merged. This example runs the join end to end.

```
node examples/surface-binding-join/run.mjs
```

It issues a signed EP receipt over an action that carries an EP-SURFACE-BINDING-v1
reference (`approval_surface`) to possession-row evidence, then:

1. verifies the receipt (authorization row);
2. confirms the surface binding is covered by the human's signature and joins to
   the possession evidence by digest equality (`digest_match: true`);
3. swaps the claimed possession evidence and shows the join fails closed
   (`surface_digest_mismatch`);
4. runs the reliance kernel beside it: `rely` with the receipt, `do_not_rely_unsigned`
   without.

The possession-row evidence here is a **synthetic** stand-in shaped like a
condition-bounded credential presentation (WIMSE LIT style). It is not a real LIT
artifact. Swap in a real presentation and nothing about the join changes: EP hashes
the bytes and carries the digest inside the signed action; the possession row's own
verifier judges what those bytes mean, in its own trust boundary. A surface
attestation is evidence about the display environment, never proof of perception.

## The join with a signed possession row (`run-lit.mjs`)

The second script replaces the synthetic stand-in with a **structured, signed**
possession row in the WinMagic-LIT shape, supplying the two pieces a real surface
vendor provides: `producePresentation` (device side, private key) and
`verifyPresentation` (relying-party side, pinned public keys). EP is unchanged; it
still only hashes the evidence bytes and joins by digest equality.

```
node examples/surface-binding-join/run-lit.mjs
```

Evidence bytes are framed as a 2-byte length prefix, a canonicalized JSON payload,
and a 64-byte Ed25519 signature by the device's Live Key over that payload. The
payload carries five items:

1. **version + profile id** — the verify library knows how to parse; condition
   claims are a declaration by reference to the profile, not a list of internals;
2. **key id** — hash of the DER-encoded SPKI public key the relying party pinned
   at registration, so verification is a lookup, not a chain walk;
3. **condition claims** — phase-table style (`user-verified-at-mint`,
   `posture-at-build`, `checksum`); mint inputs need no runtime assertion, the
   signature existing is the proof they held;
4. **ceremony binding** — a hash of the pre-surface action draft (the action minus
   `approval_surface`, avoiding circularity) plus an RP-issued nonce the verifier
   compares against its own expected value;
5. **timestamp** — the relying party applies its own staleness window.

The relying party runs four local checks: the EP receipt, the digest join, the LIT
presentation under pinned keys, and the reliance kernel. Three refusals then show
each defense doing distinct work, fail-closed with distinct reasons:

- **tampered payload byte** — both rows refuse independently
  (`surface_digest_mismatch`, `payload_unparseable`);
- **rogue device** — an identical payload signed by an unpinned key is refused by
  the LIT verifier (`key_id_not_pinned`);
- **cross-ceremony replay** — genuine evidence bytes baked into a new action draft
  pass the digest join (the bytes are the bound bytes) but the ceremony binding
  inside the signed payload refuses (`ceremony_binding_mismatch`). This is the case
  the join alone cannot catch.

The Live Key pair is generated ephemerally for the demo; in production it is
provisioned on the device, and relying parties pin the public key out-of-band at
registration.
