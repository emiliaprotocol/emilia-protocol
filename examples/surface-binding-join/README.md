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
