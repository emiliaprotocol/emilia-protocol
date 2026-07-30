# EMILIA ↔ Markovian public transparency cross-run

**Status:** Executed and independently returned on 2026-07-29.

This directory preserves the first real-action exchange between an EMILIA
authorization receipt and the public Markovian transparency log.

## Executed sequence

1. EMILIA issued and locally verified one exact
   `transparency.log.append` action receipt.
2. Markovian independently recomputed the action hash, verified the Class-B
   signoff and key window, and appended one canonical leaf.
3. Markovian preserved the exact source receipt bytes separately from its
   canonical leaf bytes. The two digests are intentionally not interchangeable.
4. Markovian returned an RFC 6962 inclusion proof at tree size 4881, a
   log-signed checkpoint with 7/7 witness cosignatures, and a consistency proof
   from 4881 to the next witnessed head at 4912.
5. The returned offline verifier passes all nine checks against the checked-in
   return package.

## Pinned coordinates

- receipt: `ep:receipt:markovian-cross-run-20260729-001`
- typed leaf index: `4869`
- leaf construction: `markovian-leaf/canonical-action-bytes/1`
- source receipt: 3,239 bytes,
  `sha256:213a9e8350ab3421c878b683d33d4c27fc5a5cd8cb521f137e8e95a41c99bd83`
- canonical leaf: 2,718 bytes,
  `sha256:aad626dc45bf0f3ea4bdbf9f378f99288edf60ab37c1a29583602f53b2446f94`
- inclusion head: tree size `4881`, 7/7 witnesses
- next head: tree size `4912`, 7/7 witnesses

## Signature constructions

The constructions are distinct and MUST NOT be conflated:

- An EP-native receipt checkpoint signature is Ed25519 over the raw 32-byte
  SHA-256 digest of the UTF-8 JCS serialization of the checkpoint object after
  removing `log_signature`. For the current receipt profile, that object is
  exactly `{log_key_id, root_hash, tree_size}`.
- A Markovian signed-note log signature covers the signed-note body.
- A Markovian witness cosignature covers
  `cosignature/v1\ntime <timestamp>\n<signed-note-body>`.

## Assurance boundary

The returned package proves that the exact canonical leaf was included in the
witnessed log and that the later witnessed head is an append-only extension of
the inclusion head. It does not make the receipt's claims true.

The source receipt carries a Class-B software-key signoff. It proves that the
pinned named key signed the exact action under the supplied public material. It
does not independently establish Class-A device-bound presence or identity
enrollment for Iman Schrock.

## Files

- `ep-markovian-action-receipt-v0.1.json`: exact source receipt sent by EMILIA.
- `ep-markovian-verification-v0.1.json`: public verification material.
- `ep-markovian-offline-result-v0.1.json`: EMILIA's pre-send offline result.
- `ep-markovian-manifest-v0.1.json`: sent byte manifest and exchange scope.
- `MARKOVIAN-CROSS-RUN-20260729-001.json`: Markovian's self-contained return.
- `verify_cross_run.py`: Markovian's returned offline verifier.

Run:

```sh
python3 interop/markovian-emilia/verify_cross_run.py \
  interop/markovian-emilia/MARKOVIAN-CROSS-RUN-20260729-001.json
```
