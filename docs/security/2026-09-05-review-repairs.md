# September 5 security review repairs

Scope: the five findings from the focused local review of receipt verification,
provider entry, and Python examples. This is a same-team repair and regression
record, not an independent audit or a claim that the protocol has no other flaws.
All test effects use synthetic local providers.

## Repairs

1. **A signed denial is not approval.** The demand verifier accepts embedded
   Class-A assurance only when the authenticated decision is `approved`.
   A trusted outer issuer cannot turn a genuine negative human decision into
   authorization by labelling its receipt `allow_with_signoff`.
2. **Validity must survive the wait to provider entry.** JavaScript Gate retains
   a private snapshot of the verified receipt and checks its validity after
   reservation, evidence logging, entry guards, and runtime-monitor setup.
   The Python synchronous gate checks again after assurance and reservation.
   Expiry before ordinary provider entry refuses with zero provider calls.
   Failed release stays held. Capability entry already committed in its store
   stays consumed and indeterminate even when the provider was not invoked.
   A lost provider response never restores authority.
3. **The legacy examples fail closed.** Unknown, malformed, contradictory, or
   failed policy responses refuse execution. An acquisition callback is not an
   approval verifier. Signoff requires a separately configured verifier over the
   exact action and complete arguments. The examples have no built-in receipt
   cryptography or replay store and recommend ReceiptGate for production.
4. **The signature profile is enforced.** EP-RECEIPT-v1 requires the Ed25519
   label and an Ed25519 issuer key. Another algorithm's valid signature is not
   accepted under this profile. Current documented case-insensitive spellings
   remain supported; absent, unknown, and conflicting labels refuse.
5. **Malformed Python receipts return refusal.** Incorrect nested payload,
   signature, and anchor shapes no longer escape as attribute errors. Merkle
   proof text that cannot be encoded also returns a failed verification result.

## Intentional compatibility changes

- Python ReceiptGate and its decorators support synchronous, non-generator tools.
  Known async/generator callables are refused before reservation. Awaitables and
  iterators returned by a synchronous callable do not escape; that attempted
  authorization remains consumed. Async execution needs an actual async lifecycle,
  not a synchronous wrapper around a coroutine.
- Legacy example signoff callbacks need a separate pinned `verify_signoff` hook.
  Returning `True` from the acquisition callback alone does not authorize.
- Receipt producers must include the correct `signature.algorithm` field.

## Regression sources

- `packages/require-receipt/security-profile.test.ts`
- `packages/gate/receipt-provider-entry-freshness.test.ts`
- `packages/gate/runtime-monitor.test.ts`
- `packages/crewai/tests/test_gate_security_regressions.py`
- `packages/python-verify/tests/test_receipt_shapes.py`
- `examples/tests/test_emilia_guard_fail_closed.py`

The signed-decision and uncertain-effect cases are also registered in
`security/claims.v1.json`. Existing conformance vectors remain unchanged.
Package runtimes and drop-in copies are rebuilt from their canonical sources.

## Release boundary

These are unreleased source repairs. Local verification does not update an
installed package or production deployment. Publishing, merging, deployment,
customer adoption, and independent audit remain separate steps. Repository and
package versions are intentionally unchanged in this repair branch.
