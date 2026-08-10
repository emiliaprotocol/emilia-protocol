# Hostile review of AE-CHALLENGE-06 and the private -07 candidate

Date: 2026-08-10

Internal record only. This is not independent review and is not an upload
artifact.

## Repaired protocol defects

1. Separate capacity and nonce operations allowed duplicate reservation or
   nonce burn. The candidate defines one owner-side transition.
2. A statefully issued challenge could deadlock at its own cap if its existing
   debit was counted again. The debit now transfers and only the positive
   incremental delta is added.
3. Replay scope omitted authenticated issuer identity. The security key is now
   the stable authenticated issuer identity plus nonce; `challenge_id` remains
   correlation only.
4. Replay, collision, and expiry precedence was ambiguous. The candidate now
   defines one total order, including expired open-body collisions.
5. Delimiter-joined replay tuples could collide. The finite model uses a
   structured tuple.
6. Recovery fencing was asserted while the reservation record omitted its
   owner token. The model now carries and checks that token.
7. The nonce wire syntax could not enforce the stated 128-bit floor. It is now
   at least 16 random octets encoded as 22 to 128 unpadded base64url
   characters.
8. The document called a refusal envelope an HTTP binding while leaving the
   corrected request and authenticated return path undefined. It is now an
   HTTP challenge-response carrier, and `present_as` profiles own the return
   path.
9. Problem Details `title` and `status` were treated as mandatory machine
   identifiers. The type URI is now primary; title can be localized and status
   can be omitted.
10. The 401/403 boundary and 409/429/503 mappings were incomplete. Their use is
    now constrained to the actual HTTP condition.
11. Retry-After conversion omitted the delay-seconds clock basis. It is now
    relative to response receipt and combined with `not_before` by taking the
    later instant.
12. An informative DMSC section used normative conformance language. It is now
    explicitly illustrative.
13. Unresolved carrier choices appeared as v1 interoperability questions. They
    are now future profiles outside the v1 core and HTTP carrier.
14. `critical` did not say whether it named nested fields. It now names only
    top-level core members; nested core objects are closed.
15. Policy-oracle, confidentiality, digest-dictionary, pre-owner resource, and
    final-action TOCTOU boundaries are now explicit.
16. The state namespace was changed in place during hardening. Issuer-scoped
    replay now uses v3, with a separate v2-to-v3 drain or atomic migration.

## Runtime defects caught and bounded

- Generated standalone JavaScript was stale while Vitest redirected imports to
  TypeScript. The standalone runtimes are regenerated and a direct standalone
  synchronization gate is required.
- Caller-supplied production nonces are refused; production nonces are minted
  internally.
- Effective `NODE_ENV=production` now applies even when the caller omits the
  explicit option.
- Production evaluation requires a challenge audience and separately supplied
  authenticated presenter. The deprecated audience assertion is insufficient.
- Per-call action digesters were removed from the security decision.
- Multiple advertised presentation profiles no longer fail merely because the
  supported profile is not the sole array member.
- A backend timeout after a possibly committed claim returns typed
  unavailability with `state_changed: unknown`, invokes no evidence verifier,
  and emits no follow-up.
- Follow-ups refuse reuse of the prior identifier or a changed action profile,
  and recheck the current action after evidence evaluation before registration.

## Deliberately unclaimed and publication-blocking

The runtime does not implement the normative `compoundClaimAndCapacity()`
transition, multi-bucket database transaction, self-describing issuance,
fenced recovery, raw-JSON duplicate detection, or a complete strict v1 profile.
Production -07 conformance is therefore blocked by an unavailable capability,
not inferred from partial behavior.

The finite model is same-team scenario exploration over small bounds. It does
not prove database isolation, crash atomicity, alias authentication, quota
transfer, or implementation refinement. No independent implementation or
interoperability result is claimed.

The candidate must remain unpublished until the source, renders, checksums,
runtime companions, and validation record are regenerated together and the
exact packet receives independent HTTP and security review.
