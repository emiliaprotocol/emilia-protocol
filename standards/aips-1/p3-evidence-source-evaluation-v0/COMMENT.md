# Comment on AIPS-1 v0.1 P3: Evidence Source evaluation

Status: draft public comment, not submitted

Target: AIPS-1 v0.1

Published deadline: 30 November 2026

AIPS-1 v0.1 requires Trigger predicates to be evaluable against declared
Evidence Sources and excludes triggers that depend solely on issuer discretion
or undefined external conditions. That boundary is useful. The draft does not
yet define enough evaluation semantics for two implementations to process the
same evidence and reliably reach the same result.

The `triggers` field is described at a high level, and Appendix A gives one
oracle example. Neither defines a complete predicate grammar, typed comparison
rules, Evidence Source snapshot binding, retrieval and freshness behavior,
conflict handling, or portable reason codes. The specification also defers its
reference verifiers to v0.2.

For v0.2, P3 should define a small, implementation-independent evaluation
profile with these properties:

1. Each Evidence Source has a stable identifier, an addressable locator, a
   declared data format, and a named trust or authentication policy.
2. Each observation records the source identifier, retrieval time, effective
   time or validity interval, media type or schema, payload digest, and any
   authentication result. A mutable URL alone is not a stable observation.
3. Trigger predicates use typed operands and a closed, versioned operator set.
   Number, string, Boolean, timestamp, existence, and collection comparisons
   need exact semantics.
4. Evaluation has three results: `SATISFIED`, `NOT_SATISFIED`, and
   `INDETERMINATE`. `NOT_SATISFIED` is appropriate only when usable evidence
   resolves the predicate false. Missing, unavailable, stale, conflicting,
   unsupported, unauthenticated, or unpinned evidence yields `INDETERMINATE`.
5. A deterministic report identifies the profile version, evaluation time,
   predicate, source snapshots, result, and closed reason codes. Re-evaluation
   over the same inputs must produce the same report bytes or the same
   canonical digest.
6. An issuer-operated source is not automatically unusable, but an issuer's
   conclusion cannot substitute for the declared evidence or become the sole
   discretionary basis for a P3 result.

The result boundary should also be normative. `SATISFIED` would mean only that
the named Trigger predicate evaluated true under the declared profile and
source snapshots. It would not establish P2 coverage scope, P5 policy status,
legal enforceability, liability, claim acceptance, settlement, or payout.

The accompanying package tests the source-pinning, closed-operator, three-state,
and deterministic-report parts of this proposal over paired offline fixtures.
Its reports are bound to their inputs. It does not retrieve or authenticate a
source, and it labels every result as local. It is not a native AIPS-1 verifier,
an AIPS-1 conformance suite, an AEB adapter, or evidence of adoption or
endorsement.
