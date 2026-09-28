# AEC revision 07 working packet

This directory stages `draft-schrock-ep-authorization-evidence-chain-07`.
It is not published. The last posted revision is -06 (Datatracker posting
2026-09-06T17:33:02Z), whose exact source is kept in `../NEXT-AEC-06/` and
`../../posted/`. This packet started from that source byte for byte.

-07 is a substantive revision. -06 defined VERIFIED as "The native verifier
accepted an artifact under the selected native profile", and defined the
native verifier as checking syntax, signatures, issuer, audience, validity
and format semantics "under pinned trust inputs" (posted -06 TXT, lines
183-190). Together those made VERIFIED carry the relying party's trust
decision, so the draft had no way to say that an artifact was intact but
signed by a key the relying party does not trust. -07:

- defines VERIFIED as the cryptographic and structural result only, and adds
  ACCEPTED as a separate result for the relying party's pinned trust inputs;
- requires the native verifier to report both, never ACCEPTED without
  VERIFIED, and to report an artifact as not VERIFIED when a combined native
  procedure cannot attribute a failure;
- keeps key-resolution material apart from the pinned trust inputs: an
  unresolvable key reference is recorded as NOT_EVALUATED, not FAILED, and a
  resolved key's directory status decides ACCEPTED;
- keeps the exact action out of ACCEPTED: native verifiers evaluate pins
  against the action the artifact carries, and only MATCH compares it with
  the expected action;
- carries the split through the acceptance inputs (Section 5), the native
  result contract (Section 6), matching (Section 7), the algorithm
  (Section 9), the replay record (Section 10, with `native_verification` and
  `acceptance` fact members and a defined `algorithm_revision` value), the
  built-in components (Section 11, each built-in requirement still a MUST,
  now stated on the result it decides), the bounded-capability component
  (Section 12, whose referenced capability and issuance authorization must
  each be VERIFIED, and ACCEPTED under the pins for its own role, and whose
  native scope result is a condition of ACCEPTED), the lifecycle
  (Section 13, whose execution outcome FAILED is kept apart from the
  native verification value) and Security Considerations (Section 14);
- defines UNSATISFIED explicitly;
- updates the implementation status and the cited revisions.

"Changes in -07" (Section 18) lists the changes.

## Files

- `UPLOAD-THIS/draft-schrock-ep-authorization-evidence-chain-07.xml`: the
  source.
- `RENDERS/`: the TXT and HTML renderings of that source, produced by
  xml2rfc 3.34.0.
- `SHA256SUMS.txt`: pins the source and both renderings.
- `VALIDATION.md`: the checks run and their results.

## What checks it

`npm run check:aec-07` (`scripts/check-aec-07.mjs`) fails unless the packet
holds exactly these three files, the rendered text states the VERIFIED,
ACCEPTED, MATCH and UNSATISFIED definitions, the separate-reporting rules,
the algorithm and replay requirements and the lifecycle line, none of the
-06 sentences that merged the two results survives in the source or the
render, the source and render are printable ASCII with no en or em dash and
no render line over 72 columns, the cited revisions are the ones listed in
`VALIDATION.md`, the checksums match, and the posted -06 XML is unchanged.

It also fails unless `packages/verify/src/evidence-chain.ts` on the same tree
is the evaluator that Sections 10 and 21 describe (it emits
`EP-AEC-EVALUATOR-07-v1` and has the receipt, key-resolution and per-fact
result code those sections name), so the packet cannot land on main ahead of
the code its Implementation Status describes. `feat/verify-aec-07-evaluator`
is merged into this branch, and the check passes here.

## Reference implementation

Section 21 describes the evaluator merged into this branch from
`feat/verify-aec-07-evaluator` (`packages/verify/src/evidence-chain.ts`, tests
in `packages/verify/aec-current-profile.test.ts`). It is not on main until
this branch merges. It changes the public contract of
`createAuthorizationChainEvaluator`: native verifier callbacks return
`verified` (or `null` when it could not be evaluated) and `accepted` instead
of `valid`, replay facts carry `native_verification` and `acceptance` instead
of `native_valid`, and replay records carry `algorithm_revision`
`EP-AEC-EVALUATOR-07-v1`, the value Section 10 now defines.
`packages/verify/CHANGELOG.md` records it under Unreleased ("Breaking:
structured AEC evaluator contract") as a BREAKING change to custom verifier
callbacks and replay facts that ships in 6.0.0. The legacy
`verifyAuthorizationChain` API is unchanged.

## Hold

Upload is the author's decision. Before it:

1. The evaluator ships in verify 6.0.0 with this branch; it is no longer
   held for a later release. The evidence pins on this branch are
   regenerated over origin/main `2d8bde58c`; if main moves before this
   branch merges, merge main and re-run the commands listed in
   `VALIDATION.md` ("Merged branch"). Section 21 describes the changed
   evaluator; if -07 is uploaded before this branch reaches main, Sections
   10 and 21 describe code that is not yet on main.
2. Set the date, confirm that -06 is still the latest AEC revision and that
   each cited draft revision is still the latest on Datatracker (if CAID -04
   has posted, cite it and recheck the Section 7 verdict names against it),
   re-render with the procedure in `VALIDATION.md`, and refresh
   `SHA256SUMS.txt`, `VALIDATION.md` and the pins in
   `scripts/check-aec-07.mjs`.
3. Upload -07 before `draft-schrock-ae-challenge-08`, which cites -07 for
   the outcome terms it restates.
