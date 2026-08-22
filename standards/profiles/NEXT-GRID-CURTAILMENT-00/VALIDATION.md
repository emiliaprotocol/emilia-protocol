# GRACE curtailment -00 validation record

Validated on 2026-08-21 against a clean worktree after merging `origin/main` at `3a029cc3`.

## Executable receipt

Command:

```bash
npx vitest run \
  tests/grace-curtailment.test.ts \
  tests/grace-mobile-grid.test.ts \
  lib/grace/mobile-grid-v2.test.ts \
  tests/mobile-production-routes.test.ts
```

Result:

```text
Test Files  4 passed (4)
Tests       80 passed (80)
```

The 80 cases include 11 hostile checks for the optional Ed25519 plus ML-DSA-65 artifact envelope.
The test keys and software backend are reference inputs, not production custody or FIPS-validation
evidence.

The runnable reference circuit also completed with:

```text
MOBILE      2 distinct Class-A handshakes: VERIFIED
COSA        DISPATCHED (reference adapter)
DELIVERY    99.2%
ACTIONSTATE signed, unregistered
SETTLEMENT  CONSUMED ONCE
replay                REFUSED (refuse_replay)
action_substitution   REFUSED (refuse_outcome_policy)
meter_rule_smuggling  REFUSED (effect_unconfirmed)
```

The circuit labels its actuator and meter as simulations and claims no physical grid event.

## Document receipt

- `xmllint --noout` accepted the RFCXML source.
- `xml2rfc 3.34.0` generated the retained TXT and HTML renderings.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` against the TXT rendering.
- Google Chrome headless printed the retained convenience PDF from the xml2rfc HTML rendering.
  The PDF is not a native xml2rfc PDF because the local xml2rfc installation lacks the optional
  WeasyPrint native libraries.
- `npm run check:grace-curtailment-profile` checks current profile identifiers, prohibited
  overclaims, the meter-rule boundary, Action State limits, six declared vertical vectors,
  publication authorization, and all four artifact digests.

## Publication authorization

- `https://datatracker.ietf.org/doc/draft-schrock-kintzele-grid-curtailment/` returned HTTP 404 on
  2026-08-21.
- The repository's ordinary new-name filing freeze would run through 2026-11-01.
- On 2026-08-21, founder Iman Schrock explicitly authorized immediate filing as a one-time internal
  governance override after the final source, renders, hashes, tests, formal scenarios, security
  case, and production build passed.
- This override does not claim that the named-external-implementation exception was satisfied.
- Justin D Kintzele approved submission as coauthor and confirmed the exact published metadata
  `Justin D Kintzele`, `J Diesel NY, LLC`, and `jkintzele@jdieselny.com` by email on 2026-08-21.
- The exact upload source is
  `REVIEW-SOURCE/draft-schrock-kintzele-grid-curtailment-00.xml`, pinned by `SHA256SUMS.txt`. The
  packet contains no duplicate `UPLOAD-THIS` copy.
- Datatracker submission 167956 was accepted and revision `-00` was posted on 2026-08-22.
- As verified on 2026-08-22, the Datatracker record lists
  `draft-schrock-kintzele-grid-curtailment-00` as an active individual Internet-Draft with an
  expiry date of 2027-02-23.
- The retained XML is byte-for-byte identical to
  `https://www.ietf.org/archive/id/draft-schrock-kintzele-grid-curtailment-00.xml` at
  `sha256:0c656d9cbdb0701a23668420460a6d1143efcf74db8919f4a9c24f4fd5697ba6`.
- The retained TXT is byte-for-byte identical to
  `https://www.ietf.org/archive/id/draft-schrock-kintzele-grid-curtailment-00.txt` at
  `sha256:8dd61f1f66077d64bb185c3a7a5354f46bb19f0d2f28beb9e2ff728a049adb87`.
- Accepted submission, Datatracker posting, and archive-byte verification do not establish an
  implementation, deployment, working-group adoption, RFC status, or IETF endorsement.

## Claim limits

The packet does not claim physical meter truth, baseline correctness, tariff eligibility, payment,
complete mediation, production COSA integration, utility adoption, external reproduction, an
independent implementation, SCITT registration, hardware key custody, or FIPS validation.
