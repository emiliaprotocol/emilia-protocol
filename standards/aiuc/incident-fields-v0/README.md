# Incident Action Authorization Field Group v0.1

Status: draft proposal, not submitted

Prepared: 2026-08-16
Target context: bounded external feedback to AIUC-1

This package proposes a small, implementation-neutral field group for recording
the authorization state of one consequential AI-agent action within an incident.
It is not an AIUC-1 document, has not been reviewed or accepted by AIUC, and does
not claim that AIUC-1 requires these fields.

## Package contents

- `SPECIFICATION.md`: the two-page-equivalent field specification and coding
  rules.
- `PRIOR-ART.md`: direct comparison with Chen's action-level Authority Frontier
  work and Wei and Heim's incident-reporting-system design work.
- `EXAMPLE-AIID-1152.md`: end-to-end coding of AI Incident Database Incident
  1152.
- `example-aiid-1152.json`: machine-readable form of the worked example.
- `incident-fields.schema.json`: JSON Schema for the example format.
- `SOURCES.md`: primary and authoritative source register.
- `CLAIM-EVIDENCE.md`: claim/evidence ledger, including negative and design
  claims.
- `validate.mjs`: zero-dependency Node validator for coded-incident JSON
  against the specification (closed code sets, required fields, unknown-field
  rejection, and the Section 7 cross-rules).
- `vectors/`: hostile test vectors, each named for the single defect it
  carries and each rejected with a specific named failure.
- `validate.selftest.mjs`: zero-dependency node:test suite covering the positive example, every
  hostile vector, and report determinism.
- The repository CI executes `validate.selftest.mjs` directly, so the public
  zero-dependency runner is enforced without folding this standards artifact
  into the repository-wide proof-stat measurement.

## Adoption boundary

Any incident database, auditor, insurer, deployer, researcher, or agent vendor
can emit these fields from its own records. EMILIA is one possible evidence
producer for the strongest evidence grade. EMILIA is never a dependency, a
required verifier, or a condition of using the vocabulary. An EMILIA-produced
record receives no preferred treatment and must satisfy the same grade criteria
as any other artifact.

## Official AIUC-1 route and timing check

Checked on 2026-08-16:

- The canonical public route is AIUC-1's
  [Provide input on AIUC-1](https://www.aiuc-1.com/learn/contribute) page. Its
  button opens a public Typeform identified by `DgTl55CN`.
- The [AIUC-1 changelog](https://www.aiuc-1.com/changelog) says the standard is
  updated quarterly on January 15, April 15, July 15, and October 15. It says
  the July 15, 2026 version is current and the next release is October 15,
  2026.
- The same changelog lists October 1, 2025 in standard history. That is a
  historical publication date, not evidence of a recurring October 1 cutoff.
- Neither checked page publishes a deadline for external input. A release date
  must not be restated as a submission deadline. Any October 1 or October 15
  contribution deadline remains unverified unless AIUC publishes one.

No AIUC-1 form has been submitted, and AIUC has not reviewed or accepted this
proposal. An initial email sharing the package was sent on 2026-08-16, but its
link pointed to a private repository. This public mirror corrects that
distribution error without changing the proposal's scope or status.

## Run

From this directory, with plain Node (no npm install):

```sh
node validate.mjs example-aiid-1152.json            # positive example, exit 0
node validate.mjs vectors/unknown-status-code.json  # named failure, exit 1
node validate.mjs vectors/malformed.json --report   # byte-stable report form
node --test validate.selftest.mjs                   # full suite, incl. determinism
```

Every file under `vectors/` is hostile and must fail with exactly the named
reason its filename describes; `example-aiid-1152.json` must pass every check.

What the validator establishes: that a coded-incident JSON document conforms
to SPECIFICATION.md. It enforces the closed authorization-status,
decision-timing, evidence-grade, execution-status, and action-class code
sets, the required field group, rejection of fields the spec does not define,
resolution of every evidence reference to a `sources` entry (Section 7 rule
3), the decision-timing rule for `denied`, `revoked`, and `specific_approval`
(rule 5), and the rule that a status other than `indeterminate` needs a
non-empty `basis_summary` and at least `E1_party_attested` evidence (rule 4,
with the Section 5 `E0_no_reviewable_evidence` row).

What it does not establish: the truth of the underlying incident facts or of
any cited source; that `incident_ref.url` resolves to the named incident
(rule 1 needs a network read, so only URL syntax is checked); `action_ref`
uniqueness across a multi-action incident record (rule 2, not checkable in a
single-action file); or the human-judgment rules 6 and 7 beyond their
structural footprint. Grading evidence is not verifying evidence.

This package is published in the EMILIA Protocol repository under the
repository's Apache-2.0 license. Publication does not make it an AIUC document
or imply AIUC review, acceptance, or adoption.

## Local schema validation (optional)

The zero-dependency validator above is the authoritative check. The JSON
Schema can additionally be exercised from the repository root:

```sh
jq empty standards/aiuc/incident-fields-v0/incident-fields.schema.json \
  standards/aiuc/incident-fields-v0/example-aiid-1152.json
npx --yes --package ajv-cli@5.0.0 --package ajv-formats@2.1.1 \
  ajv validate --spec=draft2020 -c ajv-formats \
  -s standards/aiuc/incident-fields-v0/incident-fields.schema.json \
  -d standards/aiuc/incident-fields-v0/example-aiid-1152.json
```

## Readiness checklist

- [x] Versioned two-page-equivalent field specification.
- [x] Authorization codes have mutually distinguishable coding tests.
- [x] Evidence grade is attached to each coded authorization state.
- [x] One public incident is coded with its AIID identifier.
- [x] Machine-readable example validates against the included schema.
- [x] Zero-dependency validator, hostile vectors, and node:test suite
  included and passing.
- [x] Chen arXiv:2605.25632 read and cited from the primary paper.
- [x] Wei and Heim read and cited from the primary paper.
- [x] EMILIA is framed only as an optional evidence producer.
- [x] Liability, severity, intent, verification, and certification limits are
  explicit.
- [x] AIUC-1 contribution route and release cadence checked against first-party
  pages.
- [x] Published release dates separated from any unverified input deadline.
- [x] Claim/evidence ledger and source register included.
- [ ] Independent subject-matter review completed.
- [x] Published in the public EMILIA Protocol repository under Apache-2.0.
- [ ] AIUC-1 form submitted.
- [ ] Public-link correction to Cristian Trout sent.

The unchecked items are external review and submission gates. They are not
authorized by this package.
