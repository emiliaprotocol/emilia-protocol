# EMILIA Authority Record 100-Agent Study Methodology v1

Status: preregistered before candidate selection or scanning
Registered: 2026-08-14
Planned field window: 2026-08-20 through 2026-09-30

## Question

What consequential-action surfaces and enforcement evidence are observable in a reproducible sample of public agent repositories at one immutable revision?

The study maps public evidence. It does not certify an agent, score trust, prove safety, establish complete mediation, or test a deployed service.

## Candidate frame

A repository is eligible only when all of the following are true before sampling:

1. It is public and has an identifiable upstream GitHub repository.
2. Its official documentation describes software that autonomously or semi-autonomously invokes tools, changes external state, or proposes changes for execution.
3. The repository has a resolvable default branch and at least one commit in the 180 days before the frame is frozen.
4. Its license and public documentation permit ordinary local inspection.
5. It is not an EMILIA repository, a fork selected only because it cites EMILIA, a test fixture, or an intentionally vulnerable training target.

Candidates may be found through public package directories, official framework showcases, accelerator portfolios, and repository-topic searches. IETF participation, private correspondence, and an author's relationship with EMILIA are not selection criteria.

## Fixed sample

The frozen candidate frame will be assigned to five strata according to the primary consequential surface stated in official documentation:

- code, deployment, or infrastructure: 25
- tool, connector, or MCP invocation: 25
- commerce, payments, or business records: 20
- devices, operations, or physical systems: 15
- general multi-step autonomous work: 15

Within each stratum, repositories are ordered by the lowercase hexadecimal SHA-256 of:

`EMILIA-AUTHORITY-RECORD-100-v1\0` followed by the canonical GitHub repository URL.

The lowest hashes are selected until the stratum quota is full. If an eligible repository becomes unavailable before its scan, the next hash in that stratum replaces it and the replacement is logged. The frame, hashes, exclusions, and replacements will be retained with the study artifact.

## Observation unit

One observation is one repository at:

- a canonical source URL;
- a watched branch or tag;
- the exact resolved commit;
- an artifact digest;
- a scanner version and profile digest;
- an observation and expiry time.

Moving branches are never evidence bytes. They are watched pointers whose resolved commit is recorded before inspection.

## Procedure

1. Resolve the watched ref once and record the immutable commit.
2. Download or clone only that commit.
3. Run the pinned EMILIA Authority Map profile locally.
4. Inspect official repository documentation and declared configuration needed to classify supported surfaces.
5. Record only the closed Authority Record public projection. Raw scanner findings, possible bypass paths, secrets, and exploit-enabling detail remain private.
6. Have a second reviewer check the source pin, classification, evidence status, and forbidden-claim screen.
7. Aggregate the results only after all accepted observations pass the same profile.

No active exploitation, credential use, network probing of deployed systems, or attempts to trigger external effects are permitted.

## Labels

Evidence status is one of `OBSERVED`, `SELLER_ASSERTED`, `UNVERIFIED`, or `INDETERMINATE`. Enforcement status is one of `NOT_ASSESSED`, `DECLARED`, `OBSERVED`, `OWNER_CONFIRMED`, or `INDETERMINATE`.

An unequal watched-ref resolution can make a record `STALE` only after a successful lookup. Rate limits, deletion, ambiguous resolution, and upstream failure are `UNAVAILABLE` or `INDETERMINATE`, never manufactured staleness.

## Consent and publication

Study inclusion does not authorize an individual public listing. A private draft may be prepared from public materials, but a named Authority Record becomes public only after:

1. a private invitation;
2. repository-control proof at an immutable commit;
3. owner correction opportunity;
4. explicit approval of the exact current record digest.

Withdrawal removes the public projection. Payment can purchase depth, monitoring, freshness history, and presentation. It cannot purchase a label or favorable conclusion.

The aggregate report will not publish unclaimed agent-level weakness details. Aggregate statistics must meet a minimum cell size of five.

## Outcomes

The preregistered outputs are counts and proportions for:

- observed consequential-action classes;
- evidence-status distribution;
- enforcement-status distribution;
- records with a pinned watched ref and resolvable immutable revision;
- records where a protected boundary is declared or observed;
- records whose required relationship cannot be established and is therefore `INDETERMINATE`.

No revenue, adoption, safety, compliance, or market-size conclusion follows from these observations.

## Amendments

Any change after this file's first committed digest must be appended with date, exact diff, reason, and whether scanning had begun. Results will identify the methodology commit and all amendments.
