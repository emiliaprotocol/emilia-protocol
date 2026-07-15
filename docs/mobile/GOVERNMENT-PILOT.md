# Government Mobile Pilot Acceptance Plan

This plan is vendor- and jurisdiction-neutral. It does not claim an existing
government deployment.

## Phase 1: shadow evidence

- Select one reversible but consequential workflow.
- Resolve actions from the existing system of record.
- Run the mobile ceremony without changing the existing authorization path.
- Compare every EP decision with the production decision and investigate every
  mismatch.

Exit: no unexplained action, display, identity, or policy mismatches across the
agreed sample.

## Phase 2: enforced narrow path

- Put one action family behind the system-of-record gate.
- Require durable challenge consumption and evidence logging.
- Exercise replay, concurrency, storage outage, attestation outage, revoked
  enrollment, counter rollback, app downgrade, and clock-regression drills.
- Confirm the executor cannot be called through an unmediated route.

Exit: every hostile drill refuses for the expected closed reason, and operators
can recover without deleting or rewriting evidence.

## Phase 3: independent review

- Give the profile, vectors, schemas, and captured evidence to an independent
  security reviewer.
- Re-run the shared Swift, Kotlin, and server conformance gate.
- Verify accessibility, records-retention, privacy, incident-response, and
  mobile-device-management requirements under the agency's own controls.

Exit: signed acceptance record naming scope, residual risks, owners, and rollback
conditions.

## Success metrics

- protected actions missing a consumed ceremony: zero;
- successful duplicate or concurrent consumption: zero;
- challenge-to-decision latency and abandonment by accessibility cohort;
- false-refusal rate by platform and OS version;
- mean time to revoke an enrollment; and
- percentage of audit samples independently reproducible from exported evidence.
