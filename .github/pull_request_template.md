## Summary

<!-- What changed, why it changed, and the user or protocol outcome. -->

## Scope

<!-- Link related issues/spec proposals and name the components affected. Call out intentionally excluded follow-up work. -->

Closes #

## Risk and security impact

<!--
Describe affected trust boundaries and failure modes. Consider identity, delegated scope,
machine policy, human authorization, replay, tenant isolation, secrets, privacy, execution,
and reliance. If none apply, explain why.
-->

- Security impact:
- Failure/refusal behavior:
- Compatibility impact:

## Verification

<!-- List exact commands and results. Do not write "tests pass" without naming what ran. -->

| Check | Command or evidence | Result |
| --- | --- | --- |
| Narrow tests |  |  |
| Negative/refusal tests |  |  |
| Applicable repository gates |  |  |

<!-- Explain skipped, unavailable, flaky, or environment-dependent checks. -->

Not run / limitations:

## Database and migrations

<!--
Do not equate a committed or merged migration with deployment. State the exact environment
and observed schema truth. Include ordering, backfill, locking, idempotency, rollback or
forward-fix strategy, and application compatibility when applicable.
-->

- [ ] No database or schema change.
- [ ] Migration files are included and have been tested from a clean schema.
- [ ] Existing-data/backfill behavior has been tested.
- [ ] Production deployment is required after merge.
- [ ] Production deployment has been completed and independently verified.

Migration files:

Applied environments and current status:

Deployment/rollback notes:

## Claims and evidence

<!--
For capability, quantitative, security, conformance, standards-status, adoption, or
interoperability claims, identify the current source of truth and preserve assumptions,
exclusions, and time pins. Keep implementation, local tests, CI, deployed production,
and independent/external validation as separate states.
-->

- [ ] This PR makes no public or generated claim changes.
- [ ] Claim-bearing changes are backed by current executable or primary-source evidence.
- [ ] Generated claim surfaces were regenerated from their authoritative source rather than edited directly.
- [ ] Assumptions, exclusions, limitations, and time-pinned results remain explicit.
- [ ] Standards language distinguishes an individual submission, working-group adoption, and RFC status.

Claim-bearing files and supporting evidence:

## Secrets and sensitive data

- [ ] I reviewed the diff and test output for credentials, tokens, API keys, private keys, connection strings, personal data, and confidential production or partner information.
- [ ] Examples, fixtures, screenshots, and logs use synthetic or properly sanitized data.
- [ ] This PR does not publicly disclose an uncoordinated vulnerability.

## Contribution checklist

- [ ] Every commit includes a DCO `Signed-off-by` line (`git commit -s`); I understand CI checks every commit.
- [ ] The change is scoped to the stated purpose and does not hide unrelated generated or mechanical changes.
- [ ] New behavior includes applicable positive and negative/refusal coverage.
- [ ] Documentation, conformance vectors, security-case evidence, and generated context are updated when their source behavior changed.
- [ ] I reviewed the complete diff as a reviewer would.
