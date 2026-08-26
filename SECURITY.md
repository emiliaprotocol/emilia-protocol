# Security

## Supported Versions

Security patches apply to the current protected `main` source, the latest
published version of every package registered in
[`release/release-packages.v1.json`](release/release-packages.v1.json), and the
current hosted service. Older source and package releases are not backported
unless a security advisory explicitly says otherwise. A source commit, protocol
artifact, registry package, and deployed revision are separate release
identities; see [`RELEASE-PROCESS.md`](RELEASE-PROCESS.md).

| Component | Supported |
|---|---|
| Protected repository source | Current `main` |
| Versioned protocol artifacts | Current released version of each named artifact |
| Registered npm, PyPI, and Go packages | Latest published version of each registered package |
| Hosted service (`emiliaprotocol.ai`) | Current production deployment |
| Older or prerelease versions | No, unless named by an advisory |

## Reporting Vulnerabilities

Email **team@emiliaprotocol.ai** with:

- A description of the vulnerability
- Steps to reproduce
- Expected vs actual behavior
- Impact assessment (if known)

We will acknowledge within **48 hours** and provide an initial assessment within **7 days**.

**Do not open public GitHub issues for security vulnerabilities.**

## Responsible Disclosure Process

1. **Report** the vulnerability via the email above.
2. **Acknowledgement** within 48 hours with a tracking reference.
3. **Assessment** within 7 days — we will confirm the severity and estimated fix timeline.
4. **Fix development** — a patch is developed privately and tested against the conformance suite.
5. **Coordinated disclosure** — once the fix is released, we will credit the reporter (unless anonymity is requested) and publish a security advisory.
6. **90-day disclosure window** — if we have not addressed the issue within 90 days, the reporter may disclose publicly.

We follow the principle of coordinated disclosure. Please do not disclose vulnerabilities publicly before a fix is available.

## Scope

In scope:

- **The protocol.** Flaws in a current versioned artifact that allow authority,
  exact-action binding, verification, replay, admission, or evidence guarantees
  to be bypassed under the artifact's stated scope.
- **The packages.** Every public npm, PyPI, and Go package registered in
  `release/release-packages.v1.json`, plus the MCP server and published SDKs.
- **The site and hosted service.** `emiliaprotocol.ai` and its APIs — authentication, authorization, rate limiting, write-discipline bypass, data exposure.

Out of scope (report only if you can show concrete impact): findings against third-party dependencies without an EP-specific exploit path, volumetric DoS, social-engineering of staff, and reports generated solely by automated scanners with no demonstrated impact.

## Safe Harbor

We will not pursue or support legal action against researchers who, in good faith:

- Make a sincere effort to avoid privacy violations, data destruction, and service degradation.
- Access only the minimum data necessary to demonstrate a vulnerability, and do not exfiltrate, retain, or share it.
- Report promptly and privately via the contact below, and give us a reasonable window to remediate before public disclosure.
- Do not exploit a finding beyond what is needed to prove it (no pivoting, no lateral movement, no persistence).

Activity conducted consistently with this policy is considered authorized, and we will work with you rather than against you. If legal action is initiated by a third party against you for activity that complied with this policy, we will make this authorization known. This safe harbor does not extend to actions that violate applicable law or harm third parties.

## Security Contact

- **Email:** team@emiliaprotocol.ai
- **PGP:** Available on request for encrypted communications.
- **Response SLA:** 48-hour acknowledgement, 7-day initial assessment.

## Acknowledgments

We thank the security researchers who have responsibly disclosed vulnerabilities and helped harden EMILIA Protocol:

- **Tom Gaillard** — signoff authorization bypass (consume-time authority binding) and cross-tenant receipt read (IDOR); responsibly disclosed June 2026, remediated and re-tested by the reporter against production.

## Current Security Evidence

EMILIA's current security model is mandate-first and executor-bound. Verification,
material-action matching, evidence satisfaction, local authorization, provider
admission, and observed execution are distinct conclusions. Prevention claims
apply only to declared action paths under complete mediation and shared durable
authority state. Provider response loss becomes `INDETERMINATE`; it does not
reopen consumed authority for blind replay.

Current claim status is generated rather than copied into this file:

- [`security/security-case.json`](security/security-case.json) records named
  executable claims, assumptions, exclusions, evidence hashes, and execution
  status.
- [`lib/proof-stats.json`](lib/proof-stats.json) records current test and formal
  evidence counts.
- [`conformance/conformance-manifest.json`](conformance/conformance-manifest.json)
  records the current suites, vectors, and same-team implementation relationship.
- [`DUE_DILIGENCE.md`](DUE_DILIGENCE.md) binds reviewed claims to an exact source
  revision, CI run, production-schema run, and live-control snapshot.

Passing repository evidence is not an accredited audit, production-adoption
claim, proof that every mutation path is mediated, or proof of physical outcome.

## Assessment History and Current Posture

- A historical automated and adversarial assessment used the Shannon AI
  Penetration Testing Framework on 2026-03-23. Its maintainer-authored summary
  reports 31 findings source-remediated at that snapshot. It is not represented
  as independent penetration testing.
- Strix later reported an independent recheck of the original findings against
  its tested deployment and `Fixed` for each of the 24 targeted STRIX-25 through
  STRIX-48 retests. Those 24 findings have separate source-fix, production
  deployment/schema, and external-retest evidence. The Strix retests did not
  access the live production database, and an original path lacking its own
  later recheck retains the status recorded in the register.
- The branch-protection and alert snapshot is recorded in
  [`DUE_DILIGENCE.md`](DUE_DILIGENCE.md); the number of required status contexts
  is not treated as a count of distinct security controls.
- The historical security checklist is maintained at
  [`docs/conformance/SECURITY_CHECKLIST.md`](docs/conformance/SECURITY_CHECKLIST.md).

### Threat model and adversarial testing

- **Canonical threat model** — [`THREAT_MODEL.md`](THREAT_MODEL.md).
- **Strix remediation and retest register** —
  [`docs/security/STRIX_REMEDIATION_2026-07-18.md`](docs/security/STRIX_REMEDIATION_2026-07-18.md).
- **Red-team case catalog** — `docs/conformance/RED_TEAM_CASES.md` (86 cataloged adversarial cases; use the generated proof summary for the current count).
- **Protocol-level security considerations** —
  [Authorization Receipts revision -12, Section 13](https://datatracker.ietf.org/doc/html/draft-schrock-ep-authorization-receipts-12#section-13)
  (operator compromise, presentation attacks, log equivocation, directory
  authority, separation-of-duties limits, and approver fatigue).
- **What a receipt proves and does not prove** — `docs/RECEIPT-CLAIMS.md`.

## Conformance

Compatibility claims must name the exact protocol or profile version and pass
the applicable suites and vectors in
[`conformance/conformance-manifest.json`](conformance/conformance-manifest.json).
Agreement among the JavaScript, Python, and Go reference ports is same-team
cross-language consistency, not independent implementation evidence.
