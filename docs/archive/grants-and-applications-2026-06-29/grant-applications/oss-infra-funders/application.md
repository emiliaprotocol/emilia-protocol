# Open-Source-Infrastructure Funders — EMILIA Protocol

**Date:** 2026-06-12
**Author:** Iman Schrock, EMILIA Protocol Inc.
**Purpose:** Survey the major open-source-infrastructure funders, rank them
by realistic fit for EP at its current stage (a young, for-profit-backed
open AI-security standard with modest adoption — `@emilia-protocol/verify`
~210 downloads/week as of 2026-06-11), pick the best target, and provide a
paste-ready application for that target.

EP is open security infrastructure: an Apache-2.0 standard plus reference
implementation for **authorization receipts** — offline-verifiable proof
that a named human approved an exact irreversible AI-agent action before it
executed. The fundable surface for an OSS-infra funder is the *security
toolchain*: the three-language verifiers (JavaScript, Python, Go), the
conformance suite, the zero-dependency npm packages, the IETF Internet-Draft,
and the formal models.

---

## Funder comparison

| Funder | Open in June 2026? | Mechanism / award size | For-profit maintainer eligible? | Adoption bar (the gate for EP) | Realistic fit |
|---|---|---|---|---|---|
| **GitHub Secure Open Source Fund** | **Yes** — rolling, Session 4 open | Cohort: $10k/project via GitHub Sponsors + security education, dedicated GitHub Security Lab time, tool access (CodeQL, Copilot, AutoFix), $10k Azure credits. ~15 hrs over 3 weeks. | **Yes** — "individual maintainers or small teams"; only current GitHub employees excluded. | **Low / unquantified** — requires "demonstrated community traction and adoption" + clear license + governance, but does *not* publish a download/dependent threshold. Security-domain *not* required; security infrastructure qualifies. | **Best fit (#1)** |
| **FLOSS/fund** (Zerodha) | **Yes** — rolling, low-friction | Submit a `funding.json` in the repo; $10k–$100k per recipient; $1M/yr pool. | **Yes** — any entity worldwide (individual / group / org). | **None hard-coded** — "projects of all sizes, from small but essential libraries to large platforms." Judged on merit, not a numeric gate. | **Strong #2** |
| **Sovereign Tech Standards Network** (Germany / Sovereign Tech Agency) | **Closed** — pilot call ended 2026-05-19; notifications June 2026; cohort runs mid-June 2026 → June 2027 | Fellowship-style: €4,800–5,200/month for ~10 hrs/week of standards work; up to 10 maintainers. No geographic restriction. | Eligibility is *maintainer*-based, not entity-based; for-profit backing is not an explicit bar. | Must be an active maintainer whose project's work "relates to standards at IETF, W3C, or ISO." EP's IETF I-D is a **strong conceptual fit** — but the cohort is *closed* this cycle. | **Watch — reapply next cohall** |
| **Sovereign Tech Fund** (investment program) | Yes — continuous submissions | Investment in "open digital base technologies"; work described must exceed €50k. | Commercial maintainers can apply, but the program funds *the work*, not the company. | **High** — targets *critical* infrastructure: components that are dependencies of many user-facing applications, with demonstrated criticality. Will not fund work other public entities already fund. EP is **too young** to clear this bar honestly. | Stretch — not yet |
| **Open Technology Fund — FOSS Sustainability Fund** | **Closed** — concept-note deadline 2026-05-07 | Two-stage; sustainability grants for established internet-freedom FOSS. | Yes — for-profit or nonprofit. | **High + mission gate.** Requires: released ≥3 years, ≥4 updates/year, active coding in last 2 years, *substantial active user base*, ideally many dependents. **And** the mission must be *internet freedom*. EP fails the 3-year / user-base bar and the internet-freedom framing is a stretch (EP is agent/enterprise security, not censorship circumvention). | Poor fit |
| **Alpha-Omega** (Linux Foundation / OpenSSF) | No open call | Proactive: A-O identifies *critical* OSS and invites a SOW. >70 grants, >$20M to date; new $12.5M AI-OSS-security pool (2026). | Yes (project-based). | **Very high** — funds *critical* ecosystem dependencies (major registries, foundations, core libraries). No application path for a young project. | Not addressable now |
| **Mozilla MOSS / MIECO** | **No** — MOSS on indefinite hiatus; MIECO wound down | Historical: $5k–$150k (MOSS). Redirects to Mozilla Technology Fund. | (Historical) yes | (Historical) contribution to "health of the internet." | Dead program |
| **GitHub Sponsors** | Yes — always on | Recurring/one-time sponsorship; not a grant, no fixed award. | Yes | None — but it's a donation rail, not a reviewed grant. Useful as the *payout mechanism* for the GitHub fund and FLOSS/fund, not a target on its own. | Payout rail, not a target |

**Adjacent (not OSS-infra funders, noted for completeness):** NSF **PESOSE for
AI Agents** (Phase I up to $300k) and the **NIST CAISI AI Agent Standards
Initiative** (community-led open-source agent protocols, co-invested with NSF,
announced 2026-02-17) are the strongest *new* 2025–26 fits for EP's substance —
but they are federal research programs, already tracked under EP's NSF SBIR and
NIST engagement, not philanthropic OSS-infrastructure funds. They are the right
*destination* for the standard; this document is scoped to OSS-infra
maintainer funders.

---

## #1 pick and reasoning

**GitHub Secure Open Source Fund.** It is the only program that is (a) open
right now, (b) explicitly open to for-profit small teams, (c) does not impose
a quantified adoption threshold EP can't yet meet, and (d) is *about security
of open source* — which is precisely what EP's verifiers, conformance suite,
and formal models are. The award ($10k + security-education cohort + GitHub
Security Lab time + CodeQL/Copilot/AutoFix access) is well-matched to a
solo maintainer hardening a security-critical reference implementation. The
3-week, ~15-hour commitment is realistic for one person.

**Honest caveats that shape the application:**

- EP's adoption is early (~210 weekly npm downloads; pilot in outreach; no
  production customers). The application leans on *what is already built and
  verifiable* — three interoperable verifiers, an IETF I-D, formal proofs,
  85 red-team cases — rather than on usage numbers, and names the adoption
  stage plainly.
- EP is backed by a for-profit Delaware C-corp (EMILIA Protocol Inc). The
  fund permits this; the application states it and frames the *open core*
  (verifiers, conformance suite, standard, Apache-2.0) as the fundable
  public good, distinct from any future commercial product surfaces.
- The fund wants security *improvement work*, not feature work. The proposed
  milestones are all security hardening of the open toolchain (cross-language
  verifier audit, supply-chain hardening of the zero-dep packages, conformance
  expansion, fuzzing), which is genuine and a good use of the cohort.

**#2 fallback: FLOSS/fund** — submit a `funding.json` in parallel. Lowest
friction of any program, no adoption gate, $10k–$100k range, and it stacks
with the GitHub fund. Recommended to file both.

**Watch-list: Sovereign Tech Standards Network** — reapply when the next
cohort opens (the pilot runs through June 2027; a follow-on call is likely).
EP's IETF Internet-Draft is a near-ideal fit for a program that pays
maintainers to do standards work; the only reason it isn't #1 is timing.

---

## Application — GitHub Secure Open Source Fund (paste-ready)

> **Program:** GitHub Secure Open Source Fund
> **Info:** https://github.com/open-source/github-secure-open-source-fund
> **Announcement:** https://github.blog/news-insights/company-news/announcing-github-secure-open-source-fund/
> **Apply:** application form linked from the program page (rolling; one
> application is considered for all upcoming sessions)
> **Award:** $10,000 per project via GitHub Sponsors ($6k during the program,
> $2k at the 6-month check-in, $2k at the 12-month check-in), plus the
> security-education cohort, GitHub Security Lab time, tool access, and Azure
> credits.
> **Commitment:** ~15 hours over 3 weeks + two 2.5-hour check-ins.

### Project name

EMILIA Protocol — authorization-receipt verifiers and conformance suite

### Repository

https://github.com/emiliaprotocol/emilia-protocol

### License

Apache-2.0

### One-sentence description

An open standard and zero-dependency reference toolkit that produces an
**authorization receipt** — offline-verifiable proof that a named human
approved an exact irreversible AI-agent action before it executed — with
interoperable verifiers in JavaScript, Python, and Go and an adversarial
conformance suite.

### What the project is and why it is security-relevant

AI agents are moving from recommending actions to taking them: deploying code,
moving money, rotating credentials, calling tools with real-world effect. The
defensive gap is no longer "is the model accurate?" but "did this agent have
authorization to take *this specific irreversible action* on behalf of *this
specific principal* — and can a defender prove it afterward, offline, without
trusting the system whose conduct is in question?"

EP closes that gap with a small, formally specified artifact. A verified
authorization **receipt** proves — with mathematics, by anyone, with no call
back to any EP operator — that a specific enrolled key produced a
user-verified signature over the exact action (change the amount, beneficiary,
or target and the receipt no longer verifies), under a hash-pinned policy,
consumed at most once, in an append-only log. The **receipt** is the thing
that proves this; the runtime does not vouch. And the *absence* of a receipt
for a gated action is itself evidence of bypass — defenders get a positive
signal, not just a missing log line.

The fundable open surface is the verification toolchain that makes the
receipt *checkable by third parties*:

- **`@emilia-protocol/verify` 1.4.0** and **`@emilia-protocol/issue` 0.2.0** —
  zero-dependency npm packages (verify anywhere; issue locally).
- **Three independent reference verifiers** (JavaScript, Python, Go) proven to
  agree on the canonical adversarial conformance vectors on every push — the
  IETF bar of multiple interoperable implementations.
- **A conformance suite** plus **85 cataloged red-team cases**.
- **Formal verification:** 26 TLA+ safety properties and 22 Alloy assertions,
  0 counterexamples, re-run in CI.
- **IETF Internet-Draft** `draft-schrock-ep-authorization-receipts-01`
  (including PIP-007, an initiator-escalation attestation).
- An **MCP server** so any MCP-speaking agent can place EP as a pre-action
  guard without changing its tool definitions.

This is open security infrastructure: the value to the ecosystem is a
verifier any defender can run, independent of the operator under examination.

### Adoption and project stage (stated plainly)

EP is young. `@emilia-protocol/verify` is at ~210 downloads/week (week of
2026-06-11); a first pilot is in outreach; there are no production customers
yet. What exists today is the *standard and its verifiable implementation*:
the I-D, three interoperable verifiers, the conformance suite, the formal
models, and the zero-dependency packages — all public and reproducible. We
are applying to harden that public-good security toolchain at the stage where
hardening is cheapest and most durable, before adoption rather than after an
incident forces it.

### Backing and governance

EP is maintained by Iman Schrock and backed by EMILIA Protocol Inc, a
Delaware C-corp. The **protocol, the three verifiers, the conformance suite,
the formal models, and the npm packages are Apache-2.0 and will remain open**;
managed policy, orchestration, and sector packs are optional product surfaces
built on top, not part of the open core. Governance, contribution, and
security-disclosure processes are public (`GOVERNANCE.md`, `CONTRIBUTING.md`,
`SECURITY.md`, `CODE_OF_CONDUCT.md`, DCO sign-off). This application concerns
only the open security toolchain.

### Security work we would do in the cohort

All milestones are security hardening of the open toolchain — not features:

1. **Cross-language verifier hardening.** Differential and property-based
   testing across the JavaScript, Python, and Go verifiers to prove byte-exact
   agreement on canonicalization, signature verification, and rejection paths;
   eliminate any divergence a forged receipt could exploit. (CodeQL + AutoFix
   applied across all three.)
2. **Supply-chain hardening of the zero-dependency packages.** Pinned
   provenance and SBOM verification for `@emilia-protocol/verify` and
   `@emilia-protocol/issue`, signed releases, and a reproducible-build check —
   so a verifier a defender installs is exactly the audited source.
3. **Conformance-suite and red-team expansion.** Extend the conformance
   vectors and the 85-case red-team catalog to cover the full PIP-007
   escalation-attestation path and the WebAuthn challenge-binding edge cases,
   and publish them so any third party can validate independently.
4. **Fuzzing the parse/verify boundary.** Structured fuzzing of receipt
   parsing and signature verification across all three languages to surface
   memory-safety and malformed-input issues before adoption.

We would use the GitHub Security Lab time and CodeQL/AutoFix tooling directly
against the verifiers, and the Azure credits to run the cross-language
differential and fuzzing harnesses in CI.

### What an honest receipt does and does not prove

So the reviewer can calibrate: a receipt proves a named human approved this
exact action under the stated policy, consumed once, verifiable offline. It
does **not** prove the decision was wise, that the policy was adequate, that
the approver was not coerced or colluding, or that the signing surface
rendered the action faithfully — those are policy, presentation, and human
factors outside the signature's reach. EP's credibility depends on never
claiming more than the cryptography delivers; the full claims-and-non-claims
statement is at `docs/RECEIPT-CLAIMS.md`.

### Maintainer

**Iman Schrock**, founder and sole maintainer (ORCID 0009-0004-0290-5433).
Authored the protocol stack: the IETF Internet-Draft
(`draft-schrock-ep-authorization-receipts-01`), 26 TLA+ properties and 22
Alloy assertions (0 counterexamples, re-run in CI), the 85-case red-team
suite, the three-language verifiers, and the npm toolkit. Apache-2.0 history
is public at github.com/emiliaprotocol/emilia-protocol.

### Public artifacts

- Repository: https://github.com/emiliaprotocol/emilia-protocol
- IETF Internet-Draft: `draft-schrock-ep-authorization-receipts-01`
- npm: `@emilia-protocol/verify` 1.4.0, `@emilia-protocol/issue` 0.2.0
- Verify a receipt in your browser: https://www.emiliaprotocol.ai/verify
- Conformance: `CONFORMANCE.md`, `conformance/`
- Formal proofs: `formal/PROOF_STATUS.md`
- Receipt claims and non-claims: `docs/RECEIPT-CLAIMS.md`
- Essays: https://www.emiliaprotocol.ai/essays
  (start with "The Model Is the Crumple Zone")

---

## Submission notes

- **File the GitHub fund application now** (rolling; one submission covers all
  upcoming sessions). Lead with the verifiers/conformance/formal proofs;
  state the adoption stage and for-profit backing plainly, as above.
- **In parallel, add a `funding.json` to the repo root** and register with
  **FLOSS/fund** — lowest-friction program, no adoption gate, stacks with the
  GitHub fund.
- **Add Sovereign Tech Standards Network to the watch-list** and reapply when
  the next cohort opens; EP's IETF I-D is a near-ideal fit there.
- Do **not** pursue OTF (closed + 3-year/user-base/internet-freedom gate),
  Sovereign Tech Fund (critical-dependency bar EP can't yet clear), or
  Alpha-Omega (no open call) this cycle — revisit once EP has demonstrated
  dependents and a year-plus of release history.
