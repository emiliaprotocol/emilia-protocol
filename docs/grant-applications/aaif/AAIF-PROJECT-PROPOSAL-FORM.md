<!-- SPDX-License-Identifier: Apache-2.0 -->

# AAIF — TC Review & Sponsor package (DO NOT file the hosting proposal yet)

This is the field-by-field content for AAIF's `project-proposal.yml` form — but treat it as a
**review & sponsor package, not a filing.** **Do not open the formal proposal issue yet:** its
required Field 21 checkbox commits you to **donating the EMILIA trademark and all project accounts
to AAIF on acceptance.** That is a deliberate, counsel-reviewed, much-later decision — not a box
you tick to get feedback. The standardization win you actually want comes from the **IETF**
(which takes the *spec*, not your *brand*). Use AAIF for **review + a sponsor first.**

## ▶ How to get TC review + a sponsor (without filing / donating)

1. **Join the AAIF Discord** — `discord.gg/9zTwngHAMy`. The real front door and where sponsors
   are. Post a short intro; find the TC/governance channel; note the TC meeting cadence.
2. **Read the rules** (15 min): `governance/project-lifecycle-policy.md` in `aaif/project-proposals`
   + the guide at `aaif.io/blog/how-to-submit-your-project-to-the-aaif/`. Confirm the stages and
   **when the trademark/account donation actually binds** — it's a signed contribution agreement
   after a TC vote (>50%) + Governing-Board approval, **not** at issue-filing.
3. **You already emailed `support@aaif.io` (Jun 13) — don't bump yet.** If no reply by ~Jun 20,
   send a short follow-up asking for (a) early/informal TC feedback or an office-hours slot,
   (b) a **sponsor introduction**, (c) confirmation of when donation binds — saying plainly you
   want guidance + a sponsor **before** filing a formal proposal. (Ask me to stage that draft.)
4. **Ask for a sponsor explicitly** in Discord — a TC member in security / agent-infrastructure
   who'll mentor EP to readiness. The sponsor is the unlock; the formal vote comes later.
5. **Offer to present** — volunteer a 10-min demo at a community/TC call
   (`npx @emilia-protocol/issue demo`, 60 sec, offline-verifiable). Review + visibility, zero donation.
6. **File the formal proposal ONLY when** you have a sponsor, you've decided neutral stewardship is
   the strategy, and IP counsel has reviewed AAIF's contribution agreement. Until then, the fields
   below are review material — not a filing.

## When you DO eventually file — open items
- **Field 21** (trademark/account donation): a deliberate strategy decision + counsel. **Not now.**
- **Field 14**: drop in your exact GitHub handle (placeholder `@<YOUR-GITHUB-HANDLE>` below).
- **Posture**: Fields 5 & 14 honestly state two bars EP doesn't meet yet (production in 2 orgs;
  2 maintainers + 10 contributors) — expect a "defer pending milestones," the healthy outcome of an early ask.

**Numbers (verified):** 26 TLA+ (413,137 states / 45,342 distinct, 0 errors) · 22 Alloy assertions
(15 core + 7 federation) + 35 facts · **85** red-team cases · **3,200+** tests · EIN omitted (public DE file no. only).

---

## 1. Project Name
EMILIA Protocol — Authorization Receipts for High-Risk Agent Actions

## 2. Project Description
EMILIA Protocol is an open standard and Apache-2.0 reference implementation for **authorization receipt infrastructure**: cryptographic, offline-verifiable proof that a named human approved an exact, irreversible action before it executed. As AI agents move from recommendation to execution — moving money, changing vendor bank details, deploying code, altering records — the unanswered question is not "may this action happen?" (decision-time authorization) but "who can prove what was authorized, by whom, under which policy, before it ran?" A decision log is testimony controlled by the operator; an **authorization receipt is evidence** — a named human's user-verification-gated signature over the exact action hash, recorded before execution and verifiable later without trusting EMILIA, the operator, or any database.

The protocol spans five layers: **Eye** observes risk (scope-bound, tighten-only advisories), **Guard** enforces before the write (allow / allow_with_signoff / deny), **Signoff** binds a named human (device-bound WebAuthn), **Commit** seals the action (one-time-consumed, Merkle-anchored), and the **Authorization Receipt** (EP-RECEIPT-v1) lets anyone verify the proof offline. Origin: posted as IETF Internet-Draft `draft-schrock-ep-authorization-receipts` (June 2026); converged independently with parallel efforts (PSEA, DRP), now jointly surveyed to the IETF secdispatch chairs.

## 3. Alignment with AAIF Mission
EMILIA fills the accountability gap directly beneath agent autonomy: when an agent takes a consequential action, no open, interoperable, offline-verifiable artifact today proves the action was authorized. EMILIA proposes that artifact as vendor-neutral infrastructure — Apache-2.0, specified at the IETF, formally verified, and explicitly designed so **no single vendor owns the evidence** that later proves whether an AI-agent action was authorized. The thesis is "portable evidence, not another score": EMILIA does not rank or rate agents; it produces checkable proof. That is precisely the kind of shared, neutral substrate a foundation exists to steward. *(We'd welcome the Committee's steer on aligning wording to AAIF's current mission statement.)*

## 4. Relation to Existing AAIF Projects
EMILIA is **complementary and composable**, not overlapping: it *consumes* (never redefines) policy-decision systems (OpenID AuthZEN, OPA, Cedar); it composes over identity/approval rails (OAuth/CIBA) as the durable evidence object they can ask a human to sign; it is a **sibling profile** to delegation-receipt work (DRP / `draft-nelson-agent-delegation-receipts` — DRP covers upstream user→operator delegation, EP covers downstream authorization of an exact action; the two compose) and to PSEA (dedicated-hardware tier; EP profiles the commodity-WebAuthn tier); and it anchors receipts into transparency logs via **SCITT** rather than defining its own. If AAIF hosts agent-identity, policy, or messaging projects, EMILIA is the after-the-fact evidence layer their logs do not themselves provide. We request the Committee's guidance on the cleanest mapping.

## 5. Example Use Cases and Evidence of Adoption  🟥 (required bar not yet met — stated honestly)
**Up front: EMILIA does not yet meet the "production deployment in two organizations" bar, and we are not claiming it does.** It is pre-production reference infrastructure; this submission doubles as a request for Technical Committee guidance and help reaching that milestone.

**Use cases (packaged, observe-mode ready):** GovGuard — public-sector disbursements, vendor bank-account changes, benefit-routing changes, caseworker overrides (60-day observe-mode pilot: receipts recorded without blocking production); FinGuard/AML — financial prechecks that fail closed on sanctions/embargo and escalate structuring/velocity to signoff; OpenAI-Guard and agent-framework adapters — gate irreversible tool calls; `require-receipt` — demand-side middleware so a service refuses an irreversible action unless a valid receipt is presented ("No receipt, no irreversible action").

**Adoption evidence to date (pre-production):** reference verifiers published on npm (`@emilia-protocol/verify`), in-browser and hosted read-only; a Class-A device-bound signoff exercised end-to-end on real hardware; a live two-operator federation cross-verification (PIP-006) — though **both operators are currently EMILIA-operated, so an independent operator remains an open milestone.** The active wedge is converting one GovGuard observe-mode pilot to enforce mode on one real workflow.

## 6. Technical Committee Sponsor (if identified)
Not yet identified; requesting Technical Committee guidance and a sponsor conversation.

## 7. GitHub Repository URL
https://github.com/emiliaprotocol/emilia-protocol

## 8. License
Apache-2.0

## 9. Governance Model
Open governance via a documented **Protocol Improvement Proposal (PIP)** process (PIP-000 establishes it; PIP-001 froze EP Core v1.0; PIPs 002–007 cover handshake/guard, signoff, commit, Eye, federation, initiator-attestation). A ratified Constitution (`docs/EP-CONSTITUTION-v5.md`) defines the frozen Core Objects and the change process: a Core change requires a PIP, a 90-day review, consensus, a major version bump, and a 24-month deprecation window. `GOVERNANCE.md` states the intent to transition to neutral stewardship under a foundation such as AAIF on acceptance. Single-organization today; the conformance suite is designed for multi-implementer governance.

## 10. CI/CD & Release Workflow
GitHub Actions (13 workflows). Every push runs: 4,220 automated tests (vitest); the formal models — **26 TLA+ safety properties** (TLC 2.19; 413,137 states / 45,342 distinct; 0 errors) and **22 Alloy assertions** (15 core `ep_relations` + 7 `ep_federation`) with 35 facts (0 counterexamples) on `formal/` changes; a **cross-language conformance suite** running shared vectors through three independent verifiers (JavaScript, Python, Go); plus language-governance, license-header, docs-secret, and protocol-discipline gates. Releases: npm packages via tag-triggered workflows, PyPI Trusted Publishing (OIDC) for Python; daily commit cadence; Internet-Drafts built with xml2rfc from `standards/`.

## 11. Public-Facing Contribution Process for Specifications
Specification evolution runs through the public PIP process in-repo (`PIPs/`, opened/discussed as GitHub issues & PRs) and, for the wire standard, through the **IETF**: `draft-schrock-ep-authorization-receipts` on the datatracker, discussion on the `secdispatch` mailing list. A public conformance suite (`conformance/`) defines "how to claim conformance." `CONTRIBUTING.md` + the PIP template govern proposals.

## 12. Publicly Accessible Issue Tracker
https://github.com/emiliaprotocol/emilia-protocol/issues

## 13. External Project Dependencies
All OSI-permissive (MIT / Apache-2.0 / BSD). Web/app: Next.js, React (MIT). WebAuthn: `@simplewebauthn/*` (MIT). SSO/crypto: `jose`, `@node-saml/node-saml` + `xml-crypto` (MIT). CBOR/COSE: `cbor-x` (MIT). Base-L2 anchoring: `viem` (MIT). Data: `@supabase/supabase-js` (Apache-2.0). Ops: `@sentry/nextjs`, `stripe`, `mcp-handler` (MIT). The reference verifier/issuer packages (`@emilia-protocol/verify`, `@emilia-protocol/issue`) ship **zero runtime dependencies**. Full SBOM available on request.

## 14. Maintainers & Contributors  🟥 (required bar not yet met — stated honestly)
**EMILIA does not yet meet the "2+ maintainers from different organizations and 10+ contributors" bar.** Today it is single-organization with one protocol author/maintainer — Iman Schrock (EMILIA Protocol, Inc.; GitHub org `emiliaprotocol`, handle `@<YOUR-GITHUB-HANDLE>`). Recruiting 2–3 external conformance-suite maintainers from different organizations is a named next step, and the conformance suite is built to support multi-implementer governance. We are submitting early and honestly, with this gap stated, rather than padding a contributor list.

## 15. Leadership Team & Decision Process
Leadership: Iman Schrock, Protocol Author & CEO, EMILIA Protocol, Inc. Protocol-core decisions follow the PIP process and Constitution (Core changes require PIP + 90-day review + consensus + major version bump + 24-month deprecation); reference-implementation decisions are made in the open via GitHub PRs. On acceptance, decision authority for the standard would transition to a foundation-governed Technical Committee per `GOVERNANCE.md`.

## 16. Roadmap
**Q3 2026** — secdispatch outcome for `draft-schrock-ep-authorization-receipts`; first government observe-mode pilot live; one public `require-receipt` integration; first external party issuing receipts with their own keys. **Q4 2026** — first independently operated PIP-006 node; enforcement-point and Eye conformance vectors; 2+ external conformance maintainers; pilot conversion observe→enforce. **Q1–Q2 2027** — multi-organization maintainership; EP Core stability review under foundation governance; second regulated pilot; independent security audit; IETF WG-forming conversation if dispatch supports it.

## 17. Security
No OpenSSF Best Practices badge yet (named next step). Current posture: 26 TLA+ machine-checked safety properties + 22 Alloy assertions in CI; **85 catalogued red-team cases** (`docs/conformance/RED_TEAM_CASES.md`); fail-closed verifier design; offline verification removes the operator from the trust path; secret-scan / license-header / docs-secret CI gates; AES-256-GCM for sensitive config at rest; `search_path`-pinned `SECURITY DEFINER` functions with RLS. **Independent third-party crypto/security audit is a named, not-yet-completed milestone.** Reporting via `SECURITY.md`.

## 18. Website URL
https://emiliaprotocol.ai

## 19. Documented Governance Practices (if any)
`GOVERNANCE.md`, `docs/EP-CONSTITUTION-v5.md`, and the `PIPs/` directory (PIP-000 process + PIP-001 Core freeze + accepted PIPs 002–007).

## 20. Links to Social Media Accounts
None currently active. Primary public presence: `github.com/emiliaprotocol/emilia-protocol` and `emiliaprotocol.ai/essays`.

## 21. Trademark and accounts (REQUIRED checkbox)  🟥 YOUR DECISION
The box reads: *"If the project is accepted, I agree to donate all project trademarks and accounts to the AAIF."* This is a binding commitment to hand the **EMILIA name, marks, and accounts** to the foundation on acceptance. Decide deliberately — the form will not submit unless it's checked.

## 22. Details of Existing Financial Sponsorship
None. EMILIA Protocol, Inc. is self-funded and pre-revenue; several open-source / AI-safety grant applications are pending, but no sponsorship is in place.

## 23. Infrastructure Needs or Requests
The highest-value help is not infrastructure but: (1) an **independent operator/relying party** to run the PIP-006 federation surfaces or verify externally issued receipts; (2) one **demand-side `require-receipt` integration** in a member's agent tool / MCP server / API; (3) **connections to regulated pilot contexts** for observe-mode deployment. Hosting for a neutral conformance test runner would also help.

## 24. Additional Information
What EMILIA brings to evaluate is concrete, not a white paper: a **60-second hands-on check** — `npx @emilia-protocol/issue demo` issues a receipt locally and verifies it offline with the published verifier, no account or backend. Recommended review path: `docs/RECEIPT-CLAIMS.md` (exact proof claims **and non-claims**), the I-D, `standards/draft-schrock-ep-enforcement-point-00.md` and `standards/draft-schrock-emilia-eye-00.md` (Guard and Eye profiles), `formal/PROOF_STATUS.md`, `docs/positioning/DIFFERENTIATION.md`. We would rather be early and honest than padded: the maintainership and production-adoption criteria are not yet met, and this submission is partly a request for the guidance and sponsor conversation that get us there.

## 25. Application contact name(s) and email(s)
Iman Schrock — team@emiliaprotocol.ai

## 26. Contributing or sponsoring entity signatory information
EMILIA Protocol, Inc., a Delaware C-corporation (Delaware file no. 10647704). Authorized signatory: Iman Schrock, Founder & CEO — team@emiliaprotocol.ai. Registered-agent address available on request. (EIN intentionally omitted from a public form.)
