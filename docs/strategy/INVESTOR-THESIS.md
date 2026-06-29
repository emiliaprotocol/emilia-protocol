<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA Protocol — Investor Thesis (one page)

**Category:** Accountability infrastructure for the agentic economy — the authorization & audit rail for *irreversible* AI-agent actions.

---

### The one line
OAuth answered *"who are you."* **EMILIA answers *"who approved this."*** As AI agents cross from answering to **acting** — moving money, changing vendor bank details, deploying code, altering government records — no one can prove, after the fact, that a named human authorized the exact irreversible action before it ran. A log is testimony the operator controls. **EMILIA is the evidence:** a cryptographic, offline-verifiable receipt that a specific human approved an exact action, *before* it executed — checkable by anyone, forever, without trusting the system whose conduct is in question.

### Why now
- **Agents are starting to act.** Visa/OpenAI agentic commerce, autonomous code deploys, agent-initiated payments. The unanswered half of every agentic story is *authorization*.
- **Regulation shipped the requirement but not the primitive.** EU AI Act Art. 14 (human oversight), NIST AI RMF, Five Eyes guidance all mandate human oversight of high-risk AI — and none of them ships a verifiable way to *prove* it happened. EMILIA is that missing primitive.
- **Defense wants it now.** DIU is actively soliciting human-on-the-loop + auditable governance for autonomous systems; EMILIA submitted to **DIU Project Spectrum Strike** (Round 1, June 2026). This is the American-Dynamism thesis as a single product.

### Why it's a monopoly-shaped bet
Trust infrastructure standardizes **once** and the winner owns the category — the SSL / Stripe / Plaid pattern. Whoever owns the **open protocol + the reference implementation + the conformance suite** becomes the default rail, then monetizes the managed layer (GovGuard / FinGuard, enterprise compliance, air-gapped/defense deployments). EMILIA is *deliberately* running the standards play — an **IETF Internet-Draft** and a **three-author, cross-vendor coalition** — so the protocol is un-ownable by any single competitor, and the company is the best-positioned operator of it. Open protocol = distribution; managed product = revenue.

### What's real today (stated without inflation)
- Published **IETF Internet-Draft** (`draft-schrock-ep-authorization-receipts`) + a 3-author cross-draft survey now before the IETF secdispatch chairs.
- **Formally verified** core — 26 TLA+ safety properties (0 errors across 413,137 states) and 22 Alloy assertions (0 counterexamples), re-checked on every commit.
- **Working software:** offline verifiers in JavaScript, Python, and Go (on npm); a live in-browser verifier; an MCP server for native agent integration; device-bound (Face ID / passkey) human signoff exercised **end-to-end on real hardware**.
- **Apache-2.0**, open governance, NIST AI RMF + EU AI Act compliance mappings, an air-gap/offline deployment path for classified enclaves.
- **DIU Project Spectrum Strike** Round-1 entry submitted.

### Honest stage
**Pre-revenue, no customers yet, solo founder.** The next milestone is a **60-day government observe-mode pilot** — the first place a missing approval is a *statutory* problem, not just a bad day. This is a pre-seed/seed bet on a **category-defining primitive + an open-standard moat + a regulatory tailwind**, not on current traction. The traction risk is real and named; the mitigation is that every claim above is independently verifiable in minutes.

### Use of capital
Land the first 2–3 government/finance pilots · convert observe-mode to enforce-mode on one real workflow · ship the demand-side `require-receipt` distribution loop · push the IETF work toward charter · first 2–3 engineering hires.

---

**Founder:** Iman Schrock — Founder/PI, IETF I-D author (ORCID 0009-0004-0290-5433). Non-traditional; builds in the open.
**Links:** emiliaprotocol.ai · github.com/emiliaprotocol/emilia-protocol · team@emiliaprotocol.ai
**60-second proof:** `npx @emilia-protocol/issue demo` issues a receipt locally and verifies it offline — no account, no backend.
