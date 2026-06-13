# DoD SBIR / STTR + AFWERX — EMILIA Protocol Application Package

> **Status (as of 2026-06-12): WATCH with two LIVE "fire now" candidates at DIU.**
> The DoD SBIR/STTR FY26 Release 2 BAA is OPEN (rolling monthly close
> dates) and AFWERX/SpaceWERX have reopened post-reauthorization, but no
> *current* SBIR open topic names AI assurance / human-oversight-of-agents
> — so the standing SBIR play is a reusable abstract held until a fitting
> topic posts. Meanwhile **two DIU Commercial Solutions Openings**
> (Spectrum Strike, Hydra) are a direct EP fit and close in **weeks**.
> Read §1 (landscape), §2 (the reusable abstract — paste-ready), §3
> (per-vehicle fit table), §4 (the two live DIU shots), §5 (submission /
> watch instructions). Companion live-search file: `WATCH.md`.

This is the **DoD-SBIR / AFWERX / DIU** angle. It deliberately does **not**
duplicate the DARPA BAA package in `../darpa-safe-ai/` (CLARA / I2O / DICE,
$0.5M–$5M white-paper track). DoD SBIR/AFWERX is the **dual-use,
fixed-topic, small-dollar, fast-cycle** path; DIU CSOs are the
**operational, customer-pulled** path. EP is the same protocol; the framing
here is procurement-vehicle-specific.

---

## §0 — EP facts grounding this package (honest, current)

- **What EP is:** an open (Apache-2.0) standard + reference implementation
  for **authorization receipts** — cryptographic, offline-verifiable proof
  that a *named* human approved an *exact*, **irreversible** AI-agent action
  *before* it executed (WebAuthn device-bound signoff; hash-pinned policy;
  append-only Merkle-anchored logs).
- **Standards:** IETF Internet-Draft `draft-schrock-ep-authorization-receipts`
  at **-01**, including **PIP-007** (the agent's own signed escalation
  decision — directly a human-machine-teaming accountability primitive).
- **Code:** npm `@emilia-protocol/verify` 1.4.0 + `issue` 0.2.0; independent
  **JS, Python, and Go** verifiers + a conformance suite.
- **Assurance:** **26 TLA+** safety properties machine-checked across
  413,137 states; **22 Alloy** assertions (15 in `ep_relations.als` +
  7 federation assertions in `ep_federation.als`) with 0 counterexamples;
  re-run in CI. **85 red-team** cases.
- **Disconnected ops:** an **air-gap installer** exists (`deploy/airgap/`:
  `bundle.sh`, `install.sh`, `verify-offline.sh`, `audit.sh`,
  `docker-compose.airgap.yml`) — EP issues and verifies with **no network**,
  forever, given only the approver's public key and a published checkpoint.
- **Applicant:** EMILIA Protocol Inc — for-profit US small business,
  Delaware C-corp. Founder/PI **Iman Schrock** (solo), ORCID
  0009-0004-0290-5433. **No customers yet** (pre-revenue; pilots offered,
  none signed).
- **TRL:** ~6 (system/subsystem demonstrated in a relevant environment) for
  the receipt/verify core; the multi-agent compositional path is the R&D.

> Honesty guardrails for this file (enforced by
> `scripts/check-language-governance.js` + project style): say
> **"irreversible,"** not "consequential"; **"the receipt proves"** a named
> human approved this *exact* action *before* execution — it does **not**
> prove the decision was wise/lawful, nor biometric real-world identity
> beyond the key↔approver enrollment binding; **22 Alloy** assertions;
> **no customers**; no "EmiliaClient"; **no EIN** stated.

---

## §1 — Landscape: what is OPEN in June 2026 (and what is not)

**Bottom line.** SBIR/STTR was **reauthorized 2026-04-13** (S.3971, the
Small Business Innovation and Economic Security Act) through FY2031, after a
short lapse. DoD, AFWERX, SpaceWERX, Army, and Navy have all **reopened**
solicitations. So the *vehicles* are live — but the *fixed topics* posted
right now do not name EP's category, and AFWERX's current open-topic model
is **Focused** (restricted to named areas), so SBIR is a **held-abstract
watch** for EP. The **immediately actionable** money is at **DIU**, whose
two current CSOs describe EP's exact mechanism.

### DoD SBIR/STTR — the umbrella BAA (OPEN, rolling)

- **DoD SBIR/STTR FY26 Release 2 BAA** — multi-component annual BAA.
  **Open** with rolling monthly **close dates: 2026-06-24, 2026-07-22,
  2026-08-19, 2026-09-23, 2026-10-21.** Phase I up to **$250k**
  (feasibility); Phase II up to **$1.75M**. Submit in **DSIP**
  (dodsbirsttr.mil).
- **DoW SBIR 26.BZ Release 3** (Specific/Focused topics): pre-released
  2026-06-03, **opens 2026-06-24, closes 2026-07-22.**
- Topics are component-authored and rotate each release. **No current
  release topic names** "authorization," "human approval," "agent
  oversight," "offline verification," or "zero-trust authorization for agent
  actions." → EP is
  **eligible by company** but has **no matching topic yet**. Watch each
  release's topic drop (see §5).

### AFWERX / SpaceWERX (REOPENED post-reauthorization; Focused model)

- The most recent posting is **SBIR 25.5 Release 9 — Manufacturing-Focused
  Open Topic (D2P2)**, **open 2026-06-04, close 2026-07-09**, restricted to
  six manufacturing areas (engines, composites, semiconductors, rad-hard
  electronics, **system integration & interoperability**, energetics) and
  requiring a **Government Engagement Memorandum** from a DAF customer.
  → **Not** an EP fit (manufacturing), with the marginal exception of
  "system integration & interoperability," which is a stretch and still
  needs a DAF customer EP does not have.
- **26.1 Open Topic closed 2026-03-06.** AFWERX Open/Focused topics run an
  **out-of-cycle, rolling** schedule; the **broad** open topic (dual-use,
  *no predetermined Air Force end user*) is the EP-relevant flavor when it
  returns. Phase I caps are small (**$75k SBIR / $110k STTR**, ~3-month
  feasibility, then secure a customer memo).
- **STRATFI/TACFI PY26.2** Notice of Opportunity is "coming soon" — relevant
  only *after* a Phase I/II award (matching-fund growth vehicle), not an
  entry point.
- **Action:** hold the §2 abstract; fire only when a **broad** Open Topic
  (or a Focused topic naming AI assurance / autonomy oversight /
  zero-trust) reopens.

### Army / Navy / SpaceWERX component SBIR

- **Army** (xTech-adjacent SBIR) and **Navy** SBIR rolled under the same DoD
  FY26 BAA cycle (the prior 25.x releases closed in spring 2026;
  next component topics arrive with each FY26 release). Army has historically
  posted AI/autonomy-safety topics — a credible **future** EP home; none
  open *named* for EP today.
- **SpaceWERX** reopened under the same reauthorization; current postings
  are manufacturing/space-hardware focused. **Hydra at DIU** (below) is the
  better space-domain EP shot right now.

### DIU Commercial Solutions Openings (OPEN — best fit, closing in weeks)

- **Project Spectrum Strike (Prize Challenge)** — AI agents autonomously
  triage/route spectrum-coordination & **authorization** requests
  (90+ days → <5 days), **"without persistent human-in-the-loop
  bottlenecking (while providing human-on-the-loop functionality)"** for
  flagged high-risk packets, with **"auditable … governance as policies
  change"** and a **0% false-negative** safety bar.
  Rounds: **Pitch 2026-06-15 · MVP 2026-07-10 · Live demo 2026-08-25.**
  → **EP fit 5/5.** This *is* PIP-007 + hash-pinned policy +
  authorization receipt, described in DIU's own words.
- **Hydra (USSF tactical C2)** — unified data fabric, **"operator-on-the-loop
  autonomous execution,"** **Zero-Trust Architecture** end-to-end
  (continuous verification, least-privilege, micro-segmentation), and
  **autonomous agent interaction via Model Context Protocol (MCP)** under
  human control. **Due 2026-06-15.** → **EP fit 4/5** (EP already ships an
  MCP server; receipts are the zero-trust authorization primitive for
  agent actions). Timeline is very tight.

---

## §2 — Dual-use abstract (250 words, paste-ready, topic-agnostic)

> Reusable across any DoD SBIR / AFWERX / DIU vehicle whose topic admits AI
> assurance, human oversight of autonomy, or zero-trust authorization for
> agent actions. Trim to
> the vehicle's word limit; keep the bolded DoD hooks.

EMILIA Protocol (EP) is an open (Apache-2.0) standard and reference
implementation for **authorization receipts**: cryptographic,
offline-verifiable proof that a *named* human approved an *exact*,
**irreversible** AI-agent action *before* it executed. As military and
agency systems delegate real-world actions to autonomous agents, the
governing requirement is that these systems **remain under our control** and
that accountability survive audit. Today that control is a runtime promise;
EP makes it a verifiable cryptographic invariant. EP composes WebAuthn
device-bound human signoff, hash-pinned policy binding, and append-only
Merkle-anchored logs into a self-verifying receipt that **any third party
validates offline using only the approver's public key** — no trust in, and
no network connection to, the operator's runtime. This is decisive for
**classified, disconnected, and air-gapped operations**: EP ships an
air-gap installer and verifies receipts forever without a network. EP also
captures **the agent's own signed escalation decision** (the record of "I
judged this required human authorization") — a tamper-evident
human-machine-teaming accountability primitive for human-on-the-loop
autonomy. The receipt proves a named human approved this exact action; it
does not certify the decision was wise or lawful. Safety is formally
established: 26 TLA+ properties machine-checked across 413,137 states and 22
Alloy assertions, zero counterexamples, re-run in CI, plus 85 red-team
cases. The format is published as an IETF Internet-Draft with independent
JS, Python, and Go verifiers and live npm packages, so any evaluator can
`npm i` and verify a receipt today. EP converts open-ended agentic risk into
bounded, RFC-shaped authorization risk analyzable like OAuth or Kerberos.

*(Word count: 250.)*

---

## §3 — Per-vehicle fit table

| # | Vehicle / topic | Number / ID | What they want | Deadline | Fit (1–5) | Credible match? |
|---|---|---|---|---|---|---|
| 1 | **DIU — Project Spectrum Strike** | DIU CSO (prize challenge) | AI agents triage **authorization** requests; human-on-the-loop for high-risk; **auditable governance as policy changes**; 0% false-neg | Pitch **2026-06-15** → MVP 07-10 → demo 08-25 | **5** | **Yes — bullseye.** EP = signed escalation + hash-pinned policy + receipt. |
| 2 | **DIU — Hydra (USSF C2)** | DIU CSO | **Operator-on-the-loop** autonomy; **Zero-Trust** end-to-end; **MCP** agent interaction under human control | **2026-06-15** | **4** | **Yes.** EP ships an MCP server; receipts are the ZT authorization primitive. Tight timeline. |
| 3 | **DoD SBIR/STTR FY26 Release 2** | DSIP annual BAA | Component-authored fixed topics; Phase I ≤ $250k | rolling: 06-24, 07-22, 08-19, 09-23, 10-21 | **3*** | **Conditional** — eligible by company; needs a matching topic to post. |
| 4 | **DoW SBIR 26.BZ Release 3** | DSIP (Specific/Focused) | Named focus topics | open 06-24, **close 07-22** | **3*** | **Conditional** on focus area; none names EP today. |
| 5 | **AFWERX 25.5 R9 — Mfg-Focused OT** | DAF D2P2 | 6 manufacturing areas; needs DAF customer memo | open 06-04, **close 07-09** | **1** | **No** — manufacturing focus; EP has no DAF customer. |
| 6 | **AFWERX broad Open Topic** | DAF (DSIP) | Dual-use, **no predetermined end user** | **closed 03-06; next TBD** | **4** | **Yes when it reopens** — the canonical AFWERX dual-use home for EP. |
| 7 | **Army SBIR (AI/autonomy-safety)** | under FY26 BAA | AI safety / autonomy assurance (historical) | next release topics TBD | **3** | **Plausible future** — watch each release's Army topics. |
| 8 | **SpaceWERX SBIR** | under FY26 BAA | Space hardware / manufacturing now | rolling | **2** | **No** today; Hydra (DIU) is the better space shot. |

\* SBIR fit is topic-gated: 3 = eligible-but-no-matching-topic. Re-score on
each release.

---

## §4 — The two LIVE shots (decide this week)

Both are **DIU CSO / prize-challenge** vehicles, not SBIR — meaning **no
SBIR eligibility paperwork, faster, customer-pulled**, and EP's exact
mechanism is named in the solicitation. These are the "fire now" actions.

### 4a. Project Spectrum Strike — STRONGEST FIT (Fit 5/5)

- **Why EP wins it:** DIU asks for AI agents that triage **authorization**
  requests with **human-on-the-loop for high-risk** and **auditable
  governance as policies change** and a hard **0% false-negative** bar on
  safety-critical packets. EP's PIP-007 captures the agent's signed
  escalation ("this packet is high-risk → human required"); the
  authorization receipt proves a *named* human approved the exact release
  *before* it executes; hash-pinned policy makes "governance as policies
  change" tamper-evident and replay-proof; offline verification gives the
  0%-false-negative audit trail teeth.
- **What to submit (Pitch, due 2026-06-15):** a ≤10-slide deck mapping each
  DIU requirement to an EP primitive, the §2 abstract trimmed to the pitch
  limit, a 60-second `@emilia-protocol/verify` demo (issue a mock
  spectrum-release receipt, mutate one field, show verification fail), and
  the formal-assurance numbers (26 TLA+ / 22 Alloy / 85 red-team).
- **Honest gap to state, not hide:** EP is the *authorization & audit* layer,
  **not** the spectrum-parsing engine. Best as a **teaming/sub** play with a
  spectrum-AI prime, or a standalone "governance & audit module" bid.

### 4b. Hydra — STRONG FIT, TIGHT TIMELINE (Fit 4/5)

- **Why EP fits:** "operator-on-the-loop autonomous execution" + **Zero-Trust
  end-to-end** + **MCP agent interaction under human control** is exactly the
  EP value proposition — receipts are the per-action zero-trust
  authorization primitive, and EP already exposes an **MCP server** so an
  agent must obtain a verifiable human signoff before an irreversible action.
- **Due 2026-06-15** (same day as Spectrum Strike pitch). If bandwidth forces
  a choice, **Spectrum Strike first** (cleaner fit, multi-round so a strong
  pitch buys time); pursue Hydra only via a prime already bidding the data
  fabric.

---

## §5 — Submission & WATCH instructions

### If you act now (DIU — recommended)

1. **Spectrum Strike pitch** — submit the ≤10-slide deck via the DIU
   solicitation portal (`diu.mil/work-with-us/open-solicitations` → Spectrum
   Strike) by **2026-06-15**. Lead with the requirement→primitive map.
2. **Hydra** — only if teaming with a data-fabric prime; same **2026-06-15**
   deadline. Otherwise skip and keep powder dry.

### Standing SBIR / AFWERX watch (the held-abstract play)

Open these weekly (mirrors `../darpa-safe-ai/WATCH.md`; saved-search URLs):

1. **DSIP active solicitations / topic search** —
   `https://www.dodsbirsttr.mil/topics-app/` — filter each FY26 release for
   keywords: `authorization`, `human oversight`, `human-machine teaming`,
   `assurance`, `zero trust`, `agent`, `autonomy accountability`,
   `verifiable`, `offline`.
2. **AFWERX Open Topic** —
   `https://afwerx.com/divisions/sbir-sttr/open-topic/` — watch for the
   **broad** (no-end-user) Open Topic to return, or a Focused topic naming
   AI assurance / autonomy oversight.
3. **DIU open solicitations** —
   `https://www.diu.mil/work-with-us/open-solicitations` — recheck for new
   AI/autonomy CSOs with "operator-on-the-loop," "human oversight," or
   "authorization" language.
4. **SAM.gov active opp search** —
   `https://sam.gov/search/?index=opp&keywords=%22human%20oversight%22%20%22AI%20agent%22%20OR%20%22authorization%20receipt%22%20OR%20%22zero%20trust%22%20autonomy&is_active=true&sort=-modifiedDate`
5. **Army SBIR topics** — scan each FY26 release's Army topics for
   AI/autonomy-safety.

### "Fire the SBIR/AFWERX abstract" trigger — write within 72h if ANY:

- A **DoD/AFWERX/Army/Navy/Space** SBIR topic posts naming **authorization,
  human approval, human-on/in-the-loop, agent accountability, offline/
  air-gapped verification, or zero-trust authorization for agent
  actions**. → §2 abstract is
  pre-aligned; tailor to the topic's TPOC questions.
- The **AFWERX broad Open Topic** (dual-use, no predetermined end user)
  **reopens** (deadlines are short, ~30–45 days).
- A **DIU AI/Autonomy CSO** posts with "human oversight" / "authorization" /
  "trusted autonomy" language.

Do **not** drop SBIR work for: manufacturing-only Focused topics,
hardware/sensor challenges, or any topic requiring a DAF/Service customer
memo EP does not yet have (no customers).

### Eligibility / paperwork prerequisites (true today)

- SBIR/AFWERX require **SAM.gov registration (UEI)**, **SBIR Company
  Registry**, and a **DSIP** account — set these up *before* a topic posts
  so a 30-day window is enough.
- DIU CSOs are lighter-weight (no SBIR registration), which is part of why
  they are the better immediate shot.

---

## §6 — Status tracker (this package)

| Item | Status | Next action |
|---|---|---|
| DIU Spectrum Strike | **LIVE — fire** | Submit pitch deck by **2026-06-15** |
| DIU Hydra | **LIVE — team-or-skip** | Find data-fabric prime by **2026-06-15** |
| DoD SBIR FY26 R2/R3 | **WATCH** | Scan topics each release; abstract held |
| AFWERX broad Open Topic | **WATCH** | Fire abstract when it reopens |
| Army SBIR AI/autonomy | **WATCH** | Scan Army topics each release |
| §2 dual-use abstract | **READY** | Paste-and-trim per vehicle |
| SAM.gov / SBIR Registry / DSIP | **TODO** | Register now so windows are usable |

---

*Sources (June 2026): dodsbirsttr.mil (DSIP active solicitations / FY26
Release 2 rolling close dates); afwerx.com Open Topic + 25.5 R9
Manufacturing-Focused OT (open 06-04 / close 07-09); afrl.af.mil
"AFWERX, SpaceWERX open new SBIR/STTR solicitations following
reauthorization"; SBIR reauthorization S.3971 signed 2026-04-13;
diu.mil/work-with-us/open-solicitations (Spectrum Strike, Hydra).
Re-confirm every number on the official portal before submitting.*
