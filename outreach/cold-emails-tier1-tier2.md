# EMILIA GovGuard — Tier-1 + Tier-2 Cold Email Sequences

**Goal:** 20 sends → 5 first-meeting bookings → 2 deep technical conversations → 1 LOI to scope a paid pilot.

**Cadence:**
- **Send window:** Tuesday–Thursday, 8:00–10:30 AM recipient-local-time.
- **Initial send:** all 20 in a single tight 48-hour window.
- **Follow-up #1:** 7 days after initial — short bump, link to `/r/example`.
- **Follow-up #2:** 18 days after initial — different angle (audit/oversight) or close.
- **Stop:** 21 days after initial. No fourth touch.

**Deliverables that go with every email:**
- Live demo URL: `https://emiliaprotocol.ai/r/example`
- One-pager PDF: `docs/marketing/govguard-onepager.pdf` (attach to every send)
- Pilot scope doc: send only on reply request

**Send-from:** iman@emiliaprotocol.ai (set up SPF/DKIM if not done — government spam filters are strict)

**Verification before send:**
1. Confirm each email address is still active via the agency's contact page (links cited per email).
2. Replace `[Name]` and any bracketed agency-specific reference with current incumbent's name.
3. If an agency has had a major fraud incident publicly disclosed since 2026-04-01, add one line referencing it without naming individuals.

**One legal note:** These are cold prospecting emails to public-sector unit-level contacts using publicly listed agency emails. Not constituent communication, not lobbying, not solicitation of an individual. Standard B2B GovTech outreach posture. CAN-SPAM applies; provide unsubscribe in email signature footer.

---

## CALIFORNIA — TIER 1 (5 emails)

### 1. CDSS — Program Integrity Bureau

**TO:** Use the Data Stewardship and Integrity Bureau intake (see https://www.cdss.ca.gov/inforesources/fraud — bureau lead's name varies; address to "Bureau Chief, Program Integrity" if no name is listed)
**SUBJECT:** Preventing benefit-routing changes from executing — 30-day pilot

Hi [Name],

I'm Iman Schrock, founder of EMILIA Protocol. CDSS Program Integrity is the closest unit in California to the specific control gap GovGuard addresses: payment-destination and benefit-routing changes that look valid because they happen inside authorized caseworker sessions.

Today, the controls catch the *actor* (login, MFA, session). They do not catch the *action* — the change itself goes through if the actor's session is valid.

EMILIA GovGuard sits between the case-system save and the payment system. Before a benefit-routing change is committed: verified actor identity, verified authority chain, exact-action context bound to a one-time cryptographic token, named human signoff when policy requires it. Every committed action produces a tamper-evident receipt your auditors can verify offline (live example: https://emiliaprotocol.ai/r/example).

Open to a 20-minute call to walk through what a 30-day shadow-mode pilot looks like for one CalWORKs or CalFresh workflow? Pilot fee $25K–$75K depending on integration depth. Open-source protocol (Apache 2.0) with formal verification — no lock-in.

Iman Schrock
iman@emiliaprotocol.ai · github.com/emiliaprotocol

**Hook note:** CDSS Data Stewardship & Integrity Bureau owns CalWORKs/CalFresh/Child Care fraud detection per their public site. No specific recent incident cited (don't fabricate); the page itself confirms they are the right unit.
**Timing:** Send Tuesday morning. Follow-up at day 7 with a one-line "did this make it through?" + the demo URL.

---

### 2. CDSS — Welfare Fraud Hotline / Coordination

**TO:** FraudHotline@dss.ca.gov
**SUBJECT:** Who owns prevention controls for benefit-routing changes?

Hello,

I'm reaching out because the CDSS welfare fraud hotline coordinates with county-level investigators, but my question is upstream of investigation: who at CDSS or at the county level owns *prevention* controls for benefit-routing changes — the controls that would stop a fraudulent destination change from executing in the first place?

EMILIA GovGuard is a pre-execution control layer designed for exactly this control gap. Live example of a vendor bank-change attempt that GovGuard required two named human approvers to release: https://emiliaprotocol.ai/r/example

If the right unit is in DPSS at the county level, or in CDSS Program Integrity, I'd appreciate the name and email. Happy to share a 1-page brief.

Thanks,
Iman Schrock · iman@emiliaprotocol.ai

**Hook note:** This is a referral-ask email, not a pitch. The hotline isn't the buyer; the goal is to learn the right contact. Keep it short.
**Timing:** Send same week as #1. No follow-up — if they don't reply within 14 days, reroute through DGS/SCO.

---

### 3. CA State Controller's Office — Administration & Disbursements

**TO:** See https://www.sco.ca.gov/sco_divisions.html for the Administration & Disbursements Division Chief; address to "Division Chief, Administration & Disbursements"
**SUBJECT:** Pre-execution proof for warrant/EFT disbursement changes

Dear Division Chief,

The State Controller's Office prepares and releases warrants and EFTs from the State Treasury. The control gap I'd like to discuss is narrow: at the moment a disbursement destination is changed (warrant address, EFT routing/account, payee record), the existing controls verify *who is logged in*. They do not produce a tamper-evident, cryptographically bound record proving *which named human authorized this exact change at this exact moment under this exact policy version*.

EMILIA GovGuard inserts that control as a pre-execution check. Output is a publicly verifiable trust receipt (live example: https://emiliaprotocol.ai/r/example) — the same evidence packet your auditors and Joint Legislative Audit Committee can re-verify months later without trusting our infrastructure.

Pilot scope: 1 disbursement workflow, 30 days, shadow → enforce, weekly fraud/control report. $25K–$75K. Open-source protocol, no vendor lock-in.

20 minutes next week to walk you through a sample receipt?

Iman Schrock · iman@emiliaprotocol.ai · github.com/emiliaprotocol

**Hook note:** SCO is the warrant-issuing authority — disbursement integrity is literally their statutory function. This is the highest-leverage CA target.
**Timing:** Send first. Follow-up at day 7 with a different angle (audit-evidence quality).

---

### 4. CA DGS — Procurement Division

**TO:** Procurement Division main line + email per https://www.dgs.ca.gov/PD/Contact (call (800) 559-5529 first to get the right contact name)
**SUBJECT:** Vendor bank-account change control for statewide procurement

Hi [Procurement Division contact],

DGS Procurement coordinates statewide vendor onboarding and supplier data. I'm Iman Schrock, founder of EMILIA Protocol. The control gap GovGuard addresses, in your language: a vendor's deposit account of record is changed (often via the vendor self-service portal), and that change propagates to upcoming purchase-order disbursements before any human has explicitly approved the destination switch.

GovGuard intercepts the change *before* it commits. Risk signals fire (new destination, after-hours, no prior change in 30 days), the change is held, two-party named approval is required by policy. Live example of exactly this scenario: https://emiliaprotocol.ai/r/example

This is a 30-day shadow-mode pilot, then optional enforcement, on one workflow (e.g., centralized vendor data updates above $25K next-payment exposure). $25K–$75K. Apache 2.0 protocol — no lock-in.

Open to a 20-minute scoping call?

Iman Schrock
iman@emiliaprotocol.ai

**Hook note:** DGS is the natural CA buyer for the exact wedge scenario the demo is built around. Highest demo-fit alignment of any CA contact.
**Timing:** Send second. Follow-up at day 7.

---

### 5. Angela Shell, CA Chief Procurement Officer / DGS

**TO:** Angela Shell — find direct via https://www.dgs.ca.gov/About/Executive-Staff-Page/Angela-Shell or DGS executive office
**SUBJECT:** Statewide supplier payment integrity — 20 minutes, no deck

Ms. Shell,

I'm Iman Schrock. I'm not going to send a deck. The 20-minute version: California's statewide supplier payment systems verify session-level authentication. They do not produce a cryptographically bound, tamper-evident record proving that the specific payment-destination change was authorized by the right named human under the right policy at the exact moment it executed.

That gap is where vendor impersonation fraud succeeds. EMILIA GovGuard closes it — pre-execution. Live example of a blocked-then-approved vendor bank change (the kind of incident that costs agencies six figures per occurrence): https://emiliaprotocol.ai/r/example

I'd value 20 minutes of your time to ask one question: in CA's current vendor payment integrity stack, what would it take to slot in a pre-execution control layer on one workflow as a 30-day pilot?

Iman Schrock
Founder, EMILIA Protocol
iman@emiliaprotocol.ai

**Hook note:** Strategic exec target — keep it short, respect her time, no PDF on first send. The "no deck" framing is a deliberate signal she's not your ICP for slide decks.
**Timing:** Send AFTER #4 — don't email the CPO before the procurement division. Wait 5 days post-#4, then send. Follow-up at day 14, not day 7.

---

### 6. FI$Cal — Centralized Vendor Management

**TO:** Use https://fiscal.ca.gov/user-support/cal-eprocure-resources/centralized-vendor-management/ for current contact (likely a manager-level contact via the help desk)
**SUBJECT:** Pre-execution control on vendor payee data changes — FI$Cal-aligned pilot

Hi [Name],

FI$Cal centrally maintains vendor payee data that drives downstream POs, contracts, and disbursements across CA departments. The single highest-leverage point for fraud prevention in that pipeline is *the moment a payee record is created or modified* — before any department's payments depend on the new data.

EMILIA GovGuard sits at that exact point. Pre-execution: verified identity, authority chain, policy-pinned action context, named human signoff for high-risk changes, one-time cryptographic consumption. Output is a tamper-evident receipt every department auditor can verify offline. Live example: https://emiliaprotocol.ai/r/example

A 30-day shadow-mode pilot on one workflow (e.g., new-vendor onboarding above $50K projected annual spend, or any vendor-bank-account modification) costs $25K–$75K. Apache 2.0 — your team can self-host.

20-minute call to walk through it?

Iman Schrock · iman@emiliaprotocol.ai · github.com/emiliaprotocol

**Hook note:** FI$Cal is statewide ERP. If they pilot, every CA department benefits without per-department procurement.
**Timing:** Send Wednesday. Follow-up at day 7 with the one-pager attached if not already.

---

### 7. LA County DPSS — Welfare Fraud Prevention & Investigations

**TO:** Use https://dpss.lacounty.gov/en/resources/wfpi.html — WFPI Bureau Chief or Welfare Fraud Prevention Branch lead
**SUBJECT:** County-level pilot — pre-execution control for benefit-routing changes

Dear [Name],

LA County DPSS is the largest county welfare unit in the country. WFPI's mandate is fraud prevention and investigation, and the pattern I want to discuss is one your investigators see repeatedly: benefit-routing changes that pass session-level checks because the actor is authenticated, then later turn out to have been the result of social engineering, account takeover, or an unauthorized change.

EMILIA GovGuard is a pre-execution control layer. Before a routing change commits: verified identity, verified authority, exact-action context bound to a one-time cryptographic ceremony, named human signoff when policy requires it. Live receipt example: https://emiliaprotocol.ai/r/example

LA County is the right size for a meaningful pilot — large enough to surface real signal, small enough operationally to ship a 30-day shadow-mode trial without procurement-protest exposure. $25K–$75K, one workflow, weekly fraud/control report. Apache 2.0.

20 minutes next week?

Iman Schrock · iman@emiliaprotocol.ai

**Hook note:** LA County DPSS is operationally closer to implementation than statewide CDSS — likely faster to a yes.
**Timing:** Send same day as #1 (parallel CA tracks). Follow-up at day 7.

---

## MINNESOTA — TIER 1 (5 emails)

### 8. MN DHS — Program Integrity (general)

**TO:** Per https://mn.gov/dhs/program-integrity/ — address to "Director, Program Integrity Division"
**SUBJECT:** Turning OLA fraud findings into pre-execution controls

Hi [Name],

The MN Office of the Legislative Auditor's investigations of program-integrity failures over the last several years have a consistent shape: actors with valid sessions made changes that, after the fact, turned out to be unauthorized or fraudulent. The control gap is not authentication — it is *action authorization*. Today, the system catches that the user is logged in; it does not catch what the user actually did.

EMILIA GovGuard is a pre-execution control layer. Pre-action: verified actor identity, authority chain, policy-pinned action context, named human signoff when policy requires it. Output: a tamper-evident receipt your investigators can verify offline. Live example of a vendor bank-change blocked-then-approved scenario: https://emiliaprotocol.ai/r/example

A 30-day shadow-mode pilot on one workflow (provider data changes, grant disbursement approvals, or benefit-routing changes) is $25K–$75K. Apache 2.0 protocol, formally verified, can be self-hosted.

20 minutes to discuss which workflow has the highest-leverage control gap?

Iman Schrock · iman@emiliaprotocol.ai · github.com/emiliaprotocol

**Hook note:** OLA reports are public and well-known — referencing them is honest and signals research. *Verify* before send: pull one OLA report from 2024–2026 and consider citing the report number directly.
**Timing:** Send Tuesday. Follow-up at day 7.

---

### 9. MN DHS — OIG / Program Integrity Investigations

**TO:** OIG.Investigations.DHS@state.mn.us
**SUBJECT:** Pre-execution controls for the patterns OIG investigates after the fact

Hello,

I'm Iman Schrock, founder of EMILIA Protocol. I'm not pitching investigation — your team already does that. I'm pitching the control layer that would stop the next case before it hits your investigation queue.

The pattern OIG sees repeatedly: provider-payment changes, vendor-data updates, or benefit-routing modifications that look valid at the moment they happened (authenticated user, valid session, no MFA failure) but turn out to be fraudulent on later review.

EMILIA GovGuard inserts pre-execution verification at the exact moment the change attempts to commit. Live example of a vendor bank-change attempt blocked until two named approvers signed off: https://emiliaprotocol.ai/r/example

If your office can refer me to whichever DHS division owns *prevention* controls (we're thinking Program Integrity Division or whoever owns the Medicaid provider data masters), I'd appreciate the name. Or if there's value in a 20-minute call directly with OIG, I'm available.

Iman Schrock · iman@emiliaprotocol.ai

**Hook note:** OIG is investigative, not preventative — the email respects that and asks for a referral. Higher reply rate than a direct pitch.
**Timing:** Send Wednesday. No follow-up — if OIG refers, take the referral; if not, reroute via #8 or #11.

---

### 10. MN MMB — General

**TO:** info.mmb@state.mn.us
**SUBJECT:** Vendor-payment integrity for statewide accounting — 20 min

Hello MMB,

I'm Iman Schrock. MMB owns statewide finance, accounting, and vendor payment infrastructure for Minnesota. The control gap I want to discuss is narrow: when vendor data is changed in SWIFT (bank account, remittance address, W-9 record), the existing controls verify the actor's session. They do not produce a cryptographically bound, tamper-evident record proving that *this exact change* was authorized by the right named human under the right policy.

EMILIA GovGuard is a pre-execution control layer that closes this gap. Live example showing a vendor bank-change attempt blocked until two named approvers signed off: https://emiliaprotocol.ai/r/example

Could you direct me to the right contact for a 20-minute scoping conversation about a 30-day shadow-mode pilot on one workflow? Pilot fee $25K–$75K. Open-source protocol (Apache 2.0). Formally verified.

Iman Schrock
iman@emiliaprotocol.ai · github.com/emiliaprotocol

**Hook note:** info.mmb is general — request a routing to the right person rather than pitching.
**Timing:** Send Monday so it's at the top of Tuesday's queue. No automatic follow-up — wait for routing.

---

### 11. MN MMB — Vendor Payments / SWIFT

**TO:** Syscomp.mmb@state.mn.us (and CC: W9-1099.mmb@state.mn.us)
**SUBJECT:** Pre-execution control on SWIFT vendor master file changes

Hi SWIFT Vendor Payments team,

The SWIFT vendor resources page lists your team as the contact for vendor master file changes, special-handling payments, and stop-payment requests. Those workflows are precisely where vendor impersonation fraud succeeds: an actor with valid access changes the vendor's bank-account record, and downstream payments go to the wrong destination before anyone notices.

EMILIA GovGuard is a pre-execution control layer. Before a vendor master file change commits: verified actor identity, authority chain, policy-pinned action context, named human signoff bound to the exact change (with risk flags acknowledged by the approver), one-time cryptographic consumption. Output: a tamper-evident receipt MMB auditors can verify offline. Live demo: https://emiliaprotocol.ai/r/example

A 30-day shadow-mode pilot on one workflow (vendor bank-account changes is the natural fit) is $25K–$75K. Apache 2.0 protocol.

Could we set up a 20-minute call?

Iman Schrock
Founder, EMILIA Protocol
iman@emiliaprotocol.ai

**Hook note:** This is the most demo-aligned MN target — the live `/r/example` IS a vendor bank-change blocked scenario.
**Timing:** Send Wednesday. Follow-up at day 7 — high priority.

---

### 12. MN MMB — W-9 / 1099 Supplier Data

**TO:** W9-1099.mmb@state.mn.us
**SUBJECT:** 1099 supplier data integrity — pre-execution control layer

Hi W-9/1099 team,

The 1099/foreign supplier data your team maintains is upstream of statewide vendor payments. A change to a 1099 record (new TIN, new bank routing, new remittance address) propagates to every department that uses that supplier. The control gap: at the moment of change, the system verifies the actor's session, but it does not produce a tamper-evident, cryptographically bound record proving the change was authorized.

EMILIA GovGuard is a pre-execution control layer that addresses this gap. Live example: https://emiliaprotocol.ai/r/example

Would 20 minutes next week work to discuss a 30-day shadow-mode pilot focused on 1099 data integrity? Pilot fee $25K–$75K, Apache 2.0 protocol.

Iman Schrock
iman@emiliaprotocol.ai

**Hook note:** Tighter ICP than #11 — only relevant if the W-9 team has its own change-control workflow. May get punted to Syscomp.
**Timing:** Send same day as #11. If both reply, prioritize #11.

---

## MINNESOTA — TIER 2 (3 emails)

### 13. MN OSP — Rachel Dougherty (Chief Procurement Officer & Director)

**TO:** Rachel.Dougherty@state.mn.us
**SUBJECT:** Statewide supplier onboarding integrity — 20 min

Ms. Dougherty,

I'm Iman Schrock. The Office of State Procurement runs supplier onboarding and master contracts for Minnesota. The control gap I want to discuss is narrow: at the moment a new supplier is onboarded — or an existing supplier's bank/remittance data is modified — the existing controls verify the actor's authentication. They don't produce a cryptographically bound, tamper-evident record proving *this exact change* was authorized by the right named human.

EMILIA GovGuard is a pre-execution control layer that closes that gap. Live example: https://emiliaprotocol.ai/r/example

20-minute scoping call to discuss a 30-day shadow-mode pilot on one workflow — supplier onboarding, master-contract supplier modifications, or vendor-bank-account changes? $25K–$75K, Apache 2.0 protocol, formally verified.

Iman Schrock
Founder, EMILIA Protocol
iman@emiliaprotocol.ai · github.com/emiliaprotocol

**Hook note:** Strategic exec target — short, direct, no deck. Don't bcc anyone else.
**Timing:** Send AFTER #11 + #12 land (so MMB awareness exists before OSP). Day 5 after MMB sends.

---

### 14. MN OSP — Luke Jannett (Acquisitions Manager)

**TO:** Luke.Jannett@state.mn.us
**SUBJECT:** Acquisitions-level vendor change controls — pilot

Hi Mr. Jannett,

OSP's Acquisitions function is downstream of supplier data integrity. I'm reaching out because the control gap GovGuard addresses lives at exactly that boundary: vendor data changes that propagate through Acquisitions to live procurements before any human has explicitly approved the destination change.

EMILIA GovGuard intercepts the change pre-execution. Live demo of the exact scenario: https://emiliaprotocol.ai/r/example

20 minutes to discuss whether a 30-day pilot fits within OSP's pilot/POC posture? $25K–$75K, Apache 2.0.

Iman Schrock
iman@emiliaprotocol.ai

**Hook note:** Operational-level contact — likely the actual decider for technical pilots.
**Timing:** Send same day as #13.

---

### 15. MN OSP — Doug Heeschen (Contracts Administrator)

**TO:** Doug.Heeschen@state.mn.us
**SUBJECT:** Contract-level supplier modification controls

Hi Mr. Heeschen,

I'm Iman Schrock. As the OSP Contracts Administrator, you'd be the right contact for a question about contract-level supplier modifications — specifically, the moment an active contract's supplier bank-data is changed and that change flows through to scheduled disbursements.

EMILIA GovGuard inserts a pre-execution control at exactly that boundary. Live example: https://emiliaprotocol.ai/r/example

If a 30-day shadow-mode pilot fits OSP's contracting framework, I'd value 20 minutes to scope it. $25K–$75K, Apache 2.0.

Iman Schrock
iman@emiliaprotocol.ai

**Hook note:** Most operational of the three OSP contacts — may have actual authority to scope a small pilot.
**Timing:** Send same day as #13 + #14.

---

## TIER 2 / EXTRAPOLATED — High-leverage, similar pattern (5 emails)

These contacts are extrapolated from the same audit pattern (large-county welfare fraud units + state-level financial-crime units). Verify each address before send.

### 16. LA County District Attorney — Public Integrity Division

**TO:** Public Integrity Division — verify current contact via https://da.lacounty.gov/about/divisions
**SUBJECT:** Pre-execution control layer for the cases your division prosecutes

Hello Public Integrity Division,

LA County DA's Public Integrity Division prosecutes fraud cases against public-fund integrity. I'm Iman Schrock, founder of EMILIA Protocol. I'm not pitching investigation — your division already does that. I'm pitching the *prevention* layer that would reduce your case volume.

EMILIA GovGuard is a pre-execution control layer for high-risk public-sector actions: vendor-bank-account changes, benefit-routing modifications, operator overrides. Live example of a fraudulent vendor bank-change attempt that GovGuard required two named human approvers to release: https://emiliaprotocol.ai/r/example

If your division can refer me to whichever LA County unit owns *prevention* controls for the categories you prosecute, I'd appreciate the name and email.

Iman Schrock · iman@emiliaprotocol.ai

**Hook note:** Referral-ask, not a pitch. DA office isn't the buyer.
**Timing:** Send Wednesday. No automatic follow-up.

---

### 17. San Diego County HHSA — Welfare Fraud Investigations

**TO:** Verify contact via https://www.sandiegocounty.gov/hhsa — Welfare Fraud Investigations Bureau
**SUBJECT:** County pilot — pre-execution control for benefit-routing changes

Hi [Name],

I'm reaching out because San Diego County HHSA's Welfare Fraud Investigations bureau handles cases that a pre-execution control layer could prevent entirely. The pattern: a benefit-routing change passes session-level checks at the moment of execution, then turns out to be fraudulent on review.

EMILIA GovGuard sits between the case-system save and the payment system. Live example: https://emiliaprotocol.ai/r/example

20-minute scoping call for a 30-day county-level pilot? $25K–$75K, Apache 2.0, formally verified.

Iman Schrock
iman@emiliaprotocol.ai

**Hook note:** Same pattern as LA County DPSS (#7) — second-largest county welfare unit in CA.
**Timing:** Send same day as #7.

---

### 18. Hennepin County (MN) — Human Services Fraud Investigation

**TO:** Verify via https://www.hennepin.us/your-government/contact/human-services
**SUBJECT:** County-level pilot for benefit-redirect prevention

Hi [Name],

Hennepin County is MN's largest county Human Services unit. EMILIA GovGuard is a pre-execution control layer for benefit-routing changes, vendor-bank-account modifications, and operator overrides — the categories your fraud-investigation team currently catches *after* the fact.

Live example of a vendor bank-change blocked-then-approved scenario: https://emiliaprotocol.ai/r/example

20 minutes to discuss a 30-day shadow-mode pilot? $25K–$75K. Apache 2.0 — county can self-host.

Iman Schrock
iman@emiliaprotocol.ai

**Hook note:** Same pattern as LA County / San Diego — county-level operational closer than statewide.
**Timing:** Send same day as #8 + #9.

---

### 19. MN Department of Revenue — Criminal Investigation Division

**TO:** Verify via https://www.revenue.state.mn.us — Criminal Investigation contact
**SUBJECT:** Pre-execution controls on the patterns your division investigates

Hello CID,

The MN Department of Revenue Criminal Investigation Division investigates tax-related and refund fraud. I'm not pitching investigation; I'm pitching the *prevention* layer.

EMILIA GovGuard intercepts high-risk action attempts (refund-destination changes, taxpayer-record modifications, payment redirects) *before* they execute. Live example: https://emiliaprotocol.ai/r/example

If your division can refer me to whichever MN DOR unit owns prevention-side controls (or if there's value in a direct conversation), I'd appreciate the routing.

Iman Schrock · iman@emiliaprotocol.ai

**Hook note:** Referral-ask. DOR CID is investigative, like DHS OIG (#9).
**Timing:** Send same week as MN tier-1.

---

### 20. CA EDD — Fraud Prevention / Investigation Division

**TO:** Verify via https://edd.ca.gov — Fraud Investigation/Prevention division
**SUBJECT:** Post-pandemic UI fraud-control gap — pre-execution layer

Hi [Name],

CA EDD's pandemic-era unemployment-insurance fraud loss is the most public example in the country of what happens when the control surface verifies sessions but not actions. I'm Iman Schrock, founder of EMILIA Protocol. I'm not pitching forensics; I'm pitching the layer that would have caught the destination changes at the moment they attempted to commit.

EMILIA GovGuard is a pre-execution control layer for high-risk action authorization. Live example showing a fraudulent bank-account change blocked until two named human approvers signed off: https://emiliaprotocol.ai/r/example

A 30-day shadow-mode pilot on one workflow (UI benefit-routing changes is the natural fit) is $25K–$75K. Apache 2.0 protocol — EDD can self-host. Formally verified.

20 minutes to discuss?

Iman Schrock
iman@emiliaprotocol.ai

**Hook note:** EDD's pandemic fraud loss (~$20B reported) is widely public — referencing it is honest and signals research. Avoid naming individuals or current cases.
**Timing:** Send AFTER all CA tier-1 contacts so the email isn't the first CA touch. Day 7 after #1–#7.

---

## SOC 2 AUDITOR QUOTES (3 emails — separate track)

These run in parallel to government outreach. Goal: 3 quotes within 14 days, pick the cheapest with cryptography-vendor experience, defer engagement until AWS confirms or revenue covers.

### A. Schellman & Co.

**TO:** info@schellman.com
**SUBJECT:** SOC 2 Type I scoping quote — open-source cryptographic protocol vendor

Hello Schellman team,

EMILIA Protocol is an open-source pre-execution authorization protocol for AI and high-risk action systems. Apache 2.0 license, ~50 API endpoints, formally verified (TLA+ + Alloy), no managed customer data at present (control plane only).

We're targeting SOC 2 Type I in the next 3–6 months, Type II in 12 months, to support late-2026 enterprise and government procurement. Could you provide a scoping quote?

Iman Schrock
Founder, EMILIA Protocol
iman@emiliaprotocol.ai · github.com/emiliaprotocol

---

### B. A-LIGN

**TO:** info@a-lign.com
**SUBJECT:** SOC 2 Type I scoping quote — protocol vendor with formal verification

[Same body as A, addressed to A-LIGN]

---

### C. Prescient Assurance

**TO:** contact via https://www.prescientassurance.com/
**SUBJECT:** SOC 2 Type I scoping quote — protocol vendor

[Same body as A]

---

## Tracking

Use a simple spreadsheet:

| # | Recipient | Sent | Replied | Meeting Booked | Outcome |
|---|-----------|------|---------|----------------|---------|
| 1 | CDSS Program Integrity | YYYY-MM-DD | | | |
| 2 | CDSS Hotline | | | | |
| ... | ... | | | | |

Reply rate target: ≥15% (3 of 20). Meeting-book rate from replies: ≥50%. So 3 replies → 1.5 meetings minimum. The audit's 14-day plan (5 meetings from 50 emails = 10% meeting-book rate) is achievable from 20 emails *only* if each email is well-targeted, which these are.

If reply rate after 14 days is <10%, the issue is not the emails — it's the email list. Reroute and expand to MN OLA, NY OMIG, and similar oversight units in TX/FL.

---

**Last updated:** 2026-04-28
**Owner:** Iman Schrock
