# EP Funding WATCH — DARPA / DoD / IARPA / AFWERX / DIU

> Last refreshed: **2026-06-12**. Purpose: detect the moment a fitting
> solicitation opens, and decide fast whether to "drop everything and
> write the white paper." Template lives next door at `white-paper.md`.

---

## 1. Saved-search URLs (open these every week)

**SAM.gov — keyword queries** (set each to "Active" only):
1. Trustworthy / verifiable AI:
   `https://sam.gov/search/?index=opp&keywords=%22trustworthy%20AI%22%20OR%20%22verifiable%20AI%22%20OR%20%22assured%20autonomy%22&is_active=true&sort=-modifiedDate`
2. Agent accountability / human oversight:
   `https://sam.gov/search/?index=opp&keywords=%22AI%20agent%22%20%22human%20oversight%22%20OR%20%22agent%20accountability%22%20OR%20%22controlled%20emergence%22&is_active=true&sort=-modifiedDate`
3. DARPA AI assurance issuer filter (org = DARPA):
   `https://sam.gov/search/?index=opp&keywords=DARPA%20AI%20assurance%20OR%20formal%20methods&is_active=true&sort=-modifiedDate`

**DARPA opportunities page** (scan the full active list):
4. `https://www.darpa.mil/work-with-us/opportunities`
   - Watch specifically for: **DICE** BAA (expected post-2026-05-29
     Proposers Day), **I2O Office-Wide BAA** reopening under its new office
     name (paused 2026-05-21 → was **HR001126S0001**), any **CLARA**
     follow-on / CyPhER-Forge / MATHBAC.

**Grants.gov saved search** (mirror of federal postings):
5. `https://www.grants.gov/search-grants?keywords=DARPA%20artificial%20intelligence%20assurance`
   (Log in → save as "DARPA AI assurance" with email alerts ON.)

**AFWERX / DAF SBIR-STTR cycle calendar** (dual-use accepted!):
6. `https://www.afwerx.com/divisions/sbir-sttr/open-topic/` and the DSIP
   portal `https://www.dodsbirsttr.mil/submissions/solicitation-documents/active-solicitations`
   - Note: **26.1 Open Topic closed 2026-03-06.** A **Focused Open Topic
     opened ~2026-06-04, closes 2026-07-09** (post-reauthorization). Check
     whether its focus area admits AI-assurance / trust infrastructure.

**DIU Commercial Solutions Openings:**
7. `https://www.diu.mil/work-with-us/open-solicitations` — AI/ML +
   Autonomy portfolios. Watch for any CSO naming "operator-on-the-loop,"
   "human oversight," or "trusted autonomy."

**IARPA open BAAs:**
8. `https://www.iarpa.gov/engage-with-us/open-baas` — low base rate but
   check monthly for any AI-trust / agent-assurance program.

---

## 2. The 15-minute weekly checklist (do this every Monday)

1. ( 3 min) Open SAM.gov saved searches #1–#3. Any **new** active opp
   touching AI verification / agent control / trustworthy autonomy? → log
   number + deadline in the table below.
2. ( 3 min) Open DARPA opportunities page (#4). Has **DICE** posted a BAA?
   Has the **I2O Office-Wide BAA** reopened (new office name)? Any CLARA
   successor?
3. ( 2 min) Grants.gov alert inbox (#5) — clear or triage.
4. ( 3 min) AFWERX/DSIP (#6) — is a new Open/Focused Topic live, and does
   its focus area admit dual-use AI-assurance software? Note close date.
5. ( 2 min) DIU (#7) — any new AI/Autonomy CSO with human-oversight
   language?
6. ( 2 min) Update the "Live candidates" table below; if any TRIGGER
   condition (§3) is met, escalate immediately.

---

## 3. TRIGGER criteria — "drop everything and write the white paper"

Write within **48 hours** if **any** of these is true:

- **DICE BAA posts** with a technical area naming agent control, human
  oversight, accountability, or verifiable autonomy. *(Highest-fit named
  program. Fit 5/5.)*
- **I2O Office-Wide BAA reopens** (under any new office name) — EP fits
  Thrust 1 (trustworthy AI) + Thrust 2 (secure software) and abstracts are
  rolling. *(Standing home. Fit 4/5.)*
- **A CLARA follow-on / Phase-2 / sibling** opens requiring Apache-2.0
  open-source + "verifiability with logical proofs." EP is uniquely
  pre-qualified (already Apache-2.0, already formally verified). *(Fit
  4/5.)*
- **Any SAM.gov / DARPA opp** explicitly uses "authorization," "human
  approval," "pre-action," "offline-verifiable," or "receipt" in an
  AI/autonomy context. *(Bullseye — Fit 5/5.)*

Write within **2 weeks** (worth it, not on fire) if:

- An **AFWERX/DIU dual-use** opening posts whose focus area plausibly
  admits trust/assurance infrastructure (deadlines here are short — 30–45
  days — so confirm fit fast).

Do **not** drop everything for: adversarial-robustness-only programs
(SABER/GARD/BORDEAUX lineage), energy-aware ML (ML2P), or pure
reasoning-theory calls with no authorization/accountability hook — log and
move on.

---

## 4. Live candidates table (update weekly)

| Program | Office | Number | What they want | Deadline | Fit | Status |
|---|---|---|---|---|---|---|
| **DICE** | I2O | TBD (Proposers Day 2026-05-29) | Heterogeneous AI agents under control on long missions | BAA TBD | **5** | Awaiting BAA — TRIGGER on post |
| **I2O Office-Wide** | I2O | HR001126S0001 | Trustworthy/explainable AI; secure software | Abstracts 2026-11-01 | **4** | **PAUSED 2026-05-21**; watch reopen |
| **CLARA** | DSO | DARPA-PA-25-07-02 | Verifiable AI via logical proofs; Apache-2.0 | Closed ~Apr 2026 | **4** | Closed — watch follow-on |
| **BORDEAUX** | I2O | DARPA-PS-26-20 | AI cyber-security robustness | Closed 2026-05-15 | 2 | Closed — adjacent |
| **AFWERX Focused Open Topic** | DAF | DSIP | Dual-use commercial tech (area-specific) | ~2026-07-09 | 3* | Open — confirm area admits EP |
| **DIU AI/Autonomy CSOs** | DIU | rolling | Operator-on-the-loop autonomy | rolling | 3 | Open — monitor |

\* AFWERX fit depends entirely on the open topic's focus area; re-score
each cycle.
