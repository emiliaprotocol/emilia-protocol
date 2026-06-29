# Agency SBIR (DHS + NIST) — Submission Instructions & Watch Plan

Both FY2026 solicitations are **between cycles** as of June 12, 2026 (SBIR/STTR
reauthorization landed April 13, 2026; both program pages were mid-update). So
the immediate action for each is **monitor + pre-register**, not submit.

---

## DHS S&T SBIR

**Status:** No open solicitation (Jun 2026). FY25 was 25.1 (closed Jan 21, 2025).
FY2026 window estimated **May–Jul 2026** post-reauthorization.
**Phase I:** ~$150K firm-fixed-price / ~6 months (some cycles up to ~$200K).
**Where it posts:** SAM.gov + the DHS S&T SBIR portal `sbir2.st.dhs.gov`.

**Single next action (DHS):** Watch `sbir2.st.dhs.gov` and SAM.gov (search
"DHS SBIR") for the FY2026 pre-solicitation; the moment topics post, read for an
identity/data-integrity, critical-infrastructure, or AI-assurance topic and email
that topic's author **during the ~2-week pre-release contact window** before the
topic locks.

Submission steps once open:
1. Create/confirm an account on `sbir2.st.dhs.gov`.
2. Read the topic; in the pre-release window, email the named topic author one
   tight question confirming EP's authorization-receipt approach fits.
3. Paste the DHS abstract from `application.md`, bound to the exact topic number,
   into the portal proposal. Keep to the topic's page/word limits (DHS Phase I is
   short; ~30-day turnaround once open).
4. Attach the formal-proof status, conformance results, and the air-gap note.

Pre-register now (don't wait for the topic):
- [ ] SAM.gov entity registration (UEI) — start immediately; 1–2+ weeks.
- [ ] SBA Company Registry.
- [ ] `sbir2.st.dhs.gov` portal account.

---

## NIST SBIR

**Status:** No open NOFO (Jun 2026). Page says it "is currently being updated …
resulting from the reauthorization"; "check back … for when the next SBIR NOFO
will be released."
**Phase I:** ~$100K historically (reauth may raise the cap — confirm in the NOFO).
**Where it posts:** `nist.gov/oam/funding-opportunities` and `grants.gov`
(mechanism is a NOFO/grant, not a contract portal).
**Contact:** `sbir@nist.gov` (program manager).

**Single next action (NIST):** Watch `nist.gov/oam/funding-opportunities` and
`grants.gov` for the FY2026 NIST SBIR NOFO; when it posts, confirm there is an AI
/ trustworthy-AI / measurement-science topic and that the Phase I cap, then submit
the NIST abstract from `application.md` framed as a *measurement primitive* (not a
product). Optionally email `sbir@nist.gov` now to ask the expected FY2026 NOFO
release date and whether AI-measurement topics are planned.

Submission steps once open:
1. Confirm grants.gov registrant role is active for the entity.
2. Pull the NOFO; locate the AI / measurement topic; confirm the Phase I cap.
3. Submit the NIST abstract + four technical objectives from `application.md`,
   leading with the AI RMF measurement-profile framing.
4. Attach the NIST AI RMF mapping, formal-proof status, and conformance results.

Pre-register now:
- [ ] SAM.gov entity registration (shared with DHS) — start immediately.
- [ ] grants.gov registrant role for the entity.
- [ ] SBIR.gov account.

---

## Keep distinct (important)

- **NIST SBIR ≠ NIST AI Consortium.** SBIR is a funded R&D award via grants.gov;
  the Consortium is a CRADA membership via `aiconsortium@nist.gov`
  (see `../nist-aisic/`). Reference the AI RMF mapping in both, but never imply
  one is the other.
- **DHS/NIST SBIR ≠ NSF SBIR.** The NSF Project Pitch (AI7) is already prepared
  in `../nsf-sbir-phase-1/`. The DHS and NIST pitches here are reframed for
  homeland-security accountability and measurement-science respectively — do not
  paste the NSF text into either.

## docs-secrets hostnames to allowlist

`scripts/check-docs-secrets.js` flags real hostnames in `docs/`. These program
hosts appear in this package and should be added to `SAFE_HOSTS` so the check
stays green (some already present — marked):

- `sbir.gov` — **NOT yet in allowlist; add it**
- `grants.gov` — already allowlisted
- `sam.gov` — already allowlisted
- `st.dhs.gov` (covers `sbir2.st.dhs.gov` as a suffix) — **NOT in allowlist; add it**
- `dhs.gov` — **NOT in allowlist; add it**
- `nist.gov` — already allowlisted
- `commerce.gov` — add only if referenced (CAISI parent); not used here yet

> Note: the two pitches in `application.md` write the IETF draft and portals as
> bare names/paths (e.g. `sbir2.st.dhs.gov`, `nist.gov/oam/funding-opportunities`)
> rather than full `https://` URLs, so the hostname regex (which requires an
> `https?://` prefix) does not fire on most of them. Adding the hosts above is
> belt-and-suspenders for any future full-URL edits. See the language-governance
> run note in `application.md`.
