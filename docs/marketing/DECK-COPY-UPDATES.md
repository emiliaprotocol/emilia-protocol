<!-- SPDX-License-Identifier: Apache-2.0 -->
# Deck & one-pager copy updates (2026-06-22)

The `emilia-seed-deck.pdf` and `emilia-investor-onepager.pdf` have **no source files
in this repo** (built in a design tool), so they can't be regenerated here. These are
**paste-ready** blocks to drop into them. All claims are honest as of 2026-06-22.

> **Timing flag — the reliance event:** an outside implementer independently verified
> EP this week. Use it in **private/investor** materials now. Keep it out of **public**
> marketing until that implementer posts their own note (don't front-run their statement).

---

## 1. Replace stale metric lines

- "3 cross-language suites" / "receipts · signoffs · quorum" →
  **"8 cross-language conformance suites — JS / Python / Go agree (receipts, signoffs,
  multi-party quorum, revocation, time-attestation, trust-receipt, provenance, long-term
  evidence records)."**
- Any `@emilia-protocol/verify` version pin → drop the pin or use **1.6.0**.

## 2. New slide — "We didn't enter a crowded field. We became its center."
> A dozen-plus IETF drafts now define "a signed receipt about an agent's action" —
> delegation, policy-permit, decision, compliance, route-authorization. They all
> converged on the same substrate (canonical action digest + signature). **None composes
> them, and only EP binds an accountable human.**
>
> EP authored **EP-AEC (Authorization Evidence Chain)**: the thin layer that verifies, for
> one action, that the delegation receipt + the policy permit + the human authorization all
> bind the *same* action and each verify — one offline ALLOW/DENY. Implemented in three
> languages with conformance vectors.
>
> **EP is the convergence point of the agent-authorization field, and the only one with the
> human leg.**

## 3. New slide — "Independently verified" (investor deck only, for now)
> The binding question for any verifiability claim is: *has anyone outside the team checked
> it?* In June 2026, an independent implementer ran our public crash-test and cross-language
> conformance harness on their own machine — offline receipt verification, forged-copy
> rejection, and JS/Python/Go agreement all confirmed. **The first external reliance event.**

## 4. New slide / TAM addition — "Healthcare"
> EP's two-person rule is **already mandated practice** in healthcare: the ISMP / Joint
> Commission **independent double-check** for high-alert medications. EP turns that
> attestation into tamper-evident, offline-verifiable evidence — and the receipt is
> **PHI-free by construction** (hashed identifiers only). The same primitive covers capital
> procurement (dual control; kills payment-redirect fraud) and answers **EU AI Act Article 14**
> human-oversight for high-risk medical AI.
>
> **Go-to-market: the healthcare-AI vendors and procurement platforms embed EP (B2B2H) —
> not direct hospital sales.** Demo: `npx -y @emilia-protocol/crash-test --scenario clinical`.

## 5. Updated investor one-liners (add)
- "A dozen efforts are racing to define a receipt for an agent's action. EP defined the
  layer that **composes them** — and supplies the one leg none of the others do: a named
  human's authorization."
- "The two-person rule isn't a feature we invented — it's mandated practice in healthcare
  and finance. EP makes it **verifiable**."

## 6. One-pager footer / proof strip
> Open standard (Apache-2.0) · IETF Internet-Drafts (receipts, quorum; evidence-chain
> forthcoming) · 3 interoperable verifiers over 8 conformance suites · independently
> re-verified · machine-checked TLA+ & Alloy · `npx @emilia-protocol/crash-test`
