<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP SEP — submission runbook (copy-paste ready)

*Companion to `MCP-SEP-PACKAGE.md`. That file has the SEP body (Part A), the long
socialization post (Part B), and sponsor targets (Part C). This file is the **operational
layer**: the exact Discord messages, the GitHub PR description, and the fork/PR commands —
verbatim, in order. **You post these** (GitHub + Discord are interactively authenticated).*

**The golden rule from the MCP process:** socialize → land a sponsor → *then* open the SEP
PR. A cold PR with no sponsor goes Dormant in 6 months. So do STEP 1 before STEP 3.

---

## STEP 1 — Socialize in the Security Interest Group (Discord) — do this FIRST

Post message ①. If there's interest, reply with ②. Keep them short — Discord, not essays.

**① Opener (Security IG channel):**

> 👋 Floating an Extensions-Track idea + looking for a sponsor.
> **Gap:** MCP marks dangerous calls with `destructiveHint`, but nothing standardizes a
> *portable, offline-verifiable* proof that a **named human approved an exact irreversible
> tool call** before it ran. Today that's a server log — testimony controlled by the
> acting party — not third-party-checkable evidence.
> **Proposal:** an opt-in **consent → device-bound signoff → authorization-receipt** hook
> for calls annotated irreversible, that **fails closed** (no valid receipt, no execution).
> Composes existing primitives (elicitation for the prompt, `destructiveHint` for the
> signal) and *references* an open receipt format instead of reinventing one.
> There's a working reference impl, JS/Python/Go offline verifiers, and conformance
> vectors I can port. Apache-2.0, not a vendor pitch — goal is one interoperable
> consent+evidence hook for the ecosystem. **Is this a fit for the Security IG, and would a
> maintainer be open to sponsoring?** Happy to bring the draft SEP + a 60-sec demo.

**② Follow-up (when someone bites):**

> Reference impl: `@emilia-protocol/mcp-guard` wraps a tool dispatcher — classify
> reversible vs irreversible (honors `destructiveHint`/`readOnlyHint`) → consent → signoff
> → receipt, else returns Receipt Required (HTTP 428, with legacy 402 compatibility). Offline verifiers in JS/Python/Go;
> the receipt format is a published IETF I-D (`draft-schrock-ep-authorization-receipts`),
> but the SEP fixes just the *hook + semantics* — the format stays swappable.
> Demo: `npx @emilia-protocol/issue demo` issues a receipt and verifies it offline in ~60s.
> Draft SEP: <link once the PR is up>.

---

## STEP 2 — Get the SEP file ready (fork + branch)

```bash
# 1. Fork modelcontextprotocol/modelcontextprotocol on GitHub, then:
git clone git@github.com:<your-user>/modelcontextprotocol.git
cd modelcontextprotocol
git checkout -b sep-consent-authorization-receipt

# 2. Create the SEP file from Part A of MCP-SEP-PACKAGE.md:
#    seps/0000-consent-authorization-receipt.md
#    (paste Part A verbatim; keep Status: Draft (Awaiting Sponsor), Type: Extensions Track)

git add seps/0000-consent-authorization-receipt.md
git commit -s -m "SEP: Consent + Authorization Receipt for irreversible tool calls (Extensions Track)"
git push -u origin sep-consent-authorization-receipt
```

---

## STEP 3 — Open the SEP PR (after Step 1 has interest)

Open a PR from your branch against `modelcontextprotocol/modelcontextprotocol:main`.
Use this as the **PR description**:

> ## Consent + Authorization Receipt for irreversible tool calls (Extensions Track)
>
> **Gap:** MCP standardizes tool discovery, OAuth, and elicitation — but not the
> highest-stakes moment: when an **irreversible** tool call runs (payment release, vendor
> bank-detail change, delete, deploy), there's no portable, interoperable way to prove a
> **named human authorized that exact call** before it executed. `destructiveHint` (SEP-973)
> marks the danger; nothing standardizes what happens at the call or what verifiable
> artifact it leaves. Today that proof is a server log — testimony controlled by the acting
> party — not third-party-verifiable evidence.
>
> **Proposal (opt-in, Extensions Track, fail-closed):** when a tool annotated irreversible
> is about to run and both sides negotiated the capability, the host obtains consent from a
> *named* approver (via elicitation), takes a **device-bound signoff** over the canonical
> tool-name + args hash, and emits a **portable authorization receipt** alongside the
> result that anyone can verify **offline**. No valid receipt → the call doesn't run.
>
> **Composes, doesn't reinvent:** elicitation (SEP-1330/1036) for the prompt;
> `destructiveHint` (SEP-973) for the signal; an open IETF receipt format
> (`draft-schrock-ep-authorization-receipts`) referenced, not mandated — the SEP fixes the
> hook + semantics, the format stays swappable.
>
> **Prototype (satisfies the SEP prototype bar):** `@emilia-protocol/mcp-guard` (dispatcher
> middleware), offline verifiers in JS/Python/Go, runnable conformance vectors, and a
> `npx @emilia-protocol/issue demo` that issues + verifies a receipt offline in ~60s.
>
> **Conformance:** for the observable behavior (fail-closed on missing/invalid receipt;
> receipt verifies offline) I can port a scenario + `sep-NNNN.yaml` traceability file into
> the conformance repo.
>
> **Backward compatible:** opt-in/negotiated; read-only & reversible calls untouched; clients
> that don't advertise the capability are unaffected.
>
> **Honest scope:** Apache-2.0, not a vendor pitch. A fully compromised host can lie about
> what it displayed (the WYSIWYS residual) — out of scope, addressed by device/TEE
> attestation a layer below. Offline verification proves authenticity + binding, not
> currency; one-time-use is relying-party state.
>
> **Seeking a sponsor** (Security IG). Tagging @<sponsor> — does this fit your lane?

After the PR number is assigned: rename `seps/0000-...md` → `seps/<PR#>-consent-authorization-receipt.md`,
update the `PR:` field in the SEP header, and push.

---

## STEP 4 — Tag the sponsor

In the PR (and a one-line nudge in the Security IG channel):

> **③ Sponsor tag:**
> @Den Delimarsky (cc Security IG) — this sits in the authorization/security lane you
> co-lead; would you be open to sponsoring, or pointing me to the right maintainer? PR: <link>

Targets in order: **Den Delimarsky** (Lead Maintainer, Security IG co-lead, authz-spec
co-author — best fit) → the **Security IG** as a group → **David Soria Parra** (Lead
Maintainer) → **Clare Liguori** (Core Maintainer, AWS). Tag 1–2, not everyone.

**If no response in ~2 weeks**, post in `#general`:

> **④ Fallback:**
> Bump: Extensions-Track SEP for a fail-closed consent + authorization-receipt hook on
> irreversible tool calls — prototype + conformance vectors ready, looking for a sponsor.
> PR: <link>. Is there a maintainer whose lane this fits?

---

## After sponsorship
Sponsor sets status → `draft` → informal review (PR comments) → `in-review` → Core Maintainer
review (every 2 weeks) → `accepted` → finalize with reference impl + merged conformance
scenario → `final`. Port the conformance scenario early — it surfaces normative-language
ambiguities cheaply.

**Links:** SEP guidelines `modelcontextprotocol.io/community/sep-guidelines` ·
maintainers `…/blob/main/MAINTAINERS.md` · conformance `github.com/modelcontextprotocol/conformance` ·
SEP body + sponsor plan: `docs/strategy/MCP-SEP-PACKAGE.md` · source proposal:
`docs/strategy/MCP-CONSENT-RECEIPT-PROPOSAL.md`.
