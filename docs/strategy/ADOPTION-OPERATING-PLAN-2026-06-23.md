<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Adoption Operating Plan - 2026-06-23

Purpose: turn the current positioning into adoption. This is not a feature
roadmap. It is the operating plan for getting strangers to try, repeat, require,
or rely on authorization receipts.

## Positioning verdict

The current positioning is strong when it stays narrow:

> Authorization receipts for irreversible actions.

The strongest public line is:

> Decision logs are testimony. Receipts are evidence.

The strongest adoption line is:

> No receipt, no irreversible action.

The weakest line is any broad claim that EMILIA is "the future of trust" without
immediately grounding it in an action, a receipt, and a verifier. "Trust" is the
category vision; "authorization receipt" is the thing people can adopt.

## What to lead with by audience

| Audience | Lead with | Primary ask |
|---|---|---|
| County finance / treasury / program integrity | Vendor bank-account changes and disbursements need proof of who approved them before money moved. | Scope a 60-day observe-mode GovGuard pilot. |
| Internal / external auditors | Verify a receipt offline yourself; absence of a receipt is a finding. | Join a 30-minute auditor verification briefing. |
| Insurers / brokers | The dual-authorization control already required by policy is not machine-verifiable today. EP makes it provable. | Review one insured workflow as a claims-ready evidence pilot. |
| Agent / MCP developers | Your service can answer 428 Receipt Required and let agents self-serve proof. | Add `@emilia-protocol/require-receipt` to one irreversible endpoint. |
| Standards people | EP supplies the human-authorization leg and conformance baseline for the receipt cluster. | Review AEC / conformance vectors; run the harness. |

## Adoption loops

### 1. Reliance loop - the commercial wedge

Goal: one external auditor, insurer, or oversight body relies on a real receipt.

Path:

1. Pick one workflow: vendor bank-account change, disbursement release, benefit
   redirect, caseworker override.
2. Run observe mode: no blocking, only evidence.
3. Produce sample receipts and absence findings.
4. Sit with the auditor and verify a receipt offline.
5. Capture one attributable sentence in writing:

> "[Auditor / office / carrier] independently verified an EMILIA authorization
> receipt and would rely on it as evidence in a controls review."

This is the milestone that makes the company fundable and the standard hard to
dismiss.

### 2. Demand loop - the developer wedge

Goal: one public endpoint, MCP server, or agent tool requires a receipt.

Path:

1. Service refuses an irreversible action with `428 EMILIA Receipt Required`.
2. Agent reads the challenge.
3. Agent obtains or issues an authorization receipt.
4. Agent retries.
5. Service verifies offline and keeps the receipt as evidence.

The runnable proof is already in the repo:

```bash
node examples/402-loop.mjs
```

This is the loop that can spread without EMILIA selling every node.

### 3. Conformance loop - the standards wedge

Goal: make "verifiable" a testable claim across the receipt cluster.

Path:

1. Keep `npm run conformance` as the public bar.
2. Invite external implementers to add runners.
3. Publish EP-AEC as the composition point.
4. Offer the vectors as a neutral baseline, not a proprietary win.

The adoption message is not "use our product." It is "your receipt claim should
pass public negative vectors."

## What to stop doing

- Do not lead with "trust infrastructure" in cold outreach. It is too broad.
- Do not treat AAIF as the adoption path unless there is a narrow, counsel-reviewed
  carve-out. The formal project path risks the trademark and accounts.
- Do not make developer adoption the revenue motion this quarter. Developer
  adoption is legitimacy and distribution; paid pilots create reliance.
- Do not ask prospects to understand the whole EP stack. Ask them to inspect one
  irreversible action.
- Do not make "run a node" the first ask. The first ask is "verify this receipt"
  or "require a receipt here."

## Page and CTA priorities

| Surface | Current role | Recommendation |
|---|---|---|
| Homepage | Broad category and proof | Keep broad, but primary CTAs should point to "Run the crash test" and "Scope a GovGuard pilot." Face ID is impressive, but `crash-test` tells the full auditor story. |
| `/govguard` | Best paid-pilot page | This is the commercial landing page. Keep "Who approved the disbursement?" and the $25K/60-day framing. Add proof of exactly what the auditor receives. |
| `/insurance` | Strong second wedge | Use after GovGuard, especially for brokers and carriers. The hook is "the control you already require is not provable." |
| `/auditors` | Distribution channel | Treat auditors as multipliers. Add an explicit "Bring this to a client's control test" CTA and a downloadable workpaper sample. |
| `/agent-guard` | Developer acquisition | Replace "Start free - get a key" emphasis with "Run the 428 Receipt Required loop" / "Require a receipt in one endpoint." Avoid account creation before proof. |
| `/mcp` | Developer credibility | Keep registry proof, but route serious builders to `@emilia-protocol/mcp-guard` and `require-receipt`, not only the broad MCP server. |

## Metrics

North-star metric:

> External reliance events captured in writing.

Weekly input metrics:

- 20 targeted outreach messages to auditors, county finance, insurers, or MCP tool owners.
- 5 warm-intro asks.
- 2 live receipt-verification demos.
- 1 concrete pilot or integration proposal sent.
- 1 public proof artifact improved: demo, workpaper, conformance vector, guide, or case writeup.

Developer adoption metrics:

- External repos importing `@emilia-protocol/verify`, `issue`, `require-receipt`, or `mcp-guard`.
- Public endpoints returning `428 EMILIA Receipt Required` (legacy 402 remains available for x402/AP2-compatible flows).
- External conformance runners.
- External receipts issued with non-EMILIA keys.

## 14-day operating plan

### Days 1-2: tighten the adoption front door

- Make the homepage developer CTA point to `npx -y @emilia-protocol/crash-test`
  and `node examples/402-loop.mjs`.
- Add a short "Receipt Required in one endpoint" guide linked from `/agent-guard`
  and `/mcp`.
- Add a sample auditor workpaper download linked from `/auditors` and `/govguard`.

### Days 3-5: book reliance conversations

- Send 20 warm or semi-warm messages to county finance, audit, and insurance
  contacts.
- The ask is not "buy EMILIA." The ask is:

> "Would you spend 20 minutes verifying a receipt and telling me whether this is
> evidence you could rely on in a controls review?"

- Track replies by role: auditor, treasurer/controller, insurer/broker, standards,
  developer.

### Days 6-8: convert demos into a scoped pilot

- For any interested government or insurance contact, send the 60-day observe-mode
  pilot scope.
- Require one auditor introduction as part of scope. Without the auditor, the pilot
  may produce usage but not the reliance event.

### Days 9-11: create the first demand-side public proof

- Ask 10 MCP/tool maintainers to put `require-receipt` in front of one irreversible
  demo endpoint.
- Offer to open the PR for them.
- The target is not a large integration. It is one public `428 Receipt Required`.

### Days 12-14: publish the proof trail

- Publish one short post:

> "No receipt, no irreversible action: the Receipt Required loop for agent tools"

- Publish one auditor-facing post:

> "How to verify an authorization receipt in a workpaper"

- Publish one standards-facing update:

> "Authorization Evidence Chain: composing delegation, policy permit, and human
> authorization receipts"

## Outreach snippets

### Auditor / controller

Subject: Could you verify one authorization receipt?

> I am building EMILIA Protocol, an open authorization-receipt standard for
> irreversible AI-agent and payment actions.
>
> The short version: instead of trusting an approval log, an auditor can verify a
> signed receipt offline and prove which named human approved the exact action.
>
> Would you be willing to spend 20 minutes verifying one receipt and telling me
> whether this is evidence you could rely on in a controls review? No sales deck;
> I want the audit read.

### County finance / treasury

Subject: Who approved the vendor bank-account change?

> Vendor bank-account-change fraud usually does not break in; it passes through
> an approved-looking workflow. The hard question six months later is: who
> approved that exact destination before money moved, and can an auditor verify
> it without trusting the payment system's logs?
>
> GovGuard runs in observe mode first: one workflow, 60 days, nothing blocked,
> evidence packet at the end. Would it be useful to scope this around vendor
> bank-account changes or disbursement releases?

### MCP / agent-tool maintainer

Subject: Want to make one dangerous tool require proof?

> I maintain EMILIA Protocol. We have a tiny demand-side middleware:
> `@emilia-protocol/require-receipt`.
>
> If a caller tries an irreversible action without proof, your service returns
> `428 EMILIA Receipt Required`; a well-behaved agent obtains a receipt and
> retries. Offline verifier, no EMILIA backend required.
>
> I would be happy to PR this into one demo endpoint or destructive tool so your
> project can say: no receipt, no irreversible action.

## Objections and responses

| Objection | Response | Proof to show |
|---|---|---|
| "We already have approvals." | Keep them. EP turns the approval into portable evidence a third party can verify. | `npx -y @emilia-protocol/crash-test` |
| "We cannot block production." | Start in observe mode. The first deliverable is a map of what would have needed signoff. | `/govguard`, `/pilot/sandbox` |
| "Why not just logs?" | Logs are controlled by the operator. Receipts verify offline without the operator. | `/auditors`, `@emilia-protocol/verify` |
| "Is this another policy engine?" | No. It composes with OPA/AuthZEN/Permit. After policy says yes, EP proves this exact yes happened. | EP-AEC and `docs/EP-HUMAN-AUTHORIZATION-CLAIM.md` |
| "Is the human identity real?" | A receipt proves the enrolled key signed. Real-world identity proofing is an enrollment layer; state the boundary. | `docs/RECEIPT-CLAIMS.md` |
| "No budget." | Ask for a verification briefing first. The paid ask comes only after they agree the evidence is useful. | `/auditors` |

## Bottom line

The correct adoption sequence is:

1. Get one person outside EMILIA to verify.
2. Get one auditor or insurer to rely.
3. Get one service to require.
4. Get one external implementation to conform.

That is how authorization receipts become infrastructure without EMILIA needing
the world to believe the whole story upfront.
