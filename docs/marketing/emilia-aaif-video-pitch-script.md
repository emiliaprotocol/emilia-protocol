<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA — AAIF video pitch

Audience: Manik Surtani (AAIF CTO) and the Technical Committee.
Goal: under five minutes, ideally ~4:30. Name the gap, prove the live loop, show the composition and the higher-stakes spine, ask for a non-binding read on fit.
Tone: calm, technical, no hype. A primitive, not a company pitch.

This script is matched 1:1 to the live page at `/aaif-video-pitch`. Read the teleprompter top to bottom; the `[bracketed]` cues are the on-screen section you should be on (the page's own headings), not spoken.

## Recording cockpit (page sections, in order)

| Anchor | On-screen eyebrow / heading | Click |
|---|---|---|
| hero | EMILIA FOR AAIF — "The missing human-proof layer for agent actions." | — |
| `#gap` | THE LANDSCAPE GAP / WHERE IT SITS — "A small layer between intent and mutation." | Open standards map → `/standards` |
| `#demo` | LIVE DEMO — "Try to break the action layer." | Open live demo → `/try/receipt-required` |
| `#scitt` | SCITT COMPOSITION PROOF — "An authorization receipt can ride as a SCITT Signed Statement." | SCITT profile · Harness |
| `#surfaces` | HIGHER-STAKES SURFACES — "…use the same receipt spine." | (`/quorum`, `/human-control` if you open them) |
| (ECOSYSTEM PROOF) | "The maintainer path is a badge, not a scold." | Registry index → `/fire-drill/registry` · RR-1 page |
| `#ask` | THE ASK — "…where should it belong?" | Open I-D / datatracker draft |

## Teleprompter — read straight through (~4:30)

`[hero — "The missing human-proof layer for agent actions."]`
Hi Manik — thanks again for taking a look. Here's the short version. The agent stack is filling in fast: identity, tools, execution, logs. But when an agent takes an irreversible action, one question is still unanswered — who authorized this exact action before it ran? That's the layer EMILIA fills.

`[#gap — THE LANDSCAPE GAP]`
There's a lot of good work around the perimeter — MCP for tools, identity and workload drafts, attestation and transparency logs, frameworks and AGENTS.md for execution. Many drafts describe the stack. The missing primitive is proof of human authorization.

`[#gap — WHERE IT SITS]`
EMILIA isn't trying to replace any of it. It's a small layer that sits between intent and mutation. MCP connects, goose executes, AGENTS.md guides — EMILIA is the receipt between the decision and the change. Decision logs are testimony; receipts are evidence.

`[switch to /try/receipt-required — #demo "Try to break the action layer." Run it, let each beat land]`
Here it is live — let's try to break the action layer. No receipt: blocked. A named human signs the exact action; with the receipt, it runs — once. Replay the same receipt: blocked. Tamper with the signed action: rejected. Then it exports a portable evidence packet anyone can verify offline. That's the whole invariant — no receipt, no execution; and if it runs, the proof travels.

`[#scitt — SCITT COMPOSITION PROOF]`
For transparency systems, the composition is concrete. An EMILIA receipt can ride as a SCITT Signed Statement — COSE Sign1, SCRAPI registration, and a reproducible register-to-receipt-to-verify path in CI. SCITT proves the statement was logged; EMILIA proves who authorized it. Two artifacts that compose — neither replaces the other.

`[#surfaces — HIGHER-STAKES SURFACES]`
The same receipt spine scales up. Single approval for ordinary high-risk actions. Quorum for the two-person rule — M-of-N or ordered approvals. And human-control profiles for defense and public-sector oversight, mapped carefully to DoD 3000.09, EU AI Act Article 14, and NIST's AI RMF. One spine underneath all of it. And it's real: an active individual Internet-Draft, Apache-2.0, verifiers in JavaScript, Python, and Go, thousands of tests, plus TLA+ and Alloy checks.

`[ECOSYSTEM PROOF — "a badge, not a scold."]`
For adoption, we started the MCP fire-drill: scanning the public registry for servers that let an agent take a dangerous action with no receipt, and offering RR-1 as a maintainer credential. It's a badge, not a scold — a path to make dangerous MCP actions safer than the default.

`[#ask — THE ASK]`
So the ask is modest — an early, non-binding technical read on fit. This composes with MCP, goose, and AGENTS.md. If this is the missing human-authorization layer the agent ecosystem needs, I'd value the Technical Committee's guidance on where it belongs. Thanks, Manik.

`[end card: "Decision logs are testimony. Receipts are evidence."]`

## If you need to trim to ~3:00

Cut the ECOSYSTEM PROOF beat and shorten SURFACES to one line ("the same spine covers single approval, quorum, and human-control profiles"). Keep the live demo full-length — it's the moment that lands.

## Recording notes

- The live attack sequence is the centerpiece. Let the tamper / signature-fails beats breathe.
- Touch each surface, show it exists, return to the receipt primitive. Don't over-explain.
- A small webcam bubble warms the relationship — but never let it cover the attack chain or the evidence packet.
- Keep the standards claim precise: an **active individual Internet-Draft**, not an IETF standard or endorsement.
- Keep the SCITT claim precise: an **EP–SCITT profile plus reproducible mock-transparency verification in CI** — not official SCITT WG conformance until a real returned SCITT Receipt is verified against a service's parameters.
- Keep the registry claim careful: a **high-risk advertising signal**, not a vulnerability report.

## Lower third

`draft-schrock-ep-authorization-receipts · Apache-2.0 · JS / Python / Go verifiers · offline-verifiable`

## End card

Decision logs are testimony. Receipts are evidence.

team@emiliaprotocol.ai
https://github.com/emiliaprotocol/emilia-protocol
