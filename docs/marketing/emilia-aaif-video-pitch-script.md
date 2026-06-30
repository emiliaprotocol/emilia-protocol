<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA - AAIF video pitch

Audience: Manik Surtani (AAIF CTO) and the Technical Committee.

Goal: under five minutes. Name the gap, show the live attack sequence, prove the primitive is real and small, and ask for an early non-binding read on fit.

Tone: calm, technical, no hype. Present a primitive, not a company pitch.

Recording cockpit:
- `/aaif-video-pitch` - title card, layer card, proof cards, closing card
- `/try/receipt-required` - live attack sequence
- `/fire-drill/registry` - MCP registry index
- `/fire-drill/rr-1` - RR-1 maintainer credential

## Shot List

| Time | On screen | Voiceover |
|---|---|---|
| 0:00-0:25 | `/aaif-video-pitch` title card | "Hi Manik - thanks again for taking a look. Quick frame: agents are moving past chat into actions that do not have an undo. Moving money. Deleting a repository. Changing a payout account. MCP is how they connect to those tools. But MCP does not answer one question, and neither does the rest of the stack by default." |
| 0:25-0:55 | Layer card | "MCP governs how an agent connects. goose governs how it executes. AGENTS.md guides local behavior. The open question is: when the action is irreversible, what artifact proves a named human authorized that exact action before it ran? That is the layer we built. Decision logs are testimony. Receipts are evidence." |
| 0:55-1:10 | Switch to `/try/receipt-required`, actuator locked | "Here is the whole idea in one screen. An agent is about to release 250,000 dollars. Watch what the gate does. I will try to break it." |
| 1:10-2:35 | Click `Launch attack sequence` and narrate the states | "No receipt - blocked. 428 Receipt Required; the mutation never reaches the system. Now a named human signs the exact action on their device: Ed25519 over canonical JSON, verifiable offline. With that receipt, it runs once. Replay the same receipt - blocked. It is one-time. Now I tamper with the signed action - the signature no longer verifies. Finally it exports a portable evidence packet anyone can verify offline. Blocked, signed, allowed once, blocked, rejected, exported." |
| 2:35-3:25 | `/aaif-video-pitch` real-and-small card, optionally repo/npm | "This is not a slide. EMILIA is an Apache-2.0 reference implementation with an active individual Internet-Draft, draft-schrock-ep-authorization-receipts. The reference verifiers in JavaScript, Python, and Go agree on shared conformance vectors. The core protocol invariants are modeled in TLA+ and Alloy and checked in CI. And the local check is small: no account, no backend - npx @emilia-protocol/issue demo." |
| 3:25-4:05 | `/fire-drill/registry`, then `/fire-drill/rr-1` | "We scanned the public MCP registry: about 43,800 servers. Roughly 10 percent advertise a high-risk capability: moving money, deleting or exporting data, deploying infrastructure, or changing permissions. So we made a maintainer credential, RR-1: wrap your most dangerous action, prove missing receipt is blocked, valid receipt runs once, replay is refused, and forgery is refused. It is a path to adoption, not a vulnerability label." |
| 4:05-4:30 | Closing card | "The ask is deliberately modest: an early, non-binding technical read on fit. This composes with MCP, goose, and AGENTS.md; it is Apache-2.0; and any asset or governance conversation is much later than this. If this is the human-authorization layer the agent ecosystem is missing, I would value your guidance on where it belongs. Thank you." |

## Recording Notes

- The best moment is the live attack sequence. Let the tamper/signature-fails beat breathe.
- Use a small webcam bubble if it helps the relationship feel warmer, but do not let it cover the attack chain or evidence packet.
- Keep the standards claim precise: active individual Internet-Draft, not IETF standard or endorsement.
- Keep named-server claims careful: the registry is a high-risk advertising signal, not a vulnerability report.
- If you need a shorter take, cut the ecosystem section and end around 3:50.

## Lower Third

`draft-schrock-ep-authorization-receipts / Apache-2.0 / JS-Python-Go verifiers / offline-verifiable`

## End Card

Decision logs are testimony. Receipts are evidence.

team@emiliaprotocol.ai

https://github.com/emiliaprotocol/emilia-protocol
