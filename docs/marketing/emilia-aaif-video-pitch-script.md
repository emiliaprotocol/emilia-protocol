<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA - AAIF video pitch

Audience: Manik Surtani (AAIF CTO) and the Technical Committee.

Goal: under five minutes, ideally around three. Show the space, name the void, prove the live loop, touch the broader surfaces, and ask for an early non-binding read on fit.

Tone: calm, technical, no hype. Present a primitive, not a company pitch.

Recording cockpit:
- `/aaif-video-pitch` - landscape gap, stack placement, proof cards, closing card
- `/standards` - IETF landscape map
- `/try/receipt-required` - live attack sequence
- `/quorum` - multi-party / two-person rule surface
- `/human-control` - defense and public-sector human-control surface
- `/fire-drill/registry` - MCP registry index
- `/fire-drill/rr-1` - RR-1 maintainer credential

## Three-Minute Take

| Time | On screen | Voiceover |
|---|---|---|
| 0:00-0:25 | `/aaif-video-pitch` hero | "Hi Manik - thanks again for taking a look. The short version is this: the agent stack is filling in around identity, tools, execution, and logs. But when an agent takes an irreversible action, the middle question is still open: who authorized this exact action before it ran?" |
| 0:25-0:55 | Landscape gap card | "There are many good efforts around the perimeter: MCP for tools, identity and workload drafts, attestation and transparency logs, frameworks and AGENTS.md for execution and guidance. EMILIA is not trying to replace those. It fills the black void in the middle: portable, offline-verifiable proof that a named human authorized the exact irreversible action." |
| 0:55-1:20 | Stack placement card | "So the shape is simple. MCP connects. goose executes. AGENTS.md guides. EMILIA is the receipt layer between intent and mutation. Decision logs are testimony. Receipts are evidence." |
| 1:20-2:20 | Switch to `/try/receipt-required`; click `Launch attack sequence` | "Here is that primitive live. No receipt - blocked. A named human signs the exact action. With the receipt, it runs once. Replay the same receipt - blocked. Tamper with the signed action - rejected. Then it exports a portable evidence packet anyone can verify offline. That is the invariant: no receipt, no execution; if it runs, the proof travels." |
| 2:20-2:55 | Back to `/aaif-video-pitch`, higher-stakes + proof cards | "The same spine extends upward. Single approval for ordinary high-risk actions. Quorum for the two-person rule - M-of-N or ordered approvals. Human-control profiles for defense and public-sector oversight, mapped carefully to DoD 3000.09, EU AI Act Article 14, and NIST AI RMF. And it is built: active individual Internet-Draft, Apache-2.0, JS/Python/Go verifiers, thousands of tests, TLA+ and Alloy checks, and a local no-account demo with npx." |
| 2:55-3:15 | SCITT composition proof | "For transparency systems, the composition is concrete. The EP receipt can ride as a SCITT Signed Statement: COSE Sign1, SCRAPI registration, and a reproducible register-to-receipt-to-verify path in CI. SCITT proves the statement was logged; EMILIA proves who authorized the action." |
| 3:15-3:40 | Ecosystem proof card or `/fire-drill/registry` | "For adoption, we also started the MCP fire-drill path: about 43,800 registry entries scanned, roughly 10 percent advertising high-risk capability, and RR-1 as the maintainer credential. It is not a shame label; it is a path to make dangerous MCP actions safer than the default." |
| 3:40-4:00 | Closing card | "The ask is modest: an early, non-binding technical read on fit. This composes with MCP, goose, and AGENTS.md. If this is the missing human-authorization layer the agent ecosystem needs, I would value your guidance on where it belongs." |

## Five-Minute Version

If the three-minute take feels rushed, give the live attack sequence another 45 seconds and briefly open `/standards`, `/quorum`, and `/human-control` as proof that the page is not hand-waving. Keep the same order.

## Recording Notes

- The best moment is still the live attack sequence. Let the tamper/signature-fails beat breathe.
- Do not over-explain every surface. Touch them, show they exist, then return to the receipt primitive.
- Use a small webcam bubble if it helps the relationship feel warmer, but do not let it cover the attack chain or evidence packet.
- Keep the standards claim precise: active individual Internet-Draft, not IETF standard or endorsement.
- Keep the SCITT claim precise: EP-SCITT profile plus reproducible mock transparency verification, not official SCITT WG conformance until a real returned SCITT Receipt is verified against service parameters.
- Keep named-server claims careful: the registry is a high-risk advertising signal, not a vulnerability report.
- If you need a shorter take, cut the ecosystem section and end around 3:50.

## Lower Third

`draft-schrock-ep-authorization-receipts / Apache-2.0 / JS-Python-Go verifiers / offline-verifiable`

## End Card

Decision logs are testimony. Receipts are evidence.

team@emiliaprotocol.ai

https://github.com/emiliaprotocol/emilia-protocol
