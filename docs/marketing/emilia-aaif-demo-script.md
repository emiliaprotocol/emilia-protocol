<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA — 60-second demo video script (AAIF TC)

**Goal:** show the require-receipt loop end-to-end: an irreversible agent action is
refused without a receipt, runs only with a valid exact-action receipt, and resists
replay + tampering — verifiable offline, no backend.

**Two ways to shoot it** (either works; the live page is fastest):
- **A — live page:** screen-record `https://www.emiliaprotocol.ai/try/receipt-required`
- **B — terminal:** screen-record `npx @emilia-protocol/issue demo` (no account/backend)

---

### Shot list (~60s)

| t | On screen | Voiceover (one line) |
|---|---|---|
| 0–6s | Title: "An AI agent tries to move money." | "An agent is about to take an irreversible action — release funds." |
| 6–16s | Click **Run without receipt** → `428 Receipt Required` | "With no authorization receipt, the gate refuses it. 428. No receipt, no execution." |
| 16–28s | Click **Sign the exact action** → receipt appears (EP-RECEIPT-v1) | "A named human signs the exact action on their device. Ed25519 over canonical JSON — offline, no backend." |
| 28–38s | Click **Retry with receipt** → action **runs**, evidence packet shown | "Now it runs — and exports a portable evidence packet anyone can verify." |
| 38–48s | Click **Replay same receipt** → `refused: replay` | "Replay the same receipt? Refused. One receipt, one action." |
| 48–58s | Click **Tamper** (change amount) → `refused: signature` | "Change a single field — the amount — and the signature fails. Tamper-evident." |
| 58–60s | End card: "Decision logs are testimony. Receipts are evidence." + repo URL | "Decision logs are testimony. Receipts are evidence." |

### Notes
- Keep it one continuous take; the page state transitions are the story.
- Lower-third once: `draft-schrock-ep-authorization-receipts · Apache-2.0 · JS/Py/Go verifiers`.
- No claims beyond the demo: it's a reference implementation, not a vulnerability report.
