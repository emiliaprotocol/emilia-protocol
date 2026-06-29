# First list email — "building in public" (draft)

Send once the waitlist has names. Founder voice, honest, no pitch. Paste into your
email tool (Buttondown / ConvertKit / plain Gmail BCC for the first handful).

---

## Subject line — pick one
1. Who approved that? — building EMILIA in public
2. An agent moved the money. Who signed off?
3. The accountability layer for AI agents — where it actually stands

## Preview text
No pitch — the honest state of what I'm building, and three small ways you can shape it.

---

## Body

Hey — thanks for putting your name down. You're one of the first here, so here's the honest state of what I'm building and why.

**The problem.** AI agents are starting to *act*, not just answer — moving money, changing records, deploying code. When one does something irreversible, there's a question nobody can answer cleanly: *who approved this?* Logs tell you what happened; they don't **prove** a named human authorized this exact action before it ran.

**What EMILIA is.** An open protocol for **authorization receipts** — cryptographic, offline-verifiable proof that a named human approved an exact, irreversible agent action *before* it executed. Not another model. Not a guardrail that *might* catch something after the fact. A receipt anyone can verify — forever, with open-source code and a public key — without trusting the system whose conduct is in question. OAuth answered *who are you*; this answers *who approved this*.

**Where it actually is** — and I'll be straight: I'm one founder, pre-revenue, no customers yet.
- A published **IETF Internet-Draft** (draft-schrock-ep-authorization-receipts).
- A **formally verified** core — 26 TLA+ safety properties (0 errors across 413,137 states) and 22 Alloy assertions (0 counterexamples), re-checked on every change.
- **Verifiers in JavaScript, Python, and Go.** `npm install @emilia-protocol/verify` and you can check a receipt today.
- I **red-teamed** the agent guard with six independent attacks, found three real bugs, fixed all three, and locked them down with a test that re-runs every attack on every change.

**What's next.** A 60-day observe-mode pilot with a government finance office — the first place a missing approval is a *statutory* problem, not just a bad day — and pushing the standard forward at the IETF.

That's it. No ask for money, no demo to book. If the problem resonates, three things help more than you'd think:

1. **Reply** and tell me where *you'd* want an agent to need a human's signature before it acts. It directly shapes what I build.
2. **Try the verifier** — `npm i @emilia-protocol/verify` — or read the essays at emiliaprotocol.ai/essays.
3. **Forward this** to one person who's uneasy about agents touching real money or real records.

I'll only email when there's something genuinely worth your time. Thanks for being early — it matters more than you know.

— Iman
Founder, EMILIA Protocol
emiliaprotocol.ai

*P.S. If you want the technical version: every receipt is a device-bound signature over the exact action, verifiable offline. The signature is the thing that proves it — not me, and not a server you'd have to trust.*

---

### Notes for sending
- For the first ~20 names, plain Gmail (BCC, or individual where you can) feels more personal than a blast tool — and avoids deliverability flags on a new sending domain.
- Send from your domain (team@emiliaprotocol.ai), not gmail, with SPF/DKIM/DMARC set.
- Keep one clear link max in the body; more links hurt deliverability on a young domain.
- Honesty guardrails held: "authorization receipt", "the receipt proves" (never "EMILIA proves"), 26 TLA+ / 22 Alloy, no customers/pre-revenue, solo founder.
