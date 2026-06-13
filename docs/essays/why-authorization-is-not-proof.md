# Why Authorization Is Not Proof

**Date:** 2026-06-12
**Author:** Iman Schrock

There is a question every access-control system answers well, and a different question almost none of them answer at all. The gap between those two questions is where most damaging fraud lives, and it is the gap EP exists to close.

The first question is: *may this happen?* An agent, a user, a service presents itself; a policy is evaluated; the answer is allow or deny. This is the decision-time question, and the industry is genuinely good at it. OpenID AuthZEN went final in March 2026 with a clean API for exactly this — a decision endpoint that returns a verdict. OPA and Cerbos are excellent policy engines that answer it thousands of times a second. None of this is a weakness. Decision-time authorization is a solved, mature, well-served problem, and I would not try to compete with it. EP sits next to it, not against it.

But notice what the answer to *may this happen?* actually is. It is a verdict, computed at a moment, by the operator's own engine, against the operator's own policy. It is a yes. And then, a fraction of a second later, the yes is gone. What remains is whatever the operator chose to write down.

That brings the second question, which almost nobody answers: *afterward, who can prove what was authorized, and by whom?*

The usual answer is a log. The policy engine emits a decision log; the approval tool records a row; the database persists an entry that says "user jchen approved wire #8841 at 17:24." This feels like proof. It is not. It is testimony.

I want to be exact about the difference, because the whole argument rests on it.

A log is a statement by the operator about what the operator did. It lives in a database the operator controls. It is mutable in custody — not necessarily tampered, but tamperable, and indistinguishable to an outside party from one that has been. It is unsigned, or signed only by the operator, which means it proves the operator's assertion and nothing more. And it dies with the vendor: when the SaaS sunsets, the company is acquired, or the contract ends, the auditability of those past decisions depends entirely on the operator's continued cooperation. Ask anyone who has tried to retrieve a decision log from a vendor three years after the relationship ended. The log was real. It is also gone.

The deeper problem is structural. When a regulator, a counterparty, or an auditor asks "was this action authorized?", the log answers in the voice of the party whose conduct is under examination. The operator produces evidence about the operator — self-attestation. We tolerate it in software only because, until recently, there was no alternative.

Evidence is a different kind of object, and the difference is not rhetorical. Evidence is portable: it travels with the action, not the vendor. It is signed by the party whose accountability is actually at stake — a named human — not by the system that orchestrated them. It is third-party-verifiable: anyone can check it, with mathematics, without trusting or even contacting the issuer. And it binds. Specifically, it binds a named human's user-verified signoff to the exact action hash, before execution.

That last sentence is the entire protocol, so let me unpack it the way the spec does.

*A named human.* Not a service account, not an API key, not "the system." A person, holding a key that the operator does not possess and cannot forge — a device-bound WebAuthn credential, exercised with a biometric or PIN. The operator orchestrates the request; it cannot produce the signature. That is the line that separates a receipt from a log: in a log, the operator writes the record; in a receipt, the operator literally cannot.

*The exact action hash.* The signature covers a canonical representation of one operation with concrete parameters — this amount, this beneficiary, this target. Change a digit and the receipt fails to verify. The approval cannot drift to a different action, because it was never about an action in the abstract; it was about these exact bytes.

*Before execution.* This is pre-authorization, not after-the-fact reconstruction. The human says yes to a specific thing, and only then does the thing run, and only once.

Here is the line I keep coming back to, because it is the whole thesis in five words: **decision logs are testimony; receipts are evidence.** A log records what the operator says happened. A receipt is something a named human signed, that anyone can verify, that survives the operator. One is an assertion. The other is proof.

I want to be careful not to overclaim, because overclaiming is how trust infrastructure loses the room. A receipt does not prove the decision was wise, or that the policy was adequate, or that the human was not coerced. It does not prove the signing screen showed the action honestly — that is a real and serious risk, and EP names it in the spec rather than papering over it. What a receipt proves is narrow and exact: this key, enrolled to this named approver, produced a user-verified signature over this exact action, under this policy, before it ran, recorded in an append-only log anyone can check offline. That is less than "we caught all fraud." It is also vastly more than "trust our database." The honest claim is the durable one.

None of this is a thought experiment. The verifier is published, it has zero dependencies, and three independent implementations — JavaScript, Python, and Go — are proven to agree on the adversarial vectors on every push. You can run it yourself, offline, no account, no API key:

```bash
npx @emilia-protocol/verify receipt.json
```

That command contacts nothing. It does math on a file. If it says valid, a named human signed that exact action and the receipt is in the log; if it says invalid, something was forged or altered. That is the whole point of evidence: you do not have to trust me to check it.

I also want to be honest that EP is not alone, and does not need to be. The delegation-receipts work — DRP, `draft-nelson-agent-delegation-receipts` — answers the upstream half — a user's delegation to an operator — where EP answers the downstream half, an organizational approver to an exact action; it is one of the four efforts mapped in the cross-draft survey now in front of the IETF secdispatch list, precisely because these compose. CHEQ is converging on human confirmation of agent actions from the OAuth side. Receiver-attested approaches like Sello prove what *happened* after the fact, where EP proves what was *authorized* before. The right posture here is convergence at the IETF, not category ownership. We are all circling the same realization at the same time: in a world where agents hold credentials sufficient to move money and delete data, the operator's word is no longer enough, and the artifact that replaces it has to be one a stranger can verify.

If you want the precise version of all of this — the action object, the key classes, the offline verification algorithm, the security considerations stated without minimization — it is in the Internet-Draft: `draft-schrock-ep-authorization-receipts`. Read §11 especially. The honesty there is the product.

The shift is simple to state and hard to internalize: stop asking the system to remember what it did, and start asking the human to sign what they approved. The first gives you a log. The second gives you proof.
