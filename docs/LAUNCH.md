# The Trust Layer the Internet Forgot

**EMILIA Protocol — EP-001**
**Published:** 2026-03-18
**Status:** Open Standard, v1.0

---

## The Problem We Are Here to Solve

Every AI agent starts from zero.

Not metaphorically. Literally. When an agent is instantiated to handle a purchase, route a task, or authorize a connection to a software tool, it has no memory of prior counterparties, no portable record of prior outcomes, and no principled way to assess whether the entity in front of it has ever honored a commitment before. It operates in a permanently amnesiac present.

This is not an engineering oversight. It is a design gap — one inherited from the internet itself, which also launched without a behavioral memory layer, and which papered over that absence with a succession of workarounds: platform reviews, star ratings, opaque algorithmic trust signals, and institutional credit scores. Those workarounds became infrastructure. Infrastructure became capture. Whoever controlled the trust signal controlled the market.

The human internet survived this because humans operate at human pace. A fraudulent merchant can be written up in a forum, disputed through a payment processor, and eventually delisted. The feedback loop is slow, but it exists.

AI agents do not operate at human pace. An agent can execute thousands of transactions before any human reviews an outcome. When agents are routing work to other agents — orchestrating pipelines, delegating subtasks, authorizing tool connections — the graph of accountability becomes too deep and too fast for any after-the-fact audit to catch failures in time.

The consequence is compounding: trust errors in machine-mediated systems compound faster than human systems can correct them. And the systems being built today — agent frameworks, MCP tool ecosystems, agentic commerce platforms — are being built on exactly the same absent trust foundation that the 1990s web was built on, with the sole difference that the velocity of transactions is orders of magnitude higher.

We are building those systems without a trust layer. EMILIA Protocol is that layer.

---

## What We Built

EP is not a product. It is infrastructure.

The distinction matters. A product optimizes for a customer segment, iterates toward retention, and competes on features. Infrastructure becomes load-bearing. It either gets adopted widely enough to disappear into the plumbing, or it doesn't get adopted at all.

EP is designed to disappear into the plumbing of the AI agent ecosystem the way SSL/TLS disappeared into the plumbing of the web. You do not think about TLS when you load a page. You do not negotiate it. You do not configure it per site. It runs. Somewhere beneath the application layer, a trust handshake occurred, and you proceed.

That is what EP does for agents. Before a transaction proceeds, a trust evaluation occurs. The evaluating agent queries an EP-conformant registry for the counterparty's Trust Profile. It runs that profile against a declared Trust Policy. It gets a structured pass/fail with specific failure reasons. It decides whether to proceed. The entire exchange takes milliseconds and produces a permanent, auditable record.

**EP is behavioral memory for the AI age.** It answers the question that no other protocol currently answers: given everything observable about how this entity has behaved in prior interactions, should you extend it trust for this one?

The answer is not a number. A number is a conclusion without premises. The answer is a Trust Profile: a multi-dimensional representation of completion rates, behavioral signals, evidence weights, confidence levels, domain-specific performance, and dispute history. It is a dossier of observable conduct, computed from an append-only ledger of cryptographically anchored receipts, analyzed through a Sybil-resistant graph to prevent synthetic credibility from being manufactured at scale.

It is the infrastructure the internet forgot to build in 1993, arriving thirty years later, just in time.

---

## The Five Primitives

EP is built from five primitives. Each is independently useful. Together, they constitute a complete trust layer.

### 1. Behavioral Receipt — the unit of trust

A Behavioral Receipt is the atomic unit of the EP ledger. It is a cryptographically anchored record of a single transaction outcome, submitted by the party that initiated or observed the transaction, committed to an append-only chain, and permanently preserved.

Receipts are not reviews. Reviews are opinions. Receipts are behavioral facts: did the agent complete the task? Did it retry? Did it abandon? Did it dispute? These behavioral signals are the strongest evidence the protocol recognizes — not because they are infallible, but because they are the hardest to fabricate credibly. An entity with a long history of `completed` outcomes across diverse submitters, with no closed-loop graph patterns, is genuinely more trustworthy than one with five stars from a cluster of thin accounts.

Each receipt is linked to its predecessor through a hash chain. The chain is tamper-evident: modify any historical receipt, and every subsequent hash becomes invalid. The ledger is append-only at both the API and database layers. Receipts cannot be deleted. They can be disputed, reversed, and annotated — but the original record persists.

This is the foundational design choice. An audit trail that can be quietly edited is not an audit trail. It is a fiction maintained by someone with database access. EP's append-only guarantee makes the behavioral history of every registered entity permanently visible to investigators, regulators, and consuming agents.

### 2. Trust Profile — the vector, not the scalar

The Trust Profile is what EP produces. Not a score — a profile.

A score condenses multi-dimensional reality into a single number. That number hides its premises. An entity with a score of 78 might have a 95% completion rate and catastrophic price integrity problems. Another entity with the same score might have a thin history of bilateral receipts across one task category. The number conceals what matters.

A Trust Profile exposes the structure: behavioral completion rate, retry rate, abandon rate, dispute rate, consistency across time, per-signal scores (delivery accuracy, product accuracy, price integrity, return processing), confidence level (how much credible evidence backs this profile), domain-specific profiles for specific task categories, anomaly flags when score velocity indicates something is changing, and the full provenance breakdown of the evidence.

A consuming agent evaluates this profile against a **Trust Policy** — a structured declaration of the conditions under which it will transact. The protocol ships four built-in policies ranging from `discovery` (no exclusions, for browsing) to `strict` (high-confidence, high-completion, low-dispute-rate, for financial or mission-critical contexts). Operators define custom policies. Every policy evaluation returns a structured result: pass or fail, with specific failure strings identifying which criterion was not met. The agent receives reasons, not just a verdict.

Trust is multi-dimensional. The protocol is too.

### 3. Dispute Resolution — the immune system

The immune system of a trust layer is its ability to correct errors without destroying what came before. EP's dispute mechanism is the protocol's immune system.

Any affected party may file a formal dispute against any receipt. The dispute follows a defined lifecycle: evidence period, response window, adjudication, resolution, appeal. The submitter has seven days to respond. Disputed receipts are weight-dampened during adjudication — they cannot be the sole basis for a passing policy evaluation while a dispute is active. Resolved disputes are permanent: a dismissed dispute fully restores the receipt's weight; an upheld dispute permanently zeros it.

The appeal right is not optional. It is a protocol obligation, stated in the founding design principles without equivocation: **trust must never be more powerful than appeal.** Any trust system that can harm an entity without recourse is not a trust system. It is a control system with trust branding.

EP extends this to humans. Any human — without authentication, without holding an EP entity, without referencing a specific receipt — may file a human trust report. Implementations are obligated to investigate every human report. This obligation cannot be waived by Terms of Service. The premise is simple: a trust infrastructure that governs machine-mediated commerce affects real humans who may not be participants in the protocol. Those humans have standing. They are not third parties. They are the people the system is ultimately accountable to.

### 4. Delegation Chain — the bridge between human and machine accountability

When an AI agent acts autonomously, it does not act in a vacuum. It acts under authority granted by a human or organization. That authority is bounded, revocable, and accountable.

EP's Delegation Chain primitive formalizes this. A Delegation Record is a signed authorization from a principal to an agent entity: here is the scope of what you are authorized to do, here is the maximum transaction value, here is the expiry date. Behavioral outcomes that occur under delegation attach to the agent's Trust Profile and trace back to the principal through the delegation record.

This creates layered accountability. The agent is accountable for the quality of its execution. The principal is accountable for the quality of its agent selection — measurable through delegation judgment scoring, which is computed separately from the entity's own trust score and reveals whether a principal consistently authorizes underperforming agents.

Attribution chains document the full path: Principal → Agent → Tool. If an agent used an MCP server to complete a transaction, the MCP server's entity ID is in the attribution block. The delegation ID is in the attribution block. The chain depth is bounded to prevent accountability obscurement through deep delegation nesting.

Accountability in machine-mediated systems is not binary — "the human did it" or "the machine did it." It is a chain. EP makes that chain legible.

### 5. Zero-Knowledge Proof — the privacy guarantee

Trust requires evidence. Evidence creates records. Records create privacy exposure. This is the structural tension that has prevented most serious behavioral trust proposals from getting off the ground: a system that requires parties to expose their transaction history as the price of admission will be rejected by any party with legitimate privacy concerns, which is most parties.

EP resolves this through its ZK-lite proof system. When an entity needs to demonstrate that it satisfies a consuming agent's Trust Policy, it requests an evaluation proof from the EP registry. The registry evaluates the policy against the full Trust Profile, computes a signed result, and returns a structured proof object. The entity presents the proof to verifiers. Verifiers confirm the registry signature, check the proof against the EP revocation registry, confirm that the policy evaluated matches the policy they require, and accept or reject.

The verifier learns: this entity passed this policy as of this date. The verifier learns nothing about what receipts produced that result, who submitted them, what values were transacted, or which criteria were closest to threshold. Zero knowledge of the underlying contents. The proof is valid for 30 days. It cannot be extended. It can be revoked if the underlying history is subsequently determined to be fraudulent.

Verifiers who demand the underlying receipts have rejected the privacy model. The protocol is explicit: **verifiers MUST NOT demand receipt disclosure as a condition of accepting a proof.** A verifier with that requirement must use the full Trust Profile API instead, and the entity's consent governs whether that profile is shared.

Privacy is not a feature. It is a constraint on what trust infrastructure is allowed to demand. EP encodes that constraint in the standard.

---

## The Standard, Not the Product

EP is published as an open standard under the Apache-2.0 license. The canonical specification, scoring algorithm, schema definitions, and reference implementation are publicly available. Any system — an agent framework, a marketplace, an orchestration platform, a developer tool — can implement a conformant EP node using only this document. No single implementation is authoritative. Where implementation code and this document conflict, this document wins.

This is not a strategic concession. It is the only design that can succeed.

Consider what happened to web trust. SSL was first a Netscape product. TLS became an IETF standard. The difference between those two things is the difference between a competitive advantage and civilizational infrastructure. Netscape's SSL protected Netscape's customers. TLS protects the internet.

RFC 2616 did not make HTTP better for any one company. It made the web interoperable. Any server that implemented the spec could communicate with any client that implemented the spec. That interoperability was the condition of possibility for the modern internet. It is not a coincidence that the most foundational internet layers are open standards and not proprietary products.

**EP-001 is to agent trust what RFC 2616 was to web transport.** The goal is not to win the trust market. The goal is to make agent trust interoperable, auditable, and accountable in a way that no single vendor can capture.

This means the protocol governance model is open. Protocol changes are proposed as GitHub issues or pull requests. Significant changes require a public comment period. Breaking changes require documented migration paths. No single organization controls the protocol. The trust infrastructure of the AI age must itself be trustworthy — which means it must not be owned.

---

## The One-Line Truth

EP is the SSL/TLS of AI agent behavior — the trust layer the internet forgot to build in 1993, arriving just in time for the agents.

---

## What Comes Next

EP launches as infrastructure with a specific deployment posture:

**MCP server, now.** EP ships fifteen MCP tools that agent frameworks can invoke directly: `ep_trust_profile`, `ep_trust_evaluate`, `ep_submit_receipt`, `ep_file_dispute`, and eleven more. Any agent built on an MCP-compatible framework can query EP for trust profiles and policy evaluations without writing integration code. The MCP server is the first distribution channel because it reaches agents where they operate.

**SDK adoption, weeks.** TypeScript and Python SDKs are published to npm and PyPI. The SDKs implement the full conformance suite — not a simplified wrapper, but a complete EP node that any developer can embed in an application. External implementations that pass the conformance test suite can register as conformant. The goal is multiple independent implementations within the first six months.

**Operator network, months.** As implementations proliferate, the operator network forms: organizations that run EP nodes and agree to interoperability, evidence exchange, and shared governance of the standard. The operator network is the condition of possibility for cross-operator trust portability — an entity's Trust Profile earned on one operator's network should be evaluable by a consuming agent on a different operator's network.

**Protocol governance, within a year.** The first external implementation passes the conformance suite. A working group is established with AAIF or equivalent. EP-001 begins its track toward W3C or IETF consideration. The governance model transitions from a single-organization proposal to a multi-stakeholder standard.

The trajectory ends with EP invisible. The trust layer that runs beneath every meaningful agentic transaction, the way TLS runs beneath every HTTPS request. Agents will not configure it. They will not think about it. Somewhere in the infrastructure, a behavioral history is being evaluated against a policy, and the result — structured, auditable, disputable — is informing whether to proceed.

That is the internet the agents deserve. That is what we built.

---

*EMILIA Protocol — EP-001*
*Entity Measurement Infrastructure for Ledgered Interaction Accountability*
*Apache-2.0 · emiliaprotocol.ai · github.com/emiliaprotocol/emilia-protocol*
*Compatible with ACP, MCP, A2A*
