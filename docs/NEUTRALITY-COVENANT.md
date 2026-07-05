# EMILIA Protocol — Neutrality Covenant

> **DRAFT — pending counsel review; not yet published on the site.**

This covenant states, in plain language, what the stewards of the EMILIA Protocol
commit to about the neutrality of the protocol itself. It builds on
[`GOVERNANCE.md`](../GOVERNANCE.md) — the governance document describes *how* the
protocol is stewarded; this covenant describes *what will not change* regardless
of who stewards it. Where the two documents touch the same subject, GOVERNANCE.md
controls process and this covenant controls the commitments below.

The protocol artifacts covered by this covenant are: the specification, the
reference verifiers (JavaScript, Python, and Go in one repository — a consistency
check, not independent implementations; an independent clean-room
reimplementation, COSA, is underway), the complete conformance vector suites, and
the companion Internet-Drafts (`draft-schrock-ep-*`), which are active individual
Internet-Drafts, not IETF-adopted or endorsed.

## Commitments

**1. The specification, reference verifiers, and all conformance vectors are
Apache-2.0 and remain so.** Every protocol artifact listed above is licensed
under Apache-2.0 today, and every future revision of those artifacts will be
released under Apache-2.0. We will not relicense them, we will not convert them
to a BSL-style, source-available, or delayed-open license, and we will not
introduce a more restrictive license for any successor version of the same
artifacts. This restates and extends the intellectual-property section of
GOVERNANCE.md: the spec is a shared standard, not a product.

**2. There will never be a paid or private vector tier.** The conformance
vectors that define what a conformant implementation is are public, complete,
and free of charge — all of them, including adversarial and reject vectors. We
will not publish a reduced public subset while holding richer vectors behind
payment, membership, partnership, or NDA. If a vector exists and counts toward
conformance, it is in the public repository.

**3. Any future certification program tests only against the public vectors and
is available to competitors on identical terms.** No certification program
exists today; conformance is self-certified against the published suites, as
GOVERNANCE.md records. If a certification program is ever created, it will test
implementations against exactly the vectors anyone can already run themselves,
and it will be offered to any implementer — including direct competitors of
EMILIA Protocol, Inc. — at the same price, on the same schedule, under the same
criteria. Certification will not be usable as a gate that public vectors cannot
already express.

**4. EMILIA products receive no protocol-level privilege.** Anything Gate can
verify, anyone's code can verify. Our commercial products consume the same
public specification, the same public vectors, and the same public key and
receipt formats as any third-party implementation. There are no private
extensions required for full verification, no reserved fields our products
interpret and others cannot, and no verification path that works only against
our infrastructure. If we build a capability into a product that depends on a
protocol change, the protocol change ships publicly first.

**5. No transport, vendor, or model exclusivity, ever.** The protocol will not
be bound exclusively to any transport, agent framework, cloud vendor, model
provider, or AI system. We will not sign agreements that make any party's
implementation privileged at the protocol layer, and we will not add protocol
features whose practical effect is that one vendor's stack verifies and others
cannot. Receipts describe human authorization of actions; they are deliberately
indifferent to which model acted, which vendor hosted it, and which wire carried
the message.

**6. Receipts remain verifiable if EMILIA-the-company ceases to exist.**
Offline verification is the design, not a promise: a receipt carries what a
verifier needs, verification requires no EMILIA server in the trust path, and
the verifiers and vectors that prove this are Apache-2.0 in a public repository
that anyone may fork. A relying party holding a receipt, the signer's public
key, and any Apache-2.0 verifier can check that receipt after the company, its
services, and its domains are gone. Nothing in the protocol's verification path
depends on our continued operation.

## Scope, stated honestly

This covenant binds the protocol artifacts — the specification, the reference
verifiers, the conformance vectors, and the Internet-Drafts. Commercial products
built above the protocol (Gate, managed control planes, hosted services, and
anything else EMILIA Protocol, Inc. sells) are ordinary commercial software:
they carry their own licenses, their own pricing, and no commitment from this
document beyond commitment 4 (no protocol-level privilege).

Two further boundaries apply to everything above. Verification proves signature,
binding, and log integrity — never the business correctness of an authorized
action. And EMILIA is not an auditor, regulator, or insurer: its documents,
including this one, support decisions by others; they do not conclude them.
