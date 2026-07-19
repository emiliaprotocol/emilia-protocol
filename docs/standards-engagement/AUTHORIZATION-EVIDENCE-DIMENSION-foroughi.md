<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributed dimension for draft-foroughi-agent-protocol-dimensions: Evidence Verifiability

**Status:** ready-to-adopt input for the dimensional model
(`draft-foroughi-agent-protocol-dimensions`, P. Foroughi). Offered whole: take it, trim
it, or reject it. The text follows the draft's own conventions (protocol-visible values,
"not specified" where a proposal defers to deployment, no ranking).

**Revision note.** The first version of this document proposed a three-value
authorization-evidence dimension (ephemeral, recorded, artifact). This version
implements two decisions made in review. First, the Foroughi collapse: `recorded` is not
protocol-visible, because from the wire a mediator that logs and a mediator that forgets
look identical, so internal recording is a deployment property on the "none" side of the
real boundary. Second, the single-axis merge proposed on the agent2agent list: the
authorization question ("is there a verifiable authorization decision on the wire?") and
the accountability question ("can a non-participant verify what the agent did?") share
one verifiability scale and one orthogonality argument, so they are one dimension
realized by two extension primitives, not two dimensions.

## Proposed dimension text (drop-in)

### Dimension: Evidence Verifiability (D8)

Whether an exchange places an independently verifiable evidence object on the wire, and
who can verify it. Values:

- **none**: no independently verifiable evidence object crosses the wire. Whether any
  party logs internally is a deployment property the receiver cannot observe.
- **participant-verifiable**: the parties to the exchange can verify each other's
  evidence objects (signed messages, mutual attestation). A non-participant must trust
  at least one participant.
- **third-party-verifiable**: a non-participant can verify the evidence object without
  trusting either participant. The object is bound to the exact operation it evidences.

The value is read from the exchange alone, which is the draft's stated test for a
dimension: the wire either carries an evidence object with the stated verifiability or
it does not.

### Mechanism neutrality (the substrate split)

How an object is made verifiable is substrate, the same split as D1: canonicalization,
signature scheme, anti-replay, and anchoring are substrate realizations, not dimensional
values. In particular, `third-party-verifiable` is reachable by more than one substrate:
a self-contained signed object carrying its own key material is verifiable by a
non-participant offline with no transparency log in the path, and a transparency-log
anchor (for example SCITT over RFC 9162) realizes the same value while adding anchoring
properties of its own (append time, non-equivocation, survival beyond the parties).
The dimension records who can verify; the substrate records how.

### Extensions realizing the non-trivial values

Two extension primitives let a proposal reach the upper values, exactly as EXT-REATTACH
realizes D3 = durable-reattach and EXT-CAPREG realizes D5 = registry-resolved:

- **EXT-AUTHEV (authorization evidence)**: the exchange emits a decision object, bound to
  the exact operation, evidencing that a principal authorized the operation before it
  ran. The pre-action claim class.
- **EXT-ACCTEV (accountability evidence)**: the exchange emits a record, bound to the
  exact operation, evidencing what occurred: executed as witnessed, refused, or blocked.
  The post-action claim class.

The two primitives carry different claims with different proof obligations and compose
by digest reference to the same operation, neither embedding the other. They share the
D8 scale: each can be absent (none), verifiable between the parties
(participant-verifiable), or verifiable by a non-participant (third-party-verifiable).
Meeting the artifact-level verification criteria (integrity, binding, signature,
anchoring) establishes the object's verifiability value; it does not by itself establish
the strength of the claim the object can support, which stays bounded by what the
emitting party's stated observation boundary can witness.

### Application to the surveyed proposals

| Proposal | D8 value | Basis |
|---|---|---|
| A2A | not specified (protocol layer) | TASK_STATE_INPUT_REQUIRED / AUTH_REQUIRED pause the task; the resolution is a follow-up message on the same task or context identifier. No evidence object with a stated verifiability is defined at the protocol layer. |
| MCP | none | Tool-call consent is a host obligation ("MCP itself cannot enforce these security principles at the protocol level"); elicitation returns accept/decline/cancel in-session. No message type carries an evidence object. |
| ACP (AGNTCY invocation surface) | not specified (protocol layer) | Delegated authorization carriage exists; a per-operation evidence object is not defined. |

The table does not yet discriminate the surveyed three, which is the expected shape of a
forward-looking dimension: the non-trivial values are being pursued in running work
(authorization receipts bound to a canonical operation digest and verifiable offline
against pinned keys; SCITT-anchored agent-action records verifiable by non-participants;
FIDO's Verifiable Intent work in the payments vertical). The dimension is
mechanism-neutral: any proposal emitting evidence with the stated verifiability sits at
the corresponding value, whatever its format.

### Considered and excluded

- **`recorded` as a third value**: excluded. Internal logging is not observable from the
  exchange; it is the audit and substrate facet wearing a dimension's clothing.
- **Two dimensions (authorization and accountability)**: excluded in favor of one
  dimension plus two extensions. The scale and the orthogonality argument are identical;
  splitting them would duplicate a dimension to distinguish artifact classes, which the
  extensions distinguish already.

### Why the dimension earns its place

It passes the gate test (orthogonal to D1 through D7: an exchange can hold any values on
the existing dimensions and still differ on whether verifiable evidence crosses the
wire), and its value changes integration behavior: a third-party-verifiable consumer can
build dispute, compliance, and reliance flows on the evidence; a none consumer must
re-prompt or trust the session.

---

Contact: Iman Schrock, EMILIA Protocol (team@emiliaprotocol.ai). License Apache-2.0; use
freely with or without attribution.
