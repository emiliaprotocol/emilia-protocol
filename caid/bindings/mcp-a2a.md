<!-- PRIVATE. PR-ready text, NOT submitted anywhere. Gated on Iman's word. -->
# Binding: Model Context Protocol (MCP) and Agent2Agent (A2A)

Grounding rule for this note: every claim about the target specs comes from
text fetched on 2026-07-08 from the URLs cited inline. One quoted anchor per
target. Nothing here was submitted, posted, or discussed with anyone.

What CAID is not, stated up front because it governs both bindings: CAID
proves that artifacts reference the same typed content. It does not prove
the action was authorized, executed, safe, or wise. It confers no trust,
names no humans, and replaces no verifier. Every artifact that carries a
CAID still verifies inside its own trust boundary under its own spec.
Composition joins on the identifier; it never ingests another verifier's
evidence into its own trust boundary.

---

## Target 1: Model Context Protocol (MCP)

Spec anchor (fetched this session):
"To invoke a tool, clients send a `tools/call` request" with `params`
carrying `"name"` and `"arguments"`.
Source: https://modelcontextprotocol.io/specification/2025-06-18/server/tools

Second anchor, for field placement:
"The `_meta` property/parameter is reserved by MCP to allow clients and
servers to attach additional metadata to their interactions."
Source: https://modelcontextprotocol.io/specification/2025-06-18/basic

### 1. Where actions live in MCP

In MCP, an action is a tool invocation: the client sends a `tools/call`
JSON-RPC request whose `params` carry the tool `name` and an `arguments`
object, and the server returns a result with `content` and an `isError`
flag. A tool's shape is declared at list time via `tools/list`, where each
tool definition carries `name`, `description`, `inputSchema`, optional
`outputSchema`, and optional `annotations` describing behavior (fetched
from the tools page above). The spec's own security guidance says clients
"SHOULD ... Show tool inputs to the user before calling the server" and
that there "SHOULD always be a human in the loop with the ability to deny
tool invocations", so the arguments object is already the thing users
confirm and hosts log.

### 2. Where the CAID goes

Concrete proposal: a `_meta` key named `caid` on the `tools/call` request
params, valid under the fetched key-name format (an unprefixed name of
alphanumerics; we deliberately claim no dotted prefix, and the
`mcp`/`modelcontextprotocol` prefixes are reserved by the spec).

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "release_payment",
    "arguments": {
      "amount": "150.00",
      "currency": "USD",
      "beneficiary_account": "sha256:9f2c...",
      "payment_instruction_id": "pi_8842"
    },
    "_meta": {
      "caid": "caid:1:payment.release.1:jcs-sha256:Qm9k..."
    }
  }
}
```

Mapping from tool call to action object (the issuer's job, per DESIGN.md
section 2):

1. The adopter declares, in its own configuration, a mapping from tool
   `name` to a CAID `action_type` (a registered type, or a local
   definition in the same schema; presence-based, no registration needed).
2. The action object is `{action_type: <mapped type>, <material fields
   drawn from the tool arguments per that mapping>}`. Renames and
   normalization (e.g. amount as an `amount-string`) happen here, once,
   before digesting. Extra argument fields MAY be carried and are then
   covered by the digest.
3. The client computes the CAID (refusals, not a call, if a required
   material field is missing or mistyped) and sets `params._meta.caid`.
4. The server, if it adopts too, recomputes from the same mapping and MAY
   surface the CAID in its own logs or echo it in the result's `_meta`.
   Mismatch is a refusal with a reason, never a silent pass.

Placement note, grounded in the fetched tools page: the tool-to-type
mapping must be local verifier/host configuration, not read from the
server's tool `annotations`, because the spec warns that clients "MUST
consider tool annotations to be untrusted unless they come from trusted
servers". A server MAY advertise a suggested action type, but an adopter
treats that as a hint, exactly like every other annotation.

### 3. What an MCP adopter gains unilaterally

Today the artifact a host confirms, logs, and audits is a free-form
`arguments` blob whose digest, if anyone computes one, binds whatever
bytes happened to be there. With a CAID, the confirmation prompt and the
audit log bind a typed action object with validated REQUIRED material
fields: a payment call with no amount, or an amount as a malleable float,
is a refusal before the call fires, not a surprise in forensics. The same
identifier then joins the tool call to any permit, receipt, or outcome
attestation issued about that action by any other system, with no shared
trust model needed. This value lands with a single adopter and no
counterparty: it is the adopter's own log that gets harder.

### 4. PR-ready pitch (drafted, NOT submitted)

MCP already treats the tool call as the unit users confirm and hosts
audit, and it already reserves `_meta` for exactly this kind of
attachment. We propose a convention, not a protocol change: a `_meta` key
`caid` on `tools/call` params carrying a Canonical Action IDentifier, a
typed, canonicalized (RFC 8785 JCS -> SHA-256) digest identifier over
`{action_type, ...material fields derived from arguments}`. It adds one
string to a request and changes no message flow, no schema, no
capability. The unilateral win is that a host's confirmation prompt and
audit log now bind typed material content with required-field validation
instead of a free-form args blob, and the same identifier joins the call
to permits, receipts, and attestations other systems issue about the same
action. CAID carries no trust semantics: it is not authorization, not
identity, not proof, and every artifact that carries it still verifies in
its own trust boundary. Reference issuers are ~200 lines; conformance
vectors are self-contained.

---

## Target 2: Agent2Agent Protocol (A2A)

Spec anchor (fetched this session), on the send operation:
"The primary operation for initiating agent interactions. Clients send a
message to an agent and receive either a task that tracks the processing
or a direct response message."
Source: https://a2a-protocol.org/latest/specification/

Second anchor, for field placement, from the same page's field tables:
Message: "metadata | object | No | Optional. Any metadata to provide along
with the message." Task: "metadata | object | No | A key/value object to
store custom metadata about a task."

### 1. Where actions live in A2A

In A2A, work is initiated by a client sending a Message (role plus an
array of Parts holding the content) via the send-message operation, and
the agent responds with either a direct Message or a Task, "the core unit
of action for A2A", which carries status and accumulates results as
artifacts (all from the fetched spec page). The Task is therefore the
long-lived object that an audit trail, a billing record, or a dispute
process points at. Agents advertise themselves via an Agent Card, "a JSON
metadata document published by an A2A Server, describing its identity,
capabilities, skills, service endpoint, and authentication requirements"
(same page).

### 2. Where the CAID goes

Concrete proposal: a metadata key named `caid` in the extension points the
spec already provides on both sides of the exchange:

- Request side: `message.metadata.caid` on the Message the client sends.
- Task side: `task.metadata.caid` on the resulting Task, set by the agent
  that accepted the work.

Mapping from A2A exchange to action object:

1. A2A message Parts are often free-form (text, files). CAID does not
   digest the prose. The client derives a typed action object for the
   operation it is requesting: `{action_type: <registered or local type>,
   <material fields>}`, e.g. `document.translate.1` with source digest,
   target language, and deadline as declared material fields.
2. The client computes the CAID and sets `message.metadata.caid`. The
   action object itself MAY travel as a structured Part or out of band;
   the CAID is meaningful either way because any holder of the object can
   recompute it offline.
3. The agent, on accepting, recomputes from its own reading of the
   request and sets `task.metadata.caid`. Equal strings mean both parties
   are provably talking about the same typed content; unequal strings are
   a detectable disagreement about what was asked, surfaced before work
   starts instead of after delivery.

Honest scope, load-bearing here: A2A `metadata` is a plain key/value
object with no authentication of its own in the fetched field tables, so
a `caid` key proves nothing by itself. Its job is the join: the permit
that authorized the work, the receipt the agent issues, and the outcome
attestation a third party signs can all carry the same CAID, and each of
those artifacts is verified under its own spec in its own trust boundary.

### 3. What an A2A adopter gains unilaterally

A single A2A party, client or agent, gains a stable typed join key across
the task lifecycle: the request message, the Task object, and every
downstream artifact reference one identifier instead of matching free
text and task ids across formats. The agent's own records become
material-field validated: a request whose typed object is missing a
required field is a refusal with a reason before the Task exists. And in
multi-vendor chains (the setting A2A exists for), two parties who share
nothing but the CAID string can confirm they dispute, bill, or attest
about the same action, with neither ingesting the other's evidence.

### 4. PR-ready pitch (drafted, NOT submitted)

A2A gives Task and Message a `metadata` object precisely so deployments
can attach cross-cutting context without touching the protocol. We
propose one conventional key: `caid`, carried on the request Message and
echoed on the resulting Task, holding a Canonical Action IDentifier, a
typed canonical digest (RFC 8785 JCS -> SHA-256) over `{action_type,
...required material fields}` describing the requested action. No schema
change, no new method, no capability flag. The adopter's unilateral gain
is a validated, typed record of what was asked, and a join key that lets
the Task line up with permits, receipts, insurance objects, and outcome
attestations issued by systems that share no trust model with the agent.
Disagreement about the action becomes visible as a string mismatch before
work starts. CAID carries no trust semantics: it is not authorization,
not identity, not proof, and every artifact carrying it still verifies in
its own trust boundary. Type definitions are presence-based, so a private
A2A deployment can use local definitions day one.

---

## Fetch log (this session, 2026-07-08)

- https://modelcontextprotocol.io/specification/2025-06-18/server/tools (ok)
- https://modelcontextprotocol.io/specification/2025-06-18/basic (ok)
- https://a2a-protocol.org/latest/specification/ (ok, fetched twice; the
  second fetch requested literal excerpts and matched the first)

## Status

Proposal text only. Nothing opened, posted, or sent. Both pitches are
staged for the moment Iman says go.
