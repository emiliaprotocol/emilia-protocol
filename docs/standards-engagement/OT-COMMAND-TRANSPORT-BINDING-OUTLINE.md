# OT Command Authority Transport Binding

Status: pre-draft collaboration outline; not an Internet-Draft.

This note proposes concrete transport-binding requirements and conformance
cases for the gap identified in Sections 7 and 10 of
`draft-morrison-ot-command-authority-01`. It does not assign co-authorship.
Any author list requires each person's explicit agreement.

## Scope

The binding lets a conduit decide whether a native state-changing OT command
is the exact action covered by independently verifiable command-authority
evidence. It does not define operator identity, plant safety policy, native
transport security, or a general authorization format.

The safety carve-out in `draft-morrison-ot-command-authority-01` is unchanged:
safety-instrumented functions, emergency shutdowns, protective relays, and
other autonomous safety actions MUST NOT depend on this binding.

## Proposed requirements

1. The conduit MUST derive the observed action from decoded native command
   bytes plus link or session facts the conduit establishes itself. Sender
   assertions about the command are not sufficient.
2. The binding specification MUST identify every field that changes the
   physical action and every field used only for transport correlation. A
   correlation-only field MUST NOT change the action digest.
3. The conduit MUST compare the observed action identifier with the action
   authorized by the evidence before forwarding the command.
4. Inline and detached evidence carriage MUST provide equivalent binding and
   verification properties. An inline reference is not proof by itself.
5. A detached-evidence binding MUST resolve evidence by a collision-resistant
   digest of the exact action or by an identifier cryptographically bound to
   that digest.
6. A successful admission MUST consume the applicable one-time authorization
   before the conduit forwards the native command. Replay or a second
   consumption attempt MUST be refused.
7. If dispatch may have occurred but the effect cannot be established, the
   result MUST be `INDETERMINATE`. The conduit MUST NOT blindly retry the
   command or reinterpret the same authorization as unused.
8. Failure of authority verification MUST refuse the requested state change
   without blocking an independent safety action.
9. Verification of command-authority evidence and verification of the native
   protocol's channel security MUST remain separate checks; neither substitutes
   for the other.

These requirements use the Canonical Action Identifier model for exact-action
comparison, Action Evidence Binding for evidence-to-action composition, and
Bounded Capability Receipts for one-time admission and indeterminate outcomes.
The companion remains neutral about which conforming evidence format supplies
those properties.

## Initial binding profiles

### Modbus TCP Write Single Register

The physical action includes site and device context established by the
conduit, unit identifier, function code, register, and value. The MBAP
transaction identifier is correlation metadata: changing it changes the wire
bytes but not the physical action.

Modbus provides no envelope space for authority evidence in this operation, so
the initial profile uses detached evidence keyed by the action digest.

### DNP3 Direct Operate CROB

The physical action includes conduit-established site and device context,
outstation address, object group and variation, index, control code, and
operation count. The fixed object space provides no authority-evidence
envelope, so the initial profile uses detached evidence keyed by the action
digest.

### OPC-UA Call

The physical action includes conduit-established site and device context,
object identifier, method identifier, and typed input arguments. An
authorization reference may ride in an extension object above the OPC-UA secure
channel. The conduit still resolves and verifies the referenced evidence and
compares its action binding; presence in the extension object is not
authorization.

## Conformance cases

A conforming implementation demonstrates at least the following:

- the three positive commands decode to their published action identifiers;
- changing one material command field changes the action identifier;
- changing only the Modbus transaction identifier does not change it;
- an inline OPC-UA reference that cannot be verified is refused;
- a second use of a consumed authorization is refused; and
- a lost response after possible dispatch produces `INDETERMINATE` and no
  automatic retry.

Pinned experimental vectors and executable checks are in
`examples/ot-command-binding-v1/vectors.v1.json` and
`examples/ot-command-binding-v1/vectors.test.mjs`.

## Current implementation status

The repository contains synthetic encoders and decoders for the three command
shapes and executable tests for the requirements above. They are not certified
protocol stacks and have not been exercised against a live PLC, RTU, DCS, or
safety system. Independent reproduction against one production-quality stack
is the next interoperability gate.

## Source documents

- `draft-morrison-ot-command-authority-01`
- `draft-schrock-canonical-action-identifier-02`
- `draft-schrock-action-evidence-boundary-03`
- `draft-schrock-ep-bounded-capability-receipts-03`
