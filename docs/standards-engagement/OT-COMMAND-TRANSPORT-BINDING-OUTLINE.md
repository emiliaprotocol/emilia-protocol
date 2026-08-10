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
   admitted native operation, every conduit-established context field, every
   fixed or derived field, and every field used only for transport
   correlation. A correlation-only field MUST NOT change the action digest.
3. The conduit MUST compare the observed action identifier with the action
   authorized by the evidence before forwarding the command.
4. Inline and detached evidence carriage MUST provide equivalent action
   agreement, evidence verification, and consumption properties. They do not
   provide request-instance binding the same way: inline carriage depends on
   the authenticated channel, while detached carriage depends on a
   conduit-established attempt reference bound to authenticated request or
   session context. An unbound reference is not proof by itself.
5. A detached-evidence binding MUST resolve evidence by both a distinct attempt
   reference and the collision-resistant digest of the exact action. The action
   digest is not secret and MUST NOT be used as the request-instance key. Two
   authorizations for the same exact action MUST remain separately addressable.
6. A successful admission MUST consume the applicable one-time authorization
   before the conduit forwards the native command. Replay or a second
   consumption attempt MUST be refused. The attempt holder and authoritative
   consumption record MUST share the conduit enforcement failure domain.
7. If dispatch may have occurred but the effect cannot be established, the
   result MUST be `INDETERMINATE`. The conduit MUST NOT blindly retry the
   command or reinterpret the same authorization as unused.
8. Failure of authority verification MUST refuse the requested state change
   without blocking an independent safety action.
9. Verification of command-authority evidence and verification of the native
   protocol's channel security MUST remain separate checks; neither substitutes
   for the other.
10. The conduit MUST evaluate the evidence validity window against its own
    trusted clock immediately before admission. A short window reduces exposure
    but does not establish the freshness of external facts or reconcile an
    unknown device effect.

These requirements use the Canonical Action Identifier model for exact-action
comparison, Action Evidence Binding for evidence-to-action composition, and
Bounded Capability Receipts for one-time admission and indeterminate outcomes.
The companion remains neutral about which conforming evidence format supplies
those properties.

## Initial binding profiles

### Modbus TCP Write Single Register

The admitted operation includes site and device context established by the
conduit, unit identifier, function code, the zero-based protocol address carried
on the wire, and value. A 4xxxxx register label is convention-dependent display
metadata and is not signed in place of the protocol address. The conduit MUST
refuse a wire unit identifier that does not match the unit mapped to its device
context. The MBAP protocol identifier is fixed at zero, length is derived, and
the transaction identifier is correlation metadata: changing it changes the
wire bytes but not the action.

This profile chooses encoding-scoped authority: FC 0x06 and FC 0x10 with
quantity one remain distinct admitted operations even where they produce the
same register effect. It does not normalize between native encodings.

Modbus provides no envelope space for authority evidence in this operation, so
the initial profile uses detached evidence keyed by an authenticated conduit
context, an attempt reference, and the action digest.

### DNP3 Direct Operate CROB

The admitted operation includes conduit-established site and device context,
the link-layer outstation address, application function, object group and
variation, index, the complete CROB control octet, CROB operation count,
on-time, and off-time. The qualifier object count is named separately from the
CROB operation count. The fixed object space provides no authority-evidence
envelope, so the initial profile uses detached evidence keyed by an
authenticated conduit context, an attempt reference, and the action digest.
The application sequence is correlation metadata: changing it changes the
fragment bytes but not the admitted physical action. The FIR and FIN bits are
fixed by this single-fragment profile.

The initial vectors cover DIRECT_OPERATE and DIRECT_OPERATE_NR. Because the
latter provides no protocol acknowledgement, a successful dispatch has an
`INDETERMINATE` outcome unless authoritative reconciliation establishes the
effect. SELECT followed by OPERATE is deliberately outside this first profile;
a profile adding it must bind both phases to one authorization and enforce the
arm timer in the same action state machine.

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
- a 4xxxxx display label never replaces the Modbus protocol address in the
  digest, and a wire unit identifier inconsistent with conduit context is
  refused;
- FC 0x06 and FC 0x10 quantity one remain distinct under the declared
  encoding-scoped rule;
- changing the DNP3 application function, complete control octet, operation
  count, on-time, or off-time changes the action identifier;
- changing only the DNP3 application sequence changes the fragment bytes but
  not the action identifier;
- two authorizations for the same exact action remain separately addressable by
  distinct conduit attempt references;
- DNP3 DIRECT_OPERATE_NR enters the device and terminates `INDETERMINATE`;
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
