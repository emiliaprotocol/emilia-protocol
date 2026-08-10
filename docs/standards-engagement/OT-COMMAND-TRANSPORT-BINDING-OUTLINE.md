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

### Modbus TCP transport binding

#### Applicability

This profile binds a Modbus TCP write to holding registers, function code 0x06
(Write Single Register) and function code 0x10 (Write Multiple Registers).
Modbus carries no envelope space in either function, so evidence is detached in
both cases.

Modbus TCP supplies no device authentication, no message integrity, and no
replay protection. The conduit therefore establishes every fact about WHO and
WHERE from its own link and session state, and takes from the wire only WHAT is
being written.

#### The admitted operation

The conduit MUST classify every field of the request into exactly one of four
classes, and the classification MUST be complete. For function code 0x06 the
classes are:

| Class | Fields |
|---|---|
| material | unit identifier, function code, protocol address, value |
| conduit context | site, device |
| correlation only | MBAP transaction identifier |
| fixed or derived | MBAP protocol identifier (0), MBAP length (6) |

For function code 0x10 the material set is the unit identifier, the function
code, the starting protocol address, the register quantity, and the ordered
register values. Byte count is derived from quantity and MUST NOT be bound
independently.

The action digest is computed over the material and conduit-context fields
together. Correlation-only and fixed-or-derived fields MUST NOT contribute to
it.

#### Register addressing

The digest MUST bind the zero-based protocol address as it appears in the
request. A 4xxxxx or 0xxxxx data-model label is a display rendering whose base
and offset are convention-dependent, and two conduits reading the same octets
can render the same address differently. Such a label MAY be carried alongside
the evidence as display metadata and MUST NOT substitute for the protocol
address in the digest.

#### Unit identifier and device context

The unit identifier is both a material field and a routing field. Behind a
serial gateway it selects the physical device, and the conduit has already
established which device its link context refers to. The conduit MUST refuse a
request whose wire unit identifier does not agree with the unit mapped to its
established device context, and MUST refuse it before any evidence lookup.
Resolving the disagreement in favour of either source is a conformance failure.

#### Encoding scope

This profile binds native encoding. Function code 0x06 and function code 0x10
with quantity one produce the same register effect and remain distinct admitted
operations with distinct digests. A conduit MUST NOT normalise one into the
other, and an authorisation issued for one MUST NOT admit the other. A later
profile that wishes to authorise by effect rather than by encoding must state
the normalisation explicitly and define it for every function code in its
scope; this profile does not.

#### Evidence carriage

All Modbus functions in scope use detached evidence, resolved per the common
detached-evidence requirements. The transaction identifier MUST NOT be used as
the attempt reference: it is client-chosen, two octets wide, and reused within a
session.

#### Conformance cases

A conforming implementation demonstrates that:

1. the pinned function code 0x06 request decodes to its published action
   identifier;
2. changing the protocol address, the value, or the unit identifier each yields
   a different action identifier;
3. changing only the MBAP transaction identifier yields the same action
   identifier;
4. a 4xxxxx label never appears in the digest input;
5. a wire unit identifier inconsistent with conduit device context is refused
   before evidence lookup;
6. function code 0x06 and function code 0x10 with quantity one yield different
   action identifiers; and
7. a request whose MBAP protocol identifier is non-zero, or whose length field
   disagrees with the function code, is refused as malformed rather than
   admitted.

### DNP3 transport binding

#### Applicability

This profile binds DNP3 Control Relay Output Block operations, object group 12
variation 1, carried by application function DIRECT_OPERATE (5) and
DIRECT_OPERATE_NR (6).

SELECT followed by OPERATE (functions 3 and 4) is outside this profile. A
profile adding it MUST bind both phases to a single authorisation and MUST
enforce the arm timer inside the same action state machine, so that an OPERATE
cannot be admitted against a SELECT the authorisation did not cover. Treating
the two phases as independently authorised operations is a conformance failure
in any such profile.

Requests carrying more than one control object are outside this profile. A
profile admitting them MUST bind the ordered set of control objects in one
digest rather than binding the first.

#### The admitted operation

| Class | Fields |
|---|---|
| material | application function, object group, variation, object index, control octet, CROB operation count, on-time, off-time |
| conduit context | site, device, outstation address |
| correlation only | application control sequence number |
| fixed or derived | qualifier code, qualifier object count, CROB status field |

The outstation address is conduit context rather than a decoded field. An
application fragment begins at the application control octet and carries no
data link header, so a conduit that receives fragments alone cannot derive the
address from the bytes in front of it. It contributes to the digest because it
identifies the device, and it is established from link state.

The application control sequence number varies per request and identifies no
part of the physical act. It is the DNP3 analogue of the Modbus transaction
identifier and MUST NOT contribute to the digest.

The CROB status field is a response field, zero in a request, and MUST NOT be
bound.

#### The control octet

The digest MUST bind the complete control octet, not a mnemonic for it. The
octet carries the operation type in its low four bits, the queue and clear flags
above them, and the trip-close code in its top two bits. On a breaker, the
trip-close code is the difference between opening and closing the circuit, and
it is exactly the distinction a command-authority binding exists to carry. A
binding that records LATCH_ON and discards the remaining bits admits an
operation it never authorised.

A profile MAY bind each subfield by name instead, provided every bit of the
octet is covered by exactly one named field.

#### Timing fields

On-time and off-time MUST both be bound. For a pulse operation they are the
physical act: the same object at the same index with a one-hour on-time is a
different operation from the same object with a zero on-time, and an
authorisation for one MUST NOT admit the other. They are bound whether or not
the operation type reads them, so that changing the operation type cannot
silently bring unbound timing into effect.

The CROB operation count MUST be bound and MUST be named distinctly from the
qualifier object count. The two are unrelated: the first is how many times the
point operates, the second is how many objects the request carries.

#### Evidence carriage

The object space is fixed-width and typed, and no octet of a group 12 variation
1 fragment is free. Evidence is therefore detached for both application
functions, resolved per the common detached-evidence requirements.

#### Outcome

DIRECT_OPERATE_NR supplies no application response. A conduit that has
forwarded such a request has no protocol means of establishing whether the
outstation acted. The terminal result MUST be `INDETERMINATE` unless an
authoritative reconciliation independent of this exchange establishes the
effect. This is the ordinary result for that function, not an error path, and a
conduit MUST NOT record success on dispatch.

An `INDETERMINATE` outcome MUST NOT return the consumed authorisation to an
unused state, and MUST NOT trigger an automatic retry. Re-entering the device
requires a fresh authorisation.

#### Conformance cases

A conforming implementation demonstrates that:

1. the pinned DIRECT_OPERATE fragment decodes to its published action
   identifier, given site, device and outstation address from conduit context;
2. changing the application function, the object index, any bit of the control
   octet, the operation count, the on-time, or the off-time each yields a
   different action identifier;
3. changing only the application control sequence number yields the same action
   identifier;
4. changing the outstation address in conduit context yields a different action
   identifier;
5. a SELECT or OPERATE function code is refused as out of profile rather than
   admitted as a direct operate;
6. a request carrying more than one control object is refused as out of profile;
   and
7. a DIRECT_OPERATE_NR request that is forwarded terminates `INDETERMINATE`, its
   authorisation stays consumed, and no retry is issued.

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
