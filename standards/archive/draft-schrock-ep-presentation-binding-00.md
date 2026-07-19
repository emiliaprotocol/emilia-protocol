# Presentation Binding for Human-Authorization Receipts: Proving the Human Approved What They Saw
## draft-schrock-ep-presentation-binding-00

```




Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               3 July 2026
Expires: 4 January 2027


Presentation Binding for Human-Authorization Receipts: Proving the Human
                         Approved What They Saw
                draft-schrock-ep-presentation-binding-00

Abstract

   A human-authorization receipt proves a named person produced a user-
   verified signature over a digest that commits to an exact action.  It
   does not prove the surface that person signed on DISPLAYED that
   action honestly.  If a signing interface shows a benign summary while
   committing a different action, the resulting receipt is laundered
   authority: cryptographically valid and semantically false, which is
   worse than no receipt at all.  This is the presentation attack, and
   it is the deepest unsolved problem in authorization evidence, because
   a signature cannot attest to pixels.  This document narrows the gap
   with two additive, offline-checkable pieces that touch no existing
   receipt format: a DETERMINISTIC RENDERER, a pure function from the
   canonical action to a byte-identical human-readable rendering, so a
   verifier RE-DERIVES the rendering from the signed bytes and rejects
   any surface that showed something else; and a DISPLAY ATTESTATION, a
   signed claim by the signing client binding the rendering it showed to
   the action it committed.  Neither eliminates the presentation attack
   (nothing purely digital can), but together they convert "trust the
   vendor's UI" into "verify the rendering was the honest function of
   the signed action," and they make the residual risk explicit rather
   than hidden.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF).  Note that other groups may also distribute
   working documents as Internet-Drafts.  The list of current Internet-
   Drafts is at https://datatracker.ietf.org/drafts/current/.

   Internet-Drafts are draft documents valid for a maximum of six months
   and may be updated, replaced, or obsoleted by other documents at any
   time.  It is inappropriate to use Internet-Drafts as reference
   material or to cite them other than as "work in progress."




Schrock                  Expires 4 January 2027                 [Page 1]

Internet-Draft            Presentation Binding                 July 2026


   This Internet-Draft will expire on 4 January 2027.

Copyright Notice

   Copyright (c) 2026 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents (https://trustee.ietf.org/
   license-info) in effect on the date of publication of this document.
   Please review these documents carefully, as they describe your rights
   and restrictions with respect to this document.  Code Components
   extracted from this document must include Revised BSD License text as
   described in Section 4.e of the Trust Legal Provisions and are
   provided without warranty as described in the Revised BSD License.

Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   2
     1.1.  Terminology . . . . . . . . . . . . . . . . . . . . . . .   3
   2.  The Deterministic Renderer  . . . . . . . . . . . . . . . . .   3
   3.  The Display Attestation . . . . . . . . . . . . . . . . . . .   4
   4.  Composition with the Evidence Layers  . . . . . . . . . . . .   4
   5.  Residual Risk: WYSIWYS Is Not Solved  . . . . . . . . . . . .   4
   6.  Security Considerations . . . . . . . . . . . . . . . . . . .   5
   7.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   5
   8.  References  . . . . . . . . . . . . . . . . . . . . . . . . .   5
     8.1.  Normative References  . . . . . . . . . . . . . . . . . .   5
     8.2.  Informative References  . . . . . . . . . . . . . . . . .   5
   Appendix A.  Implementation Status  . . . . . . . . . . . . . . .   6
   Author's Address  . . . . . . . . . . . . . . . . . . . . . . . .   6

1.  Introduction

   The hard part of human authorization was never the signature.  It is
   the question a relying party's counsel asks first: a receipt of WHAT?
   A named human signed a digest; the digest commits to an action; but
   the human did not see the digest; they saw a screen, and the screen
   was drawn by software.  If that software rendered "approve invoice,
   $1.00" while committing "wire $82,000 to account X", the receipt is
   perfect and the authority is fabricated.  Every downstream layer —
   composition, sufficiency, recourse — inherits this weakness: they
   compose and grade a receipt whose meaning was set by an unattested
   rendering step.

   Two observations make the problem tractable without overclaiming.
   First, most presentation attacks are RENDERING attacks: the surface
   computed the display from something other than the signed action.



Schrock                  Expires 4 January 2027                 [Page 2]

Internet-Draft            Presentation Binding                 July 2026


   That is defeatable, because a rendering can be made a PURE FUNCTION
   of the signed action and re-derived by any verifier.  Second, the
   residue (a compromised or malicious client that renders honestly to a
   verifier's re-derivation while showing the human something else out
   of band) cannot be closed by any digital artifact and MUST be stated
   as residual risk, not papered over.  This document does the first and
   is scrupulous about the second.

1.1.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

2.  The Deterministic Renderer

   A conforming renderer is a PURE FUNCTION from a canonical action
   object to a rendering.  For any two canonical actions that are deeply
   equal it MUST produce byte-identical output on every conformant
   runtime, in every locale, at any time; it MUST NOT read the clock,
   locale, environment, randomness, or any I/O.  It reads a fixed,
   ordered, closed set of action fields (for example: action type,
   target, organization, initiator, policy, amount, currency, requested-
   at, risk signals), each with a fixed label, and produces an ordered
   list of label/value lines, a concatenated human-readable text, and a
   rendering digest over the canonical structure.

   Because the rendering is a pure function of the SIGNED action, a
   verifier re-derives it from the very bytes the receipt's action
   digest commits to and compares.  A surface that displayed "$1" for an
   action that says "$82,000" cannot produce a rendering that re-
   derives; the deviation is detected offline, by anyone, without
   trusting the surface.  This turns "render from the exact hashed
   bytes, never a re-described copy" from an unverifiable interface rule
   into a verifiable property.

   Handling untrusted content is normative: values that can carry
   display-manipulating characters (bidirectional overrides, control
   characters, homoglyph-bearing runs, or excessive length) MUST be
   neutralized by a specified, deterministic transformation before
   rendering, and a value that cannot be safely rendered MUST cause the
   renderer to refuse rather than emit a misleading line.  The
   neutralization is itself part of the pure function, so the verifier
   re-derives the same neutralized rendering.





Schrock                  Expires 4 January 2027                 [Page 3]

Internet-Draft            Presentation Binding                 July 2026


3.  The Display Attestation

   A display attestation (wire tag EP-DISPLAY-ATTESTATION-v1) is a
   signed claim by the signing client: "I rendered THIS rendering of
   THIS action."  It binds the rendering digest to the action digest
   under the client's key and is stored ALONGSIDE the receipt (in an
   audit record, a provenance bundle, or an evidence-graph node), never
   inside the signed receipt body; verifiers that predate this profile
   continue to verify receipts unchanged; verifiers that implement it
   add the display check.  For high-stakes action classes a relying
   party's policy MAY require a valid display attestation and fail
   closed when it is missing or does not verify.

   Verified versus accepted applies here too: verifying the attestation
   (its signature holds and its rendering re-derives from the action) is
   distinct from trusting the CLIENT that made it.  A display
   attestation raises the cost and auditability of a presentation
   attack; it does not, by itself, make the client honest.

4.  Composition with the Evidence Layers

   Presentation binding is the missing precondition under the rest of
   the stack.  An authorization receipt
   ([I-D.schrock-ep-authorization-receipts]) gains a rendering that a
   verifier can re-derive; a binding
   ([I-D.schrock-human-authorization-binding]) that carries such a
   receipt MAY additionally require the display attestation as part of
   its digest-grounding requirement; an evidence policy
   ([I-D.schrock-ep-action-evidence-graph]) MAY, for a high-stakes
   reliance purpose, treat a receipt without a verifying display
   attestation as insufficient.  The property this document adds — the
   human approved what a verifier can prove they were shown, is the one
   every other layer silently assumed.

5.  Residual Risk: WYSIWYS Is Not Solved

   This profile narrows the presentation-attack surface; it does not
   eliminate it, and implementers MUST NOT represent it as doing so.  A
   compromised signing client can render honestly to the verifier's re-
   derivation while presenting a different artifact to the human through
   a channel the protocol cannot observe (a manipulated display driver,
   an overlaid window, a coerced approver).  Defenses against that
   residue are operational and hardware-rooted (trusted display paths,
   out-of-band confirmation of material fields, secure enclaves) and are
   out of scope here, though at least one such path ships today:
   Android's Protected Confirmation renders a prompt in a TEE-isolated
   display path and signs the exact displayed text under a key
   restricted to user-confirmed content, with an attestation chain a



Schrock                  Expires 4 January 2027                 [Page 4]

Internet-Draft            Presentation Binding                 July 2026


   relying party can grade.  Profiling such mechanisms as display
   attestors for this document's attestation, with assurance graded by
   the attestation chain, is planned work for a future revision.  What
   this document removes is the CHEAP, SCALABLE, UNDETECTABLE rendering
   attack — the software surface that simply computed the display from
   the wrong bytes — and it makes the remaining, expensive residue
   explicit so a relying party can price it rather than discover it in a
   dispute.

6.  Security Considerations

   The entire document is a security consideration; the residual risk
   section states the boundary.  One further point: the renderer MUST be
   conservative to the point of refusing.  A renderer that guesses at an
   unmodeled field, truncates silently, or best-effort displays hostile
   content trades a detectable failure for an undetectable one.  Refusal
   to render is a safe outcome; a misleading render is the attack.

7.  IANA Considerations

   This document has no IANA actions.  Registration of the render
   profile and display-attestation identifiers is anticipated for a
   future revision.

8.  References

8.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON
              Canonicalization Scheme (JCS)", RFC 8785,
              DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/info/rfc8785>.

8.2.  Informative References

   [I-D.schrock-ep-action-evidence-graph]
              Schrock, I., "Action Evidence Graphs and Evidence Policy
              Replay for High-Risk Agent Actions (EP-AEG)", Work in
              Progress, Internet-Draft, draft-schrock-ep-action-



Schrock                  Expires 4 January 2027                 [Page 5]

Internet-Draft            Presentation Binding                 July 2026


              evidence-graph-00, July 2026,
              <https://datatracker.ietf.org/doc/draft-schrock-ep-action-
              evidence-graph/>.

   [I-D.schrock-ep-authorization-receipts]
              Schrock, I., "Authorization Receipts for High-Risk Agent
              Actions", Work in Progress, Internet-Draft, draft-schrock-
              ep-authorization-receipts-05, July 2026,
              <https://datatracker.ietf.org/doc/draft-schrock-ep-
              authorization-receipts/>.

   [I-D.schrock-human-authorization-binding]
              Schrock, I., "Binding Named-Human Authorization Evidence
              into Agent-Action Records", Work in Progress, Internet-
              Draft, draft-schrock-human-authorization-binding-00, July
              2026, <https://datatracker.ietf.org/doc/draft-schrock-
              human-authorization-binding/>.

Appendix A.  Implementation Status

   A reference implementation (the deterministic renderer, the display
   attestation, and the offline re-derivation check) is published
   Apache-2.0 in the EMILIA Protocol repository (lib/wysiwys/render.js)
   with conformance vectors and a test suite, including negative
   vectors: a rendering that does not re-derive from its action is
   rejected, and hostile display content (bidirectional overrides,
   control characters, over-length values) is neutralized or refused
   rather than rendered misleadingly.

Author's Address

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai
















Schrock                  Expires 4 January 2027                 [Page 6]

```
