# Independent Stream submission note

**To:** rfc-ise@rfc-editor.org
**Subject:** Independent Stream submission: draft-schrock-ae-challenge-02

Eliot,

I would like to submit `draft-schrock-ae-challenge-02` for publication through
the Independent Stream as an Informational RFC.

The document defines a machine-readable challenge returned before a
high-risk agent action when required authorization evidence is missing or
stale. It binds the request to the relying party's exact action, identifies
the evidence still required, and closes the obtain-present-retry loop without
treating the challenge or a successful acquisition response as authorization.
The intended audience is implementers of agent runtimes, relying-party
enforcement points, and authorization-evidence systems. The reference
implementation and conformance tests are public; no independent implementation
is claimed.

There has been no IETF working-group or IESG discussion, adoption, review, or
consensus call. For completeness, the draft was mentioned once on the non-WG
`agent2agent` list on 28 July 2026 and received no substantive reply. IANA
ticket #1456851 concerned only the timing of the media-type request and was
closed pending a publication path, without a technical or registration-policy
decision.

The only requested IANA action is registration of
`application/authorization-evidence-challenge+json` in the standards tree.
It does not request an allocation governed by IETF Review or Standards Action.
RFC 6838 Section 3.1 permits a standards-tree registration from a non-IETF RFC
stream with IESG approval; IANA advised that it can process this request when
the Independent Stream document reaches IETF conflict review.

I acknowledge that the IPR rules of RFC 4846 and RFC 5744 apply and that,
unless I state otherwise, permission is granted to produce derivative works,
in whole or in part, as stated in those RFCs.

Possible independent reviewers, subject to their availability, are:

- Mark Nottingham, mnot@mnot.net, for HTTP semantics and use of status 428.
- Tymofii Pidlisnyi, signal@aeoess.com, for agent-authorization and
  evidence-gate semantics. We have exchanged technical email, but he is not an
  author, employee, or implementer of this draft.

I have not asked either person to commit to a review. I am happy to address an
initial review or provide any additional information.

Best,

Iman Schrock
EMILIA Protocol
team@emiliaprotocol.ai
