# CAID -05: IANA URI-scheme name repair

Posted source: `UPLOAD-THIS/draft-schrock-canonical-action-identifier-05.xml`.
Datatracker confirmed publication on 2026-10-02:
<https://datatracker.ietf.org/doc/html/draft-schrock-canonical-action-identifier-05>.
The archived XML is byte-identical to the source in this directory (SHA-256
`581c2d1e902f5365a3578c62751d32be728f2b6072354f873ce6b74bb77f1ebc`).
The TXT and HTML in `RENDERS/` are generated review copies. The posted -04
files remain immutable.

IANA ticket #1460612 reported on 2026-10-02 that the designated expert did
not find `caid` sufficiently descriptive and distinguished under RFC 7595
Section 3.8. The expert offered `canactid` as an acceptable example. This
revision takes that exact name. It changes the literal URI scheme and the
complete identifier string, but not the action object, suite, or digest.

This is a wire-breaking change. A `caid:` identifier from -04 and a
`canactid:` identifier from -05 are not equal even if their suffixes match.
Do not rewrite identifiers inside signed receipts or permits. The party
that knows the action object must compute the new identifier and bind the
complete new string in any new commitment. A verifier for -05 refuses the
legacy prefix; a deployment that still accepts -04 must select that profile
explicitly. Section 3.6 of the draft states the transition rule.

The three published reference implementations and Verify 6.0.0 still emit
the -04 form. Section 13 discloses this; no claim of -05 implementation or
production deployment is made. Implementation migration needs its own
versioned release and conformance corpus, not a search-and-replace of
stored identifiers.

Validation on 2026-10-02:

- `xmllint --noout` passed.
- `xml2rfc 3.34.0` generated both renders. It emitted only the same two
  informational stream/consensus warnings as -04, with no long-line warning.
- `idnits -m submission` reported `PASS No nit found` for the TXT.
- The -04 source and its posted copies were not edited.

IANA ticket #1460612 is **not** a completed registration. On 2026-10-02,
Iman replied in that existing ticket, accepted `canactid`, linked the
posted -05, and supplied the updated Provisional registration fields with
Iman as change controller. Do not describe `canactid` as registered until
IANA adds it to the URI Schemes registry.
