# Staged Drafts

Files here are complete candidates that have not been filed. The authoritative
disposition for every item is [`../STATUS.json`](../STATUS.json).

## July 27 lifecycle wave

The only complete staged draft is:

- `draft-schrock-ep-revocation-statement-00`

It is the mandatory July 27 filing candidate. Before filing it must retain all
of these properties:

- an authentic revocation remains terminal regardless of age;
- future-dated revocations and future-dated status heads fail closed;
- JavaScript, Python, and Go agree on the executable vectors;
- the draft composes with the IETF Token Status List work;
- xml2rfc, claim tracing, full tests, and an independent hostile review pass.

The design freezes July 20, the hostile-review deadline is July 24, and the
target filing date is July 27.

`draft-schrock-authorization-evidence-challenge-01` remains a conditional
candidate, but it is intentionally absent from this directory. There is no
reviewed `-01` source yet, and it must not be staged until its source-locked
AuthZEN AARP binding review is complete.

No staged file should be uploaded merely because it renders. A revision must
carry a coherent technical change and independently clear its gate.
