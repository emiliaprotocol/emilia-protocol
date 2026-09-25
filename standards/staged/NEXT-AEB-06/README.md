# Action Evidence Boundary -06 review candidate

This packet is a complete, renderable candidate based on the exact published
`draft-schrock-action-evidence-boundary-05` source. The base XML is retained in
repository history at commit `cf5ccb3a5172fbced7d54aeb00b0cc70b5430062`
with SHA-256
`53b09b275fd3868dfbea11340a71e4827c38ad3cba2fdd12595cdcf42eb6c240`.

The revision narrows AEB to the consequence-admission lifecycle after a native
authorization path has made its decision. In particular, it:

- composes after AIMS, OAuth, AuthZEN, COAZ, AP2, and local authorization;
- leaves COAZ authoritative for operation-to-SARC mapping and PEP enforcement;
- uses CAID only when independently encoded action formats must be joined;
- uses AEC only when local policy requires multiple evidence legs;
- does not require a second PDP or define a universal token;
- distinguishes an authorized MCP or API request from a downstream provider
  effect; and
- defines the post-permit sequence as stable replay identity, durable consume
  or reserve, provider entry, terminal or indeterminate outcome, and
  authenticated reconciliation without blind retry.

Every one-time native replay identity is fenced independently of the operation
record, so changing an operation identifier cannot make the same authority
spendable again.

`UPLOAD-THIS/` contains the candidate XML source. `RENDERS/` contains the text
and HTML produced from that source. This packet is staged review material. It
has not been submitted, published, adopted by a working group, or reviewed by
the referenced protocol owners. References to AP2 describe composition with
its native artifacts and do not claim AP2 interoperability.
