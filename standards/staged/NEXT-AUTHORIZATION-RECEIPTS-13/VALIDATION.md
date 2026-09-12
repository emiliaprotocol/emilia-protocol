# Validation

- `xml2rfc 3.34.0 --no-network --text`: PASS.
- `xml2rfc 3.34.0 --no-network --html`: PASS.
- The retained text and HTML both contain Section 13.13, "What Successful
  Verification Does Not Establish."
- xml2rfc retained the source draft's existing warnings: no explicit stream on
  an IETF Standards Track document and inferred `consensus="true"`. No new
  schema or reference warning was introduced by the boundary section.
- This is candidate rendering evidence, not submission or publication
  evidence.
