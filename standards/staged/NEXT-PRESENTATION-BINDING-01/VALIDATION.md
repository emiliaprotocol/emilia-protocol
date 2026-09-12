# Validation

- `xml2rfc 3.34.0 --no-network --text`: PASS.
- `xml2rfc 3.34.0 --no-network --html`: PASS.
- The retained text and HTML both contain Section 6.1, "Receipt and
  Presentation Evidence Remain Distinct."
- xml2rfc retained the source draft's existing unused-RFC8785 warning. No new
  schema or reference warning was introduced by the boundary section.
- This is candidate rendering evidence, not submission or publication
  evidence.
