# Authority Record evidence sources v1

Authority Records begin with source inspection, but repository source is not the product boundary. Autonomous systems may be assembled from generated code, signed releases, hosted tools, deployment configuration, and runtime services that a source scan cannot fully inspect.

The private `EMILIA-AUTHORITY-EVIDENCE-OBSERVATION-v1` envelope records evidence from seven source classes:

- repository state;
- signed release;
- build provenance;
- tool schema;
- deployment manifest;
- runtime attestation;
- observed action interface.

Every observation names the watched pointer, the immutable identifier it resolved to, the exact evidence digest, the collector and profile, the observation and expiry times, and the Authority Record surfaces it supports. A successful resolution to different immutable bytes is `STALE`. A lookup failure is `UNAVAILABLE`. An ambiguous result is `INDETERMINATE`.

When exact bytes cannot be inspected, the record uses `UNVERIFIABLE` or `INDETERMINATE` with a reason. It never converts missing evidence into a score, certification, or favorable verdict.

## Publication boundary

These envelopes are private preparation evidence. They do not alter the closed public Authority Record v1 projection and do not authorize publication. A named record becomes public only after the owner proves control, reviews the redacted public projection, and approves the exact bytes. Payment can buy depth, freshness, monitoring, and presentation. It cannot buy a favorable conclusion.

The current beta claim path remains GitHub-repository based. Supporting additional owner-proof mechanisms is separate work from accepting additional evidence sources.

## Relationship to software provenance

Software provenance answers what program or build is present. An Authority Record maps observable consequential-action surfaces and their evidence. Gate separately decides whether one exact action may cross a configured protected boundary. None of those statements proves the others.
