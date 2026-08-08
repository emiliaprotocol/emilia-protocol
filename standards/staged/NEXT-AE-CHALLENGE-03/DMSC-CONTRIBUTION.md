Subject: Re: Deployment Scenarios and Gap Analysis for AI Agent Gateway -03

Linda, YiFei, Bing,

I worked the evidence-challenge question into concrete text rather than another
architecture proposal. I think it fits as one mechanism under the gateway
handoff work while leaving conserved admission as the separate Section 7.8
problem:

> When a receiving gateway refuses an action because required authorization
> evidence is missing, stale, or unverifiable, it may return a structured
> evidence challenge identifying the exact action, outstanding evidence
> requirements, applicable freshness or status constraints, and supported
> presentation profiles. The challenge does not authorize the action or
> transfer admission ownership; conserved admission across gateway boundaries
> remains the separate requirement described in Section 7.8.

One conformance case would make the boundary testable: Gateway B derives the
exact action under its own pinned profile and challenges Gateway A for a
current approval. B must refuse an action mismatch, stale status, replayed
challenge, or unsupported presentation profile. A second attempt at the same
single-use right concurrently at A and B must not pass merely because both
gateways understand the challenge; it passes only under a separate mechanism
that establishes exclusive admission, or else B refuses or returns an
indeterminate result.

I have put the transport-neutral challenge and the HTTP binding in
`draft-schrock-ae-challenge-03`, with this DMSC use explicitly informative. If
this wording helps the draft, I am happy to turn it into the exact edits and
test case you want for the next revision.

Best,
Iman

