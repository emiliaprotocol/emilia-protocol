Subject: Re: Deployment Scenarios and Gap Analysis for AI Agent Gateway -03

Linda, YiFei, Bing, and Aijun,

Thank you, Linda. I followed your direction to keep this mechanism-neutral.
The attached revision adds Section 7.8 as the gap and requirements section; it
does not define a distributed authorization-transfer protocol.

I also worked the narrower evidence-challenge seam into concrete text that can
fit under the handoff discussion without blurring it with conserved admission:

> When a receiving gateway refuses an action because required authorization
> evidence is missing, stale, or unverifiable, it may return a structured
> evidence challenge identifying the exact action, outstanding evidence
> requirements, applicable freshness or status constraints, and supported
> presentation profiles. The challenge does not authorize the action or
> transfer admission ownership; conserved admission across gateway boundaries
> remains the separate requirement described in Section 7.8.

One conformance case would make that boundary testable: Gateway B derives the
exact action under its own pinned profile and challenges Gateway A for a
current approval. B must refuse an action mismatch, stale status, a replayed
challenge, or an unsupported presentation profile. A second attempt at the
same single-use right concurrently at A and B must not pass merely because both
gateways understand the challenge; it passes only under a separate mechanism
that establishes exclusive admission, or else B refuses or returns an
indeterminate result.

For reference, I have now published the transport-neutral challenge and its
separate HTTP binding in `draft-schrock-ae-challenge-03`:

https://datatracker.ietf.org/doc/draft-schrock-ae-challenge/

The DMSC gateway use is explicitly informative. If this wording helps the
draft, I am happy to place the paragraph and conformance case exactly where you
prefer in the next revision.

Best,
Iman
