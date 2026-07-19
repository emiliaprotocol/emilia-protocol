---- MODULE ep_capability_witness ----
\* Non-vacuity witnesses. Each is the NEGATION of an "interesting state reached"
\* claim; TLC MUST report each as violated. A violation proves the interesting
\* state is reachable, hence the corresponding real invariant is non-vacuous.
EXTENDS ep_capability, FiniteSets

\* Should FAIL: some capability actually reaches consumed > 0 (a spend commits).
W_NoConsume == \A c \in Capabilities : consumed[c] = 0

\* Should FAIL: a delegated child is actually registered (parentPtr set).
W_NoChild == \A c \in registered : parentPtr[c] = "none"

\* Should FAIL: a delegation chain of depth 2 is actually reached.
W_NoDepth2 == \A c \in Capabilities : chainLen[c] < 2

\* Should FAIL: a partial-consumption state (reserved>0 AND consumed>0 on the
\* same capability) is actually reached.
W_NoPartial == \A c \in Capabilities : ~(reserved[c] > 0 /\ consumed[c] > 0)

\* Should FAIL: two operations are reserved simultaneously on one capability
\* (this is what makes ReservedIsReservedSum a real sum, not "reserved->0").
W_NoConcurrentReserve == \A c \in Capabilities : Cardinality(ReservedOpsOf(c)) <= 1
====
