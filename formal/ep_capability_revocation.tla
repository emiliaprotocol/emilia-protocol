-------------------- MODULE ep_capability_revocation --------------------
\* Bounded model of BCR-03 revocation inheritance inside one authoritative
\* atomic state domain.  It separates two signed policies:
\*
\*   direct  -- revocation blocks the named capability and future children
\*              allocated from it, but does not retract already transferred
\*              descendant authority by itself;
\*   cascade -- revocation also blocks every later reservation and child
\*              allocation below the revoked ancestor.
\*
\* Revocation, reservation, and child registration are atomic transitions.
\* An owned reservation remains owned when revocation commits later.  Missing
\* ancestor state closes later admission rather than being interpreted as
\* active or direct.  The model does not claim cross-domain revocation,
\* revocation delivery, database correctness, or physical exactly-once effect.

EXTENDS Naturals, FiniteSets

CONSTANTS RootCap, ChildCap, GrandchildCap, Operations, MaxSteps

Capabilities == {RootCap, ChildCap, GrandchildCap}
Modes == {"direct", "cascade"}

Parent(c) ==
    CASE c = RootCap -> "none"
      [] c = ChildCap -> RootCap
      [] c = GrandchildCap -> ChildCap
      [] OTHER -> "none"

Ancestors(c) ==
    CASE c = RootCap -> {}
      [] c = ChildCap -> {RootCap}
      [] c = GrandchildCap -> {RootCap, ChildCap}
      [] OTHER -> {}

VARIABLES mode, registered, available, revoked, opStatus, opCap, step

vars == <<mode, registered, available, revoked, opStatus, opCap, step>>

LineageKnown(c) ==
    c \in available /\ Ancestors(c) \subseteq available

CascadeAncestorRevoked(c) ==
    \E a \in Ancestors(c) : a \in revoked /\ mode[a] = "cascade"

RevocationBlocks(c) ==
    c \in revoked \/ CascadeAncestorRevoked(c)

AdmissionEligible(c) ==
    c \in registered /\ LineageKnown(c) /\ ~RevocationBlocks(c)

ParentCanAllocate(c) ==
    c # RootCap
    /\ Parent(c) \in registered
    /\ LineageKnown(Parent(c))
    /\ ~RevocationBlocks(Parent(c))

Init ==
    /\ mode \in [Capabilities -> Modes]
    /\ registered = {RootCap}
    /\ available = {RootCap}
    /\ revoked = {}
    /\ opStatus = [o \in Operations |-> "none"]
    /\ opCap = [o \in Operations |-> "none"]
    /\ step = 0

RegisterChild(c) ==
    /\ step < MaxSteps
    /\ c \in {ChildCap, GrandchildCap}
    /\ c \notin registered
    /\ ParentCanAllocate(c)
    /\ registered' = registered \union {c}
    /\ available' = available \union {c}
    /\ step' = step + 1
    /\ UNCHANGED <<mode, revoked, opStatus, opCap>>

Reserve(c, o) ==
    /\ step < MaxSteps
    /\ c \in Capabilities
    /\ o \in Operations
    /\ opStatus[o] = "none"
    /\ AdmissionEligible(c)
    /\ opStatus' = [opStatus EXCEPT ![o] = "owned"]
    /\ opCap' = [opCap EXCEPT ![o] = c]
    /\ step' = step + 1
    /\ UNCHANGED <<mode, registered, available, revoked>>

Revoke(c) ==
    /\ step < MaxSteps
    /\ c \in registered
    /\ c \in available
    /\ c \notin revoked
    /\ revoked' = revoked \union {c}
    /\ step' = step + 1
    /\ UNCHANGED <<mode, registered, available, opStatus, opCap>>

LoseAncestorState(c) ==
    /\ step < MaxSteps
    /\ c \in available
    /\ available' = available \ {c}
    /\ step' = step + 1
    /\ UNCHANGED <<mode, registered, revoked, opStatus, opCap>>

Next ==
    \/ \E c \in Capabilities : RegisterChild(c)
    \/ \E c \in Capabilities, o \in Operations : Reserve(c, o)
    \/ \E c \in Capabilities : Revoke(c)
    \/ \E c \in Capabilities : LoseAncestorState(c)
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

BoundedExploration == step <= MaxSteps

TypeInvariant ==
    /\ mode \in [Capabilities -> Modes]
    /\ registered \subseteq Capabilities
    /\ available \subseteq registered
    /\ revoked \subseteq registered
    /\ opStatus \in [Operations -> {"none", "owned"}]
    /\ opCap \in [Operations -> Capabilities \union {"none"}]
    /\ step \in 0..MaxSteps

RegistrationOrder ==
    /\ ChildCap \in registered => RootCap \in registered
    /\ GrandchildCap \in registered => ChildCap \in registered

OwnedOperationSound ==
    \A o \in Operations :
      opStatus[o] = "owned" => opCap[o] \in registered

CascadeRevocationClosesDescendants ==
    \A c \in registered : CascadeAncestorRevoked(c) => ~AdmissionEligible(c)

DirectRevocationDoesNotRetractTransferredAuthority ==
    \A c \in registered :
      c \notin revoked
      /\ LineageKnown(c)
      /\ (\A a \in Ancestors(c) : a \in revoked => mode[a] = "direct")
      => AdmissionEligible(c)

MissingLineageFailsClosed ==
    \A c \in registered : ~LineageKnown(c) => ~AdmissionEligible(c)

ModeImmutable ==
    [][mode' = mode]_vars

RevocationIrreversible ==
    [][revoked \subseteq revoked']_vars

OwnedReservationNeverReopens ==
    [][\A o \in Operations :
         opStatus[o] = "owned" => opStatus'[o] = "owned"]_vars

NewReservationRequiresCurrentCompleteLineage ==
    [][\A o \in Operations :
         opStatus[o] = "none" /\ opStatus'[o] = "owned"
         => AdmissionEligible(opCap'[o])]_vars

NewChildRequiresActiveParentLineage ==
    [][\A c \in {ChildCap, GrandchildCap} :
         c \notin registered /\ c \in registered'
         => ParentCanAllocate(c)]_vars

THEOREM Spec => []TypeInvariant
THEOREM Spec => []RegistrationOrder
THEOREM Spec => []OwnedOperationSound
THEOREM Spec => []CascadeRevocationClosesDescendants
THEOREM Spec => []DirectRevocationDoesNotRetractTransferredAuthority
THEOREM Spec => []MissingLineageFailsClosed
THEOREM Spec => ModeImmutable
THEOREM Spec => RevocationIrreversible
THEOREM Spec => OwnedReservationNeverReopens
THEOREM Spec => NewReservationRequiresCurrentCompleteLineage
THEOREM Spec => NewChildRequiresActiveParentLineage

==========================================================================
