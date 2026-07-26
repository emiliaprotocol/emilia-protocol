---------------------- MODULE ep_autonomy_control_plane ----------------------
\* Bounded safety model for the EMILIA Autonomy Control Plane profile.
\*
\* A human-authorized root grants a finite action set and budget. An agent may
\* derive a child objective, but only as a subset of that authority. Execution
\* additionally requires independent evaluation, fresh fitness evidence, a
\* bounded canary, and a non-suspended status. The unsafe configuration enables
\* one deliberate self-expansion transition and MUST falsify AuthorityNeverExpands.
\*
\* This model abstracts signatures, CAID computation, clocks, test truth,
\* deployment systems, and durable storage. TLC checks a finite control model;
\* it is not an implementation refinement or an unbounded theorem.

EXTENDS Naturals, FiniteSets

CONSTANT AllowSelfExpansion

VARIABLES childActions, childBudget, derived, independentlyApproved,
          fitnessPassed, canaryPassed, suspended, executed

vars == <<childActions, childBudget, derived, independentlyApproved,
          fitnessPassed, canaryPassed, suspended, executed>>

Actions == {"inspect", "patch", "deploy"}
RootActions == {"inspect", "patch"}
RootBudget == 2

Init ==
  /\ childActions = {}
  /\ childBudget = 0
  /\ derived = FALSE
  /\ independentlyApproved = FALSE
  /\ fitnessPassed = FALSE
  /\ canaryPassed = FALSE
  /\ suspended = FALSE
  /\ executed = FALSE

DeriveBounded ==
  /\ ~derived
  /\ \E selected \in SUBSET RootActions, budget \in 0..RootBudget:
       /\ childActions' = selected
       /\ childBudget' = budget
  /\ derived' = TRUE
  /\ UNCHANGED <<independentlyApproved, fitnessPassed, canaryPassed,
                  suspended, executed>>

UnsafeSelfExpansion ==
  /\ AllowSelfExpansion
  /\ ~derived
  /\ childActions' = RootActions \union {"deploy"}
  /\ childBudget' = RootBudget + 1
  /\ derived' = TRUE
  /\ UNCHANGED <<independentlyApproved, fitnessPassed, canaryPassed,
                  suspended, executed>>

ApproveIndependently ==
  /\ derived
  /\ ~independentlyApproved
  /\ independentlyApproved' = TRUE
  /\ UNCHANGED <<childActions, childBudget, derived, fitnessPassed,
                  canaryPassed, suspended, executed>>

AcceptFitness ==
  /\ derived
  /\ ~fitnessPassed
  /\ fitnessPassed' = TRUE
  /\ UNCHANGED <<childActions, childBudget, derived, independentlyApproved,
                  canaryPassed, suspended, executed>>

AcceptCanary ==
  /\ fitnessPassed
  /\ ~canaryPassed
  /\ canaryPassed' = TRUE
  /\ UNCHANGED <<childActions, childBudget, derived, independentlyApproved,
                  fitnessPassed, suspended, executed>>

Suspend ==
  /\ ~suspended
  /\ suspended' = TRUE
  /\ UNCHANGED <<childActions, childBudget, derived, independentlyApproved,
                  fitnessPassed, canaryPassed, executed>>

Execute ==
  /\ derived
  /\ independentlyApproved
  /\ fitnessPassed
  /\ canaryPassed
  /\ ~suspended
  /\ ~executed
  /\ executed' = TRUE
  /\ UNCHANGED <<childActions, childBudget, derived, independentlyApproved,
                  fitnessPassed, canaryPassed, suspended>>

Next ==
  \/ DeriveBounded
  \/ UnsafeSelfExpansion
  \/ ApproveIndependently
  \/ AcceptFitness
  \/ AcceptCanary
  \/ Suspend
  \/ Execute

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ childActions \subseteq Actions
  /\ childBudget \in 0..(RootBudget + 1)
  /\ derived \in BOOLEAN
  /\ independentlyApproved \in BOOLEAN
  /\ fitnessPassed \in BOOLEAN
  /\ canaryPassed \in BOOLEAN
  /\ suspended \in BOOLEAN
  /\ executed \in BOOLEAN

AuthorityNeverExpands ==
  /\ childActions \subseteq RootActions
  /\ childBudget <= RootBudget

ExecutionRequiresIndependentEvidence ==
  executed => independentlyApproved /\ fitnessPassed /\ canaryPassed

SuspensionBlocksExecution == suspended => ~ENABLED Execute

=============================================================================
