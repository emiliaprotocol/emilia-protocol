---------------------- MODULE ep_authority_program ----------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Public bounded model for EP-AUTHORITY-PROGRAM-v1.
\*
\* This model mirrors the pure verifier in
\* packages/verify/src/authority-program.ts.  It is a verification fold over
\* one relying-party-pinned, signed series/parallel program and one immutable
\* signed receipt per declared stage.  `checked` is model-checker bookkeeping;
\* it is NOT a mutable workflow row, scheduler, transition API, or execution
\* state.  The implementation accepts the complete bundle in any array order.
\*
\* Deliberate scope boundary: a successful authority-program result proves
\* program/stage/evidence/capability/allocation binding only.  It never proves
\* that a material action executed.  executionProven is therefore invariantly
\* FALSE, matching the verifier's `execution_proven: false` result.

CONSTANTS RootNode, Nodes, NodeKind, Children, StageForNode

\* Finite model used by ep_authority_program.cfg.  These operators are cfg
\* overrides, not protocol constants.
ModelNodes == {
  "seq-root", "stage-a-node", "parallel-bc",
  "stage-b-node", "stage-c-node", "stage-d-node"
}

NodeKindModel == [node \in ModelNodes |->
  CASE node = "seq-root" -> "sequence"
    [] node = "parallel-bc" -> "parallel"
    [] OTHER -> "stage"]

ChildrenModel == [node \in ModelNodes |->
  CASE node = "seq-root" ->
         <<"stage-a-node", "parallel-bc", "stage-d-node">>
    [] node = "parallel-bc" -> <<"stage-b-node", "stage-c-node">>
    [] OTHER -> <<>>]

StageForNodeModel == [node \in ModelNodes |->
  CASE node = "stage-a-node" -> "stage-a"
    [] node = "stage-b-node" -> "stage-b"
    [] node = "stage-c-node" -> "stage-c"
    [] node = "stage-d-node" -> "stage-d"
    [] OTHER -> "none"]

StageNodes == {n \in Nodes : NodeKind[n] = "stage"}
SequenceNodes == {n \in Nodes : NodeKind[n] = "sequence"}
ParallelNodes == {n \in Nodes : NodeKind[n] = "parallel"}
Stages == {StageForNode[n] : n \in StageNodes}

RECURSIVE EntryStages(_)
EntryStages(n) ==
  CASE NodeKind[n] = "stage" -> {StageForNode[n]}
    [] NodeKind[n] = "sequence" -> EntryStages(Children[n][1])
    [] NodeKind[n] = "parallel" ->
         UNION {EntryStages(Children[n][i]) : i \in 1..Len(Children[n])}

RECURSIVE ExitStages(_)
ExitStages(n) ==
  CASE NodeKind[n] = "stage" -> {StageForNode[n]}
    [] NodeKind[n] = "sequence" ->
         ExitStages(Children[n][Len(Children[n])])
    [] NodeKind[n] = "parallel" ->
         UNION {ExitStages(Children[n][i]) : i \in 1..Len(Children[n])}

SequenceEdges(n) ==
  IF NodeKind[n] # "sequence"
  THEN {}
  ELSE UNION {
    {[from |-> source, to |-> target] :
       source \in ExitStages(Children[n][i]),
       target \in EntryStages(Children[n][i + 1])}
    : i \in 1..(Len(Children[n]) - 1)
  }

DerivedEdges == UNION {SequenceEdges(n) : n \in Nodes}
ProgramPredecessors(stage) ==
  {edge.from : edge \in {candidate \in DerivedEdges : candidate.to = stage}}

ExpressionIsSeriesParallel ==
  /\ RootNode \in Nodes
  /\ NodeKind \in [Nodes -> {"stage", "sequence", "parallel"}]
  /\ Children \in [Nodes -> Seq(Nodes)]
  /\ StageForNode \in [Nodes -> (Stages \cup {"none"})]
  /\ \A n \in StageNodes :
       /\ Children[n] = <<>>
       /\ StageForNode[n] # "none"
  /\ \A n \in SequenceNodes :
       /\ Len(Children[n]) >= 2
       /\ StageForNode[n] = "none"
  /\ \A n \in ParallelNodes :
       /\ Len(Children[n]) >= 2
       /\ StageForNode[n] = "none"
  /\ Cardinality(StageNodes) = Cardinality(Stages)
  /\ EntryStages(RootNode) \subseteq Stages
  /\ ExitStages(RootNode) \subseteq Stages
  /\ \A edge \in DerivedEdges : edge.from # edge.to

GlobalFaults == {
  "none",
  "program-pin",
  "program-signature",
  "root-action-binding",
  "stage-set",
  "duplicate-receipt",
  "parallel-allocation"
}

StageFaults == {
  "stage-signature",
  "stage-authority",
  "root-binding",
  "predecessor-digest",
  "aec-binding",
  "aom-binding",
  "capability-narrowing"
}

FaultKinds == GlobalFaults \cup StageFaults

VARIABLES status, checked, faultKind, faultStage, executionProven
vars == <<status, checked, faultKind, faultStage, executionProven>>

ProgramPinned == faultKind # "program-pin"
ProgramSignatureValid == faultKind # "program-signature"
CompleteUniqueStageSet ==
  faultKind \notin {"stage-set", "duplicate-receipt"}
ParallelAllocationAuthoritative == faultKind # "parallel-allocation"
RootActionBindingVerified == faultKind # "root-action-binding"

StageSignatureValid(stage) ==
  ~(faultKind = "stage-signature" /\ faultStage = stage)
StageAuthorityExact(stage) ==
  ~(faultKind = "stage-authority" /\ faultStage = stage)
RootBindingExact(stage) ==
  ~(faultKind = "root-binding" /\ faultStage = stage)
PredecessorDigestsExact(stage) ==
  ~(faultKind = "predecessor-digest" /\ faultStage = stage)
AecJoinExact(stage) ==
  ~(faultKind = "aec-binding" /\ faultStage = stage)
AomJoinExact(stage) ==
  ~(faultKind = "aom-binding" /\ faultStage = stage)
CapabilityNarrowed(stage) ==
  ~(faultKind = "capability-narrowing" /\ faultStage = stage)

StageValid(stage) ==
  /\ StageSignatureValid(stage)
  /\ StageAuthorityExact(stage)
  /\ RootBindingExact(stage)
  /\ PredecessorDigestsExact(stage)
  /\ AecJoinExact(stage)
  /\ AomJoinExact(stage)
  /\ CapabilityNarrowed(stage)

ProgramEnvelopeValid ==
  /\ ProgramPinned
  /\ ProgramSignatureValid
  /\ RootActionBindingVerified
  /\ CompleteUniqueStageSet

Init ==
  /\ status = "checking"
  /\ checked = {}
  /\ faultKind \in FaultKinds
  /\ faultStage \in Stages
  /\ executionProven = FALSE

RejectProgram ==
  /\ status = "checking"
  /\ ~ProgramEnvelopeValid
  /\ status' = "invalid"
  /\ UNCHANGED <<checked, faultKind, faultStage, executionProven>>

CheckStage(stage) ==
  /\ status = "checking"
  /\ ProgramEnvelopeValid
  /\ stage \in Stages \ checked
  /\ ProgramPredecessors(stage) \subseteq checked
  /\ IF StageValid(stage)
        THEN /\ checked' = checked \cup {stage}
             /\ status' = "checking"
        ELSE /\ checked' = checked
             /\ status' = "invalid"
  /\ UNCHANGED <<faultKind, faultStage, executionProven>>

Finalize ==
  /\ status = "checking"
  /\ ProgramEnvelopeValid
  /\ checked = Stages
  /\ status' = IF ParallelAllocationAuthoritative THEN "valid" ELSE "invalid"
  /\ UNCHANGED <<checked, faultKind, faultStage, executionProven>>

TerminalStutter ==
  /\ status \in {"valid", "invalid"}
  /\ UNCHANGED vars

Evaluate ==
  RejectProgram
  \/ (\E stage \in Stages : CheckStage(stage))
  \/ Finalize
  \/ TerminalStutter

Spec == Init /\ [][Evaluate]_vars /\ WF_vars(Evaluate)

TypeOK ==
  /\ status \in {"checking", "valid", "invalid"}
  /\ checked \subseteq Stages
  /\ faultKind \in FaultKinds
  /\ faultStage \in Stages
  /\ executionProven \in BOOLEAN

CheckedReceiptsAreValid ==
  \A stage \in checked : StageValid(stage)

CheckedReceiptsHaveTheirPredecessors ==
  \A stage \in checked : ProgramPredecessors(stage) \subseteq checked

ValidOnlyAfterCompleteFold ==
  status = "valid" => checked = Stages

ValidImpliesPinnedSignedProgram ==
  status = "valid" => (ProgramPinned /\ ProgramSignatureValid)

ValidImpliesRootActionBinding ==
  status = "valid" => RootActionBindingVerified

ValidImpliesExactStageSet ==
  status = "valid" => CompleteUniqueStageSet

ValidImpliesExactReceiptBindings ==
  status = "valid" =>
    \A stage \in Stages :
      /\ StageSignatureValid(stage)
      /\ StageAuthorityExact(stage)
      /\ RootBindingExact(stage)
      /\ PredecessorDigestsExact(stage)
      /\ AecJoinExact(stage)
      /\ AomJoinExact(stage)

ConservationOfAuthority ==
  status = "valid" =>
    /\ \A stage \in Stages : CapabilityNarrowed(stage)
    /\ ParallelAllocationAuthoritative

NoExecutionProof == executionProven = FALSE

EventuallyTerminates == <>(status \in {"valid", "invalid"})

=============================================================================
