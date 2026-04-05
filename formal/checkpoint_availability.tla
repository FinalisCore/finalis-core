------------------------------ MODULE checkpoint_availability ------------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Normative mapping:
\* - docs/spec/CHECKPOINT_DERIVATION_SPEC.md
\* - docs/spec/AVAILABILITY_STATE_COMPLETENESS.md
\*
\* This model abstracts live checkpoint derivation at the operator/validator
\* eligibility and committee-selection layer. It preserves:
\* - finalized-history-driven validator lifecycle
\* - consensus-relevant availability projection
\* - explicit fallback/hysteresis mode selection
\* - deterministic total-order committee selection
\* - replay/restore/rebuild equivalence
\* - exclusion of observability-only evidence from checkpoint outputs

CONSTANTS ScenarioId, CommitteeSize, MinEligible

v1 == "v1"
v2 == "v2"
v3 == "v3"

o1 == "o1"
o2 == "o2"
o3 == "o3"

ACTIVE == "ACTIVE"
WARMUP == "WARMUP"
PROBATION == "PROBATION"
EJECTED == "EJECTED"

ValidatorOrder == <<v1, v2, v3>>
OperatorOrder == <<o1, o2, o3>>
RebuildValidatorOrder == <<v2, v3, v1>>
ValidatorToOperator == [v1 |-> o1, v2 |-> o2, v3 |-> o3]
RankOrder == <<0, 1, 2>>

BaselineHistory ==
    <<
      [ epoch |-> 1,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> WARMUP],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2},
        candidateRank |-> [v1 |-> 0, v2 |-> 1, v3 |-> 1]
      ],
      [ epoch |-> 2,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2, o3},
        candidateRank |-> [v1 |-> 1, v2 |-> 1, v3 |-> 0]
      ],
      [ epoch |-> 3,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> PROBATION, o3 |-> EJECTED],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1},
        candidateRank |-> [v1 |-> 2, v2 |-> 0, v3 |-> 1]
      ]
    >>

StickyFallbackHistory ==
    <<
      [ epoch |-> 1,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> WARMUP],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2},
        candidateRank |-> [v1 |-> 1, v2 |-> 0, v3 |-> 2]
      ],
      [ epoch |-> 2,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2, o3},
        candidateRank |-> [v1 |-> 2, v2 |-> 1, v3 |-> 0]
      ],
      [ epoch |-> 3,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> WARMUP, o3 |-> EJECTED],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1},
        candidateRank |-> [v1 |-> 0, v2 |-> 1, v3 |-> 2]
      ],
      [ epoch |-> 4,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> EJECTED],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2},
        candidateRank |-> [v1 |-> 1, v2 |-> 0, v3 |-> 2]
      ]
    >>

OrderingTieHistory ==
    <<
      [ epoch |-> 1,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2, o3},
        candidateRank |-> [v1 |-> 0, v2 |-> 0, v3 |-> 0]
      ],
      [ epoch |-> 2,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2, o3},
        candidateRank |-> [v1 |-> 1, v2 |-> 1, v3 |-> 1]
      ]
    >>

LongHorizonHistory ==
    <<
      [ epoch |-> 1,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> WARMUP],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2},
        candidateRank |-> [v1 |-> 0, v2 |-> 1, v3 |-> 2]
      ],
      [ epoch |-> 2,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2, o3},
        candidateRank |-> [v1 |-> 1, v2 |-> 0, v3 |-> 2]
      ],
      [ epoch |-> 3,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> PROBATION, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o3},
        candidateRank |-> [v1 |-> 2, v2 |-> 1, v3 |-> 0]
      ],
      [ epoch |-> 4,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2, o3},
        candidateRank |-> [v1 |-> 0, v2 |-> 2, v3 |-> 1]
      ],
      [ epoch |-> 5,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> WARMUP, o3 |-> EJECTED],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1},
        candidateRank |-> [v1 |-> 1, v2 |-> 0, v3 |-> 2]
      ],
      [ epoch |-> 6,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> WARMUP],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2},
        candidateRank |-> [v1 |-> 2, v2 |-> 0, v3 |-> 1]
      ]
    >>

History ==
    IF ScenarioId = 1 THEN BaselineHistory
    ELSE IF ScenarioId = 2 THEN StickyFallbackHistory
    ELSE IF ScenarioId = 3 THEN OrderingTieHistory
    ELSE LongHorizonHistory

Schedules == {"continuous", "restore", "rebuild"}
Modes == {"NORMAL", "FALLBACK"}
Reasons == {"NONE", "INSUFFICIENT_ELIGIBLE_OPERATORS", "HYSTERESIS_RECOVERY_PENDING"}
Statuses == {WARMUP, ACTIVE, PROBATION, EJECTED}
Phases == {"load", "project", "derive", "done"}

VARIABLES pos, phase, rawAvail, projectedAvail, checkpoint

vars == <<pos, phase, rawAvail, projectedAvail, checkpoint>>

SeqToSet(seq) == {seq[i] : i \in 1..Len(seq)}

NoDuplicates(seq) == \A i, j \in 1..Len(seq) : i # j => seq[i] # seq[j]

IsPermutation(left, right) ==
    /\ Len(left) = Len(right)
    /\ NoDuplicates(left)
    /\ NoDuplicates(right)
    /\ SeqToSet(left) = SeqToSet(right)

ValidatorSet == SeqToSet(ValidatorOrder)
OperatorSet == SeqToSet(OperatorOrder)
RankSet == SeqToSet(RankOrder)

RECURSIVE ReverseSeq(_)
ReverseSeq(seq) ==
    IF seq = <<>> THEN <<>> ELSE ReverseSeq(Tail(seq)) \o <<Head(seq)>>

RestoreValidatorOrder == ReverseSeq(ValidatorOrder)

PresentedValidatorOrder(style) ==
    IF style = "continuous" THEN ValidatorOrder
    ELSE IF style = "restore" THEN RestoreValidatorOrder
    ELSE RebuildValidatorOrder

DummyRawAvailability ==
    [ epoch |-> 0,
      availabilityStatus |-> [o \in OperatorSet |-> WARMUP],
      availabilityBondOk |-> {},
      availabilityScoreOk |-> {},
      evidence |-> <<>>,
      presentedOrder |-> ValidatorOrder ]

DummyProjectedAvailability ==
    [ epoch |-> 0,
      availabilityStatus |-> [o \in OperatorSet |-> WARMUP],
      availabilityBondOk |-> {},
      availabilityScoreOk |-> {} ]

InitCheckpoint ==
    [ epoch |-> 0,
      mode |-> "FALLBACK",
      reason |-> "INSUFFICIENT_ELIGIBLE_OPERATORS",
      eligibleCount |-> 0,
      committee |-> <<>>,
      proposerSchedule |-> <<>> ]

HistoryAt(n) == History[n]

RawEvidence(style, epoch) ==
    <<[style |-> style, epoch |-> epoch],
      [style |-> style, epoch |-> epoch + 100]>>

LoadRaw(style, step) ==
    [ epoch |-> step.epoch,
      availabilityStatus |-> step.availabilityStatus,
      availabilityBondOk |-> step.availabilityBondOk,
      availabilityScoreOk |-> step.availabilityScoreOk,
      evidence |-> RawEvidence(style, step.epoch),
      presentedOrder |-> PresentedValidatorOrder(style) ]

ConsensusRelevantAvailabilityState(raw) ==
    [ epoch |-> raw.epoch,
      availabilityStatus |-> raw.availabilityStatus,
      availabilityBondOk |-> raw.availabilityBondOk,
      availabilityScoreOk |-> raw.availabilityScoreOk ]

AvailabilityEvidence(raw) ==
    IF "evidence" \in DOMAIN raw THEN raw.evidence ELSE <<>>

AvailabilityEligibleOperator(avail, operator) ==
    /\ avail.availabilityStatus[operator] = ACTIVE
    /\ operator \in avail.availabilityBondOk
    /\ operator \in avail.availabilityScoreOk

EligibleOperatorSet(avail) ==
    {operator \in OperatorSet : AvailabilityEligibleOperator(avail, operator)}

EligibleOperatorCount(avail) == Cardinality(EligibleOperatorSet(avail))

BaseEligible(step, validator) ==
    /\ validator \in step.lifecycleActive
    /\ validator \in step.hasBond
    /\ (validator \in step.genesisValidators \/ validator \in step.meetsMinBond)

CommitteeEligible(step, avail, mode, validator) ==
    /\ BaseEligible(step, validator)
    /\ (mode = "FALLBACK" \/ AvailabilityEligibleOperator(avail, ValidatorToOperator[validator]))

ModeReason(prevMode, eligibleCount) ==
    IF prevMode = "NORMAL" THEN
        IF eligibleCount < MinEligible THEN
            [mode |-> "FALLBACK", reason |-> "INSUFFICIENT_ELIGIBLE_OPERATORS"]
        ELSE
            [mode |-> "NORMAL", reason |-> "NONE"]
    ELSE
        IF eligibleCount >= MinEligible + 1 THEN
            [mode |-> "NORMAL", reason |-> "NONE"]
        ELSE IF eligibleCount = MinEligible THEN
            [mode |-> "FALLBACK", reason |-> "HYSTERESIS_RECOVERY_PENDING"]
        ELSE
            [mode |-> "FALLBACK", reason |-> "INSUFFICIENT_ELIGIBLE_OPERATORS"]

FallbackSticky(cp) == cp.mode = "FALLBACK" /\ cp.reason = "HYSTERESIS_RECOVERY_PENDING"

RECURSIVE FilterSeq(_, _)
FilterSeq(seq, allowed) ==
    IF seq = <<>> THEN
        <<>>
    ELSE IF Head(seq) \in allowed THEN
        <<Head(seq)>> \o FilterSeq(Tail(seq), allowed)
    ELSE
        FilterSeq(Tail(seq), allowed)

PresentedEligibleCandidates(style, step, avail, mode) ==
    FilterSeq(PresentedValidatorOrder(style),
              {validator \in ValidatorSet : CommitteeEligible(step, avail, mode, validator)})

RankGroup(step, avail, mode, rank) ==
    {validator \in ValidatorSet :
        CommitteeEligible(step, avail, mode, validator)
        /\ step.candidateRank[validator] = rank}

RECURSIVE ConcatRankGroups(_, _, _, _)
ConcatRankGroups(rankSeq, step, avail, mode) ==
    IF rankSeq = <<>> THEN
        <<>>
    ELSE
        FilterSeq(ValidatorOrder, RankGroup(step, avail, mode, Head(rankSeq))) \o
        ConcatRankGroups(Tail(rankSeq), step, avail, mode)

CanonicalCandidateSequence(step, avail, mode, style) ==
    LET _presented == PresentedEligibleCandidates(style, step, avail, mode)
    IN ConcatRankGroups(RankOrder, step, avail, mode)

TakeCommittee(seq) ==
    SubSeq(seq, 1, IF Len(seq) < CommitteeSize THEN Len(seq) ELSE CommitteeSize)

ProposerSchedule(committee, epoch) ==
    \* Abstract deterministic permutation placeholder. The live implementation
    \* derives a deterministic permutation from the finalized checkpoint. This
    \* model preserves determinism without modeling the byte-level permutation.
    committee

DeriveCheckpoint(step, avail, prevCheckpoint, style) ==
    LET decision == ModeReason(prevCheckpoint.mode, EligibleOperatorCount(avail))
        candidates == CanonicalCandidateSequence(step, avail, decision.mode, style)
        committee == TakeCommittee(candidates)
    IN [ epoch |-> step.epoch,
          mode |-> decision.mode,
          reason |-> decision.reason,
          eligibleCount |-> EligibleOperatorCount(avail),
          committee |-> committee,
          proposerSchedule |-> ProposerSchedule(committee, step.epoch) ]

ExpectedProjectedAt(n) ==
    IF n = 0 THEN DummyProjectedAvailability
    ELSE ConsensusRelevantAvailabilityState(LoadRaw("continuous", HistoryAt(n)))

RECURSIVE ExpectedCheckpointAt(_)
ExpectedCheckpointAt(n) ==
    IF n = 0 THEN
        InitCheckpoint
    ELSE
        DeriveCheckpoint(HistoryAt(n), ExpectedProjectedAt(n), ExpectedCheckpointAt(n - 1), "continuous")

TypeHistoryStep(step) ==
    /\ step.epoch \in Nat \ {0}
    /\ step.lifecycleActive \subseteq ValidatorSet
    /\ step.hasBond \subseteq ValidatorSet
    /\ step.genesisValidators \subseteq ValidatorSet
    /\ step.meetsMinBond \subseteq ValidatorSet
    /\ step.availabilityStatus \in [OperatorSet -> Statuses]
    /\ step.availabilityBondOk \subseteq OperatorSet
    /\ step.availabilityScoreOk \subseteq OperatorSet
    /\ step.candidateRank \in [ValidatorSet -> RankSet]

TypeRaw(raw) ==
    /\ raw.epoch \in Nat
    /\ raw.availabilityStatus \in [OperatorSet -> Statuses]
    /\ raw.availabilityBondOk \subseteq OperatorSet
    /\ raw.availabilityScoreOk \subseteq OperatorSet
    /\ raw.evidence \in Seq([style : Schedules, epoch : Nat])
    /\ IsPermutation(raw.presentedOrder, ValidatorOrder)

TypeProjected(avail) ==
    /\ avail.epoch \in Nat
    /\ avail.availabilityStatus \in [OperatorSet -> Statuses]
    /\ avail.availabilityBondOk \subseteq OperatorSet
    /\ avail.availabilityScoreOk \subseteq OperatorSet

TypeCheckpoint(cp) ==
    /\ cp.epoch \in Nat
    /\ cp.mode \in Modes
    /\ cp.reason \in Reasons
    /\ cp.eligibleCount \in 0..Cardinality(OperatorSet)
    /\ cp.committee \in Seq(ValidatorSet)
    /\ cp.proposerSchedule \in Seq(ValidatorSet)

Init ==
    /\ pos = [s \in Schedules |-> 0]
    /\ phase = [s \in Schedules |-> "load"]
    /\ rawAvail = [s \in Schedules |-> DummyRawAvailability]
    /\ projectedAvail = [s \in Schedules |-> DummyProjectedAvailability]
    /\ checkpoint = [s \in Schedules |-> InitCheckpoint]

LoadStep(s) ==
    /\ s \in Schedules
    /\ phase[s] = "load"
    /\ pos[s] < Len(History)
    /\ rawAvail' = [rawAvail EXCEPT ![s] = LoadRaw(s, HistoryAt(pos[s] + 1))]
    /\ phase' = [phase EXCEPT ![s] = "project"]
    /\ UNCHANGED <<pos, projectedAvail, checkpoint>>

ProjectStep(s) ==
    /\ s \in Schedules
    /\ phase[s] = "project"
    /\ projectedAvail' = [projectedAvail EXCEPT ![s] = ConsensusRelevantAvailabilityState(rawAvail[s])]
    /\ phase' = [phase EXCEPT ![s] = "derive"]
    /\ UNCHANGED <<pos, rawAvail, checkpoint>>

DeriveStep(s) ==
    /\ s \in Schedules
    /\ phase[s] = "derive"
    /\ pos[s] < Len(History)
    /\ checkpoint' =
        [checkpoint EXCEPT ![s] = DeriveCheckpoint(HistoryAt(pos[s] + 1), projectedAvail[s], checkpoint[s], s)]
    /\ pos' = [pos EXCEPT ![s] = pos[s] + 1]
    /\ phase' =
        [phase EXCEPT ![s] = IF pos[s] + 1 = Len(History) THEN "done" ELSE "load"]
    /\ UNCHANGED <<rawAvail, projectedAvail>>

Next ==
    \E s \in Schedules :
        LoadStep(s) \/ ProjectStep(s) \/ DeriveStep(s)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ NoDuplicates(ValidatorOrder)
    /\ NoDuplicates(OperatorOrder)
    /\ IsPermutation(RestoreValidatorOrder, ValidatorOrder)
    /\ IsPermutation(RebuildValidatorOrder, ValidatorOrder)
    /\ NoDuplicates(RankOrder)
    /\ ScenarioId \in 1..4
    /\ Cardinality(Statuses) = 4
    /\ ValidatorToOperator \in [ValidatorSet -> OperatorSet]
    /\ CommitteeSize \in 0..Len(ValidatorOrder)
    /\ MinEligible \in 0..Cardinality(OperatorSet)
    /\ \A i \in 1..Len(History) : TypeHistoryStep(HistoryAt(i))
    /\ pos \in [Schedules -> 0..Len(History)]
    /\ phase \in [Schedules -> Phases]
    /\ \A s \in Schedules : TypeRaw(rawAvail[s])
    /\ \A s \in Schedules : TypeProjected(projectedAvail[s])
    /\ \A s \in Schedules : TypeCheckpoint(checkpoint[s])

ProjectionIdempotent ==
    \A s \in Schedules :
        phase[s] # "load" =>
            ConsensusRelevantAvailabilityState(rawAvail[s]) =
            ConsensusRelevantAvailabilityState(ConsensusRelevantAvailabilityState(rawAvail[s]))

EvidenceProjectionIdempotent ==
    \A i \in 1..Len(History) :
        \A s \in Schedules :
            ConsensusRelevantAvailabilityState(LoadRaw(s, HistoryAt(i))) =
            ConsensusRelevantAvailabilityState(
                ConsensusRelevantAvailabilityState(LoadRaw(s, HistoryAt(i))))

EvidenceIsolation ==
    \A i \in 1..Len(History) :
        \A s, t \in Schedules :
            ConsensusRelevantAvailabilityState(LoadRaw(s, HistoryAt(i))) =
            ConsensusRelevantAvailabilityState(LoadRaw(t, HistoryAt(i)))

ProjectedReplayEquivalence ==
    \A s, t \in Schedules :
        /\ pos[s] = pos[t]
        /\ phase[s] \in {"load", "done"}
        /\ phase[t] \in {"load", "done"}
        => projectedAvail[s] = projectedAvail[t]

CheckpointReplayEquivalence ==
    \A s, t \in Schedules :
        pos[s] = pos[t] => checkpoint[s] = checkpoint[t]

CheckpointMatchesExpected ==
    \A s \in Schedules :
        checkpoint[s] = ExpectedCheckpointAt(pos[s])

ProjectedMatchesExpected ==
    \A s \in Schedules :
        /\ phase[s] \in {"load", "done"}
        => projectedAvail[s] = ExpectedProjectedAt(pos[s])

HysteresisConformance ==
    \A n \in 1..Len(History) :
        LET prev == ExpectedCheckpointAt(n - 1)
            avail == ExpectedProjectedAt(n)
            decision == ModeReason(prev.mode, EligibleOperatorCount(avail))
            cp == ExpectedCheckpointAt(n)
        IN /\ cp.mode = decision.mode
           /\ cp.reason = decision.reason
           /\ cp.eligibleCount = EligibleOperatorCount(avail)

StyleIndependence ==
    \A n \in 1..Len(History) :
        \A s \in Schedules :
            DeriveCheckpoint(HistoryAt(n), ExpectedProjectedAt(n), ExpectedCheckpointAt(n - 1), s)
            = ExpectedCheckpointAt(n)

CommitteeEligibilitySoundness ==
    \A n \in 1..Len(History) :
        \A v \in SeqToSet(ExpectedCheckpointAt(n).committee) :
            CommitteeEligible(HistoryAt(n), ExpectedProjectedAt(n), ExpectedCheckpointAt(n).mode, v)

CommitteeBounded ==
    \A n \in 0..Len(History) :
        Len(ExpectedCheckpointAt(n).committee) <= CommitteeSize

StickyFallbackDefinition ==
    \A n \in 0..Len(History) :
        FallbackSticky(ExpectedCheckpointAt(n)) =
        (ExpectedCheckpointAt(n).mode = "FALLBACK" /\ ExpectedCheckpointAt(n).reason = "HYSTERESIS_RECOVERY_PENDING")

=============================================================================
