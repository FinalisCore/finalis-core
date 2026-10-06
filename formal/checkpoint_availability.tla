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
\* - fallback committee sizing: committee = min(K, len(C)), never shrunk to the
\*   eligible-operator count (786f59d)
\* - per-operator bond aggregation with saturating addition (786f59d)
\* - audit evidence attributed only when signed by the challenged operator (1809a75)
\* - emergency committee recovery: an empty candidate set takes up to
\*   EmergencyMaxMembers bonded members of the EmergencyLookbackEpochs prior
\*   committees (consensus::emergency_fallback_committee_members); never empty

CONSTANTS ScenarioId, CommitteeSize, MinEligible, MaxBond

v1 == "v1"
v2 == "v2"
v3 == "v3"
\* Secondary validator of operator o2. It mirrors v2's finalized lifecycle facts,
\* so it exercises bond aggregation without changing representative selection.
v4 == "v4"

o1 == "o1"
o2 == "o2"
o3 == "o3"

ACTIVE == "ACTIVE"
WARMUP == "WARMUP"
PROBATION == "PROBATION"
EJECTED == "EJECTED"

ValidatorOrder == <<v1, v2, v3>>
AllValidatorOrder == <<v1, v2, v3, v4>>
OperatorOrder == <<o1, o2, o3>>
RebuildValidatorOrder == <<v2, v3, v1>>
ValidatorToOperator == [v \in {v1, v2, v3, v4} |-> IF v = v1 THEN o1 ELSE IF v = v3 THEN o3 ELSE o2]
RankOrder == <<0, 1, 2>>

\* Abstract bond units; v4 alone sits at the ceiling so o2's aggregate saturates.
ValidatorBond == [v \in {v1, v2, v3, v4} |-> IF v = v4 THEN MaxBond ELSE IF v = v3 THEN 1 ELSE 2]

EmergencyMaxMembers == 4
EmergencyLookbackEpochs == 2

Signers == {"operator", "attacker", "none"}

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

\* Epochs 2-3: every validator is bonded but none is lifecycle-active, so the
\* candidate set is empty and the emergency prior-committee rule must apply.
EmergencyHistory ==
    <<
      [ epoch |-> 1,
        lifecycleActive |-> {v1, v2, v3},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> ACTIVE, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {o1, o2, o3},
        candidateRank |-> [v1 |-> 1, v2 |-> 0, v3 |-> 2]
      ],
      [ epoch |-> 2,
        lifecycleActive |-> {},
        hasBond |-> {v1, v2, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> PROBATION, o2 |-> PROBATION, o3 |-> WARMUP],
        availabilityBondOk |-> {o1, o2, o3},
        availabilityScoreOk |-> {},
        candidateRank |-> [v1 |-> 0, v2 |-> 1, v3 |-> 2]
      ],
      [ epoch |-> 3,
        lifecycleActive |-> {},
        hasBond |-> {v1, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v2, v3},
        availabilityStatus |-> [o1 |-> PROBATION, o2 |-> EJECTED, o3 |-> WARMUP],
        availabilityBondOk |-> {o1, o3},
        availabilityScoreOk |-> {},
        candidateRank |-> [v1 |-> 2, v2 |-> 0, v3 |-> 1]
      ],
      [ epoch |-> 4,
        lifecycleActive |-> {v1, v3},
        hasBond |-> {v1, v3},
        genesisValidators |-> {v1},
        meetsMinBond |-> {v3},
        availabilityStatus |-> [o1 |-> ACTIVE, o2 |-> EJECTED, o3 |-> ACTIVE],
        availabilityBondOk |-> {o1, o3},
        availabilityScoreOk |-> {o1, o3},
        candidateRank |-> [v1 |-> 0, v2 |-> 2, v3 |-> 1]
      ]
    >>

History ==
    IF ScenarioId = 1 THEN BaselineHistory
    ELSE IF ScenarioId = 2 THEN StickyFallbackHistory
    ELSE IF ScenarioId = 3 THEN OrderingTieHistory
    ELSE IF ScenarioId = 4 THEN LongHorizonHistory
    ELSE EmergencyHistory

Schedules == {"continuous", "restore", "rebuild"}
Modes == {"NORMAL", "FALLBACK"}
Reasons == {"NONE", "INSUFFICIENT_ELIGIBLE_OPERATORS", "HYSTERESIS_RECOVERY_PENDING", "EMERGENCY_PRIOR_COMMITTEE"}
Statuses == {WARMUP, ACTIVE, PROBATION, EJECTED}
Phases == {"load", "project", "derive", "done"}

\* olderCheckpoint: the checkpoint before `checkpoint` (emergency lookback = 2 epochs).
VARIABLES pos, phase, rawAvail, projectedAvail, checkpoint, olderCheckpoint

vars == <<pos, phase, rawAvail, projectedAvail, checkpoint, olderCheckpoint>>

SeqToSet(seq) == {seq[i] : i \in 1..Len(seq)}

NoDuplicates(seq) == \A i, j \in 1..Len(seq) : i # j => seq[i] # seq[j]

IsPermutation(left, right) ==
    /\ Len(left) = Len(right)
    /\ NoDuplicates(left)
    /\ NoDuplicates(right)
    /\ SeqToSet(left) = SeqToSet(right)

ValidatorSet == SeqToSet(ValidatorOrder)
AllValidatorSet == SeqToSet(AllValidatorOrder)
OperatorSet == SeqToSet(OperatorOrder)
RankSet == SeqToSet(RankOrder)

Min(a, b) == IF a < b THEN a ELSE b

\* Live uint64 saturating addition (seed.bonded_amount in finalized_committee_candidates_for_height).
SatAdd(a, b) == IF a + b > MaxBond THEN MaxBond ELSE a + b

RECURSIVE SatSum(_)
SatSum(seq) == IF seq = <<>> THEN 0 ELSE SatAdd(Head(seq), SatSum(Tail(seq)))

RECURSIVE RawSum(_)
RawSum(seq) == IF seq = <<>> THEN 0 ELSE Head(seq) + RawSum(Tail(seq))

\* v4 inherits v2's finalized lifecycle facts.
WithSecondary(set) == IF v2 \in set THEN set \cup {v4} ELSE set

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
      committeeBonds |-> <<>>,
      proposerSchedule |-> <<>> ]

HistoryAt(n) == History[n]

\* Audit responses as received: operator-signed, unsigned, and third-party-signed.
RawResponses(style, epoch) ==
    <<[style |-> style, epoch |-> epoch, signer |-> "operator"],
      [style |-> style, epoch |-> epoch + 100, signer |-> "none"],
      [style |-> style, epoch |-> epoch + 200, signer |-> "attacker"]>>

\* verify_audit_response: only responses signed by the challenged operator are
\* attributed; the rest are NO_RESPONSE and produce no evidence.
RECURSIVE AttributedEvidence(_)
AttributedEvidence(seq) ==
    IF seq = <<>> THEN <<>>
    ELSE IF Head(seq).signer = "operator" THEN <<Head(seq)>> \o AttributedEvidence(Tail(seq))
    ELSE AttributedEvidence(Tail(seq))

RawEvidence(style, epoch) == AttributedEvidence(RawResponses(style, epoch))

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
    /\ validator \in WithSecondary(step.lifecycleActive)
    /\ validator \in WithSecondary(step.hasBond)
    /\ (validator \in step.genesisValidators \/ validator \in WithSecondary(step.meetsMinBond))

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

\* Operator aggregation: one candidate per operator, represented by its smallest
\* eligible validator, weighted by the saturating sum of its eligible bonds.
OperatorEligibleValidators(step, avail, mode, operator) ==
    FilterSeq(AllValidatorOrder,
              {v \in AllValidatorSet : ValidatorToOperator[v] = operator /\ CommitteeEligible(step, avail, mode, v)})

Representative(step, avail, mode, operator) == Head(OperatorEligibleValidators(step, avail, mode, operator))

OperatorBondSeq(step, avail, mode, operator) ==
    LET vs == OperatorEligibleValidators(step, avail, mode, operator)
    IN [i \in 1..Len(vs) |-> ValidatorBond[vs[i]]]

OperatorAggregatedBond(step, avail, mode, operator) == SatSum(OperatorBondSeq(step, avail, mode, operator))

CandidateOperators(step, avail, mode) ==
    {operator \in OperatorSet : OperatorEligibleValidators(step, avail, mode, operator) # <<>>}

RankOf(step, validator) == IF validator = v4 THEN step.candidateRank[v2] ELSE step.candidateRank[validator]

RankGroup(step, avail, mode, rank) ==
    {Representative(step, avail, mode, operator) :
        operator \in {o \in CandidateOperators(step, avail, mode) :
                        RankOf(step, Representative(step, avail, mode, o)) = rank}}

RECURSIVE ConcatRankGroups(_, _, _, _)
ConcatRankGroups(rankSeq, step, avail, mode) ==
    IF rankSeq = <<>> THEN
        <<>>
    ELSE
        FilterSeq(AllValidatorOrder, RankGroup(step, avail, mode, Head(rankSeq))) \o
        ConcatRankGroups(Tail(rankSeq), step, avail, mode)

CanonicalCandidateSequence(step, avail, mode, style) ==
    LET _presented == PresentedEligibleCandidates(style, step, avail, mode)
    IN ConcatRankGroups(RankOrder, step, avail, mode)

\* Spec §11 / 786f59d: min(K, len(C)) in every mode; FALLBACK never shrinks K to
\* the eligible-operator count.
TakeCommittee(seq) == SubSeq(seq, 1, Min(CommitteeSize, Len(seq)))

BondedForEmergency(step) == WithSecondary(step.hasBond)

RECURSIVE DistinctPrefix(_, _, _)
DistinctPrefix(seq, acc, limit) ==
    IF seq = <<>> \/ Len(acc) >= limit THEN acc
    ELSE IF Head(seq) \in SeqToSet(acc) THEN DistinctPrefix(Tail(seq), acc, limit)
    ELSE DistinctPrefix(Tail(seq), Append(acc, Head(seq)), limit)

\* Newest prior committee first, bonded members only, capped, then canonical order.
EmergencyCommittee(step, prevCheckpoint, olderCp) ==
    LET recent == FilterSeq(prevCheckpoint.committee \o olderCp.committee, BondedForEmergency(step))
        chosen == DistinctPrefix(recent, <<>>, EmergencyMaxMembers)
    IN FilterSeq(AllValidatorOrder, SeqToSet(chosen))

IsEmergency(cp) == cp.reason = "EMERGENCY_PRIOR_COMMITTEE"

ProposerSchedule(committee, epoch) ==
    \* Abstract deterministic permutation placeholder. The live implementation
    \* derives a deterministic permutation from the finalized checkpoint. This
    \* model preserves determinism without modeling the byte-level permutation.
    committee

DeriveCheckpoint(step, avail, prevCheckpoint, olderCp, style) ==
    LET decision == ModeReason(prevCheckpoint.mode, EligibleOperatorCount(avail))
        candidates == CanonicalCandidateSequence(step, avail, decision.mode, style)
        normal == TakeCommittee(candidates)
        emergency == candidates = <<>>
        committee == IF emergency THEN EmergencyCommittee(step, prevCheckpoint, olderCp) ELSE normal
        bonds == IF emergency
                 THEN [i \in 1..Len(committee) |-> ValidatorBond[committee[i]]]
                 ELSE [i \in 1..Len(committee) |->
                         OperatorAggregatedBond(step, avail, decision.mode, ValidatorToOperator[committee[i]])]
    IN [ epoch |-> step.epoch,
          mode |-> IF emergency THEN "FALLBACK" ELSE decision.mode,
          reason |-> IF emergency THEN "EMERGENCY_PRIOR_COMMITTEE" ELSE decision.reason,
          eligibleCount |-> EligibleOperatorCount(avail),
          committee |-> committee,
          committeeBonds |-> bonds,
          proposerSchedule |-> ProposerSchedule(committee, step.epoch) ]

ExpectedProjectedAt(n) ==
    IF n = 0 THEN DummyProjectedAvailability
    ELSE ConsensusRelevantAvailabilityState(LoadRaw("continuous", HistoryAt(n)))

RECURSIVE ExpectedCheckpointAt(_)
ExpectedCheckpointAt(n) ==
    IF n = 0 THEN
        InitCheckpoint
    ELSE
        DeriveCheckpoint(HistoryAt(n), ExpectedProjectedAt(n), ExpectedCheckpointAt(n - 1),
                         IF n = 1 THEN InitCheckpoint ELSE ExpectedCheckpointAt(n - 2), "continuous")

ExpectedOlderCheckpointAt(n) == IF n <= 1 THEN InitCheckpoint ELSE ExpectedCheckpointAt(n - 1)

ExpectedDecisionAt(n) ==
    ModeReason(ExpectedCheckpointAt(n - 1).mode, EligibleOperatorCount(ExpectedProjectedAt(n)))

\* Candidates as derived (under the hysteresis decision, before any emergency override).
ExpectedCandidatesAt(n) ==
    CanonicalCandidateSequence(HistoryAt(n), ExpectedProjectedAt(n), ExpectedDecisionAt(n).mode, "continuous")

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
    /\ raw.evidence \in Seq([style : Schedules, epoch : Nat, signer : Signers])
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
    /\ cp.committee \in Seq(AllValidatorSet)
    /\ cp.committeeBonds \in Seq(0..MaxBond)
    /\ Len(cp.committeeBonds) = Len(cp.committee)
    /\ cp.proposerSchedule \in Seq(AllValidatorSet)

Init ==
    /\ pos = [s \in Schedules |-> 0]
    /\ phase = [s \in Schedules |-> "load"]
    /\ rawAvail = [s \in Schedules |-> DummyRawAvailability]
    /\ projectedAvail = [s \in Schedules |-> DummyProjectedAvailability]
    /\ checkpoint = [s \in Schedules |-> InitCheckpoint]
    /\ olderCheckpoint = [s \in Schedules |-> InitCheckpoint]

LoadStep(s) ==
    /\ s \in Schedules
    /\ phase[s] = "load"
    /\ pos[s] < Len(History)
    /\ rawAvail' = [rawAvail EXCEPT ![s] = LoadRaw(s, HistoryAt(pos[s] + 1))]
    /\ phase' = [phase EXCEPT ![s] = "project"]
    /\ UNCHANGED <<pos, projectedAvail, checkpoint, olderCheckpoint>>

ProjectStep(s) ==
    /\ s \in Schedules
    /\ phase[s] = "project"
    /\ projectedAvail' = [projectedAvail EXCEPT ![s] = ConsensusRelevantAvailabilityState(rawAvail[s])]
    /\ phase' = [phase EXCEPT ![s] = "derive"]
    /\ UNCHANGED <<pos, rawAvail, checkpoint, olderCheckpoint>>

DeriveStep(s) ==
    /\ s \in Schedules
    /\ phase[s] = "derive"
    /\ pos[s] < Len(History)
    /\ checkpoint' =
        [checkpoint EXCEPT ![s] =
            DeriveCheckpoint(HistoryAt(pos[s] + 1), projectedAvail[s], checkpoint[s], olderCheckpoint[s], s)]
    /\ olderCheckpoint' = [olderCheckpoint EXCEPT ![s] = checkpoint[s]]
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
    /\ ScenarioId \in 1..5
    /\ Cardinality(Statuses) = 4
    /\ MaxBond \in Nat \ {0}
    /\ ValidatorToOperator \in [AllValidatorSet -> OperatorSet]
    /\ ValidatorBond \in [AllValidatorSet -> 1..MaxBond]
    /\ CommitteeSize \in 0..Len(ValidatorOrder)
    /\ MinEligible \in 0..Cardinality(OperatorSet)
    /\ \A i \in 1..Len(History) : TypeHistoryStep(HistoryAt(i))
    /\ pos \in [Schedules -> 0..Len(History)]
    /\ phase \in [Schedules -> Phases]
    /\ \A s \in Schedules : TypeRaw(rawAvail[s])
    /\ \A s \in Schedules : TypeProjected(projectedAvail[s])
    /\ \A s \in Schedules : TypeCheckpoint(checkpoint[s])
    /\ \A s \in Schedules : TypeCheckpoint(olderCheckpoint[s])

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
        /\ checkpoint[s] = ExpectedCheckpointAt(pos[s])
        /\ olderCheckpoint[s] = ExpectedOlderCheckpointAt(pos[s])

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
        IN /\ (~IsEmergency(cp) => (cp.mode = decision.mode /\ cp.reason = decision.reason))
           /\ (IsEmergency(cp) => cp.mode = "FALLBACK")
           /\ cp.eligibleCount = EligibleOperatorCount(avail)

StyleIndependence ==
    \A n \in 1..Len(History) :
        \A s \in Schedules :
            DeriveCheckpoint(HistoryAt(n), ExpectedProjectedAt(n), ExpectedCheckpointAt(n - 1),
                             ExpectedOlderCheckpointAt(n), s)
            = ExpectedCheckpointAt(n)

CommitteeEligibilitySoundness ==
    \A n \in 1..Len(History) :
        ~IsEmergency(ExpectedCheckpointAt(n)) =>
            \A v \in SeqToSet(ExpectedCheckpointAt(n).committee) :
                CommitteeEligible(HistoryAt(n), ExpectedProjectedAt(n), ExpectedCheckpointAt(n).mode, v)

CommitteeBounded ==
    \A n \in 0..Len(History) :
        Len(ExpectedCheckpointAt(n).committee) <=
            (IF IsEmergency(ExpectedCheckpointAt(n)) THEN EmergencyMaxMembers ELSE CommitteeSize)

\* Never derive an empty committee once the chain has started.
NonEmptyCommittee ==
    \A n \in 1..Len(History) : Len(ExpectedCheckpointAt(n).committee) >= 1

\* 786f59d: in every mode the committee is min(K, len(C)), independent of eligibleCount.
FallbackCommitteeSizing ==
    \A n \in 1..Len(History) :
        ~IsEmergency(ExpectedCheckpointAt(n)) =>
            Len(ExpectedCheckpointAt(n).committee) = Min(CommitteeSize, Len(ExpectedCandidatesAt(n)))

\* One committee seat per operator (aggregation), and every seat's weight is the
\* saturating sum of that operator's eligible bonds: never wraps, never exceeds MaxBond.
BondAggregationPerOperator ==
    \A n \in 1..Len(History) :
        LET cp == ExpectedCheckpointAt(n)
        IN /\ \A i, j \in 1..Len(cp.committee) :
                 i # j => ValidatorToOperator[cp.committee[i]] # ValidatorToOperator[cp.committee[j]]
           /\ (~IsEmergency(cp) =>
                 \A i \in 1..Len(cp.committee) :
                     LET bonds == OperatorBondSeq(HistoryAt(n), ExpectedProjectedAt(n), cp.mode,
                                                  ValidatorToOperator[cp.committee[i]])
                     IN cp.committeeBonds[i] = Min(MaxBond, RawSum(bonds)))
           /\ \A i \in 1..Len(cp.committeeBonds) : cp.committeeBonds[i] <= MaxBond

\* Emergency members are bonded members of the lookback committees, capped.
EmergencyCommitteeSoundness ==
    \A n \in 1..Len(History) :
        LET cp == ExpectedCheckpointAt(n)
            prior == SeqToSet(ExpectedCheckpointAt(n - 1).committee) \cup
                     SeqToSet(ExpectedOlderCheckpointAt(n).committee)
        IN IsEmergency(cp) =>
               /\ ExpectedCandidatesAt(n) = <<>>
               /\ SeqToSet(cp.committee) \subseteq prior \cap BondedForEmergency(HistoryAt(n))
               /\ Len(cp.committee) <= EmergencyMaxMembers

\* 1809a75: only operator-signed audit responses become evidence.
AuditEvidenceAttributed ==
    \A s \in Schedules :
        \A i \in 1..Len(rawAvail[s].evidence) : rawAvail[s].evidence[i].signer = "operator"

StickyFallbackDefinition ==
    \A n \in 0..Len(History) :
        FallbackSticky(ExpectedCheckpointAt(n)) =
        (ExpectedCheckpointAt(n).mode = "FALLBACK" /\ ExpectedCheckpointAt(n).reason = "HYSTERESIS_RECOVERY_PENDING")

=============================================================================
