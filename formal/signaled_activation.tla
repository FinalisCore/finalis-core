------------------------- MODULE signaled_activation -------------------------
(***************************************************************************)
(* Signaled activation of a consensus upgrade (docs/spec/SIGNALED_ACTIVATION.md, *)
(* CHECKPOINT_DERIVATION_SPEC §6.4). Abstract over finality (an epoch ends  *)
(* once its last height is final) and over ticket order (any K-subset of   *)
(* the candidates may be drawn).                                            *)
(*                                                                          *)
(* Modelled rules:                                                          *)
(* - an operator runs the old or the new binary; only the new one signals,  *)
(*   once (upgrading is the vote; no downgrade, which would equal offline); *)
(* - the first signal opens the record and its window of Window epochs;     *)
(* - at each epoch end L the committee for L+1 is derived first, then the   *)
(*   record advances: lock-in needs ceil(2n/3) of the active operators and  *)
(*   a quorum of committee(L+1); activation at the start of L+2; a record   *)
(*   past its window without lock-in is removed;                            *)
(* - from activation on only signalers are candidates; suspended operators  *)
(*   are not candidates, but emergency recovery may take prior committee    *)
(*   members of the 2 prior epochs that did not exit, suspended or not,     *)
(*   also only signalers;                                                     *)
(*   no candidate and no recovery member: derivation fails closed (halt).   *)
(*                                                                          *)
(* Mutations (each must break an invariant, see the *_mutation configs):    *)
(*   "no_committee_check"  lock-in ignores committee(L+1)                   *)
(*   "no_exclusion"        non-signalers stay candidates after activation   *)
(*   "no_emergency_skip"   emergency recovery takes non-signalers           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Ops, K, Window, MaxEpoch, MaxExits, Mutation, Recovery

Quorum(n)    == (2 * n) \div 3 + 1
Threshold(n) == (2 * n + 2) \div 3
Min(a, b)    == IF a < b THEN a ELSE b

VARIABLES epoch,      \* current epoch
          committee,  \* committee of the current epoch
          prevCommittee, \* committee of the epoch before (emergency recovery looks back 2 epochs)
          upgraded,   \* operators running the new binary
          signalers,  \* operators whose signal is recorded
          rec,        \* [state, first, act]: the UPG: record, state "none" = no record
          exited,     \* operators that left (not active, never recovered)
          suspended,  \* operators suspended for liveness (not candidates, recoverable)
          halted,     \* derivation failed closed
          everFailed, \* ghost: a record was removed at its window end
          exclusionHalt \* ghost: derivation failed closed where it would not without the upgrade rule (A2)

vars == <<epoch, committee, prevCommittee, upgraded, signalers, rec, exited, suspended, halted, everFailed, exclusionHalt>>

States == {"none", "defined", "signaling", "locked", "active"}

ActiveAt(e) == rec.state \in {"locked", "active"} /\ e >= rec.act

TypeOK ==
  /\ epoch \in 1..MaxEpoch
  /\ committee \subseteq Ops /\ prevCommittee \subseteq Ops
  /\ upgraded \subseteq Ops
  /\ signalers \subseteq upgraded
  /\ rec.state \in States /\ rec.first \in 0..MaxEpoch /\ rec.act \in 0..(MaxEpoch + 2)
  /\ exited \subseteq Ops /\ suspended \subseteq Ops
  /\ halted \in BOOLEAN /\ everFailed \in BOOLEAN /\ exclusionHalt \in BOOLEAN

Init ==
  /\ epoch = 1
  /\ committee \in {S \in SUBSET Ops : Cardinality(S) = Min(K, Cardinality(Ops))}
  /\ prevCommittee = {}
  /\ upgraded = {}
  /\ signalers = {}
  /\ rec = [state |-> "none", first |-> 0, act |-> 0]
  /\ exited = {}
  /\ suspended = {}
  /\ halted = FALSE
  /\ everFailed = FALSE
  /\ exclusionHalt = FALSE

Upgrade(o) ==
  /\ o \notin upgraded
  /\ upgraded' = upgraded \cup {o}
  /\ UNCHANGED <<epoch, committee, prevCommittee, signalers, rec, exited, suspended, halted, everFailed, exclusionHalt>>

Signal(o) ==
  /\ ~halted
  /\ o \in upgraded /\ o \notin exited /\ o \notin signalers
  /\ signalers' = signalers \cup {o}
  /\ rec' = IF rec.state = "none" THEN [state |-> "defined", first |-> epoch, act |-> 0] ELSE rec
  /\ UNCHANGED <<epoch, committee, prevCommittee, upgraded, exited, suspended, halted, everFailed, exclusionHalt>>

Exit(o) ==
  /\ o \notin exited /\ Cardinality(exited) < MaxExits
  /\ exited' = exited \cup {o}
  /\ UNCHANGED <<epoch, committee, prevCommittee, upgraded, signalers, rec, suspended, halted, everFailed, exclusionHalt>>

ToggleSuspend(o) ==
  /\ suspended' = IF o \in suspended THEN suspended \ {o} ELSE suspended \cup {o}
  /\ UNCHANGED <<epoch, committee, prevCommittee, upgraded, signalers, rec, exited, halted, everFailed, exclusionHalt>>

\* Eligibility for the committee of epoch e (§6.4), before liveness filtering.
UpgradeEligible(o, e) == ~ActiveAt(e) \/ o \in signalers

EndEpoch ==
  /\ ~halted /\ epoch < MaxEpoch
  /\ LET next  == epoch + 1
         cands == {o \in Ops : o \notin exited /\ o \notin suspended
                               /\ (UpgradeEligible(o, next) \/ Mutation = "no_exclusion")}
         em    == {o \in committee \cup prevCommittee : o \notin exited
                                     /\ (UpgradeEligible(o, next) \/ Mutation = "no_emergency_skip")}
         base  == {o \in Ops : o \notin exited /\ o \notin suspended}
         emBase == {o \in committee \cup prevCommittee : o \notin exited}
         \* Recovery = "signalers" (the implemented rule, fix A2): with no recovery member, any signaler
         \* that did not exit, suspended or not; "prior_only": the rule before A2 (fails closed).
         emSig == IF Recovery = "signalers" /\ ActiveAt(next) THEN {o \in signalers : o \notin exited} ELSE {}
     IN \E C \in (IF cands # {}
                  THEN {S \in SUBSET cands : Cardinality(S) = Min(K, Cardinality(cands))}
                  ELSE IF em # {} THEN {em}
                  ELSE IF emSig # {} THEN {emSig} ELSE {{}}) :
          /\ halted' = (C = {})
          /\ exclusionHalt' = (C = {} /\ (base # {} \/ emBase # {}))
          /\ committee' = C
          /\ prevCommittee' = committee
          /\ epoch' = next
          /\ LET active   == Ops \ exited
                 support  == Cardinality(signalers \cap active) >= Threshold(Cardinality(active))
                 seats    == Mutation = "no_committee_check" \/ Cardinality(C \cap signalers) >= Quorum(Cardinality(C))
                 lock     == C # {} /\ support /\ seats
             IN \/ /\ rec.state \in {"defined", "signaling"}
                   /\ IF lock
                      THEN /\ rec' = [rec EXCEPT !.state = "locked", !.act = epoch + 2]
                           /\ UNCHANGED <<signalers, everFailed>>
                      ELSE IF next >= rec.first + Window
                           THEN /\ rec' = [state |-> "none", first |-> 0, act |-> 0]  \* failed: removed
                                /\ signalers' = {}
                                /\ everFailed' = TRUE
                           ELSE /\ rec' = [rec EXCEPT !.state = "signaling"]
                                /\ UNCHANGED <<signalers, everFailed>>
                \/ /\ rec.state = "locked"
                   /\ rec' = IF next >= rec.act THEN [rec EXCEPT !.state = "active"] ELSE rec
                   /\ UNCHANGED <<signalers, everFailed>>
                \/ /\ rec.state \in {"none", "active"}
                   /\ UNCHANGED <<rec, signalers, everFailed>>
  /\ UNCHANGED <<upgraded, exited, suspended>>

Next ==
  \/ \E o \in Ops : Upgrade(o) \/ Signal(o) \/ Exit(o) \/ ToggleSuspend(o)
  \/ EndEpoch

Spec == Init /\ [][Next]_vars

Symmetry == Permutations(Ops)

(***************************************************************************)
(* Invariants                                                               *)
(***************************************************************************)

\* From activation on, every committee seat belongs to a signaler, so the whole committee runs the
\* new rules (no downgrade) and can sign new-rules blocks.
ActiveCommitteeAllSignalers == ActiveAt(epoch) /\ ~halted => committee \subseteq signalers
ActiveCommitteeUpgraded     == ActiveAt(epoch) /\ ~halted => committee \subseteq upgraded

\* The parent committee of the first new-rules block (epoch act - 1, derived before lock-in) has a
\* quorum of signalers, so its time signatures and votes are available at the switch.
ParentCommitteeReady ==
  rec.state \in {"locked", "active"} /\ epoch = rec.act - 1 =>
    Cardinality(committee \cap signalers) >= Quorum(Cardinality(committee))

(* Reachability: each is expected to be violated (the state is reachable). *)
NeverActive == rec.state # "active"
NeverFailed == ~everFailed
\* The upgrade rule never turns a derivation the old rule completes into a fail-closed halt.
NoExclusionHalt == ~exclusionHalt
=============================================================================
