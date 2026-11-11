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
(*   also only signalers; with none of those, any signaler that did not     *)
(*   exit (A2); with no signaler left at all, the rule without the upgrade  *)
(*   filter (last resort, decision 8b): liveness over "every seat signals"; *)
(*   no member even then: derivation fails closed (halt), as the old rule;  *)
(* - at the epoch end before activation, support is checked again: below    *)
(*   ceil(2n/3) of active operators the record is removed (decision 8a).    *)
(*                                                                          *)
(* Mutations (each must break an invariant, see the *_mutation configs):    *)
(*   "no_committee_check"  lock-in ignores committee(L+1)                   *)
(*   "no_exclusion"        non-signalers stay candidates after activation   *)
(*   "no_emergency_skip"   emergency recovery takes non-signalers           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Ops, K, Window, MaxEpoch, MaxExits, Mutation, Recovery, Recheck

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
          exclusionHalt, \* ghost: derivation failed closed where it would not without the upgrade rule (A2)
          lastResort, \* ghost: the current committee came from the last-resort rule (decision 8b)
          everCancelled \* ghost: a locked-in record was removed at its activation boundary (decision 8a)

vars == <<epoch, committee, prevCommittee, upgraded, signalers, rec, exited, suspended, halted, everFailed, exclusionHalt,
          lastResort, everCancelled>>

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
  /\ lastResort \in BOOLEAN /\ everCancelled \in BOOLEAN

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
  /\ lastResort = FALSE
  /\ everCancelled = FALSE

Upgrade(o) ==
  /\ o \notin upgraded
  /\ upgraded' = upgraded \cup {o}
  /\ UNCHANGED <<epoch, committee, prevCommittee, signalers, rec, exited, suspended, halted, everFailed, exclusionHalt, lastResort, everCancelled>>

Signal(o) ==
  /\ ~halted
  /\ o \in upgraded /\ o \notin exited /\ o \notin signalers
  /\ signalers' = signalers \cup {o}
  /\ rec' = IF rec.state = "none" THEN [state |-> "defined", first |-> epoch, act |-> 0] ELSE rec
  /\ UNCHANGED <<epoch, committee, prevCommittee, upgraded, exited, suspended, halted, everFailed, exclusionHalt, lastResort, everCancelled>>

Exit(o) ==
  /\ o \notin exited /\ Cardinality(exited) < MaxExits
  /\ exited' = exited \cup {o}
  /\ UNCHANGED <<epoch, committee, prevCommittee, upgraded, signalers, rec, suspended, halted, everFailed, exclusionHalt, lastResort, everCancelled>>

ToggleSuspend(o) ==
  /\ suspended' = IF o \in suspended THEN suspended \ {o} ELSE suspended \cup {o}
  /\ UNCHANGED <<epoch, committee, prevCommittee, upgraded, signalers, rec, exited, halted, everFailed, exclusionHalt, lastResort, everCancelled>>

\* Eligibility for the committee of epoch e (§6.4), before liveness filtering, under record r.
ActiveUnder(r, e) == r.state \in {"locked", "active"} /\ e >= r.act
UpgradeEligible(o, e) == ~ActiveAt(e) \/ o \in signalers

NoRec == [state |-> "none", first |-> 0, act |-> 0]

EndEpoch ==
  /\ ~halted /\ epoch < MaxEpoch
  /\ LET next  == epoch + 1
         active   == Ops \ exited
         support  == Cardinality(signalers \cap active) >= Threshold(Cardinality(active))
         \* decision 8a: a locked-in record whose activation is the next epoch, with support below the
         \* threshold, is removed before the next committee is derived; the old rules continue.
         cancel == Recheck = "on" /\ rec.state = "locked" /\ next >= rec.act /\ ~support
         r     == IF cancel THEN NoRec ELSE rec
         sig   == IF cancel THEN {} ELSE signalers
         elig(o) == ~ActiveUnder(r, next) \/ o \in sig
         cands == {o \in Ops : o \notin exited /\ o \notin suspended
                               /\ (elig(o) \/ Mutation = "no_exclusion")}
         em    == {o \in committee \cup prevCommittee : o \notin exited
                                     /\ (elig(o) \/ Mutation = "no_emergency_skip")}
         base  == {o \in Ops : o \notin exited /\ o \notin suspended}
         emBase == {o \in committee \cup prevCommittee : o \notin exited}
         \* Recovery: "prior_only" = before A2 (fails closed); "signalers" = A2 (any signaler that did
         \* not exit); "last_resort" = A2, then the rule without the upgrade filter (decision 8b).
         emSig == IF Recovery \in {"signalers", "last_resort"} /\ ActiveUnder(r, next)
                  THEN {o \in sig : o \notin exited} ELSE {}
         useOld == Recovery = "last_resort" /\ cands = {} /\ em = {} /\ emSig = {}
         options == IF cands # {}
                    THEN {S \in SUBSET cands : Cardinality(S) = Min(K, Cardinality(cands))}
                    ELSE IF em # {} THEN {em}
                    ELSE IF emSig # {} THEN {emSig}
                    ELSE IF useOld /\ base # {} THEN {S \in SUBSET base : Cardinality(S) = Min(K, Cardinality(base))}
                    ELSE IF useOld /\ emBase # {} THEN {emBase}
                    ELSE {{}}
     IN \E C \in options :
          /\ halted' = (C = {})
          /\ exclusionHalt' = (C = {} /\ (base # {} \/ emBase # {}))
          /\ lastResort' = (useOld /\ C # {})
          /\ everCancelled' = (everCancelled \/ cancel)
          /\ committee' = C
          /\ prevCommittee' = committee
          /\ epoch' = next
          /\ LET seats    == Mutation = "no_committee_check" \/ Cardinality(C \cap sig) >= Quorum(Cardinality(C))
                 lock     == C # {} /\ support /\ seats
             IN \/ /\ r.state \in {"defined", "signaling"}
                   /\ IF lock
                      THEN /\ rec' = [r EXCEPT !.state = "locked", !.act = epoch + 2]
                           /\ signalers' = sig /\ everFailed' = everFailed
                      ELSE IF next >= r.first + Window
                           THEN /\ rec' = NoRec  \* failed: removed
                                /\ signalers' = {}
                                /\ everFailed' = TRUE
                           ELSE /\ rec' = [r EXCEPT !.state = "signaling"]
                                /\ signalers' = sig /\ everFailed' = everFailed
                \/ /\ r.state = "locked"
                   /\ rec' = IF next >= r.act THEN [r EXCEPT !.state = "active"] ELSE r
                   /\ signalers' = sig /\ everFailed' = everFailed
                \/ /\ r.state \in {"none", "active"}
                   /\ rec' = r /\ signalers' = sig /\ everFailed' = everFailed
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
\* Except under the last-resort rule, which applies only once no signaler is left (decision 8b).
ActiveCommitteeAllSignalers == ActiveAt(epoch) /\ ~halted /\ ~lastResort => committee \subseteq signalers
ActiveCommitteeUpgraded     == ActiveAt(epoch) /\ ~halted /\ ~lastResort => committee \subseteq upgraded

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
NeverCancelled == ~everCancelled
NeverLastResort == ~lastResort
=============================================================================
