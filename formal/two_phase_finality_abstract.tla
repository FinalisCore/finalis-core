----------------------- MODULE two_phase_finality_abstract -----------------------
(***************************************************************************)
(* Exhaustively checkable over-approximation of two_phase_finality.tla.   *)
(*                                                                         *)
(* Every guard dropped here only restricts honest behaviour in the        *)
(* detailed model, so this model has a superset of its behaviours and     *)
(* Agreement here implies Agreement there:                                 *)
(* - the local round: resets/restarts (to 0) and catch-up (to any higher) *)
(*   already let a node be at any round at any time;                       *)
(* - timed-out rounds: only block votes, and restarts clear them;         *)
(* - honest proposals and valid values: an honest leader can propose no   *)
(*   more than a Byzantine one, so every (round, value, pol round) is     *)
(*   proposed.                                                             *)
(* What remains is what safety rests on: the lock rule, the vote-round    *)
(* floor, durable prevotes (one per round), and precommit on a polka.     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Honest, Byz, Values, MaxRound, Nil, LockRule, FloorRule

N      == Cardinality(Honest \cup Byz)
Q      == (2 * N) \div 3 + 1
Rounds == 0..MaxRound

VARIABLES lockedV, lockedR, prevoted, precommits

vars == <<lockedV, lockedR, prevoted, precommits>>

\* Byzantine validators count toward every polka and every precommit quorum.
Polka(v, r) ==
  Cardinality({n \in Honest : prevoted[n][r] = v}) + Cardinality(Byz) >= Q

Committed(v, r) ==
  Cardinality({n \in Honest : <<n, r, v>> \in precommits}) + Cardinality(Byz) >= Q

\* local_vote_round_floor_locked.
VoteFloorOK(n, r) ==
  ~FloorRule \/ (lockedR[n] <= r /\ \A r2 \in Rounds : r2 > r => prevoted[n][r2] = Nil)

TypeOK ==
  /\ lockedV \in [Honest -> Values \cup {Nil}]
  /\ lockedR \in [Honest -> -1..MaxRound]
  /\ prevoted \in [Honest -> [Rounds -> Values \cup {Nil}]]
  /\ precommits \subseteq Honest \X Rounds \X Values

Init ==
  /\ lockedV = [n \in Honest |-> Nil]
  /\ lockedR = [n \in Honest |-> -1]
  /\ prevoted = [n \in Honest |-> [r \in Rounds |-> Nil]]
  /\ precommits = {}

\* Prevote for a proposal of v at round r carrying a polka from vr (-1: fresh).
Prevote(n, r, v, vr) ==
  /\ vr < r
  /\ prevoted[n][r] = Nil
  /\ VoteFloorOK(n, r)
  /\ IF vr = -1
       THEN ~LockRule \/ lockedR[n] = -1 \/ lockedV[n] = v
       ELSE /\ Polka(v, vr)
            /\ ~LockRule \/ lockedR[n] <= vr \/ lockedV[n] = v
  /\ prevoted' = [prevoted EXCEPT ![n][r] = v]
  /\ UNCHANGED <<lockedV, lockedR, precommits>>

Precommit(n, r, v) ==
  /\ VoteFloorOK(n, r)
  /\ Polka(v, r)
  /\ lockedR[n] < r \/ (lockedR[n] = r /\ lockedV[n] = v)
  /\ lockedV' = [lockedV EXCEPT ![n] = v]
  /\ lockedR' = [lockedR EXCEPT ![n] = r]
  /\ precommits' = precommits \cup {<<n, r, v>>}
  /\ UNCHANGED prevoted

Next ==
  \E n \in Honest, r \in Rounds, v \in Values :
    \/ \E vr \in -1..MaxRound : Prevote(n, r, v, vr)
    \/ Precommit(n, r, v)

Spec == Init /\ [][Next]_vars

Agreement ==
  \A v1, v2 \in Values : (\E r1, r2 \in Rounds : Committed(v1, r1) /\ Committed(v2, r2)) => v1 = v2

NothingFinalizes == \A v \in Values, r \in Rounds : ~Committed(v, r)
NoCrossRoundFinality == \A v \in Values, r \in Rounds : Committed(v, r) => r = 0

ValuesSymmetry == Permutations(Values)
HonestSymmetry == Permutations(Honest)
Symmetry == ValuesSymmetry \cup HonestSymmetry
=============================================================================
