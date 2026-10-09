---------------------------- MODULE two_phase_finality ----------------------------
(***************************************************************************)
(* Bounded model of the two-phase finality voting rules at one height     *)
(* (docs/spec/TWO_PHASE_FINALITY.md, src/node/node_consensus.cpp).        *)
(*                                                                         *)
(* Adversary: every Byzantine validator has signed every prevote and      *)
(* precommit, and every Byzantine leader has proposed every value with     *)
(* every proof-of-lock round. Delivery is asynchronous: an honest node    *)
(* acts on a quorum whenever it exists, or never. Honest nodes may time   *)
(* out, catch up rounds, lose round state on a reconnect reset, and       *)
(* restart (losing the non-durable timed-out-round record).               *)
(*                                                                         *)
(* Abstractions (each only adds behaviours, so safety carries over):      *)
(* - values are abstract transition ids; a fresh proposal may reuse any   *)
(* - every proposal body is known to every node                           *)
(* - rounds advance without requiring a TC; per-round "once" reservations *)
(*   that a reset clears are not modelled                                  *)
(* - an honest leader may propose more than once per round                *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Honest, Byz, Values, MaxRound, Leader, Nil,
          LockRule,      \* FALSE drops the lock check on prevotes (mutation: must break Agreement)
          FloorRule      \* FALSE drops the vote-round floor (mutation: must break Agreement)

Nodes  == Honest \cup Byz
N      == Cardinality(Nodes)
Q      == (2 * N) \div 3 + 1
Rounds == 0..MaxRound

VARIABLES round, lockedV, lockedR, validV, validR, prevoted, precommits, timedOut, proposals

vars == <<round, lockedV, lockedR, validV, validR, prevoted, precommits, timedOut, proposals>>

Proposal == [r : Rounds, v : Values, vr : -1..MaxRound]

ByzProposals == {p \in Proposal : Leader[p.r] \in Byz /\ p.vr < p.r}

AllProposals == proposals \cup ByzProposals

\* Byzantine validators count toward every polka and every precommit quorum.
Polka(v, r) ==
  Cardinality({n \in Honest : prevoted[n][r] = v}) + Cardinality(Byz) >= Q

Committed(v, r) ==
  Cardinality({n \in Honest : <<n, r, v>> \in precommits}) + Cardinality(Byz) >= Q

\* local_vote_round_floor_locked: an honest node never votes below a round it already voted in
\* (its durable prevotes and lock). Round resets and restarts move round[n] back; this does not.
VoteFloorOK(n, r) ==
  ~FloorRule \/ (lockedR[n] <= r /\ \A r2 \in Rounds : r2 > r => prevoted[n][r2] = Nil)

TypeOK ==
  /\ round \in [Honest -> Rounds]
  /\ lockedV \in [Honest -> Values \cup {Nil}]
  /\ lockedR \in [Honest -> -1..MaxRound]
  /\ validV \in [Honest -> Values \cup {Nil}]
  /\ validR \in [Honest -> -1..MaxRound]
  /\ prevoted \in [Honest -> [Rounds -> Values \cup {Nil}]]
  /\ precommits \subseteq Honest \X Rounds \X Values
  /\ timedOut \in [Honest -> SUBSET Rounds]
  /\ proposals \subseteq Proposal

Init ==
  /\ round = [n \in Honest |-> 0]
  /\ lockedV = [n \in Honest |-> Nil]
  /\ lockedR = [n \in Honest |-> -1]
  /\ validV = [n \in Honest |-> Nil]
  /\ validR = [n \in Honest |-> -1]
  /\ prevoted = [n \in Honest |-> [r \in Rounds |-> Nil]]
  /\ precommits = {}
  /\ timedOut = [n \in Honest |-> {}]
  /\ proposals = {}

\* Leader of (h, r): its valid value with the polka round if it has one from an earlier round,
\* otherwise a fresh value.
HonestPropose(n) ==
  LET r == round[n] IN
  /\ Leader[r] = n
  /\ IF validR[n] >= 0 /\ validR[n] < r
       THEN proposals' = proposals \cup {[r |-> r, v |-> validV[n], vr |-> validR[n]]}
       ELSE \E v \in Values : proposals' = proposals \cup {[r |-> r, v |-> v, vr |-> -1]}
  /\ UNCHANGED <<round, lockedV, lockedR, validV, validR, prevoted, precommits, timedOut>>

\* can_prevote_locked + handle_propose_result.
Prevote(n, p) ==
  /\ p \in AllProposals
  /\ p.r = round[n]
  /\ prevoted[n][p.r] = Nil
  /\ p.r \notin timedOut[n]
  /\ VoteFloorOK(n, p.r)
  /\ IF p.vr = -1
       THEN ~LockRule \/ lockedR[n] = -1 \/ lockedV[n] = p.v
       ELSE /\ Polka(p.v, p.vr)
            /\ ~LockRule \/ lockedR[n] <= p.vr \/ lockedV[n] = p.v
  /\ prevoted' = [prevoted EXCEPT ![n][p.r] = p.v]
  /\ UNCHANGED <<round, lockedV, lockedR, validV, validR, precommits, timedOut, proposals>>

\* on_prevotes_changed_locked + lock_on_polka_locked: current round, not timed out, lock moves
\* only to a later round (or is the same lock).
Precommit(n, v) ==
  LET r == round[n] IN
  /\ r \notin timedOut[n]
  /\ VoteFloorOK(n, r)
  /\ Polka(v, r)
  /\ lockedR[n] < r \/ (lockedR[n] = r /\ lockedV[n] = v)
  /\ lockedV' = [lockedV EXCEPT ![n] = v]
  /\ lockedR' = [lockedR EXCEPT ![n] = r]
  /\ precommits' = precommits \cup {<<n, r, v>>}
  /\ UNCHANGED <<round, validV, validR, prevoted, timedOut, proposals>>

\* Valid value: highest-round polka seen, any round.
UpdateValid(n, v, r) ==
  /\ Polka(v, r)
  /\ r > validR[n]
  /\ validV' = [validV EXCEPT ![n] = v]
  /\ validR' = [validR EXCEPT ![n] = r]
  /\ UNCHANGED <<round, lockedV, lockedR, prevoted, precommits, timedOut, proposals>>

Timeout(n) ==
  /\ round[n] < MaxRound
  /\ timedOut' = [timedOut EXCEPT ![n] = @ \cup {round[n]}]
  /\ round' = [round EXCEPT ![n] = @ + 1]
  /\ UNCHANGED <<lockedV, lockedR, validV, validR, prevoted, precommits, proposals>>

\* Round catch-up on a justified proposal or TC: no timeout vote for the skipped rounds.
Advance(n) ==
  /\ \E r \in Rounds : r > round[n] /\ round' = [round EXCEPT ![n] = r]
  /\ UNCHANGED <<lockedV, lockedR, validV, validR, prevoted, precommits, timedOut, proposals>>

\* Reconnect reset: back to round 0; durable safety state and timed-out rounds kept.
Reset(n) ==
  /\ round' = [round EXCEPT ![n] = 0]
  /\ UNCHANGED <<lockedV, lockedR, validV, validR, prevoted, precommits, timedOut, proposals>>

\* Restart: round 0, the in-memory timed-out rounds are lost; lock, valid value, prevotes are durable.
Restart(n) ==
  /\ round' = [round EXCEPT ![n] = 0]
  /\ timedOut' = [timedOut EXCEPT ![n] = {}]
  /\ UNCHANGED <<lockedV, lockedR, validV, validR, prevoted, precommits, proposals>>

Next ==
  \E n \in Honest :
    \/ HonestPropose(n)
    \/ \E p \in AllProposals : Prevote(n, p)
    \/ \E v \in Values : Precommit(n, v)
    \/ \E v \in Values, r \in Rounds : UpdateValid(n, v, r)
    \/ Timeout(n)
    \/ Advance(n)
    \/ Reset(n)
    \/ Restart(n)

Spec == Init /\ [][Next]_vars

\* At most one transition finalizes at the height, in any rounds.
Agreement ==
  \A v1, v2 \in Values : (\E r1, r2 \in Rounds : Committed(v1, r1) /\ Committed(v2, r2)) => v1 = v2

\* Reachability check (expected to be violated): something finalizes.
NothingFinalizes == \A v \in Values, r \in Rounds : ~Committed(v, r)

\* Reachability check (expected to be violated): a value finalizes in a later round than one
\* in which another value had an honest prevote, i.e. the model exercises lock movement.
NoCrossRoundFinality == \A v \in Values, r \in Rounds : Committed(v, r) => r = 0

ValuesSymmetry == Permutations(Values)
=============================================================================
