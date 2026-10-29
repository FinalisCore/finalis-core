--------------------- MODULE two_phase_finality_persistence ---------------------
(***************************************************************************)
(* two_phase_finality_abstract.tla with the persistence layer made        *)
(* explicit: each honest node has an in-memory and a durable copy of its  *)
(* lock and prevote record, a durable write can fail, and a restart       *)
(* reloads memory from the durable copy. Votes that left the process are  *)
(* tracked separately (sentPv, sentPc); only sent votes count toward    *)
(* polkas and commits.                                                    *)
(*                                                                         *)
(* Write model (src/node/node_consensus.cpp + RocksDB 8.9 as measured by   *)
(* tests/test_storage_faults.cpp):                                         *)
(* - a write serializes the whole in-memory safety state of the height    *)
(*   (persist_consensus_safety_state_locked);                              *)
(* - a failed write is ambiguous: the batch may or may not survive a      *)
(*   restart (WAL write() failure: lost; WAL sync failure: replayed);      *)
(* - StickyFailure: after a failure every write fails until restart       *)
(*   (RocksDB background error). FALSE allows later writes to succeed.    *)
(*                                                                         *)
(* Code paths (FixLock = FixPrevote = FALSE, the code at 9467c05):        *)
(* - prevote / lock: memory is updated, then written; on failure memory   *)
(*   keeps the new value and nothing is sent;                              *)
(* - PrecommitFromMemoryLock: lock_on_polka_locked's early return on a    *)
(*   re-delivered polka, local_votes_for_rebroadcast_locked and            *)
(*   reseed_local_votes_locked all send a precommit for the memory lock;   *)
(* - PrevoteFromMemory: the stall rebroadcast sends memory prevotes.       *)
(* FixLock / FixPrevote = TRUE model the candidate fix for the lock and   *)
(* the prevote record separately: memory changes only after the write     *)
(* succeeds (restore on failure). A hypothetical design, not the code.    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Honest, Byz, Values, MaxRound, Nil, FixLock, FixPrevote, StickyFailure

N      == Cardinality(Honest \cup Byz)
Q      == (2 * N) \div 3 + 1
Rounds == 0..MaxRound

VARIABLES mLockV, mLockR, mPv,   \* in-memory lock and prevote record
          dLockV, dLockR, dPv,   \* durable copies
          broken,                \* DB in background-error state (until restart)
          sentPv, sentPc         \* votes that left the process: sets of <<n, r, v>>

vars == <<mLockV, mLockR, mPv, dLockV, dLockR, dPv, broken, sentPv, sentPc>>

Polka(v, r) ==
  Cardinality({n \in Honest : <<n, r, v>> \in sentPv}) + Cardinality(Byz) >= Q

Committed(v, r) ==
  Cardinality({n \in Honest : <<n, r, v>> \in sentPc}) + Cardinality(Byz) >= Q

\* local_vote_round_floor_locked, over memory (as the code reads it).
VoteFloorOK(n, r) ==
  mLockR[n] <= r /\ \A r2 \in Rounds : r2 > r => mPv[n][r2] = Nil

TypeOK ==
  /\ mLockV \in [Honest -> Values \cup {Nil}] /\ dLockV \in [Honest -> Values \cup {Nil}]
  /\ mLockR \in [Honest -> -1..MaxRound] /\ dLockR \in [Honest -> -1..MaxRound]
  /\ mPv \in [Honest -> [Rounds -> Values \cup {Nil}]] /\ dPv \in [Honest -> [Rounds -> Values \cup {Nil}]]
  /\ broken \in [Honest -> BOOLEAN]
  /\ sentPv \subseteq Honest \X Rounds \X Values
  /\ sentPc \subseteq Honest \X Rounds \X Values

Init ==
  /\ mLockV = [n \in Honest |-> Nil] /\ dLockV = mLockV
  /\ mLockR = [n \in Honest |-> -1] /\ dLockR = mLockR
  /\ mPv = [n \in Honest |-> [r \in Rounds |-> Nil]] /\ dPv = mPv
  /\ broken = [n \in Honest |-> FALSE]
  /\ sentPv = {} /\ sentPc = {}

\* One durable write of the new memory state (lv, lr, pv). ok: it is durable. Otherwise the outcome
\* is ambiguous unless the DB is already broken (then the batch is rejected, never written).
WriteOutcome(n, lv, lr, pv, ok) ==
  IF ok
    THEN /\ dLockV' = [dLockV EXCEPT ![n] = lv] /\ dLockR' = [dLockR EXCEPT ![n] = lr]
         /\ dPv' = [dPv EXCEPT ![n] = pv] /\ broken' = broken
    ELSE /\ broken' = [broken EXCEPT ![n] = StickyFailure]
         /\ \/ UNCHANGED <<dLockV, dLockR, dPv>>
            \/ /\ ~broken[n]
               /\ dLockV' = [dLockV EXCEPT ![n] = lv] /\ dLockR' = [dLockR EXCEPT ![n] = lr]
               /\ dPv' = [dPv EXCEPT ![n] = pv]

CanSucceed(n) == ~broken[n]

\* Prevote for a proposal of v at r carrying a polka from vr (-1: fresh). record_local_prevote_locked.
Prevote(n, r, v, vr) ==
  /\ vr < r
  /\ mPv[n][r] = Nil
  /\ VoteFloorOK(n, r)
  /\ IF vr = -1 THEN mLockR[n] = -1 \/ mLockV[n] = v
                ELSE Polka(v, vr) /\ (mLockR[n] <= vr \/ mLockV[n] = v)
  /\ LET pv == [mPv[n] EXCEPT ![r] = v] IN
     \E ok \in BOOLEAN :
       /\ ok => CanSucceed(n)
       /\ WriteOutcome(n, mLockV[n], mLockR[n], pv, ok)
       /\ mPv' = IF ok \/ ~FixPrevote THEN [mPv EXCEPT ![n] = pv] ELSE mPv
       /\ sentPv' = IF ok THEN sentPv \cup {<<n, r, v>>} ELSE sentPv
  /\ UNCHANGED <<mLockV, mLockR, sentPc>>

\* on_prevotes_changed_locked + lock_on_polka_locked, the path that writes (lock moves to (v, r)).
Precommit(n, r, v) ==
  /\ VoteFloorOK(n, r)
  /\ Polka(v, r)
  /\ mLockR[n] < r
  /\ \E ok \in BOOLEAN :
       /\ ok => CanSucceed(n)
       /\ WriteOutcome(n, v, r, mPv[n], ok)
       /\ IF ok \/ ~FixLock
            THEN mLockV' = [mLockV EXCEPT ![n] = v] /\ mLockR' = [mLockR EXCEPT ![n] = r]
            ELSE UNCHANGED <<mLockV, mLockR>>
       /\ sentPc' = IF ok THEN sentPc \cup {<<n, r, v>>} ELSE sentPc
  /\ UNCHANGED <<mPv, sentPv>>

\* Early return / stall rebroadcast / reseed: a precommit for the memory lock, no write.
PrecommitFromMemoryLock(n) ==
  /\ mLockR[n] >= 0
  /\ sentPc' = sentPc \cup {<<n, mLockR[n], mLockV[n]>>}
  /\ UNCHANGED <<mLockV, mLockR, mPv, dLockV, dLockR, dPv, broken, sentPv>>

\* Stall rebroadcast of a memory prevote, no write.
PrevoteFromMemory(n, r) ==
  /\ mPv[n][r] # Nil
  /\ sentPv' = sentPv \cup {<<n, r, mPv[n][r]>>}
  /\ UNCHANGED <<mLockV, mLockR, mPv, dLockV, dLockR, dPv, broken, sentPc>>

\* Crash + restart: memory is reloaded from the durable copy; sent votes are out for good.
Restart(n) ==
  /\ mLockV' = [mLockV EXCEPT ![n] = dLockV[n]] /\ mLockR' = [mLockR EXCEPT ![n] = dLockR[n]]
  /\ mPv' = [mPv EXCEPT ![n] = dPv[n]]
  /\ broken' = [broken EXCEPT ![n] = FALSE]
  /\ UNCHANGED <<dLockV, dLockR, dPv, sentPv, sentPc>>

Next ==
  \E n \in Honest :
    \/ \E r \in Rounds, v \in Values :
         \/ \E vr \in -1..MaxRound : Prevote(n, r, v, vr)
         \/ Precommit(n, r, v)
    \/ PrecommitFromMemoryLock(n)
    \/ \E r \in Rounds : PrevoteFromMemory(n, r)
    \/ Restart(n)

Spec == Init /\ [][Next]_vars

Agreement ==
  \A v1, v2 \in Values : (\E r1, r2 \in Rounds : Committed(v1, r1) /\ Committed(v2, r2)) => v1 = v2

\* An honest node never sends two different prevotes, or two different precommits, in one round.
NoHonestDoublePrevote ==
  \A n \in Honest, r \in Rounds, v1, v2 \in Values : (<<n, r, v1>> \in sentPv /\ <<n, r, v2>> \in sentPv) => v1 = v2
NoHonestDoublePrecommit ==
  \A n \in Honest, r \in Rounds, v1, v2 \in Values : (<<n, r, v1>> \in sentPc /\ <<n, r, v2>> \in sentPc) => v1 = v2

\* P1: every sent precommit/prevote is backed by the durable copy (lock at or after its round;
\* prevote recorded), so a restart cannot forget it.
SentPrecommitDurable ==
  \A n \in Honest, r \in Rounds, v \in Values : <<n, r, v>> \in sentPc => dLockR[n] >= r
SentPrevoteDurable ==
  \A n \in Honest, r \in Rounds, v \in Values : <<n, r, v>> \in sentPv => dPv[n][r] = v

\* Reachability (expected to be violated): something finalizes, so the safety checks are not vacuous.
NothingFinalizes == \A v \in Values, r \in Rounds : ~Committed(v, r)

\* Memory never runs ahead of disk: every in-memory lock and prevote record is durable. Holds for
\* the fix (disk may be ahead after an ambiguous commit), not for the current code.
MemoryBackedByDisk ==
  \A n \in Honest :
    /\ mLockR[n] <= dLockR[n]
    /\ \A r \in Rounds : mPv[n][r] # Nil => dPv[n][r] = mPv[n][r]

ValuesSymmetry == Permutations(Values)
HonestSymmetry == Permutations(Honest)
Symmetry == ValuesSymmetry \cup HonestSymmetry
=============================================================================
