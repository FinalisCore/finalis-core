---------------------------- MODULE timed_release ----------------------------
(***************************************************************************)
(* Time-locked transactions (McFly layer, docs/CONSENSUS.md "Timed        *)
(* Transactions"). Abstract over finality (heights finalize one at a time, *)
(* as two_phase_finality.tla establishes) and over cryptography (a body   *)
(* key for unlock height u is known once Threshold validators signed      *)
(* time_signature_message(u)).                                              *)
(*                                                                         *)
(* Modelled rules:                                                          *)
(* - honest validators sign height h only once h is final; Byzantine ones  *)
(*   have signed every height from the start (worst case);                *)
(* - block h (h > 1) needs the aggregate on h - 1 (the proposal gate);    *)
(* - a TxTimed is included only at a height <= its unlock height;         *)
(* - settlement in block h: short locks with unlock = h - 1, then long    *)
(*   locks whose opening the block carries (optional, only once the key  *)
(*   is known, within the grace period), then expiry at unlock + Grace + 1,*)
(*   all before the block's records;                                      *)
(* - records: inclusions, and relays of a decrypted body as a standalone  *)
(*   transaction (possible only if bodies are valid on their own, i.e.    *)
(*   without timed_body_chain_domain); a relayed body spends the body's   *)
(*   inputs, so its later settlement forfeits the bond;                   *)
(* - early-time-signature evidence for (v, H) is valid in block h iff     *)
(*   H >= h.                                                                *)
(*                                                                         *)
(* Mutations (each must break an invariant, see the *_mutation configs):  *)
(*   "sign_early"      honest validators sign heights not yet final       *)
(*   "late_inclusion"  inclusion allowed after the unlock height          *)
(*   "settle_last"     records run before settlement                      *)
(*   "standalone_body" bodies signed under the plain chain domain         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Honest, Byz, Txs, MaxH, Grace, Mutation

Validators == Honest \cup Byz
N          == Cardinality(Validators)
Threshold  == (2 * N) \div 3 + 1
Heights    == 1..MaxH
NoOutcome  == "none"

VARIABLES final,     \* highest final height (0: genesis)
          signed,    \* [Honest -> SUBSET Heights]: heights each honest validator signed
          unlock,    \* [Txs -> 0..MaxH]: 0 = not sent yet
          long,      \* [Txs -> BOOLEAN]
          incl,      \* [Txs -> 0..MaxH]: inclusion height, 0 = not included
          relayed,   \* [Txs -> BOOLEAN]: body relayed as a standalone record before settlement
          outcome,   \* [Txs -> {"none", "applied", "forfeit", "expired"}]
          settledAt, \* [Txs -> 0..MaxH]
          slashed    \* validators slashed by early-time-signature evidence

vars == <<final, signed, unlock, long, incl, relayed, outcome, settledAt, slashed>>

Signers(h)  == Byz \cup {v \in Honest : h \in signed[v]}
KeyKnown(h) == Cardinality(Signers(h)) >= Threshold

TypeOK ==
  /\ final \in 0..MaxH
  /\ signed \in [Honest -> SUBSET Heights]
  /\ unlock \in [Txs -> 0..MaxH]
  /\ long \in [Txs -> BOOLEAN]
  /\ incl \in [Txs -> 0..MaxH]
  /\ relayed \in [Txs -> BOOLEAN]
  /\ outcome \in [Txs -> {NoOutcome, "applied", "forfeit", "expired"}]
  /\ settledAt \in [Txs -> 0..MaxH]
  /\ slashed \subseteq Validators

Init ==
  /\ final = 0
  /\ signed = [v \in Honest |-> {}]
  /\ unlock = [t \in Txs |-> 0]
  /\ long = [t \in Txs |-> FALSE]
  /\ incl = [t \in Txs |-> 0]
  /\ relayed = [t \in Txs |-> FALSE]
  /\ outcome = [t \in Txs |-> NoOutcome]
  /\ settledAt = [t \in Txs |-> 0]
  /\ slashed = {}

\* A sender seals a body to an unlock height not yet final (wallets refuse anything else).
Send(t, u, l) ==
  /\ unlock[t] = 0
  /\ u > final
  /\ unlock' = [unlock EXCEPT ![t] = u]
  /\ long' = [long EXCEPT ![t] = l]
  /\ UNCHANGED <<final, signed, incl, relayed, outcome, settledAt, slashed>>

\* In height order (only the set of signed heights matters, not the order: fewer interleavings).
HonestSign(v, h) ==
  /\ h \notin signed[v]
  /\ \A k \in 1..(h - 1) : k \in signed[v]
  /\ (h <= final \/ Mutation = "sign_early")
  /\ signed' = [signed EXCEPT ![v] = @ \cup {h}]
  /\ UNCHANGED <<final, unlock, long, incl, relayed, outcome, settledAt, slashed>>

\* Escrows block h settles before its records: short locks due at h - 1, long locks the block opens
\* (subset `opened`), long locks expiring at h.
ShortDue(h)       == {t \in Txs : incl[t] # 0 /\ outcome[t] = NoOutcome /\ ~long[t] /\ unlock[t] = h - 1}
LongOpenable(h)   == {t \in Txs : incl[t] # 0 /\ outcome[t] = NoOutcome /\ long[t] /\
                                  unlock[t] < h /\ h - unlock[t] <= Grace /\ KeyKnown(unlock[t])}
LongExpiring(h)   == {t \in Txs : incl[t] # 0 /\ outcome[t] = NoOutcome /\ long[t] /\ h = unlock[t] + Grace + 1}

Settle(S, rel) == [t \in Txs |-> IF t \in S THEN IF rel[t] THEN "forfeit" ELSE "applied" ELSE outcome[t]]

\* Records a block can carry: inclusions, relays of known bodies (standalone_body only), and
\* early-time-signature evidence.
Includable(h) == {t \in Txs : incl[t] = 0 /\ unlock[t] # 0 /\ (h <= unlock[t] \/ Mutation = "late_inclusion")}
Relayable(h, pending) ==
  IF Mutation = "standalone_body" \/ Mutation = "settle_last"
  THEN {t \in pending : ~relayed[t] /\ KeyKnown(unlock[t])}
  ELSE {}

\* The adversary relays every body it can and files every piece of evidence it holds: both effects
\* are sticky, so doing it at once is its strongest move (and keeps the state space small).
FinalizeBlock(I, opened) ==
  LET h == final + 1 IN
  /\ h <= MaxH
  /\ (h = 1 \/ KeyKnown(h - 1))                              \* the proposal gate
  /\ I \subseteq Includable(h)
  /\ opened \subseteq LongOpenable(h)
  /\ LET due      == ShortDue(h) \cup opened
         expiring == LongExpiring(h)
         pending  == {t \in Txs : incl[t] # 0 /\ outcome[t] = NoOutcome}
     IN
     IF Mutation = "settle_last"
     THEN \* records first: relays can hit escrows this block settles
       LET rel == [t \in Txs |-> relayed[t] \/ t \in Relayable(h, pending)] IN
          /\ relayed' = rel
          /\ outcome' = [t \in Txs |-> IF t \in expiring THEN "expired" ELSE Settle(due, rel)[t]]
     ELSE
       /\ relayed' = [t \in Txs |-> relayed[t] \/ t \in Relayable(h, pending \ (due \cup expiring))]
       /\ outcome' = [t \in Txs |-> IF t \in expiring THEN "expired" ELSE Settle(due, relayed)[t]]
  /\ slashed' = slashed \cup {v \in Validators : \E hh \in h..MaxH : v \in Signers(hh)}
  /\ incl' = [t \in Txs |-> IF t \in I THEN h ELSE incl[t]]
  /\ settledAt' = [t \in Txs |-> IF outcome[t] = NoOutcome /\ outcome'[t] # NoOutcome THEN h ELSE settledAt[t]]
  /\ final' = h
  /\ UNCHANGED <<signed, unlock, long>>

Next ==
  \/ \E t \in Txs, u \in Heights, l \in BOOLEAN : Send(t, u, l)
  \/ \E v \in Honest, h \in Heights : HonestSign(v, h)
  \/ \E I \in SUBSET Txs, opened \in SUBSET Txs : FinalizeBlock(I, opened)
  \/ (final = MaxH /\ UNCHANGED vars)  \* the bounded chain ends

Spec == Init /\ [][Next]_vars

Symmetry == Permutations(Honest) \cup Permutations(Txs)

(***************************************************************************)
(* Invariants                                                               *)
(***************************************************************************)

\* No body key for a height that is not final (so no block up to it can depend on the body).
NoEarlyKey == \A h \in Heights : KeyKnown(h) => h <= final

\* An honest sender's well-formed body never forfeits its bond: nobody can spend its inputs first.
NoBondLoss == \A t \in Txs : outcome[t] # "forfeit"

\* Short locks settle exactly at unlock + 1; long locks open within the grace period or expire at
\* unlock + Grace + 1; nothing included is left unsettled past that.
SettleOnTime ==
  \A t \in Txs :
    /\ (outcome[t] # NoOutcome /\ ~long[t]) => settledAt[t] = unlock[t] + 1
    /\ (outcome[t] # NoOutcome /\ long[t]) => settledAt[t] \in (unlock[t] + 1)..(unlock[t] + Grace + 1)
    /\ (incl[t] # 0 /\ ~long[t] /\ final > unlock[t]) => outcome[t] # NoOutcome
    /\ (incl[t] # 0 /\ long[t] /\ final > unlock[t] + Grace) => outcome[t] # NoOutcome

\* Early-signature slashing never hits an honest validator.
HonestNotSlashed == slashed \subseteq Byz

\* Reachability (expected violated, run with --expect-violation): a body applies, a long lock opens,
\* a long lock expires.
NothingApplied == \A t \in Txs : outcome[t] # "applied"
NoLongOpened   == \A t \in Txs : ~(long[t] /\ outcome[t] = "applied")
NoLongExpired  == \A t \in Txs : outcome[t] # "expired"
==============================================================================
