--------------------------- MODULE MC_two_phase_finality ---------------------------
\* TLC bindings: 4 validators (h1, h2, h3 honest, b1 Byzantine), quorum 3, rounds 0..2,
\* round leaders h1, b1, h2 (an honest leader on each side of a Byzantine one).
EXTENDS two_phase_finality

CONSTANTS h1, h2, h3, b1, vA, vB

MCHonest   == {h1, h2, h3}
MCByz      == {b1}
MCValues   == {vA, vB}
MCMaxRound == 2
MCLeader   == [r \in 0..2 |-> CASE r = 0 -> h1 [] r = 1 -> b1 [] r = 2 -> h2]
=============================================================================
