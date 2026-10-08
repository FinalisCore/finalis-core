// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto/confidential.hpp"
#include "utxo/confidential_tx.hpp"

namespace finalis::consensus {

// Supply audit for confidential (TxV2) outputs, whose amounts are hidden.
//
// Every TxV2 tally enforces  sum(inputs) = sum(outputs) + fee*H + E  (E = balance-proof excess),
// so summed over history the blinds cancel and the following identity must hold:
//
//   sum(unspent confidential commitments) + sum(all excesses) == pool_value * H
//
// where pool_value is the value held in confidential outputs, tracked only from public data as
// sum over accepted TxV2 of (transparent inputs - transparent outputs - fee)  (a "turnstile").
//
// The identity catches bookkeeping corruption (wrong stored commitment, tally bug). It cannot catch
// value created by a broken range proof (that still balances mod the group order); the turnstile
// does, as soon as more value leaves the pool than entered it (pool_value < 0).
//
// The turnstile is a consensus rule: CanonicalDerivedState::confidential_pool_value is committed and
// frontier execution rejects any TxV2 that would make it negative. This ledger is an independent,
// history-derived recomputation kept as defense in depth: the audit cross-checks it against the
// committed value and checks the commitment identity. It never fails block application.
struct ConfidentialSupplyLedger {
  // False when history was not replayed (e.g. fast-start without a persisted ledger), or on an
  // internal accounting error; the audit then reports Unavailable instead of a verdict.
  bool known{true};
  std::int64_t pool_value{0};
  // First height at which pool_value went negative (0 = never).
  std::uint64_t first_negative_height{0};
  crypto::CommitmentSum excess_sum;
  std::uint64_t txv2_count{0};

  bool operator==(const ConfidentialSupplyLedger&) const = default;
};

// Consensus turnstile: change in the confidential pool caused by `tx`, i.e. transparent inputs minus
// transparent outputs minus fee, resolving inputs against `utxos` (the set the tx spends from).
// False if a transparent input is missing from `utxos`.
bool txv2_confidential_pool_delta(const TxV2& tx, const UtxoSetV2& utxos, __int128* delta);

// Accounts the accepted transactions of one finalized slice, in order. `pre_slice_utxos` is the UTXO
// set before the slice; outputs created earlier in the same slice are resolved from `accepted_txs`.
void account_confidential_supply(const UtxoSetV2& pre_slice_utxos, const std::vector<AnyTx>& accepted_txs,
                                 std::uint64_t height, ConfidentialSupplyLedger* ledger);

enum class ConfidentialSupplyAuditStatus : std::uint8_t { Ok, Unavailable, Failed };

struct ConfidentialSupplyAuditResult {
  ConfidentialSupplyAuditStatus status{ConfidentialSupplyAuditStatus::Unavailable};
  std::string detail;
  std::int64_t pool_value{0};
  std::size_t confidential_utxo_count{0};
};

// O(confidential UTXOs). Checks that the ledger's independently derived pool value never went negative
// and equals `committed_pool_value` (the consensus P), then the commitment identity against it. With the
// consensus rule in place, any failure indicates a bug or corrupted state.
ConfidentialSupplyAuditResult audit_confidential_supply(const UtxoSetV2& utxos, const ConfidentialSupplyLedger& ledger,
                                                        std::uint64_t committed_pool_value);

const char* confidential_supply_audit_status_name(ConfidentialSupplyAuditStatus status);

// Persisted form, tagged with the finalized height it describes.
Bytes serialize_confidential_supply_ledger(const ConfidentialSupplyLedger& ledger, std::uint64_t height);
std::optional<ConfidentialSupplyLedger> parse_confidential_supply_ledger(const Bytes& bytes, std::uint64_t* height);

}  // namespace finalis::consensus
