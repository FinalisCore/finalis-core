// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "utxo/tx.hpp"
#include "wallet/light_verifier.hpp"

namespace finalis::wallet {

// A transparent coin one server says the wallet holds.
struct ClaimedUtxo {
  OutPoint outpoint;
  std::uint64_t value{0};
  Bytes script_pubkey;
  std::uint64_t height{0};
};

struct EndpointClaims {
  std::string endpoint;
  std::uint64_t tip_height{0};
  std::vector<ClaimedUtxo> utxos;
};

struct VerifiedBalance {
  bool verified{false};
  std::uint64_t height{0};      // finalized height the coins were proven at
  std::string proof_endpoint;   // server whose proofs were accepted
  std::string detail;           // why the balance is unverified
  // Verified: every claimed coin proven unspent. Unverified: the first server's list, as reported.
  std::vector<ClaimedUtxo> utxos;
  // Servers caught out: an invalid proof, a coin described wrongly, or a proven coin left out at the
  // very height it was proven.
  std::vector<std::pair<std::string, std::string>> misbehaving;
  // Per requested confidential coin, in order; empty when unverified.
  std::vector<UtxoProofStatus> confidential;
};

// Combines what every server reports and keeps only what validator signatures back: a coin counts when
// any server reports it and it is proven unspent, so one honest server is enough to reveal a coin and
// no server can invent one. Proofs are taken from `proof_endpoints` in order until one verifies.
// `confidential` lists the wallet's confidential coins with their expected leaves. Without a verifier
// (no genesis to start from) the first server's report is returned, marked unverified.
VerifiedBalance verify_claimed_balance(LightVerifier* verifier, const std::vector<EndpointClaims>& claims,
                                       const std::vector<std::pair<OutPoint, Bytes>>& confidential,
                                       const std::vector<std::string>& proof_endpoints);

}  // namespace finalis::wallet
