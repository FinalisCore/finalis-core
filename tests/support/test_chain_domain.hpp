// SPDX-License-Identifier: MIT

#pragma once

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "utxo/validate.hpp"

namespace finalis::test {

// A fixed chain identity for tests that validate transactions without a node: test_network() and a
// constant genesis hash. Transactions signed with test_chain_domain() validate under a context from
// with_test_chain_identity().
inline const ChainId& test_chain_id() {
  static const ChainId id = [] {
    ChainId c;
    c.network_name = mainnet_network().name;
    c.genesis_hash_hex = std::string(64, 'a');
    return c;
  }();
  return id;
}

// Mainnet parameters without admission PoW, which these context-free tests never mine. The chain
// domain only uses the network id, so it is mainnet's.
inline const NetworkConfig& test_network() {
  static const NetworkConfig net = [] {
    NetworkConfig n = mainnet_network();
    n.onboarding_admission_pow_difficulty_bits = 0;
    n.validator_join_admission_pow_difficulty_bits = 0;
    return n;
  }();
  return net;
}

inline Hash32 test_chain_domain() { return consensus_chain_domain(test_network(), test_chain_id()); }

inline SpecialValidationContext with_test_chain_identity(SpecialValidationContext ctx = {}) {
  if (!ctx.network) ctx.network = &test_network();
  if (!ctx.chain_id) ctx.chain_id = &test_chain_id();
  return ctx;
}

// A context with only the test chain identity, for validating plain transactions.
inline const SpecialValidationContext* test_validation_ctx() {
  static const SpecialValidationContext ctx = with_test_chain_identity();
  return &ctx;
}

}  // namespace finalis::test
