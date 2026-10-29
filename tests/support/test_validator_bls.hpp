// SPDX-License-Identifier: MIT

#pragma once

// A test validator's BLS key and proof of possession, derived from its Ed25519 seed exactly as
// validator_bls_registration does in production.

#include <stdexcept>

#include "crypto/bls12_381.hpp"
#include "crypto/ed25519.hpp"
#include "utxo/signing.hpp"

namespace finalis::test {

inline ValidatorBlsRegistration test_bls_registration(const crypto::KeyPair& validator) {
  auto reg = validator_bls_registration(validator.private_key);
  if (!reg) throw std::runtime_error("validator bls derivation failed");
  return *reg;
}

inline crypto::BlsPublicKey test_bls_pubkey(const crypto::KeyPair& validator) {
  return test_bls_registration(validator).pubkey;
}

}  // namespace finalis::test
