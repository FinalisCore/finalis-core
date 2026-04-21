// SPDX-License-Identifier: MIT

#include "utxo/signing.hpp"

#include <algorithm>
#include <limits>

#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"

namespace finalis {

namespace {

std::optional<crypto::KeyPair> keypair_from_private_key(const Bytes& private_key_32, std::string* err) {
  if (private_key_32.size() != 32) {
    if (err) *err = "private key must be 32 bytes";
    return std::nullopt;
  }
  std::array<std::uint8_t, 32> seed{};
  std::copy(private_key_32.begin(), private_key_32.end(), seed.begin());
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value() && err) *err = "failed to derive keypair";
  return kp;
}

bool outpoint_less(const OutPoint& a, const OutPoint& b) {
  if (a.txid != b.txid) return a.txid < b.txid;
  return a.index < b.index;
}

std::vector<OutPoint> prev_outpoints(const std::vector<std::pair<OutPoint, TxOut>>& prevs) {
  std::vector<OutPoint> out;
  out.reserve(prevs.size());
  for (const auto& [op, _] : prevs) out.push_back(op);
  return out;
}

}  // namespace

std::vector<std::pair<OutPoint, TxOut>> deterministic_largest_first_prevs(
    const std::vector<std::pair<OutPoint, TxOut>>& available_prevs) {
  auto sorted = available_prevs;
  std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
    if (a.second.value != b.second.value) return a.second.value > b.second.value;
    return outpoint_less(a.first, b.first);
  });
  return sorted;
}

std::optional<WalletSendPlan> plan_wallet_p2pkh_send(const std::vector<std::pair<OutPoint, TxOut>>& available_prevs,
                                                     const Bytes& recipient_script_pubkey,
                                                     const Bytes& change_script_pubkey,
                                                     std::uint64_t amount_units,
                                                     std::uint64_t requested_fee_units,
                                                     std::uint64_t dust_threshold_units, std::string* err) {
  if (amount_units == 0) {
    if (err) *err = "amount must be positive";
    return std::nullopt;
  }

  WalletSendPlan plan;
  plan.amount_units = amount_units;
  plan.requested_fee_units = requested_fee_units;

  const std::uint64_t target = amount_units + requested_fee_units;
  for (const auto& prev : deterministic_largest_first_prevs(available_prevs)) {
    plan.selected_prevs.push_back(prev);
    plan.selected_units += prev.second.value;
    if (plan.selected_units >= target) break;
  }
  if (plan.selected_units < target) {
    if (err) *err = "insufficient finalized funds";
    return std::nullopt;
  }

  plan.outputs.push_back(TxOut{amount_units, recipient_script_pubkey});
  const std::uint64_t raw_change = plan.selected_units - target;
  plan.change_units = (raw_change > dust_threshold_units) ? raw_change : 0;
  if (plan.change_units > 0) {
    plan.outputs.push_back(TxOut{plan.change_units, change_script_pubkey});
  }
  plan.applied_fee_units = requested_fee_units + (raw_change - plan.change_units);
  return plan;
}

std::optional<Tx> build_signed_p2pkh_tx_single_input(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                      const Bytes& private_key_32,
                                                      const std::vector<TxOut>& outputs,
                                                      std::string* err) {
  auto kp = keypair_from_private_key(private_key_32, err);
  if (!kp.has_value()) {
    return std::nullopt;
  }

  std::array<std::uint8_t, 20> expected_pkh{};
  if (!is_p2pkh_script_pubkey(prev_out.script_pubkey, &expected_pkh)) {
    if (err) *err = "prev output is not P2PKH";
    return std::nullopt;
  }
  const auto got_pkh = crypto::h160(Bytes(kp->public_key.begin(), kp->public_key.end()));
  if (!std::equal(got_pkh.begin(), got_pkh.end(), expected_pkh.begin())) {
    if (err) *err = "private key does not match prev output pubkey hash";
    return std::nullopt;
  }

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{prev_outpoint.txid, prev_outpoint.index, Bytes{}, 0xFFFFFFFF});
  tx.outputs = outputs;

  auto msg = signing_message_for_input(tx, 0);
  if (!msg.has_value()) {
    if (err) *err = "failed to build sighash";
    return std::nullopt;
  }
  auto sig = crypto::ed25519_sign(*msg, private_key_32);
  if (!sig.has_value()) {
    if (err) *err = "failed to sign";
    return std::nullopt;
  }

  Bytes script_sig;
  script_sig.reserve(98);
  script_sig.push_back(0x40);
  script_sig.insert(script_sig.end(), sig->begin(), sig->end());
  script_sig.push_back(0x20);
  script_sig.insert(script_sig.end(), kp->public_key.begin(), kp->public_key.end());
  tx.inputs[0].script_sig = script_sig;

  return tx;
}

std::optional<Tx> build_signed_p2pkh_tx_multi_input(const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                    const Bytes& private_key_32,
                                                    const std::vector<TxOut>& outputs,
                                                    std::string* err) {
  if (prevs.empty()) {
    if (err) *err = "at least one prev output is required";
    return std::nullopt;
  }
  auto kp = keypair_from_private_key(private_key_32, err);
  if (!kp.has_value()) {
    return std::nullopt;
  }

  const auto got_pkh = crypto::h160(Bytes(kp->public_key.begin(), kp->public_key.end()));
  for (const auto& [prev_outpoint, prev_out] : prevs) {
    (void)prev_outpoint;
    std::array<std::uint8_t, 20> expected_pkh{};
    if (!is_p2pkh_script_pubkey(prev_out.script_pubkey, &expected_pkh)) {
      if (err) *err = "prev output is not P2PKH";
      return std::nullopt;
    }
    if (!std::equal(got_pkh.begin(), got_pkh.end(), expected_pkh.begin())) {
      if (err) *err = "private key does not match prev output pubkey hash";
      return std::nullopt;
    }
  }

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.outputs = outputs;
  tx.inputs.reserve(prevs.size());
  for (const auto& [prev_outpoint, _] : prevs) {
    tx.inputs.push_back(TxIn{prev_outpoint.txid, prev_outpoint.index, Bytes{}, 0xFFFFFFFF});
  }

  for (std::uint32_t i = 0; i < tx.inputs.size(); ++i) {
    auto msg = signing_message_for_input(tx, i);
    if (!msg.has_value()) {
      if (err) *err = "failed to build sighash";
      return std::nullopt;
    }
    auto sig = crypto::ed25519_sign(*msg, private_key_32);
    if (!sig.has_value()) {
      if (err) *err = "failed to sign";
      return std::nullopt;
    }
    Bytes script_sig;
    script_sig.reserve(98);
    script_sig.push_back(0x40);
    script_sig.insert(script_sig.end(), sig->begin(), sig->end());
    script_sig.push_back(0x20);
    script_sig.insert(script_sig.end(), kp->public_key.begin(), kp->public_key.end());
    tx.inputs[i].script_sig = script_sig;
  }

  return tx;
}

std::optional<Tx> build_unbond_tx(const OutPoint& bond_outpoint, const PubKey32& validator_pubkey,
                                  std::uint64_t bond_value, std::uint64_t fee,
                                  const Bytes& validator_privkey_32, std::string* err) {
  if (bond_value < fee) {
    if (err) *err = "fee exceeds bond value";
    return std::nullopt;
  }
  if (validator_privkey_32.size() != 32) {
    if (err) *err = "private key must be 32 bytes";
    return std::nullopt;
  }
  auto kp = keypair_from_private_key(validator_privkey_32, err);
  if (!kp.has_value() || kp->public_key != validator_pubkey) {
    if (err) *err = "private key/pubkey mismatch";
    return std::nullopt;
  }

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{bond_outpoint.txid, bond_outpoint.index, Bytes{}, 0xFFFFFFFF});
  Bytes spk{'S', 'C', 'V', 'A', 'L', 'U', 'N', 'B'};
  spk.insert(spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  tx.outputs.push_back(TxOut{bond_value - fee, spk});

  auto msg = unbond_message_for_input(tx, 0);
  if (!msg.has_value()) {
    if (err) *err = "unbond sighash failed";
    return std::nullopt;
  }
  auto sig = crypto::ed25519_sign(*msg, validator_privkey_32);
  if (!sig.has_value()) {
    if (err) *err = "unbond sign failed";
    return std::nullopt;
  }
  Bytes script_sig;
  script_sig.reserve(98);
  script_sig.push_back(0x40);
  script_sig.insert(script_sig.end(), sig->begin(), sig->end());
  script_sig.push_back(0x20);
  script_sig.insert(script_sig.end(), validator_pubkey.begin(), validator_pubkey.end());
  tx.inputs[0].script_sig = script_sig;

  return tx;
}

std::optional<Tx> build_validator_join_request_tx(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                  const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                  const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                  std::uint64_t bond_amount, std::uint64_t fee,
                                                  const Bytes& change_script_pubkey, std::string* err,
                                                  const ValidatorJoinAdmissionPowBuildContext* pow_ctx) {
  return build_validator_join_request_tx(
      std::vector<std::pair<OutPoint, TxOut>>{{prev_outpoint, prev_out}}, funding_privkey_32, validator_pubkey,
      validator_privkey_32, payout_pubkey, bond_amount, fee, change_script_pubkey, err, pow_ctx);
}

std::optional<Tx> build_validator_join_request_tx(const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                  const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                  const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                  std::uint64_t bond_amount, std::uint64_t fee,
                                                  const Bytes& change_script_pubkey, std::string* err,
                                                  const ValidatorJoinAdmissionPowBuildContext* pow_ctx) {
  std::uint64_t total_prev = 0;
  for (const auto& prev : prevs) total_prev += prev.second.value;
  if (total_prev < bond_amount + fee) {
    if (err) *err = "insufficient prev value for bond + fee";
    return std::nullopt;
  }
  auto pop = crypto::ed25519_sign(validator_join_request_pop_message(validator_pubkey, payout_pubkey), validator_privkey_32);
  if (!pop.has_value()) {
    if (err) *err = "failed to sign join request proof";
    return std::nullopt;
  }

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  Bytes req_spk{'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  req_spk.insert(req_spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  req_spk.insert(req_spk.end(), payout_pubkey.begin(), payout_pubkey.end());
  req_spk.insert(req_spk.end(), pop->begin(), pop->end());
  if (pow_ctx && pow_ctx->network && validator_join_admission_pow_enabled(*pow_ctx->network)) {
    // The admission PoW is epoch-scoped, expires quickly, and is only used to
    // make fresh operator admission attempts more expensive to mint.
    if (!pow_ctx->chain_id) {
      if (err) *err = "missing chain id for validator join admission pow";
      return std::nullopt;
    }
    const auto pow_epoch = admission_pow_epoch_for_height(pow_ctx->current_height, pow_ctx->network->committee_epoch_blocks);
    const auto anchor = admission_pow_epoch_anchor_hash(pow_epoch, pow_ctx->network->committee_epoch_blocks,
                                                        pow_ctx->finalized_hash_at_height);
    if (!anchor.has_value()) {
      if (err) *err = "missing finalized epoch anchor for validator join admission pow";
      return std::nullopt;
    }
    const auto operator_id = consensus::canonical_operator_id_from_join_request(payout_pubkey);
    const auto bond_commitment = bond_commitment_for_join_request(operator_id, payout_pubkey, bond_amount, prev_outpoints(prevs));
    const auto challenge =
        admission_pow_challenge(admission_pow_chain_id_hash(*pow_ctx->chain_id), pow_epoch, *anchor, operator_id,
                                bond_commitment);
    std::uint64_t nonce = 0;
    while (true) {
      if (leading_zero_bits(admission_pow_work_hash(challenge, nonce)) >=
          pow_ctx->network->validator_join_admission_pow_difficulty_bits)
        break;
      if (nonce == std::numeric_limits<std::uint64_t>::max()) {
        if (err) *err = "failed to find validator join admission pow nonce";
        return std::nullopt;
      }
      ++nonce;
    }
    codec::ByteWriter w;
    w.u64le(pow_epoch);
    w.u64le(nonce);
    const auto suffix = w.take();
    req_spk.insert(req_spk.end(), suffix.begin(), suffix.end());
  }

  std::vector<TxOut> outputs{TxOut{bond_amount, reg_spk}, TxOut{0, req_spk}};
  const std::uint64_t change = total_prev - bond_amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, change_script_pubkey});
  return build_signed_p2pkh_tx_multi_input(prevs, funding_privkey_32, outputs, err);
}

std::optional<Tx> build_onboarding_registration_tx(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                   const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                   const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                   std::uint64_t fee, const Bytes& change_script_pubkey,
                                                   std::string* err,
                                                   const ValidatorJoinAdmissionPowBuildContext* pow_ctx) {
  return build_onboarding_registration_tx(std::vector<std::pair<OutPoint, TxOut>>{{prev_outpoint, prev_out}},
                                          funding_privkey_32, validator_pubkey, validator_privkey_32, payout_pubkey,
                                          fee, change_script_pubkey, err, pow_ctx);
}

std::optional<Tx> build_onboarding_registration_tx(const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                   const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                   const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                   std::uint64_t fee, const Bytes& change_script_pubkey,
                                                   std::string* err,
                                                   const ValidatorJoinAdmissionPowBuildContext* pow_ctx) {
  std::uint64_t total_prev = 0;
  for (const auto& prev : prevs) total_prev += prev.second.value;
  if (total_prev < fee) {
    if (err) *err = "insufficient prev value for fee";
    return std::nullopt;
  }
  auto pop = crypto::ed25519_sign(onboarding_registration_pop_message(validator_pubkey, payout_pubkey),
                                  validator_privkey_32);
  if (!pop.has_value()) {
    if (err) *err = "failed to sign onboarding registration proof";
    return std::nullopt;
  }

  Bytes req_spk{'S', 'C', 'O', 'N', 'B', 'R', 'E', 'G'};
  req_spk.insert(req_spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  req_spk.insert(req_spk.end(), payout_pubkey.begin(), payout_pubkey.end());
  req_spk.insert(req_spk.end(), pop->begin(), pop->end());
  if (pow_ctx && pow_ctx->network && onboarding_admission_pow_enabled(*pow_ctx->network)) {
    if (!pow_ctx->chain_id) {
      if (err) *err = "missing chain id for onboarding admission pow";
      return std::nullopt;
    }
    const auto pow_epoch = admission_pow_epoch_for_height(pow_ctx->current_height, pow_ctx->network->committee_epoch_blocks);
    const auto anchor = admission_pow_epoch_anchor_hash(pow_epoch, pow_ctx->network->committee_epoch_blocks,
                                                        pow_ctx->finalized_hash_at_height);
    if (!anchor.has_value()) {
      if (err) *err = "missing finalized epoch anchor for onboarding admission pow";
      return std::nullopt;
    }
    const auto challenge =
        admission_pow_challenge(admission_pow_chain_id_hash(*pow_ctx->chain_id), pow_epoch, *anchor, validator_pubkey,
                                onboarding_registration_commitment(validator_pubkey, payout_pubkey));
    std::uint64_t nonce = 0;
    while (true) {
      if (leading_zero_bits(admission_pow_work_hash(challenge, nonce)) >=
          pow_ctx->network->onboarding_admission_pow_difficulty_bits)
        break;
      if (nonce == std::numeric_limits<std::uint64_t>::max()) {
        if (err) *err = "failed to find onboarding admission pow nonce";
        return std::nullopt;
      }
      ++nonce;
    }
    codec::ByteWriter w;
    w.u64le(pow_epoch);
    w.u64le(nonce);
    const auto suffix = w.take();
    req_spk.insert(req_spk.end(), suffix.begin(), suffix.end());
  }

  std::vector<TxOut> outputs{TxOut{0, req_spk}};
  const std::uint64_t change = total_prev - fee;
  if (change > 0) outputs.push_back(TxOut{change, change_script_pubkey});
  return build_signed_p2pkh_tx_multi_input(prevs, funding_privkey_32, outputs, err);
}

std::optional<Tx> build_slash_tx(const OutPoint& bond_outpoint, std::uint64_t bond_value, const Vote& vote_a,
                                 const Vote& vote_b, std::uint64_t fee, std::string* err) {
  if (bond_value < fee) {
    if (err) *err = "fee exceeds bond value";
    return std::nullopt;
  }

  codec::ByteWriter ev;
  ev.u64le(vote_a.height);
  ev.u32le(vote_a.round);
  ev.bytes_fixed(vote_a.frontier_transition_id);
  ev.bytes_fixed(vote_a.validator_pubkey);
  ev.bytes_fixed(vote_a.signature);
  ev.u64le(vote_b.height);
  ev.u32le(vote_b.round);
  ev.bytes_fixed(vote_b.frontier_transition_id);
  ev.bytes_fixed(vote_b.validator_pubkey);
  ev.bytes_fixed(vote_b.signature);
  Bytes evidence_blob = ev.take();

  codec::ByteWriter ss;
  ss.bytes(Bytes{'S', 'C', 'S', 'L', 'A', 'S', 'H'});
  ss.varbytes(evidence_blob);
  Bytes script_sig = ss.take();

  const Hash32 evh = crypto::sha256d(evidence_blob);
  Bytes burn{'S', 'C', 'B', 'U', 'R', 'N'};
  burn.insert(burn.end(), evh.begin(), evh.end());

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{bond_outpoint.txid, bond_outpoint.index, script_sig, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{bond_value - fee, burn});
  return tx;
}

}  // namespace finalis
