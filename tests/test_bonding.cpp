// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "common/address.hpp"
#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "codec/bytes.hpp"
#include "consensus/monetary.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp) throw std::runtime_error("key gen failed");
  return *kp;
}

Bytes reg_script(const PubKey32& pub) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  s.insert(s.end(), pub.begin(), pub.end());
  return s;
}

Bytes unb_script(const PubKey32& pub) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'U', 'N', 'B'};
  s.insert(s.end(), pub.begin(), pub.end());
  return s;
}

Bytes join_request_script(const PubKey32& validator_pub, const PubKey32& payout_pub, const Sig64& pop) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  s.insert(s.end(), validator_pub.begin(), validator_pub.end());
  s.insert(s.end(), payout_pub.begin(), payout_pub.end());
  s.insert(s.end(), pop.begin(), pop.end());
  return s;
}

Bytes onboarding_registration_script(const PubKey32& validator_pub, const PubKey32& payout_pub, const Sig64& pop) {
  Bytes s{'S', 'C', 'O', 'N', 'B', 'R', 'E', 'G'};
  s.insert(s.end(), validator_pub.begin(), validator_pub.end());
  s.insert(s.end(), payout_pub.begin(), payout_pub.end());
  s.insert(s.end(), pop.begin(), pop.end());
  return s;
}

Bytes onboarding_registration_script_with_pow(const PubKey32& validator_pub, const PubKey32& payout_pub, const Sig64& pop,
                                              std::uint64_t epoch, std::uint64_t nonce) {
  Bytes s = onboarding_registration_script(validator_pub, payout_pub, pop);
  codec::ByteWriter w;
  w.u64le(epoch);
  w.u64le(nonce);
  const auto suffix = w.take();
  s.insert(s.end(), suffix.begin(), suffix.end());
  return s;
}

Bytes join_request_script_with_pow(const PubKey32& validator_pub, const PubKey32& payout_pub, const Sig64& pop,
                                   std::uint64_t epoch, std::uint64_t nonce) {
  Bytes s = join_request_script(validator_pub, payout_pub, pop);
  codec::ByteWriter w;
  w.u64le(epoch);
  w.u64le(nonce);
  const auto suffix = w.take();
  s.insert(s.end(), suffix.begin(), suffix.end());
  return s;
}

ChainId sample_chain_id(const NetworkConfig& net) {
  return ChainId{
      .network_name = "testnet",
      .magic = net.magic,
      .network_id_hex = "00112233445566778899aabbccddeeff",
      .protocol_version = net.protocol_version,
      .genesis_hash_hex =
          "1111111111111111111111111111111111111111111111111111111111111111",
  };
}

SpecialValidationContext join_pow_ctx(const NetworkConfig& net, const ChainId& chain_id, std::uint64_t current_height,
                                      const Hash32& anchor) {
  return SpecialValidationContext{
      .network = &net,
      .chain_id = &chain_id,
      .current_height = current_height,
      .enforce_variable_bond_range = true,
      .min_bond_amount = net.validator_bond_min_amount,
      .max_bond_amount = net.validator_bond_max_amount,
      .finalized_hash_at_height = [anchor](std::uint64_t height) -> std::optional<Hash32> {
        if (height == 0) return zero_hash();
        return anchor;
      },
  };
}

SpecialValidationContext join_pow_ctx_with_validators(const NetworkConfig& net, const ChainId& chain_id,
                                                      const consensus::ValidatorRegistry& vr,
                                                      std::uint64_t current_height, const Hash32& anchor) {
  auto ctx = join_pow_ctx(net, chain_id, current_height, anchor);
  ctx.validators = &vr;
  return ctx;
}

std::optional<Tx> build_manual_join_tx(const OutPoint& prev_outpoint, const TxOut& prev_out, const Bytes& funding_privkey,
                                       const PubKey32& validator_pubkey, std::uint64_t bond_amount, std::uint64_t fee,
                                       const Bytes& change_script_pubkey, const Bytes& req_script, std::string* err = nullptr) {
  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  std::vector<TxOut> outputs{TxOut{bond_amount, reg_spk}, TxOut{0, req_script}};
  const auto change = prev_out.value - bond_amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, change_script_pubkey});
  return build_signed_p2pkh_tx_single_input(prev_outpoint, prev_out, funding_privkey, outputs, err);
}

}  // namespace

TEST(test_scval_scripts_detection) {
  const auto kp = key_from_byte(9);
  Bytes reg = reg_script(kp.public_key);
  Bytes unb = unb_script(kp.public_key);
  PubKey32 out{};
  ASSERT_TRUE(is_validator_register_script(reg, &out));
  ASSERT_EQ(out, kp.public_key);
  ASSERT_TRUE(is_validator_unbond_script(unb, &out));
  ASSERT_EQ(out, kp.public_key);
}

TEST(test_onboarding_registration_script_detection) {
  const auto validator = key_from_byte(0x31);
  const auto payout = key_from_byte(0x32);
  const auto pop =
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key),
                            validator.private_key);
  Bytes req = onboarding_registration_script(validator.public_key, payout.public_key, pop);
  PubKey32 out_validator{};
  PubKey32 out_payout{};
  Sig64 out_pop{};
  ASSERT_TRUE(is_onboarding_registration_script(req, &out_validator, &out_payout, &out_pop));
  ASSERT_EQ(out_validator, validator.public_key);
  ASSERT_EQ(out_payout, payout.public_key);
  ASSERT_EQ(out_pop, pop);

  OnboardingRegistrationScriptData parsed{};
  ASSERT_TRUE(parse_onboarding_registration_script(req, &parsed));
  ASSERT_TRUE(!parsed.has_admission_pow);
}

TEST(test_onboarding_registration_script_roundtrip_with_admission_pow_fields) {
  const auto validator = key_from_byte(0x33);
  const auto payout = key_from_byte(0x34);
  const auto pop =
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key),
                            validator.private_key);
  const auto script = onboarding_registration_script_with_pow(validator.public_key, payout.public_key, pop, 33, 9);
  OnboardingRegistrationScriptData parsed{};
  ASSERT_TRUE(parse_onboarding_registration_script(script, &parsed));
  ASSERT_TRUE(parsed.has_admission_pow);
  ASSERT_EQ(parsed.admission_pow_epoch, 33ULL);
  ASSERT_EQ(parsed.admission_pow_nonce, 9ULL);
}

TEST(test_sconbreg_tx_validates_with_zero_value_output_and_valid_pop) {
  const auto sponsor = key_from_byte(0x41);
  const auto validator = key_from_byte(0x42);
  const auto payout = key_from_byte(0x43);
  const OutPoint spend_op{Hash32{0x41}, 0};
  const TxOut prev_out{
      1'000'000,
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end())))};
  std::string err;
  auto tx = build_onboarding_registration_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                             validator.private_key, payout.public_key, 1000,
                                             prev_out.script_pubkey, &err);
  ASSERT_TRUE(tx.has_value());
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});
  auto r = validate_tx(*tx, 1, utxos, nullptr);
  ASSERT_TRUE(r.ok);
}

TEST(test_sconbreg_tx_rejects_join_request_mixing) {
  const auto sponsor = key_from_byte(0x51);
  const auto validator = key_from_byte(0x52);
  const auto payout = key_from_byte(0x53);
  const OutPoint spend_op{Hash32{0x51}, 0};
  const TxOut prev_out{
      BOND_AMOUNT + 1000,
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end())))};
  auto join_pop =
      *crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key),
                            validator.private_key);
  auto onboarding_pop =
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key),
                            validator.private_key);
  std::vector<TxOut> outputs{
      TxOut{BOND_AMOUNT, reg_script(validator.public_key)},
      TxOut{0, join_request_script(validator.public_key, payout.public_key, join_pop)},
      TxOut{0, onboarding_registration_script(validator.public_key, payout.public_key, onboarding_pop)},
  };
  const auto change = prev_out.value - BOND_AMOUNT - 1000;
  if (change > 0) outputs.push_back(TxOut{change, prev_out.script_pubkey});
  auto tx = build_signed_p2pkh_tx_single_input(spend_op, prev_out, sponsor.private_key, outputs);
  ASSERT_TRUE(tx.has_value());
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});
  auto r = validate_tx(*tx, 1, utxos, nullptr);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, std::string("SCONBREG may not appear with validator join outputs"));
}

TEST(test_sconbreg_rejects_duplicate_and_banned_validator_pubkey_when_registry_context_present) {
  const auto sponsor = key_from_byte(0x58);
  const auto validator = key_from_byte(0x59);
  const auto payout = key_from_byte(0x5a);
  const OutPoint spend_op{Hash32{0x58}, 0};
  const TxOut prev_out{
      1'000'000,
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end())))};
  std::string err;
  auto tx = build_onboarding_registration_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                             validator.private_key, payout.public_key, 1000, prev_out.script_pubkey);
  ASSERT_TRUE(tx.has_value());
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});

  auto net = mainnet_network();
  const auto chain_id = sample_chain_id(net);
  Hash32 anchor{};
  anchor.fill(0x31);
  consensus::ValidatorRegistry vr;
  ASSERT_TRUE(vr.register_onboarding(validator.public_key, 10, &err));
  auto duplicate_ctx = join_pow_ctx_with_validators(net, chain_id, vr, 10, anchor);
  auto duplicate = validate_tx(*tx, 1, utxos, &duplicate_ctx);
  ASSERT_TRUE(!duplicate.ok);
  ASSERT_EQ(duplicate.error, std::string("validator already registered"));

  vr.ban(validator.public_key, 11);
  auto banned_ctx = join_pow_ctx_with_validators(net, chain_id, vr, 11, anchor);
  auto banned = validate_tx(*tx, 1, utxos, &banned_ctx);
  ASSERT_TRUE(!banned.ok);
  ASSERT_EQ(banned.error, std::string("validator banned"));
}

TEST(test_sconbreg_admission_pow_valid_nonce_is_accepted_and_disabled_mode_preserves_legacy) {
  auto net = mainnet_network();
  net.onboarding_admission_pow_difficulty_bits = 4;
  const auto chain_id = sample_chain_id(net);
  Hash32 anchor{};
  anchor.fill(0x66);
  const auto sponsor = key_from_byte(0x61);
  const auto validator = key_from_byte(0x62);
  const auto payout = key_from_byte(0x63);
  const OutPoint spend_op{Hash32{0x61}, 0};
  const TxOut prev_out{
      1'000'000,
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end())))};
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &net,
      .chain_id = &chain_id,
      .current_height = 33,
      .finalized_hash_at_height = [anchor](std::uint64_t height) -> std::optional<Hash32> {
        if (height == 0) return zero_hash();
        return anchor;
      },
  };
  std::string err;
  auto tx = build_onboarding_registration_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                             validator.private_key, payout.public_key, 1000, prev_out.script_pubkey,
                                             &err, &pow_ctx);
  ASSERT_TRUE(tx.has_value());
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});
  auto ctx = join_pow_ctx(net, chain_id, 33, anchor);
  const auto accepted = validate_tx(*tx, 1, utxos, &ctx);
  ASSERT_TRUE(accepted.ok);

  auto disabled_net = net;
  disabled_net.onboarding_admission_pow_difficulty_bits = 0;
  auto disabled_ctx = join_pow_ctx(disabled_net, chain_id, 33, anchor);
  auto legacy_tx = build_onboarding_registration_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                                    validator.private_key, payout.public_key, 1000,
                                                    prev_out.script_pubkey, &err, nullptr);
  ASSERT_TRUE(legacy_tx.has_value());
  ASSERT_TRUE(validate_tx(*legacy_tx, 1, utxos, &disabled_ctx).ok);
}

TEST(test_sconbreg_admission_pow_rejects_invalid_nonce_expired_epoch_wrong_anchor_and_wrong_payout_binding) {
  auto net = mainnet_network();
  net.onboarding_admission_pow_difficulty_bits = 4;
  net.committee_epoch_blocks = 16;
  const auto chain_id = sample_chain_id(net);
  Hash32 anchor{};
  anchor.fill(0x77);
  const auto sponsor = key_from_byte(0x71);
  const auto validator = key_from_byte(0x72);
  const auto payout = key_from_byte(0x73);
  const auto other_payout = key_from_byte(0x74);
  const OutPoint spend_op{Hash32{0x71}, 0};
  const TxOut prev_out{
      1'000'000,
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end())))};
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &net,
      .chain_id = &chain_id,
      .current_height = 33,
      .finalized_hash_at_height = [anchor](std::uint64_t height) -> std::optional<Hash32> {
        if (height == 0) return zero_hash();
        return anchor;
      },
  };
  std::string err;
  auto valid_tx = build_onboarding_registration_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                                   validator.private_key, payout.public_key, 1000,
                                                   prev_out.script_pubkey, &err, &pow_ctx);
  ASSERT_TRUE(valid_tx.has_value());
  UtxoSet view;
  view.emplace(spend_op, UtxoEntry{prev_out});
  auto valid_ctx = join_pow_ctx(net, chain_id, 33, anchor);
  ASSERT_TRUE(validate_tx(*valid_tx, 1, view, &valid_ctx).ok);

  OnboardingRegistrationScriptData parsed{};
  ASSERT_TRUE(parse_onboarding_registration_script(valid_tx->outputs[0].script_pubkey, &parsed));

  const auto pow_anchor = admission_pow_epoch_anchor_hash(
      parsed.admission_pow_epoch, net.committee_epoch_blocks, valid_ctx.finalized_hash_at_height);
  ASSERT_TRUE(pow_anchor.has_value());
  const auto pow_challenge = admission_pow_challenge(
      admission_pow_chain_id_hash(chain_id), parsed.admission_pow_epoch, *pow_anchor, validator.public_key,
      onboarding_registration_commitment(validator.public_key, payout.public_key));
  std::uint64_t bad_nonce = parsed.admission_pow_nonce + 1;
  while (leading_zero_bits(admission_pow_work_hash(pow_challenge, bad_nonce)) >=
         net.onboarding_admission_pow_difficulty_bits) {
    ++bad_nonce;
  }
  auto bad_nonce_script = onboarding_registration_script_with_pow(
      validator.public_key, payout.public_key, parsed.pop, parsed.admission_pow_epoch, bad_nonce);
  auto bad_nonce_tx = build_signed_p2pkh_tx_single_input(
      spend_op, prev_out, sponsor.private_key,
      std::vector<TxOut>{TxOut{0, bad_nonce_script}, TxOut{prev_out.value - 1000, prev_out.script_pubkey}});
  ASSERT_TRUE(bad_nonce_tx.has_value());
  ASSERT_TRUE(!validate_tx(*bad_nonce_tx, 1, view, &valid_ctx).ok);

  bool wrong_anchor_rejected = false;
  for (std::uint32_t i = 0; i < 256; ++i) {
    Hash32 wrong_anchor{};
    wrong_anchor.fill(static_cast<std::uint8_t>(0x78 + i));
    if (wrong_anchor == anchor) continue;
    auto wrong_anchor_ctx = join_pow_ctx(net, chain_id, 33, wrong_anchor);
    if (!validate_tx(*valid_tx, 1, view, &wrong_anchor_ctx).ok) {
      wrong_anchor_rejected = true;
      break;
    }
  }
  ASSERT_TRUE(wrong_anchor_rejected);

  auto expired_ctx = join_pow_ctx(net, chain_id, 97, anchor);
  ASSERT_TRUE(!validate_tx(*valid_tx, 1, view, &expired_ctx).ok);

  auto wrong_payout_pop =
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, other_payout.public_key),
                            validator.private_key);
  auto wrong_payout_script = onboarding_registration_script_with_pow(
      validator.public_key, other_payout.public_key, wrong_payout_pop, parsed.admission_pow_epoch,
      parsed.admission_pow_nonce);
  auto wrong_payout_tx = build_signed_p2pkh_tx_single_input(
      spend_op, prev_out, sponsor.private_key,
      std::vector<TxOut>{TxOut{0, wrong_payout_script}, TxOut{prev_out.value - 1000, prev_out.script_pubkey}});
  ASSERT_TRUE(wrong_payout_tx.has_value());
  ASSERT_TRUE(!validate_tx(*wrong_payout_tx, 1, view, &valid_ctx).ok);
}

TEST(test_admission_pow_challenge_is_deterministic_and_bound) {
  const auto payout = key_from_byte(0x41);
  const auto operator_id = consensus::canonical_operator_id_from_join_request(payout.public_key);
  std::vector<OutPoint> inputs{
      OutPoint{Hash32{1}, 0},
  };
  Hash32 anchor{};
  anchor.fill(0x55);
  auto chain_id = sample_chain_id(mainnet_network());
  const auto chain_hash = admission_pow_chain_id_hash(chain_id);
  const auto bond_a = bond_commitment_for_join_request(operator_id, payout.public_key, BOND_AMOUNT, inputs);
  const auto challenge_a = admission_pow_challenge(chain_hash, 33, anchor, operator_id, bond_a);
  const auto challenge_b = admission_pow_challenge(chain_hash, 33, anchor, operator_id, bond_a);
  ASSERT_EQ(challenge_a, challenge_b);

  const auto changed_amount = bond_commitment_for_join_request(operator_id, payout.public_key, BOND_AMOUNT + 1, inputs);
  ASSERT_TRUE(admission_pow_challenge(chain_hash, 33, anchor, operator_id, changed_amount) != challenge_a);
  const auto other_operator = key_from_byte(0x42);
  ASSERT_TRUE(admission_pow_challenge(chain_hash, 33, anchor,
                                      consensus::canonical_operator_id_from_join_request(other_operator.public_key), bond_a) !=
              challenge_a);
}

TEST(test_join_request_script_roundtrip_with_admission_pow_fields) {
  const auto validator = key_from_byte(0x51);
  const auto payout = key_from_byte(0x52);
  const auto pop =
      *crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key), validator.private_key);
  const auto script = join_request_script_with_pow(validator.public_key, payout.public_key, pop, 33, 7);
  ValidatorJoinRequestScriptData parsed;
  ASSERT_TRUE(parse_validator_join_request_script(script, &parsed));
  ASSERT_EQ(parsed.validator_pubkey, validator.public_key);
  ASSERT_EQ(parsed.payout_pubkey, payout.public_key);
  ASSERT_EQ(parsed.pop, pop);
  ASSERT_TRUE(parsed.has_admission_pow);
  ASSERT_EQ(parsed.admission_pow_epoch, 33ULL);
  ASSERT_EQ(parsed.admission_pow_nonce, 7ULL);
}

TEST(test_validator_join_admission_pow_valid_nonce_is_accepted_and_disabled_mode_preserves_legacy) {
  const auto sponsor = key_from_byte(0x61);
  const auto validator = key_from_byte(0x62);
  const auto payout = key_from_byte(0x63);
  const auto sponsor_pkh = crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end()));
  const Bytes change_spk = address::p2pkh_script_pubkey(sponsor_pkh);
  OutPoint spend_op{};
  spend_op.txid.fill(0x91);
  spend_op.index = 0;
  TxOut prev_out{BOND_AMOUNT + 1'000, change_spk};
  UtxoSet view;
  view[spend_op] = UtxoEntry{prev_out};

  auto net = mainnet_network();
  net.validator_join_admission_pow_difficulty_bits = 4;
  const auto chain_id = sample_chain_id(net);
  Hash32 anchor{};
  anchor.fill(0x77);
  const auto ctx = join_pow_ctx(net, chain_id, 33, anchor);

  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &net,
      .chain_id = &chain_id,
      .current_height = 33,
      .finalized_hash_at_height = [anchor](std::uint64_t height) -> std::optional<Hash32> {
        if (height == 0) return zero_hash();
        return anchor;
      },
  };
  std::string err;
  auto tx = build_validator_join_request_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                            validator.private_key, payout.public_key, BOND_AMOUNT, 1'000, change_spk, &err,
                                            &pow_ctx);
  ASSERT_TRUE(tx.has_value());
  const auto accepted = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(accepted.ok);

  auto disabled_net = net;
  disabled_net.validator_join_admission_pow_difficulty_bits = 0;
  auto legacy_tx = build_validator_join_request_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                                   validator.private_key, payout.public_key, BOND_AMOUNT, 1'000, change_spk,
                                                   &err, nullptr);
  ASSERT_TRUE(legacy_tx.has_value());
  const auto disabled_ctx = join_pow_ctx(disabled_net, chain_id, 33, anchor);
  ASSERT_TRUE(validate_tx(*legacy_tx, 1, view, &disabled_ctx).ok);
}

TEST(test_validator_join_admission_pow_rejects_invalid_nonce_expired_epoch_wrong_anchor_and_wrong_payout_binding) {
  const auto sponsor = key_from_byte(0x71);
  const auto validator = key_from_byte(0x72);
  const auto payout = key_from_byte(0x73);
  const auto other_payout = key_from_byte(0x74);
  const auto sponsor_pkh = crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end()));
  const Bytes change_spk = address::p2pkh_script_pubkey(sponsor_pkh);
  OutPoint spend_op{};
  spend_op.txid.fill(0x92);
  spend_op.index = 0;
  TxOut prev_out{BOND_AMOUNT + 1'000, change_spk};
  UtxoSet view;
  view[spend_op] = UtxoEntry{prev_out};

  auto net = mainnet_network();
  net.validator_join_admission_pow_difficulty_bits = 4;
  const auto chain_id = sample_chain_id(net);
  Hash32 anchor{};
  anchor.fill(0x88);
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &net,
      .chain_id = &chain_id,
      .current_height = 33,
      .finalized_hash_at_height = [anchor](std::uint64_t height) -> std::optional<Hash32> {
        if (height == 0) return zero_hash();
        return anchor;
      },
  };
  std::string err;
  auto valid_tx = build_validator_join_request_tx(spend_op, prev_out, sponsor.private_key, validator.public_key,
                                                  validator.private_key, payout.public_key, BOND_AMOUNT, 1'000, change_spk,
                                                  &err, &pow_ctx);
  ASSERT_TRUE(valid_tx.has_value());
  ValidatorJoinRequestScriptData parsed;
  ASSERT_TRUE(parse_validator_join_request_script(valid_tx->outputs[1].script_pubkey, &parsed));

  const auto pop_same =
      *crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key), validator.private_key);
  auto bad_nonce_script =
      join_request_script_with_pow(validator.public_key, payout.public_key, pop_same, parsed.admission_pow_epoch,
                                   parsed.admission_pow_nonce + 1);
  auto bad_nonce_tx =
      build_manual_join_tx(spend_op, prev_out, sponsor.private_key, validator.public_key, BOND_AMOUNT, 1'000, change_spk,
                           bad_nonce_script, &err);
  ASSERT_TRUE(bad_nonce_tx.has_value());
  auto valid_ctx = join_pow_ctx(net, chain_id, 33, anchor);
  ASSERT_TRUE(!validate_tx(*bad_nonce_tx, 1, view, &valid_ctx).ok);

  Hash32 wrong_anchor{};
  wrong_anchor.fill(0x99);
  auto wrong_anchor_ctx = join_pow_ctx(net, chain_id, 33, wrong_anchor);
  ASSERT_TRUE(!validate_tx(*valid_tx, 1, view, &wrong_anchor_ctx).ok);

  auto expired_ctx = join_pow_ctx(net, chain_id, 97, anchor);
  ASSERT_TRUE(!validate_tx(*valid_tx, 1, view, &expired_ctx).ok);

  const auto mutated_pop = *crypto::ed25519_sign(
      validator_join_request_pop_message(validator.public_key, other_payout.public_key), validator.private_key);
  auto wrong_payout_script =
      join_request_script_with_pow(validator.public_key, other_payout.public_key, mutated_pop, parsed.admission_pow_epoch,
                                   parsed.admission_pow_nonce);
  auto wrong_payout_tx =
      build_manual_join_tx(spend_op, prev_out, sponsor.private_key, validator.public_key, BOND_AMOUNT, 1'000, change_spk,
                           wrong_payout_script, &err);
  ASSERT_TRUE(wrong_payout_tx.has_value());
  auto wrong_payout_ctx = join_pow_ctx(net, chain_id, 33, anchor);
  ASSERT_TRUE(!validate_tx(*wrong_payout_tx, 1, view, &wrong_payout_ctx).ok);
}

TEST(test_unbond_signature_and_rule_validation) {
  const auto kp = key_from_byte(10);
  OutPoint bond_op{};
  bond_op.txid.fill(0xA0);
  bond_op.index = 0;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 1);
  vr.advance_height(WARMUP_BLOCKS + 2);

  std::string err;
  auto tx = build_unbond_tx(bond_op, kp.public_key, BOND_AMOUNT, 1000, kp.private_key, &err);
  ASSERT_TRUE(tx.has_value());

  SpecialValidationContext ctx{
      .validators = &vr,
      .current_height = WARMUP_BLOCKS + 5,
      .is_committee_member = {},
  };
  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(r.ok);
}

TEST(test_scvalreg_requires_matching_join_request) {
  const auto kp = key_from_byte(17);
  const auto sponsor = key_from_byte(18);

  OutPoint spend_op{};
  spend_op.txid.fill(0xD1);
  spend_op.index = 0;

  UtxoSet view;
  auto sponsor_pkh = crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end()));
  view[spend_op] = UtxoEntry{TxOut{BOND_AMOUNT, address::p2pkh_script_pubkey(sponsor_pkh)}};

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{spend_op.txid, spend_op.index, Bytes{}, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{BOND_AMOUNT, reg_script(kp.public_key)});

  auto msg = signing_message_for_input(tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, sponsor.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), sponsor.public_key.begin(), sponsor.public_key.end());
  tx.inputs[0].script_sig = ss;

  consensus::ValidatorRegistry vr;
  SpecialValidationContext ctx{
      .validators = &vr,
      .current_height = 1,
  };
  auto r = validate_tx(tx, 1, view, &ctx);
  ASSERT_TRUE(!r.ok);
}

TEST(test_unbond_delay_enforced) {
  const auto kp = key_from_byte(11);
  OutPoint unb_op{};
  unb_op.txid.fill(0xB0);
  unb_op.index = 0;

  UtxoSet view;
  view[unb_op] = UtxoEntry{TxOut{BOND_AMOUNT - 1000, unb_script(kp.public_key)}};

  consensus::ValidatorRegistry vr;
  OutPoint bond_op{};
  bond_op.txid.fill(0xA1);
  bond_op.index = 0;
  vr.register_bond(kp.public_key, bond_op, 1);
  vr.request_unbond(kp.public_key, 50);

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{unb_op.txid, unb_op.index, Bytes{}, 0xFFFFFFFF});
  auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  tx.outputs.push_back(TxOut{BOND_AMOUNT - 2000, address::p2pkh_script_pubkey(pkh)});

  auto msg = signing_message_for_input(tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), kp.public_key.begin(), kp.public_key.end());
  tx.inputs[0].script_sig = ss;

  SpecialValidationContext early{.validators = &vr, .current_height = 50 + UNBOND_DELAY_BLOCKS - 1};
  auto r1 = validate_tx(tx, 1, view, &early);
  ASSERT_TRUE(!r1.ok);

  SpecialValidationContext late{.validators = &vr, .current_height = 50 + UNBOND_DELAY_BLOCKS};
  auto r2 = validate_tx(tx, 1, view, &late);
  ASSERT_TRUE(r2.ok);
}

TEST(test_existing_pre_fork_bond_can_unbond_after_economics_fork) {
  const auto kp = key_from_byte(21);
  OutPoint unb_op{};
  unb_op.txid.fill(0xC0);
  unb_op.index = 0;

  UtxoSet view;
  view[unb_op] = UtxoEntry{TxOut{BOND_AMOUNT - 1000, unb_script(kp.public_key)}};

  consensus::ValidatorRegistry vr;
  OutPoint bond_op{};
  bond_op.txid.fill(0xC1);
  bond_op.index = 0;
  ASSERT_TRUE(vr.register_bond(kp.public_key, bond_op, 1, BOND_AMOUNT));
  ASSERT_TRUE(vr.request_unbond(kp.public_key, 50));

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{unb_op.txid, unb_op.index, Bytes{}, 0xFFFFFFFF});
  auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  tx.outputs.push_back(TxOut{BOND_AMOUNT - 2000, address::p2pkh_script_pubkey(pkh)});

  auto msg = signing_message_for_input(tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), kp.public_key.begin(), kp.public_key.end());
  tx.inputs[0].script_sig = ss;

  SpecialValidationContext post_fork{
      .validators = &vr,
      .current_height = consensus::ECONOMICS_FORK_HEIGHT + UNBOND_DELAY_BLOCKS + 50,
  };
  auto r = validate_tx(tx, 1, view, &post_fork);
  ASSERT_TRUE(r.ok);
}

TEST(test_unbond_finalize_withdrawal_clears_live_bond_state) {
  const auto kp = key_from_byte(16);
  OutPoint bond_op{};
  bond_op.txid.fill(0xB2);
  bond_op.index = 0;

  consensus::ValidatorRegistry vr;
  ASSERT_TRUE(vr.register_bond(kp.public_key, bond_op, 10, BOND_AMOUNT));
  vr.advance_height(10 + WARMUP_BLOCKS);

  auto before = vr.get(kp.public_key);
  ASSERT_TRUE(before.has_value());
  ASSERT_TRUE(before->has_bond);
  ASSERT_TRUE(vr.is_active_for_height(kp.public_key, 10 + WARMUP_BLOCKS));

  ASSERT_TRUE(vr.request_unbond(kp.public_key, 50));
  ASSERT_TRUE(!vr.can_withdraw_bond(kp.public_key, 50 + UNBOND_DELAY_BLOCKS - 1, UNBOND_DELAY_BLOCKS));
  ASSERT_TRUE(vr.can_withdraw_bond(kp.public_key, 50 + UNBOND_DELAY_BLOCKS, UNBOND_DELAY_BLOCKS));
  ASSERT_TRUE(vr.finalize_withdrawal(kp.public_key));

  auto after = vr.get(kp.public_key);
  ASSERT_TRUE(after.has_value());
  ASSERT_TRUE(!after->has_bond);
  ASSERT_TRUE(!vr.can_withdraw_bond(kp.public_key, 50 + UNBOND_DELAY_BLOCKS, UNBOND_DELAY_BLOCKS));
  ASSERT_TRUE(!vr.is_active_for_height(kp.public_key, 50 + UNBOND_DELAY_BLOCKS + 1));
}

TEST(test_banned_validator_cannot_unbond_scvalreg) {
  const auto kp = key_from_byte(14);
  OutPoint bond_op{};
  bond_op.txid.fill(0xB1);
  bond_op.index = 0;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 1);
  vr.ban(kp.public_key, 10);

  std::string err;
  auto tx = build_unbond_tx(bond_op, kp.public_key, BOND_AMOUNT, 1000, kp.private_key, &err);
  ASSERT_TRUE(tx.has_value());

  SpecialValidationContext ctx{
      .validators = &vr,
      .current_height = 20,
      .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
      .is_committee_member = {},
  };
  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(!r.ok);
}

TEST(test_slash_evidence_parsing_and_validation) {
  const auto kp = key_from_byte(12);
  OutPoint bond_op{};
  bond_op.txid.fill(0xC0);
  bond_op.index = 1;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  Vote a;
  a.height = 100;
  a.round = 2;
  a.block_id.fill(0x11);
  a.validator_pubkey = kp.public_key;
  auto siga = crypto::ed25519_sign(vote_signing_message(a.height, a.round, a.block_id), kp.private_key);
  ASSERT_TRUE(siga.has_value());
  a.signature = *siga;

  Vote b = a;
  b.block_id.fill(0x22);
  auto sigb = crypto::ed25519_sign(vote_signing_message(b.height, b.round, b.block_id), kp.private_key);
  ASSERT_TRUE(sigb.has_value());
  b.signature = *sigb;

  std::string err;
  auto tx = build_slash_tx(bond_op, BOND_AMOUNT, a, b, 0, &err);
  ASSERT_TRUE(tx.has_value());

  SlashEvidence e;
  ASSERT_TRUE(parse_slash_script_sig(tx->inputs[0].script_sig, &e));

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 10);
  vr.advance_height(200);
  SpecialValidationContext ctx{
      .validators = &vr,
      .current_height = 200,
      .is_committee_member = [](const PubKey32&, std::uint64_t, std::uint32_t) { return true; },
  };

  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(r.ok);
}

TEST(test_scvalunb_slash_evidence_validation) {
  const auto kp = key_from_byte(15);
  OutPoint unb_op{};
  unb_op.txid.fill(0xC1);
  unb_op.index = 0;

  UtxoSet view;
  view[unb_op] = UtxoEntry{TxOut{BOND_AMOUNT - 1000, unb_script(kp.public_key)}};

  Vote a;
  a.height = 200;
  a.round = 1;
  a.block_id.fill(0x31);
  a.validator_pubkey = kp.public_key;
  auto siga = crypto::ed25519_sign(vote_signing_message(a.height, a.round, a.block_id), kp.private_key);
  ASSERT_TRUE(siga.has_value());
  a.signature = *siga;

  Vote b = a;
  b.block_id.fill(0x32);
  auto sigb = crypto::ed25519_sign(vote_signing_message(b.height, b.round, b.block_id), kp.private_key);
  ASSERT_TRUE(sigb.has_value());
  b.signature = *sigb;

  std::string err;
  auto tx = build_slash_tx(unb_op, BOND_AMOUNT - 1000, a, b, 0, &err);
  ASSERT_TRUE(tx.has_value());

  consensus::ValidatorRegistry vr;
  OutPoint bond_op{};
  bond_op.txid.fill(0xC2);
  bond_op.index = 0;
  vr.register_bond(kp.public_key, bond_op, 10);
  ASSERT_TRUE(vr.request_unbond(kp.public_key, 50));

  SpecialValidationContext ctx{
      .validators = &vr,
      .current_height = 200,
      .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
      .is_committee_member = [](const PubKey32&, std::uint64_t, std::uint32_t) { return true; },
  };
  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(r.ok);
}

TEST(test_scvalreg_not_spendable_as_normal_p2pkh) {
  const auto kp = key_from_byte(13);
  OutPoint bond_op{};
  bond_op.txid.fill(0xD0);
  bond_op.index = 0;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{bond_op.txid, bond_op.index, Bytes{}, 0xFFFFFFFF});
  auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  tx.outputs.push_back(TxOut{BOND_AMOUNT - 1000, address::p2pkh_script_pubkey(pkh)});

  auto msg = signing_message_for_input(tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), kp.public_key.begin(), kp.public_key.end());
  tx.inputs[0].script_sig = ss;

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 1);
  SpecialValidationContext ctx{
      .validators = &vr,
      .current_height = 10,
      .is_committee_member = {},
  };

  auto r = validate_tx(tx, 1, view, &ctx);
  ASSERT_TRUE(!r.ok);
}

void register_bonding_tests() {}
