// SPDX-License-Identifier: MIT

#include "support/test_chain_domain.hpp"
#include "test_framework.hpp"
#include "support/test_validator_bls.hpp"

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

Bytes join_request_script(const crypto::KeyPair& validator, const PubKey32& payout_pub, const Sig64& pop) {
  const auto bls = test::test_bls_registration(validator);
  ValidatorJoinRequestScriptData d{};
  d.validator_pubkey = validator.public_key;
  d.payout_pubkey = payout_pub;
  d.pop = pop;
  d.bls_pubkey = bls.pubkey;
  d.bls_pop = bls.pop;
  return encode_validator_join_request_script(d);
}

Bytes onboarding_registration_script(const crypto::KeyPair& validator, const PubKey32& payout_pub, const Sig64& pop) {
  const auto bls = test::test_bls_registration(validator);
  OnboardingRegistrationScriptData d{};
  d.validator_pubkey = validator.public_key;
  d.payout_pubkey = payout_pub;
  d.pop = pop;
  d.bls_pubkey = bls.pubkey;
  d.bls_pop = bls.pop;
  return encode_onboarding_registration_script(d);
}

Bytes onboarding_registration_script_with_pow(const crypto::KeyPair& validator, const PubKey32& payout_pub, const Sig64& pop,
                                              std::uint64_t epoch, std::uint64_t nonce) {
  const auto bls = test::test_bls_registration(validator);
  OnboardingRegistrationScriptData d{};
  d.validator_pubkey = validator.public_key;
  d.payout_pubkey = payout_pub;
  d.pop = pop;
  d.bls_pubkey = bls.pubkey;
  d.bls_pop = bls.pop;
  d.has_admission_pow = true;
  d.admission_pow_epoch = epoch;
  d.admission_pow_nonce = nonce;
  return encode_onboarding_registration_script(d);
}

Bytes join_request_script_with_pow(const crypto::KeyPair& validator, const PubKey32& payout_pub, const Sig64& pop,
                                   std::uint64_t epoch, std::uint64_t nonce) {
  const auto bls = test::test_bls_registration(validator);
  ValidatorJoinRequestScriptData d{};
  d.validator_pubkey = validator.public_key;
  d.payout_pubkey = payout_pub;
  d.pop = pop;
  d.bls_pubkey = bls.pubkey;
  d.bls_pop = bls.pop;
  d.has_admission_pow = true;
  d.admission_pow_epoch = epoch;
  d.admission_pow_nonce = nonce;
  return encode_validator_join_request_script(d);
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

// Chain identity the slash tests validate under; evidence counts only if signed in its domain.
const ChainId& slash_test_chain_id() {
  static const ChainId id = sample_chain_id(mainnet_network());
  return id;
}

Hash32 slash_test_domain() { return consensus_chain_domain(mainnet_network(), slash_test_chain_id()); }

SpecialValidationContext join_pow_ctx(const NetworkConfig& net, const ChainId& chain_id, std::uint64_t current_height,
                                      const Hash32& anchor) {
  return finalis::test::with_test_chain_identity(SpecialValidationContext{
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
  });
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
  return build_signed_p2pkh_tx_single_input(finalis::test::test_chain_domain(), prev_outpoint, prev_out, funding_privkey, outputs, err);
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
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key, test::test_bls_pubkey(validator)),
                            validator.private_key);
  Bytes req = onboarding_registration_script(validator, payout.public_key, pop);
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
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key, test::test_bls_pubkey(validator)),
                            validator.private_key);
  const auto script = onboarding_registration_script_with_pow(validator, payout.public_key, pop, 33, 9);
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
  auto tx = build_onboarding_registration_tx(finalis::test::test_chain_domain(), spend_op, prev_out, sponsor.private_key, validator.public_key,
                                             validator.private_key, payout.public_key, 1000,
                                             prev_out.script_pubkey, &err);
  ASSERT_TRUE(tx.has_value());
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});
  auto r = validate_tx(*tx, 1, utxos, finalis::test::test_validation_ctx());
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
      *crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key, test::test_bls_pubkey(validator)),
                            validator.private_key);
  auto onboarding_pop =
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key, test::test_bls_pubkey(validator)),
                            validator.private_key);
  std::vector<TxOut> outputs{
      TxOut{BOND_AMOUNT, reg_script(validator.public_key)},
      TxOut{0, join_request_script(validator, payout.public_key, join_pop)},
      TxOut{0, onboarding_registration_script(validator, payout.public_key, onboarding_pop)},
  };
  const auto change = prev_out.value - BOND_AMOUNT - 1000;
  if (change > 0) outputs.push_back(TxOut{change, prev_out.script_pubkey});
  auto tx = build_signed_p2pkh_tx_single_input(finalis::test::test_chain_domain(), spend_op, prev_out, sponsor.private_key, outputs);
  ASSERT_TRUE(tx.has_value());
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});
  auto r = validate_tx(*tx, 1, utxos, finalis::test::test_validation_ctx());
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
  auto net = mainnet_network();
  const auto chain_id = sample_chain_id(net);
  std::string err;
  auto tx = build_onboarding_registration_tx(consensus_chain_domain(net, chain_id), spend_op, prev_out, sponsor.private_key, validator.public_key,
                                             validator.private_key, payout.public_key, 1000, prev_out.script_pubkey);
  ASSERT_TRUE(tx.has_value());
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});

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
  auto tx = build_onboarding_registration_tx(consensus_chain_domain(net, chain_id), spend_op, prev_out, sponsor.private_key, validator.public_key,
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
  auto legacy_tx = build_onboarding_registration_tx(consensus_chain_domain(net, chain_id), spend_op, prev_out, sponsor.private_key, validator.public_key,
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
  auto valid_tx = build_onboarding_registration_tx(consensus_chain_domain(net, chain_id), spend_op, prev_out, sponsor.private_key, validator.public_key,
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
      validator, payout.public_key, parsed.pop, parsed.admission_pow_epoch, bad_nonce);
  auto bad_nonce_tx = build_signed_p2pkh_tx_single_input(consensus_chain_domain(net, chain_id), 
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
      *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, other_payout.public_key, test::test_bls_pubkey(validator)),
                            validator.private_key);
  auto wrong_payout_script = onboarding_registration_script_with_pow(
      validator, other_payout.public_key, wrong_payout_pop, parsed.admission_pow_epoch,
      parsed.admission_pow_nonce);
  auto wrong_payout_tx = build_signed_p2pkh_tx_single_input(consensus_chain_domain(net, chain_id), 
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
      *crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key, test::test_bls_pubkey(validator)), validator.private_key);
  const auto script = join_request_script_with_pow(validator, payout.public_key, pop, 33, 7);
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
  auto tx = build_validator_join_request_tx(consensus_chain_domain(net, chain_id), spend_op, prev_out, sponsor.private_key, validator.public_key,
                                            validator.private_key, payout.public_key, BOND_AMOUNT, 1'000, change_spk, &err,
                                            &pow_ctx);
  ASSERT_TRUE(tx.has_value());
  const auto accepted = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(accepted.ok);

  auto disabled_net = net;
  disabled_net.validator_join_admission_pow_difficulty_bits = 0;
  auto legacy_tx = build_validator_join_request_tx(consensus_chain_domain(net, chain_id), spend_op, prev_out, sponsor.private_key, validator.public_key,
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
  auto valid_tx = build_validator_join_request_tx(consensus_chain_domain(net, chain_id), spend_op, prev_out, sponsor.private_key, validator.public_key,
                                                  validator.private_key, payout.public_key, BOND_AMOUNT, 1'000, change_spk,
                                                  &err, &pow_ctx);
  ASSERT_TRUE(valid_tx.has_value());
  ValidatorJoinRequestScriptData parsed;
  ASSERT_TRUE(parse_validator_join_request_script(valid_tx->outputs[1].script_pubkey, &parsed));

  const auto pop_same =
      *crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key, test::test_bls_pubkey(validator)), validator.private_key);
  auto bad_nonce_script =
      join_request_script_with_pow(validator, payout.public_key, pop_same, parsed.admission_pow_epoch,
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
      validator_join_request_pop_message(validator.public_key, other_payout.public_key, test::test_bls_pubkey(validator)), validator.private_key);
  auto wrong_payout_script =
      join_request_script_with_pow(validator, other_payout.public_key, mutated_pop, parsed.admission_pow_epoch,
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
  auto tx = build_unbond_tx(finalis::test::test_chain_domain(), bond_op, kp.public_key, BOND_AMOUNT, 1000, kp.private_key, &err);
  ASSERT_TRUE(tx.has_value());

  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .validators = &vr,
      .current_height = WARMUP_BLOCKS + 5,
      .is_committee_member = {},
  });
  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(r.ok);
}

// A genesis validator's bond outpoint is (zero_hash, 0) on every network, so only the chain domain
// in the signature keeps an unbond signed on one chain (testnet) from being valid on another.
TEST(test_unbond_and_spend_signed_for_one_chain_are_invalid_on_another) {
  const auto kp = key_from_byte(10);
  const OutPoint bond_op{zero_hash(), 0};
  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};
  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 1);
  vr.advance_height(WARMUP_BLOCKS + 2);

  ChainId other_chain = finalis::test::test_chain_id();
  other_chain.genesis_hash_hex = std::string(64, 'b');
  const auto other_domain = consensus_chain_domain(finalis::test::test_network(), other_chain);
  ASSERT_TRUE(other_domain != finalis::test::test_chain_domain());

  const auto ctx = finalis::test::with_test_chain_identity(
      SpecialValidationContext{.validators = &vr, .current_height = WARMUP_BLOCKS + 5});
  std::string err;
  const auto here = build_unbond_tx(finalis::test::test_chain_domain(), bond_op, kp.public_key, BOND_AMOUNT, 1000,
                                    kp.private_key, &err);
  const auto elsewhere = build_unbond_tx(other_domain, bond_op, kp.public_key, BOND_AMOUNT, 1000, kp.private_key, &err);
  ASSERT_TRUE(here.has_value() && elsewhere.has_value());
  ASSERT_TRUE(validate_tx(*here, 1, view, &ctx).ok);
  ASSERT_EQ(validate_tx(*elsewhere, 1, view, &ctx).error, std::string("unbond signature invalid"));

  // Plain spends: same rule; and no chain identity at all fails closed.
  const OutPoint coin_op{Hash32{0x77}, 0};
  const TxOut coin{50'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end())))};
  UtxoSet coins;
  coins.emplace(coin_op, UtxoEntry{coin});
  const std::vector<TxOut> outs{TxOut{49'000, coin.script_pubkey}};
  const auto spend_elsewhere = build_signed_p2pkh_tx_single_input(other_domain, coin_op, coin, kp.private_key, outs);
  const auto spend_here =
      build_signed_p2pkh_tx_single_input(finalis::test::test_chain_domain(), coin_op, coin, kp.private_key, outs);
  ASSERT_TRUE(spend_here.has_value() && spend_elsewhere.has_value());
  ASSERT_TRUE(validate_tx(*spend_here, 1, coins, finalis::test::test_validation_ctx()).ok);
  ASSERT_EQ(validate_tx(*spend_elsewhere, 1, coins, finalis::test::test_validation_ctx()).error,
            std::string("signature invalid"));
  ASSERT_EQ(validate_tx(*spend_here, 1, coins, nullptr).error, std::string("tx validation requires chain identity"));
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

  auto msg = signing_message_for_input(finalis::test::test_chain_domain(), tx, 0);
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
  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .validators = &vr,
      .current_height = 1,
  });
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

  auto msg = signing_message_for_input(finalis::test::test_chain_domain(), tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), kp.public_key.begin(), kp.public_key.end());
  tx.inputs[0].script_sig = ss;

  SpecialValidationContext early = finalis::test::with_test_chain_identity(SpecialValidationContext{.validators = &vr, .current_height = 50 + UNBOND_DELAY_BLOCKS - 1});
  auto r1 = validate_tx(tx, 1, view, &early);
  ASSERT_TRUE(!r1.ok);

  SpecialValidationContext late = finalis::test::with_test_chain_identity(SpecialValidationContext{.validators = &vr, .current_height = 50 + UNBOND_DELAY_BLOCKS});
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

  auto msg = signing_message_for_input(finalis::test::test_chain_domain(), tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), kp.public_key.begin(), kp.public_key.end());
  tx.inputs[0].script_sig = ss;

  SpecialValidationContext post_fork = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .validators = &vr,
      // CLEANSLATE: Validator economics are active at genesis.
      .current_height = UNBOND_DELAY_BLOCKS + 50,
  });
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
  auto tx = build_unbond_tx(finalis::test::test_chain_domain(), bond_op, kp.public_key, BOND_AMOUNT, 1000, kp.private_key, &err);
  ASSERT_TRUE(tx.has_value());

  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .validators = &vr,
      .current_height = 20,
      .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
      .is_committee_member = {},
  });
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
  auto siga = crypto::ed25519_sign(vote_signing_message(slash_test_domain(), a.height, a.round, a.block_id), kp.private_key);
  ASSERT_TRUE(siga.has_value());
  a.signature = *siga;

  Vote b = a;
  b.block_id.fill(0x22);
  auto sigb = crypto::ed25519_sign(vote_signing_message(slash_test_domain(), b.height, b.round, b.block_id), kp.private_key);
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
  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .network = &mainnet_network(),
      .chain_id = &slash_test_chain_id(),
      .validators = &vr,
      .current_height = 200,
      .is_committee_member = [](const PubKey32&, std::uint64_t, std::uint32_t) { return true; },
  });

  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(r.ok);
}

// A key reused on another network signs there under that network's chain domain. Two such votes are
// not equivocation evidence here, and here-domain evidence needs the chain identity to check.
TEST(test_slash_evidence_from_another_chain_is_rejected) {
  const auto kp = key_from_byte(17);
  OutPoint bond_op{};
  bond_op.txid.fill(0xC4);
  bond_op.index = 0;
  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  ChainId other = slash_test_chain_id();
  other.genesis_hash_hex = "2222222222222222222222222222222222222222222222222222222222222222";
  const Hash32 other_domain = consensus_chain_domain(mainnet_network(), other);
  ASSERT_TRUE(other_domain != slash_test_domain());
  ASSERT_TRUE(consensus_chain_domain(testnet_network(), slash_test_chain_id()) != slash_test_domain());

  auto signed_vote = [&](const Hash32& domain, std::uint8_t id_byte) {
    Vote v;
    v.height = 500;
    v.round = 1;
    v.block_id.fill(id_byte);
    v.validator_pubkey = kp.public_key;
    v.signature = *crypto::ed25519_sign(vote_signing_message(domain, v.height, v.round, v.block_id), kp.private_key);
    return v;
  };

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 10);
  vr.advance_height(600);
  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .network = &mainnet_network(),
      .chain_id = &slash_test_chain_id(),
      .validators = &vr,
      .current_height = 600,
      .is_committee_member = [](const PubKey32&, std::uint64_t, std::uint32_t) { return true; },
  });

  auto foreign = build_slash_tx(bond_op, BOND_AMOUNT, signed_vote(other_domain, 0x51), signed_vote(other_domain, 0x52), 0);
  ASSERT_TRUE(foreign.has_value());
  ASSERT_TRUE(!validate_tx(*foreign, 1, view, &ctx).ok);
  auto mixed = build_slash_tx(bond_op, BOND_AMOUNT, signed_vote(slash_test_domain(), 0x51),
                              signed_vote(other_domain, 0x52), 0);
  ASSERT_TRUE(mixed.has_value());
  ASSERT_TRUE(!validate_tx(*mixed, 1, view, &ctx).ok);

  auto local = build_slash_tx(bond_op, BOND_AMOUNT, signed_vote(slash_test_domain(), 0x51),
                              signed_vote(slash_test_domain(), 0x52), 0);
  ASSERT_TRUE(local.has_value());
  ASSERT_TRUE(validate_tx(*local, 1, view, &ctx).ok);
  SpecialValidationContext no_identity = ctx;
  no_identity.chain_id = nullptr;
  ASSERT_TRUE(!validate_tx(*local, 1, view, &no_identity).ok);
}

// Prevote equivocation is slashable with prevote-domain evidence; the declared kind must match the
// signatures' domain in both directions.
TEST(test_prevote_slash_evidence_validation) {
  const auto kp = key_from_byte(16);
  OutPoint bond_op{};
  bond_op.txid.fill(0xC3);
  bond_op.index = 0;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  auto signed_pair = [&](bool prevote) {
    auto sign = [&](const Vote& v) {
      const auto msg = prevote ? prevote_signing_message(slash_test_domain(), v.height, v.round, v.block_id)
                               : vote_signing_message(slash_test_domain(), v.height, v.round, v.block_id);
      return *crypto::ed25519_sign(msg, kp.private_key);
    };
    Vote a;
    a.height = 300;
    a.round = 4;
    a.block_id.fill(0x41);
    a.validator_pubkey = kp.public_key;
    a.signature = sign(a);
    Vote b = a;
    b.block_id.fill(0x42);
    b.signature = sign(b);
    return std::make_pair(a, b);
  };

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 10);
  vr.advance_height(400);
  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .network = &mainnet_network(),
      .chain_id = &slash_test_chain_id(),
      .validators = &vr,
      .current_height = 400,
      .is_committee_member = [](const PubKey32&, std::uint64_t, std::uint32_t) { return true; },
  });

  const auto [pa, pb] = signed_pair(true);
  auto tx = build_slash_tx(bond_op, BOND_AMOUNT, pa, pb, 0, nullptr, SlashVoteKind::Prevote);
  ASSERT_TRUE(tx.has_value());
  SlashEvidence e;
  ASSERT_TRUE(parse_slash_script_sig(tx->inputs[0].script_sig, &e));
  ASSERT_TRUE(e.kind == SlashVoteKind::Prevote);
  ASSERT_TRUE(validate_tx(*tx, 1, view, &ctx).ok);

  // Prevote signatures declared as precommits, and precommit signatures declared as prevotes.
  auto wrong = build_slash_tx(bond_op, BOND_AMOUNT, pa, pb, 0, nullptr, SlashVoteKind::Precommit);
  ASSERT_TRUE(wrong.has_value());
  ASSERT_TRUE(!validate_tx(*wrong, 1, view, &ctx).ok);
  const auto [ca, cb] = signed_pair(false);
  wrong = build_slash_tx(bond_op, BOND_AMOUNT, ca, cb, 0, nullptr, SlashVoteKind::Prevote);
  ASSERT_TRUE(wrong.has_value());
  ASSERT_TRUE(!validate_tx(*wrong, 1, view, &ctx).ok);

  // Unknown kind byte: not parsed as slash evidence.
  Bytes script_sig = tx->inputs[0].script_sig;
  script_sig[script_sig.size() - 1 - 2 * (8 + 4 + 32 + 32 + 64)] = 2;  // kind byte precedes the two votes
  ASSERT_TRUE(!parse_slash_script_sig(script_sig, nullptr));
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
  auto siga = crypto::ed25519_sign(vote_signing_message(slash_test_domain(), a.height, a.round, a.block_id), kp.private_key);
  ASSERT_TRUE(siga.has_value());
  a.signature = *siga;

  Vote b = a;
  b.block_id.fill(0x32);
  auto sigb = crypto::ed25519_sign(vote_signing_message(slash_test_domain(), b.height, b.round, b.block_id), kp.private_key);
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

  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .network = &mainnet_network(),
      .chain_id = &slash_test_chain_id(),
      .validators = &vr,
      .current_height = 200,
      .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
      .is_committee_member = [](const PubKey32&, std::uint64_t, std::uint32_t) { return true; },
  });
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

  auto msg = signing_message_for_input(finalis::test::test_chain_domain(), tx, 0);
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
  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .validators = &vr,
      .current_height = 10,
      .is_committee_member = {},
  });

  auto r = validate_tx(tx, 1, view, &ctx);
  ASSERT_TRUE(!r.ok);
}

// --- Validator BLS keys (time signatures) ---

TEST(test_validator_bls_key_is_derived_from_the_ed25519_seed_and_proven) {
  const auto a = key_from_byte(0x71);
  const auto b = key_from_byte(0x72);
  const auto ra = test::test_bls_registration(a);
  ASSERT_TRUE(test::test_bls_registration(a).pubkey == ra.pubkey);  // deterministic
  ASSERT_TRUE(test::test_bls_registration(b).pubkey != ra.pubkey);
  ASSERT_TRUE(crypto::bls_pop_verify(ra.pubkey, ra.pop));
  ASSERT_TRUE(!crypto::bls_pop_verify(test::test_bls_registration(b).pubkey, ra.pop));
  ASSERT_TRUE(!validator_bls_registration(Bytes(31, 1)).has_value());
  // The BLS key is not the Ed25519 key reused: its secret differs from the seed.
  const auto sk = crypto::bls_key_from_validator_seed(a.private_key);
  ASSERT_TRUE(sk.has_value());
  ASSERT_TRUE(!std::equal(sk->bytes.begin(), sk->bytes.end(), a.private_key.begin()));
}

TEST(test_registration_scripts_carry_the_bls_key_and_reject_the_old_layout) {
  const auto v = key_from_byte(0x73);
  const auto payout = key_from_byte(0x74);
  const auto pop = *crypto::ed25519_sign(
      validator_join_request_pop_message(v.public_key, payout.public_key, test::test_bls_pubkey(v)), v.private_key);
  for (const bool pow : {false, true}) {
    const Bytes s = pow ? join_request_script_with_pow(v, payout.public_key, pop, 5, 6) : join_request_script(v, payout.public_key, pop);
    ASSERT_EQ(s.size(), pow ? kValidatorRegistrationScriptPowBytes : kValidatorRegistrationScriptBytes);
    ValidatorJoinRequestScriptData d{};
    ASSERT_TRUE(parse_validator_join_request_script(s, &d));
    ASSERT_TRUE(d.bls_pubkey == test::test_bls_pubkey(v));
    ASSERT_TRUE(d.bls_pop == test::test_bls_registration(v).pop);
    ASSERT_EQ(d.has_admission_pow, pow);
    ASSERT_TRUE(encode_validator_join_request_script(d) == s);
    OnboardingRegistrationScriptData o{};
    ASSERT_TRUE(!parse_onboarding_registration_script(s, &o));  // prefixes are not interchangeable
  }
  // The pre-BLS layout (136 / 152 bytes) no longer parses.
  Bytes old{'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  old.resize(136, 0);
  ASSERT_TRUE(!parse_validator_join_request_script(old));
  old.resize(152, 0);
  ASSERT_TRUE(!parse_validator_join_request_script(old));
  ASSERT_TRUE(!is_supported_base_layer_output_script(old));
}

// The Ed25519 proof binds the BLS key, the BLS proof shows possession, and a key belongs to one
// validator only.
TEST(test_sconbreg_rejects_foreign_unproven_or_taken_bls_key) {
  const auto sponsor = key_from_byte(0x75);
  const auto validator = key_from_byte(0x76);
  const auto other = key_from_byte(0x77);
  const auto payout = key_from_byte(0x78);
  const OutPoint spend_op{Hash32{0x75}, 0};
  const TxOut prev_out{
      1'000'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(sponsor.public_key.begin(), sponsor.public_key.end())))};
  UtxoSet utxos;
  utxos.emplace(spend_op, UtxoEntry{prev_out});
  const auto mine = test::test_bls_registration(validator);
  const auto theirs = test::test_bls_registration(other);
  auto validate_with = [&](const crypto::BlsPublicKey& bls_pk, const crypto::BlsSignature& bls_pop, const crypto::BlsPublicKey& signed_pk,
                           const SpecialValidationContext* ctx) {
    OnboardingRegistrationScriptData d{};
    d.validator_pubkey = validator.public_key;
    d.payout_pubkey = payout.public_key;
    d.pop = *crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key, signed_pk),
                                  validator.private_key);
    d.bls_pubkey = bls_pk;
    d.bls_pop = bls_pop;
    std::vector<TxOut> outputs{TxOut{0, encode_onboarding_registration_script(d)},
                               TxOut{prev_out.value - 1000, prev_out.script_pubkey}};
    auto tx = build_signed_p2pkh_tx_single_input(finalis::test::test_chain_domain(), spend_op, prev_out, sponsor.private_key, outputs);
    ASSERT_TRUE(tx.has_value());
    return validate_tx(*tx, 1, utxos, ctx ? ctx : finalis::test::test_validation_ctx());
  };
  ASSERT_TRUE(validate_with(mine.pubkey, mine.pop, mine.pubkey, nullptr).ok);
  // Someone else's key under this validator's Ed25519 proof of the original key.
  auto r = validate_with(theirs.pubkey, theirs.pop, mine.pubkey, nullptr);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, std::string("onboarding registration proof invalid"));
  // The validator vouches for a key it cannot prove possession of.
  r = validate_with(theirs.pubkey, mine.pop, theirs.pubkey, nullptr);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, std::string("onboarding registration bls proof invalid"));
  // A key already registered to another validator.
  consensus::ValidatorRegistry vr;
  std::string err;
  ASSERT_TRUE(vr.register_onboarding(other.public_key, 3, &err, std::nullopt, mine.pubkey));
  SpecialValidationContext ctx = finalis::test::with_test_chain_identity(SpecialValidationContext{
      .validators = &vr,
      .current_height = 4,
  });
  r = validate_with(mine.pubkey, mine.pop, mine.pubkey, &ctx);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, std::string("bls key already registered"));
}

TEST(test_registry_binds_a_bls_key_to_one_validator) {
  const auto a = key_from_byte(0x79);
  const auto b = key_from_byte(0x7a);
  const auto ka = test::test_bls_pubkey(a);
  const auto kb = test::test_bls_pubkey(b);
  consensus::ValidatorRegistry vr;
  std::string err;
  ASSERT_TRUE(vr.register_onboarding(a.public_key, 1, &err, std::nullopt, ka));
  ASSERT_TRUE(vr.bls_key_owner(ka) == a.public_key);
  ASSERT_TRUE(!vr.bls_key_owner(kb).has_value());
  // Bonding after onboarding must name the same key; with it, the key is kept.
  err.clear();
  ASSERT_TRUE(!vr.register_bond(a.public_key, OutPoint{Hash32{0x79}, 0}, 2, BOND_AMOUNT, &err, std::nullopt, kb));
  ASSERT_EQ(err, std::string("bls key mismatch"));
  ASSERT_TRUE(vr.register_bond(a.public_key, OutPoint{Hash32{0x79}, 0}, 2, BOND_AMOUNT, &err, std::nullopt, ka));
  ASSERT_TRUE(vr.get(a.public_key)->bls_pubkey == ka);
  // Another validator cannot take it.
  ASSERT_TRUE(!vr.register_bond(b.public_key, OutPoint{Hash32{0x7a}, 0}, 2, BOND_AMOUNT, &err, std::nullopt, ka));
  ASSERT_EQ(err, std::string("bls key already registered"));
  ASSERT_TRUE(vr.register_bond(b.public_key, OutPoint{Hash32{0x7a}, 0}, 2, BOND_AMOUNT, &err, std::nullopt, kb));
}
