#include "utxo/validate.hpp"

#include <algorithm>
#include <set>
#include <type_traits>

#include "codec/bytes.hpp"
#include "common/chain_id.hpp"
#include "consensus/monetary.hpp"
#include "consensus/randomness.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "address/address.hpp"
#include "privacy/mint_scripts.hpp"

namespace finalis {

namespace {

std::optional<Vote> read_vote_fixed(codec::ByteReader& r) {
  Vote v;
  auto h = r.u64le();
  auto round = r.u32le();
  auto bid = r.bytes_fixed<32>();
  auto pub = r.bytes_fixed<32>();
  auto sig = r.bytes_fixed<64>();
  if (!h || !round || !bid || !pub || !sig) return std::nullopt;
  v.height = *h;
  v.round = *round;
  v.frontier_transition_id = *bid;
  v.validator_pubkey = *pub;
  v.signature = *sig;
  return v;
}

Bytes chain_id_bytes(const ChainId& chain_id) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'C', 'H', 'A', 'I', 'N', '_', 'I', 'D', '_', 'V', '1'});
  w.varbytes(Bytes(chain_id.network_name.begin(), chain_id.network_name.end()));
  w.u32le(chain_id.magic);
  w.varbytes(Bytes(chain_id.network_id_hex.begin(), chain_id.network_id_hex.end()));
  w.u32le(chain_id.protocol_version);
  w.varbytes(Bytes(chain_id.genesis_hash_hex.begin(), chain_id.genesis_hash_hex.end()));
  return w.take();
}

std::vector<OutPoint> tx_input_outpoints(const Tx& tx) {
  std::vector<OutPoint> out;
  out.reserve(tx.inputs.size());
  for (const auto& in : tx.inputs) out.push_back(OutPoint{in.prev_txid, in.prev_index});
  return out;
}

std::vector<OutPoint> txv2_input_outpoints(const TxV2& tx) {
  std::vector<OutPoint> out;
  out.reserve(tx.inputs.size());
  for (const auto& in : tx.inputs) out.push_back(OutPoint{in.prev_txid, in.prev_index});
  return out;
}

UtxoSet legacy_transparent_view(const UtxoSetV2& utxos) {
  UtxoSet out;
  for (const auto& [op, entry] : utxos) {
    if (entry.kind != UtxoOutputKind::Transparent) continue;
    out.emplace(op, UtxoEntry{std::get<UtxoTransparentData>(entry.body).out});
  }
  return out;
}

bool consume_verify_budget(std::size_t* remaining, std::size_t cost, std::string* err) {
  if (!remaining) return true;
  if (*remaining < cost) {
    if (err) *err = "tx verify budget exceeded";
    return false;
  }
  *remaining -= cost;
  return true;
}

}  // namespace

UtxoSetV2 upgrade_utxo_set_v2(const UtxoSet& utxos) {
  UtxoSetV2 out;
  for (const auto& [op, entry] : utxos) {
    out.emplace(op, UtxoEntryV2{entry.out});
  }
  return out;
}

bool is_p2pkh_script_pubkey(const Bytes& script_pubkey, std::array<std::uint8_t, 20>* out_hash) {
  if (script_pubkey.size() != 25) return false;
  if (script_pubkey[0] != 0x76 || script_pubkey[1] != 0xA9 || script_pubkey[2] != 0x14 ||
      script_pubkey[23] != 0x88 || script_pubkey[24] != 0xAC) {
    return false;
  }
  if (out_hash) {
    std::copy(script_pubkey.begin() + 3, script_pubkey.begin() + 23, out_hash->begin());
  }
  return true;
}

bool is_p2pkh_script_sig(const Bytes& script_sig, Sig64* out_sig, PubKey32* out_pub) {
  if (script_sig.size() != 98) return false;
  if (script_sig[0] != 0x40 || script_sig[65] != 0x20) return false;
  if (out_sig) std::copy(script_sig.begin() + 1, script_sig.begin() + 65, out_sig->begin());
  if (out_pub) std::copy(script_sig.begin() + 66, script_sig.end(), out_pub->begin());
  return true;
}

bool is_supported_base_layer_output_script(const Bytes& script_pubkey) {
  return is_p2pkh_script_pubkey(script_pubkey, nullptr) || is_validator_register_script(script_pubkey, nullptr) ||
         is_validator_unbond_script(script_pubkey, nullptr) ||
         is_onboarding_registration_script(script_pubkey, nullptr, nullptr, nullptr) ||
         is_validator_join_request_script(script_pubkey, nullptr, nullptr, nullptr) ||
         is_burn_script(script_pubkey, nullptr) || privacy::is_mint_deposit_script(script_pubkey, nullptr, nullptr);
}

std::optional<Bytes> signing_message_for_input(const Tx& tx, std::uint32_t input_index) {
  if (input_index >= tx.inputs.size()) return std::nullopt;
  Tx signing = tx;
  for (auto& in : signing.inputs) {
    in.script_sig.clear();
  }
  const Hash32 txh = crypto::sha256d(signing.serialize_without_hashcash());

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'I', 'G', '-', 'V', '0'});
  w.u32le(input_index);
  w.bytes_fixed(txh);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

std::optional<Bytes> unbond_message_for_input(const Tx& tx, std::uint32_t input_index) {
  if (input_index >= tx.inputs.size()) return std::nullopt;
  Tx signing = tx;
  for (auto& in : signing.inputs) {
    in.script_sig.clear();
  }
  const Hash32 txh = crypto::sha256d(signing.serialize_without_hashcash());

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'U', 'N', 'B', 'O', 'N', 'D', '-', 'V', '0'});
  w.bytes_fixed(txh);
  w.u32le(input_index);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

std::optional<Bytes> signing_message_for_input_v2(const TxV2& tx, std::uint32_t input_index) {
  if (input_index >= tx.inputs.size()) return std::nullopt;
  TxV2 signing = tx;
  for (auto& in : signing.inputs) {
    if (in.kind == TxInputKind::Transparent) {
      std::get<TransparentInputWitnessV2>(in.witness).script_sig.clear();
    } else {
      std::get<ConfidentialInputWitnessV2>(in.witness).spend_sig.fill(0);
    }
  }
  const Hash32 txh = crypto::sha256d(signing.serialize());
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'I', 'G', '-', 'V', '2'});
  w.u32le(input_index);
  w.bytes_fixed(txh);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

std::optional<Hash32> balance_proof_message_v2(const TxV2& tx) {
  TxV2 signing = tx;
  for (auto& in : signing.inputs) {
    if (in.kind == TxInputKind::Transparent) {
      std::get<TransparentInputWitnessV2>(in.witness).script_sig.clear();
    } else {
      std::get<ConfidentialInputWitnessV2>(in.witness).spend_sig.fill(0);
    }
  }
  signing.balance_proof.excess_sig.fill(0);
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'B', 'A', 'L', '-', 'V', '2'});
  w.bytes(signing.serialize());
  return crypto::sha256d(w.data());
}

Bytes onboarding_registration_pop_message(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'O', 'N', 'B', 'O', 'A', 'R', 'D', '-', 'V', '1'});
  w.bytes_fixed(validator_pubkey);
  w.bytes_fixed(payout_pubkey);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

Bytes validator_join_request_pop_message(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'A', 'L', 'J', 'O', 'I', 'N', 'R', 'E', 'Q', '-', 'V', '1'});
  w.bytes_fixed(validator_pubkey);
  w.bytes_fixed(payout_pubkey);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

Hash32 admission_pow_chain_id_hash(const ChainId& chain_id) {
  return crypto::sha256d(chain_id_bytes(chain_id));
}

Hash32 onboarding_registration_commitment(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'O', 'N', 'B', 'O', 'A', 'R', 'D', '_', 'C', 'O', 'M', 'M',
                'I', 'T', '_', 'V', '1'});
  w.bytes_fixed(validator_pubkey);
  w.bytes_fixed(payout_pubkey);
  return crypto::sha256d(w.data());
}

Hash32 join_request_input_commitment(const std::vector<OutPoint>& inputs) {
  codec::ByteWriter w;
  w.bytes(
      Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'J', 'O', 'I', 'N', '_', 'I', 'N', 'P', 'U', 'T', 'S', '_', 'V', '1'});
  w.varint(inputs.size());
  for (const auto& input : inputs) {
    w.bytes_fixed(input.txid);
    w.u32le(input.index);
  }
  return crypto::sha256d(w.data());
}

Hash32 bond_commitment_for_join_request(const PubKey32& operator_id, const PubKey32& payout_pubkey,
                                        std::uint64_t bond_amount, const std::vector<OutPoint>& inputs) {
  codec::ByteWriter w;
  w.bytes(
      Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'B', 'O', 'N', 'D', '_', 'C', 'O', 'M', 'M', 'I', 'T', '_', 'V', '1'});
  w.bytes_fixed(operator_id);
  w.bytes_fixed(payout_pubkey);
  w.u64le(bond_amount);
  w.bytes_fixed(join_request_input_commitment(inputs));
  return crypto::sha256d(w.data());
}

std::uint64_t admission_pow_epoch_for_height(std::uint64_t height, std::uint64_t epoch_blocks) {
  return consensus::committee_epoch_start(height, epoch_blocks);
}

std::optional<Hash32> admission_pow_epoch_anchor_hash(
    std::uint64_t admission_pow_epoch, std::uint64_t epoch_blocks,
    const std::function<std::optional<Hash32>(std::uint64_t)>& finalized_hash_at_height) {
  if (admission_pow_epoch == 0 || epoch_blocks == 0) return std::nullopt;
  if (consensus::committee_epoch_start(admission_pow_epoch, epoch_blocks) != admission_pow_epoch) return std::nullopt;
  if (admission_pow_epoch <= 1) return zero_hash();
  if (!finalized_hash_at_height) return std::nullopt;
  return finalized_hash_at_height(admission_pow_epoch - 1);
}

Hash32 admission_pow_challenge(const Hash32& chain_id_hash, std::uint64_t admission_pow_epoch,
                               const Hash32& finalized_epoch_anchor_hash, const PubKey32& operator_id,
                               const Hash32& bond_commitment) {
  codec::ByteWriter w;
  w.bytes(
      Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'A', 'D', 'M', 'I', 'S', 'S', 'I', 'O', 'N', '_', 'P', 'O', 'W', '_',
            'V', '1'});
  w.bytes_fixed(chain_id_hash);
  w.u64le(admission_pow_epoch);
  w.bytes_fixed(finalized_epoch_anchor_hash);
  w.bytes_fixed(operator_id);
  w.bytes_fixed(bond_commitment);
  return crypto::sha256d(w.data());
}

Hash32 admission_pow_work_hash(const Hash32& challenge, std::uint64_t nonce) {
  codec::ByteWriter w;
  w.bytes_fixed(challenge);
  w.u64le(nonce);
  return crypto::sha256d(w.data());
}

std::uint32_t leading_zero_bits(const Hash32& hash) {
  std::uint32_t count = 0;
  for (std::uint8_t b : hash) {
    if (b == 0) {
      count += 8;
      continue;
    }
    for (int bit = 7; bit >= 0; --bit) {
      if (((b >> bit) & 1U) == 0U) {
        ++count;
      } else {
        return count;
      }
    }
  }
  return count;
}

bool validate_admission_pow(const ValidatorJoinRequestScriptData& req, const std::vector<OutPoint>& inputs,
                            std::uint64_t bond_amount, const SpecialValidationContext& ctx, std::string* err) {
  // Admission PoW is join-admission friction only. It must not influence
  // committee weight, proposer schedule, finality, or reward weighting.
  if (!ctx.network || !validator_join_admission_pow_enabled(*ctx.network)) return true;
  if (!ctx.chain_id) {
    if (err) *err = "missing chain id context for admission pow";
    return false;
  }
  if (!req.has_admission_pow) {
    if (err) *err = "missing admission pow";
    return false;
  }
  const auto current_epoch = admission_pow_epoch_for_height(ctx.current_height, ctx.network->committee_epoch_blocks);
  const auto previous_epoch =
      current_epoch > ctx.network->committee_epoch_blocks ? current_epoch - ctx.network->committee_epoch_blocks : 0;
  if (req.admission_pow_epoch != current_epoch && req.admission_pow_epoch != previous_epoch) {
    if (err) *err = "admission pow epoch expired";
    return false;
  }
  const auto anchor = admission_pow_epoch_anchor_hash(req.admission_pow_epoch, ctx.network->committee_epoch_blocks,
                                                      ctx.finalized_hash_at_height);
  if (!anchor.has_value()) {
    if (err) *err = "missing finalized epoch anchor for admission pow";
    return false;
  }
  const auto operator_id = consensus::canonical_operator_id_from_join_request(req.payout_pubkey);
  const auto bond_commitment = bond_commitment_for_join_request(operator_id, req.payout_pubkey, bond_amount, inputs);
  const auto challenge =
      admission_pow_challenge(admission_pow_chain_id_hash(*ctx.chain_id), req.admission_pow_epoch, *anchor, operator_id,
                              bond_commitment);
  const auto work_hash = admission_pow_work_hash(challenge, req.admission_pow_nonce);
  if (leading_zero_bits(work_hash) < ctx.network->validator_join_admission_pow_difficulty_bits) {
    if (err) *err = "admission pow difficulty not met";
    return false;
  }
  return true;
}

bool validate_onboarding_admission_pow(const OnboardingRegistrationScriptData& req, const SpecialValidationContext& ctx,
                                       std::string* err) {
  if (!ctx.network || !onboarding_admission_pow_enabled(*ctx.network)) return true;
  if (!ctx.chain_id) {
    if (err) *err = "missing chain id context for admission pow";
    return false;
  }
  if (!req.has_admission_pow) {
    if (err) *err = "missing onboarding admission pow";
    return false;
  }
  const auto current_epoch = admission_pow_epoch_for_height(ctx.current_height, ctx.network->committee_epoch_blocks);
  const auto previous_epoch =
      current_epoch > ctx.network->committee_epoch_blocks ? current_epoch - ctx.network->committee_epoch_blocks : 0;
  if (req.admission_pow_epoch != current_epoch && req.admission_pow_epoch != previous_epoch) {
    if (err) *err = "onboarding admission pow epoch expired";
    return false;
  }
  const auto anchor = admission_pow_epoch_anchor_hash(req.admission_pow_epoch, ctx.network->committee_epoch_blocks,
                                                      ctx.finalized_hash_at_height);
  if (!anchor.has_value()) {
    if (err) *err = "missing finalized epoch anchor for onboarding admission pow";
    return false;
  }
  const auto challenge =
      admission_pow_challenge(admission_pow_chain_id_hash(*ctx.chain_id), req.admission_pow_epoch, *anchor,
                              req.validator_pubkey, onboarding_registration_commitment(req.validator_pubkey, req.payout_pubkey));
  const auto work_hash = admission_pow_work_hash(challenge, req.admission_pow_nonce);
  if (leading_zero_bits(work_hash) < ctx.network->onboarding_admission_pow_difficulty_bits) {
    if (err) *err = "onboarding admission pow difficulty not met";
    return false;
  }
  return true;
}

Bytes vote_signing_message(std::uint64_t height, std::uint32_t round, const Hash32& transition_id) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'O', 'T', 'E', '-', 'V', '1'});
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(transition_id);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

Bytes timeout_vote_signing_message(std::uint64_t height, std::uint32_t round) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'T', 'I', 'M', 'E', 'O', 'U', 'T', '-', 'V', '1'});
  w.u64le(height);
  w.u32le(round);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

bool parse_slash_script_sig(const Bytes& script_sig, SlashEvidence* out) {
  static const Bytes marker{'S', 'C', 'S', 'L', 'A', 'S', 'H'};
  if (script_sig.size() < marker.size()) return false;
  if (!std::equal(marker.begin(), marker.end(), script_sig.begin())) return false;

  Bytes tail(script_sig.begin() + static_cast<long>(marker.size()), script_sig.end());
  Bytes blob;
  if (!codec::parse_exact(tail, [&](codec::ByteReader& r) {
        auto b = r.varbytes();
        if (!b) return false;
        blob = *b;
        return true;
      })) {
    return false;
  }

  Vote a;
  Vote b;
  if (!codec::parse_exact(blob, [&](codec::ByteReader& r) {
        auto v1 = read_vote_fixed(r);
        auto v2 = read_vote_fixed(r);
        if (!v1 || !v2) return false;
        a = *v1;
        b = *v2;
        return true;
      })) {
    return false;
  }

  if (out) {
    out->a = a;
    out->b = b;
    out->raw_blob = blob;
  }
  return true;
}

TxValidationResult validate_tx(const Tx& tx, size_t tx_index_in_block, const UtxoSet& utxos,
                               const SpecialValidationContext* ctx) {
  if (tx.version != 1) return {false, "unsupported tx version", 0};
  if (tx.lock_time != 0) return {false, "lock_time must be 0 in v0", 0};
  if (tx.inputs.empty() || tx.outputs.empty()) return {false, "tx inputs/outputs empty", 0};
  if (tx.inputs.size() > kMaxTxInputs) return {false, "tx has too many inputs", 0};

  std::size_t verify_budget_remaining = kMaxTxEd25519Verifies;

  if (tx_index_in_block == 0) {
    if (tx.inputs.size() != 1) return {false, "coinbase must have one input", 0};
    const auto& in = tx.inputs[0];
    if (in.prev_txid != zero_hash()) return {false, "coinbase prev_txid invalid", 0};
    if (in.prev_index != 0xFFFFFFFF) return {false, "coinbase prev_index invalid", 0};
    if (in.sequence != 0xFFFFFFFF) return {false, "coinbase sequence invalid", 0};
    if (in.script_sig.size() > 100) return {false, "coinbase script_sig > 100", 0};
    return {true, "", 0};
  }

  for (const auto& out : tx.outputs) {
    if (!is_supported_base_layer_output_script(out.script_pubkey)) {
      return {false, "unsupported script_pubkey", 0};
    }
    OnboardingRegistrationScriptData onboarding_req{};
    if (parse_onboarding_registration_script(out.script_pubkey, &onboarding_req)) {
      if (out.value != 0) return {false, "SCONBREG output must have zero value", 0};
      std::string budget_error;
      if (!consume_verify_budget(&verify_budget_remaining, 1, &budget_error)) return {false, budget_error, 0};
      if (!crypto::ed25519_verify(
              onboarding_registration_pop_message(onboarding_req.validator_pubkey, onboarding_req.payout_pubkey),
              onboarding_req.pop, onboarding_req.validator_pubkey)) {
        return {false, "onboarding registration proof invalid", 0};
      }
      if (ctx && ctx->validators) {
        auto existing = ctx->validators->get(onboarding_req.validator_pubkey);
        if (existing.has_value()) {
          return {false,
                  existing->status == consensus::ValidatorStatus::BANNED ? "validator banned"
                                                                          : "validator already registered",
                  0};
        }
      }
      if (ctx && ctx->network && onboarding_admission_pow_enabled(*ctx->network) && !onboarding_req.has_admission_pow) {
        return {false, "missing onboarding admission pow", 0};
      }
    }
    PubKey32 pub{};
    if (is_validator_register_script(out.script_pubkey, &pub)) {
      (void)pub;
      if (ctx && ctx->enforce_variable_bond_range) {
        const std::uint64_t min_bond_amount = ctx->min_bond_amount;
        const std::uint64_t max_bond_amount = std::max<std::uint64_t>(ctx->max_bond_amount, min_bond_amount);
        if (out.value < min_bond_amount || out.value > max_bond_amount) {
          return {false, "SCVALREG output out of v7 bond range", 0};
        }
      } else if (out.value != BOND_AMOUNT) {
        return {false, "SCVALREG output must equal BOND_AMOUNT", 0};
      }
    }
    ValidatorJoinRequestScriptData join_req{};
    if (parse_validator_join_request_script(out.script_pubkey, &join_req)) {
      if (out.value != 0) return {false, "SCVALJRQ output must have zero value", 0};
      std::string budget_error;
      if (!consume_verify_budget(&verify_budget_remaining, 1, &budget_error)) return {false, budget_error, 0};
      if (!crypto::ed25519_verify(
              validator_join_request_pop_message(join_req.validator_pubkey, join_req.payout_pubkey), join_req.pop,
              join_req.validator_pubkey)) {
        return {false, "validator join request proof invalid", 0};
      }
      if (ctx && ctx->network && validator_join_admission_pow_enabled(*ctx->network) && !join_req.has_admission_pow) {
        return {false, "missing admission pow", 0};
      }
    }
  }

  std::set<PubKey32> reg_outputs;
  std::set<PubKey32> onboarding_outputs;
  std::set<PubKey32> join_req_outputs;
  for (const auto& out : tx.outputs) {
    PubKey32 pub{};
    if (is_validator_register_script(out.script_pubkey, &pub)) reg_outputs.insert(pub);
    if (is_onboarding_registration_script(out.script_pubkey, &pub, nullptr, nullptr)) onboarding_outputs.insert(pub);
    if (is_validator_join_request_script(out.script_pubkey, &pub, nullptr, nullptr)) join_req_outputs.insert(pub);
  }
  if (onboarding_outputs.size() > 1) return {false, "multiple SCONBREG outputs not allowed", 0};
  if (!onboarding_outputs.empty() && (!reg_outputs.empty() || !join_req_outputs.empty())) {
    return {false, "SCONBREG may not appear with validator join outputs", 0};
  }
  for (const auto& pub : join_req_outputs) {
    if (reg_outputs.find(pub) == reg_outputs.end()) return {false, "join request missing matching SCVALREG output", 0};
  }
  for (const auto& pub : reg_outputs) {
    if (join_req_outputs.find(pub) == join_req_outputs.end()) {
      return {false, "SCVALREG output missing matching SCVALJRQ output", 0};
    }
  }

  if (ctx && ctx->network && onboarding_admission_pow_enabled(*ctx->network)) {
    for (const auto& out : tx.outputs) {
      OnboardingRegistrationScriptData onboarding_req{};
      if (!parse_onboarding_registration_script(out.script_pubkey, &onboarding_req)) continue;
      std::string pow_error;
      if (!validate_onboarding_admission_pow(onboarding_req, *ctx, &pow_error)) {
        return {false, pow_error.empty() ? "onboarding admission pow invalid" : pow_error, 0};
      }
    }
  }
  if (ctx && ctx->network && validator_join_admission_pow_enabled(*ctx->network)) {
    const auto inputs = tx_input_outpoints(tx);
    for (const auto& out : tx.outputs) {
      ValidatorJoinRequestScriptData join_req{};
      if (!parse_validator_join_request_script(out.script_pubkey, &join_req)) continue;
      const auto bond_it = std::find_if(tx.outputs.begin(), tx.outputs.end(), [&](const TxOut& candidate) {
        PubKey32 reg_pub{};
        return is_validator_register_script(candidate.script_pubkey, &reg_pub) && reg_pub == join_req.validator_pubkey;
      });
      if (bond_it == tx.outputs.end()) return {false, "join request missing matching SCVALREG output", 0};
      std::string pow_error;
      if (!validate_admission_pow(join_req, inputs, bond_it->value, *ctx, &pow_error)) {
        return {false, pow_error.empty() ? "validator join request admission pow invalid" : pow_error, 0};
      }
    }
  }

  std::uint64_t in_sum = 0;
  std::uint64_t out_sum = 0;
  std::set<OutPoint> seen_inputs;
  for (const auto& out : tx.outputs) out_sum += out.value;

  for (std::uint32_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& in = tx.inputs[i];
    if (in.sequence != 0xFFFFFFFF) return {false, "sequence must be FFFFFFFF", 0};
    OutPoint op{in.prev_txid, in.prev_index};
    if (!seen_inputs.insert(op).second) return {false, "duplicate input outpoint", 0};
    auto it = utxos.find(op);
    if (it == utxos.end()) return {false, "missing utxo", 0};

    const TxOut& prev_out = it->second.out;

    std::array<std::uint8_t, 20> pkh{};
    if (is_p2pkh_script_pubkey(prev_out.script_pubkey, &pkh)) {
      Sig64 sig{};
      PubKey32 pub{};
      if (!is_p2pkh_script_sig(in.script_sig, &sig, &pub)) return {false, "bad script_sig", 0};
      const auto derived = crypto::h160(Bytes(pub.begin(), pub.end()));
      if (!std::equal(derived.begin(), derived.end(), pkh.begin())) {
        return {false, "pubkey hash mismatch", 0};
      }

      const auto msg = signing_message_for_input(tx, i);
      if (!msg.has_value()) return {false, "sighash failed", 0};
      std::string budget_error;
      if (!consume_verify_budget(&verify_budget_remaining, 1, &budget_error)) return {false, budget_error, 0};
      if (!crypto::ed25519_verify(*msg, sig, pub)) return {false, "signature invalid", 0};
      in_sum += prev_out.value;
      continue;
    }

    PubKey32 bond_pub{};
    if (is_validator_register_script(prev_out.script_pubkey, &bond_pub)) {
      if (!ctx || !ctx->validators) return {false, "bond spend requires validator context", 0};

      SlashEvidence evidence;
      if (parse_slash_script_sig(in.script_sig, &evidence)) {
        if (tx.outputs.size() != 1) return {false, "slash tx must have exactly one output", 0};
        Hash32 burn_hash{};
        if (!is_burn_script(tx.outputs[0].script_pubkey, &burn_hash)) return {false, "slash output must be SCBURN", 0};
        const Hash32 evh = crypto::sha256d(evidence.raw_blob);
        if (burn_hash != evh) return {false, "slash evidence hash mismatch", 0};

        if (evidence.a.height != evidence.b.height || evidence.a.round != evidence.b.round) {
          return {false, "invalid equivocation evidence height/round", 0};
        }
        if (evidence.a.frontier_transition_id == evidence.b.frontier_transition_id) {
          return {false, "invalid equivocation evidence transition_id", 0};
        }
        if (evidence.a.validator_pubkey != evidence.b.validator_pubkey) return {false, "evidence pubkey mismatch", 0};
        if (evidence.a.validator_pubkey != bond_pub) return {false, "evidence pubkey must match bond", 0};

        const auto a_msg =
            vote_signing_message(evidence.a.height, evidence.a.round, evidence.a.frontier_transition_id);
        const auto b_msg =
            vote_signing_message(evidence.b.height, evidence.b.round, evidence.b.frontier_transition_id);
        std::string budget_error;
        if (!consume_verify_budget(&verify_budget_remaining, 2, &budget_error)) return {false, budget_error, 0};
        if (!crypto::ed25519_verify(a_msg, evidence.a.signature, evidence.a.validator_pubkey)) {
          return {false, "invalid evidence signature a", 0};
        }
        if (!crypto::ed25519_verify(b_msg, evidence.b.signature, evidence.b.validator_pubkey)) {
          return {false, "invalid evidence signature b", 0};
        }
        if (!ctx->is_committee_member) return {false, "slash spend requires committee context", 0};
        if (!ctx->is_committee_member(evidence.a.validator_pubkey, evidence.a.height, evidence.a.round)) {
          return {false, "slash evidence validator not in committee", 0};
        }
      } else {
        // UNBOND path
        if (tx.outputs.size() != 1) return {false, "unbond tx must have exactly one output", 0};
        auto info = ctx->validators->get(bond_pub);
        if (!info.has_value()) return {false, "unknown validator for bond output", 0};
        if (info->status == consensus::ValidatorStatus::BANNED) {
          return {false, "banned validator bond must be slashed, not unbonded", 0};
        }
        PubKey32 out_pub{};
        if (!is_validator_unbond_script(tx.outputs[0].script_pubkey, &out_pub)) {
          return {false, "unbond tx must output SCVALUNB", 0};
        }
        if (out_pub != bond_pub) return {false, "unbond pubkey mismatch", 0};

        Sig64 sig{};
        PubKey32 pub{};
        if (!is_p2pkh_script_sig(in.script_sig, &sig, &pub)) return {false, "bad unbond auth script_sig", 0};
        if (pub != bond_pub) return {false, "unbond auth pubkey mismatch", 0};
        const auto msg = unbond_message_for_input(tx, i);
        if (!msg.has_value()) return {false, "unbond sighash failed", 0};
        std::string budget_error;
        if (!consume_verify_budget(&verify_budget_remaining, 1, &budget_error)) return {false, budget_error, 0};
        if (!crypto::ed25519_verify(*msg, sig, pub)) return {false, "unbond signature invalid", 0};
      }

      in_sum += prev_out.value;
      continue;
    }

    PubKey32 unbond_pub{};
    if (is_validator_unbond_script(prev_out.script_pubkey, &unbond_pub)) {
      if (!ctx || !ctx->validators) return {false, "unbond spend requires validator context", 0};
      auto info = ctx->validators->get(unbond_pub);
      if (!info.has_value()) return {false, "unknown validator for unbond output", 0};
      SlashEvidence evidence;
      if (parse_slash_script_sig(in.script_sig, &evidence)) {
        if (tx.outputs.size() != 1) return {false, "slash tx must have exactly one output", 0};
        Hash32 burn_hash{};
        if (!is_burn_script(tx.outputs[0].script_pubkey, &burn_hash)) return {false, "slash output must be SCBURN", 0};
        const Hash32 evh = crypto::sha256d(evidence.raw_blob);
        if (burn_hash != evh) return {false, "slash evidence hash mismatch", 0};
        if (evidence.a.height != evidence.b.height || evidence.a.round != evidence.b.round) {
          return {false, "invalid equivocation evidence height/round", 0};
        }
        if (evidence.a.frontier_transition_id == evidence.b.frontier_transition_id) {
          return {false, "invalid equivocation evidence transition_id", 0};
        }
        if (evidence.a.validator_pubkey != evidence.b.validator_pubkey) return {false, "evidence pubkey mismatch", 0};
        if (evidence.a.validator_pubkey != unbond_pub) return {false, "evidence pubkey must match unbond output", 0};
        const auto a_msg =
            vote_signing_message(evidence.a.height, evidence.a.round, evidence.a.frontier_transition_id);
        const auto b_msg =
            vote_signing_message(evidence.b.height, evidence.b.round, evidence.b.frontier_transition_id);
        std::string budget_error;
        if (!consume_verify_budget(&verify_budget_remaining, 2, &budget_error)) return {false, budget_error, 0};
        if (!crypto::ed25519_verify(a_msg, evidence.a.signature, evidence.a.validator_pubkey)) {
          return {false, "invalid evidence signature a", 0};
        }
        if (!crypto::ed25519_verify(b_msg, evidence.b.signature, evidence.b.validator_pubkey)) {
          return {false, "invalid evidence signature b", 0};
        }
        if (!ctx->is_committee_member) return {false, "slash spend requires committee context", 0};
        if (!ctx->is_committee_member(evidence.a.validator_pubkey, evidence.a.height, evidence.a.round)) {
          return {false, "slash evidence validator not in committee", 0};
        }
        in_sum += prev_out.value;
        continue;
      }
      if (!ctx->validators->can_withdraw_bond(unbond_pub, ctx->current_height, ctx->unbond_delay_blocks)) {
        return {false, "unbond delay not reached", 0};
      }

      Sig64 sig{};
      PubKey32 pub{};
      if (!is_p2pkh_script_sig(in.script_sig, &sig, &pub)) return {false, "bad unbond-spend script_sig", 0};
      if (pub != unbond_pub) return {false, "unbond-spend pubkey mismatch", 0};
      const auto msg = signing_message_for_input(tx, i);
      if (!msg.has_value()) return {false, "unbond-spend sighash failed", 0};
      std::string budget_error;
      if (!consume_verify_budget(&verify_budget_remaining, 1, &budget_error)) return {false, budget_error, 0};
      if (!crypto::ed25519_verify(*msg, sig, pub)) return {false, "unbond-spend signature invalid", 0};

      for (const auto& o : tx.outputs) {
        if (!is_p2pkh_script_pubkey(o.script_pubkey, nullptr)) {
          return {false, "unbond output spend must go to P2PKH", 0};
        }
      }

      in_sum += prev_out.value;
      continue;
    }

    return {false, "unsupported prev script_pubkey", 0};
  }

  if (in_sum < out_sum) return {false, "negative fee", 0};
  return {true, "", in_sum - out_sum};
}

BlockValidationResult validate_block_txs(const Block& block, const UtxoSet& base_utxos, std::uint64_t block_reward,
                                         const SpecialValidationContext* ctx,
                                         const ExpectedCoinbaseOutputsBuilder* expected_coinbase_outputs) {
  if (block.txs.empty()) return {false, "block has no tx", 0};
  UtxoSet work = base_utxos;

  std::uint64_t fees = 0;
  for (size_t i = 0; i < block.txs.size(); ++i) {
    auto r = validate_tx(block.txs[i], i, work, ctx);
    if (!r.ok) return {false, "tx invalid at index " + std::to_string(i) + ": " + r.error, 0};
    fees += r.fee;

    if (i > 0) {
      for (const auto& in : block.txs[i].inputs) {
        work.erase(OutPoint{in.prev_txid, in.prev_index});
      }
    }
    const Hash32 txid = block.txs[i].txid();
    for (std::uint32_t out_i = 0; out_i < block.txs[i].outputs.size(); ++out_i) {
      work[OutPoint{txid, out_i}] = UtxoEntry{block.txs[i].outputs[out_i]};
    }
  }

  (void)block_reward;
  std::uint64_t coinbase_sum = 0;
  for (const auto& out : block.txs[0].outputs) coinbase_sum += out.value;
  if (expected_coinbase_outputs) {
    const auto expected = (*expected_coinbase_outputs)(fees);
    std::uint64_t expected_sum = 0;
    for (const auto& out : expected) expected_sum += out.value;
    if (coinbase_sum != expected_sum) {
      return {false, "coinbase sum mismatch", 0};
    }
    if (block.txs[0].outputs.size() != expected.size()) return {false, "coinbase payout distribution mismatch", 0};
    for (std::size_t i = 0; i < expected.size(); ++i) {
      if (block.txs[0].outputs[i].value != expected[i].value ||
          block.txs[0].outputs[i].script_pubkey != expected[i].script_pubkey) {
        return {false, "coinbase payout distribution mismatch", 0};
      }
    }
  } else if (coinbase_sum != fees) {
    return {false, "coinbase sum mismatch", 0};
  }

  return {true, "", fees};
}

void apply_block_to_utxo(const Block& block, UtxoSet& utxos) {
  for (size_t i = 0; i < block.txs.size(); ++i) {
    if (i > 0) {
      for (const auto& in : block.txs[i].inputs) {
        utxos.erase(OutPoint{in.prev_txid, in.prev_index});
      }
    }
    const Hash32 txid = block.txs[i].txid();
    for (std::uint32_t out_i = 0; out_i < block.txs[i].outputs.size(); ++out_i) {
      utxos[OutPoint{txid, out_i}] = UtxoEntry{block.txs[i].outputs[out_i]};
    }
  }
}

AnyTxValidationResult validate_tx_v2(const TxV2& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                     const SpecialValidationContext* ctx) {
  AnyTxValidationResult out;
  out.cost.serialized_size = tx.serialize().size();

  if (!ctx || !ctx->confidential_policy) {
    out.error = "missing confidential policy context";
    return out;
  }
  const auto& policy = *ctx->confidential_policy;
  if (ctx->current_height < policy.activation_height) {
    out.error = "confidential tx not active";
    return out;
  }
  if (tx.version != static_cast<std::uint32_t>(TxVersionKind::CONFIDENTIAL_V2)) {
    out.error = "unsupported tx version";
    return out;
  }
  if (tx_index_in_block == 0) {
    out.error = "confidential coinbase not supported";
    return out;
  }
  if (tx.lock_time != 0) {
    out.error = "lock_time must be 0 in v2";
    return out;
  }
  if (tx.inputs.empty() || tx.outputs.empty()) {
    out.error = "tx inputs/outputs empty";
    return out;
  }
  if (tx.inputs.size() > policy.max_inputs_per_tx) {
    out.error = "tx has too many inputs";
    return out;
  }
  if (tx.outputs.size() > policy.max_outputs_per_tx) {
    out.error = "tx has too many outputs";
    return out;
  }
  if (tx.fee > policy.max_fee) {
    out.error = "fee too large";
    return out;
  }

  std::size_t confidential_input_count = 0;
  std::size_t confidential_output_count = 0;
  std::size_t total_range_proof_bytes = 0;
  const bool zero_excess_pubkey =
      std::all_of(tx.balance_proof.excess_pubkey.begin(), tx.balance_proof.excess_pubkey.end(),
                  [](std::uint8_t b) { return b == 0; });
  const bool zero_excess_sig =
      std::all_of(tx.balance_proof.excess_sig.begin(), tx.balance_proof.excess_sig.end(),
                  [](std::uint8_t b) { return b == 0; });
  std::vector<crypto::Commitment33> proof_commitments;
  std::vector<crypto::ProofBytes> proofs;
  std::uint64_t in_sum = 0;
  std::uint64_t out_sum = 0;
  std::set<OutPoint> seen_inputs;
  std::vector<crypto::Commitment33> input_commitments;
  std::vector<crypto::Commitment33> non_excess_output_commitments;

  if (!crypto::commitment_is_identity(tx.balance_proof.excess_commitment) &&
      !crypto::commitment_is_canonical(tx.balance_proof.excess_commitment)) {
    out.error = "invalid excess commitment";
    return out;
  }

  for (std::size_t input_index = 0; input_index < tx.inputs.size(); ++input_index) {
    const auto& input = tx.inputs[input_index];
    const OutPoint op{input.prev_txid, input.prev_index};
    if (!seen_inputs.insert(op).second) {
      out.error = "duplicate input outpoint";
      return out;
    }
    auto it = utxos.find(op);
    if (it == utxos.end()) {
      out.error = "missing utxo";
      return out;
    }
    if (input.kind == TxInputKind::Confidential) {
      ++confidential_input_count;
      if (!crypto::confidential_backend_status().excess_authorization_available) {
        out.error = "confidential inputs unsupported by zkp backend";
        return out;
      }
      if (input.sequence != 0xFFFFFFFF) {
        out.error = "sequence must be FFFFFFFF";
        return out;
      }
      if (it->second.kind != UtxoOutputKind::Confidential) {
        out.error = "confidential input cannot spend transparent utxo";
        return out;
      }
      const auto& prev_out = std::get<UtxoConfidentialData>(it->second.body);
      const auto& witness = std::get<ConfidentialInputWitnessV2>(input.witness);
      if (!crypto::compressed_pubkey33_is_canonical(witness.one_time_pubkey)) {
        out.error = "invalid confidential input one_time_pubkey";
        return out;
      }
      if (witness.one_time_pubkey != prev_out.one_time_pubkey) {
        out.error = "confidential input one_time_pubkey mismatch";
        return out;
      }
      const auto msg = signing_message_for_input_v2(tx, static_cast<std::uint32_t>(input_index));
      if (!msg.has_value()) {
        out.error = "sighash failed";
        return out;
      }
      Hash32 msg32{};
      std::copy(msg->begin(), msg->end(), msg32.begin());
      if (!crypto::verify_schnorr_authorization(msg32, witness.one_time_pubkey, witness.spend_sig)) {
        out.error = "confidential input authorization invalid";
        return out;
      }
      input_commitments.push_back(prev_out.value_commitment);
      continue;
    }
    if (it->second.kind != UtxoOutputKind::Transparent) {
      out.error = "transparent input cannot spend confidential utxo";
      return out;
    }
    const auto& prev_out = std::get<UtxoTransparentData>(it->second.body).out;
    if (input.sequence != 0xFFFFFFFF) {
      out.error = "sequence must be FFFFFFFF";
      return out;
    }
    std::array<std::uint8_t, 20> pkh{};
    if (!is_p2pkh_script_pubkey(prev_out.script_pubkey, &pkh)) {
      out.error = "v2 transparent inputs currently support P2PKH only";
      return out;
    }
    const auto& witness = std::get<TransparentInputWitnessV2>(input.witness);
    Sig64 sig{};
    PubKey32 pub{};
    if (!is_p2pkh_script_sig(witness.script_sig, &sig, &pub)) {
      out.error = "bad script_sig";
      return out;
    }
    const auto derived = crypto::h160(Bytes(pub.begin(), pub.end()));
    if (!std::equal(derived.begin(), derived.end(), pkh.begin())) {
      out.error = "pubkey hash mismatch";
      return out;
    }
    const auto msg = signing_message_for_input_v2(tx, static_cast<std::uint32_t>(input_index));
    if (!msg.has_value()) {
      out.error = "sighash failed";
      return out;
    }
    if (!crypto::ed25519_verify(*msg, sig, pub)) {
      out.error = "signature invalid";
      return out;
    }
    in_sum += prev_out.value;
    input_commitments.push_back(crypto::transparent_amount_commitment(prev_out.value));
  }

  for (const auto& output : tx.outputs) {
    if (output.kind == TxOutputKind::Transparent) {
      const auto& transparent = std::get<TransparentTxOutV2>(output.body);
      if (!is_supported_base_layer_output_script(transparent.script_pubkey)) {
        out.error = "unsupported script_pubkey";
        return out;
      }
      out_sum += transparent.value;
      non_excess_output_commitments.push_back(crypto::transparent_amount_commitment(transparent.value));
      continue;
    }
    ++confidential_output_count;
    if (!crypto::confidential_backend_status().confidential_outputs_supported) {
      out.error = "confidential outputs unsupported by zkp backend";
      return out;
    }
    const auto& confidential = std::get<ConfidentialTxOutV2>(output.body);
    if (!crypto::commitment_is_canonical(confidential.value_commitment)) {
      out.error = "invalid confidential value commitment";
      return out;
    }
    if (!crypto::compressed_pubkey33_is_canonical(confidential.one_time_pubkey)) {
      out.error = "invalid confidential one_time_pubkey";
      return out;
    }
    if (!crypto::compressed_pubkey33_is_canonical(confidential.ephemeral_pubkey)) {
      out.error = "invalid confidential ephemeral_pubkey";
      return out;
    }
    if (confidential.memo.size() > policy.max_memo_bytes) {
      out.error = "confidential memo too large";
      return out;
    }
    if (confidential.range_proof.bytes.empty()) {
      out.error = "missing confidential range proof";
      return out;
    }
    if (confidential.range_proof.bytes.size() > policy.max_range_proof_bytes) {
      out.error = "confidential range proof too large";
      return out;
    }
    total_range_proof_bytes += confidential.range_proof.bytes.size();
    proof_commitments.push_back(confidential.value_commitment);
    proofs.push_back(confidential.range_proof);
    non_excess_output_commitments.push_back(confidential.value_commitment);
    out.cost.confidential_verify_weight += crypto::range_proof_verify_weight(confidential.range_proof);
  }

  if (confidential_input_count > policy.max_confidential_inputs_per_tx) {
    out.error = "too many confidential inputs";
    return out;
  }
  if (confidential_output_count > policy.max_confidential_outputs_per_tx) {
    out.error = "too many confidential outputs";
    return out;
  }
  if (total_range_proof_bytes > policy.max_total_proof_bytes_per_tx) {
    out.error = "too many proof bytes";
    return out;
  }
  if (!proof_commitments.empty() && !crypto::verify_output_range_proofs_batch(proof_commitments, proofs)) {
    out.error = "range proof invalid";
    return out;
  }

  if (confidential_output_count == 0 && confidential_input_count == 0) {
    if (in_sum < out_sum || in_sum - out_sum != tx.fee) {
      out.error = "fee mismatch";
      return out;
    }
  } else if (confidential_input_count == 0 && (in_sum < out_sum || in_sum - out_sum < tx.fee)) {
    out.error = "insufficient transparent input value";
    return out;
  }

  non_excess_output_commitments.push_back(crypto::transparent_amount_commitment(tx.fee));

  std::vector<crypto::Commitment33> negative_commitments = non_excess_output_commitments;
  negative_commitments.push_back(tx.balance_proof.excess_commitment);
  if (!crypto::verify_commitment_tally(input_commitments, negative_commitments)) {
    out.error = "commitment balance mismatch";
    return out;
  }

  if (crypto::commitment_is_identity(tx.balance_proof.excess_commitment)) {
    if (!zero_excess_pubkey || !zero_excess_sig) {
      out.error = "identity excess must not carry authorization";
      return out;
    }
  } else {
    if (!crypto::confidential_backend_status().excess_authorization_available) {
      out.error = "excess authorization unsupported by zkp backend";
      return out;
    }
    if (!crypto::xonly_pubkey32_is_canonical(tx.balance_proof.excess_pubkey)) {
      out.error = "invalid excess pubkey";
      return out;
    }
    const auto msg = balance_proof_message_v2(tx);
    if (!msg.has_value()) {
      out.error = "balance proof sighash failed";
      return out;
    }
    if (!crypto::verify_excess_authorization(*msg, tx.balance_proof.excess_commitment,
                                             tx.balance_proof.excess_pubkey, tx.balance_proof.excess_sig)) {
      out.error = "excess authorization invalid";
      return out;
    }
  }

  out.ok = true;
  out.cost.fee = tx.fee;
  return out;
}

AnyTxValidationResult validate_any_tx(const AnyTx& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                      const SpecialValidationContext* ctx) {
  return std::visit(
      [&](const auto& value) -> AnyTxValidationResult {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Tx>) {
          const auto vr = validate_tx(value, tx_index_in_block, legacy_transparent_view(utxos), ctx);
          return AnyTxValidationResult{
              .ok = vr.ok,
              .error = vr.error,
              .cost = TxValidationCost{.fee = vr.fee, .confidential_verify_weight = 0, .serialized_size = value.serialize().size()},
          };
        } else {
          return validate_tx_v2(value, tx_index_in_block, utxos, ctx);
        }
      },
      tx);
}

void apply_any_tx_to_utxo(const AnyTx& tx, UtxoSetV2& utxos) {
  std::visit(
      [&](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Tx>) {
          for (const auto& in : value.inputs) {
            utxos.erase(OutPoint{in.prev_txid, in.prev_index});
          }
          const Hash32 txid = value.txid();
          for (std::uint32_t out_i = 0; out_i < value.outputs.size(); ++out_i) {
            utxos[OutPoint{txid, out_i}] = UtxoEntryV2{value.outputs[out_i]};
          }
        } else {
          for (const auto& in : value.inputs) {
            utxos.erase(OutPoint{in.prev_txid, in.prev_index});
          }
          const Hash32 txid = value.txid();
          for (std::uint32_t out_i = 0; out_i < value.outputs.size(); ++out_i) {
            const auto& out = value.outputs[out_i];
            if (out.kind == TxOutputKind::Transparent) {
              const auto& transparent = std::get<TransparentTxOutV2>(out.body);
              utxos[OutPoint{txid, out_i}] = UtxoEntryV2{TxOut{transparent.value, transparent.script_pubkey}};
            } else {
              const auto& confidential = std::get<ConfidentialTxOutV2>(out.body);
              UtxoEntryV2 entry;
              entry.kind = UtxoOutputKind::Confidential;
              entry.body = UtxoConfidentialData{
                  .value_commitment = confidential.value_commitment,
                  .one_time_pubkey = confidential.one_time_pubkey,
                  .ephemeral_pubkey = confidential.ephemeral_pubkey,
                  .scan_tag = confidential.scan_tag,
                  .memo = confidential.memo,
              };
              utxos[OutPoint{txid, out_i}] = std::move(entry);
            }
          }
        }
      },
      tx);
}

}  // namespace finalis
