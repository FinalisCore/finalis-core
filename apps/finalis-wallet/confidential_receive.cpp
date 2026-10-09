// SPDX-License-Identifier: MIT

#include "confidential_receive.hpp"

#include <algorithm>
#include <optional>

#include "confidential_memo.hpp"
#include "crypto/secure_memory.hpp"

namespace finalis::wallet {
namespace {

std::optional<Hash32> decode_hash32(const std::string& hex) {
  auto bytes = hex_decode(hex);
  if (!bytes || bytes->size() != 32) {
    if (bytes) crypto::secure_wipe(*bytes);
    return std::nullopt;
  }
  Hash32 out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  crypto::secure_wipe(*bytes);
  return out;
}

}  // namespace

std::vector<ConfidentialReceiveMatch> match_received_confidential_outputs(const TxV2& tx, const Hash32& txid,
                                                                          const WalletStore::State& state,
                                                                          std::size_t* already_imported) {
  std::vector<ConfidentialReceiveMatch> out;
  if (already_imported) *already_imported = 0;
  const std::string txid_hex = hex_encode32(txid);
  for (std::size_t i = 0; i < tx.outputs.size(); ++i) {
    const auto& output = tx.outputs[i];
    if (output.kind != TxOutputKind::Confidential) continue;
    const auto& confidential = std::get<ConfidentialTxOutV2>(output.body);
    const auto vout = static_cast<std::uint32_t>(i);
    const std::string one_time_hex = hex_encode(Bytes(confidential.one_time_pubkey.begin(), confidential.one_time_pubkey.end()));
    const std::string ephemeral_hex = hex_encode(Bytes(confidential.ephemeral_pubkey.begin(), confidential.ephemeral_pubkey.end()));
    const auto request_it = std::find_if(
        state.confidential_requests.begin(), state.confidential_requests.end(),
        [&](const WalletStore::ConfidentialRequestRecord& req) {
          return req.one_time_pubkey_hex == one_time_hex && req.ephemeral_pubkey_hex == ephemeral_hex &&
                 req.scan_tag == confidential.scan_tag.value;
        });
    if (request_it == state.confidential_requests.end()) continue;
    const bool known = std::any_of(state.confidential_coins.begin(), state.confidential_coins.end(),
                                   [&](const WalletStore::ConfidentialCoinRecord& coin) {
                                     return coin.txid_hex == txid_hex && coin.vout == vout;
                                   });
    if (known) {
      if (already_imported) ++*already_imported;
      continue;
    }
    auto memo_key = decode_hash32(request_it->memo_key_hex);
    if (!memo_key) continue;
    auto recovery =
        decrypt_confidential_recovery_memo(confidential.memo, *memo_key, confidential.one_time_pubkey, confidential.ephemeral_pubkey);
    crypto::secure_wipe(*memo_key);
    if (!recovery) continue;
    Bytes blind_bytes(recovery->blind.bytes.begin(), recovery->blind.bytes.end());
    std::string blind_hex = hex_encode(blind_bytes);
    crypto::secure_wipe(blind_bytes);
    crypto::secure_wipe(recovery->blind.bytes);
    out.push_back(ConfidentialReceiveMatch{
        .coin =
            WalletStore::ConfidentialCoinRecord{
                .txid_hex = txid_hex,
                .vout = vout,
                .account_id = request_it->account_id,
                .amount = recovery->amount,
                .value_commitment_hex =
                    hex_encode(Bytes(confidential.value_commitment.bytes.begin(), confidential.value_commitment.bytes.end())),
                .one_time_pubkey_hex = one_time_hex,
                .ephemeral_pubkey_hex = ephemeral_hex,
                .spend_secret_hex = request_it->spend_secret_hex,
                .blinding_factor_hex = blind_hex,
                .spent = false,
            },
        .request_id = request_it->request_id,
    });
    crypto::secure_wipe(blind_hex);
  }
  return out;
}

}  // namespace finalis::wallet
