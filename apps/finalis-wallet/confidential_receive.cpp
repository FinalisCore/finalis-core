// SPDX-License-Identifier: MIT

#include "confidential_receive.hpp"

#include <algorithm>
#include <optional>

#include "confidential_memo.hpp"
#include "crypto/secure_memory.hpp"
#include "wallet/confidential_keys.hpp"

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

namespace {

// One derived receive request of an account, kept for matching outputs of one tx.
struct DerivedRequest {
  std::string account_id;
  std::uint32_t index{0};
  ConfidentialRequestPublicKeys keys;
};

std::vector<DerivedRequest> derive_account_requests(const WalletStore::State& state) {
  std::vector<DerivedRequest> out;
  for (const auto& account : state.confidential_accounts) {
    auto view = decode_hash32(account.view_key_material_hex);
    auto spend = decode_hash32(account.spend_key_material_hex);
    std::optional<PubKey33> spend_pubkey;
    if (spend) spend_pubkey = crypto::secp256k1_pubkey_from_scalar(*spend);
    if (spend) crypto::secure_wipe(*spend);
    if (!view || !spend_pubkey) {
      if (view) crypto::secure_wipe(*view);
      continue;
    }
    const std::uint64_t limit = static_cast<std::uint64_t>(account.next_request_index) + kConfidentialRequestGap;
    for (std::uint64_t index = 0; index < limit && index <= 0xFFFF'FFFFULL; ++index) {
      auto keys = derive_confidential_request_public_keys(*view, *spend_pubkey, static_cast<std::uint32_t>(index));
      if (!keys) continue;
      out.push_back(DerivedRequest{account.account_id, static_cast<std::uint32_t>(index), *keys});
    }
    crypto::secure_wipe(*view);
  }
  return out;
}

std::optional<std::string> derived_spend_secret_hex(const WalletStore::State& state, const std::string& account_id,
                                                    std::uint32_t index) {
  const auto account = std::find_if(state.confidential_accounts.begin(), state.confidential_accounts.end(),
                                    [&](const auto& a) { return a.account_id == account_id; });
  if (account == state.confidential_accounts.end()) return std::nullopt;
  auto view = decode_hash32(account->view_key_material_hex);
  auto spend = decode_hash32(account->spend_key_material_hex);
  std::optional<ConfidentialRequestKeys> keys;
  if (view && spend) keys = derive_confidential_request_keys(*view, *spend, index);
  if (view) crypto::secure_wipe(*view);
  if (spend) crypto::secure_wipe(*spend);
  if (!keys) return std::nullopt;
  return hex_encode(Bytes(keys->one_time_secret.begin(), keys->one_time_secret.end()));
}

}  // namespace

std::vector<ConfidentialReceiveMatch> match_received_confidential_outputs(const TxV2& tx, const Hash32& txid,
                                                                          const WalletStore::State& state,
                                                                          std::size_t* already_imported) {
  std::vector<ConfidentialReceiveMatch> out;
  if (already_imported) *already_imported = 0;
  const std::string txid_hex = hex_encode32(txid);
  std::optional<std::vector<DerivedRequest>> derived;  // computed on the first unmatched output only
  for (std::size_t i = 0; i < tx.outputs.size(); ++i) {
    const auto& output = tx.outputs[i];
    if (output.kind != TxOutputKind::Confidential) continue;
    const auto& confidential = std::get<ConfidentialTxOutV2>(output.body);
    const auto vout = static_cast<std::uint32_t>(i);
    const std::string one_time_hex = hex_encode(Bytes(confidential.one_time_pubkey.begin(), confidential.one_time_pubkey.end()));
    const std::string ephemeral_hex = hex_encode(Bytes(confidential.ephemeral_pubkey.begin(), confidential.ephemeral_pubkey.end()));
    const bool known = std::any_of(state.confidential_coins.begin(), state.confidential_coins.end(),
                                   [&](const WalletStore::ConfidentialCoinRecord& coin) {
                                     return coin.txid_hex == txid_hex && coin.vout == vout;
                                   });

    // Who this output pays: a stored request record, else a request derived from an account.
    std::string account_id;
    std::string request_id;
    std::optional<std::uint32_t> derived_index;
    std::optional<Hash32> memo_key;
    std::string spend_secret_hex;
    const auto request_it = std::find_if(
        state.confidential_requests.begin(), state.confidential_requests.end(),
        [&](const WalletStore::ConfidentialRequestRecord& req) {
          return req.one_time_pubkey_hex == one_time_hex && req.ephemeral_pubkey_hex == ephemeral_hex &&
                 req.scan_tag == confidential.scan_tag.value;
        });
    if (request_it != state.confidential_requests.end()) {
      account_id = request_it->account_id;
      request_id = request_it->request_id;
      memo_key = decode_hash32(request_it->memo_key_hex);
      spend_secret_hex = request_it->spend_secret_hex;
    } else {
      if (!derived) derived = derive_account_requests(state);
      const auto derived_it = std::find_if(derived->begin(), derived->end(), [&](const DerivedRequest& d) {
        return d.keys.one_time_pubkey == confidential.one_time_pubkey &&
               d.keys.ephemeral_pubkey == confidential.ephemeral_pubkey && d.keys.scan_tag == confidential.scan_tag;
      });
      if (derived_it == derived->end()) continue;
      account_id = derived_it->account_id;
      derived_index = derived_it->index;
      memo_key = derived_it->keys.memo_key;
    }
    if (known) {
      if (already_imported) ++*already_imported;
      if (memo_key) crypto::secure_wipe(*memo_key);
      crypto::secure_wipe(spend_secret_hex);
      continue;
    }
    if (!memo_key) continue;
    auto recovery =
        decrypt_confidential_recovery_memo(confidential.memo, *memo_key, confidential.one_time_pubkey, confidential.ephemeral_pubkey);
    crypto::secure_wipe(*memo_key);
    if (!recovery) {
      crypto::secure_wipe(spend_secret_hex);
      continue;
    }
    if (derived_index) {
      auto secret = derived_spend_secret_hex(state, account_id, *derived_index);
      if (!secret) {
        crypto::secure_wipe(recovery->blind.bytes);
        continue;
      }
      spend_secret_hex = std::move(*secret);
    }
    Bytes blind_bytes(recovery->blind.bytes.begin(), recovery->blind.bytes.end());
    std::string blind_hex = hex_encode(blind_bytes);
    crypto::secure_wipe(blind_bytes);
    crypto::secure_wipe(recovery->blind.bytes);
    out.push_back(ConfidentialReceiveMatch{
        .coin =
            WalletStore::ConfidentialCoinRecord{
                .txid_hex = txid_hex,
                .vout = vout,
                .account_id = account_id,
                .amount = recovery->amount,
                .value_commitment_hex =
                    hex_encode(Bytes(confidential.value_commitment.bytes.begin(), confidential.value_commitment.bytes.end())),
                .one_time_pubkey_hex = one_time_hex,
                .ephemeral_pubkey_hex = ephemeral_hex,
                .spend_secret_hex = spend_secret_hex,
                .blinding_factor_hex = blind_hex,
                .spent = false,
            },
        .request_id = request_id,
        .derived_index = derived_index,
    });
    crypto::secure_wipe(spend_secret_hex);
    crypto::secure_wipe(blind_hex);
  }
  return out;
}

}  // namespace finalis::wallet
