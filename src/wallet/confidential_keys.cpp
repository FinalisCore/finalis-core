// SPDX-License-Identifier: MIT

#include "wallet/confidential_keys.hpp"

#include <string_view>

#include "crypto/hash.hpp"

namespace finalis::wallet {
namespace {

constexpr std::string_view kTweakTag = "FINALIS/conf-request/tweak/v1";
constexpr std::string_view kEphemeralTag = "FINALIS/conf-request/ephemeral/v1";
constexpr std::string_view kScanTagTag = "FINALIS/conf-request/scan-tag/v1";
constexpr std::string_view kMemoTag = "FINALIS/conf-request/memo/v1";

// BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || v || le32(index) || counter).
Hash32 tagged_hash(std::string_view tag, const Hash32& view_secret, std::uint32_t index, std::uint8_t counter) {
  const Hash32 tag_hash = crypto::sha256(Bytes(tag.begin(), tag.end()));
  Bytes preimage;
  preimage.reserve(32 + 32 + 32 + 4 + 1);
  preimage.insert(preimage.end(), tag_hash.begin(), tag_hash.end());
  preimage.insert(preimage.end(), tag_hash.begin(), tag_hash.end());
  preimage.insert(preimage.end(), view_secret.begin(), view_secret.end());
  for (int shift = 0; shift < 32; shift += 8) preimage.push_back(static_cast<std::uint8_t>(index >> shift));
  preimage.push_back(counter);
  const Hash32 out = crypto::sha256(preimage);
  crypto::secure_wipe(preimage);
  return out;
}

// First tagged hash (counter 0, 1, ...) that is a valid secp256k1 scalar in [1, n). A retry happens
// with probability about 2^-128 per attempt.
std::optional<Hash32> hash_to_scalar(std::string_view tag, const Hash32& view_secret, std::uint32_t index) {
  for (unsigned counter = 0; counter < 256; ++counter) {
    Hash32 candidate = tagged_hash(tag, view_secret, index, static_cast<std::uint8_t>(counter));
    if (crypto::secp256k1_pubkey_from_scalar(candidate).has_value()) return candidate;
    crypto::secure_wipe(candidate);
  }
  return std::nullopt;
}

}  // namespace

std::optional<ConfidentialRequestPublicKeys> derive_confidential_request_public_keys(const Hash32& view_secret,
                                                                                    const PubKey33& spend_pubkey,
                                                                                    std::uint32_t index) {
  if (!crypto::secp256k1_pubkey_from_scalar(view_secret).has_value()) return std::nullopt;
  auto tweak = hash_to_scalar(kTweakTag, view_secret, index);
  auto ephemeral_secret = hash_to_scalar(kEphemeralTag, view_secret, index);
  if (!tweak || !ephemeral_secret) return std::nullopt;
  crypto::ScopedWipe<Hash32, Hash32> wipe(*tweak, *ephemeral_secret);

  const auto one_time_pubkey = crypto::secp256k1_pubkey_tweak_add(spend_pubkey, *tweak);
  const auto ephemeral_pubkey = crypto::secp256k1_pubkey_from_scalar(*ephemeral_secret);
  if (!one_time_pubkey || !ephemeral_pubkey) return std::nullopt;

  ConfidentialRequestPublicKeys out;
  out.one_time_pubkey = *one_time_pubkey;
  out.ephemeral_pubkey = *ephemeral_pubkey;
  out.scan_tag = crypto::ScanTag{tagged_hash(kScanTagTag, view_secret, index, 0)[0]};
  out.memo_key = tagged_hash(kMemoTag, view_secret, index, 0);
  return out;
}

std::optional<ConfidentialRequestKeys> derive_confidential_request_keys(const Hash32& view_secret,
                                                                        const Hash32& spend_secret,
                                                                        std::uint32_t index) {
  const auto spend_pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret);
  if (!spend_pubkey) return std::nullopt;
  auto pub = derive_confidential_request_public_keys(view_secret, *spend_pubkey, index);
  if (!pub) return std::nullopt;
  auto tweak = hash_to_scalar(kTweakTag, view_secret, index);
  if (!tweak) return std::nullopt;
  crypto::ScopedWipe<Hash32> wipe(*tweak);
  auto one_time_secret = crypto::secp256k1_scalar_tweak_add(spend_secret, *tweak);
  if (!one_time_secret) return std::nullopt;

  ConfidentialRequestKeys out;
  out.pub.one_time_pubkey = pub->one_time_pubkey;
  out.pub.ephemeral_pubkey = pub->ephemeral_pubkey;
  out.pub.scan_tag = pub->scan_tag;
  out.pub.memo_key = pub->memo_key;
  out.one_time_secret = *one_time_secret;
  crypto::secure_wipe(*one_time_secret);
  return out;
}

}  // namespace finalis::wallet
