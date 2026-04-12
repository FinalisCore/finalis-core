#include "crypto/confidential.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis::crypto {
namespace {

bool fixed33_is_nonzero(const PubKey33& value) {
  return std::any_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte != 0; });
}

Commitment33 hash_tagged_commitment(const Bytes& domain, std::span<const std::uint8_t> payload) {
  codec::ByteWriter w;
  w.bytes(domain);
  w.varint(payload.size());
  w.bytes(Bytes(payload.begin(), payload.end()));
  const auto hash = sha256d(w.data());
  Commitment33 out;
  out.bytes[0] = 0x02 | (hash[0] & 0x01);
  std::copy(hash.begin(), hash.end(), out.bytes.begin() + 1);
  return out;
}

}  // namespace

bool confidential_crypto_init() { return true; }

bool compressed_pubkey33_is_canonical(const PubKey33& pubkey) {
  if (pubkey[0] != 0x02 && pubkey[0] != 0x03) return false;
  return fixed33_is_nonzero(pubkey);
}

bool commitment_is_canonical(const Commitment33& commitment) {
  return compressed_pubkey33_is_canonical(commitment.bytes);
}

Commitment33 transparent_amount_commitment(std::uint64_t amount) {
  codec::ByteWriter w;
  w.u64le(amount);
  const Bytes payload = w.take();
  return hash_tagged_commitment(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'c', 't', '.', 't', 'r', 'a', 'n', 's',
                                      'p', 'a', 'r', 'e', 'n', 't', '.', 'a', 'm', 'o', 'u', 'n', 't', '.', 'v', '1'},
                                payload);
}

std::optional<Commitment33> add_commitments(std::span<const Commitment33> commitments) {
  if (commitments.empty()) return std::nullopt;
  codec::ByteWriter w;
  w.bytes(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'c', 't', '.', 'a', 'd', 'd', '.', 'v', '1'});
  w.varint(commitments.size());
  for (const auto& commitment : commitments) {
    if (!commitment_is_canonical(commitment)) return std::nullopt;
    w.bytes_fixed(commitment.bytes);
  }
  const auto digest = sha256d(w.data());
  Commitment33 out;
  out.bytes[0] = 0x02 | (digest[0] & 0x01);
  std::copy(digest.begin(), digest.end(), out.bytes.begin() + 1);
  return out;
}

std::optional<Commitment33> subtract_commitments(const Commitment33& lhs, const Commitment33& rhs) {
  if (!commitment_is_canonical(lhs) || !commitment_is_canonical(rhs)) return std::nullopt;
  codec::ByteWriter w;
  w.bytes(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'c', 't', '.', 's', 'u', 'b', '.', 'v', '1'});
  w.bytes_fixed(lhs.bytes);
  w.bytes_fixed(rhs.bytes);
  const auto digest = sha256d(w.data());
  Commitment33 out;
  out.bytes[0] = 0x02 | (digest[0] & 0x01);
  std::copy(digest.begin(), digest.end(), out.bytes.begin() + 1);
  return out;
}

bool verify_output_range_proof(const Commitment33& commitment, const ProofBytes& proof) {
  return commitment_is_canonical(commitment) && !proof.bytes.empty();
}

bool verify_output_range_proofs_batch(std::span<const Commitment33> commitments, std::span<const ProofBytes> proofs) {
  if (commitments.size() != proofs.size()) return false;
  for (std::size_t i = 0; i < commitments.size(); ++i) {
    if (!verify_output_range_proof(commitments[i], proofs[i])) return false;
  }
  return true;
}

std::size_t range_proof_verify_weight(const ProofBytes& proof) { return proof.bytes.size(); }

}  // namespace finalis::crypto
