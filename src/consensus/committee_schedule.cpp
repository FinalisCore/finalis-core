// SPDX-License-Identifier: MIT

#include "consensus/committee_schedule.hpp"

#include <algorithm>
#include <vector>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis::consensus {
namespace {

Hash32 hash_bytes(const Bytes& domain, const std::vector<Bytes>& parts) {
  codec::ByteWriter w;
  w.bytes(domain);
  for (const auto& part : parts) w.varbytes(part);
  return crypto::sha256d(w.data());
}

}  // namespace

Hash32 compute_committee_root(const std::vector<ValidatorBestTicket>& committee) {
  std::vector<Bytes> parts;
  parts.reserve(committee.size());
  for (const auto& entry : committee) {
    codec::ByteWriter w;
    w.bytes_fixed(entry.validator_pubkey);
    w.bytes_fixed(entry.best_ticket_hash);
    w.u64le(entry.nonce);
    parts.push_back(w.take());
  }
  return hash_bytes(Bytes{'S', 'E', 'L', 'F', 'C', 'O', 'I', 'N', '_', 'C', 'O', 'M', 'M', 'I', 'T', 'T', 'E',
                          'E', '_', 'V', '1'},
                    parts);
}

Hash32 compute_proposer_seed(const Hash32& epoch_anchor, std::uint64_t height, const Hash32& committee_root) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'E', 'L', 'F', 'C', 'O', 'I', 'N', '_', 'P', 'R', 'O', 'P', 'O', 'S', 'E', 'R', '_', 'V',
                '1'});
  w.bytes_fixed(epoch_anchor);
  w.u64le(height);
  w.bytes_fixed(committee_root);
  return crypto::sha256d(w.data());
}

std::vector<PubKey32> proposer_schedule_from_committee(const std::vector<ValidatorBestTicket>& committee,
                                                       const Hash32& proposer_seed) {
  std::vector<std::pair<Hash32, PubKey32>> scored;
  scored.reserve(committee.size());
  for (const auto& entry : committee) {
    codec::ByteWriter w;
    w.bytes_fixed(proposer_seed);
    w.bytes_fixed(entry.validator_pubkey);
    scored.push_back({crypto::sha256d(w.data()), entry.validator_pubkey});
  }
  std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
    if (a.first != b.first) return a.first < b.first;
    return a.second < b.second;
  });
  std::vector<PubKey32> out;
  out.reserve(scored.size());
  for (const auto& [_, pub] : scored) out.push_back(pub);
  return out;
}

}  // namespace finalis::consensus
