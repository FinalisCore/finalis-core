#include "consensus/randomness.hpp"

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis::consensus {

Hash32 initial_finalized_randomness(const NetworkConfig& network, const ChainId& chain_id) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'R', 'A', 'N', 'D', '-', 'G', 'E', 'N', '-', 'V', '1'});
  w.bytes_fixed(network.network_id);
  const auto gh = hex_decode(chain_id.genesis_hash_hex);
  if (gh && gh->size() == 32) w.bytes(*gh);
  return crypto::sha256d(w.data());
}

Hash32 advance_finalized_randomness(const Hash32& prev_randomness, const BlockHeader& header) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'R', 'A', 'N', 'D', '-', 'A', 'C', 'C', '-', 'V', '1'});
  w.bytes_fixed(prev_randomness);
  w.bytes_fixed(header.block_id());
  w.bytes_fixed(header.leader_pubkey);
  w.u64le(header.height);
  w.u32le(header.round);
  return crypto::sha256d(w.data());
}

Hash32 advance_finalized_randomness(const Hash32& prev_randomness, const FrontierTransition& transition) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'R', 'A', 'N', 'D', '-', 'F', 'R', 'O', 'N', 'T', '-', 'V', '1'});
  w.bytes_fixed(prev_randomness);
  w.bytes_fixed(transition.transition_id());
  w.bytes_fixed(transition.leader_pubkey);
  w.u64le(transition.height);
  w.u32le(transition.round);
  return crypto::sha256d(w.data());
}

std::uint64_t committee_epoch_start(std::uint64_t height, std::uint64_t epoch_blocks) {
  if (height == 0) return 0;
  if (epoch_blocks == 0) epoch_blocks = 1;
  return ((height - 1) / epoch_blocks) * epoch_blocks + 1;
}

Hash32 committee_epoch_seed(const Hash32& epoch_randomness, std::uint64_t epoch_start_height) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'C', 'O', 'M', 'M', '-', 'E', 'P', 'O', 'C', 'H', '-', 'V', '1'});
  w.bytes_fixed(epoch_randomness);
  w.u64le(epoch_start_height);
  return crypto::sha256d(w.data());
}

}  // namespace finalis::consensus
