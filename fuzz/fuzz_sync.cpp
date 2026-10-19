// SPDX-License-Identifier: MIT

// Catch-up sync fuzzer. A syncing node takes a finalized transition, its finality certificate and its
// certified ingress records from a peer and applies them with the pure consensus functions this
// target calls: verify_frontier_finality_certificate and apply_frontier_record.
//
// The fixture is a reference chain of kHeights transitions (one-validator committee, a chain of
// transparent spends) with its parent states, records and certificates. Each input picks a parent
// state and a record/certificate (usually the matching ones) and mutates them: byte flips in the
// encoded transition, certificate and ingress records, dropped or duplicated records, and parts taken
// from other heights. Oracles:
//   - a certificate that verifies certifies the reference transition of its height (only the
//     committee key signs, so any other transition is a forgery);
//   - a record that applies yields a post-state matching the transition's next_state_commitment,
//     one height above its parent;
//   - a certified transition that applies yields exactly the reference post-state (the certified
//     transition must bind the records it executes).
//
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/); otherwise a
// standalone smoke binary.

#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <random>
#include <stdexcept>
#include <vector>

#include "support/test_leader_vrf.hpp"

#include "common/address.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/ingress.hpp"
#include "consensus/randomness.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

constexpr std::size_t kHeights = 6;

struct Stats {
  std::uint64_t cert_ok{0};
  std::uint64_t applied{0};
  std::uint64_t certified_and_applied{0};
} g_stats;

[[noreturn]] void fail(const char* what, std::size_t size) {
  std::cerr << "fuzz_sync: " << what << " size=" << size << "\n";
  std::abort();
}

struct Cursor {
  const Bytes& in;
  std::size_t pos{0};
  bool done() const { return pos >= in.size(); }
  std::uint8_t u8() { return pos < in.size() ? in[pos++] : 0; }
  std::size_t u16() { return (static_cast<std::size_t>(u8()) << 8) | u8(); }
};

crypto::KeyPair key_from_byte(std::uint8_t base) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(base);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp) throw std::runtime_error("key derivation failed");
  return *kp;
}

consensus::CanonicalDerivationConfig make_cfg() {
  consensus::CanonicalDerivationConfig cfg;
  cfg.network = mainnet_network();
  cfg.chain_id.network_name = cfg.network.name;
  cfg.chain_id.magic = cfg.network.magic;
  cfg.chain_id.network_id_hex = hex_encode(Bytes(cfg.network.network_id.begin(), cfg.network.network_id.end()));
  cfg.chain_id.protocol_version = PROTOCOL_VERSION;
  cfg.chain_id.genesis_hash_hex = "fuzz-sync";
  cfg.chain_id.genesis_source = "fuzz";
  return cfg;
}

TxOut p2pkh_out(const PubKey32& pub, std::uint64_t value) {
  return TxOut{value, address::p2pkh_script_pubkey(crypto::h160(Bytes(pub.begin(), pub.end())))};
}

struct Height {
  consensus::CanonicalFrontierRecord record;
  FinalityCertificate cert;
};

struct Fixture {
  consensus::CanonicalDerivationConfig cfg;
  std::vector<consensus::CanonicalDerivedState> states;  // states[h]: after height h (states[0]: genesis)
  std::vector<Height> heights;                            // heights[h - 1]: the transition of height h
};

consensus::CertifiedIngressLaneRecords lane_records_for(const Fixture& fx, const consensus::CanonicalDerivedState& parent,
                                                        const std::vector<Bytes>& raws, FrontierVector* next_vector,
                                                        const crypto::KeyPair& signer) {
  consensus::CertifiedIngressLaneRecords lanes;
  *next_vector = parent.finalized_frontier_vector;
  auto roots = parent.finalized_lane_roots;
  const auto epoch = consensus::committee_epoch_start(parent.finalized_height + 1, fx.cfg.network.committee_epoch_blocks);
  for (const auto& raw : raws) {
    auto tx = parse_any_tx(raw);
    if (!tx) throw std::runtime_error("bad fixture tx");
    const auto lane = consensus::assign_ingress_lane(*tx);
    IngressCertificate cert;
    cert.epoch = epoch;
    cert.lane = lane;
    cert.seq = ++next_vector->lane_max_seq[lane];
    cert.txid = txid_any(*tx);
    cert.tx_hash = crypto::sha256d(raw);
    cert.prev_lane_root = roots[lane];
    const auto h = cert.signing_hash();
    auto sig = crypto::ed25519_sign(Bytes(h.begin(), h.end()), signer.private_key);
    if (!sig) throw std::runtime_error("ingress sign failed");
    cert.sigs = {FinalitySig{signer.public_key, *sig}};
    roots[lane] = consensus::compute_lane_root_append(roots[lane], cert.tx_hash);
    lanes[lane].push_back({cert, raw});
  }
  return lanes;
}

Fixture build_fixture() {
  Fixture fx;
  fx.cfg = make_cfg();
  const auto validator = key_from_byte(90);
  const auto domain = consensus_chain_domain(fx.cfg.network, fx.cfg.chain_id);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(validator.public_key);
  genesis.genesis_time_unix = 1735689600ULL;
  consensus::CanonicalDerivedState state;
  std::string err;
  if (!consensus::build_genesis_canonical_state(fx.cfg, genesis, &state, &err)) throw std::runtime_error(err);

  // A funded output that each height spends on to the next owner.
  std::vector<crypto::KeyPair> owners{key_from_byte(1), key_from_byte(2)};
  OutPoint op{};
  op.txid.fill(0x5A);
  std::size_t owner = 0;
  TxOut out = p2pkh_out(owners[owner].public_key, 1'000'000);
  state.utxos[op] = UtxoEntry{out};
  state.state_commitment = consensus::consensus_state_commitment(fx.cfg, state);
  fx.states.push_back(state);

  for (std::size_t h = 1; h <= kHeights; ++h) {
    const auto& parent = fx.states.back();
    std::vector<Bytes> raws;
    if (h % 3 != 0) {  // every third height is empty
      const TxOut next = p2pkh_out(owners[1 - owner].public_key, out.value - 2'000);
      std::string tx_err;
      auto tx = build_signed_p2pkh_tx_single_input(domain, op, out, owners[owner].private_key, {next}, &tx_err);
      if (!tx) throw std::runtime_error("spend build failed: " + tx_err);
      owner = 1 - owner;
      raws.push_back(tx->serialize());
      op = OutPoint{tx->txid(), 0};
      out = next;
    }

    FrontierVector next_vector;
    auto lanes = lane_records_for(fx, parent, raws, &next_vector, validator);
    SpecialValidationContext vctx;
    vctx.network = &fx.cfg.network;
    vctx.chain_id = &fx.cfg.chain_id;
    consensus::FrontierExecutionResult result;
    if (!consensus::execute_frontier_lane_prefix(parent.utxos, parent.confidential_pool_value,
                                                 parent.finalized_frontier_vector, next_vector, lanes,
                                                 parent.finalized_lane_roots, &vctx, &result, &err)) {
      throw std::runtime_error("execution failed: " + err);
    }
    const auto leader = consensus::canonical_leader_for_height_round(fx.cfg, parent, h, 0);
    if (!leader) throw std::runtime_error("no leader");
    const auto parent_round = parent.finalized_block_metadata.contains(parent.finalized_height)
                                  ? parent.finalized_block_metadata.at(parent.finalized_height).round
                                  : 0u;
    std::vector<FinalitySig> prev_signers;
    consensus::ParentFinalityContext parent_ctx;
    if (consensus::resolve_parent_finality_context(fx.cfg, parent, parent_round, &parent_ctx, &err) &&
        parent_ctx.has_parent) {
      auto sig = crypto::ed25519_sign(
          vote_signing_message(domain, parent_ctx.height, parent_ctx.round, parent_ctx.transition_id),
          validator.private_key);
      prev_signers.push_back(FinalitySig{validator.public_key, *sig});
    }
    if (!consensus::populate_frontier_transition_metadata(fx.cfg, parent, h, 0, *leader, parent_round, prev_signers,
                                                          result.accepted_fee_units, result.next_utxos,
                                                          &result.transition, &err)) {
      throw std::runtime_error("metadata failed: " + err);
    }
    if (!test::attach_test_leader_vrf(&result.transition, parent.finalized_randomness, {validator})) {
      throw std::runtime_error("vrf failed");
    }
    Height ht;
    ht.record = consensus::CanonicalFrontierRecord{result.transition, lanes};
    if (!test::attach_test_next_state_commitment(fx.cfg, parent, &ht.record)) {
      throw std::runtime_error("next state commitment failed");
    }

    const auto committee = consensus::canonical_committee_for_height_round(fx.cfg, parent, h, 0);
    const auto id = ht.record.transition.transition_id();
    auto sig = crypto::ed25519_sign(vote_signing_message(domain, h, 0, id), validator.private_key);
    ht.cert.height = h;
    ht.cert.round = 0;
    ht.cert.frontier_transition_id = id;
    ht.cert.quorum_threshold = static_cast<std::uint32_t>(consensus::quorum_threshold(committee.size()));
    ht.cert.committee_members = committee;
    ht.cert.signatures = {FinalitySig{validator.public_key, *sig}};

    if (!consensus::verify_frontier_finality_certificate(fx.cfg, parent, ht.record.transition, ht.cert, &err)) {
      throw std::runtime_error("fixture certificate rejected: " + err);
    }
    consensus::CanonicalDerivedState next;
    if (!consensus::apply_frontier_record(fx.cfg, parent, ht.record, &next, &err)) {
      throw std::runtime_error("fixture record rejected: " + err);
    }
    fx.heights.push_back(std::move(ht));
    fx.states.push_back(std::move(next));
  }
  return fx;
}

const Fixture& fixture() {
  static const Fixture fx = [] {
    try {
      return build_fixture();
    } catch (const std::exception& e) {
      std::cerr << "fuzz_sync: fixture: " << e.what() << "\n";
      std::abort();
    }
  }();
  return fx;
}

// XORs one byte of `v`'s encoding; false when the result no longer parses.
template <class T>
bool flip(T* v, Cursor& c) {
  Bytes b = v->serialize();
  if (b.empty()) return false;
  b[c.u16() % b.size()] ^= static_cast<std::uint8_t>(c.u8() | 1u);
  auto parsed = T::parse(b);
  if (!parsed) return false;
  *v = *parsed;
  return true;
}

std::vector<consensus::CertifiedIngressRecord*> all_records(consensus::CertifiedIngressLaneRecords& lanes) {
  std::vector<consensus::CertifiedIngressRecord*> out;
  for (auto& lane : lanes) {
    for (auto& r : lane) out.push_back(&r);
  }
  return out;
}

void run_one(const Bytes& in) {
  const auto& fx = fixture();
  if (in.size() < 2) return;
  Cursor c{in};
  const std::size_t h = 1 + c.u8() % kHeights;           // the record/certificate's reference height
  const std::uint8_t parent_sel = c.u8();
  const std::size_t p = (parent_sel & 3u) ? h - 1 : parent_sel % kHeights;  // usually the matching parent

  consensus::CanonicalFrontierRecord record = fx.heights[h - 1].record;
  FinalityCertificate cert = fx.heights[h - 1].cert;

  for (int ops = 0; ops < 6 && !c.done(); ++ops) {
    switch (c.u8() % 8) {
      case 0:
        if (!flip(&record.transition, c)) return;
        break;
      case 1:
        if (!flip(&cert, c)) return;
        break;
      case 2: {
        auto recs = all_records(record.lane_records);
        if (recs.empty()) break;
        auto* r = recs[c.u8() % recs.size()];
        if (r->tx_bytes.empty()) break;
        r->tx_bytes[c.u16() % r->tx_bytes.size()] ^= static_cast<std::uint8_t>(c.u8() | 1u);
        break;
      }
      case 3: {
        auto recs = all_records(record.lane_records);
        if (recs.empty()) break;
        if (!flip(&recs[c.u8() % recs.size()]->certificate, c)) return;
        break;
      }
      case 4: {
        auto& lane = record.lane_records[c.u8() % record.lane_records.size()];
        if (!lane.empty()) lane.erase(lane.begin() + static_cast<std::ptrdiff_t>(c.u8() % lane.size()));
        break;
      }
      case 5: {
        auto recs = all_records(record.lane_records);
        if (recs.empty()) break;
        const auto copy = *recs[c.u8() % recs.size()];
        record.lane_records[copy.certificate.lane % record.lane_records.size()].push_back(copy);
        break;
      }
      case 6:
        cert = fx.heights[c.u8() % kHeights].cert;
        break;
      case 7:
        record.lane_records = fx.heights[c.u8() % kHeights].record.lane_records;
        break;
    }
  }

  const auto& parent = fx.states[p];
  std::string err;
  const bool cert_ok = consensus::verify_frontier_finality_certificate(fx.cfg, parent, record.transition, cert, &err);
  if (cert_ok) {
    ++g_stats.cert_ok;
    const auto th = record.transition.height;
    if (th < 1 || th > kHeights || record.transition.transition_id() != fx.heights[th - 1].record.transition.transition_id()) {
      fail("certificate verified for a transition the committee never signed", in.size());
    }
  }

  consensus::CanonicalDerivedState out;
  const bool applied = consensus::apply_frontier_record(fx.cfg, parent, record, &out, &err);
  if (applied) {
    ++g_stats.applied;
    if (out.finalized_height != parent.finalized_height + 1) fail("applied record skipped a height", in.size());
    if (consensus::consensus_post_state_commitment(fx.cfg, out) != record.transition.next_state_commitment) {
      fail("applied state differs from the transition's next_state_commitment", in.size());
    }
  }
  if (cert_ok && applied) {
    ++g_stats.certified_and_applied;
    const auto& ref = fx.states[parent.finalized_height + 1];
    if (out.state_commitment != ref.state_commitment ||
        consensus::frontier_utxo_state_root(out.utxos) != consensus::frontier_utxo_state_root(ref.utxos)) {
      fail("certified transition applied to a non-reference post-state", in.size());
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  run_one(Bytes(data, data + size));
  return 0;
}

#ifndef FINALIS_LIBFUZZER
int main(int argc, char** argv) {
  if (argc > 1) {
    for (int i = 1; i < argc; ++i) {
      std::ifstream in(argv[i], std::ios::binary);
      if (!in.good()) continue;
      Bytes b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      run_one(b);
    }
    return 0;
  }

  // The unmutated reference chain must certify and apply, then random mutations.
  for (std::uint8_t h = 0; h < kHeights; ++h) run_one(Bytes{h, 1});
  if (g_stats.certified_and_applied != kHeights) {
    std::cerr << "fuzz_sync: reference chain did not certify and apply\n";
    return 1;
  }
  std::mt19937_64 rng(0x53594E43ULL);
  std::uniform_int_distribution<int> len_dist(2, 64);
  for (int i = 0; i < 3000; ++i) {
    const int n = len_dist(rng);
    Bytes b(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) b[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(rng() & 0xFFu);
    run_one(b);
  }
  std::cout << "fuzz_sync done cert_ok=" << g_stats.cert_ok << " applied=" << g_stats.applied
            << " certified_and_applied=" << g_stats.certified_and_applied << "\n";
  return 0;
}
#endif
