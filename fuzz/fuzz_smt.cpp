// SPDX-License-Identifier: MIT

// Differential fuzzer for the incremental UTXO commitment tree. The input is a script of update
// batches applied to crypto::PersistentSmt and to a std::map model. After every batch:
//   - root() equals SparseMerkleTree::compute_root_from_leaves over the model (the full rebuild),
//   - size() equals the model size,
//   - proofs for every touched key verify with the model value (or as non-membership), and fail
//     with a different value,
//   - the SMT delta codec round-trips the batch.
// At the end every earlier version still has its original root (structure sharing must not mutate
// old versions), and from_leaf_hashes over the model gives the same root as the incremental tree.
//
// Keys are drawn from a few base keys with one fuzzer-chosen bit flipped, or taken raw from the
// input, so long shared prefixes and single-bit splits are the common case.
//
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/); otherwise a
// standalone smoke binary.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <random>
#include <vector>

#include "crypto/hash.hpp"
#include "crypto/smt.hpp"

using namespace finalis;

namespace {

[[noreturn]] void fail(const char* what, std::size_t size) {
  std::cerr << "fuzz_smt: " << what << " size=" << size << "\n";
  std::abort();
}

struct Reader {
  const Bytes& b;
  std::size_t pos{0};
  bool empty() const { return pos >= b.size(); }
  std::uint8_t u8() { return pos < b.size() ? b[pos++] : 0; }
};

const std::vector<Hash32>& base_keys() {
  static const std::vector<Hash32> keys = [] {
    std::vector<Hash32> out;
    for (std::uint8_t i = 0; i < 4; ++i) out.push_back(crypto::sha256(Bytes{0x53, 0x4D, 0x54, i}));
    return out;
  }();
  return keys;
}

Hash32 read_key(Reader& r) {
  const std::uint8_t sel = r.u8();
  Hash32 k{};
  if (sel & 0x80u) {
    for (auto& byte : k) byte = r.u8();
    return k;
  }
  k = base_keys()[sel & 3u];
  if (sel & 0x04u) {
    const std::uint8_t bit = r.u8();
    k[bit / 8] ^= static_cast<std::uint8_t>(0x80u >> (bit % 8));
  }
  return k;
}

Hash32 root_of(const std::map<Hash32, Bytes>& model) {
  return crypto::SparseMerkleTree::compute_root_from_leaves({model.begin(), model.end()});
}

void run_one(const Bytes& in) {
  // The delta codec is also fed raw bytes: anything it accepts must survive a re-encode.
  if (auto d = crypto::decode_smt_delta(in); d.has_value()) {
    auto again = crypto::decode_smt_delta(crypto::encode_smt_delta(*d));
    if (!again.has_value() || *again != *d) fail("raw delta round trip", in.size());
  }

  Reader r{in};
  std::map<Hash32, Bytes> model;
  crypto::PersistentSmt tree;
  std::vector<std::pair<crypto::PersistentSmt, Hash32>> versions;
  versions.push_back({tree, tree.root()});

  for (int batch = 0; batch < 32 && !r.empty(); ++batch) {
    std::vector<crypto::SmtChange> changes;
    std::vector<Hash32> touched;
    const int n = 1 + r.u8() % 8;
    for (int i = 0; i < n && !r.empty(); ++i) {
      const std::uint8_t op = r.u8();
      const Hash32 k = read_key(r);
      touched.push_back(k);
      if (op % 3 == 0) {
        model.erase(k);
        changes.push_back({k, std::nullopt});
      } else {
        Bytes val(1 + op % 3);
        for (auto& byte : val) byte = r.u8();
        model[k] = val;
        changes.push_back({k, crypto::SparseMerkleTree::leaf_hash(k, val)});
      }
    }

    tree = tree.updated(changes);
    const Hash32 root = tree.root();
    if (root != root_of(model)) fail("incremental root != full rebuild", in.size());
    if (tree.size() != model.size()) fail("size mismatch", in.size());

    for (const auto& k : touched) {
      const auto proof = tree.proof(k);
      const auto it = model.find(k);
      const std::optional<Bytes> value = it == model.end() ? std::nullopt : std::optional<Bytes>(it->second);
      if (!crypto::SparseMerkleTree::verify_proof(root, k, value, proof)) fail("valid proof rejected", in.size());
      Bytes wrong = value.value_or(Bytes{});
      wrong.push_back(0xEE);
      if (crypto::SparseMerkleTree::verify_proof(root, k, wrong, proof)) fail("proof accepted wrong value", in.size());
      if (value.has_value() && crypto::SparseMerkleTree::verify_proof(root, k, std::nullopt, proof)) {
        fail("membership proof accepted as absence", in.size());
      }
    }

    auto decoded = crypto::decode_smt_delta(crypto::encode_smt_delta(changes));
    if (!decoded.has_value() || *decoded != changes) fail("delta round trip", in.size());

    versions.push_back({tree, root});
  }

  for (const auto& [old, root] : versions) {
    if (old.root() != root) fail("old version root changed", in.size());
  }
  std::vector<std::pair<Hash32, Hash32>> hashes;
  for (const auto& [k, val] : model) hashes.push_back({k, crypto::SparseMerkleTree::leaf_hash(k, val)});
  if (crypto::PersistentSmt::from_leaf_hashes(hashes).root() != tree.root()) {
    fail("from_leaf_hashes root != incremental root", in.size());
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

  std::mt19937_64 rng(0x534D5446ULL);
  std::uniform_int_distribution<int> len_dist(0, 2048);
  for (int i = 0; i < 300; ++i) {
    const int n = len_dist(rng);
    Bytes b(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) b[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(rng() & 0xFFu);
    run_one(b);
  }
  std::cout << "fuzz_smt done\n";
  return 0;
}
#endif
