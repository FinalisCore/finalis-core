// SPDX-License-Identifier: MIT

// Soundness fuzzer for the confidential-amount primitives. The first input byte picks a mode:
//   0  raw: commitment and range proof bytes straight from the input through every parser and
//      verifier (sanitizer findings only).
//   1  range-proof malleability: a valid proof for a fixed commitment is mutated (byte XORs,
//      truncation, appended bytes) or checked against a commitment to a different amount. Any
//      change must be rejected.
//   2  tally soundness: commitments to input amounts/blinds. verify_commitment_tally may accept
//      only when the amounts balance, must accept the balanced set whose last blind is
//      combine_blinds of the rest, and must agree with comparing the two CommitmentSums.
//
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/); otherwise a
// standalone smoke binary.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <random>
#include <vector>

#include "crypto/confidential.hpp"
#include "crypto/hash.hpp"

using namespace finalis;
using namespace finalis::crypto;

namespace {

[[noreturn]] void fail(const char* what, std::size_t size) {
  std::cerr << "fuzz_confidential: " << what << " size=" << size << "\n";
  std::abort();
}

struct Reader {
  const Bytes& b;
  std::size_t pos{0};
  bool empty() const { return pos >= b.size(); }
  std::uint8_t u8() { return pos < b.size() ? b[pos++] : 0; }
  std::uint32_t u32() {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | u8();
    return v;
  }
  template <class A>
  void fill(A& a) {
    for (auto& byte : a) byte = u8();
  }
};

constexpr std::uint64_t kFixedAmount = 1'234'567'890'123ULL;

struct Fixture {
  Blind32 blind;
  Commitment33 commitment;
  ProofBytes proof;
};

const Fixture& fixture() {
  static const Fixture f = [] {
    if (!confidential_crypto_init() || !confidential_backend_status().confidential_outputs_supported) {
      std::cerr << "fuzz_confidential: confidential backend unavailable\n";
      std::abort();
    }
    Fixture out;
    out.blind.bytes = sha256(Bytes{'f', 'u', 'z', 'z', 'b'});
    auto c = confidential_amount_commitment(kFixedAmount, out.blind);
    auto p = c ? sign_output_range_proof(*c, kFixedAmount, out.blind, sha256(Bytes{'n', 'o', 'n', 'c', 'e'}))
               : std::nullopt;
    if (!p || !verify_output_range_proof(*c, *p) || !range_proof_has_canonical_shape(*p)) {
      std::cerr << "fuzz_confidential: fixture proof does not verify\n";
      std::abort();
    }
    out.commitment = *c;
    out.proof = *p;
    return out;
  }();
  return f;
}

void run_raw(Reader& r, std::size_t size) {
  Commitment33 c;
  r.fill(c.bytes);
  ProofBytes p;
  p.bytes.assign(r.b.begin() + static_cast<std::ptrdiff_t>(std::min(r.pos, r.b.size())), r.b.end());
  (void)commitment_is_canonical(c);
  (void)commitment_is_identity(c);
  (void)range_proof_has_canonical_shape(p);
  const bool ok = verify_output_range_proof(c, p);
  if (ok != verify_output_range_proofs_batch(std::span<const Commitment33>(&c, 1), std::span<const ProofBytes>(&p, 1))) {
    fail("batch and single verify disagree", size);
  }
  CommitmentSum sum;
  (void)commitment_sum_add(&sum, c);
  (void)commitment_sum_add(&sum, fixture().commitment);
}

void run_malleability(Reader& r, std::size_t size) {
  const auto& f = fixture();
  ProofBytes p = f.proof;
  const std::uint8_t kind = r.u8();
  switch (kind % 4) {
    case 0:
    case 1: {
      const int n = 1 + r.u8() % 4;
      for (int i = 0; i < n; ++i) {
        const std::size_t off = ((static_cast<std::size_t>(r.u8()) << 8) | r.u8()) % p.bytes.size();
        p.bytes[off] ^= r.u8();
      }
      break;
    }
    case 2:
      p.bytes.resize(p.bytes.size() - 1 - r.u8() % p.bytes.size());
      break;
    case 3: {
      const int n = 1 + r.u8() % 8;
      for (int i = 0; i < n; ++i) p.bytes.push_back(r.u8());
      break;
    }
  }
  if (p != f.proof && verify_output_range_proof(f.commitment, p)) fail("mutated range proof accepted", size);

  const std::uint64_t delta = 1 + std::uint64_t{r.u32()};
  if (auto other = confidential_amount_commitment(kFixedAmount + delta, f.blind);
      other && verify_output_range_proof(*other, f.proof)) {
    fail("range proof accepted for another amount", size);
  }
}

struct Side {
  std::vector<std::uint64_t> amounts;
  std::vector<Blind32> blinds;
  std::vector<Commitment33> commitments;
};

std::optional<CommitmentSum> sum_of(const std::vector<Commitment33>& cs) {
  CommitmentSum s;
  for (const auto& c : cs) {
    if (!commitment_sum_add(&s, c)) return std::nullopt;
  }
  return s;
}

void check_tally(const Side& pos, const Side& neg, std::size_t size) {
  std::uint64_t sp = 0, sn = 0;
  for (auto a : pos.amounts) sp += a;
  for (auto a : neg.amounts) sn += a;
  const bool tally = verify_commitment_tally(pos.commitments, neg.commitments);
  if (tally && sp != sn) fail("tally accepted unbalanced amounts", size);
  const auto ps = sum_of(pos.commitments);
  const auto ns = sum_of(neg.commitments);
  if (!ps || !ns) fail("commitment_sum_add rejected a valid commitment", size);
  if ((*ps == *ns) != tally) fail("CommitmentSum and tally disagree", size);
}

bool add(Side& side, std::uint64_t amount, const Blind32& blind) {
  auto c = confidential_amount_commitment(amount, blind);
  if (!c) return false;
  side.amounts.push_back(amount);
  side.blinds.push_back(blind);
  side.commitments.push_back(*c);
  return true;
}

void run_tally(Reader& r, std::size_t size) {
  (void)fixture();
  Side pos, neg;
  const int npos = 1 + r.u8() % 4;
  const int nneg = r.u8() % 4;
  // Amounts are 32-bit so sums cannot wrap; a blind is a fixed scalar tweaked by one input byte
  // or taken raw, so equal and related blinds are common.
  const auto read_blind = [&] {
    Blind32 b;
    const std::uint8_t sel = r.u8();
    if (sel & 0x80u) {
      r.fill(b.bytes);
    } else {
      b.bytes = sha256(Bytes{'b', static_cast<std::uint8_t>(sel & 0x0Fu)});
    }
    return b;
  };
  for (int i = 0; i < npos; ++i) {
    const std::uint64_t a = r.u32();
    if (!add(pos, a, read_blind())) return;
  }
  for (int i = 0; i < nneg; ++i) {
    const std::uint64_t a = r.u32();
    if (!add(neg, a, read_blind())) return;
  }
  check_tally(pos, neg, size);

  // Balance it: the last negative takes the remaining amount and the blind that cancels the rest.
  std::uint64_t sp = 0, sn = 0;
  for (auto a : pos.amounts) sp += a;
  for (auto a : neg.amounts) sn += a;
  if (sp < sn) return;
  std::vector<Blind32> all = pos.blinds;
  all.insert(all.end(), neg.blinds.begin(), neg.blinds.end());
  const auto last_blind = combine_blinds(all, pos.blinds.size());
  if (!last_blind) return;
  Side balanced = neg;
  if (!add(balanced, sp - sn, *last_blind)) return;
  if (!verify_commitment_tally(pos.commitments, balanced.commitments)) fail("tally rejected balanced set", size);
  check_tally(pos, balanced, size);

  // Off by one in the amount must break it.
  Side off = neg;
  if (add(off, sp - sn + 1, *last_blind)) check_tally(pos, off, size);
}

void run_one(const Bytes& in) {
  if (in.empty()) return;
  Reader r{in, 1};
  switch (in[0] % 3) {
    case 0: run_raw(r, in.size()); break;
    case 1: run_malleability(r, in.size()); break;
    case 2: run_tally(r, in.size()); break;
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

  std::mt19937_64 rng(0x434F4E46ULL);
  std::uniform_int_distribution<int> len_dist(1, 256);
  for (int i = 0; i < 1500; ++i) {
    const int n = len_dist(rng);
    Bytes b(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) b[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(rng() & 0xFFu);
    run_one(b);
  }
  std::cout << "fuzz_confidential done\n";
  return 0;
}
#endif
