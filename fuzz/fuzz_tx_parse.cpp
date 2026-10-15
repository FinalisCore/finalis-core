// SPDX-License-Identifier: MIT

// Transaction decoders (Tx, TxV2 with confidential outputs and proofs, and the parse_any_tx
// dispatcher the node uses on ingress). Every accepted input must re-encode to bytes that parse
// back to the same transaction with the same txid.
//
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/); otherwise a
// standalone smoke binary that replays files given as arguments or runs a fixed random loop.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>

#include "utxo/confidential_tx.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

namespace {

[[noreturn]] void fail(const char* what, std::size_t size) {
  std::cerr << "fuzz_tx_parse: " << what << " size=" << size << "\n";
  std::abort();
}

template <class T>
void check_roundtrip(const Bytes& in, const char* what) {
  auto tx = T::parse(in);
  if (!tx.has_value()) return;
  const Bytes enc = tx->serialize();
  auto again = T::parse(enc);
  if (!again.has_value() || again->serialize() != enc || again->txid() != tx->txid()) {
    fail(what, in.size());
  }
}

void run_one(const Bytes& in) {
  check_roundtrip<Tx>(in, "Tx round trip");
  check_roundtrip<TxV2>(in, "TxV2 round trip");
  if (auto any = parse_any_tx(in); any.has_value()) {
    const Bytes enc = serialize_any_tx(*any);
    auto again = parse_any_tx(enc);
    if (!again.has_value() || serialize_any_tx(*again) != enc || txid_any(*again) != txid_any(*any)) {
      fail("AnyTx round trip", in.size());
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

  std::mt19937_64 rng(0x53435458ULL);
  std::uniform_int_distribution<int> len_dist(0, 4096);
  for (int i = 0; i < 20000; ++i) {
    const int n = len_dist(rng);
    Bytes b(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) b[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(rng() & 0xFFu);
    run_one(b);
  }
  std::cout << "fuzz_tx_parse done\n";
  return 0;
}
#endif
