// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "p2p/framing.hpp"

using namespace finalis;

namespace {

// An accepted frame must re-encode to bytes that decode back to the same encoding.
void run_one(const Bytes& in) {
  auto f = p2p::decode_frame(in);
  if (!f.has_value()) return;
  const Bytes enc = p2p::encode_frame(*f);
  auto again = p2p::decode_frame(enc);
  if (!again.has_value() || p2p::encode_frame(*again) != enc) {
    std::cerr << "fuzz_p2p_frame: frame round trip size=" << in.size() << "\n";
    std::abort();
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

  std::mt19937_64 rng(0x53434F49ULL);
  std::uniform_int_distribution<int> len_dist(0, 2048);
  for (int i = 0; i < 20000; ++i) {
    const int n = len_dist(rng);
    Bytes b(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) b[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(rng() & 0xFFu);
    run_one(b);
  }
  std::cout << "fuzz_p2p_frame done\n";
  return 0;
}
#endif
