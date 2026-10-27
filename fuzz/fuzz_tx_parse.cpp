// SPDX-License-Identifier: MIT

// Transaction decoders (Tx, TxV2 with confidential outputs and proofs, and the parse_any_tx
// dispatcher the node uses on ingress). Every accepted input must re-encode to bytes that parse
// back to the same transaction with the same txid. Also the time-lock decoders: TxTimed, its SWE
// ciphertext and well-formedness proof, sealed bodies (transfer or reveal), early-time-signature
// slashing evidence and SCDATA01 data scripts; those must re-encode to the input (a transfer body,
// like AnyTx, to a stable encoding).
//
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/); otherwise a
// standalone smoke binary that replays files given as arguments or runs a fixed random loop.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>

#include "codec/bytes.hpp"
#include "crypto/swe.hpp"
#include "crypto/swe_proofs.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/tx.hpp"
#include "utxo/validate.hpp"

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

// Decoders whose accepted inputs are canonical: re-encoding gives back the input.
void run_time_lock_decoders(const Bytes& in) {
  if (auto ct = crypto::SweCiphertext::parse(in); ct.has_value() && ct->serialize() != in) {
    fail("SweCiphertext not canonical", in.size());
  }
  if (auto proof = crypto::SweWellFormednessProof::parse(in); proof.has_value() && proof->serialize() != in) {
    fail("SweWellFormednessProof not canonical", in.size());
  }
  if (auto body = parse_timed_body(in); body.has_value()) {
    // A reveal is canonical; a transfer re-encodes stably (as AnyTx above).
    const Bytes enc = serialize_timed_body(*body);
    auto again = parse_timed_body(enc);
    if (!again.has_value() || serialize_timed_body(*again) != enc ||
        (std::holds_alternative<TimedReveal>(*body) && enc != in)) {
      fail("timed body round trip", in.size());
    }
  }
  EarlyTimeSignatureEvidence evidence;
  if (parse_early_time_signature_script_sig(in, &evidence)) {
    codec::ByteWriter w;
    w.bytes(Bytes{'S', 'C', 'T', 'S', 'L', 'A', 'S', 'H'});
    w.varbytes(evidence.raw_blob);
    if (w.take() != in || evidence.raw_blob.size() != 8 + crypto::kBlsSignatureBytes) {
      fail("time slash evidence not canonical", in.size());
    }
  }
  Bytes data;
  if (is_data_output_script(in, &data)) {
    const auto again = data_output_script_pubkey(data);
    if (!again.has_value() || *again != in) fail("data script not canonical", in.size());
  }
}

void run_one(const Bytes& in) {
  check_roundtrip<Tx>(in, "Tx round trip");
  check_roundtrip<TxV2>(in, "TxV2 round trip");
  check_roundtrip<TxTimed>(in, "TxTimed round trip");
  run_time_lock_decoders(in);
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
