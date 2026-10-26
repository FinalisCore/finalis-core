// SPDX-License-Identifier: MIT

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <thread>

#include "node/node.hpp"
#include "common/version.hpp"

using finalis::node::Node;

namespace {
constexpr int kExitOperatorActionRequired = 78;  // EX_CONFIG
// A safety-critical write failed and the node fail-stopped. Restartable: the restart reloads the
// consensus safety state from disk.
constexpr int kExitSafetyStorageFailed = 75;  // EX_TEMPFAIL
// Bound on shutdown after fail-stop; DB close can block after an ENOSPC WAL failure.
constexpr auto kFailStopShutdownBound = std::chrono::seconds(30);
volatile std::sig_atomic_t g_stop = 0;
void on_sigint(int) { g_stop = 1; }
}  // namespace

int main(int argc, char** argv) {
  if (argc >= 2) {
    const std::string arg1 = argv[1];
    if (arg1 == "--version" || arg1 == "version") {
      std::cout << finalis::node_software_version() << "\n";
      return 0;
    }
  }

#ifndef SC_HAS_ROCKSDB
  // Built with FINALIS_ALLOW_FILE_BACKEND (see CMakeLists.txt): that storage is not crash-durable,
  // so a validator's vote locks and finalized state could be lost or torn.
  std::cerr << "finalis-node was built without RocksDB (non-durable file backend, fuzz/test only); refusing to start\n";
  return kExitOperatorActionRequired;
#endif
  auto cfg = finalis::node::parse_args(argc, argv);
  if (!cfg.has_value()) {
    std::cerr << "usage: finalis-node [--testnet] [--node-id <id>] [--db <dir>] [--genesis <path>] [--allow-unsafe-genesis-override] [--unsafe-discard-vote-lock-at-height <h>] [--port <p>] "
                 "[--validator-key-file <path>] [--validator-passphrase <pass>] [--validator-passphrase-env <ENV>] [--allow-unencrypted-keystore] "
                 "[--public] [--listen] [--bind <ip>] [--with-lightserver] [--lightserver-bind <ip>] "
                 "[--lightserver-port <p>] [--lightserver-admin-socket <path>] [--lightserver-trusted-proxy <cidrs>] [--outbound-target <n>] [--dns-seeds|--no-dns-seeds] "
                 "[--peers host:port,...] [--seeds host:port,...] [--disable-p2p] [--acknowledge-emergency-fallback] [--no-reindex] [--no-fast-start] [--log-json] "
                 "[--handshake-timeout-ms <ms>] [--frame-timeout-ms <ms>] [--idle-timeout-ms <ms>] "
                 "[--peer-queue-max-bytes <n>] [--peer-queue-max-msgs <n>] [--max-inbound <n>] [--ban-seconds <s>] "
                 "[--invalid-frame-ban-threshold <n>] [--invalid-frame-window-seconds <s>] "
                 "[--min-relay-fee <sats>] [--hashcash-enabled] [--hashcash-base-bits <n>] [--hashcash-max-bits <n>] "
                 "[--hashcash-epoch-seconds <n>] [--hashcash-fee-exempt-min <sats>] "
                 "[--hashcash-pressure-tx-threshold <n>] [--hashcash-pressure-step-txs <n>] "
                 "[--hashcash-pressure-bits-per-step <n>] [--hashcash-large-tx-bytes <n>] "
                 "[--hashcash-large-tx-extra-bits <n>] "
                 "[--validator-min-bond <u64>] [--validator-warmup-blocks <n>] [--validator-cooldown-blocks <n>] "
                 "[--validator-join-limit-window-blocks <n>] [--validator-join-limit-max-new <n>] "
                 "[--liveness-window-blocks <n>] [--miss-rate-suspend-threshold-percent <n>] "
                 "[--miss-rate-exit-threshold-percent <n>] [--suspend-duration-blocks <n>] "
                 "(default live path: frontier-only finalized-checkpoint operator-aggregated committees)\n";
    return 1;
  }

  Node node(*cfg);
  if (!node.init()) {
    std::cerr << "node init failed\n";
    // Distinct code so service managers stop restarting (systemd RestartPreventExitStatus=78).
    return node.init_requires_operator_action() ? kExitOperatorActionRequired : 1;
  }
  node.start();

  std::signal(SIGINT, on_sigint);
  std::signal(SIGTERM, on_sigint);

  while (!g_stop && !node.safety_storage_failed()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  if (node.safety_storage_failed()) {
    std::cerr << "CRITICAL safety-critical storage write failed; node stopped signing and is shutting down "
                 "(exit "
              << kExitSafetyStorageFailed << "); see the log for the failed operation\n";
    // Ends the process if stop() blocks; nothing after the failure needs to reach disk.
    std::thread([] {
      std::this_thread::sleep_for(kFailStopShutdownBound);
      std::cerr << "CRITICAL fail-stop shutdown exceeded " << kFailStopShutdownBound.count() << "s; exiting\n";
      std::_Exit(kExitSafetyStorageFailed);
    }).detach();
    node.stop();
    return kExitSafetyStorageFailed;
  }
  node.stop();
  return 0;
}
