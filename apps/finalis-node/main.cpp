#include <csignal>
#include <iostream>
#include <thread>

#include "node/node.hpp"
#include "common/version.hpp"

using finalis::node::Node;

namespace {
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

  auto cfg = finalis::node::parse_args(argc, argv);
  if (!cfg.has_value()) {
    std::cerr << "usage: finalis-node [--node-id <id>] [--db <dir>] [--genesis <path>] [--allow-unsafe-genesis-override] [--port <p>] "
                 "[--validator-key-file <path>] [--validator-passphrase <pass>] [--validator-passphrase-env <ENV>] "
                 "[--public] [--listen] [--bind <ip>] [--with-lightserver] [--lightserver-bind <ip>] "
                 "[--lightserver-port <p>] [--outbound-target <n>] [--dns-seeds|--no-dns-seeds] "
                 "[--peers host:port,...] [--seeds host:port,...] [--disable-p2p] [--no-reindex] [--log-json] "
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
    return 1;
  }
  node.start();

  std::signal(SIGINT, on_sigint);
  std::signal(SIGTERM, on_sigint);

  while (!g_stop) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  node.stop();
  return 0;
}
