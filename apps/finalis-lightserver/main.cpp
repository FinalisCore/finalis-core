#include <csignal>
#include <chrono>
#include <iostream>
#include <thread>

#include "lightserver/server.hpp"
#include "common/version.hpp"

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_sigint(int) { g_stop = 1; }
}

int main(int argc, char** argv) {
  if (argc >= 2) {
    const std::string arg1 = argv[1];
    if (arg1 == "--version" || arg1 == "version") {
      std::cout << finalis::lightserver_software_version() << "\n";
      return 0;
    }
  }

  auto cfg = finalis::lightserver::parse_args(argc, argv);
  if (!cfg.has_value()) {
    std::cerr
        << "usage: finalis-lightserver [--db <dir>] [--bind 127.0.0.1] [--port <network-default>] "
           "[--relay-host 127.0.0.1] [--relay-port <node-p2p-default>] [--max-committee N]\n";
    return 1;
  }

  finalis::lightserver::Server s(*cfg);
  if (!s.init()) {
    std::cerr << "lightserver init failed\n";
    return 1;
  }
  if (!s.start()) {
    std::cerr << "lightserver start failed\n";
    return 1;
  }

  std::signal(SIGINT, on_sigint);
  std::signal(SIGTERM, on_sigint);
  while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(200));
  s.stop();
  return 0;
}
