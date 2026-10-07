// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <map>
#include <optional>
#include <string>

namespace {

// Live progress on the controlling terminal. ctest captures stdout/stderr (and with
// --output-on-failure only shows them after a failed run), so progress goes straight to
// /dev/tty instead: one line rewritten in place, failures kept on their own lines.
// No terminal (CI, redirected output) or FINALIS_TEST_PROGRESS=0: silently disabled.
class TtyProgress {
 public:
  TtyProgress() {
#ifndef _WIN32
    const char* env = std::getenv("FINALIS_TEST_PROGRESS");
    if (env == nullptr || std::string(env) != "0") tty_ = std::fopen("/dev/tty", "w");
#endif
  }
  ~TtyProgress() {
    if (!tty_) return;
    std::fputs("\r\033[2K", tty_);
    std::fclose(tty_);
  }
  TtyProgress(const TtyProgress&) = delete;
  TtyProgress& operator=(const TtyProgress&) = delete;

  void ok(const std::string& progress) {
    if (!tty_) return;
    std::fprintf(tty_, "\r\033[2K[ok %s]", progress.c_str());
    std::fflush(tty_);
  }
  void fail(const std::string& progress, const std::string& name, const std::string& what) {
    if (!tty_) return;
    std::fprintf(tty_, "\r\033[2K[fail %s] %s: %s\n", progress.c_str(), name.c_str(), what.c_str());
    std::fflush(tty_);
  }

 private:
  std::FILE* tty_{nullptr};
};

}  // namespace

std::vector<std::pair<std::string, TestFn>>& tests() {
  static std::vector<std::pair<std::string, TestFn>> t;
  return t;
}

Reg::Reg(const std::string& n, TestFn fn) { tests().push_back({n, std::move(fn)}); }

std::map<std::string, std::string>& test_tags() {
  static std::map<std::string, std::string> t;
  return t;
}

RegTags::RegTags(const std::string& n, const std::string& tags) { test_tags()[n] = tags; }

namespace {

int usage_error(const std::string& message) {
  std::cerr << "[tests] " << message << "\n"
            << "usage: finalis-tests [--list | --list-tags | --run <exact-test-name>]\n"
            << "  env: FINALIS_TEST_FILTER=<substring>, FINALIS_TEST_SHARD_INDEX/FINALIS_TEST_SHARD_COUNT\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
  if (std::getenv("FINALIS_TEST_QUIET_LOGS") == nullptr) {
    _putenv_s("FINALIS_TEST_QUIET_LOGS", "1");
  }
#else
  if (std::getenv("FINALIS_TEST_QUIET_LOGS") == nullptr) {
    setenv("FINALIS_TEST_QUIET_LOGS", "1", 1);
  }
#endif
  bool list = false;
  bool list_tags = false;
  std::optional<std::string> run_exact;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--list") {
      list = true;
    } else if (arg == "--list-tags") {
      list_tags = true;
    } else if (arg == "--run") {
      if (i + 1 >= argc) return usage_error("--run requires a test name");
      run_exact = argv[++i];
    } else {
      return usage_error("unknown argument: " + arg);
    }
  }

  // A tag for a name that is not a registered test is a typo; fail loudly instead of silently unlabelling.
  for (const auto& [name, tags] : test_tags()) {
    const bool known = std::any_of(tests().begin(), tests().end(), [&](const auto& t) { return t.first == name; });
    if (!known) return usage_error("TEST_TAGS for unknown test: " + name);
  }

  if (list || list_tags) {
    for (const auto& [name, fn] : tests()) {
      std::cout << name;
      if (list_tags) {
        auto it = test_tags().find(name);
        std::cout << '\t' << (it == test_tags().end() ? "" : it->second);
      }
      std::cout << '\n';
    }
    return 0;
  }

  int failed = 0;
  std::vector<std::string> failed_names;
  const char* filter = std::getenv("FINALIS_TEST_FILTER");
  const char* shard_index_env = std::getenv("FINALIS_TEST_SHARD_INDEX");
  const char* shard_count_env = std::getenv("FINALIS_TEST_SHARD_COUNT");
  const std::size_t shard_count = shard_count_env ? static_cast<std::size_t>(std::atoi(shard_count_env)) : 1;
  const std::size_t shard_index = shard_index_env ? static_cast<std::size_t>(std::atoi(shard_index_env)) : 0;

  std::vector<std::pair<std::string, TestFn>> selected;
  selected.reserve(tests().size());
  if (run_exact.has_value()) {
    filter = nullptr;
    auto it = std::find_if(tests().begin(), tests().end(), [&](const auto& t) { return t.first == *run_exact; });
    if (it == tests().end()) {
      std::cerr << "[tests] no test named " << *run_exact << "\n";
      return 2;
    }
    selected.push_back(*it);
  } else {
    std::size_t shard_counter = 0;
    for (const auto& [name, fn] : tests()) {
      if (filter && std::string(name).find(filter) == std::string::npos) continue;
      if (shard_count > 1 && (shard_counter++ % shard_count) != shard_index) continue;
      selected.push_back({name, fn});
    }
  }

  const std::size_t total = selected.size();
  std::cout << "[tests] total=" << total;
  if (filter) std::cout << " filter=\"" << filter << "\"";
  if (shard_count > 1 && !run_exact.has_value()) std::cout << " shard=" << shard_index << "/" << shard_count;
  std::cout << std::endl;

  TtyProgress tty_progress;
  std::size_t index = 0;
  for (const auto& [name, fn] : selected) {
    ++index;
    const std::string progress =
        std::to_string(index) + "/" + std::to_string(total) + " " + std::to_string(index * 100 / total) + "%";
    std::cout << "[run " << progress << "] " << name << std::endl;
    try {
      fn();
      std::cout << "[ok " << progress << "] " << name << "\n";
      tty_progress.ok(progress);
    } catch (const std::exception& e) {
      ++failed;
      failed_names.push_back(name);
      std::cout << "[fail " << progress << "] " << name << ": " << e.what() << "\n";
      tty_progress.fail(progress, name, e.what());
    }
  }
  if (failed) {
    std::cerr << "[failed-summary] count=" << failed << "\n";
    for (const auto& name : failed_names) {
      std::cerr << "[failed-summary] " << name << "\n";
    }
    std::cerr << failed << " tests failed\n";
    return 1;
  }
  std::cout << "all tests passed\n";
  return 0;
}
