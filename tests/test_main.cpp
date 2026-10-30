// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "consensus/frontier_execution.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#ifndef _WIN32
#include <csignal>
#include <cstring>
#include <iterator>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

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

// Tests tagged "isolate" inject storage faults; a fault can abort the process inside librocksdb
// (tests/KNOWN_DEFECTS.md, E1). They run in a child process (this binary, `--run NAME`), so an
// abort fails that test with its signal instead of ending the whole run. POSIX only.
#ifndef _WIN32
bool has_tag(const std::string& name, const std::string& tag) {
  auto it = test_tags().find(name);
  if (it == test_tags().end()) return false;
  return ("," + it->second + ",").find("," + tag + ",") != std::string::npos;
}

// Runs `name` in a child; returns std::nullopt on success, else the failure message.
std::optional<std::string> run_isolated(const std::string& name, std::size_t index) {
  const std::string result_path = "/tmp/finalis-test-child-" + std::to_string(::getpid()) + "-" + std::to_string(index);
  std::remove(result_path.c_str());
  std::vector<std::string> env_storage;
  for (char** e = environ; *e; ++e) {
    if (std::strncmp(*e, "FINALIS_TEST_CHILD_RESULT=", 26) != 0) env_storage.emplace_back(*e);
  }
  env_storage.push_back("FINALIS_TEST_CHILD_RESULT=" + result_path);
  std::vector<char*> envp;
  for (auto& e : env_storage) envp.push_back(e.data());
  envp.push_back(nullptr);
  std::string self = "/proc/self/exe", arg0 = "finalis-tests", run = "--run", test = name;
  char* argv[] = {arg0.data(), run.data(), test.data(), nullptr};
  std::cout.flush();
  std::cerr.flush();
  pid_t pid = 0;
  if (posix_spawn(&pid, self.c_str(), nullptr, nullptr, argv, envp.data()) != 0) return std::string("posix_spawn failed");
  int status = 0;
  if (::waitpid(pid, &status, 0) < 0) return std::string("waitpid failed");
  std::string message;
  {
    std::ifstream in(result_path);
    message.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  }
  std::remove(result_path.c_str());
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return std::nullopt;
  if (WIFSIGNALED(status)) {
    const int sig = WTERMSIG(status);
    return "child process killed by signal " + std::to_string(sig) +
           (sig == SIGABRT ? " (SIGABRT; see the child's stderr above, e.g. an assertion inside librocksdb)" : "");
  }
  return message.empty() ? "child process exit " + std::to_string(WEXITSTATUS(status)) : message;
}
#endif


int usage_error(const std::string& message) {
  std::cerr << "[tests] " << message << "\n"
            << "usage: finalis-tests [--list | --list-tags | --run <exact-test-name>]\n"
            << "  env: FINALIS_TEST_FILTER=<substring>, FINALIS_TEST_SHARD_INDEX/FINALIS_TEST_SHARD_COUNT\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  // Every incrementally maintained UTXO root is checked against a full recomputation in tests.
  finalis::consensus::set_utxo_tree_crosscheck(true);
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

  // Tests tagged "known-defect" reproduce open production defects and fail until they are fixed
  // (tests/KNOWN_DEFECTS.md). Default: excluded, and counted in the header so they stay visible.
  // FINALIS_TEST_KNOWN_DEFECTS=only runs just them; =include runs everything. --run ignores this.
  const char* known_defects_env = std::getenv("FINALIS_TEST_KNOWN_DEFECTS");
  const std::string known_defects = known_defects_env ? known_defects_env : "exclude";
  if (known_defects != "exclude" && known_defects != "only" && known_defects != "include") {
    return usage_error("FINALIS_TEST_KNOWN_DEFECTS must be exclude, only or include");
  }
  const auto is_known_defect = [](const std::string& name) {
    auto it = test_tags().find(name);
    if (it == test_tags().end()) return false;
    const std::string tags = "," + it->second + ",";
    return tags.find(",known-defect,") != std::string::npos;
  };
  std::size_t known_defects_skipped = 0;

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
      const bool known = is_known_defect(name);
      if ((known && known_defects == "exclude") || (!known && known_defects == "only")) {
        if (known) ++known_defects_skipped;
        continue;
      }
      if (shard_count > 1 && (shard_counter++ % shard_count) != shard_index) continue;
      selected.push_back({name, fn});
    }
  }

  // Set when this process is an isolated child (see run_isolated): the parent prints the progress.
  const char* child_result = std::getenv("FINALIS_TEST_CHILD_RESULT");
  const std::size_t total = selected.size();
  if (!child_result) {
    std::cout << "[tests] total=" << total;
    if (filter) std::cout << " filter=\"" << filter << "\"";
    if (shard_count > 1 && !run_exact.has_value()) std::cout << " shard=" << shard_index << "/" << shard_count;
    if (known_defects != "exclude") std::cout << " known-defects=" << known_defects;
    std::cout << std::endl;
  }
  if (known_defects_skipped > 0) {
    std::cout << "[tests] skipped " << known_defects_skipped
              << " known-defect test(s); run them with FINALIS_TEST_KNOWN_DEFECTS=only (tests/KNOWN_DEFECTS.md)" << std::endl;
  }

  TtyProgress tty_progress;
  std::size_t index = 0;
  for (const auto& [name, fn] : selected) {
    ++index;
    const std::string progress =
        std::to_string(index) + "/" + std::to_string(total) + " " + std::to_string(index * 100 / total) + "%";
    if (!child_result) std::cout << "[run " << progress << "] " << name << std::endl;
#ifndef _WIN32
    if (!run_exact.has_value() && has_tag(name, "isolate")) {
      if (const auto err = run_isolated(name, index); err.has_value()) {
        ++failed;
        failed_names.push_back(name);
        std::cout << "[fail " << progress << "] " << name << ": " << *err << "\n";
        tty_progress.fail(progress, name, *err);
      } else {
        std::cout << "[ok " << progress << "] " << name << "\n";
        tty_progress.ok(progress);
      }
      continue;
    }
#endif
    try {
      fn();
      if (!child_result) std::cout << "[ok " << progress << "] " << name << "\n";
      tty_progress.ok(progress);
    } catch (const std::exception& e) {
      ++failed;
      failed_names.push_back(name);
      if (child_result) {
        std::ofstream(child_result) << e.what();
      } else {
        std::cout << "[fail " << progress << "] " << name << ": " << e.what() << "\n";
      }
      tty_progress.fail(progress, name, e.what());
    }
  }
  if (child_result) return failed ? 1 : 0;
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
