// SPDX-License-Identifier: MIT

// finalis-updater (docs/operations/UPDATER.md, SIGNALED_ACTIVATION §9): verifies signed release
// manifests against the operator's trust policy. Notify mode only: it never installs anything.

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "common/release_manifest.hpp"
#include "common/version.hpp"
#include "crypto/hash.hpp"
#include "lightserver/client.hpp"

namespace {

constexpr const char* kDefaultTrustPath = "/etc/finalis/release-trust.txt";
constexpr std::size_t kMaxManifestBytes = 1 << 20;

std::optional<std::string> read_text(const std::string& path, std::string* err) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    *err = "cannot read " + path;
    return std::nullopt;
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

std::optional<finalis::Hash32> sha256_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;
  finalis::Bytes data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return finalis::crypto::sha256(data);
}

void usage() {
  std::cerr << "usage:\n"
            << "  finalis-updater verify --manifest <file> --sigs <file> [--trust " << kDefaultTrustPath
            << "] [--artifacts-dir <dir>]\n"
            << "  finalis-updater check --url <https://.../release-dir> [--trust " << kDefaultTrustPath
            << "] [--network mainnet] [--current <version>]\n"
            << "    fetches <url>/manifest.txt and <url>/manifest.sig, verifies them and reports whether a newer\n"
            << "    trusted release exists. Notify only: nothing is installed.\n";
}

// Prints the verification result; 0 when trusted.
int report_verification(const std::string& manifest_text, const std::string& sigs_text,
                        const finalis::ReleaseTrustPolicy& policy, finalis::ReleaseManifest* out) {
  std::string err;
  const auto sigs = finalis::parse_release_signatures(sigs_text, &err);
  if (!sigs) {
    std::cout << "trusted=no\nerror=" << err << "\n";
    return 1;
  }
  const auto v = finalis::verify_release_manifest(manifest_text, *sigs, policy);
  std::cout << "valid_signers=" << v.valid_signers << "\nthreshold=" << policy.threshold << "\n";
  if (!v.ok) {
    std::cout << "trusted=no\nerror=" << v.error << "\n";
    return 1;
  }
  *out = *finalis::parse_release_manifest(manifest_text, &err);
  std::cout << "trusted=yes\nversion=" << out->version << "\nnetwork=" << out->network
            << "\nrules_fingerprint=" << out->rules_fingerprint << "\n";
  for (const auto& u : out->upgrades) std::cout << "upgrade=" << finalis::hex_encode32(u) << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string cmd = argv[1];
  std::string trust_path = kDefaultTrustPath, manifest_path, sigs_path, artifacts_dir, url, network = "mainnet";
  std::string current = finalis::kReleaseVersion;
  for (int i = 2; i < argc; ++i) {
    const std::string a = argv[i];
    const auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : std::string{}; };
    if (a == "--trust") trust_path = next();
    else if (a == "--manifest") manifest_path = next();
    else if (a == "--sigs") sigs_path = next();
    else if (a == "--artifacts-dir") artifacts_dir = next();
    else if (a == "--url") url = next();
    else if (a == "--network") network = next();
    else if (a == "--current") current = next();
    else {
      usage();
      return 2;
    }
  }
  std::string err;
  const auto trust_text = read_text(trust_path, &err);
  if (!trust_text) {
    std::cerr << err << " (trust policy: threshold and release keys, see docs/operations/UPDATER.md)\n";
    return 2;
  }
  const auto policy = finalis::parse_release_trust_policy(*trust_text, &err);
  if (!policy) {
    std::cerr << "invalid trust policy " << trust_path << ": " << err << "\n";
    return 2;
  }

  if (cmd == "verify") {
    if (manifest_path.empty() || sigs_path.empty()) {
      usage();
      return 2;
    }
    const auto manifest_text = read_text(manifest_path, &err);
    const auto sigs_text = manifest_text ? read_text(sigs_path, &err) : std::nullopt;
    if (!sigs_text) {
      std::cerr << err << "\n";
      return 2;
    }
    finalis::ReleaseManifest m;
    if (report_verification(*manifest_text, *sigs_text, *policy, &m) != 0) return 1;
    if (artifacts_dir.empty()) return 0;
    bool all_ok = true;
    for (const auto& a : m.artifacts) {
      const auto path = (std::filesystem::path(artifacts_dir) / a.name).string();
      const auto h = sha256_file(path);
      const bool ok = h.has_value() && *h == a.sha256;
      std::cout << "artifact=" << a.name << " " << (h ? (ok ? "ok" : "hash-mismatch") : "missing") << "\n";
      all_ok = all_ok && ok;
    }
    std::cout << "artifacts=" << (all_ok ? "ok" : "failed") << "\n";
    return all_ok ? 0 : 1;
  }

  if (cmd == "check") {
    if (url.rfind("https://", 0) != 0) {
      std::cerr << "check needs an https:// --url\n";
      return 2;
    }
    while (!url.empty() && url.back() == '/') url.pop_back();
    const auto manifest_text = finalis::lightserver::http_get(url + "/manifest.txt", kMaxManifestBytes, &err);
    const auto sigs_text =
        manifest_text ? finalis::lightserver::http_get(url + "/manifest.sig", kMaxManifestBytes, &err) : std::nullopt;
    if (!sigs_text) {
      std::cout << "status=fetch-failed\nerror=" << err << "\n";
      return 1;
    }
    finalis::ReleaseManifest m;
    if (report_verification(*manifest_text, *sigs_text, *policy, &m) != 0) {
      std::cout << "status=untrusted\n";
      return 1;
    }
    if (m.network != network) {
      std::cout << "status=other-network\n";
      return 1;
    }
    const auto cmp = finalis::compare_release_versions(m.version, current);
    if (!cmp) {
      std::cout << "status=error\nerror=current version not MAJOR.MINOR.PATCH: " << current << "\n";
      return 2;
    }
    std::cout << "current=" << current << "\nstatus=" << (*cmp > 0 ? "update-available" : "up-to-date") << "\n";
    return 0;
  }

  usage();
  return 2;
}
