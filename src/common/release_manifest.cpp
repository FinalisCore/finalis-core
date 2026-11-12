// SPDX-License-Identifier: MIT

#include "common/release_manifest.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <sstream>

#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"

namespace finalis {
namespace {

constexpr const char* kManifestHeader = "finalis-release-manifest v1";
constexpr const char* kSigningDomain = "FINALIS-RELEASE-MANIFEST-V1";

bool fail(std::string* err, const std::string& why) {
  if (err) *err = why;
  return false;
}

bool is_lower_hex(const std::string& s, std::size_t len) {
  return s.size() == len && std::all_of(s.begin(), s.end(), [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}

template <std::size_t N>
std::optional<std::array<std::uint8_t, N>> fixed_hex(const std::string& s) {
  if (!is_lower_hex(s, 2 * N)) return std::nullopt;
  const auto b = hex_decode(s);
  if (!b || b->size() != N) return std::nullopt;
  std::array<std::uint8_t, N> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

bool valid_token(const std::string& s) {
  return !s.empty() && s.size() <= 128 &&
         std::all_of(s.begin(), s.end(), [](char c) { return c > 0x20 && c < 0x7f; });
}

bool valid_artifact_name(const std::string& s) {
  return !s.empty() && s.size() <= 128 && s != "." && s != ".." && std::all_of(s.begin(), s.end(), [](char c) {
           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                  c == '-' || c == '+';
         });
}

// Splits text into lines; false if it does not end with '\n' or holds '\r' or an empty line.
bool split_lines(const std::string& text, std::vector<std::string>* out, std::string* err) {
  if (text.empty() || text.back() != '\n') return fail(err, "text must end with a newline");
  if (text.find('\r') != std::string::npos) return fail(err, "carriage return not allowed");
  std::size_t start = 0;
  while (start < text.size()) {
    const auto end = text.find('\n', start);
    if (end == start) return fail(err, "empty line not allowed");
    out->push_back(text.substr(start, end - start));
    start = end + 1;
  }
  return true;
}

std::vector<std::string> fields(const std::string& line) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= line.size()) {
    const auto end = line.find(' ', start);
    out.push_back(line.substr(start, end == std::string::npos ? std::string::npos : end - start));
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return out;
}

}  // namespace

bool canonicalize_release_manifest(ReleaseManifest* m, std::string* err) {
  if (!parse_release_version(m->version)) return fail(err, "version must be MAJOR.MINOR.PATCH");
  if (!valid_token(m->network)) return fail(err, "invalid network");
  if (!valid_token(m->rules_fingerprint)) return fail(err, "invalid rules_fingerprint");
  if (m->artifacts.empty()) return fail(err, "no artifacts");
  std::sort(m->upgrades.begin(), m->upgrades.end());
  if (std::adjacent_find(m->upgrades.begin(), m->upgrades.end()) != m->upgrades.end()) {
    return fail(err, "duplicate upgrade");
  }
  std::sort(m->artifacts.begin(), m->artifacts.end(),
            [](const ReleaseArtifact& a, const ReleaseArtifact& b) { return a.name < b.name; });
  for (std::size_t i = 0; i < m->artifacts.size(); ++i) {
    if (!valid_artifact_name(m->artifacts[i].name)) return fail(err, "invalid artifact name: " + m->artifacts[i].name);
    if (i > 0 && m->artifacts[i].name == m->artifacts[i - 1].name) return fail(err, "duplicate artifact");
  }
  return true;
}

std::string serialize_release_manifest(const ReleaseManifest& m) {
  std::ostringstream o;
  o << kManifestHeader << "\n"
    << "version " << m.version << "\n"
    << "network " << m.network << "\n"
    << "rules_fingerprint " << m.rules_fingerprint << "\n";
  for (const auto& u : m.upgrades) o << "upgrade " << hex_encode32(u) << "\n";
  for (const auto& a : m.artifacts) o << "artifact " << hex_encode32(a.sha256) << " " << a.name << "\n";
  return o.str();
}

std::optional<ReleaseManifest> parse_release_manifest(const std::string& text, std::string* err) {
  std::vector<std::string> lines;
  if (!split_lines(text, &lines, err)) return std::nullopt;
  if (lines.size() < 5 || lines[0] != kManifestHeader) {
    fail(err, "not a v1 release manifest");
    return std::nullopt;
  }
  ReleaseManifest m;
  const auto keyed = [&](std::size_t i, const char* key, std::string* value) {
    const auto f = fields(lines[i]);
    if (f.size() != 2 || f[0] != key) return fail(err, std::string("expected ") + key + " on line " + std::to_string(i + 1));
    *value = f[1];
    return true;
  };
  if (!keyed(1, "version", &m.version) || !keyed(2, "network", &m.network) ||
      !keyed(3, "rules_fingerprint", &m.rules_fingerprint)) {
    return std::nullopt;
  }
  for (std::size_t i = 4; i < lines.size(); ++i) {
    const auto f = fields(lines[i]);
    if (f.size() == 2 && f[0] == "upgrade") {
      const auto id = fixed_hex<32>(f[1]);
      if (!id) {
        fail(err, "invalid upgrade id on line " + std::to_string(i + 1));
        return std::nullopt;
      }
      m.upgrades.push_back(*id);
    } else if (f.size() == 3 && f[0] == "artifact") {
      const auto h = fixed_hex<32>(f[1]);
      if (!h) {
        fail(err, "invalid artifact hash on line " + std::to_string(i + 1));
        return std::nullopt;
      }
      m.artifacts.push_back(ReleaseArtifact{f[2], *h});
    } else {
      fail(err, "unexpected line " + std::to_string(i + 1));
      return std::nullopt;
    }
  }
  auto canonical = m;
  if (!canonicalize_release_manifest(&canonical, err)) return std::nullopt;
  if (serialize_release_manifest(canonical) != text) {
    fail(err, "manifest is not in canonical form");
    return std::nullopt;
  }
  return canonical;
}

Bytes release_signing_message(const std::string& manifest_text) {
  Bytes msg(kSigningDomain, kSigningDomain + std::char_traits<char>::length(kSigningDomain));
  msg.push_back(0);
  msg.insert(msg.end(), manifest_text.begin(), manifest_text.end());
  const auto digest = crypto::sha256d(msg);
  return Bytes(digest.begin(), digest.end());
}

std::string serialize_release_signatures(const std::vector<ReleaseSignature>& sigs) {
  std::ostringstream o;
  for (const auto& s : sigs) {
    o << "sig " << hex_encode32(s.pubkey) << " " << hex_encode(Bytes(s.sig.begin(), s.sig.end())) << "\n";
  }
  return o.str();
}

std::optional<std::vector<ReleaseSignature>> parse_release_signatures(const std::string& text, std::string* err) {
  std::vector<std::string> lines;
  if (!split_lines(text, &lines, err)) return std::nullopt;
  std::vector<ReleaseSignature> out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    const auto f = fields(lines[i]);
    const auto pub = f.size() == 3 && f[0] == "sig" ? fixed_hex<32>(f[1]) : std::nullopt;
    const auto sig = pub ? fixed_hex<64>(f[2]) : std::nullopt;
    if (!sig) {
      fail(err, "invalid signature line " + std::to_string(i + 1));
      return std::nullopt;
    }
    out.push_back(ReleaseSignature{*pub, *sig});
  }
  return out;
}

std::optional<ReleaseTrustPolicy> parse_release_trust_policy(const std::string& text, std::string* err) {
  std::vector<std::string> lines;
  if (!split_lines(text, &lines, err)) return std::nullopt;
  ReleaseTrustPolicy p;
  bool have_threshold = false;
  std::set<PubKey32> seen;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (lines[i][0] == '#') continue;
    const auto f = fields(lines[i]);
    if (f.size() == 2 && f[0] == "threshold" && !have_threshold) {
      if (f[1].empty() || f[1].size() > 3 || !std::all_of(f[1].begin(), f[1].end(), ::isdigit)) {
        fail(err, "invalid threshold");
        return std::nullopt;
      }
      p.threshold = static_cast<std::size_t>(std::stoul(f[1]));
      have_threshold = true;
    } else if ((f.size() == 2 || f.size() == 3) && f[0] == "key") {
      const auto pub = fixed_hex<32>(f[1]);
      if (!pub || !seen.insert(*pub).second) {
        fail(err, "invalid or duplicate key on line " + std::to_string(i + 1));
        return std::nullopt;
      }
      p.keys.push_back(ReleaseTrustKey{*pub, f.size() == 3 ? f[2] : std::string{}});
    } else {
      fail(err, "unexpected line " + std::to_string(i + 1));
      return std::nullopt;
    }
  }
  if (!have_threshold || p.threshold == 0 || p.threshold > p.keys.size()) {
    fail(err, "threshold must be between 1 and the number of keys");
    return std::nullopt;
  }
  return p;
}

ReleaseVerification verify_release_manifest(const std::string& manifest_text, const std::vector<ReleaseSignature>& sigs,
                                            const ReleaseTrustPolicy& policy) {
  ReleaseVerification r;
  std::string err;
  if (!parse_release_manifest(manifest_text, &err)) {
    r.error = "manifest invalid: " + err;
    return r;
  }
  if (policy.threshold == 0 || policy.threshold > policy.keys.size()) {
    r.error = "trust policy invalid";
    return r;
  }
  std::set<PubKey32> trusted;
  for (const auto& k : policy.keys) trusted.insert(k.pubkey);
  const auto msg = release_signing_message(manifest_text);
  std::set<PubKey32> valid;
  for (const auto& s : sigs) {
    if (trusted.count(s.pubkey) == 0 || valid.count(s.pubkey) != 0) continue;
    if (crypto::ed25519_verify(msg, s.sig, s.pubkey)) valid.insert(s.pubkey);
  }
  r.valid_signers = valid.size();
  r.ok = r.valid_signers >= policy.threshold;
  if (!r.ok) {
    r.error = "signed by " + std::to_string(r.valid_signers) + " of the required " + std::to_string(policy.threshold) +
              " trusted keys";
  }
  return r;
}

std::optional<std::array<std::uint64_t, 3>> parse_release_version(const std::string& v) {
  std::string s = !v.empty() && v[0] == 'v' ? v.substr(1) : v;
  std::array<std::uint64_t, 3> out{};
  std::size_t part = 0, start = 0;
  while (part < 3) {
    const auto end = s.find('.', start);
    const auto tok = s.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (tok.empty() || tok.size() > 9 || !std::all_of(tok.begin(), tok.end(), ::isdigit)) return std::nullopt;
    if (tok.size() > 1 && tok[0] == '0') return std::nullopt;
    out[part++] = std::stoull(tok);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  if (part != 3 || s.find('.', start) != std::string::npos ||
      std::count(s.begin(), s.end(), '.') != 2) {
    return std::nullopt;
  }
  return out;
}

std::optional<int> compare_release_versions(const std::string& a, const std::string& b) {
  const auto va = parse_release_version(a);
  const auto vb = parse_release_version(b);
  if (!va || !vb) return std::nullopt;
  if (*va < *vb) return -1;
  if (*vb < *va) return 1;
  return 0;
}

}  // namespace finalis
