// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"

// Signed release manifests (docs/spec/SIGNALED_ACTIVATION.md §9, docs/operations/UPDATER.md). Not
// consensus: what code a node runs is decided by its operator's trust policy, when rules switch by the
// chain (signaled activation).
//
// Manifest (canonical text, one field per line, '\n' line ends, nothing else):
//   finalis-release-manifest v1
//   version <MAJOR.MINOR.PATCH>
//   network <name>
//   rules_fingerprint <text without spaces, or ->
//   upgrade <64 hex>            zero or more, ascending, unique
//   artifact <64 hex> <name>    one or more, ascending by name, unique; name is [A-Za-z0-9._+-]
// Signatures file: lines "sig <pubkey 64 hex> <sig 128 hex>". Each signs release_signing_message.
// Trust policy: "threshold <n>" then "key <pubkey 64 hex> [label]" lines. A release is trusted when at
// least `threshold` distinct policy keys signed it. Raising the threshold or adding keys changes only
// this file, never the manifest format.
namespace finalis {

struct ReleaseArtifact {
  std::string name;
  Hash32 sha256{};
};

struct ReleaseManifest {
  std::string version;
  std::string network;
  std::string rules_fingerprint{"-"};
  std::vector<Hash32> upgrades;
  std::vector<ReleaseArtifact> artifacts;
};

struct ReleaseSignature {
  PubKey32 pubkey{};
  Sig64 sig{};
};

struct ReleaseTrustKey {
  PubKey32 pubkey{};
  std::string label;
};

struct ReleaseTrustPolicy {
  std::size_t threshold{0};
  std::vector<ReleaseTrustKey> keys;
};

// Sorts upgrades and artifacts into canonical order. False if a field is invalid or duplicated.
bool canonicalize_release_manifest(ReleaseManifest* m, std::string* err);
std::string serialize_release_manifest(const ReleaseManifest& m);
// Strict: the text must be exactly the canonical serialization of what it parses to.
std::optional<ReleaseManifest> parse_release_manifest(const std::string& text, std::string* err);

// What a release key signs: a domain tag and the exact manifest text.
Bytes release_signing_message(const std::string& manifest_text);

std::string serialize_release_signatures(const std::vector<ReleaseSignature>& sigs);
std::optional<std::vector<ReleaseSignature>> parse_release_signatures(const std::string& text, std::string* err);

std::optional<ReleaseTrustPolicy> parse_release_trust_policy(const std::string& text, std::string* err);

struct ReleaseVerification {
  bool ok{false};
  std::size_t valid_signers{0};  // distinct policy keys with a valid signature
  std::string error;
};
// The manifest text must parse canonically, and at least policy.threshold distinct policy keys must
// have signed it. Signatures by keys outside the policy, invalid ones and repeats do not count.
ReleaseVerification verify_release_manifest(const std::string& manifest_text, const std::vector<ReleaseSignature>& sigs,
                                            const ReleaseTrustPolicy& policy);

// MAJOR.MINOR.PATCH, optional leading 'v'.
std::optional<std::array<std::uint64_t, 3>> parse_release_version(const std::string& v);
// <0, 0, >0 like strcmp; nullopt if either is not a version.
std::optional<int> compare_release_versions(const std::string& a, const std::string& b);

}  // namespace finalis
