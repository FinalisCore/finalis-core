// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "common/release_manifest.hpp"
#include "crypto/ed25519.hpp"

using namespace finalis;

namespace {

crypto::KeyPair release_key(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  return *crypto::keypair_from_seed32(seed);
}

ReleaseSignature sign(const std::string& manifest_text, const crypto::KeyPair& kp) {
  return ReleaseSignature{kp.public_key, *crypto::ed25519_sign(release_signing_message(manifest_text), kp.private_key)};
}

std::string sample_manifest_text() {
  ReleaseManifest m;
  m.version = "2.3.0";
  m.network = "mainnet";
  Hash32 h1{}, h2{}, up{};
  h1.fill(0x11);
  h2.fill(0x22);
  up.fill(0x33);
  m.artifacts = {ReleaseArtifact{"finalis-node", h1}, ReleaseArtifact{"finalis-cli", h2}};  // unsorted on purpose
  m.upgrades = {up};
  std::string err;
  ASSERT_TRUE(canonicalize_release_manifest(&m, &err));
  return serialize_release_manifest(m);
}

ReleaseTrustPolicy policy_of(std::size_t threshold, const std::vector<const crypto::KeyPair*>& keys) {
  ReleaseTrustPolicy p;
  p.threshold = threshold;
  for (const auto* k : keys) p.keys.push_back(ReleaseTrustKey{k->public_key, ""});
  return p;
}

}  // namespace

// The manifest has one canonical text: parse(serialize(m)) == m, and any other spelling of the same
// content is rejected, so a signature covers exactly one meaning.
TEST(test_release_manifest_is_canonical_text) {
  const auto text = sample_manifest_text();
  std::string err;
  const auto m = parse_release_manifest(text, &err);
  ASSERT_TRUE(m.has_value());
  ASSERT_EQ(m->artifacts.size(), 2u);
  ASSERT_EQ(m->artifacts[0].name, std::string("finalis-cli"));  // sorted by name
  ASSERT_EQ(serialize_release_manifest(*m), text);
  ASSERT_TRUE(text.rfind("finalis-release-manifest v1\nversion 2.3.0\nnetwork mainnet\nrules_fingerprint -\nupgrade ", 0) == 0);

  for (const std::string& bad : {
           text.substr(0, text.size() - 1),                                   // no final newline
           text + "\n",                                                       // empty line
           std::string(text).insert(text.find("network"), " "),               // extra space
           [&] { auto t = text; t.replace(t.find("2.3.0"), 5, "2.3"); return t; }(),
           [&] { auto t = text; t.replace(t.find("finalis-cli"), 11, "../evil"); return t; }(),
       }) {
    ASSERT_TRUE(!parse_release_manifest(bad, &err).has_value());
  }
  // Same content, artifacts out of order: not canonical.
  const auto cli = text.find("artifact ");
  const auto node = text.find("artifact ", cli + 1);
  const auto swapped = text.substr(0, cli) + text.substr(node) + text.substr(cli, node - cli);
  ASSERT_TRUE(!parse_release_manifest(swapped, &err).has_value());
  ASSERT_EQ(err, std::string("manifest is not in canonical form"));

  ReleaseManifest dup = *m;
  dup.artifacts.push_back(dup.artifacts[0]);
  ASSERT_TRUE(!canonicalize_release_manifest(&dup, &err));
}

// 1-of-1 (the founder's key today) and m-of-n later: only the policy file changes. Signatures by keys
// outside the policy, invalid ones, signatures over another text and repeats never count.
TEST(test_release_manifest_verification_follows_the_trust_policy_threshold) {
  const auto text = sample_manifest_text();
  const auto founder = release_key(0x01);
  const auto second = release_key(0x02);
  const auto third = release_key(0x03);
  const auto stranger = release_key(0x09);

  const auto one = policy_of(1, {&founder});
  ASSERT_TRUE(verify_release_manifest(text, {sign(text, founder)}, one).ok);
  ASSERT_TRUE(!verify_release_manifest(text, {}, one).ok);
  ASSERT_TRUE(!verify_release_manifest(text, {sign(text, stranger)}, one).ok);
  // A signature over a different release does not carry over.
  auto other = text;
  other.replace(other.find("2.3.0"), 5, "2.3.1");
  ASSERT_TRUE(!verify_release_manifest(text, {sign(other, founder)}, one).ok);
  auto forged = sign(text, stranger);
  forged.pubkey = founder.public_key;
  ASSERT_TRUE(!verify_release_manifest(text, {forged}, one).ok);

  const auto two_of_three = policy_of(2, {&founder, &second, &third});
  auto r = verify_release_manifest(text, {sign(text, founder)}, two_of_three);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.valid_signers, 1u);
  ASSERT_EQ(r.error, std::string("signed by 1 of the required 2 trusted keys"));
  r = verify_release_manifest(text, {sign(text, founder), sign(text, founder)}, two_of_three);  // repeat
  ASSERT_TRUE(!r.ok);
  r = verify_release_manifest(text, {sign(text, founder), sign(text, stranger), sign(text, third)}, two_of_three);
  ASSERT_TRUE(r.ok);
  ASSERT_EQ(r.valid_signers, 2u);

  // A manifest that is not canonical is never trusted, whatever signs it.
  const auto bad = text + "\n";
  ASSERT_TRUE(!verify_release_manifest(bad, {sign(bad, founder)}, one).ok);
}

TEST(test_release_signatures_and_trust_policy_parse_strictly) {
  const auto text = sample_manifest_text();
  const auto founder = release_key(0x01);
  const auto second = release_key(0x02);
  const std::vector<ReleaseSignature> sigs{sign(text, founder), sign(text, second)};
  std::string err;
  const auto back = parse_release_signatures(serialize_release_signatures(sigs), &err);
  ASSERT_TRUE(back.has_value());
  ASSERT_EQ(back->size(), 2u);
  ASSERT_TRUE(back->at(1).pubkey == second.public_key && back->at(1).sig == sigs[1].sig);
  ASSERT_TRUE(!parse_release_signatures("sig 00\n", &err).has_value());

  const std::string founder_hex = hex_encode32(founder.public_key);
  const std::string second_hex = hex_encode32(second.public_key);
  const auto p = parse_release_trust_policy("# founder only for now\nthreshold 1\nkey " + founder_hex + " founder\n", &err);
  ASSERT_TRUE(p.has_value());
  ASSERT_EQ(p->threshold, 1u);
  ASSERT_EQ(p->keys.at(0).label, std::string("founder"));
  // Raising the threshold later is a policy edit.
  const auto p2 = parse_release_trust_policy("threshold 2\nkey " + founder_hex + "\nkey " + second_hex + "\n", &err);
  ASSERT_TRUE(p2.has_value() && p2->threshold == 2 && p2->keys.size() == 2);
  for (const std::string& bad : {
           std::string("threshold 0\nkey ") + founder_hex + "\n",
           std::string("threshold 2\nkey ") + founder_hex + "\n",       // more than the keys
           std::string("key ") + founder_hex + "\n",                     // no threshold
           std::string("threshold 1\nkey ") + founder_hex + "\nkey " + founder_hex + "\n",  // duplicate
           std::string("threshold 1\nkey ") + founder_hex.substr(2) + "\n",
       }) {
    ASSERT_TRUE(!parse_release_trust_policy(bad, &err).has_value());
  }
}

TEST(test_release_versions_compare_numerically) {
  ASSERT_EQ(*compare_release_versions("2.2.14", "2.2.9"), 1);
  ASSERT_EQ(*compare_release_versions("v2.3.0", "2.3.0"), 0);
  ASSERT_EQ(*compare_release_versions("2.10.0", "3.0.0"), -1);
  for (const char* bad : {"2.3", "2.3.0.1", "2.03.0", "2..0", "x.y.z", "", "2.3.0-rc1"}) {
    ASSERT_TRUE(!parse_release_version(bad).has_value());
  }
}
