#include "genesis/genesis.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"
#include "utxo/tx.hpp"

namespace finalis::genesis {
namespace {

constexpr char kPrefix[] = "SCGENV1";

std::optional<std::string> find_string(const std::string& json, const std::string& key) {
  std::regex re("\\\"" + key + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return m[1].str();
}

std::optional<std::uint64_t> find_u64(const std::string& json, const std::string& key) {
  std::regex re("\\\"" + key + "\\\"\\s*:\\s*([0-9]+)");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return static_cast<std::uint64_t>(std::stoull(m[1].str()));
}

std::optional<std::vector<std::string>> find_string_array(const std::string& json, const std::string& key) {
  std::regex re("\\\"" + key + "\\\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  const std::string body = m[1].str();
  std::regex item_re("\\\"([^\\\"]*)\\\"");
  std::vector<std::string> out;
  for (std::sregex_iterator it(body.begin(), body.end(), item_re), end; it != end; ++it) {
    out.push_back((*it)[1].str());
  }
  return out;
}

bool parse_pubkey_hex(const std::string& s, PubKey32* out) {
  auto b = hex_decode(s);
  if (!b.has_value() || b->size() != 32) return false;
  std::copy(b->begin(), b->end(), out->begin());
  return true;
}

std::string quote(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    if (c == '\\' || c == '"') out.push_back('\\');
    out.push_back(c);
  }
  return out;
}

bool has_suffix(const std::string& s, const std::string& suff) {
  if (s.size() < suff.size()) return false;
  return std::equal(suff.rbegin(), suff.rend(), s.rbegin(), [](char a, char b) {
    return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
  });
}

}  // namespace

std::optional<Document> parse_json(const std::string& json_text, std::string* err) {
  Document d;

  auto version = find_u64(json_text, "version");
  auto network_name = find_string(json_text, "network_name");
  auto protocol_version = find_u64(json_text, "protocol_version");
  auto network_id_hex = find_string(json_text, "network_id_hex");
  auto magic = find_u64(json_text, "magic");
  auto genesis_time_unix = find_u64(json_text, "genesis_time_unix");
  auto initial_height = find_u64(json_text, "initial_height");
  auto validators = find_string_array(json_text, "initial_validators");
  auto initial_active_set_size = find_u64(json_text, "initial_active_set_size");
  auto min_committee = find_u64(json_text, "min_committee");
  auto max_committee = find_u64(json_text, "max_committee");
  auto sizing_rule = find_string(json_text, "sizing_rule");
  auto c = find_u64(json_text, "C");
  auto monetary_params_ref = find_string(json_text, "monetary_params_ref");

  if (!version || !network_name || !protocol_version || !network_id_hex || !magic || !genesis_time_unix ||
      !initial_height || !validators || !initial_active_set_size || !min_committee || !max_committee || !sizing_rule ||
      !c || !monetary_params_ref) {
    if (err) *err = "missing required genesis.json fields";
    return std::nullopt;
  }

  auto nid = hex_decode(*network_id_hex);
  if (!nid.has_value() || nid->size() != 16) {
    if (err) *err = "network_id_hex must be 16 bytes hex";
    return std::nullopt;
  }

  d.version = static_cast<std::uint32_t>(*version);
  d.network_name = *network_name;
  d.protocol_version = static_cast<std::uint32_t>(*protocol_version);
  std::copy(nid->begin(), nid->end(), d.network_id.begin());
  d.magic = static_cast<std::uint32_t>(*magic);
  d.genesis_time_unix = *genesis_time_unix;
  d.initial_height = *initial_height;
  d.initial_active_set_size = static_cast<std::uint32_t>(*initial_active_set_size);
  d.initial_committee_params.min_committee = static_cast<std::uint32_t>(*min_committee);
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(*max_committee);
  d.initial_committee_params.sizing_rule = *sizing_rule;
  d.initial_committee_params.c = static_cast<std::uint32_t>(*c);
  d.monetary_params_ref = *monetary_params_ref;

  d.initial_validators.clear();
  for (const auto& s : *validators) {
    PubKey32 pk{};
    if (!parse_pubkey_hex(s, &pk)) {
      if (err) *err = "invalid validator pubkey hex";
      return std::nullopt;
    }
    d.initial_validators.push_back(pk);
  }

  auto seeds = find_string_array(json_text, "seeds");
  if (seeds.has_value()) d.seeds = *seeds;
  auto note = find_string(json_text, "note");
  if (note.has_value()) d.note = *note;

  return d;
}

std::string to_json(const Document& d) {
  std::ostringstream oss;
  oss << "{\n";
  oss << "  \"version\": " << d.version << ",\n";
  oss << "  \"network_name\": \"" << quote(d.network_name) << "\",\n";
  oss << "  \"protocol_version\": " << d.protocol_version << ",\n";
  oss << "  \"network_id_hex\": \"" << hex_encode(Bytes(d.network_id.begin(), d.network_id.end())) << "\",\n";
  oss << "  \"magic\": " << d.magic << ",\n";
  oss << "  \"genesis_time_unix\": " << d.genesis_time_unix << ",\n";
  oss << "  \"initial_height\": " << d.initial_height << ",\n";
  oss << "  \"initial_validators\": [\n";
  for (std::size_t i = 0; i < d.initial_validators.size(); ++i) {
    oss << "    \"" << hex_encode(Bytes(d.initial_validators[i].begin(), d.initial_validators[i].end())) << "\"";
    if (i + 1 != d.initial_validators.size()) oss << ",";
    oss << "\n";
  }
  oss << "  ],\n";
  oss << "  \"initial_active_set_size\": " << d.initial_active_set_size << ",\n";
  oss << "  \"initial_committee_params\": {\n";
  oss << "    \"min_committee\": " << d.initial_committee_params.min_committee << ",\n";
  oss << "    \"max_committee\": " << d.initial_committee_params.max_committee << ",\n";
  oss << "    \"sizing_rule\": \"" << quote(d.initial_committee_params.sizing_rule) << "\",\n";
  oss << "    \"C\": " << d.initial_committee_params.c << "\n";
  oss << "  },\n";
  oss << "  \"monetary_params_ref\": \"" << quote(d.monetary_params_ref) << "\",\n";
  oss << "  \"seeds\": [";
  for (std::size_t i = 0; i < d.seeds.size(); ++i) {
    if (i) oss << ", ";
    oss << "\"" << quote(d.seeds[i]) << "\"";
  }
  oss << "],\n";
  oss << "  \"note\": \"" << quote(d.note) << "\"\n";
  oss << "}\n";
  return oss.str();
}

Bytes encode_bin(const Document& d) {
  codec::ByteWriter w;
  w.bytes(Bytes(kPrefix, kPrefix + 7));
  w.u32le(d.version);
  w.varbytes(Bytes(d.network_name.begin(), d.network_name.end()));
  w.u32le(d.protocol_version);
  w.bytes_fixed(d.network_id);
  w.u32le(d.magic);
  w.u64le(d.genesis_time_unix);
  w.u64le(d.initial_height);
  w.varint(d.initial_validators.size());
  for (const auto& pk : d.initial_validators) w.bytes_fixed(pk);
  w.u32le(d.initial_active_set_size);
  w.u32le(d.initial_committee_params.min_committee);
  w.u32le(d.initial_committee_params.max_committee);
  w.varbytes(Bytes(d.initial_committee_params.sizing_rule.begin(), d.initial_committee_params.sizing_rule.end()));
  w.u32le(d.initial_committee_params.c);
  w.varbytes(Bytes(d.monetary_params_ref.begin(), d.monetary_params_ref.end()));
  w.varint(d.seeds.size());
  for (const auto& s : d.seeds) w.varbytes(Bytes(s.begin(), s.end()));
  w.varbytes(Bytes(d.note.begin(), d.note.end()));
  return w.take();
}

std::optional<Document> decode_bin(const Bytes& bin, std::string* err) {
  Document d;
  if (!codec::parse_exact(bin, [&](codec::ByteReader& r) {
        auto prefix = r.bytes(7);
        if (!prefix) return false;
        if (!std::equal(prefix->begin(), prefix->end(), kPrefix)) return false;

        auto version = r.u32le();
        auto network_name = r.varbytes();
        auto protocol_version = r.u32le();
        auto network_id = r.bytes_fixed<16>();
        auto magic = r.u32le();
        auto genesis_time_unix = r.u64le();
        auto initial_height = r.u64le();
        auto nvals = r.varint();
        if (!version || !network_name || !protocol_version || !network_id || !magic || !genesis_time_unix ||
            !initial_height || !nvals) {
          return false;
        }

        d.version = *version;
        d.network_name.assign(network_name->begin(), network_name->end());
        d.protocol_version = *protocol_version;
        d.network_id = *network_id;
        d.magic = *magic;
        d.genesis_time_unix = *genesis_time_unix;
        d.initial_height = *initial_height;

        d.initial_validators.clear();
        d.initial_validators.reserve(*nvals);
        for (std::uint64_t i = 0; i < *nvals; ++i) {
          auto pk = r.bytes_fixed<32>();
          if (!pk) return false;
          d.initial_validators.push_back(*pk);
        }

        auto active = r.u32le();
        auto minc = r.u32le();
        auto maxc = r.u32le();
        auto rule = r.varbytes();
        auto c = r.u32le();
        auto monetary = r.varbytes();
        auto seed_count = r.varint();
        if (!active || !minc || !maxc || !rule || !c || !monetary || !seed_count) return false;

        d.initial_active_set_size = *active;
        d.initial_committee_params.min_committee = *minc;
        d.initial_committee_params.max_committee = *maxc;
        d.initial_committee_params.sizing_rule.assign(rule->begin(), rule->end());
        d.initial_committee_params.c = *c;
        d.monetary_params_ref.assign(monetary->begin(), monetary->end());

        d.seeds.clear();
        d.seeds.reserve(*seed_count);
        for (std::uint64_t i = 0; i < *seed_count; ++i) {
          auto s = r.varbytes();
          if (!s) return false;
          d.seeds.emplace_back(s->begin(), s->end());
        }
        auto note = r.varbytes();
        if (!note) return false;
        d.note.assign(note->begin(), note->end());
        return true;
      })) {
    if (err) *err = "invalid genesis binary";
    return std::nullopt;
  }
  return d;
}

Hash32 hash_bin(const Bytes& bin) { return crypto::sha256d(bin); }
Hash32 hash_doc(const Document& doc) { return hash_bin(encode_bin(doc)); }

Hash32 block_id(const Document& doc) {
  const Hash32 ghash = hash_doc(doc);
  Bytes pre{'S', 'C', '-', 'G', 'E', 'N', 'E', 'S', 'I', 'S', '-', 'H', 'D', 'R', '-', 'V', '1'};
  pre.insert(pre.end(), ghash.begin(), ghash.end());

  BlockHeader h;
  h.prev_finalized_hash = zero_hash();
  h.height = 0;
  h.timestamp = doc.genesis_time_unix;
  h.merkle_root = crypto::sha256d(pre);
  auto vals = doc.initial_validators;
  std::sort(vals.begin(), vals.end());
  h.leader_pubkey = vals.empty() ? PubKey32{} : vals.front();
  h.round = 0;
  return h.block_id();
}

bool validate_document(const Document& doc, const NetworkConfig& cfg, std::string* err, std::size_t min_validators) {
  if (doc.version != 1) {
    if (err) *err = "unsupported genesis version";
    return false;
  }
  if (doc.network_name != cfg.name) {
    if (err) *err = "network_name mismatch";
    return false;
  }
  if (doc.protocol_version != cfg.protocol_version) {
    if (err) *err = "protocol_version mismatch";
    return false;
  }
  if (doc.network_id != cfg.network_id) {
    if (err) *err = "network_id mismatch";
    return false;
  }
  if (doc.magic != cfg.magic) {
    if (err) *err = "magic mismatch";
    return false;
  }
  if (doc.initial_height != 0) {
    if (err) *err = "initial_height must be 0";
    return false;
  }
  if (doc.initial_validators.size() < min_validators) {
    if (err) *err = "insufficient initial validators";
    return false;
  }
  if (doc.initial_active_set_size != doc.initial_validators.size()) {
    if (err) *err = "initial_active_set_size must equal validators.size";
    return false;
  }
  std::set<PubKey32> uniq(doc.initial_validators.begin(), doc.initial_validators.end());
  if (uniq.size() != doc.initial_validators.size()) {
    if (err) *err = "duplicate initial validators";
    return false;
  }
  if (doc.initial_committee_params.max_committee == 0 ||
      doc.initial_committee_params.max_committee > cfg.max_committee) {
    if (err) *err = "invalid max_committee";
    return false;
  }
  if (doc.initial_committee_params.min_committee < 1 ||
      doc.initial_committee_params.min_committee > doc.initial_committee_params.max_committee) {
    if (err) *err = "invalid min_committee";
    return false;
  }
  return true;
}

std::optional<Document> load_from_path(const std::string& path, std::string* err) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) {
    if (err) *err = "failed to open " + path;
    return std::nullopt;
  }
  std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (has_suffix(path, ".json")) return parse_json(raw, err);

  Bytes b(raw.begin(), raw.end());
  return decode_bin(b, err);
}

std::optional<Bytes> load_bin_from_path(const std::string& path, std::string* err) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) {
    if (err) *err = "failed to open " + path;
    return std::nullopt;
  }
  std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return Bytes(raw.begin(), raw.end());
}

bool write_bin_to_path(const std::string& path, const Bytes& bin, std::string* err) {
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out.good()) {
    if (err) *err = "failed to open output " + path;
    return false;
  }
  out.write(reinterpret_cast<const char*>(bin.data()), static_cast<std::streamsize>(bin.size()));
  if (!out.good()) {
    if (err) *err = "failed writing " + path;
    return false;
  }
  return true;
}

}  // namespace finalis::genesis
