// SPDX-License-Identifier: MIT

#include "wallet/verified_balance.hpp"

#include <map>
#include <set>

#include "common/types.hpp"

namespace finalis::wallet {
namespace {

std::string outpoint_text(const OutPoint& op) { return hex_encode32(op.txid) + ":" + std::to_string(op.index); }

}  // namespace

VerifiedBalance verify_claimed_balance(LightVerifier* verifier, const std::vector<EndpointClaims>& claims,
                                       const std::vector<std::pair<OutPoint, Bytes>>& confidential,
                                       const std::vector<std::string>& proof_endpoints) {
  VerifiedBalance out;
  if (!claims.empty()) out.utxos = claims.front().utxos;
  if (verifier == nullptr) {
    out.detail = "no genesis to verify against";
    return out;
  }

  // Distinct (outpoint, leaf) claims: two servers describing one outpoint differently are both checked.
  struct Claim {
    ClaimedUtxo utxo;
    std::set<std::string> by;
  };
  std::map<std::pair<OutPoint, Bytes>, Claim> distinct;
  for (const auto& endpoint : claims) {
    for (const auto& utxo : endpoint.utxos) {
      auto& claim = distinct[{utxo.outpoint, transparent_utxo_leaf(utxo.value, utxo.script_pubkey)}];
      claim.utxo = utxo;
      claim.by.insert(endpoint.endpoint);
    }
  }
  std::vector<std::pair<OutPoint, Bytes>> expected;
  expected.reserve(distinct.size() + confidential.size());
  for (const auto& [key, claim] : distinct) expected.push_back(key);
  expected.insert(expected.end(), confidential.begin(), confidential.end());

  std::optional<VerifiedUtxos> proven;
  std::vector<std::string> unavailable;
  for (const auto& endpoint : proof_endpoints) {
    std::string error;
    bool server_fault = false;
    proven = verifier->verify_utxos(endpoint, expected, &error, &server_fault);
    if (proven.has_value()) {
      out.proof_endpoint = endpoint;
      break;
    }
    if (server_fault) {
      out.misbehaving.push_back({endpoint, error});
    } else {
      unavailable.push_back(endpoint + ": " + error);
    }
  }
  if (!proven.has_value()) {
    out.detail = "no server provided valid proofs";
    if (!unavailable.empty()) out.detail += " (" + unavailable.front() + ")";
    return out;
  }

  out.verified = true;
  out.height = proven->height;
  out.utxos.clear();
  std::map<std::string, std::uint64_t> tip_of;
  for (const auto& endpoint : claims) tip_of[endpoint.endpoint] = endpoint.tip_height;
  std::set<OutPoint> unspent;
  std::size_t i = 0;
  for (const auto& [key, claim] : distinct) {
    switch (proven->statuses[i++]) {
      case UtxoProofStatus::Unspent:
        out.utxos.push_back(claim.utxo);
        unspent.insert(key.first);
        break;
      case UtxoProofStatus::Different:
        for (const auto& endpoint : claim.by) {
          out.misbehaving.push_back({endpoint, "misdescribed coin " + outpoint_text(key.first)});
        }
        break;
      case UtxoProofStatus::Spent:
        // A server behind the proven height may still list it; one at that height may not.
        for (const auto& endpoint : claim.by) {
          if (tip_of[endpoint] == out.height) {
            out.misbehaving.push_back({endpoint, "listed absent coin " + outpoint_text(key.first)});
          }
        }
        break;
    }
  }
  out.confidential.assign(proven->statuses.begin() + static_cast<std::ptrdiff_t>(distinct.size()), proven->statuses.end());

  // At the proven height every honest server lists every unspent coin.
  for (const auto& endpoint : claims) {
    if (endpoint.tip_height != out.height) continue;
    std::set<OutPoint> listed;
    for (const auto& utxo : endpoint.utxos) listed.insert(utxo.outpoint);
    for (const auto& op : unspent) {
      if (!listed.contains(op)) {
        out.misbehaving.push_back({endpoint.endpoint, "left out coin " + outpoint_text(op)});
        break;
      }
    }
  }
  return out;
}

}  // namespace finalis::wallet
