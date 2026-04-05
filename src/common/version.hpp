#pragma once

namespace finalis {

inline constexpr const char* kReleaseVersion = "0.7";
inline constexpr const char* kWalletApiVersion = "FINALIS_WALLET_API_V1";

inline constexpr const char* core_software_version() { return "finalis-core/0.7"; }
inline constexpr const char* node_software_version() { return "finalis-node/0.7"; }
inline constexpr const char* lightserver_software_version() { return "finalis-lightserver/0.7"; }
inline constexpr const char* cli_software_version() { return "finalis-cli/0.7"; }

}  // namespace finalis
