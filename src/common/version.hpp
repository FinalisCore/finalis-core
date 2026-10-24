// SPDX-License-Identifier: MIT

#pragma once

namespace finalis {

// Set from project(VERSION) in CMakeLists.txt.
#ifndef FINALIS_RELEASE_VERSION
#error "FINALIS_RELEASE_VERSION must be defined by the build (CMakeLists.txt)"
#endif

inline constexpr const char* kReleaseVersion = FINALIS_RELEASE_VERSION;
inline constexpr const char* kWalletApiVersion = "FINALIS_WALLET_API_V1";

inline constexpr const char* core_software_version() { return "finalis-core/" FINALIS_RELEASE_VERSION; }
inline constexpr const char* node_software_version() { return "finalis-node/" FINALIS_RELEASE_VERSION; }
inline constexpr const char* lightserver_software_version() { return "finalis-lightserver/" FINALIS_RELEASE_VERSION; }
inline constexpr const char* cli_software_version() { return "finalis-cli/" FINALIS_RELEASE_VERSION; }

}  // namespace finalis
