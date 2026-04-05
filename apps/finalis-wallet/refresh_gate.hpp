#pragma once

#include <cstdint>

namespace finalis::wallet {

bool should_apply_refresh_result(std::uint64_t result_generation, std::uint64_t latest_generation,
                                 std::uint64_t result_state_version, std::uint64_t latest_state_version);
bool should_keep_refresh_indicator(std::uint64_t completed_generation, std::uint64_t latest_generation);

}  // namespace finalis::wallet
