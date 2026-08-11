#pragma once

#include <string_view>

namespace rootpermit::apt_helper {

enum class StartupContractError {
  none,
  arguments_present,
  environment_invalid,
};

// The future helper has a fixed executable identity: no caller-supplied argv
// and exactly the two environment entries created by the root broker.  This
// pure function is testable without starting a privileged process.
[[nodiscard]] StartupContractError validate_startup_contract(
    int argc, const char* const argv[], const char* const envp[]) noexcept;

[[nodiscard]] std::string_view startup_contract_error_name(
    StartupContractError error) noexcept;

}  // namespace rootpermit::apt_helper
