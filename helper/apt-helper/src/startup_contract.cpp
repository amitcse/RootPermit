#include "rootpermit/apt_helper/startup_contract.hpp"

#include <array>
#include <string_view>

namespace rootpermit::apt_helper {
namespace {

constexpr std::array<std::string_view, 2> kAllowedEnvironment{
    "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"};

[[nodiscard]] bool environment_matches(const char* const envp[]) noexcept {
  if (envp == nullptr) {
    return false;
  }

  for (std::size_t index = 0; index < kAllowedEnvironment.size(); ++index) {
    if (envp[index] == nullptr || kAllowedEnvironment[index] != envp[index]) {
      return false;
    }
  }
  return envp[kAllowedEnvironment.size()] == nullptr;
}

}  // namespace

StartupContractError validate_startup_contract(const int argc,
                                               const char* const argv[],
                                               const char* const envp[]) noexcept {
  if (argc != 1 || argv == nullptr || argv[0] == nullptr || argv[1] != nullptr) {
    return StartupContractError::arguments_present;
  }
  return environment_matches(envp) ? StartupContractError::none
                                   : StartupContractError::environment_invalid;
}

std::string_view startup_contract_error_name(const StartupContractError error) noexcept {
  switch (error) {
    case StartupContractError::none:
      return "none";
    case StartupContractError::arguments_present:
      return "arguments_present";
    case StartupContractError::environment_invalid:
      return "environment_invalid";
  }
  return "unknown";
}

}  // namespace rootpermit::apt_helper
