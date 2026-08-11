#include "rootpermit/apt_helper/startup_contract.hpp"

#include <array>
#include <cstdlib>
#include <iostream>

namespace {

using rootpermit::apt_helper::StartupContractError;
using rootpermit::apt_helper::validate_startup_contract;

bool expect(const bool condition, const char* const name) {
  if (!condition) {
    std::cerr << "failed: " << name << '\n';
  }
  return condition;
}

}  // namespace

int main() {
  std::array<const char*, 2> argv{"rootpermit-apt-helper", nullptr};
  std::array<const char*, 3> environment{
      "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", nullptr};
  bool passed = expect(validate_startup_contract(1, argv.data(), environment.data()) ==
                           StartupContractError::none,
                       "fixed argv and environment are accepted");

  std::array<const char*, 3> unexpected_argument{
      "rootpermit-apt-helper", "curl", nullptr};
  passed = expect(validate_startup_contract(2, unexpected_argument.data(), environment.data()) ==
                      StartupContractError::arguments_present,
                  "user argument is rejected") &&
           passed;

  std::array<const char*, 4> unexpected_environment{
      "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LD_PRELOAD=x", nullptr};
  passed = expect(validate_startup_contract(1, argv.data(), unexpected_environment.data()) ==
                      StartupContractError::environment_invalid,
                  "additional environment is rejected") &&
           passed;

  passed = expect(validate_startup_contract(1, argv.data(), nullptr) ==
                      StartupContractError::environment_invalid,
                  "missing environment is rejected") &&
           passed;
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
