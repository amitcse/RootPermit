#include "rootpermit/apt_helper/startup_contract.hpp"

#include <cstdlib>
#include <iostream>

extern char** environ;

int main(const int argc, char* argv[]) {
  const auto result = rootpermit::apt_helper::validate_startup_contract(
      argc, argv, const_cast<const char* const*>(environ));
  if (result != rootpermit::apt_helper::StartupContractError::none) {
    std::cerr << "rootpermit-apt-helper: startup contract rejected: "
              << rootpermit::apt_helper::startup_contract_error_name(result) << '\n';
    return EXIT_FAILURE;
  }

  // This is an M0 harness, not an APT executor.  It intentionally does not
  // parse a package name, contact APT, or mutate package-manager state.
  std::cerr << "rootpermit-apt-helper: execution unavailable (M4 evidence gate)\n";
  return 77;
}
