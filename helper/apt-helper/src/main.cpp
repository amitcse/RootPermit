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

  const auto handoff = rootpermit::apt_helper::validate_runtime_handoff();
  if (handoff != rootpermit::apt_helper::HandoffContractError::none) {
    std::cerr << "rootpermit-apt-helper: inherited FD contract rejected: "
              << rootpermit::apt_helper::handoff_contract_error_name(handoff) << '\n';
    return EXIT_FAILURE;
  }

  // This validates only the handoff boundary. It intentionally does not parse
  // a caller path, contact APT, or mutate package-manager state. A control
  // handshake and libapt-pkg simulation are still blocked by the M4 fixture
  // evidence gate even on an image where the headers are installed.
  std::cerr << "rootpermit-apt-helper: execution unavailable (M4 evidence gate; libapt headers "
            << (rootpermit::apt_helper::libapt_pkg_headers_available() ? "present" : "absent")
            << ")\n";
  return 77;
}
