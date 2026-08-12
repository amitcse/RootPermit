cmake_minimum_required(VERSION 3.24)

# This target deliberately contains no libapt-pkg calls.  M4 replaces the
# implementation only after the sealed-plan evidence gate has passed.
project(rootpermit_apt_helper LANGUAGES CXX)

option(RP_APT_HELPER_BUILD_M4_TARGETS
  "Enable the libapt-pkg-dependent targets that are only valid for M4 evidence" OFF)

set(RP_APT_HELPER_LIBAPT_VERSION "2.9" CACHE STRING
  "Minimum libapt-pkg major.minor declaration for the Ubuntu reference image")

# The M0/M1 startup-contract library is deliberately independent of libapt-pkg.
# Requiring headers for every CMake invocation would let an unavailable M4
# toolchain turn a boundary-only build into a silently skipped test.  The first
# target that is allowed to include or link libapt-pkg must opt into this mode.
if(RP_APT_HELPER_BUILD_M4_TARGETS)
  find_path(RP_APT_PKG_INCLUDE_DIR apt-pkg/apt-pkgconfig.h REQUIRED)
  find_library(RP_APT_PKG_LIBRARY NAMES apt-pkg REQUIRED)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(rootpermit_apt_helper_contract STATIC
  src/startup_contract.cpp
)
target_include_directories(rootpermit_apt_helper_contract PUBLIC include)
target_compile_options(rootpermit_apt_helper_contract PRIVATE
  -Wall -Wextra -Wpedantic -Werror)

add_executable(rootpermit-apt-helper src/main.cpp)
target_link_libraries(rootpermit-apt-helper PRIVATE rootpermit_apt_helper_contract)
target_compile_options(rootpermit-apt-helper PRIVATE -Wall -Wextra -Wpedantic -Werror)

include(CTest)
if(BUILD_TESTING)
  add_executable(rootpermit-apt-helper-contract-test tests/startup_contract_test.cpp)
  target_link_libraries(rootpermit-apt-helper-contract-test PRIVATE rootpermit_apt_helper_contract)
  target_compile_options(rootpermit-apt-helper-contract-test PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME rootpermit-apt-helper-contract
    COMMAND rootpermit-apt-helper-contract-test)
endif()

if(RP_APT_HELPER_BUILD_M4_TARGETS)
  # This sentinel keeps the dependency contract executable before M4's private
  # simulation target exists.  It links the exact development library, but does
  # not grant an execution path or claim the M4 evidence gate has passed.
  add_library(rootpermit_apt_helper_m4_toolchain INTERFACE)
  target_include_directories(rootpermit_apt_helper_m4_toolchain INTERFACE
    "${RP_APT_PKG_INCLUDE_DIR}")
  target_link_libraries(rootpermit_apt_helper_m4_toolchain INTERFACE
    "${RP_APT_PKG_LIBRARY}")
endif()
