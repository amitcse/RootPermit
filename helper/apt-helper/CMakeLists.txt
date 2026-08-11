cmake_minimum_required(VERSION 3.24)

# This target deliberately contains no libapt-pkg calls.  M4 replaces the
# implementation only after the sealed-plan evidence gate has passed.
project(rootpermit_apt_helper LANGUAGES CXX)

option(RP_APT_HELPER_REQUIRE_LIBAPT
  "Check that the pinned libapt-pkg development package is available" OFF)

set(RP_APT_HELPER_LIBAPT_VERSION "2.9" CACHE STRING
  "Minimum libapt-pkg major.minor declaration for the Ubuntu reference image")

if(RP_APT_HELPER_REQUIRE_LIBAPT)
  find_path(RP_APT_PKG_INCLUDE_DIR apt-pkg/apt-pkgconfig.h)
  if(NOT RP_APT_PKG_INCLUDE_DIR)
    message(FATAL_ERROR
      "libapt-pkg-dev is required when RP_APT_HELPER_REQUIRE_LIBAPT=ON")
  endif()
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
