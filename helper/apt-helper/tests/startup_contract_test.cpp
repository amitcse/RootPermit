#include "rootpermit/apt_helper/startup_contract.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

using rootpermit::apt_helper::DescriptorObservation;
using rootpermit::apt_helper::Digest;
using rootpermit::apt_helper::HandoffContractError;
using rootpermit::apt_helper::ImmutableInputError;
using rootpermit::apt_helper::ImmutableObjectMetadata;
using rootpermit::apt_helper::PackageAction;
using rootpermit::apt_helper::StartupContractError;
using rootpermit::apt_helper::validate_handoff_contract;
using rootpermit::apt_helper::validate_immutable_object;
using rootpermit::apt_helper::validate_startup_contract;

bool expect(const bool condition, const char* const name) {
  if (!condition) std::cerr << "failed: " << name << '\n';
  return condition;
}

Digest digest_from_hex(const std::string& hex) {
  Digest digest{};
  for (std::size_t index = 0; index < digest.size(); ++index) {
    const auto value = [](const char item) -> std::uint8_t {
      return static_cast<std::uint8_t>(item <= '9' ? item - '0' : item - 'a' + 10);
    };
    digest[index] = static_cast<std::uint8_t>((value(hex[index * 2]) << 4U) | value(hex[index * 2 + 1]));
  }
  return digest;
}

std::vector<DescriptorObservation> valid_descriptors() {
  return {
      {.fd = 3, .is_seqpacket_socket = true, .peer_identity_matches = true},
      {.fd = 4, .is_directory = true, .is_read_only = true},
      {.fd = 5, .is_directory = true},
      {.fd = 6, .is_directory = true, .is_read_only = true},
  };
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
                  "user argument is rejected") && passed;

  std::array<const char*, 4> unexpected_environment{
      "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LD_PRELOAD=x", nullptr};
  passed = expect(validate_startup_contract(1, argv.data(), unexpected_environment.data()) ==
                      StartupContractError::environment_invalid,
                  "additional environment is rejected") && passed;

  auto descriptors = valid_descriptors();
  passed = expect(validate_handoff_contract(descriptors) == HandoffContractError::none,
                  "exact inherited descriptor contract is accepted") && passed;
  descriptors.push_back({.fd = 7});
  passed = expect(validate_handoff_contract(descriptors) == HandoffContractError::unexpected_fd,
                  "additional inherited descriptor is rejected") && passed;
  descriptors = valid_descriptors();
  descriptors[0].peer_identity_matches = false;
  passed = expect(validate_handoff_contract(descriptors) == HandoffContractError::peer_identity_unverified,
                  "unverified control peer is rejected") && passed;
  descriptors = valid_descriptors();
  descriptors[3].is_read_only = false;
  passed = expect(validate_handoff_contract(descriptors) == HandoffContractError::content_store_not_read_only,
                  "writable content store is rejected") && passed;

  constexpr std::array<std::uint8_t, 3> kAbc{'a', 'b', 'c'};
  // SHA-256("abc"), independently specified in FIPS 180-4 test material.
  const std::string object_name = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  const auto digest = digest_from_hex(object_name);
  const ImmutableObjectMetadata metadata{
      .object_name = object_name, .expected_digest = digest, .owner_uid = 0,
      .mode = 0444, .hardlink_count = 1, .regular_file = true};
  passed = expect(validate_immutable_object(metadata, kAbc) == ImmutableInputError::none,
                  "root-owned content-addressed immutable object is accepted") && passed;
  auto hardlinked = metadata;
  hardlinked.hardlink_count = 2;
  passed = expect(validate_immutable_object(hardlinked, kAbc) == ImmutableInputError::hardlink_present,
                  "hardlinked content object is rejected") && passed;
  auto swapped = metadata;
  swapped.object_name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  passed = expect(validate_immutable_object(swapped, kAbc) == ImmutableInputError::object_name_digest_mismatch,
                  "content-addressed name swap is rejected") && passed;

  std::vector<PackageAction> graph{
      {.package_name = "zlib1g", .architecture = "amd64", .installed_version = "",
       .target_version = "1.0", .origin_identity = "ubuntu", .dependency_parents = {1}},
      {.package_name = "apt", .architecture = "amd64", .installed_version = "",
       .target_version = "2.0", .origin_identity = "ubuntu", .dependency_parents = {}},
  };
  passed = expect(rootpermit::apt_helper::normalize_action_graph(&graph) &&
                      graph[0].package_name == "apt" && graph[1].dependency_parents == std::vector<std::uint32_t>{0},
                  "action graph is sorted and dependency indexes are remapped") && passed;
  graph[1].dependency_parents = {2};
  passed = expect(!rootpermit::apt_helper::normalize_action_graph(&graph),
                  "out-of-range dependency parent is rejected") && passed;

  // a8 {1:1, 2:h'01..', 3:[], 4:[], 5:h'02..', 6:0, 7:"x", 8:h'03..'}.
  // It is the smallest canonical PlanManifest envelope. The plan digest is
  // deliberately a signed frozen-plan reference, not a self-hash of this map.
  std::vector<std::uint8_t> manifest{0xa8, 0x01, 0x01, 0x02, 0x58, 0x20};
  manifest.insert(manifest.end(), 32, 0x01);
  manifest.insert(manifest.end(), {0x03, 0x80, 0x04, 0x80, 0x05, 0x58, 0x20});
  manifest.insert(manifest.end(), 32, 0x02);
  manifest.insert(manifest.end(), {0x06, 0x00, 0x07, 0x61, 'x', 0x08, 0x58, 0x20});
  manifest.insert(manifest.end(), 32, 0x03);
  rootpermit::apt_helper::PlanManifest parsed{};
  passed = expect(rootpermit::apt_helper::parse_plan_manifest(manifest, &parsed) ==
                      rootpermit::apt_helper::ManifestError::none &&
                      parsed.toolchain == "x" && parsed.inputs.empty() && parsed.action_graph.empty(),
                  "canonical sealed plan manifest subset is accepted") && passed;
  auto invalid_utf8 = manifest;
  invalid_utf8[81] = 0xff;
  passed = expect(rootpermit::apt_helper::parse_plan_manifest(invalid_utf8, &parsed) ==
                      rootpermit::apt_helper::ManifestError::invalid_field,
                  "invalid UTF-8 plan metadata is rejected") && passed;
  manifest[0] = 0xa9;
  manifest.insert(manifest.end(), {0x09, 0xf6});
  passed = expect(rootpermit::apt_helper::parse_plan_manifest(manifest, &parsed) ==
                      rootpermit::apt_helper::ManifestError::unknown_field,
                  "unknown plan manifest field is rejected") && passed;
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
