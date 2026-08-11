#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rootpermit::apt_helper {

// These are ABI, not configuration. The broker must create the descriptors
// before exec and the helper must never resolve an input path supplied by a
// requester. Standard input/output/error (0..2) are deliberately outside this
// handoff contract.
inline constexpr int kControlFd = 3;
inline constexpr int kPlanRootFd = 4;
inline constexpr int kJournalRootFd = 5;
inline constexpr int kContentStoreFd = 6;
inline constexpr std::array<int, 4> kRequiredInheritedFds{
    kControlFd, kPlanRootFd, kJournalRootFd, kContentStoreFd};
inline constexpr std::string_view kHelperProtocolVersion = "rootpermit-helper/v1";

enum class StartupContractError {
  none,
  arguments_present,
  environment_invalid,
};

// The future helper has a fixed executable identity: no caller-supplied argv
// and exactly the two environment entries created by the root broker. This
// pure function is testable without starting a privileged process.
[[nodiscard]] StartupContractError validate_startup_contract(
    int argc, const char* const argv[], const char* const envp[]) noexcept;
[[nodiscard]] std::string_view startup_contract_error_name(
    StartupContractError error) noexcept;

enum class HandoffContractError {
  none,
  missing_required_fd,
  unexpected_fd,
  control_not_seqpacket,
  plan_root_not_directory,
  plan_root_not_read_only,
  journal_root_not_directory,
  content_store_not_directory,
  content_store_not_read_only,
  peer_identity_unverified,
};

// A small, platform-neutral observation of inherited descriptors. Linux
// inspection populates this structure; unit tests can construct hostile cases
// without exercising a privileged process.
struct DescriptorObservation {
  int fd{};
  bool is_directory{};
  bool is_read_only{};
  bool is_seqpacket_socket{};
  bool peer_identity_matches{};
};

[[nodiscard]] HandoffContractError validate_handoff_contract(
    std::span<const DescriptorObservation> descriptors) noexcept;
[[nodiscard]] std::string_view handoff_contract_error_name(
    HandoffContractError error) noexcept;

// Linux-only runtime inspection. It validates descriptor types/flags and that
// no FD >= 3 was inherited beyond the four sealed handles. A peer start-time
// check is deliberately not claimed here: it is bound by the authenticated
// control handshake planned with the broker protocol, not inferred from PID.
[[nodiscard]] HandoffContractError validate_runtime_handoff() noexcept;

using Digest = std::array<std::uint8_t, 32>;

enum class ManifestError {
  none,
  malformed_cbor,
  non_canonical_cbor,
  unsupported_version,
  missing_field,
  unknown_field,
  invalid_field,
  duplicate_input,
  input_order_invalid,
  action_graph_invalid,
};

enum class ImmutableInputError {
  none,
  invalid_object_name,
  object_name_digest_mismatch,
  object_digest_mismatch,
  not_regular_file,
  owner_not_root,
  writable_by_group_or_other,
  hardlink_present,
};

struct ImmutableObjectMetadata {
  std::string_view object_name;
  Digest expected_digest{};
  std::uint32_t owner_uid{};
  std::uint32_t mode{};
  std::uint32_t hardlink_count{};
  bool regular_file{};
};

// The object name is the lowercase SHA-256 hex digest. The bytes are supplied
// from an already-open content-store file descriptor; this API has no path
// parameter by design.
[[nodiscard]] ImmutableInputError validate_immutable_object(
    const ImmutableObjectMetadata& metadata, std::span<const std::uint8_t> bytes) noexcept;
[[nodiscard]] std::string_view immutable_input_error_name(
    ImmutableInputError error) noexcept;

enum class PackageActionKind : std::uint64_t { install = 1 };

struct PackageAction {
  std::string package_name;
  std::string architecture;
  std::string installed_version;
  std::string target_version;
  PackageActionKind kind{PackageActionKind::install};
  std::string origin_identity;
  Digest deb_digest{};
  std::uint64_t archive_bytes{};
  std::uint64_t installed_delta_bytes{};
  std::vector<std::uint32_t> dependency_parents;
};

// The simulation adapter builds an unordered graph. Before comparison or
// execution, this routine sorts by the v1 frozen-plan key and remaps all parent
// indexes. It is intentionally independent of libapt-pkg.
[[nodiscard]] bool normalize_action_graph(std::vector<PackageAction>* actions) noexcept;
[[nodiscard]] bool action_graphs_equal(const std::vector<PackageAction>& left,
                                       const std::vector<PackageAction>& right) noexcept;

struct SealedInput {
  Digest digest{};
  std::uint64_t role{};
};

struct PlanManifest {
  Digest plan_digest{};
  std::vector<SealedInput> inputs;
  std::vector<PackageAction> action_graph;
  Digest policy_digest{};
  std::int64_t created_utc{};
  std::string toolchain;
  Digest prestate_observation{};
};

// Parses the deterministic-CBOR PlanManifest subset in Engineering Spec v2
// section 4.4. It accepts no unknown fields and rejects alternate CBOR forms.
// The plan digest is the frozen-plan projection digest; it is verified against
// the broker's signed Request/control message, not against a manifest which
// embeds that same field. Manifest-file content addressing is verified through
// validate_immutable_object before parsing.
[[nodiscard]] ManifestError parse_plan_manifest(
    std::span<const std::uint8_t> encoded, PlanManifest* manifest) noexcept;
[[nodiscard]] std::string_view manifest_error_name(ManifestError error) noexcept;

// Compile-time capability only. This source tree never calls libapt-pkg when
// headers are unavailable, and a true value does not by itself claim that M4's
// VM evidence gate has passed.
[[nodiscard]] constexpr bool libapt_pkg_headers_available() noexcept {
#if defined(RP_APT_HELPER_HAS_LIBAPT_PKG)
  return true;
#else
  return false;
#endif
}

}  // namespace rootpermit::apt_helper
