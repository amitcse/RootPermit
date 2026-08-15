#include "rootpermit/apt_helper/startup_contract.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rootpermit::apt_helper {
namespace {

constexpr std::array<std::string_view, 2> kAllowedEnvironment{
    "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"};
constexpr std::size_t kMaxManifestBytes = 1U << 20U;
constexpr std::size_t kMaxObjectBytes = 128U << 20U;
constexpr std::size_t kMaxGraphActions = 16'384;
constexpr std::size_t kMaxInputs = 16'384;

[[nodiscard]] bool environment_matches(const char* const envp[]) noexcept {
  if (envp == nullptr) return false;
  for (std::size_t index = 0; index < kAllowedEnvironment.size(); ++index) {
    if (envp[index] == nullptr || kAllowedEnvironment[index] != envp[index]) return false;
  }
  return envp[kAllowedEnvironment.size()] == nullptr;
}

[[nodiscard]] bool is_required_fd(const int fd) noexcept {
  return std::find(kRequiredInheritedFds.begin(), kRequiredInheritedFds.end(), fd) !=
         kRequiredInheritedFds.end();
}

[[nodiscard]] bool is_lower_hex_digest(std::string_view value) noexcept {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](const char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}

[[nodiscard]] char hex_digit(const std::uint8_t byte) noexcept {
  constexpr std::string_view kDigits{"0123456789abcdef"};
  return kDigits[byte & 0x0fU];
}

[[nodiscard]] std::string digest_hex(const Digest& digest) {
  std::string output(64, '0');
  for (std::size_t index = 0; index < digest.size(); ++index) {
    output[index * 2] = hex_digit(static_cast<std::uint8_t>(digest[index] >> 4U));
    output[index * 2 + 1] = hex_digit(digest[index]);
  }
  return output;
}

// A small SHA-256 implementation is kept local so the privileged boundary has
// no runtime crypto package dependency. It is used only for content addresses
// and the protocol's already-defined plan digest domain.
class Sha256 {
 public:
  Sha256() noexcept { state_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U}; }
  void update(std::span<const std::uint8_t> input) noexcept {
    total_bytes_ += input.size();
    std::size_t offset = 0;
    if (used_ != 0) {
      const std::size_t take = std::min(block_.size() - used_, input.size());
      std::memcpy(block_.data() + used_, input.data(), take);
      used_ += take;
      offset += take;
      if (used_ == block_.size()) { transform(block_); used_ = 0; }
    }
    while (input.size() - offset >= block_.size()) {
      std::array<std::uint8_t, 64> full{};
      std::memcpy(full.data(), input.data() + offset, full.size());
      transform(full);
      offset += full.size();
    }
    if (offset < input.size()) {
      used_ = input.size() - offset;
      std::memcpy(block_.data(), input.data() + offset, used_);
    }
  }
  [[nodiscard]] Digest final() noexcept {
    const std::uint64_t bit_length = total_bytes_ * 8U;
    block_[used_++] = 0x80U;
    if (used_ > 56) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.end(), 0U);
      transform(block_); used_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.begin() + 56, 0U);
    for (std::size_t index = 0; index < 8; ++index) {
      block_[63 - index] = static_cast<std::uint8_t>(bit_length >> (index * 8U));
    }
    transform(block_);
    Digest output{};
    for (std::size_t index = 0; index < state_.size(); ++index) {
      for (std::size_t byte = 0; byte < 4; ++byte) {
        output[index * 4 + byte] = static_cast<std::uint8_t>(state_[index] >> (24U - byte * 8U));
      }
    }
    return output;
  }
 private:
  [[nodiscard]] static std::uint32_t rotr(const std::uint32_t value, const std::uint32_t count) noexcept {
    return (value >> count) | (value << (32U - count));
  }
  void transform(const std::array<std::uint8_t, 64>& block) noexcept {
    constexpr std::array<std::uint32_t, 64> k{
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index < 16; ++index) {
      words[index] = (static_cast<std::uint32_t>(block[index * 4]) << 24U) |
                     (static_cast<std::uint32_t>(block[index * 4 + 1]) << 16U) |
                     (static_cast<std::uint32_t>(block[index * 4 + 2]) << 8U) |
                     static_cast<std::uint32_t>(block[index * 4 + 3]);
    }
    for (std::size_t index = 16; index < words.size(); ++index) {
      const auto s0 = rotr(words[index - 15], 7U) ^ rotr(words[index - 15], 18U) ^ (words[index - 15] >> 3U);
      const auto s1 = rotr(words[index - 2], 17U) ^ rotr(words[index - 2], 19U) ^ (words[index - 2] >> 10U);
      words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    auto a = state_[0]; auto b = state_[1]; auto c = state_[2]; auto d = state_[3];
    auto e = state_[4]; auto f = state_[5]; auto g = state_[6]; auto h = state_[7];
    for (std::size_t index = 0; index < words.size(); ++index) {
      const auto s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
      const auto choose = (e & f) ^ ((~e) & g);
      const auto temporary1 = h + s1 + choose + k[index] + words[index];
      const auto s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
      const auto majority = (a & b) ^ (a & c) ^ (b & c);
      const auto temporary2 = s0 + majority;
      h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
  }
  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> block_{};
  std::size_t used_{};
  std::uint64_t total_bytes_{};
};

[[nodiscard]] Digest sha256(const std::span<const std::uint8_t> bytes) noexcept {
  Sha256 hasher; hasher.update(bytes); return hasher.final();
}

[[nodiscard]] bool constant_time_equal(const Digest& left, const Digest& right) noexcept {
  std::uint8_t different = 0;
  for (std::size_t index = 0; index < left.size(); ++index) different |= left[index] ^ right[index];
  return different == 0;
}

[[nodiscard]] bool safe_regular_file(const struct stat& metadata,
                                     const std::size_t maximum_bytes) noexcept {
  return S_ISREG(metadata.st_mode) && metadata.st_uid == 0 &&
         (metadata.st_mode & 0222U) == 0U && metadata.st_nlink == 1 &&
         metadata.st_size >= 0 &&
         static_cast<std::uint64_t>(metadata.st_size) <= maximum_bytes;
}

[[nodiscard]] bool read_fd(const int fd, std::vector<std::uint8_t>* output,
                           const std::size_t maximum_bytes) noexcept {
  output->clear();
  std::array<std::uint8_t, 8192> buffer{};
  while (true) {
    const auto count = ::read(fd, buffer.data(), buffer.size());
    if (count == 0) return true;
    if (count < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (output->size() > maximum_bytes - static_cast<std::size_t>(count)) return false;
    output->insert(output->end(), buffer.begin(), buffer.begin() + count);
  }
}

[[nodiscard]] int open_sealed_child(const int parent_fd, const std::string_view name) noexcept {
  if (!is_lower_hex_digest(name) && name != "manifest.cbor") return -1;
  std::string nul_terminated{name};
  return ::openat(parent_fd, nul_terminated.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

struct CborValue {
  enum class Kind { unsigned_integer, negative_integer, bytes, text, array, map, null_value };
  Kind kind{};
  std::uint64_t unsigned_value{};
  std::int64_t signed_value{};
  std::vector<std::uint8_t> bytes;
  std::string text;
  std::vector<CborValue> array;
  std::vector<std::pair<CborValue, CborValue>> map;
};

[[nodiscard]] bool valid_utf8(const std::span<const std::uint8_t> bytes) noexcept {
  for (std::size_t index = 0; index < bytes.size();) {
    const auto lead = bytes[index++];
    if (lead <= 0x7fU) continue;
    std::size_t continuation_count{};
    std::uint32_t code_point{};
    if (lead >= 0xc2U && lead <= 0xdfU) { continuation_count = 1; code_point = lead & 0x1fU; }
    else if (lead >= 0xe0U && lead <= 0xefU) { continuation_count = 2; code_point = lead & 0x0fU; }
    else if (lead >= 0xf0U && lead <= 0xf4U) { continuation_count = 3; code_point = lead & 0x07U; }
    else return false;
    if (bytes.size() - index < continuation_count) return false;
    for (std::size_t count = 0; count < continuation_count; ++count) {
      const auto next = bytes[index++];
      if ((next & 0xc0U) != 0x80U) return false;
      code_point = (code_point << 6U) | (next & 0x3fU);
    }
    if ((continuation_count == 1 && code_point < 0x80U) ||
        (continuation_count == 2 && code_point < 0x800U) ||
        (continuation_count == 3 && code_point < 0x10000U) ||
        (code_point >= 0xd800U && code_point <= 0xdfffU) || code_point > 0x10ffffU) return false;
  }
  return true;
}

class CborParser {
 public:
  explicit CborParser(std::span<const std::uint8_t> input) : input_(input) {}
  [[nodiscard]] ManifestError parse(CborValue* output) noexcept {
    if (input_.size() > kMaxManifestBytes) return ManifestError::invalid_field;
    const auto result = value(0, output);
    return result == ManifestError::none && offset_ != input_.size() ? ManifestError::malformed_cbor : result;
  }
 private:
  [[nodiscard]] ManifestError value(const std::size_t depth, CborValue* output) noexcept {
    if (depth > 16) return ManifestError::invalid_field;
    std::uint8_t initial{};
    if (!take_byte(&initial)) return ManifestError::malformed_cbor;
    const auto major = static_cast<std::uint8_t>(initial >> 5U);
    const auto additional = static_cast<std::uint8_t>(initial & 0x1fU);
    if (additional == 31U) return ManifestError::non_canonical_cbor;
    std::uint64_t argument{};
    switch (major) {
      case 0:
        if (const auto error = argument_value(additional, &argument); error != ManifestError::none) return error;
        output->kind = CborValue::Kind::unsigned_integer; output->unsigned_value = argument; return ManifestError::none;
      case 1:
        if (const auto error = argument_value(additional, &argument); error != ManifestError::none) return error;
        if (argument > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return ManifestError::invalid_field;
        output->kind = CborValue::Kind::negative_integer; output->signed_value = -1 - static_cast<std::int64_t>(argument); return ManifestError::none;
      case 2:
      case 3: {
        if (const auto error = argument_value(additional, &argument); error != ManifestError::none) return error;
        if (argument > 65'536U || argument > input_.size() - offset_) return ManifestError::invalid_field;
        const auto length = static_cast<std::size_t>(argument);
        output->kind = major == 2 ? CborValue::Kind::bytes : CborValue::Kind::text;
        if (major == 2) output->bytes.assign(input_.begin() + static_cast<std::ptrdiff_t>(offset_), input_.begin() + static_cast<std::ptrdiff_t>(offset_ + length));
        else {
          const auto text_bytes = input_.subspan(offset_, length);
          if (!valid_utf8(text_bytes)) return ManifestError::invalid_field;
          output->text.assign(reinterpret_cast<const char*>(text_bytes.data()), length);
        }
        offset_ += length;
        return ManifestError::none;
      }
      case 4:
      case 5: {
        if (const auto error = argument_value(additional, &argument); error != ManifestError::none) return error;
        const auto limit = major == 4 ? kMaxGraphActions : 128U;
        if (argument > limit) return ManifestError::invalid_field;
        if (major == 4) {
          output->kind = CborValue::Kind::array; output->array.reserve(static_cast<std::size_t>(argument));
          for (std::uint64_t index = 0; index < argument; ++index) { CborValue item{}; if (const auto error = value(depth + 1, &item); error != ManifestError::none) return error; output->array.push_back(std::move(item)); }
        } else {
          output->kind = CborValue::Kind::map; output->map.reserve(static_cast<std::size_t>(argument));
          std::vector<std::uint8_t> previous_key;
          for (std::uint64_t index = 0; index < argument; ++index) {
            const auto start = offset_; CborValue key{}; if (const auto error = value(depth + 1, &key); error != ManifestError::none) return error;
            std::vector<std::uint8_t> encoded_key(input_.begin() + static_cast<std::ptrdiff_t>(start), input_.begin() + static_cast<std::ptrdiff_t>(offset_));
            if (!previous_key.empty() && !(previous_key.size() < encoded_key.size() || (previous_key.size() == encoded_key.size() && previous_key < encoded_key))) return ManifestError::non_canonical_cbor;
            previous_key = std::move(encoded_key);
            CborValue item{}; if (const auto error = value(depth + 1, &item); error != ManifestError::none) return error;
            output->map.emplace_back(std::move(key), std::move(item));
          }
        }
        return ManifestError::none;
      }
      case 7:
        if (additional == 22U) { output->kind = CborValue::Kind::null_value; return ManifestError::none; }
        return ManifestError::malformed_cbor;
      default: return ManifestError::malformed_cbor;
    }
  }
  [[nodiscard]] ManifestError argument_value(const std::uint8_t additional, std::uint64_t* value) noexcept {
    if (additional <= 23U) { *value = additional; return ManifestError::none; }
    std::size_t width{};
    if (additional == 24U) width = 1; else if (additional == 25U) width = 2; else if (additional == 26U) width = 4; else if (additional == 27U) width = 8; else return ManifestError::non_canonical_cbor;
    if (input_.size() - offset_ < width) return ManifestError::malformed_cbor;
    std::uint64_t parsed{};
    for (std::size_t index = 0; index < width; ++index) parsed = (parsed << 8U) | input_[offset_++];
    const auto minimal = (width == 1 && parsed >= 24U) || (width == 2 && parsed > 0xffU) || (width == 4 && parsed > 0xffffU) || (width == 8 && parsed > 0xffffffffU);
    if (!minimal) return ManifestError::non_canonical_cbor;
    *value = parsed; return ManifestError::none;
  }
  [[nodiscard]] bool take_byte(std::uint8_t* output) noexcept { if (offset_ == input_.size()) return false; *output = input_[offset_++]; return true; }
  std::span<const std::uint8_t> input_;
  std::size_t offset_{};
};

[[nodiscard]] const CborValue* map_field(const CborValue& map, const std::uint64_t key) noexcept {
  if (map.kind != CborValue::Kind::map) return nullptr;
  for (const auto& [candidate, value] : map.map) if (candidate.kind == CborValue::Kind::unsigned_integer && candidate.unsigned_value == key) return &value;
  return nullptr;
}
[[nodiscard]] bool map_has_exact_fields(const CborValue& map, const std::span<const std::uint64_t> keys) noexcept {
  if (map.kind != CborValue::Kind::map || map.map.size() != keys.size()) return false;
  for (const auto key : keys) if (map_field(map, key) == nullptr) return false;
  return true;
}
[[nodiscard]] bool copy_digest(const CborValue* value, Digest* output) noexcept {
  if (value == nullptr || value->kind != CborValue::Kind::bytes || value->bytes.size() != output->size()) return false;
  std::copy(value->bytes.begin(), value->bytes.end(), output->begin()); return true;
}
[[nodiscard]] bool valid_package_name(const std::string_view value) noexcept {
  if (value.empty() || value.size() > 255 || value.front() < 'a' || value.front() > 'z') return false;
  return std::all_of(value.begin() + 1, value.end(), [](const char item) { return (item >= 'a' && item <= 'z') || (item >= '0' && item <= '9') || item == '+' || item == '.' || item == '-'; });
}
[[nodiscard]] bool valid_text(const CborValue* value, std::string* output, const std::size_t maximum, const bool allow_empty = false) noexcept {
  if (value == nullptr || value->kind != CborValue::Kind::text || value->text.size() > maximum || (!allow_empty && value->text.empty())) return false;
  *output = value->text; return true;
}
[[nodiscard]] bool parse_action(const CborValue& value, PackageAction* action) noexcept {
  constexpr std::array<std::uint64_t, 10> kFields{1,2,3,4,5,6,7,8,9,10};
  if (!map_has_exact_fields(value, kFields)) return false;
  if (!valid_text(map_field(value, 1), &action->package_name, 255) || !valid_package_name(action->package_name) ||
      !valid_text(map_field(value, 2), &action->architecture, 64) || !valid_text(map_field(value, 3), &action->installed_version, 256, true) ||
      !valid_text(map_field(value, 4), &action->target_version, 256) || !valid_text(map_field(value, 6), &action->origin_identity, 512)) return false;
  const auto* kind = map_field(value, 5);
  const auto* archive = map_field(value, 9); const auto* installed = map_field(value, 10);
  if (kind == nullptr || kind->kind != CborValue::Kind::unsigned_integer || kind->unsigned_value != 1U ||
      archive == nullptr || archive->kind != CborValue::Kind::unsigned_integer ||
      installed == nullptr || installed->kind != CborValue::Kind::unsigned_integer || !copy_digest(map_field(value, 7), &action->deb_digest)) return false;
  action->kind = PackageActionKind::install; action->archive_bytes = archive->unsigned_value; action->installed_delta_bytes = installed->unsigned_value;
  const auto* parents = map_field(value, 8);
  if (parents == nullptr || parents->kind != CborValue::Kind::array || parents->array.size() > kMaxGraphActions) return false;
  action->dependency_parents.clear(); action->dependency_parents.reserve(parents->array.size());
  for (const auto& parent : parents->array) {
    if (parent.kind != CborValue::Kind::unsigned_integer || parent.unsigned_value > std::numeric_limits<std::uint32_t>::max()) return false;
    action->dependency_parents.push_back(static_cast<std::uint32_t>(parent.unsigned_value));
  }
  return true;
}

[[nodiscard]] bool actions_equal(const PackageAction& left, const PackageAction& right) noexcept {
  return left.package_name == right.package_name && left.architecture == right.architecture && left.installed_version == right.installed_version &&
         left.target_version == right.target_version && left.kind == right.kind && left.origin_identity == right.origin_identity &&
         constant_time_equal(left.deb_digest, right.deb_digest) && left.archive_bytes == right.archive_bytes &&
         left.installed_delta_bytes == right.installed_delta_bytes && left.dependency_parents == right.dependency_parents;
}

}  // namespace

StartupContractError validate_startup_contract(const int argc, const char* const argv[], const char* const envp[]) noexcept {
  if (argc != 1 || argv == nullptr || argv[0] == nullptr || argv[1] != nullptr) return StartupContractError::arguments_present;
  return environment_matches(envp) ? StartupContractError::none : StartupContractError::environment_invalid;
}

std::string_view startup_contract_error_name(const StartupContractError error) noexcept {
  switch (error) { case StartupContractError::none: return "none"; case StartupContractError::arguments_present: return "arguments_present"; case StartupContractError::environment_invalid: return "environment_invalid"; }
  return "unknown";
}

HandoffContractError validate_handoff_contract(const std::span<const DescriptorObservation> descriptors) noexcept {
  for (const auto fd : kRequiredInheritedFds) {
    const auto iterator = std::find_if(descriptors.begin(), descriptors.end(), [fd](const DescriptorObservation& item) { return item.fd == fd; });
    if (iterator == descriptors.end()) return HandoffContractError::missing_required_fd;
    if (fd == kControlFd && !iterator->is_seqpacket_socket) return HandoffContractError::control_not_seqpacket;
    if (fd == kControlFd && !iterator->peer_identity_matches) return HandoffContractError::peer_identity_unverified;
    if (fd == kPlanRootFd && (!iterator->is_directory || !iterator->is_read_only)) return !iterator->is_directory ? HandoffContractError::plan_root_not_directory : HandoffContractError::plan_root_not_read_only;
    if (fd == kJournalRootFd && !iterator->is_directory) return HandoffContractError::journal_root_not_directory;
    if (fd == kContentStoreFd && (!iterator->is_directory || !iterator->is_read_only)) return !iterator->is_directory ? HandoffContractError::content_store_not_directory : HandoffContractError::content_store_not_read_only;
  }
  for (const auto& descriptor : descriptors) if (descriptor.fd >= kControlFd && !is_required_fd(descriptor.fd)) return HandoffContractError::unexpected_fd;
  return HandoffContractError::none;
}

std::string_view handoff_contract_error_name(const HandoffContractError error) noexcept {
  switch (error) {
    case HandoffContractError::none: return "none"; case HandoffContractError::missing_required_fd: return "missing_required_fd"; case HandoffContractError::unexpected_fd: return "unexpected_fd";
    case HandoffContractError::control_not_seqpacket: return "control_not_seqpacket"; case HandoffContractError::plan_root_not_directory: return "plan_root_not_directory";
    case HandoffContractError::plan_root_not_read_only: return "plan_root_not_read_only"; case HandoffContractError::journal_root_not_directory: return "journal_root_not_directory";
    case HandoffContractError::content_store_not_directory: return "content_store_not_directory"; case HandoffContractError::content_store_not_read_only: return "content_store_not_read_only";
    case HandoffContractError::peer_identity_unverified: return "peer_identity_unverified";
  }
  return "unknown";
}

HandoffContractError validate_runtime_handoff() noexcept {
  DIR* directory = ::opendir("/proc/self/fd");
  if (directory == nullptr) return HandoffContractError::missing_required_fd;
  std::vector<DescriptorObservation> observed;
  while (const dirent* entry = ::readdir(directory)) {
    char* end{}; errno = 0; const long fd = std::strtol(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0' || fd < kControlFd || fd > std::numeric_limits<int>::max()) continue;
    if (fd == ::dirfd(directory)) continue;
    const int flags = ::fcntl(static_cast<int>(fd), F_GETFL);
    struct stat info {};
    if (flags < 0 || ::fstat(static_cast<int>(fd), &info) != 0) { ::closedir(directory); return HandoffContractError::unexpected_fd; }
    DescriptorObservation item{.fd = static_cast<int>(fd), .is_directory = S_ISDIR(info.st_mode), .is_read_only = (flags & O_ACCMODE) == O_RDONLY};
    if (item.fd == kControlFd) {
      int socket_type{}; socklen_t length = sizeof(socket_type);
      item.is_seqpacket_socket = ::getsockopt(item.fd, SOL_SOCKET, SO_TYPE, &socket_type, &length) == 0 && socket_type == SOCK_SEQPACKET;
      // The authenticated startup packet binds PID and start time. Before that
      // packet arrives, peer identity is intentionally unverified and the
      // helper fails closed rather than trusting SO_PEERCRED's PID alone.
      item.peer_identity_matches = false;
    }
    observed.push_back(item);
  }
  ::closedir(directory);
  return validate_handoff_contract(observed);
}

ImmutableInputError validate_immutable_object(const ImmutableObjectMetadata& metadata, const std::span<const std::uint8_t> bytes) noexcept {
  if (!is_lower_hex_digest(metadata.object_name)) return ImmutableInputError::invalid_object_name;
  if (metadata.object_name != digest_hex(metadata.expected_digest)) return ImmutableInputError::object_name_digest_mismatch;
  if (!constant_time_equal(sha256(bytes), metadata.expected_digest)) return ImmutableInputError::object_digest_mismatch;
  if (!metadata.regular_file) return ImmutableInputError::not_regular_file;
  if (metadata.owner_uid != 0U) return ImmutableInputError::owner_not_root;
  if ((metadata.mode & 0022U) != 0U) return ImmutableInputError::writable_by_group_or_other;
  if (metadata.hardlink_count != 1U) return ImmutableInputError::hardlink_present;
  return ImmutableInputError::none;
}

std::string_view immutable_input_error_name(const ImmutableInputError error) noexcept {
  switch (error) {
    case ImmutableInputError::none: return "none"; case ImmutableInputError::invalid_object_name: return "invalid_object_name";
    case ImmutableInputError::object_name_digest_mismatch: return "object_name_digest_mismatch"; case ImmutableInputError::object_digest_mismatch: return "object_digest_mismatch";
    case ImmutableInputError::not_regular_file: return "not_regular_file"; case ImmutableInputError::owner_not_root: return "owner_not_root";
    case ImmutableInputError::writable_by_group_or_other: return "writable_by_group_or_other"; case ImmutableInputError::hardlink_present: return "hardlink_present";
  }
  return "unknown";
}

SealedPlanError verify_sealed_plan(const int plan_root_fd, const int content_store_fd,
                                   const Digest& manifest_digest,
                                   PlanManifest* manifest) noexcept {
  if (manifest == nullptr) return SealedPlanError::manifest_invalid;
  const auto manifest_fd = open_sealed_child(plan_root_fd, "manifest.cbor");
  if (manifest_fd < 0) return errno == ENOENT ? SealedPlanError::manifest_missing : SealedPlanError::io_failure;
  struct stat manifest_metadata {};
  if (::fstat(manifest_fd, &manifest_metadata) != 0 ||
      !safe_regular_file(manifest_metadata, kMaxManifestBytes)) {
    ::close(manifest_fd);
    return SealedPlanError::manifest_unsafe;
  }
  std::vector<std::uint8_t> encoded_manifest;
  const auto read_manifest = read_fd(manifest_fd, &encoded_manifest, kMaxManifestBytes);
  ::close(manifest_fd);
  if (!read_manifest) return SealedPlanError::io_failure;
  if (!constant_time_equal(sha256(encoded_manifest), manifest_digest)) {
    return SealedPlanError::manifest_digest_mismatch;
  }
  PlanManifest parsed{};
  if (parse_plan_manifest(encoded_manifest, &parsed) != ManifestError::none) {
    return SealedPlanError::manifest_invalid;
  }
  for (const auto& input : parsed.inputs) {
    const auto name = digest_hex(input.digest);
    const auto object_fd = open_sealed_child(content_store_fd, name);
    if (object_fd < 0) return errno == ENOENT ? SealedPlanError::input_missing : SealedPlanError::io_failure;
    struct stat metadata {};
    if (::fstat(object_fd, &metadata) != 0 || !safe_regular_file(metadata, kMaxObjectBytes)) {
      ::close(object_fd);
      return SealedPlanError::input_unsafe;
    }
    std::vector<std::uint8_t> bytes;
    const auto read_object = read_fd(object_fd, &bytes, kMaxObjectBytes);
    ::close(object_fd);
    if (!read_object) return SealedPlanError::io_failure;
    if (!constant_time_equal(sha256(bytes), input.digest)) return SealedPlanError::input_digest_mismatch;
  }
  *manifest = std::move(parsed);
  return SealedPlanError::none;
}

std::string_view sealed_plan_error_name(const SealedPlanError error) noexcept {
  switch (error) {
    case SealedPlanError::none: return "none";
    case SealedPlanError::manifest_missing: return "manifest_missing";
    case SealedPlanError::manifest_unsafe: return "manifest_unsafe";
    case SealedPlanError::manifest_digest_mismatch: return "manifest_digest_mismatch";
    case SealedPlanError::manifest_invalid: return "manifest_invalid";
    case SealedPlanError::input_missing: return "input_missing";
    case SealedPlanError::input_unsafe: return "input_unsafe";
    case SealedPlanError::input_digest_mismatch: return "input_digest_mismatch";
    case SealedPlanError::io_failure: return "io_failure";
  }
  return "unknown";
}

bool normalize_action_graph(std::vector<PackageAction>* actions) noexcept {
  if (actions == nullptr || actions->size() > kMaxGraphActions) return false;
  const auto original = *actions;
  for (const auto& action : original) {
    if (!valid_package_name(action.package_name) || action.architecture.empty() || action.target_version.empty() || action.kind != PackageActionKind::install) return false;
    for (const auto parent : action.dependency_parents) if (parent >= original.size()) return false;
  }
  std::vector<std::size_t> order(original.size());
  for (std::size_t index = 0; index < order.size(); ++index) order[index] = index;
  std::sort(order.begin(), order.end(), [&original](const std::size_t left, const std::size_t right) {
    const auto& a = original[left]; const auto& b = original[right];
    return std::tie(a.package_name, a.architecture, a.target_version) < std::tie(b.package_name, b.architecture, b.target_version);
  });
  for (std::size_t index = 1; index < order.size(); ++index) {
    const auto& previous = original[order[index - 1]]; const auto& current = original[order[index]];
    if (std::tie(previous.package_name, previous.architecture, previous.target_version) == std::tie(current.package_name, current.architecture, current.target_version)) return false;
  }
  std::vector<std::uint32_t> remap(original.size());
  std::vector<PackageAction> normalized; normalized.reserve(original.size());
  for (std::size_t index = 0; index < order.size(); ++index) remap[order[index]] = static_cast<std::uint32_t>(index);
  for (const auto old_index : order) {
    PackageAction action = original[old_index];
    for (auto& parent : action.dependency_parents) parent = remap[parent];
    std::sort(action.dependency_parents.begin(), action.dependency_parents.end());
    if (std::adjacent_find(action.dependency_parents.begin(), action.dependency_parents.end()) != action.dependency_parents.end()) return false;
    normalized.push_back(std::move(action));
  }
  *actions = std::move(normalized); return true;
}

bool action_graphs_equal(const std::vector<PackageAction>& left, const std::vector<PackageAction>& right) noexcept {
  return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(), actions_equal);
}

ManifestError parse_plan_manifest(const std::span<const std::uint8_t> encoded, PlanManifest* manifest) noexcept {
  if (manifest == nullptr) return ManifestError::invalid_field;
  CborValue root{}; if (const auto error = CborParser(encoded).parse(&root); error != ManifestError::none) return error;
  constexpr std::array<std::uint64_t, 8> kFields{1,2,3,4,5,6,7,8};
  if (root.kind != CborValue::Kind::map) return ManifestError::malformed_cbor;
  if (root.map.size() != kFields.size()) return root.map.size() > kFields.size() ? ManifestError::unknown_field : ManifestError::missing_field;
  if (!map_has_exact_fields(root, kFields)) return ManifestError::unknown_field;
  const auto* version = map_field(root, 1);
  if (version == nullptr || version->kind != CborValue::Kind::unsigned_integer || version->unsigned_value != 1U) return ManifestError::unsupported_version;
  PlanManifest candidate{};
  if (!copy_digest(map_field(root, 2), &candidate.plan_digest) || !copy_digest(map_field(root, 5), &candidate.policy_digest) || !copy_digest(map_field(root, 8), &candidate.prestate_observation)) return ManifestError::invalid_field;
  const auto* created = map_field(root, 6); const auto* toolchain = map_field(root, 7);
  if (created == nullptr || (created->kind != CborValue::Kind::unsigned_integer && created->kind != CborValue::Kind::negative_integer) || !valid_text(toolchain, &candidate.toolchain, 128)) return ManifestError::invalid_field;
  candidate.created_utc = created->kind == CborValue::Kind::unsigned_integer ? static_cast<std::int64_t>(created->unsigned_value) : created->signed_value;
  const auto* inputs = map_field(root, 3);
  if (inputs == nullptr || inputs->kind != CborValue::Kind::array || inputs->array.size() > kMaxInputs) return ManifestError::invalid_field;
  Digest previous{}; bool has_previous = false;
  for (const auto& input : inputs->array) {
    constexpr std::array<std::uint64_t, 2> kInputFields{1,2};
    SealedInput parsed{}; const auto* role = map_field(input, 2);
    if (!map_has_exact_fields(input, kInputFields) || !copy_digest(map_field(input, 1), &parsed.digest) || role == nullptr || role->kind != CborValue::Kind::unsigned_integer || role->unsigned_value == 0U) return ManifestError::invalid_field;
    parsed.role = role->unsigned_value;
    if (has_previous && !std::lexicographical_compare(previous.begin(), previous.end(), parsed.digest.begin(), parsed.digest.end())) return constant_time_equal(previous, parsed.digest) ? ManifestError::duplicate_input : ManifestError::input_order_invalid;
    previous = parsed.digest; has_previous = true; candidate.inputs.push_back(parsed);
  }
  const auto* graph = map_field(root, 4);
  if (graph == nullptr || graph->kind != CborValue::Kind::array || graph->array.size() > kMaxGraphActions) return ManifestError::action_graph_invalid;
  for (const auto& item : graph->array) { PackageAction action{}; if (!parse_action(item, &action)) return ManifestError::action_graph_invalid; candidate.action_graph.push_back(std::move(action)); }
  const auto unnormalized = candidate.action_graph;
  if (!normalize_action_graph(&candidate.action_graph) || !action_graphs_equal(unnormalized, candidate.action_graph)) return ManifestError::action_graph_invalid;
  *manifest = std::move(candidate); return ManifestError::none;
}

std::string_view manifest_error_name(const ManifestError error) noexcept {
  switch (error) {
    case ManifestError::none: return "none"; case ManifestError::malformed_cbor: return "malformed_cbor"; case ManifestError::non_canonical_cbor: return "non_canonical_cbor";
    case ManifestError::unsupported_version: return "unsupported_version"; case ManifestError::missing_field: return "missing_field"; case ManifestError::unknown_field: return "unknown_field";
    case ManifestError::invalid_field: return "invalid_field"; case ManifestError::duplicate_input: return "duplicate_input"; case ManifestError::input_order_invalid: return "input_order_invalid";
    case ManifestError::action_graph_invalid: return "action_graph_invalid";
  }
  return "unknown";
}

}  // namespace rootpermit::apt_helper
