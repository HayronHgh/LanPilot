#include "rwn/core/pairing_store.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <map>
#include <ranges>
#include <stdexcept>
#include <string>
#include <utility>

namespace rwn::core {
namespace {

constexpr std::uintmax_t maximum_state_bytes = 16U * 1024U;

[[nodiscard]] bool identifier(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return std::isalnum(character) != 0 || character == '-' ||
                   character == '_' || character == '.';
        });
}

void validate_device(const PairedDevice& device) {
    const auto display_valid = !device.display_name.empty() &&
        device.display_name.size() <= 128 &&
        std::ranges::all_of(
            device.display_name, [](const unsigned char character) {
                return character >= 0x20U && character != 0x7fU;
            });
    if (!identifier(device.id) || !display_valid ||
        !is_canonical_fingerprint(device.fingerprint) ||
        device.certificate.device_id != device.id ||
        device.certificate.fingerprint != device.fingerprint ||
        !identifier(device.certificate.serial) ||
        device.certificate.not_before >= device.certificate.not_after) {
        throw std::invalid_argument("pairing state device is invalid");
    }
}

[[nodiscard]] std::string hex_encode(const std::string_view input) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result;
    result.reserve(input.size() * 2);
    for (const unsigned char character : input) {
        result.push_back(digits[character >> 4U]);
        result.push_back(digits[character & 0x0fU]);
    }
    return result;
}

[[nodiscard]] std::string hex_decode(const std::string_view input) {
    const auto nibble = [](const char character) -> unsigned int {
        if (character >= '0' && character <= '9')
            return static_cast<unsigned int>(character - '0');
        if (character >= 'a' && character <= 'f')
            return static_cast<unsigned int>(character - 'a' + 10);
        throw std::invalid_argument("pairing state hex value is invalid");
    };
    if (input.empty() || input.size() > 256 || input.size() % 2 != 0)
        throw std::invalid_argument("pairing state display name is invalid");
    std::string result(input.size() / 2, '\0');
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<char>(
            (nibble(input[index * 2]) << 4U) |
            nibble(input[index * 2 + 1]));
    }
    return result;
}

[[nodiscard]] std::int64_t parse_integer(const std::string_view input) {
    std::int64_t result{};
    const auto parsed = std::from_chars(
        input.data(), input.data() + input.size(), result);
    if (input.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != input.data() + input.size()) {
        throw std::invalid_argument("pairing state integer is invalid");
    }
    return result;
}

[[nodiscard]] std::map<std::string, std::string, std::less<>> parse_fields(
    const std::string& contents) {
    std::map<std::string, std::string, std::less<>> fields;
    std::size_t offset{};
    while (offset < contents.size()) {
        const auto end = contents.find('\n', offset);
        if (end == std::string::npos)
            throw std::invalid_argument("pairing state line is unterminated");
        const std::string_view line(contents.data() + offset, end - offset);
        const auto separator = line.find('=');
        if (line.empty() || line.find('\r') != std::string_view::npos ||
            separator == std::string_view::npos || separator == 0 ||
            separator + 1 >= line.size()) {
            throw std::invalid_argument("pairing state line is invalid");
        }
        const auto [_, inserted] = fields.emplace(
            std::string(line.substr(0, separator)),
            std::string(line.substr(separator + 1)));
        if (!inserted)
            throw std::invalid_argument("pairing state field is duplicated");
        offset = end + 1;
    }
    return fields;
}

[[nodiscard]] std::string take(
    std::map<std::string, std::string, std::less<>>& fields,
    const std::string_view key) {
    const auto found = fields.find(key);
    if (found == fields.end())
        throw std::invalid_argument("pairing state field is missing");
    auto value = std::move(found->second);
    fields.erase(found);
    return value;
}

[[nodiscard]] std::string serialize(const PairedDevice& device) {
    validate_device(device);
    const auto not_before = std::chrono::duration_cast<std::chrono::seconds>(
        device.certificate.not_before.time_since_epoch()).count();
    const auto not_after = std::chrono::duration_cast<std::chrono::seconds>(
        device.certificate.not_after.time_since_epoch()).count();
    if (not_before < 0 || not_after <= not_before)
        throw std::invalid_argument("pairing state certificate time is invalid");
    return "schema_version=1\n"
           "device_id=" + device.id + "\n"
           "display_name_hex=" + hex_encode(device.display_name) + "\n"
           "certificate_sha256=" + device.fingerprint + "\n"
           "certificate_serial=" + device.certificate.serial + "\n"
           "not_before_unix=" + std::to_string(not_before) + "\n"
           "not_after_unix=" + std::to_string(not_after) + "\n"
           "revoked=" + std::string(device.revoked ? "1\n" : "0\n");
}

[[nodiscard]] PairedDevice deserialize(const std::string& contents) {
    auto fields = parse_fields(contents);
    if (take(fields, "schema_version") != "1")
        throw std::invalid_argument("pairing state schema is unsupported");
    const auto id = take(fields, "device_id");
    const auto display_name = hex_decode(take(fields, "display_name_hex"));
    const auto fingerprint = take(fields, "certificate_sha256");
    const auto serial = take(fields, "certificate_serial");
    const auto not_before = parse_integer(take(fields, "not_before_unix"));
    const auto not_after = parse_integer(take(fields, "not_after_unix"));
    const auto revoked = take(fields, "revoked");
    if (!fields.empty() || (revoked != "0" && revoked != "1") ||
        not_before < 0 || not_after <= not_before) {
        throw std::invalid_argument("pairing state contains invalid fields");
    }
    PairedDevice device{
        .id = id,
        .display_name = display_name,
        .fingerprint = fingerprint,
        .certificate = {
            .device_id = id,
            .fingerprint = fingerprint,
            .serial = serial,
            .not_before = TimePoint{std::chrono::seconds{not_before}},
            .not_after = TimePoint{std::chrono::seconds{not_after}},
        },
        .revoked = revoked == "1",
    };
    validate_device(device);
    return device;
}

void reject_link(const std::filesystem::path& path) {
    if (std::filesystem::is_symlink(std::filesystem::symlink_status(path)))
        throw std::invalid_argument("pairing state path must not be a symlink");
}

[[nodiscard]] std::filesystem::path validate_root(
    std::filesystem::path root) {
    if (!root.is_absolute())
        throw std::invalid_argument("pairing root must be absolute");
    reject_link(root);
    return root;
}

[[nodiscard]] std::filesystem::path resolve_state_path(
    const WorkspaceScope& scope, const std::filesystem::path& relative) {
    if (relative.empty() || relative.is_absolute())
        throw std::invalid_argument("pairing state path must be relative");
    auto current = scope.root();
    for (const auto& component : relative) {
        current /= component;
        reject_link(current);
    }
    return scope.resolve(relative);
}

}  // namespace

PairingStore::PairingStore(
    std::filesystem::path root,
    std::filesystem::path relative_state_file,
    DurableFileSystem& filesystem)
    : scope_(validate_root(std::move(root))),
      state_path_(resolve_state_path(scope_, relative_state_file)),
      staging_path_(resolve_state_path(
          scope_,
          std::filesystem::path(relative_state_file.string() + ".staging"))),
      filesystem_(filesystem) {
    std::filesystem::create_directories(scope_.root());
    std::filesystem::create_directories(state_path_.parent_path());
    reject_link(scope_.root());
    reject_link(state_path_);
    reject_link(staging_path_);
}

bool PairingStore::exists() const {
    reject_link(state_path_);
    return std::filesystem::is_regular_file(state_path_);
}

PairedDevice PairingStore::load() const {
    reject_link(state_path_);
    if (!std::filesystem::is_regular_file(state_path_) ||
        std::filesystem::file_size(state_path_) > maximum_state_bytes) {
        throw std::invalid_argument("pairing state file is invalid");
    }
    std::ifstream input(state_path_, std::ios::binary);
    if (!input) throw std::runtime_error("pairing state could not be opened");
    std::string contents{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    if (input.bad()) throw std::runtime_error("pairing state could not be read");
    return deserialize(contents);
}

void PairingStore::create(const PairedDevice& device) {
    persist(device, true);
}

void PairingStore::replace_revoked(const PairedDevice& device) {
    validate_device(device);
    const auto current = load();
    if (!current.revoked || device.revoked || current.id != device.id) {
        throw std::invalid_argument(
            "pairing rotation requires the same revoked device");
    }
    persist(device, false);
}

PairedDevice PairingStore::revoke(const std::string_view device_id) {
    auto device = load();
    if (device.id != device_id)
        throw std::invalid_argument("unknown device cannot be revoked");
    if (!device.revoked) {
        device.revoked = true;
        persist(device, false);
    }
    return device;
}

void PairingStore::persist(
    const PairedDevice& device, const bool require_absent) {
    validate_device(device);
    reject_link(state_path_);
    reject_link(staging_path_);
    if (require_absent && std::filesystem::exists(state_path_))
        throw std::invalid_argument("pairing state already exists");
    if (std::filesystem::exists(staging_path_))
        throw std::invalid_argument("pairing staging file already exists");
    const auto contents = serialize(device);
    std::ofstream output(staging_path_, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("pairing staging file could not be created");
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.flush();
    if (!output) throw std::runtime_error("pairing staging write failed");
    output.close();
    filesystem_.flush_file(staging_path_);
    reject_link(state_path_);
    filesystem_.atomic_replace(staging_path_, state_path_);
}

}  // namespace rwn::core
