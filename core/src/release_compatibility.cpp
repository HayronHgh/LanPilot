#include "rwn/core/release_compatibility.hpp"

#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <fstream>
#include <limits>
#include <map>
#include <ranges>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace rwn::core {
namespace {

[[nodiscard]] std::string_view trim(const std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1U);
}

[[nodiscard]] std::string parse_quoted_string(const std::string_view value) {
    const auto clean = trim(value);
    if (clean.size() < 2 || clean.front() != '"' || clean.back() != '"' ||
        clean.substr(1, clean.size() - 2U).find_first_of("\\\"\r\n") !=
            std::string_view::npos) {
        throw std::invalid_argument("release string setting is invalid");
    }
    return std::string(clean.substr(1, clean.size() - 2U));
}

template <typename Integer>
[[nodiscard]] Integer unsigned_integer(const std::string_view value) {
    const auto clean = trim(value);
    Integer result{};
    const auto parsed = std::from_chars(
        clean.data(), clean.data() + clean.size(), result);
    if (clean.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != clean.data() + clean.size()) {
        throw std::invalid_argument("release integer setting is invalid");
    }
    return result;
}

[[nodiscard]] bool valid_identifier(
    const std::string_view value, const std::size_t maximum) {
    return !value.empty() && value.size() <= maximum &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_' || character == '.';
           });
}

[[nodiscard]] bool lower_hex(
    const std::string_view value, const std::size_t length) {
    return value.size() == length &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isdigit(character) != 0 ||
                      (character >= 'a' && character <= 'f');
           });
}

[[nodiscard]] std::map<std::string, std::string, std::less<>> load_settings(
    const std::filesystem::path& path, const std::size_t maximum_bytes) {
    if (!path.is_absolute() || !std::filesystem::is_regular_file(path) ||
        std::filesystem::file_size(path) == 0 ||
        std::filesystem::file_size(path) > maximum_bytes) {
        throw std::invalid_argument("release settings path is invalid");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("release settings could not be opened");
    std::map<std::string, std::string, std::less<>> result;
    std::string line;
    while (std::getline(input, line)) {
        const auto clean = trim(line);
        if (clean.empty() || clean.front() == '#') continue;
        const auto equals = clean.find('=');
        if (equals == std::string_view::npos ||
            clean.find('=', equals + 1U) != std::string_view::npos) {
            throw std::invalid_argument("release setting line is invalid");
        }
        const auto key = std::string(trim(clean.substr(0, equals)));
        const auto value = std::string(trim(clean.substr(equals + 1U)));
        if (!valid_identifier(key, 64) || value.empty() ||
            !result.emplace(key, value).second) {
            throw std::invalid_argument("release setting key is invalid");
        }
    }
    if (input.bad()) throw std::runtime_error("release settings read failed");
    return result;
}

void validate_policy(const ReleaseCompatibilityPolicy& policy) {
    if (policy.minimum_peer_version > policy.maximum_peer_version ||
        policy.protocol_minimum == 0 ||
        policy.protocol_minimum > policy.protocol_maximum ||
        policy.state_schema_minimum_readable == 0 ||
        policy.state_schema_minimum_readable > policy.state_schema_current ||
        policy.package_schema == 0) {
        throw std::invalid_argument("release compatibility policy is invalid");
    }
}

void validate_manifest(const UpdateManifest& manifest) {
    if (!valid_identifier(manifest.platform, 32) ||
        !valid_identifier(manifest.architecture, 32) ||
        !lower_hex(manifest.package_sha256, 64) || manifest.package_size == 0 ||
        manifest.state_schema == 0 || manifest.package_schema == 0 ||
        manifest.signature_algorithm != "ecdsa-p256-sha256" ||
        !lower_hex(manifest.signature_hex, 128) ||
        manifest.minimum_installed_version >= manifest.version ||
        std::ranges::all_of(
            manifest.package_sha256, [](const char value) { return value == '0'; }) ||
        std::ranges::all_of(
            manifest.signature_hex, [](const char value) { return value == '0'; })) {
        throw std::invalid_argument("update manifest is invalid");
    }
}

[[nodiscard]] std::vector<std::byte> hex_bytes(const std::string_view value) {
    std::vector<std::byte> result(value.size() / 2U);
    const auto nibble = [](const unsigned char character) -> std::uint8_t {
        if (std::isdigit(character) != 0) {
            return static_cast<std::uint8_t>(character - '0');
        }
        return static_cast<std::uint8_t>(character - 'a' + 10);
    };
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>(
            (nibble(value[index * 2U]) << 4U) |
            nibble(value[index * 2U + 1U]));
    }
    return result;
}

}  // namespace

SemanticVersion parse_semantic_version(const std::string_view value) {
    SemanticVersion result;
    const auto first = value.find('.');
    const auto second = first == std::string_view::npos
                            ? std::string_view::npos
                            : value.find('.', first + 1U);
    if (first == std::string_view::npos || second == std::string_view::npos ||
        value.find('.', second + 1U) != std::string_view::npos) {
        throw std::invalid_argument("semantic version must be major.minor.patch");
    }
    result.major = unsigned_integer<std::uint16_t>(value.substr(0, first));
    result.minor = unsigned_integer<std::uint16_t>(
        value.substr(first + 1U, second - first - 1U));
    result.patch = unsigned_integer<std::uint16_t>(value.substr(second + 1U));
    if (to_string(result) != value) {
        throw std::invalid_argument("semantic version is not canonical");
    }
    return result;
}

std::string to_string(const SemanticVersion& version) {
    return std::to_string(version.major) + "." +
           std::to_string(version.minor) + "." +
           std::to_string(version.patch);
}

ReleaseCompatibilityPolicy load_release_compatibility(
    const std::filesystem::path& path) {
    const auto values = load_settings(path, 16U * 1024U);
    constexpr std::array<std::string_view, 8> required{
        "maximum_peer_version", "minimum_peer_version", "package_schema",
        "product_version", "protocol_maximum", "protocol_minimum",
        "state_schema_current", "state_schema_minimum_readable"};
    if (values.size() != required.size() ||
        !std::ranges::all_of(required, [&values](const auto key) {
            return values.contains(key);
        })) {
        throw std::invalid_argument("release compatibility settings are incomplete");
    }
    ReleaseCompatibilityPolicy policy{
        .product_version = parse_semantic_version(
            parse_quoted_string(values.at("product_version"))),
        .minimum_peer_version = parse_semantic_version(
            parse_quoted_string(values.at("minimum_peer_version"))),
        .maximum_peer_version = parse_semantic_version(
            parse_quoted_string(values.at("maximum_peer_version"))),
        .protocol_minimum = unsigned_integer<std::uint16_t>(
            values.at("protocol_minimum")),
        .protocol_maximum = unsigned_integer<std::uint16_t>(
            values.at("protocol_maximum")),
        .state_schema_current = unsigned_integer<std::uint32_t>(
            values.at("state_schema_current")),
        .state_schema_minimum_readable = unsigned_integer<std::uint32_t>(
            values.at("state_schema_minimum_readable")),
        .package_schema = unsigned_integer<std::uint32_t>(
            values.at("package_schema")),
    };
    validate_policy(policy);
    return policy;
}

bool peer_is_compatible(
    const ReleaseCompatibilityPolicy& policy,
    const SemanticVersion peer_version,
    const std::uint16_t peer_protocol_minimum,
    const std::uint16_t peer_protocol_maximum) {
    validate_policy(policy);
    return peer_version >= policy.minimum_peer_version &&
           peer_version <= policy.maximum_peer_version &&
           peer_protocol_minimum != 0 &&
           peer_protocol_minimum <= peer_protocol_maximum &&
           std::max(policy.protocol_minimum, peer_protocol_minimum) <=
               std::min(policy.protocol_maximum, peer_protocol_maximum);
}

bool state_schema_is_readable(
    const ReleaseCompatibilityPolicy& policy, const std::uint32_t schema) {
    validate_policy(policy);
    return schema >= policy.state_schema_minimum_readable &&
           schema <= policy.state_schema_current;
}

UpdateManifest load_update_manifest(const std::filesystem::path& path) {
    const auto values = load_settings(path, 64U * 1024U);
    constexpr std::array<std::string_view, 10> required{
        "architecture", "minimum_installed_version", "package_schema",
        "package_sha256", "package_size", "platform", "signature",
        "signature_algorithm", "state_schema", "version"};
    if (values.size() != required.size() ||
        !std::ranges::all_of(required, [&values](const auto key) {
            return values.contains(key);
        })) {
        throw std::invalid_argument("update manifest settings are incomplete");
    }
    UpdateManifest manifest{
        .version = parse_semantic_version(
            parse_quoted_string(values.at("version"))),
        .minimum_installed_version = parse_semantic_version(
            parse_quoted_string(values.at("minimum_installed_version"))),
        .platform = parse_quoted_string(values.at("platform")),
        .architecture = parse_quoted_string(values.at("architecture")),
        .package_sha256 = parse_quoted_string(values.at("package_sha256")),
        .package_size = unsigned_integer<std::uint64_t>(
            values.at("package_size")),
        .state_schema = unsigned_integer<std::uint32_t>(
            values.at("state_schema")),
        .package_schema = unsigned_integer<std::uint32_t>(
            values.at("package_schema")),
        .signature_algorithm =
            parse_quoted_string(values.at("signature_algorithm")),
        .signature_hex = parse_quoted_string(values.at("signature")),
    };
    validate_manifest(manifest);
    return manifest;
}

VerifiedUpdate::VerifiedUpdate(
    UpdateManifest manifest, std::filesystem::path package_path)
    : manifest_(std::move(manifest)), package_path_(std::move(package_path)) {}

std::string canonical_update_payload(const UpdateManifest& manifest) {
    validate_manifest(manifest);
    std::ostringstream output;
    output << "version=" << to_string(manifest.version) << '\n'
           << "minimum_installed_version="
           << to_string(manifest.minimum_installed_version) << '\n'
           << "platform=" << manifest.platform << '\n'
           << "architecture=" << manifest.architecture << '\n'
           << "package_sha256=" << manifest.package_sha256 << '\n'
           << "package_size=" << manifest.package_size << '\n'
           << "state_schema=" << manifest.state_schema << '\n'
           << "package_schema=" << manifest.package_schema << '\n'
           << "signature_algorithm=" << manifest.signature_algorithm << '\n';
    return output.str();
}

std::vector<std::byte> ecdsa_p256_signature_der(
    const std::span<const std::byte> raw_signature) {
    const auto is_zero = [](const std::span<const std::byte> value) {
        return std::ranges::all_of(
            value,
            [](const std::byte item) { return item == std::byte{}; });
    };
    if (raw_signature.size() != 64U ||
        is_zero(raw_signature.first(32)) ||
        is_zero(raw_signature.last(32))) {
        throw std::invalid_argument("P-256 signature must be nonzero raw r and s");
    }
    const auto encode_integer = [](const std::span<const std::byte> value) {
        auto first = value.begin();
        while (first + 1 != value.end() && *first == std::byte{}) ++first;
        const auto requires_zero =
            (std::to_integer<std::uint8_t>(*first) & 0x80U) != 0;
        const auto integer_size =
            static_cast<std::size_t>(value.end() - first) +
            (requires_zero ? 1U : 0U);
        std::vector<std::byte> encoded;
        encoded.reserve(2U + integer_size);
        encoded.push_back(std::byte{0x02});
        encoded.push_back(static_cast<std::byte>(integer_size));
        if (requires_zero) encoded.push_back(std::byte{});
        encoded.insert(encoded.end(), first, value.end());
        return encoded;
    };
    const auto r = encode_integer(raw_signature.first(32));
    const auto s = encode_integer(raw_signature.last(32));
    const auto content_size = r.size() + s.size();
    if (content_size > 127U) {
        throw std::logic_error("P-256 DER signature length is invalid");
    }
    std::vector<std::byte> der;
    der.reserve(content_size + 2U);
    der.push_back(std::byte{0x30});
    der.push_back(static_cast<std::byte>(content_size));
    der.insert(der.end(), r.begin(), r.end());
    der.insert(der.end(), s.begin(), s.end());
    return der;
}

VerifiedUpdate verify_update_candidate(
    const UpdateManifest& manifest,
    const SemanticVersion installed_version,
    const ReleaseCompatibilityPolicy& policy,
    const std::string_view expected_platform,
    const std::string_view expected_architecture,
    const std::filesystem::path& package_path,
    const UpdateSignatureVerifier& signature_verifier) {
    validate_manifest(manifest);
    validate_policy(policy);
    if (!valid_identifier(expected_platform, 32) ||
        !valid_identifier(expected_architecture, 32) ||
        manifest.platform != expected_platform ||
        manifest.architecture != expected_architecture ||
        manifest.version != policy.product_version ||
        installed_version < manifest.minimum_installed_version ||
        installed_version >= manifest.version ||
        manifest.state_schema != policy.state_schema_current ||
        manifest.package_schema != policy.package_schema ||
        !package_path.is_absolute() ||
        !std::filesystem::is_regular_file(package_path) ||
        std::filesystem::file_size(package_path) != manifest.package_size ||
        sha256_file(package_path) != manifest.package_sha256) {
        throw std::invalid_argument("update candidate does not match policy or package");
    }
    const auto payload_text = canonical_update_payload(manifest);
    const auto payload = std::as_bytes(std::span{payload_text});
    const auto signature = hex_bytes(manifest.signature_hex);
    if (!signature_verifier.verify(payload, signature)) {
        throw std::runtime_error("update manifest signature verification failed");
    }
    return VerifiedUpdate(
        manifest, std::filesystem::weakly_canonical(package_path));
}

}  // namespace rwn::core
