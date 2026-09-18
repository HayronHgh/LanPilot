#pragma once

#include <cstddef>
#include <compare>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

struct SemanticVersion {
    std::uint16_t major{};
    std::uint16_t minor{};
    std::uint16_t patch{};
    [[nodiscard]] auto operator<=>(const SemanticVersion&) const = default;
};

[[nodiscard]] SemanticVersion parse_semantic_version(std::string_view value);
[[nodiscard]] std::string to_string(const SemanticVersion& version);

struct ReleaseCompatibilityPolicy {
    SemanticVersion product_version;
    SemanticVersion minimum_peer_version;
    SemanticVersion maximum_peer_version;
    std::uint16_t protocol_minimum{};
    std::uint16_t protocol_maximum{};
    std::uint32_t state_schema_current{};
    std::uint32_t state_schema_minimum_readable{};
    std::uint32_t package_schema{};
};

[[nodiscard]] ReleaseCompatibilityPolicy load_release_compatibility(
    const std::filesystem::path& path);
[[nodiscard]] bool peer_is_compatible(
    const ReleaseCompatibilityPolicy& policy, SemanticVersion peer_version,
    std::uint16_t peer_protocol_minimum,
    std::uint16_t peer_protocol_maximum);
[[nodiscard]] bool state_schema_is_readable(
    const ReleaseCompatibilityPolicy& policy, std::uint32_t schema);

struct UpdateManifest {
    SemanticVersion version;
    SemanticVersion minimum_installed_version;
    std::string platform;
    std::string architecture;
    std::string package_sha256;
    std::uint64_t package_size{};
    std::uint32_t state_schema{};
    std::uint32_t package_schema{};
    std::string signature_algorithm;
    std::string signature_hex;
};

class UpdateSignatureVerifier {
public:
    virtual ~UpdateSignatureVerifier() = default;
    [[nodiscard]] virtual bool verify(
        std::span<const std::byte> canonical_payload,
        std::span<const std::byte> signature) const = 0;
};

[[nodiscard]] std::vector<std::byte> ecdsa_p256_signature_der(
    std::span<const std::byte> raw_signature);

class VerifiedUpdate {
public:
    [[nodiscard]] const UpdateManifest& manifest() const { return manifest_; }
    [[nodiscard]] const std::filesystem::path& package_path() const {
        return package_path_;
    }

private:
    VerifiedUpdate(UpdateManifest manifest, std::filesystem::path package_path);

    friend VerifiedUpdate verify_update_candidate(
        const UpdateManifest&, SemanticVersion,
        const ReleaseCompatibilityPolicy&, std::string_view,
        std::string_view, const std::filesystem::path&,
        const UpdateSignatureVerifier&);

    UpdateManifest manifest_;
    std::filesystem::path package_path_;
};

[[nodiscard]] UpdateManifest load_update_manifest(
    const std::filesystem::path& path);
[[nodiscard]] std::string canonical_update_payload(
    const UpdateManifest& manifest);
[[nodiscard]] VerifiedUpdate verify_update_candidate(
    const UpdateManifest& manifest, SemanticVersion installed_version,
    const ReleaseCompatibilityPolicy& policy,
    std::string_view expected_platform,
    std::string_view expected_architecture,
    const std::filesystem::path& package_path,
    const UpdateSignatureVerifier& signature_verifier);

}  // namespace rwn::core
