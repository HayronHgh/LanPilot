#pragma once

#include "rwn/core/release_compatibility.hpp"

#include <array>
#include <cstddef>
#include <span>

namespace rwn::platform::windows {

class CngEcdsaP256UpdateVerifier final
    : public core::UpdateSignatureVerifier {
public:
    explicit CngEcdsaP256UpdateVerifier(
        std::span<const std::byte> public_key_xy);

    [[nodiscard]] bool verify(
        std::span<const std::byte> canonical_payload,
        std::span<const std::byte> signature) const override;

private:
    std::array<std::byte, 64> public_key_xy_{};
};

}  // namespace rwn::platform::windows
