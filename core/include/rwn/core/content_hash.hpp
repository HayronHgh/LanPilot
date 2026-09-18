#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace rwn::core {

using Sha256Digest = std::array<std::byte, 32>;

class Sha256Accumulator final {
public:
    void update(std::span<const std::byte> bytes);
    [[nodiscard]] Sha256Digest finish();
    [[nodiscard]] std::uint64_t bytes_received() const noexcept;

private:
    void transform();

    std::array<std::uint32_t, 8> state_{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffer_size_{};
    std::uint64_t total_bytes_{};
    bool finished_{};
};

[[nodiscard]] Sha256Digest sha256(std::span<const std::byte> bytes);
[[nodiscard]] std::string sha256_hex(std::span<const std::byte> bytes);
[[nodiscard]] std::string sha256_hex(std::string_view text);
[[nodiscard]] std::string sha256_file(const std::filesystem::path& path);
[[nodiscard]] bool is_sha256_hex(std::string_view value);

}  // namespace rwn::core
