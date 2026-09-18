#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace rwn::core {
namespace {

constexpr std::array<std::uint32_t, 64> round_constants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

std::string to_hex(const Sha256Digest& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (const auto value : digest) {
        const auto byte = std::to_integer<unsigned int>(value);
        result.push_back(digits[(byte >> 4U) & 0x0fU]);
        result.push_back(digits[byte & 0x0fU]);
    }
    return result;
}

}  // namespace

void Sha256Accumulator::update(const std::span<const std::byte> input) {
    if (finished_) {
        throw std::logic_error("SHA-256 accumulator is already finished");
    }
    if (input.size() > std::numeric_limits<std::uint64_t>::max() -
            bytes_received()) {
        throw std::overflow_error("SHA-256 input length overflow");
    }
    for (const auto value : input) {
        buffer_[buffer_size_++] = std::to_integer<std::uint8_t>(value);
        if (buffer_size_ == buffer_.size()) {
            transform();
            total_bytes_ += buffer_.size();
            buffer_size_ = 0;
        }
    }
}

Sha256Digest Sha256Accumulator::finish() {
    if (finished_) {
        throw std::logic_error("SHA-256 accumulator is already finished");
    }
    finished_ = true;
    const auto message_bytes = bytes_received();
    buffer_[buffer_size_++] = 0x80U;
    if (buffer_size_ > 56) {
        std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_),
                  buffer_.end(), 0U);
        transform();
        buffer_size_ = 0;
    }
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_),
              buffer_.begin() + 56, 0U);
    const auto bit_length = message_bytes * 8U;
    for (std::size_t index = 0; index < 8; ++index) {
        buffer_[63 - index] =
            static_cast<std::uint8_t>(bit_length >> (index * 8U));
    }
    transform();

    Sha256Digest digest{};
    for (std::size_t word = 0; word < state_.size(); ++word) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            digest[word * 4 + byte] = static_cast<std::byte>(
                state_[word] >> ((3U - byte) * 8U));
        }
    }
    return digest;
}

std::uint64_t Sha256Accumulator::bytes_received() const noexcept {
    return total_bytes_ + buffer_size_;
}

void Sha256Accumulator::transform() {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
        schedule[index] =
            (static_cast<std::uint32_t>(buffer_[index * 4]) << 24U) |
            (static_cast<std::uint32_t>(buffer_[index * 4 + 1]) << 16U) |
            (static_cast<std::uint32_t>(buffer_[index * 4 + 2]) << 8U) |
            static_cast<std::uint32_t>(buffer_[index * 4 + 3]);
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
        const auto s0 = std::rotr(schedule[index - 15], 7) ^
                        std::rotr(schedule[index - 15], 18) ^
                        (schedule[index - 15] >> 3U);
        const auto s1 = std::rotr(schedule[index - 2], 17) ^
                        std::rotr(schedule[index - 2], 19) ^
                        (schedule[index - 2] >> 10U);
        schedule[index] = schedule[index - 16] + s0 +
                          schedule[index - 7] + s1;
    }

    auto a = state_[0];
    auto b = state_[1];
    auto c = state_[2];
    auto d = state_[3];
    auto e = state_[4];
    auto f = state_[5];
    auto g = state_[6];
    auto h = state_[7];
    for (std::size_t index = 0; index < schedule.size(); ++index) {
        const auto sum1 =
            std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const auto choice = (e & f) ^ (~e & g);
        const auto temporary1 = h + sum1 + choice +
                                round_constants[index] + schedule[index];
        const auto sum0 =
            std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const auto majority = (a & b) ^ (a & c) ^ (b & c);
        const auto temporary2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

Sha256Digest sha256(const std::span<const std::byte> bytes) {
    Sha256Accumulator state;
    state.update(bytes);
    return state.finish();
}

std::string sha256_hex(const std::span<const std::byte> bytes) {
    return to_hex(sha256(bytes));
}

std::string sha256_hex(const std::string_view text) {
    return sha256_hex(std::as_bytes(std::span{text.data(), text.size()}));
}

std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("content file could not be opened");
    }
    Sha256Accumulator state;
    std::array<char, 64U * 1024U> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            state.update(std::as_bytes(std::span{
                buffer.data(), static_cast<std::size_t>(count)}));
        }
    }
    if (!input.eof()) {
        throw std::runtime_error("content file could not be read");
    }
    return to_hex(state.finish());
}

bool is_sha256_hex(const std::string_view value) {
    return value.size() == 64 && std::ranges::all_of(value, [](const unsigned char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'f');
    });
}

}  // namespace rwn::core
