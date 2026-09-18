#include "rwn/platform/windows/pairing_code.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace rwn::platform::windows {

std::string generate_pairing_code() {
    constexpr std::uint64_t range = 1'000'000ULL;
    constexpr std::uint64_t source_range = 1ULL << 32U;
    constexpr std::uint64_t rejection_limit = (source_range / range) * range;
    std::uint32_t random_value{};
    do {
        const auto status = BCryptGenRandom(
            nullptr, reinterpret_cast<PUCHAR>(&random_value), sizeof(random_value),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            throw std::runtime_error("Windows CNG pairing-code generation failed");
        }
    } while (static_cast<std::uint64_t>(random_value) >= rejection_limit);

    const auto value = random_value % static_cast<std::uint32_t>(range);
    std::string result(6, '0');
    auto remainder = value;
    for (auto index = result.size(); index > 0; --index) {
        result[index - 1] = static_cast<char>('0' + remainder % 10U);
        remainder /= 10U;
    }
    return result;
}

}  // namespace rwn::platform::windows
