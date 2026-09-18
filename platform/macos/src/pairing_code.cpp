#include "rwn/platform/macos/pairing_code.hpp"

#include <Security/SecRandom.h>

#include <cstdint>
#include <stdexcept>
#include <string>

namespace rwn::platform::macos {

std::string generate_pairing_code() {
    constexpr std::uint64_t range = 1'000'000ULL;
    constexpr std::uint64_t source_range = 1ULL << 32U;
    constexpr std::uint64_t rejection_limit = (source_range / range) * range;
    std::uint32_t random_value{};
    do {
        if (SecRandomCopyBytes(
                kSecRandomDefault, sizeof(random_value),
                reinterpret_cast<std::uint8_t*>(&random_value)) != errSecSuccess) {
            throw std::runtime_error(
                "macOS secure pairing-code generation failed");
        }
    } while (static_cast<std::uint64_t>(random_value) >= rejection_limit);
    auto remainder = random_value % static_cast<std::uint32_t>(range);
    std::string result(6, '0');
    for (auto index = result.size(); index > 0; --index) {
        result[index - 1] = static_cast<char>('0' + remainder % 10U);
        remainder /= 10U;
    }
    return result;
}

}  // namespace rwn::platform::macos
