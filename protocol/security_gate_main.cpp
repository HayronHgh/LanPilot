#include "rwn/protocol/security_gate.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {

template <typename Integer>
Integer integer(const std::string_view value) {
    Integer result{};
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result);
    if (value.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size()) {
        throw std::invalid_argument("numeric argument is invalid");
    }
    return result;
}

}  // namespace

int main(const int argc, const char* const argv[]) {
    if (argc > 3) {
        std::cerr << "usage: rwn-protocol-security-gate [seed] [cases]\n";
        return 2;
    }
    try {
        const auto seed = argc >= 2
                              ? integer<std::uint64_t>(argv[1])
                              : 0x52574e2d763031ULL;
        const auto cases = argc == 3 ? integer<std::size_t>(argv[2]) : 4096U;
        const auto report =
            rwn::protocol::run_envelope_mutation_gate(seed, cases);
        std::cout << rwn::protocol::render_protocol_mutation_json(report);
        return report.passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "protocol security gate failed: " << error.what() << '\n';
        return 1;
    }
}
