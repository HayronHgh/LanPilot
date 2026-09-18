#include "rwn/protocol/security_gate.hpp"

#include "rwn/protocol/envelope.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace rwn::protocol {
namespace {

class XorShift64 final {
public:
    explicit XorShift64(const std::uint64_t seed) : state_(seed) {}

    [[nodiscard]] std::uint64_t next() {
        state_ ^= state_ << 13U;
        state_ ^= state_ >> 7U;
        state_ ^= state_ << 17U;
        return state_;
    }

private:
    std::uint64_t state_;
};

void fingerprint_byte(std::uint64_t& fingerprint, const std::byte value) {
    fingerprint ^= std::to_integer<std::uint8_t>(value);
    fingerprint *= 1'099'511'628'211ULL;
}

void overwrite_u32(
    std::vector<std::byte>& bytes, const std::size_t offset,
    const std::uint32_t value) {
    if (offset + 4U > bytes.size()) return;
    bytes[offset] = static_cast<std::byte>((value >> 24U) & 0xffU);
    bytes[offset + 1U] = static_cast<std::byte>((value >> 16U) & 0xffU);
    bytes[offset + 2U] = static_cast<std::byte>((value >> 8U) & 0xffU);
    bytes[offset + 3U] = static_cast<std::byte>(value & 0xffU);
}

[[nodiscard]] std::vector<std::byte> baseline_envelope() {
    Envelope envelope{
        .version = 1,
        .type = MessageType::workspace_manifest,
        .correlation_id = "fuzz-corpus",
        .payload = std::vector<std::byte>(256, std::byte{0x5a}),
        .unknown_fields = {{.tag = 900, .value = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}}},
    };
    return encode(envelope);
}

void mutate(
    std::vector<std::byte>& bytes, XorShift64& random,
    const std::size_t case_index) {
    switch (case_index % 6U) {
        case 0: {
            bytes.resize(static_cast<std::size_t>(random.next() % bytes.size()));
            break;
        }
        case 1: {
            const auto index = static_cast<std::size_t>(random.next() % bytes.size());
            const auto bit = static_cast<unsigned>(random.next() % 8U);
            bytes[index] ^= static_cast<std::byte>(1U << bit);
            break;
        }
        case 2: {
            constexpr std::array values{
                0U, 1U, static_cast<std::uint32_t>(max_payload_size),
                static_cast<std::uint32_t>(max_payload_size + 1U),
                std::numeric_limits<std::uint32_t>::max()};
            overwrite_u32(bytes, 12U, values[random.next() % values.size()]);
            break;
        }
        case 3: {
            const auto count = static_cast<std::size_t>(random.next() % 32U + 1U);
            for (std::size_t index = 0; index < count; ++index) {
                bytes.push_back(static_cast<std::byte>(random.next() & 0xffU));
            }
            break;
        }
        case 4: {
            const auto position = static_cast<std::size_t>(random.next() % bytes.size());
            bytes.insert(
                bytes.begin() + static_cast<std::ptrdiff_t>(position),
                static_cast<std::byte>(random.next() & 0xffU));
            break;
        }
        case 5: {
            const auto position = static_cast<std::size_t>(random.next() % bytes.size());
            const auto available = bytes.size() - position;
            const auto count = std::min<std::size_t>(
                available, static_cast<std::size_t>(random.next() % 16U + 1U));
            bytes.erase(
                bytes.begin() + static_cast<std::ptrdiff_t>(position),
                bytes.begin() + static_cast<std::ptrdiff_t>(position + count));
            break;
        }
    }
}

}  // namespace

ProtocolMutationReport run_envelope_mutation_gate(
    const std::uint64_t seed, const std::size_t cases) {
    if (seed == 0 || cases < 64 || cases > 1'000'000) {
        throw std::invalid_argument("protocol mutation gate settings are invalid");
    }
    const auto baseline = baseline_envelope();
    XorShift64 random(seed);
    ProtocolMutationReport report{
        .schema_version = 1,
        .seed = seed,
        .cases = cases,
        .accepted = 0,
        .rejected = 0,
        .canonical_round_trips = 0,
        .corpus_fingerprint = {},
        .passed = false,
    };
    std::uint64_t fingerprint = 14'695'981'039'346'656'037ULL;
    for (std::size_t index = 0; index < cases; ++index) {
        auto bytes = baseline;
        mutate(bytes, random, index);
        for (const auto byte : bytes) fingerprint_byte(fingerprint, byte);
        fingerprint_byte(
            fingerprint, static_cast<std::byte>(index & 0xffU));
        try {
            const auto decoded = decode(bytes);
            const auto canonical = encode(decoded);
            if (decode(canonical) != decoded) {
                throw std::runtime_error(
                    "accepted protocol mutation failed canonical round trip");
            }
            ++report.accepted;
            ++report.canonical_round_trips;
        } catch (const std::invalid_argument&) {
            ++report.rejected;
        } catch (const std::length_error&) {
            ++report.rejected;
        }
    }
    std::ostringstream fingerprint_text;
    fingerprint_text << std::hex << std::setfill('0') << std::setw(16)
                     << fingerprint;
    report.corpus_fingerprint = fingerprint_text.str();
    report.passed = report.accepted != 0 && report.rejected != 0 &&
                    report.accepted + report.rejected == report.cases &&
                    report.canonical_round_trips == report.accepted;
    return report;
}

std::string render_protocol_mutation_json(
    const ProtocolMutationReport& report) {
    if (report.schema_version != 1 || report.seed == 0 || report.cases < 64 ||
        report.accepted + report.rejected != report.cases ||
        report.canonical_round_trips != report.accepted ||
        report.corpus_fingerprint.size() != 16 ||
        !std::ranges::all_of(
            report.corpus_fingerprint,
            [](const unsigned char character) {
                return std::isdigit(character) != 0 ||
                       (character >= 'a' && character <= 'f');
            }) ||
        report.passed != (report.accepted != 0 && report.rejected != 0)) {
        throw std::invalid_argument("protocol mutation report is inconsistent");
    }
    std::ostringstream output;
    output << "{\n"
           << "  \"schema_version\": " << report.schema_version << ",\n"
           << "  \"seed\": " << report.seed << ",\n"
           << "  \"cases\": " << report.cases << ",\n"
           << "  \"accepted\": " << report.accepted << ",\n"
           << "  \"rejected\": " << report.rejected << ",\n"
           << "  \"canonical_round_trips\": "
           << report.canonical_round_trips << ",\n"
           << "  \"corpus_fingerprint\": \""
           << report.corpus_fingerprint << "\",\n"
           << "  \"passed\": " << (report.passed ? "true" : "false")
           << "\n}\n";
    return output.str();
}

}  // namespace rwn::protocol
