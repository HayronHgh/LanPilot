#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace rwn::protocol {

struct ProtocolMutationReport {
    std::uint32_t schema_version{1};
    std::uint64_t seed{};
    std::size_t cases{};
    std::size_t accepted{};
    std::size_t rejected{};
    std::size_t canonical_round_trips{};
    std::string corpus_fingerprint;
    bool passed{};
};

[[nodiscard]] ProtocolMutationReport run_envelope_mutation_gate(
    std::uint64_t seed, std::size_t cases);
[[nodiscard]] std::string render_protocol_mutation_json(
    const ProtocolMutationReport& report);

}  // namespace rwn::protocol
