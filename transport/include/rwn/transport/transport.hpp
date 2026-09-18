#pragma once

#include "rwn/transport/certificate_identity.hpp"

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace rwn::transport {

enum class StreamPurpose : std::uint8_t { control, input, clipboard, command, file, build };
enum class DatagramChannel : std::uint8_t { video, audio, pointer };

class ReliableStream {
public:
    virtual ~ReliableStream() = default;
    virtual void write(std::span<const std::byte> data) = 0;
    [[nodiscard]] virtual std::vector<std::byte> read() = 0;
};

class Transport {
public:
    virtual ~Transport() = default;
    [[nodiscard]] virtual std::unique_ptr<ReliableStream> open_stream(StreamPurpose purpose) = 0;
    virtual void send_datagram(DatagramChannel channel, std::span<const std::byte> data) = 0;
};

struct AcceptedStream {
    StreamPurpose purpose{StreamPurpose::control};
    std::unique_ptr<ReliableStream> stream;
};

struct ReceivedDatagram {
    DatagramChannel channel{DatagramChannel::video};
    std::vector<std::byte> payload;
};

class DuplexTransport : public Transport {
public:
    [[nodiscard]] virtual AcceptedStream accept_stream(
        std::chrono::milliseconds timeout) = 0;
    [[nodiscard]] virtual ReceivedDatagram receive_datagram(
        std::chrono::milliseconds timeout) = 0;
};

struct AuthenticatedConnection {
    std::unique_ptr<DuplexTransport> transport;
    AuthenticatedPeerEvidence peer;
};

}  // namespace rwn::transport
