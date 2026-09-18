#pragma once
#include "rwn/transport/channel_session.hpp"
#include "rwn/transport/tls_stream_io.hpp"
#include <stdexcept>

namespace channel_tests {
using namespace rwn::transport;
inline void check(bool condition) {
    if (!condition) throw std::runtime_error("TCP channel invariant failed");
}
template<class F> void rejects(F operation) {
    try { operation(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("invalid TCP channel message accepted");
}
inline ChannelSessionId id() { ChannelSessionId value{}; value[0] = 1; return value; }
inline AuthenticatedPeerEvidence peer() {
    AuthenticatedPeerEvidence value{};
    value.certificate_sha256[0] = 7;
    value.tls_1_3_negotiated = value.certificate_chain_valid = value.revocation_checked = true;
    return value;
}
// Deterministic workflow fixture: controls record fragmentation, not crypto.
class RecordFixture final : public TlsByteChannel {
public:
    AuthenticatedPeerEvidence evidence = channel_tests::peer();
    std::vector<std::vector<std::byte>> records;
    std::vector<std::byte> written;
    std::size_t next{}, writes{};
    bool cancelled{};
    unsigned idle_waits{}, readiness_calls{};
    bool timeout_when_empty{};
    std::vector<std::chrono::milliseconds> read_budgets;
    const AuthenticatedPeerEvidence& peer() const noexcept override { return evidence; }
    void write(std::span<const std::byte> bytes, std::chrono::milliseconds) override {
        check(!cancelled && bytes.size() <= tls_channel_write_limit);
        ++writes; written.insert(written.end(), bytes.begin(), bytes.end());
    }
    std::vector<std::byte> read_some(std::chrono::milliseconds budget) override {
        read_budgets.push_back(budget);
        if (cancelled) throw std::runtime_error("fixture cancelled");
        if (next == records.size())
            throw std::runtime_error(timeout_when_empty ? "fixture native timeout" : "fixture EOF");
        return records[next++];
    }
    void cancel() noexcept override { cancelled = true; }
    bool wait_readable(std::chrono::milliseconds) override {
        ++readiness_calls;
        if (cancelled) throw std::runtime_error("fixture cancelled");
        if (idle_waits) { --idle_waits; return false; }
        return true; // Includes EOF: read must fail closed, never spin on EOF.
    }
};
inline void stream_workflow() {
    RecordFixture channel;
    channel.records = {{std::byte{1}}, {std::byte{2}, std::byte{3}, std::byte{4}}, {std::byte{5}}};
    TlsStreamIo io(channel);
    channel.idle_waits = 80;
    for (unsigned i = 0; i < 80; ++i)
        check(!io.wait_message_start(std::chrono::milliseconds(500)));
    check(channel.next == 0 && !channel.cancelled);
    check(io.wait_message_start(std::chrono::milliseconds(500)));
    std::array<std::byte, 2> header{}, payload{};
    io.read_exact(header, std::chrono::seconds(1));
    check(header[0] == std::byte{1} && header[1] == std::byte{2});
    check(io.buffered_bytes() == 2);
    const auto waits = channel.readiness_calls;
    check(io.wait_message_start(std::chrono::milliseconds(500)));
    check(channel.readiness_calls == waits); // Buffered bytes bypass idle wait.
    io.read_exact(payload, std::chrono::seconds(1));
    check(payload[0] == std::byte{3} && payload[1] == std::byte{4});
    check(channel.next == 2); // Retained payload must not wait for another record.
    std::vector<std::byte> large(2*tls_channel_write_limit+13, std::byte{42});
    io.write_all(large, std::chrono::seconds(1));
    check(channel.writes == 3 && channel.written == large);
    bool failed = false;
    try { io.read_exact(header, std::chrono::seconds(1)); }
    catch (const std::runtime_error&) { failed = true; }
    check(failed && channel.cancelled); // Truncated read poisons connection.
    failed = false;
    try { static_cast<void>(io.wait_message_start(std::chrono::milliseconds(500))); }
    catch (const std::runtime_error&) { failed = true; }
    check(failed); // Cancelled idle wait must not hide the disconnect.
}
inline void workflow() {
    stream_workflow();
    for (bool input : {false,true}) {
        const ChannelAdmission admitted{id(),9,{true,true,input}};
        const auto decoded = decode_channel_admission(encode_channel_admission(admitted));
        check(decoded.grants.desktop_input == input);
        validate_channel_admission(decoded,{TcpChannel::visual,id(),9},false);
        if (input) validate_channel_admission(decoded,{TcpChannel::visual,id(),9},true);
    }
    const auto now = TcpChannelSession::Clock::now();
    const auto expires = now + std::chrono::seconds(30);
    TcpChannelSession session(id(), 9, peer().certificate_sha256, {true, true}, expires);
    for (unsigned i = 1; i <= 2; ++i) {
        const ChannelHello hello{static_cast<TcpChannel>(i), id(), 9};
        const auto decoded = decode_channel_hello(encode_channel_hello(hello));
        check(decoded.channel == hello.channel && decoded.session_id == id() && decoded.generation == 9);
        check(session.attach(decoded, peer(), i, now));
        check(session.active(hello.channel, i, now));
    }
    session.disconnect(3); // An unrelated connection cannot revoke desktop.
    check(session.active(TcpChannel::visual, 1, now));
    check(!session.input_allowed(2, now)); // Control ACK is not input permission.
    session.disconnect(2);
    check(session.revoked());
    check(!session.active(TcpChannel::visual, 1, now));
    check(!session.attach({TcpChannel::control, id(), 9}, peer(), 5, now));
}
inline void security() {
    const ChannelAdmission view_only{id(),9,{true,true,false}};
    const ChannelHello issued{TcpChannel::visual,id(),9};
    rejects([&]{validate_channel_admission(view_only,issued,true);});
    auto other = issued; other.session_id[1]=1;
    rejects([&]{validate_channel_admission(view_only,other,false);});
    other=issued; ++other.generation;
    rejects([&]{validate_channel_admission(view_only,other,false);});
    other=issued; other.channel=TcpChannel::control;
    rejects([&]{validate_channel_admission(view_only,other,false);});
    const auto admission = encode_channel_admission(view_only);
    for (std::size_t n=0;n<admission.size();++n)
        rejects([&]{static_cast<void>(decode_channel_admission(std::span(admission).first(n)));});
    for (std::size_t offset : {0U,1U,2U,3U,4U,6U,7U}) {
        auto broken=admission; broken[offset]^=std::byte{0xff};
        rejects([&]{static_cast<void>(decode_channel_admission(broken));});
    }
    for (unsigned flags=0;flags<256;++flags) {
        if (flags==3 || flags==7) continue;
        auto broken=admission; broken[5]=std::byte{static_cast<unsigned char>(flags)};
        rejects([&]{static_cast<void>(decode_channel_admission(broken));});
    }
    // A transport timeout after ANY partial header must poison the stream.
    // This tests adapter policy, not native socket timing or TLS decryption.
    for (std::size_t prefix = 1; prefix < 64; ++prefix) {
        RecordFixture partial;
        partial.records = {std::vector<std::byte>(prefix, std::byte{42})};
        partial.timeout_when_empty = true;
        TlsStreamIo partial_io(partial);
        check(partial_io.wait_message_start(std::chrono::milliseconds(500)));
        std::array<std::byte, 64> header{};
        bool timeout_rejected = false;
        try { partial_io.read_exact(header, std::chrono::milliseconds(100)); }
        catch (const std::runtime_error&) { timeout_rejected = true; }
        check(timeout_rejected && partial.cancelled && partial.readiness_calls == 1);
        check(partial.read_budgets.size() == 2);
        check(partial.read_budgets[0].count() > 0 &&
              partial.read_budgets[0] <= std::chrono::milliseconds(100));
        check(partial.read_budgets[1].count() > 0 &&
              partial.read_budgets[1] <= partial.read_budgets[0]);
        // Never fall back to boundary-idle waiting after a partial message.
        check(partial.next == 1);
    }
    RecordFixture idle_channel;
    TlsStreamIo idle_io(idle_channel);
    rejects([&] { static_cast<void>(idle_io.wait_message_start(std::chrono::milliseconds(0))); });
    rejects([&] { static_cast<void>(idle_io.wait_message_start(std::chrono::seconds(31))); });
    check(idle_channel.readiness_calls == 0);
    // Readiness is not proof of a complete message (including readable EOF).
    check(idle_io.wait_message_start(std::chrono::milliseconds(1)));
    std::array<std::byte, 1> eof_byte{};
    bool eof_rejected = false;
    try { idle_io.read_exact(eof_byte, std::chrono::milliseconds(1)); }
    catch (const std::runtime_error&) { eof_rejected = true; }
    check(eof_rejected && idle_channel.cancelled);
    RecordFixture oversized_channel;
    oversized_channel.records = {std::vector<std::byte>(tls_channel_write_limit+1)};
    TlsStreamIo oversized_io(oversized_channel);
    std::array<std::byte, 1> destination{};
    bool bounded = false;
    try { oversized_io.read_exact(destination, std::chrono::seconds(1)); }
    catch (const std::runtime_error&) { bounded = true; }
    check(bounded && oversized_channel.cancelled);
    rejects([&] { oversized_io.read_exact(destination, std::chrono::milliseconds(0)); });
    const auto now = TcpChannelSession::Clock::now();
    const auto expires = now + std::chrono::seconds(30);
    rejects([&] { TcpChannelSession invalid(id(), 9, peer().certificate_sha256,
                                          {true, false, true}, expires); });
    TcpChannelSession interactive(id(), 9, peer().certificate_sha256, {true, true, true}, expires);
    check(!interactive.input_allowed(2, now));
    check(interactive.attach({TcpChannel::control, id(), 9}, peer(), 2, now));
    check(!interactive.input_allowed(2, now)); // No control before visual admission.
    check(interactive.attach({TcpChannel::visual, id(), 9}, peer(), 1, now));
    check(interactive.input_allowed(2, now));
    check(!interactive.input_allowed(1, now));
    check(!interactive.input_allowed(2, expires));
    interactive.revoke();
    check(!interactive.input_allowed(2, now));
    ChannelHello hello{TcpChannel::visual, id(), 0x0102030405060708ULL};
    auto bytes = encode_channel_hello(hello);
    check(bytes[24] == std::byte{1} && bytes[31] == std::byte{8});
    for (std::size_t size = 0; size < bytes.size(); ++size)
        rejects([&] { (void)decode_channel_hello(std::span(bytes).first(size)); });
    for (std::size_t offset : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U}) {
        auto bad = bytes; bad[offset] = std::byte{255};
        rejects([&] { (void)decode_channel_hello(bad); });
    }
    std::array<std::byte, channel_hello_bytes+1> oversized{};
    rejects([&] { (void)decode_channel_hello(oversized); });
    hello.generation = 9;
    TcpChannelSession denied(id(), 9, peer().certificate_sha256, {}, expires);
    check(!denied.attach(hello, peer(), 1, now));
    TcpChannelSession session(id(), 9, peer().certificate_sha256, {true, true}, expires);
    auto wrong = hello; wrong.session_id[1] = 8;
    check(!session.attach(wrong, peer(), 1, now));
    wrong = hello; wrong.generation = 8;
    check(!session.attach(wrong, peer(), 1, now));
    auto impostor = peer(); impostor.certificate_sha256[1] = 8;
    check(!session.attach(hello, impostor, 1, now));
    for (unsigned field = 0; field < 3; ++field) {
        auto unverified = peer();
        if (field == 0) unverified.tls_1_3_negotiated = false;
        if (field == 1) unverified.certificate_chain_valid = false;
        if (field == 2) unverified.revocation_checked = false;
        rejects([&] { (void)session.attach(hello, unverified, 1, now); });
    }
    check(!session.attach(hello, peer(), 0, now));
    check(!session.attach(hello, peer(), 1, expires));
    check(session.attach(hello, peer(), 1, now));
    check(!session.attach(hello, peer(), 2, now)); // No live-channel replacement.
    hello.channel = TcpChannel::control;
    check(!session.attach(hello, peer(), 1, now)); // Must be a distinct socket.
    check(session.attach(hello, peer(), 2, now));
    hello.channel = static_cast<TcpChannel>(3); // Agent belongs to SSH, not TCP.
    rejects([&] { (void)session.attach(hello, peer(), 3, now); });
    auto agent_wire = bytes; agent_wire[5] = std::byte{3};
    rejects([&] { (void)decode_channel_hello(agent_wire); });
    check(!session.active(TcpChannel::visual, 1, expires));
    session.disconnect(1);
    check(!session.active(TcpChannel::control, 2, now));
}
} // namespace channel_tests
