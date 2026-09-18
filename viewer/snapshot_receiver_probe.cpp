// Intentionally compile the production receiver/compositor in this isolated
// runtime probe. This avoids a second implementation and changes no viewer CLI.
#include "main.cpp"
#include <iostream>

int main(int argc, char** argv) {
    using namespace rwn::desktop;
    const bool timeout_case = argc == 2 && std::string_view(argv[1]) == "timeout";
    const bool malformed = argc == 2 && std::string_view(argv[1]) == "malformed";
    const bool eof_case = malformed || (argc == 2 && std::string_view(argv[1]) == "eof");
    const bool concurrent = timeout_case ||
        (argc == 2 && std::string_view(argv[1]) == "concurrent");
    if (argc > 2 || (argc == 2 && !concurrent && !eof_case)) return 64;
    HWND window{};
    HANDLE write_pipe{};
    HANDLE unused_control_read{};
    try {
        ViewerState state;
        window = CreateWindowExW(0, L"STATIC", L"RWN receiver probe", WS_POPUP,
            0, 0, 320, 180, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (!window) throw std::runtime_error("hidden window failed");
        state.window = window;
        state.interactive = true; // ACK queue only; never install input hooks.
        state.visual_protocol = true;
        state.renderer = std::make_unique<rwn::viewer::D3D11Nv12Renderer>();
        state.renderer->initialize(window);
        if (!CreatePipe(&state.output_read, &write_pipe, nullptr, 0) ||
            !CreatePipe(&unused_control_read, &state.input_write, nullptr, 0))
            throw std::runtime_error("probe pipe creation failed");
        constexpr std::uint32_t width = 1920, height = 1080, stride = width * 4;
        std::vector<std::byte> pixels(stride * height);
        for (std::size_t i = 0; i < pixels.size(); ++i)
            pixels[i] = i % 4 == 3 ? std::byte{255} : static_cast<std::byte>((i * 19U + i / stride) % 256U);
        const auto first_digest = rwn::core::sha256(pixels);
        std::vector<std::byte> wire;
        std::uint64_t sequence{};
        std::size_t last_header_offset{};
        const auto message = [&](VisualMessageType type, std::uint64_t epoch,
                                 std::span<const std::byte> payload) {
            const auto header = encode_visual_message_header({
                .type = type, .payload_size = static_cast<std::uint32_t>(payload.size()),
                .session_generation = 77, .representation_epoch = epoch,
                .visual_sequence = ++sequence, .frame_id = epoch,
                .captured_at_us = steady_timestamp_us()});
            last_header_offset = wire.size();
            wire.insert(wire.end(), header.begin(), header.end());
            wire.insert(wire.end(), payload.begin(), payload.end());
        };
        const auto snapshot = [&](std::uint64_t epoch, std::size_t bytes, bool commit) {
            message(VisualMessageType::state_reset, epoch, encode_visual_state_reset({}));
            for (std::size_t offset = 0; offset < bytes; offset += 65536U) {
                const auto count = std::min<std::size_t>(65536U, bytes - offset);
                message(VisualMessageType::full_snapshot, epoch, encode_visual_full_snapshot_chunk({
                    .surface_width = width, .surface_height = height, .row_stride = stride,
                    .total_bytes = static_cast<std::uint32_t>(pixels.size()),
                    .chunk_offset = static_cast<std::uint32_t>(offset),
                    .chunk = {pixels.begin() + offset, pixels.begin() + offset + count}}));
            }
            if (commit) message(VisualMessageType::frame_commit, epoch,
                encode_visual_frame_commit({.base_frame_id = 0}));
        };
        snapshot(1, pixels.size(), true);
        for (std::size_t i = 0; i < pixels.size(); i += 4) pixels[i] ^= std::byte{127};
        snapshot(2, 2U * 1024U * 1024U, true); // Invalid incomplete commit.
        snapshot(3, 2U * 1024U * 1024U, false); // Abort by newer STATE_RESET.
        const auto pause_offset = wire.size();
        const auto damaged_header_offset = last_header_offset;
        snapshot(4, pixels.size(), true);
        if (eof_case) {
            if (malformed) {
                wire.resize(damaged_header_offset + visual_message_header_size);
                wire[damaged_header_offset] = std::byte{0}; // Invalid RWV2 magic.
            } else wire.resize(pause_offset - 100U); // EOF inside epoch3 chunk payload.
            for (std::size_t i = 0; i < pixels.size(); i += 4) pixels[i] ^= std::byte{127};
        }
        if (concurrent)
            state.compositor = std::jthread([&](std::stop_token stop) { compositor_loop(state, stop); });
        std::exception_ptr writer_error;
        std::jthread writer([&] {
            try {
                if (timeout_case) {
                    write_exact(write_pipe, std::span<const std::byte>(wire).first(pause_offset));
                    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
                    bool requested = false;
                    while (std::chrono::steady_clock::now() < until) {
                        {
                            std::lock_guard lock(state.control_mutex);
                            requested = std::count_if(state.reliable_control.begin(), state.reliable_control.end(),
                                [](const auto& c) { return c.type == ReverseControlType::request_full_snapshot; }) >= 2;
                        }
                        if (requested) break;
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                    if (!requested) throw std::runtime_error("timeout did not request snapshot recovery");
                    write_exact(write_pipe, std::span<const std::byte>(wire).subspan(pause_offset));
                } else write_exact(write_pipe, std::span<const std::byte>(wire));
            }
            catch (...) { writer_error = std::current_exception(); }
            CloseHandle(write_pipe);
            write_pipe = nullptr;
        });
        // Reader drains a real byte pipe through production framing/validation.
        // Process its bounded commands afterward to make ordering deterministic.
        frame_reader_loop(state, true, false, true);
        writer.join();
        if (writer_error) std::rethrow_exception(writer_error);
        if (eof_case && (state.snapshot_commands.empty() ||
            state.snapshot_commands.back().kind != SnapshotCommandKind::cancel))
            throw std::runtime_error("EOF left a pending snapshot instead of cancelling it");
        if (!concurrent)
            state.compositor = std::jthread([&](std::stop_token stop) { compositor_loop(state, stop); });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while ((eof_case ? state.snapshot_cancels.load() < 5 : state.snapshot_commits.load() < 2) &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        state.compositor.request_stop();
        state.compositor_ready.notify_all();
        state.compositor.join();
        if (state.snapshot_commits != (eof_case ? 1U : 2U) ||
            (eof_case && state.snapshot_started_at_us != 0) ||
            state.renderer->committed_framebuffer_bgra() != pixels)
            throw std::runtime_error("receiver recovery did not produce exact final surface");
        std::vector<FrameCommitAck> acks;
        // Exact-only has no decoded H.264 frame to supply pointer dimensions.
        // Exercise the production coordinate mapper without injecting input.
        if (state.exact_surface_width.load() != width ||
            state.exact_surface_height.load() != height)
            throw std::runtime_error("snapshot commit lost pointer surface dimensions");
        const auto left = map_client_pointer_to_surface(state, window, 80, 90);
        const auto right = map_client_pointer_to_surface(state, window, 240, 90);
        if (!left || !right || left->first >= right->first ||
            left->second != right->second ||
            map_client_pointer_to_surface(state, window, -1, 90))
            throw std::runtime_error("exact-only pointer mapping failed");
        std::size_t recovery_requests{};
        for (const auto& control : state.reliable_control) {
            if (control.type == ReverseControlType::frame_commit_ack)
                acks.push_back(decode_frame_commit_ack(control.payload));
            if (control.type == ReverseControlType::request_full_snapshot) ++recovery_requests;
        }
        if (acks.size() != (eof_case ? 1U : 2U) || recovery_requests != (timeout_case ? 2U : 1U) ||
            !frame_commit_ack_matches(acks[0], 77, 1, 1, first_digest) ||
            (!eof_case && !frame_commit_ack_matches(acks[1], 77, 4, 4, rwn::core::sha256(pixels))))
            throw std::runtime_error("invalid or missing recovery ACK");
        std::cout << "receiver_recovery=PASS commits=" << state.snapshot_commits.load()
                  << " valid_acks=" << acks.size() << " aborted_acks=0 eof=" << eof_case
                  << " malformed=" << malformed
                  << " recovery_requests=" << recovery_requests
                  << " concurrent=" << concurrent << " timeout=" << timeout_case
                  << " gpu_mismatch_bytes=0 input_events=0\n";
        state.stop();
        CloseHandle(unused_control_read); unused_control_read = nullptr;
        DestroyWindow(window); window = nullptr;
        return 0;
    } catch (const std::exception& error) {
        if (write_pipe) CloseHandle(write_pipe);
        if (unused_control_read) CloseHandle(unused_control_read);
        if (window) DestroyWindow(window);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
