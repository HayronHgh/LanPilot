// Exercise production queue/writer without OS input hooks, SSH, or injection.
#include "main.cpp"
#include <iostream>

int main(int argc, char** argv) {
    using namespace rwn::desktop;
    ViewerState state;
    HANDLE reader{};
    try {
        const bool motion = argc == 2 && std::string_view(argv[1]) == "motion";
        const bool pressure = argc == 2 && std::string_view(argv[1]) == "pressure";
        if (argc > 2 || (argc == 2 && !motion && !pressure)) return 64;
        if (!CreatePipe(&reader, &state.input_write, nullptr, 65536))
            throw std::runtime_error("local pipe failed");
        state.interactive = true;
        if (pressure) {
            for (unsigned i = 0; i < 255; ++i)
                state.enqueue_input({.kind = InputKind::pointer_button,
                    .value_a = 1, .pressed = i % 2 == 0, .text = {}});
            state.enqueue_input({.kind = InputKind::pointer_move,
                .value_a = 1000, .value_b = 1000, .text = {}});
            bool rejected{};
            try { state.enqueue_input({.kind = InputKind::pointer_button,
                .value_a = 1, .pressed = false, .text = {}}); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected || state.reliable_control.size() != 255 || !state.pointer_control)
                throw std::runtime_error("barrier capacity admission was not atomic");
            state.enqueue_release_all();
            if (state.input_epoch != 2 || state.pointer_control ||
                state.reliable_control.size() != 1 ||
                state.reliable_control.front().type != ReverseControlType::release_all_input ||
                state.reliable_control.front().input_epoch != 2)
                throw std::runtime_error("overflow release did not invalidate old epoch");
            CloseHandle(reader); reader = nullptr;
            state.interactive = false;
            std::cout << "pressure=PASS bounded=1 atomic_rejection=1 release_epoch=2 input_injected=0\n";
            return 0;
        }
        if (motion) state.enqueue_input({.kind = InputKind::pointer_move,
            .value_a = 999, .value_b = 999, .text = {}});
        if (motion) state.enqueue_input({.kind = InputKind::pointer_move,
            .value_a = 1000, .value_b = 1000, .text = {}});
        for (unsigned click = 0; click < (motion ? 1U : 64U); ++click) {
            for (const bool pressed : {true, false})
            {
                state.enqueue_input({.kind = InputKind::pointer_button,
                    .value_a = 1, .pressed = pressed, .text = {}});
                if (motion && pressed) {
                    state.enqueue_input({.kind = InputKind::pointer_move,
                        .value_a = 1999, .value_b = 1999, .text = {}});
                    state.enqueue_input({.kind = InputKind::pointer_move,
                        .value_a = 2000, .value_b = 2000, .text = {}});
                }
            }
        }
        state.enqueue_release_all();
        state.control_closing = true;
        state.control_writer = std::jthread([&] { control_writer_loop(state); });
        unsigned edges{};
        for (std::uint64_t sequence = 1; sequence <= 129; ++sequence) {
            std::array<std::byte, reverse_control_header_size> bytes{};
            if (!read_exact(reader, bytes)) throw std::runtime_error("missing header");
            const auto header = decode_reverse_control_header(bytes);
            std::vector<std::byte> payload(header.payload_size);
            if (!read_exact(reader, payload)) throw std::runtime_error("missing payload");
            validate_reverse_control_payload(header, payload);
            if (motion) {
                // The pointer location at DOWN is an ordering barrier, not a
                // supersedable intermediate motion once a button edge follows.
                if (header.sequence != sequence || header.input_epoch != 1)
                    throw std::runtime_error("motion sequence/epoch lost");
                if (sequence == 5) {
                    if (header.type != ReverseControlType::release_all_input)
                        throw std::runtime_error("motion release lost");
                    break;
                }
                if (header.type != ReverseControlType::input_event)
                    throw std::runtime_error("motion input lost");
                const auto event = decode_input_event(payload);
                if (sequence == 1 || sequence == 3) {
                    if (event.kind != InputKind::pointer_move ||
                        event.value_a != (sequence == 1 ? 1000U : 2000U))
                        throw std::runtime_error("motion barrier FAIL: edge precedes its pointer location");
                } else {
                    if (event.kind != InputKind::pointer_button || event.value_a != 1 ||
                        event.pressed != (sequence == 2))
                        throw std::runtime_error("motion button edge lost");
                    ++edges;
                }
                continue;
            }
            if (header.sequence != sequence || header.input_epoch != 1)
                throw std::runtime_error("wire ordering or epoch lost");
            if (sequence == 129) {
                if (header.type != ReverseControlType::release_all_input)
                    throw std::runtime_error("release overtook button edges");
                continue;
            }
            if (header.type != ReverseControlType::input_event)
                throw std::runtime_error("button message type lost");
            const auto event = decode_input_event(payload);
            if (event.kind != InputKind::pointer_button || event.value_a != 1 ||
                event.sequence != sequence || event.pressed != (sequence % 2 == 1))
                throw std::runtime_error("button edge lost or reordered");
            ++edges;
        }
        state.control_writer.join();
        CloseHandle(reader); reader = nullptr;
        state.interactive = false;
        std::cout << "input_queue=PASS motion=" << motion << " edges=" << edges
                  << " ordered_release=1 input_injected=0\n";
        return 0;
    } catch (const std::exception& error) {
        if (reader) CloseHandle(reader); // Break pipe to unblock failed writer.
        { std::lock_guard lock(state.control_mutex); state.control_closing = true; }
        state.control_ready.notify_all();
        if (state.control_writer.joinable()) state.control_writer.join();
        state.interactive = false;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
