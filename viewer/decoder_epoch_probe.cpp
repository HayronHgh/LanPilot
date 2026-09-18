// Live H.264 is read into memory only. No pixel/bitstream files or input hooks.
#include "main.cpp"
#include <iostream>
#include "sps_probe.hpp"

int main() {
    HWND window{};
    try {
        using namespace rwn::desktop;
        rwn::viewer::probe::test_sps_reader();
        std::cout << "sps_reader_fixture=PASS truncated_rejected=1 overflow_rejected=1\n";
        VideoFrame seed;
        const auto input = GetStdHandle(STD_INPUT_HANDLE);
        for (unsigned i = 0; i < 128 && seed.encoded.empty(); ++i) {
            std::array<std::byte, visual_message_header_size> bytes{};
            if (!read_exact(input, bytes)) throw std::runtime_error("missing seed header");
            const auto header = decode_visual_message_header(bytes);
            std::vector<std::byte> payload(header.payload_size);
            if (!read_exact(input, payload)) throw std::runtime_error("missing seed payload");
            validate_visual_message_payload(header, payload);
            if (header.type != VisualMessageType::h264_access_unit ||
                !(header.flags & visual_flag_keyframe)) continue;
            const auto unit = decode_visual_h264_access_unit(payload);
            seed.width = unit.width; seed.height = unit.height;
            seed.encoded = unit.encoded; seed.keyframe = true;
        }
        if (seed.encoded.empty()) throw std::runtime_error("no IDR seed");
        rwn::viewer::probe::print_sps(seed.encoded, std::cout);
        window = CreateWindowExW(0, L"STATIC", L"RWN decoder epoch probe", WS_POPUP,
            0, 0, 320, 180, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (!window) throw std::runtime_error("hidden window failed");
        rwn::viewer::D3D11Nv12Renderer renderer;
        renderer.initialize(window);
        rwn::platform::windows::WindowsMediaFoundationH264Decoder decoder(renderer.native_device());
        const auto print_low_latency = [](const char* phase, const auto& instance) {
            const auto value = instance.low_latency_readback();
            std::cout << "low_latency_readback phase=" << phase << " value="
                      << (value ? std::to_string(*value) : "unavailable") << '\n';
        };
        print_low_latency("created", decoder);
        std::uint64_t sequence{}, outputs{};
        for (const auto epoch : {1ULL, 4ULL, 9ULL}) {
            decoder.flush_representation();
            std::uint64_t epoch_outputs{};
            for (unsigned i = 0; i < 16; ++i) {
                seed.frame_id = ++sequence;
                seed.representation_epoch = epoch;
                seed.captured_at_us = sequence * 16667U;
                const auto decoded = decoder.submit_nv12(seed);
                if (!decoded) continue;
                if (!epoch_outputs) std::cout << "mf_nominal_range=" << decoded->nominal_range
                    << " mf_yuv_matrix=" << decoded->yuv_matrix << '\n';
                if (decoded->representation_epoch != epoch || !decoded->keyframe ||
                    decoded->frame_id > seed.frame_id ||
                    decoded->captured_at_us != decoded->frame_id * 16667U)
                    throw std::runtime_error("decoder lost epoch/frame/keyframe lineage at epoch " + std::to_string(epoch));
                static_cast<void>(renderer.render_persistent(window, *decoded));
                ++epoch_outputs;
            }
            if (!epoch_outputs) throw std::runtime_error("decoder produced no output");
            print_low_latency("after_negotiation_and_output", decoder);
            const auto pending_before = decoder.queue_depths().compressed_lineage;
            unsigned tail_outputs{};
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(30);
            do {
                if (const auto tail = decoder.poll_nv12()) {
                    if (tail->representation_epoch != epoch || tail->frame_id > sequence)
                        throw std::runtime_error("polled output lost lineage");
                    ++tail_outputs;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            } while (std::chrono::steady_clock::now() < deadline);
            std::cout << "silent_tail_poll_ms=30 pending_before=" << pending_before
                      << " additional_outputs=" << tail_outputs
                      << " pending_after=" << decoder.queue_depths().compressed_lineage << '\n';
            outputs += epoch_outputs;
            std::cout << "epoch=" << epoch << " outputs=" << epoch_outputs << " lineage=PASS\n";
        }
        std::cout << "decoder_epoch=PASS outputs=" << outputs << " input_injected=0\n";
        // Resume the original, unmodified reference-dependent stream after
        // reseeding with its first IDR. Poll after every normal submission.
        decoder.flush_representation();
        seed.frame_id = 1; seed.captured_at_us = 16667; seed.representation_epoch = 20;
        static_cast<void>(decoder.submit_nv12(seed));
        rwn::platform::windows::WindowsMediaFoundationH264Decoder cpu_decoder;
        unsigned cpu_outputs = cpu_decoder.submit_nv12(seed) ? 1U : 0U;
        std::size_t cpu_max_pending{};
        unsigned stream_inputs{}, normal_outputs{}, extra_outputs{};
        std::size_t max_pending{}, max_ready{};
        for (unsigned packet = 0; packet < 512 && stream_inputs < 90; ++packet) {
            std::array<std::byte, visual_message_header_size> bytes{};
            if (!read_exact(input, bytes)) throw std::runtime_error("stream ended during pump probe");
            const auto header = decode_visual_message_header(bytes);
            std::vector<std::byte> payload(header.payload_size);
            if (!read_exact(input, payload)) throw std::runtime_error("stream payload truncated");
            validate_visual_message_payload(header, payload);
            if (header.type != VisualMessageType::h264_access_unit) continue;
            const auto unit = decode_visual_h264_access_unit(payload);
            seed.frame_id = ++stream_inputs + 1U;
            seed.captured_at_us = seed.frame_id * 16667U;
            seed.keyframe = (header.flags & visual_flag_keyframe) != 0;
            seed.encoded = unit.encoded;
            if (decoder.submit_nv12(seed)) ++normal_outputs;
            while (decoder.poll_nv12()) ++extra_outputs;
            if (cpu_decoder.submit_nv12(seed)) ++cpu_outputs;
            while (cpu_decoder.poll_nv12()) ++cpu_outputs;
            cpu_max_pending = std::max(cpu_max_pending, cpu_decoder.queue_depths().compressed_lineage);
            const auto depth = decoder.queue_depths();
            max_pending = std::max(max_pending, depth.compressed_lineage);
            max_ready = std::max(max_ready, depth.decoded_ready);
        }
        if (stream_inputs != 90) throw std::runtime_error("insufficient stream samples");
        unsigned silent_outputs{};
        unsigned cpu_silent_outputs{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(30);
        do {
            if (decoder.poll_nv12()) ++silent_outputs;
            if (cpu_decoder.poll_nv12()) ++cpu_silent_outputs;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } while (std::chrono::steady_clock::now() < deadline);
        std::cout << "stream_pump inputs=" << stream_inputs << " normal_outputs=" << normal_outputs
                  << " immediate_extra_outputs=" << extra_outputs << " silent_extra_outputs=" << silent_outputs
                  << " max_pending=" << max_pending << " max_ready=" << max_ready
                  << " final_pending=" << decoder.queue_depths().compressed_lineage << '\n';
        std::cout << "same_stream_cpu outputs=" << cpu_outputs
                  << " silent_extra_outputs=" << cpu_silent_outputs
                  << " max_pending=" << cpu_max_pending
                  << " final_pending=" << cpu_decoder.queue_depths().compressed_lineage
                  << " gpu_output=" << cpu_decoder.queue_depths().d3d11_output_active << '\n';
        print_low_latency("gpu_after_stream", decoder);
        print_low_latency("cpu_after_stream", cpu_decoder);
        DestroyWindow(window);
        return 0;
    } catch (const std::exception& error) {
        if (window) DestroyWindow(window);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
