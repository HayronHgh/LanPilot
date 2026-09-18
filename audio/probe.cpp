#include "rwn/audio/audio.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>

int main(const int argc, char** argv) {
    try {
        if (argc != 2) {
            std::cerr << "usage: rwn-audio-probe <absolute-libopus-path>\n";
            return 64;
        }
        rwn::audio::DynamicOpusCodec codec{std::filesystem::path(argv[1])};
        const rwn::audio::PcmFrame silence{
            .sample_rate = rwn::audio::opus_sample_rate,
            .channels = rwn::audio::opus_channels,
            .samples_per_channel = rwn::audio::opus_frame_samples,
            .interleaved_samples = std::vector<std::int16_t>(
                rwn::audio::opus_channels * rwn::audio::opus_frame_samples),
        };
        const auto encoded = codec.encode(silence);
        const auto decoded = codec.decode({
            .sequence = 1,
            .captured_at_us = 1,
            .sample_rate = rwn::audio::opus_sample_rate,
            .channels = rwn::audio::opus_channels,
            .samples_per_channel = rwn::audio::opus_frame_samples,
            .opus = encoded,
        });
        const auto plc = codec.conceal_loss(rwn::audio::opus_frame_samples);
        std::cout << "opus_bytes=" << encoded.size()
                  << " decoded_samples=" << decoded.samples_per_channel
                  << " plc_samples=" << plc.samples_per_channel << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "rwn-audio-probe: " << error.what() << '\n';
        return 1;
    }
}
