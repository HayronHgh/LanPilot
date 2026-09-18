#include "rwn/audio/audio.hpp"

#if defined(_WIN32)
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

#include <stdexcept>
#include <string>
#include <utility>

namespace rwn::audio {
namespace {

struct OpusEncoder;
struct OpusDecoder;
constexpr int opus_application_audio = 2049;

#if defined(_WIN32)
using LibraryHandle = HMODULE;
#else
using LibraryHandle = void*;
#endif

LibraryHandle open_library(const std::filesystem::path& path) {
#if defined(_WIN32)
    const auto handle = LoadLibraryExW(
        path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
#else
    const auto handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
    if (handle == nullptr) {
        throw std::runtime_error("failed to load the configured Opus library");
    }
    return handle;
}

void close_library(const LibraryHandle handle) noexcept {
#if defined(_WIN32)
    FreeLibrary(handle);
#else
    dlclose(handle);
#endif
}

template <typename Function>
Function load_symbol(const LibraryHandle handle, const char* name) {
#if defined(_WIN32)
    const auto address = reinterpret_cast<void*>(GetProcAddress(handle, name));
#else
    const auto address = dlsym(handle, name);
#endif
    if (address == nullptr) {
        throw std::runtime_error(
            std::string("configured Opus library is missing symbol ") + name);
    }
    return reinterpret_cast<Function>(address);
}

}  // namespace

class DynamicOpusCodec::Impl {
public:
    Impl(std::filesystem::path library_path, const std::uint16_t channels)
        : channels_(channels) {
        if (!library_path.is_absolute() || !std::filesystem::is_regular_file(library_path) ||
            (channels_ != 1 && channels_ != opus_channels)) {
            throw std::invalid_argument(
                "Opus library must be an absolute regular file and channels must be 1 or 2");
        }
        library_path = std::filesystem::weakly_canonical(library_path);
        library_ = open_library(library_path);
        try {
            encoder_create_ = load_symbol<EncoderCreate>(library_, "opus_encoder_create");
            encoder_destroy_ = load_symbol<EncoderDestroy>(library_, "opus_encoder_destroy");
            encode_ = load_symbol<Encode>(library_, "opus_encode");
            decoder_create_ = load_symbol<DecoderCreate>(library_, "opus_decoder_create");
            decoder_destroy_ = load_symbol<DecoderDestroy>(library_, "opus_decoder_destroy");
            decode_ = load_symbol<Decode>(library_, "opus_decode");
            int error{};
            encoder_ = encoder_create_(
                static_cast<int>(opus_sample_rate), channels_,
                opus_application_audio, &error);
            if (encoder_ == nullptr || error != 0) {
                throw std::runtime_error("Opus encoder creation failed");
            }
            decoder_ = decoder_create_(
                static_cast<int>(opus_sample_rate), channels_, &error);
            if (decoder_ == nullptr || error != 0) {
                throw std::runtime_error("Opus decoder creation failed");
            }
        } catch (...) {
            cleanup();
            throw;
        }
    }

    ~Impl() { cleanup(); }

    std::vector<std::byte> encode(const PcmFrame& frame) {
        validate_pcm_frame(frame);
        if (frame.channels != channels_) {
            throw std::invalid_argument("PCM channel count does not match Opus codec");
        }
        std::vector<std::byte> output(maximum_opus_packet_size);
        const auto count = encode_(
            encoder_, frame.interleaved_samples.data(), frame.samples_per_channel,
            reinterpret_cast<unsigned char*>(output.data()),
            static_cast<int>(output.size()));
        if (count <= 0) {
            throw std::runtime_error("Opus encoding failed");
        }
        output.resize(static_cast<std::size_t>(count));
        return output;
    }

    PcmFrame decode(const AudioPacket& packet) {
        if (packet.channels != channels_) {
            throw std::invalid_argument("Opus packet channel count does not match codec");
        }
        return decode_bytes(
            reinterpret_cast<const unsigned char*>(packet.opus.data()),
            static_cast<int>(packet.opus.size()), packet.samples_per_channel);
    }

    PcmFrame conceal_loss(const std::uint16_t samples_per_channel) {
        return decode_bytes(nullptr, 0, samples_per_channel);
    }

private:
    using EncoderCreate = OpusEncoder* (*)(int, int, int, int*);
    using EncoderDestroy = void (*)(OpusEncoder*);
    using Encode = int (*)(OpusEncoder*, const std::int16_t*, int,
                           unsigned char*, int);
    using DecoderCreate = OpusDecoder* (*)(int, int, int*);
    using DecoderDestroy = void (*)(OpusDecoder*);
    using Decode = int (*)(OpusDecoder*, const unsigned char*, int,
                           std::int16_t*, int, int);

    PcmFrame decode_bytes(
        const unsigned char* data, const int size,
        const std::uint16_t requested_samples) {
        if (requested_samples == 0 || requested_samples > 2880) {
            throw std::invalid_argument("Opus decode sample count is invalid");
        }
        std::vector<std::int16_t> samples(
            static_cast<std::size_t>(requested_samples) * channels_);
        const auto decoded = decode_(
            decoder_, data, size, samples.data(), requested_samples, 0);
        if (decoded <= 0 || decoded > requested_samples) {
            throw std::runtime_error("Opus decoding or PLC failed");
        }
        samples.resize(static_cast<std::size_t>(decoded) * channels_);
        return {
            .sample_rate = opus_sample_rate,
            .channels = channels_,
            .samples_per_channel = static_cast<std::uint16_t>(decoded),
            .interleaved_samples = std::move(samples),
        };
    }

    void cleanup() noexcept {
        if (decoder_ != nullptr && decoder_destroy_ != nullptr) {
            decoder_destroy_(decoder_);
            decoder_ = nullptr;
        }
        if (encoder_ != nullptr && encoder_destroy_ != nullptr) {
            encoder_destroy_(encoder_);
            encoder_ = nullptr;
        }
        if (library_ != nullptr) {
            close_library(library_);
            library_ = nullptr;
        }
    }

    std::uint16_t channels_{};
    LibraryHandle library_{};
    EncoderCreate encoder_create_{};
    EncoderDestroy encoder_destroy_{};
    Encode encode_{};
    DecoderCreate decoder_create_{};
    DecoderDestroy decoder_destroy_{};
    Decode decode_{};
    OpusEncoder* encoder_{};
    OpusDecoder* decoder_{};
};

DynamicOpusCodec::DynamicOpusCodec(
    std::filesystem::path absolute_library_path,
    const std::uint16_t channels)
    : impl_(std::make_unique<Impl>(
          std::move(absolute_library_path), channels)) {}

DynamicOpusCodec::~DynamicOpusCodec() = default;

std::vector<std::byte> DynamicOpusCodec::encode(const PcmFrame& frame) {
    return impl_->encode(frame);
}

PcmFrame DynamicOpusCodec::decode(const AudioPacket& packet) {
    return impl_->decode(packet);
}

PcmFrame DynamicOpusCodec::conceal_loss(
    const std::uint16_t samples_per_channel) {
    return impl_->conceal_loss(samples_per_channel);
}

}  // namespace rwn::audio
