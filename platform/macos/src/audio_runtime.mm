#include "rwn/platform/macos/audio_runtime.hpp"

#import <ApplicationServices/ApplicationServices.h>
#import <AudioToolbox/AudioToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <Foundation/Foundation.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require_status(const OSStatus status, const char* operation) {
    if (status != noErr) {
        throw std::runtime_error(
            std::string(operation) + " failed with OSStatus " +
            std::to_string(status));
    }
}

std::uint64_t host_timestamp_us() {
    const auto time = CMClockGetTime(CMClockGetHostTimeClock());
    return static_cast<std::uint64_t>(CMTimeGetSeconds(time) * 1000000.0);
}

std::int16_t float_to_pcm(const float sample) {
    const auto bounded = std::clamp(sample, -1.0F, 1.0F);
    return static_cast<std::int16_t>(std::lrint(
        bounded * static_cast<float>(std::numeric_limits<std::int16_t>::max())));
}

struct AudioBufferListStorage {
    AudioBufferList list;
    AudioBuffer additional_buffer;
};

}  // namespace

@interface RWNAudioStreamOutput : NSObject <SCStreamOutput> {
@public
    std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<std::int16_t> samples_;
    std::uint64_t first_sample_at_us_;
}
@end

@implementation RWNAudioStreamOutput
- (instancetype)init {
    self = [super init];
    if (self != nil) first_sample_at_us_ = 0;
    return self;
}

- (void)stream:(SCStream*)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
    ofType:(SCStreamOutputType)type {
    (void)stream;
    if (type != SCStreamOutputTypeAudio ||
        !CMSampleBufferDataIsReady(sampleBuffer)) {
        return;
    }
    auto description = CMSampleBufferGetFormatDescription(sampleBuffer);
    const auto* format = description == nullptr ? nullptr :
        CMAudioFormatDescriptionGetStreamBasicDescription(description);
    if (format == nullptr || format->mFormatID != kAudioFormatLinearPCM ||
        format->mSampleRate != rwn::audio::opus_sample_rate ||
        format->mChannelsPerFrame != rwn::audio::opus_channels ||
        (format->mFormatFlags &
         (kAudioFormatFlagIsFloat | kAudioFormatFlagIsSignedInteger)) == 0) {
        return;
    }
    AudioBufferListStorage storage{};
    storage.list.mNumberBuffers = 2;
    CMBlockBufferRef retained_block{};
    const auto status = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
        sampleBuffer, nullptr, &storage.list, sizeof(storage), nullptr,
        nullptr, kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment,
        &retained_block);
    if (status != noErr || storage.list.mNumberBuffers == 0 ||
        storage.list.mNumberBuffers > 2) {
        if (retained_block != nullptr) CFRelease(retained_block);
        return;
    }
    const auto frames = static_cast<std::size_t>(
        CMSampleBufferGetNumSamples(sampleBuffer));
    if (frames == 0 || frames > rwn::audio::opus_sample_rate) {
        if (retained_block != nullptr) CFRelease(retained_block);
        return;
    }
    std::vector<std::int16_t> converted;
    converted.reserve(frames * rwn::audio::opus_channels);
    const bool planar =
        (format->mFormatFlags & kAudioFormatFlagIsNonInterleaved) != 0;
    const bool floating =
        (format->mFormatFlags & kAudioFormatFlagIsFloat) != 0;
    if ((planar && storage.list.mNumberBuffers < rwn::audio::opus_channels) ||
        (floating && format->mBitsPerChannel != 32) ||
        (!floating && format->mBitsPerChannel != 16)) {
        if (retained_block != nullptr) CFRelease(retained_block);
        return;
    }
    const auto bytes_per_sample =
        static_cast<std::size_t>(format->mBitsPerChannel / 8U);
    for (std::size_t frame = 0; frame < frames; ++frame) {
        for (std::size_t channel = 0; channel < rwn::audio::opus_channels;
             ++channel) {
            const auto buffer_index = planar ? channel : 0U;
            const auto sample_index = planar
                ? frame : frame * rwn::audio::opus_channels + channel;
            const auto& buffer = storage.list.mBuffers[buffer_index];
            if ((sample_index + 1U) * bytes_per_sample >
                buffer.mDataByteSize) {
                if (retained_block != nullptr) CFRelease(retained_block);
                return;
            }
            if (buffer.mData == nullptr) {
                converted.push_back(0);
            } else if (floating) {
                const auto* data = static_cast<const float*>(buffer.mData);
                converted.push_back(float_to_pcm(data[sample_index]));
            } else {
                const auto* data = static_cast<const std::int16_t*>(buffer.mData);
                converted.push_back(data[sample_index]);
            }
        }
    }
    if (retained_block != nullptr) CFRelease(retained_block);
    {
        std::lock_guard lock(mutex_);
        constexpr auto maximum_samples =
            static_cast<std::size_t>(rwn::audio::opus_sample_rate) *
            rwn::audio::opus_channels;
        if (samples_.size() + converted.size() > maximum_samples) {
            samples_.clear();
            first_sample_at_us_ = 0;
        }
        if (samples_.empty()) first_sample_at_us_ = host_timestamp_us();
        samples_.insert(samples_.end(), converted.begin(), converted.end());
    }
    condition_.notify_all();
}
@end

namespace rwn::platform::macos {

class MacosSystemAudioCapture::Impl {
public:
    Impl() {
        @autoreleasepool {
            if (@available(macOS 13.0, *)) {
                if (!CGPreflightScreenCaptureAccess()) {
                    throw std::runtime_error(
                        "macOS screen recording permission is required for system audio");
                }
                dispatch_semaphore_t ready = dispatch_semaphore_create(0);
                __block SCShareableContent* content = nil;
                __block NSError* content_error = nil;
                [SCShareableContent
                    getShareableContentExcludingDesktopWindows:YES
                    onScreenWindowsOnly:YES
                    completionHandler:^(SCShareableContent* value, NSError* error) {
                        content = [value retain];
                        content_error = [error retain];
                        dispatch_semaphore_signal(ready);
                    }];
                if (dispatch_semaphore_wait(
                        ready, dispatch_time(DISPATCH_TIME_NOW,
                                             5 * NSEC_PER_SEC)) != 0) {
                    throw std::runtime_error(
                        "ScreenCaptureKit audio discovery timed out");
                }
                if (content_error != nil || content.displays.count == 0) {
                    const std::string reason = content_error == nil
                        ? "ScreenCaptureKit found no display for audio"
                        : content_error.localizedDescription.UTF8String;
                    [content_error release];
                    [content release];
                    throw std::runtime_error(reason);
                }
                SCContentFilter* filter = [[SCContentFilter alloc]
                    initWithDisplay:content.displays.firstObject
                    excludingWindows:@[]];
                SCStreamConfiguration* configuration =
                    [[SCStreamConfiguration alloc] init];
                configuration.width = 2;
                configuration.height = 2;
                configuration.queueDepth = 1;
                configuration.minimumFrameInterval = CMTimeMake(1, 1);
                configuration.capturesAudio = YES;
                configuration.excludesCurrentProcessAudio = NO;
                configuration.sampleRate = audio::opus_sample_rate;
                configuration.channelCount = audio::opus_channels;
                output_ = [[RWNAudioStreamOutput alloc] init];
                stream_ = [[SCStream alloc]
                    initWithFilter:filter configuration:configuration
                    delegate:nil];
                queue_ = dispatch_queue_create(
                    "dev.remoteworkspace.system-audio",
                    DISPATCH_QUEUE_SERIAL);
                NSError* output_error = nil;
                if (![stream_ addStreamOutput:output_
                         type:SCStreamOutputTypeAudio
                         sampleHandlerQueue:queue_
                         error:&output_error]) {
                    const std::string reason =
                        output_error.localizedDescription.UTF8String;
                    [configuration release];
                    [filter release];
                    [content release];
                    throw std::runtime_error(reason);
                }
                dispatch_semaphore_t started = dispatch_semaphore_create(0);
                __block NSError* start_error = nil;
                [stream_ startCaptureWithCompletionHandler:^(NSError* error) {
                    start_error = [error retain];
                    dispatch_semaphore_signal(started);
                }];
                if (dispatch_semaphore_wait(
                        started, dispatch_time(DISPATCH_TIME_NOW,
                                               5 * NSEC_PER_SEC)) != 0 ||
                    start_error != nil) {
                    const std::string reason = start_error == nil
                        ? "ScreenCaptureKit audio start timed out"
                        : start_error.localizedDescription.UTF8String;
                    [start_error release];
                    [configuration release];
                    [filter release];
                    [content release];
                    throw std::runtime_error(reason);
                }
                [configuration release];
                [filter release];
                [content release];
            } else {
                throw std::runtime_error(
                    "system audio capture requires macOS 13 or later");
            }
        }
    }

    ~Impl() {
        @autoreleasepool {
            if (stream_ != nil) {
                dispatch_semaphore_t stopped = dispatch_semaphore_create(0);
                [stream_ stopCaptureWithCompletionHandler:^(NSError*) {
                    dispatch_semaphore_signal(stopped);
                }];
                dispatch_semaphore_wait(
                    stopped, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC));
                [stream_ release];
            }
            [output_ release];
        }
    }

    [[nodiscard]] std::optional<audio::CapturedPcmFrame> capture(
        const std::chrono::milliseconds timeout) {
        if (timeout <= std::chrono::milliseconds::zero() ||
            timeout > std::chrono::seconds{10}) {
            throw std::invalid_argument("macOS audio timeout is outside bounds");
        }
        constexpr auto target_samples =
            static_cast<std::size_t>(audio::opus_channels) *
            audio::opus_frame_samples;
        std::unique_lock lock(output_->mutex_);
        if (!output_->condition_.wait_for(lock, timeout, [&] {
                return output_->samples_.size() >= target_samples;
            })) {
            return std::nullopt;
        }
        audio::CapturedPcmFrame result{
            .frame = {
                .sample_rate = audio::opus_sample_rate,
                .channels = audio::opus_channels,
                .samples_per_channel = audio::opus_frame_samples,
                .interleaved_samples = std::vector<std::int16_t>(
                    output_->samples_.begin(), output_->samples_.begin() +
                        static_cast<std::ptrdiff_t>(target_samples)),
            },
            .captured_at_us = output_->first_sample_at_us_,
        };
        output_->samples_.erase(
            output_->samples_.begin(), output_->samples_.begin() +
                static_cast<std::ptrdiff_t>(target_samples));
        if (output_->samples_.empty()) output_->first_sample_at_us_ = 0;
        audio::validate_pcm_frame(result.frame);
        return result;
    }

private:
    RWNAudioStreamOutput* output_{};
    SCStream* stream_{};
    dispatch_queue_t queue_{};
};

class MacosAudioPlayback::Impl {
public:
    Impl() {
        AudioStreamBasicDescription format{};
        format.mSampleRate = audio::opus_sample_rate;
        format.mFormatID = kAudioFormatLinearPCM;
        format.mFormatFlags =
            kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
        format.mBytesPerPacket = audio::opus_channels * sizeof(std::int16_t);
        format.mFramesPerPacket = 1;
        format.mBytesPerFrame = format.mBytesPerPacket;
        format.mChannelsPerFrame = audio::opus_channels;
        format.mBitsPerChannel = 16;
        require_status(AudioQueueNewOutput(
            &format, completed, this, nullptr, nullptr, 0, &queue_),
            "create macOS audio output queue");
    }

    ~Impl() {
        if (queue_ != nullptr) {
            static_cast<void>(AudioQueueStop(queue_, true));
            static_cast<void>(AudioQueueDispose(queue_, true));
        }
    }

    void play(
        const audio::PcmFrame& frame,
        const std::chrono::milliseconds timeout) {
        if (timeout <= std::chrono::milliseconds::zero() ||
            timeout > std::chrono::seconds{10}) {
            throw std::invalid_argument("macOS audio timeout is outside bounds");
        }
        audio::validate_pcm_frame(frame);
        std::vector<std::int16_t> stereo;
        const std::int16_t* source = frame.interleaved_samples.data();
        if (frame.channels == 1) {
            stereo.reserve(
                static_cast<std::size_t>(frame.samples_per_channel) * 2U);
            for (const auto sample : frame.interleaved_samples) {
                stereo.push_back(sample);
                stereo.push_back(sample);
            }
            source = stereo.data();
        }
        const auto bytes = static_cast<UInt32>(
            static_cast<std::size_t>(frame.samples_per_channel) *
            audio::opus_channels * sizeof(std::int16_t));
        AudioQueueBufferRef buffer{};
        require_status(AudioQueueAllocateBuffer(queue_, bytes, &buffer),
                       "allocate macOS audio output buffer");
        std::memcpy(buffer->mAudioData, source, bytes);
        buffer->mAudioDataByteSize = bytes;
        std::size_t expected{};
        {
            std::lock_guard lock(mutex_);
            expected = ++submitted_;
        }
        const auto enqueue = AudioQueueEnqueueBuffer(queue_, buffer, 0, nullptr);
        if (enqueue != noErr) {
            static_cast<void>(AudioQueueFreeBuffer(queue_, buffer));
            require_status(enqueue, "enqueue macOS audio output buffer");
        }
        require_status(AudioQueueStart(queue_, nullptr),
                       "start macOS audio output queue");
        std::unique_lock lock(mutex_);
        if (!condition_.wait_for(lock, timeout, [&] {
                return completed_ >= expected;
            })) {
            throw std::runtime_error("macOS audio playback timed out");
        }
    }

private:
    static void completed(
        void* context, AudioQueueRef queue, AudioQueueBufferRef buffer) {
        auto& self = *static_cast<Impl*>(context);
        static_cast<void>(AudioQueueFreeBuffer(queue, buffer));
        {
            std::lock_guard lock(self.mutex_);
            ++self.completed_;
        }
        self.condition_.notify_all();
    }

    AudioQueueRef queue_{};
    std::mutex mutex_;
    std::condition_variable condition_;
    std::size_t submitted_{};
    std::size_t completed_{};
};

MacosSystemAudioCapture::MacosSystemAudioCapture()
    : impl_(std::make_unique<Impl>()) {}
MacosSystemAudioCapture::~MacosSystemAudioCapture() = default;

std::optional<audio::CapturedPcmFrame> MacosSystemAudioCapture::capture(
    const std::chrono::milliseconds timeout) {
    return impl_->capture(timeout);
}

MacosAudioPlayback::MacosAudioPlayback()
    : impl_(std::make_unique<Impl>()) {}
MacosAudioPlayback::~MacosAudioPlayback() = default;

void MacosAudioPlayback::play(
    const audio::PcmFrame& frame,
    const std::chrono::milliseconds timeout) {
    impl_->play(frame, timeout);
}

}  // namespace rwn::platform::macos
