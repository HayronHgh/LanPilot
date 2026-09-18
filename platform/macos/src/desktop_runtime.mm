#include "rwn/platform/macos/desktop_runtime.hpp"

#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <VideoToolbox/VideoToolbox.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void require_status(const OSStatus status, const char* operation) {
    if (status != noErr) {
        throw std::runtime_error(
            std::string(operation) + " failed with OSStatus " +
            std::to_string(status));
    }
}

CGKeyCode hid_usage_to_key_code(const std::uint32_t usage) {
    switch (usage) {
        case 0x04U: return 0x00;  // A
        case 0x05U: return 0x0b;  // B
        case 0x06U: return 0x08;  // C
        case 0x07U: return 0x02;  // D
        case 0x08U: return 0x0e;  // E
        case 0x09U: return 0x03;  // F
        case 0x0aU: return 0x05;  // G
        case 0x0bU: return 0x04;  // H
        case 0x0cU: return 0x22;  // I
        case 0x0dU: return 0x26;  // J
        case 0x0eU: return 0x28;  // K
        case 0x0fU: return 0x25;  // L
        case 0x10U: return 0x2e;  // M
        case 0x11U: return 0x2d;  // N
        case 0x12U: return 0x1f;  // O
        case 0x13U: return 0x23;  // P
        case 0x14U: return 0x0c;  // Q
        case 0x15U: return 0x0f;  // R
        case 0x16U: return 0x01;  // S
        case 0x17U: return 0x11;  // T
        case 0x18U: return 0x20;  // U
        case 0x19U: return 0x09;  // V
        case 0x1aU: return 0x0d;  // W
        case 0x1bU: return 0x07;  // X
        case 0x1cU: return 0x10;  // Y
        case 0x1dU: return 0x06;  // Z
        case 0x1eU: return 0x12;  // 1
        case 0x1fU: return 0x13;  // 2
        case 0x20U: return 0x14;  // 3
        case 0x21U: return 0x15;  // 4
        case 0x22U: return 0x17;  // 5
        case 0x23U: return 0x16;  // 6
        case 0x24U: return 0x1a;  // 7
        case 0x25U: return 0x1c;  // 8
        case 0x26U: return 0x19;  // 9
        case 0x27U: return 0x1d;  // 0
        case 0x28U: return 0x24;  // Return
        case 0x29U: return 0x35;  // Escape
        case 0x2aU: return 0x33;  // Delete
        case 0x2bU: return 0x30;  // Tab
        case 0x2cU: return 0x31;  // Space
        case 0x2dU: return 0x1b;  // Hyphen
        case 0x2eU: return 0x18;  // Equal
        case 0x2fU: return 0x21;  // Left bracket
        case 0x30U: return 0x1e;  // Right bracket
        case 0x31U: return 0x2a;  // Backslash
        case 0x32U: return 0x0a;  // ISO section / non-US hash
        case 0x33U: return 0x29;  // Semicolon
        case 0x34U: return 0x27;  // Quote
        case 0x35U: return 0x32;  // Grave
        case 0x36U: return 0x2b;  // Comma
        case 0x37U: return 0x2f;  // Period
        case 0x38U: return 0x2c;  // Slash
        case 0x39U: return 0x39;  // Caps Lock
        case 0x3aU: return 0x7a;  // F1
        case 0x3bU: return 0x78;  // F2
        case 0x3cU: return 0x63;  // F3
        case 0x3dU: return 0x76;  // F4
        case 0x3eU: return 0x60;  // F5
        case 0x3fU: return 0x61;  // F6
        case 0x40U: return 0x62;  // F7
        case 0x41U: return 0x64;  // F8
        case 0x42U: return 0x65;  // F9
        case 0x43U: return 0x6d;  // F10
        case 0x44U: return 0x67;  // F11
        case 0x45U: return 0x6f;  // F12
        case 0x46U: return 0x69;  // Print Screen -> F13
        case 0x47U: return 0x6b;  // Scroll Lock -> F14
        case 0x48U: return 0x71;  // Pause -> F15
        case 0x49U: return 0x72;  // Insert -> Help
        case 0x4aU: return 0x73;  // Home
        case 0x4bU: return 0x74;  // Page Up
        case 0x4cU: return 0x75;  // Forward Delete
        case 0x4dU: return 0x77;  // End
        case 0x4eU: return 0x79;  // Page Down
        case 0x4fU: return 0x7c;  // Right
        case 0x50U: return 0x7b;  // Left
        case 0x51U: return 0x7d;  // Down
        case 0x52U: return 0x7e;  // Up
        case 0x53U: return 0x47;  // Keypad Clear / Num Lock
        case 0x54U: return 0x4b;  // Keypad divide
        case 0x55U: return 0x43;  // Keypad multiply
        case 0x56U: return 0x4e;  // Keypad subtract
        case 0x57U: return 0x45;  // Keypad add
        case 0x58U: return 0x4c;  // Keypad Enter
        case 0x59U: return 0x53;  // Keypad 1
        case 0x5aU: return 0x54;  // Keypad 2
        case 0x5bU: return 0x55;  // Keypad 3
        case 0x5cU: return 0x56;  // Keypad 4
        case 0x5dU: return 0x57;  // Keypad 5
        case 0x5eU: return 0x58;  // Keypad 6
        case 0x5fU: return 0x59;  // Keypad 7
        case 0x60U: return 0x5b;  // Keypad 8
        case 0x61U: return 0x5c;  // Keypad 9
        case 0x62U: return 0x52;  // Keypad 0
        case 0x63U: return 0x41;  // Keypad decimal
        case 0x64U: return 0x0a;  // Non-US backslash
        case 0x68U: return 0x69;  // F13
        case 0x69U: return 0x6b;  // F14
        case 0x6aU: return 0x71;  // F15
        case 0x6bU: return 0x6a;  // F16
        case 0x6cU: return 0x40;  // F17
        case 0x6dU: return 0x4f;  // F18
        case 0x6eU: return 0x50;  // F19
        case 0x6fU: return 0x5a;  // F20
        case 0x7fU: return 0x4a;  // Mute
        case 0x80U: return 0x48;  // Volume Up
        case 0x81U: return 0x49;  // Volume Down
        case 0xe0U: return 0x3b;  // Left Control
        case 0xe1U: return 0x38;  // Left Shift
        case 0xe2U: return 0x3a;  // Left Option
        case 0xe3U: return 0x37;  // Left Command
        case 0xe4U: return 0x3e;  // Right Control
        case 0xe5U: return 0x3c;  // Right Shift
        case 0xe6U: return 0x3d;  // Right Option
        case 0xe7U: return 0x36;  // Right Command
        default: throw std::invalid_argument("unsupported HID keyboard usage");
    }
}

std::uint64_t host_timestamp_us() {
    const auto time = CMClockGetTime(CMClockGetHostTimeClock());
    return static_cast<std::uint64_t>(CMTimeGetSeconds(time) * 1000000.0);
}

rwn::desktop::VisualSckStatus visual_sck_status(const SCFrameStatus status) {
    using enum rwn::desktop::VisualSckStatus;
    switch (status) {
        case SCFrameStatusComplete: return complete;
        case SCFrameStatusIdle: return idle;
        case SCFrameStatusBlank: return blank;
        case SCFrameStatusSuspended: return suspended;
        case SCFrameStatusStarted: return started;
        case SCFrameStatusStopped: return stopped;
    }
    return unknown;
}

struct SckFrameMetadata {
    rwn::desktop::VisualSckStatus status{
        rwn::desktop::VisualSckStatus::unknown};
    CGRect content_rect{};
    std::uint32_t dirty_rect_count{};
    std::uint64_t dirty_union_area{};
    std::uint32_t dirty_ratio_ppm{};
};

bool decode_sck_rectangle(id value, CGRect& rectangle) {
    if (value == nil) return false;
    if ([value isKindOfClass:[NSDictionary class]]) {
        return CGRectMakeWithDictionaryRepresentation(
            reinterpret_cast<CFDictionaryRef>(value), &rectangle);
    }
    if ([value isKindOfClass:[NSValue class]] &&
        [value respondsToSelector:@selector(rectValue)]) {
        rectangle = [static_cast<NSValue*>(value) rectValue];
        return true;
    }
    return false;
}

std::uint64_t clipped_rectangle_union_area(
    NSArray* values,
    const CGRect content_rect) {
    if (values == nil || values.count == 0 ||
        content_rect.size.width <= 0 || content_rect.size.height <= 0) {
        return 0;
    }
    std::vector<CGRect> rectangles;
    std::vector<double> x_edges;
    rectangles.reserve(values.count);
    x_edges.reserve(values.count * 2U);
    for (id value in values) {
        CGRect rectangle{};
        if (!decode_sck_rectangle(value, rectangle)) continue;
        const auto clipped = CGRectIntersection(rectangle, content_rect);
        if (CGRectIsNull(clipped) || CGRectIsEmpty(clipped)) continue;
        rectangles.push_back(clipped);
        x_edges.push_back(CGRectGetMinX(clipped));
        x_edges.push_back(CGRectGetMaxX(clipped));
    }
    std::ranges::sort(x_edges);
    x_edges.erase(std::unique(x_edges.begin(), x_edges.end()), x_edges.end());
    double area{};
    for (std::size_t index = 1; index < x_edges.size(); ++index) {
        const auto left = x_edges[index - 1U];
        const auto right = x_edges[index];
        if (right <= left) continue;
        std::vector<std::pair<double, double>> intervals;
        for (const auto rectangle : rectangles) {
            if (CGRectGetMinX(rectangle) < right &&
                CGRectGetMaxX(rectangle) > left) {
                intervals.emplace_back(
                    CGRectGetMinY(rectangle), CGRectGetMaxY(rectangle));
            }
        }
        std::ranges::sort(intervals);
        double covered_y{};
        double current_start{};
        double current_end{};
        bool has_interval{};
        for (const auto [start, end] : intervals) {
            if (!has_interval || start > current_end) {
                if (has_interval) covered_y += current_end - current_start;
                current_start = start;
                current_end = end;
                has_interval = true;
            } else {
                current_end = std::max(current_end, end);
            }
        }
        if (has_interval) covered_y += current_end - current_start;
        area += (right - left) * covered_y;
    }
    return static_cast<std::uint64_t>(std::llround(std::max(0.0, area)));
}

SckFrameMetadata sck_frame_metadata(CMSampleBufferRef sample_buffer) {
    SckFrameMetadata metadata;
    const auto attachments = CMSampleBufferGetSampleAttachmentsArray(
        sample_buffer, false);
    if (attachments == nullptr || CFArrayGetCount(attachments) == 0) {
        return metadata;
    }
    NSDictionary* values = (__bridge NSDictionary*)
        CFArrayGetValueAtIndex(attachments, 0);
    if (NSNumber* status = [values objectForKey:SCStreamFrameInfoStatus]) {
        metadata.status = visual_sck_status(
            static_cast<SCFrameStatus>([status integerValue]));
    }
    if (id content = [values objectForKey:SCStreamFrameInfoContentRect]) {
        static_cast<void>(decode_sck_rectangle(
            content, metadata.content_rect));
    }
    NSArray* dirty = [values objectForKey:SCStreamFrameInfoDirtyRects];
    metadata.dirty_rect_count = dirty == nil
        ? 0U : static_cast<std::uint32_t>(dirty.count);
    metadata.dirty_union_area = clipped_rectangle_union_area(
        dirty, metadata.content_rect);
    const auto content_area = metadata.content_rect.size.width > 0 &&
            metadata.content_rect.size.height > 0
        ? metadata.content_rect.size.width * metadata.content_rect.size.height
        : 0.0;
    metadata.dirty_ratio_ppm = content_area <= 0
        ? 0U
        : static_cast<std::uint32_t>(std::clamp(
            std::llround(
                static_cast<double>(metadata.dirty_union_area) * 1'000'000.0 /
                content_area), 0LL, 1'000'000LL));
    return metadata;
}

}  // namespace

@interface RWNStreamOutput : NSObject <SCStreamOutput> {
@public
    std::mutex mutex_;
    std::condition_variable condition_;
    CVPixelBufferRef pixel_buffer_;
    CVPixelBufferRef analysis_pixel_buffer_;
    bool analysis_enabled_;
    std::uint64_t generation_;
    std::uint64_t captured_at_us_;
    std::uint64_t sample_presentation_us_;
    std::int64_t sample_age_us_;
    std::uint64_t replaced_frames_;
    std::uint64_t replaced_analysis_frames_;
    std::uint64_t pixel_buffer_frame_id_;
    std::atomic_uint64_t callback_sequence_;
    rwn::desktop::VisualLifecycleTracker* lifecycle_tracker_;
}
@end

@implementation RWNStreamOutput
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        pixel_buffer_ = nullptr;
        analysis_pixel_buffer_ = nullptr;
        analysis_enabled_ = false;
        generation_ = 0;
        captured_at_us_ = 0;
        sample_presentation_us_ = 0;
        sample_age_us_ = 0;
        replaced_frames_ = 0;
        replaced_analysis_frames_ = 0;
        pixel_buffer_frame_id_ = 0;
        callback_sequence_ = 0;
        lifecycle_tracker_ = nullptr;
    }
    return self;
}

- (void)dealloc {
    if (pixel_buffer_ != nullptr) {
        CVPixelBufferRelease(pixel_buffer_);
    }
    if (analysis_pixel_buffer_ != nullptr) {
        CVPixelBufferRelease(analysis_pixel_buffer_);
    }
    [super dealloc];
}

- (void)stream:(SCStream*)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
    ofType:(SCStreamOutputType)type {
    (void)stream;
    if (type != SCStreamOutputTypeScreen || !CMSampleBufferDataIsReady(sampleBuffer)) {
        return;
    }
    const auto callback_arrival_us = host_timestamp_us();
    const auto callback_sequence = callback_sequence_.fetch_add(1) + 1U;
    const auto sck_metadata = sck_frame_metadata(sampleBuffer);
    auto buffer = CMSampleBufferGetImageBuffer(sampleBuffer);
    const auto valid_image = buffer != nullptr;
    if (buffer == nullptr) {
        if (lifecycle_tracker_ != nullptr) {
            rwn::desktop::VisualTraceEvent metadata{
                .callback_sequence = callback_sequence,
                .sck_status = sck_metadata.status,
                .valid_image = false,
                .content_x = static_cast<std::uint32_t>(std::max(
                    0.0, sck_metadata.content_rect.origin.x)),
                .content_y = static_cast<std::uint32_t>(std::max(
                    0.0, sck_metadata.content_rect.origin.y)),
                .content_width = static_cast<std::uint32_t>(std::max(
                    0.0, sck_metadata.content_rect.size.width)),
                .content_height = static_cast<std::uint32_t>(std::max(
                    0.0, sck_metadata.content_rect.size.height)),
                .sck_dirty_rect_count = sck_metadata.dirty_rect_count,
                .sck_dirty_union_area = sck_metadata.dirty_union_area,
                .sck_dirty_ratio_ppm = sck_metadata.dirty_ratio_ppm,
            };
            lifecycle_tracker_->record(
                rwn::desktop::VisualLifecycleStage::sck_callback,
                0, callback_arrival_us, metadata);
        }
        return;
    }
    CVPixelBufferRetain(buffer);
    const auto presentation = CMSampleBufferGetPresentationTimeStamp(sampleBuffer);
    const auto presentation_seconds = CMTIME_IS_VALID(presentation)
        ? CMTimeGetSeconds(presentation)
        : 0.0;
    const auto sample_presentation_us =
        std::isfinite(presentation_seconds) && presentation_seconds > 0.0
        ? static_cast<std::uint64_t>(presentation_seconds * 1000000.0)
        : 0U;
    std::uint64_t frame_id{};
    std::uint64_t superseded_frame_id{};
    {
        std::lock_guard lock(mutex_);
        if (pixel_buffer_ != nullptr) {
            superseded_frame_id = pixel_buffer_frame_id_;
            CVPixelBufferRelease(pixel_buffer_);
            ++replaced_frames_;
        }
        pixel_buffer_ = buffer;
        if (analysis_enabled_) {
            CVPixelBufferRetain(buffer);
            if (analysis_pixel_buffer_ != nullptr) {
                CVPixelBufferRelease(analysis_pixel_buffer_);
                ++replaced_analysis_frames_;
            }
            analysis_pixel_buffer_ = buffer;
        }
        captured_at_us_ = callback_arrival_us;
        sample_presentation_us_ = sample_presentation_us;
        sample_age_us_ = sample_presentation_us != 0
            ? static_cast<std::int64_t>(callback_arrival_us) -
                  static_cast<std::int64_t>(sample_presentation_us)
            : 0;
        frame_id = ++generation_;
        pixel_buffer_frame_id_ = frame_id;
    }
    if (lifecycle_tracker_ != nullptr) {
        rwn::desktop::VisualTraceEvent metadata{
            .callback_sequence = callback_sequence,
            .sck_status = sck_metadata.status,
            .valid_image = valid_image,
            .content_x = static_cast<std::uint32_t>(std::max(
                0.0, sck_metadata.content_rect.origin.x)),
            .content_y = static_cast<std::uint32_t>(std::max(
                0.0, sck_metadata.content_rect.origin.y)),
            .content_width = static_cast<std::uint32_t>(std::max(
                0.0, sck_metadata.content_rect.size.width)),
            .content_height = static_cast<std::uint32_t>(std::max(
                0.0, sck_metadata.content_rect.size.height)),
            .sck_dirty_rect_count = sck_metadata.dirty_rect_count,
            .sck_dirty_union_area = sck_metadata.dirty_union_area,
            .sck_dirty_ratio_ppm = sck_metadata.dirty_ratio_ppm,
        };
        lifecycle_tracker_->record(
            rwn::desktop::VisualLifecycleStage::sck_callback,
            frame_id, callback_arrival_us, metadata);
        if (superseded_frame_id != 0) {
            auto superseded = metadata;
            superseded.superseded_by = frame_id;
            lifecycle_tracker_->record(
                rwn::desktop::VisualLifecycleStage::superseded,
                superseded_frame_id, callback_arrival_us, superseded);
        }
        lifecycle_tracker_->record(
            rwn::desktop::VisualLifecycleStage::latest_publish,
            frame_id, callback_arrival_us, metadata);
        if (sck_metadata.status !=
                rwn::desktop::VisualSckStatus::complete &&
            sck_metadata.status !=
                rwn::desktop::VisualSckStatus::started) {
            lifecycle_tracker_->record(
                rwn::desktop::VisualLifecycleStage::nonvisual_pipeline_advance,
                frame_id, callback_arrival_us, metadata);
        }
    }
    condition_.notify_all();
}
@end

namespace rwn::platform::macos {

struct NativeCapturedFrame {
    CVPixelBufferRef pixel_buffer{};
    std::uint64_t frame_id{};
    std::uint64_t captured_at_us{};
    std::uint64_t sample_presentation_us{};
    std::int64_t sample_age_us{};
};

class MacosScreenCaptureBackend::Impl {
public:
    Impl(
        const std::uint32_t maximum_width,
        const std::uint32_t maximum_height,
        const std::uint32_t frames_per_second,
        desktop::VisualLifecycleTracker* lifecycle_tracker = nullptr,
        const bool shows_cursor = true,
        const bool analyze_from_start = false) {
        configured_fps_ = frames_per_second == 0 ? 60 : frames_per_second;
        @autoreleasepool {
            if (!CGPreflightScreenCaptureAccess()) {
                throw std::runtime_error("macOS screen recording permission is not granted");
            }
            dispatch_semaphore_t content_ready = dispatch_semaphore_create(0);
            __block SCShareableContent* content = nil;
            __block NSError* content_error = nil;
            [SCShareableContent
                getShareableContentExcludingDesktopWindows:YES
                onScreenWindowsOnly:YES
                completionHandler:^(SCShareableContent* value, NSError* error) {
                    content = [value retain];
                    content_error = [error retain];
                    dispatch_semaphore_signal(content_ready);
                }];
            if (dispatch_semaphore_wait(
                    content_ready,
                    dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
                throw std::runtime_error("ScreenCaptureKit display discovery timed out");
            }
            if (content_error != nil || content.displays.count == 0) {
                const std::string reason = content_error == nil
                    ? "ScreenCaptureKit found no display"
                    : content_error.localizedDescription.UTF8String;
                [content_error release];
                [content release];
                throw std::runtime_error(reason);
            }
            SCDisplay* display = content.displays.firstObject;
            SCContentFilter* filter = [[SCContentFilter alloc]
                initWithDisplay:display excludingWindows:@[]];
            SCStreamConfiguration* configuration =
                [[SCStreamConfiguration alloc] init];
            const auto limited = maximum_width != 0 && maximum_height != 0;
            const auto width_scale = limited
                ? static_cast<double>(maximum_width) / display.width
                : 1.0;
            const auto height_scale = limited
                ? static_cast<double>(maximum_height) / display.height
                : 1.0;
            const auto scale = std::min({1.0, width_scale, height_scale});
            configuration.width = std::max(
                2U, static_cast<std::uint32_t>(display.width * scale) & ~1U);
            configuration.height = std::max(
                2U, static_cast<std::uint32_t>(display.height * scale) & ~1U);
            configuration.pixelFormat = kCVPixelFormatType_32BGRA;
            configuration.colorSpaceName = kCGColorSpaceSRGB;
            configuration.colorMatrix =
                kCGDisplayStreamYCbCrMatrix_ITU_R_709_2;
            if (@available(macOS 14.0, *)) {
                configuration.captureResolution = SCCaptureResolutionBest;
            }
            configuration.minimumFrameInterval = CMTimeMake(
                1, static_cast<std::int32_t>(
                    frames_per_second == 0 ? 60 : frames_per_second));
            configuration.queueDepth = 5;
            configuration.showsCursor = shows_cursor ? YES : NO;
            output_ = [[RWNStreamOutput alloc] init];
            output_->lifecycle_tracker_ = lifecycle_tracker;
            stream_ = [[SCStream alloc]
                initWithFilter:filter configuration:configuration delegate:nil];
            queue_ = dispatch_queue_create(
                "dev.remoteworkspace.desktop-capture", DISPATCH_QUEUE_SERIAL);
            // Subscribe before the first callback, including a completely idle
            // desktop whose only complete frame arrives during startCapture.
            output_->analysis_enabled_ = analyze_from_start;
            NSError* output_error = nil;
            if (![stream_ addStreamOutput:output_
                     type:SCStreamOutputTypeScreen
                     sampleHandlerQueue:queue_
                     error:&output_error]) {
                const std::string reason = output_error.localizedDescription.UTF8String;
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
                    started,
                    dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0 ||
                start_error != nil) {
                const std::string reason = start_error == nil
                    ? "ScreenCaptureKit start timed out"
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
            if (repeat_pixel_buffer_ != nullptr) {
                CVPixelBufferRelease(repeat_pixel_buffer_);
            }
        }
    }

    std::optional<desktop::RawFrame> capture(
        const std::chrono::milliseconds timeout) {
        auto native = take_latest(timeout);
        if (!native) return std::nullopt;
        auto buffer = native->pixel_buffer;
        const auto release_buffer = [&] { CVPixelBufferRelease(buffer); };
        if (CVPixelBufferGetPixelFormatType(buffer) != kCVPixelFormatType_32BGRA) {
            release_buffer();
            throw std::runtime_error("ScreenCaptureKit returned a non-BGRA frame");
        }
        const auto copy_started = host_timestamp_us();
        const auto lock_status = CVPixelBufferLockBaseAddress(
            buffer, kCVPixelBufferLock_ReadOnly);
        if (lock_status != noErr) {
            release_buffer();
            require_status(lock_status, "lock ScreenCaptureKit pixel buffer");
        }
        const auto width = CVPixelBufferGetWidth(buffer);
        const auto height = CVPixelBufferGetHeight(buffer);
        const auto source_stride = CVPixelBufferGetBytesPerRow(buffer);
        const auto row_size = width * 4U;
        desktop::RawFrame frame{
            .frame_id = native->frame_id,
            .captured_at_us = native->captured_at_us,
            .width = static_cast<std::uint32_t>(width),
            .height = static_cast<std::uint32_t>(height),
            .row_stride = static_cast<std::uint32_t>(row_size),
            .bgra = std::vector<std::byte>(row_size * height),
        };
        const auto* source = static_cast<const std::byte*>(
            CVPixelBufferGetBaseAddress(buffer));
        for (std::size_t row = 0; row < height; ++row) {
            std::copy_n(
                source + source_stride * row, row_size,
                frame.bgra.data() + row_size * row);
        }
        CVPixelBufferUnlockBaseAddress(buffer, kCVPixelBufferLock_ReadOnly);
        release_buffer();
        {
            std::lock_guard lock(timing_mutex_);
            last_timing_ = MacosCaptureTiming{
                .frame_id = frame.frame_id,
                .sample_presentation_us = native->sample_presentation_us,
                .callback_arrival_us = native->captured_at_us,
                .sample_age_us = native->sample_age_us,
                .bgra_copy_us = host_timestamp_us() - copy_started,
                .configured_fps = configured_fps_,
                .queue_depth = 5,
            };
        }
        return frame;
    }

    std::optional<NativeCapturedFrame> take_latest(
        const std::chrono::milliseconds timeout) {
        if (timeout < std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("capture timeout must be non-negative");
        }
        std::unique_lock lock(output_->mutex_);
        if (!output_->condition_.wait_for(lock, timeout, [&] {
                return output_->pixel_buffer_ != nullptr;
            })) {
            return std::nullopt;
        }
        auto buffer = output_->pixel_buffer_;
        output_->pixel_buffer_ = nullptr;
        output_->pixel_buffer_frame_id_ = 0;
        consumed_generation_ = output_->generation_;
        const auto captured_at = output_->captured_at_us_;
        const auto sample_presentation_us = output_->sample_presentation_us_;
        const auto sample_age_us = output_->sample_age_us_;
        if (repeat_pixel_buffer_ != nullptr) {
            CVPixelBufferRelease(repeat_pixel_buffer_);
        }
        CVPixelBufferRetain(buffer);
        repeat_pixel_buffer_ = buffer;
        repeat_frame_id_ = consumed_generation_;
        lock.unlock();
        return NativeCapturedFrame{
            .pixel_buffer = buffer,
            .frame_id = consumed_generation_,
            .captured_at_us = captured_at,
            .sample_presentation_us = sample_presentation_us,
            .sample_age_us = sample_age_us,
        };
    }

    std::optional<NativeCapturedFrame> repeat_last() {
        std::lock_guard lock(output_->mutex_);
        if (repeat_pixel_buffer_ == nullptr || repeat_frame_id_ == 0) {
            return std::nullopt;
        }
        CVPixelBufferRetain(repeat_pixel_buffer_);
        const auto now_us = host_timestamp_us();
        return NativeCapturedFrame{
            .pixel_buffer = repeat_pixel_buffer_,
            .frame_id = repeat_frame_id_,
            .captured_at_us = now_us,
            .sample_presentation_us = now_us,
            .sample_age_us = 0,
        };
    }

    void enable_dirty_analysis(const bool enabled) {
        std::lock_guard lock(output_->mutex_);
        output_->analysis_enabled_ = enabled;
        if (!enabled && output_->analysis_pixel_buffer_ != nullptr) {
            CVPixelBufferRelease(output_->analysis_pixel_buffer_);
            output_->analysis_pixel_buffer_ = nullptr;
        }
    }

    std::optional<NativeCapturedFrame> take_analysis_latest(
        const std::chrono::milliseconds timeout) {
        if (timeout < std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("analysis timeout must be non-negative");
        }
        std::unique_lock lock(output_->mutex_);
        if (!output_->condition_.wait_for(lock, timeout, [&] {
                return output_->analysis_pixel_buffer_ != nullptr;
            })) {
            return std::nullopt;
        }
        auto buffer = output_->analysis_pixel_buffer_;
        output_->analysis_pixel_buffer_ = nullptr;
        const auto frame_id = output_->generation_;
        const auto captured_at = output_->captured_at_us_;
        const auto sample_presentation_us = output_->sample_presentation_us_;
        const auto sample_age_us = output_->sample_age_us_;
        lock.unlock();
        return NativeCapturedFrame{
            .pixel_buffer = buffer,
            .frame_id = frame_id,
            .captured_at_us = captured_at,
            .sample_presentation_us = sample_presentation_us,
            .sample_age_us = sample_age_us,
        };
    }

    std::optional<MacosCaptureTiming> last_timing() const {
        std::lock_guard lock(timing_mutex_);
        return last_timing_;
    }

    void record_direct_timing(const NativeCapturedFrame& frame) {
        std::lock_guard lock(timing_mutex_);
        last_timing_ = MacosCaptureTiming{
            .frame_id = frame.frame_id,
            .sample_presentation_us = frame.sample_presentation_us,
            .callback_arrival_us = frame.captured_at_us,
            .sample_age_us = frame.sample_age_us,
            .bgra_copy_us = 0,
            .configured_fps = configured_fps_,
            .queue_depth = 5,
        };
    }

    std::uint64_t replaced_frame_count() const {
        std::lock_guard lock(output_->mutex_);
        return output_->replaced_frames_;
    }

    std::uint64_t replaced_analysis_frame_count() const {
        std::lock_guard lock(output_->mutex_);
        return output_->replaced_analysis_frames_;
    }

private:
    RWNStreamOutput* output_{};
    SCStream* stream_{};
    dispatch_queue_t queue_{};
    std::uint64_t consumed_generation_{};
    std::uint32_t configured_fps_{60};
    mutable std::mutex timing_mutex_;
    std::optional<MacosCaptureTiming> last_timing_;
    CVPixelBufferRef repeat_pixel_buffer_{};
    std::uint64_t repeat_frame_id_{};
};

namespace {

std::uint32_t merged_rectangle_count(
    const std::vector<std::uint8_t>& dirty,
    const std::uint32_t columns,
    const std::uint32_t rows) {
    struct Run {
        std::uint32_t x{};
        std::uint32_t width{};
    };
    std::vector<Run> previous;
    std::uint32_t rectangles{};
    for (std::uint32_t y = 0; y < rows; ++y) {
        std::vector<Run> current;
        for (std::uint32_t x = 0; x < columns;) {
            if (dirty[static_cast<std::size_t>(y) * columns + x] == 0) {
                ++x;
                continue;
            }
            const auto start = x;
            while (x < columns &&
                   dirty[static_cast<std::size_t>(y) * columns + x] != 0) {
                ++x;
            }
            current.push_back({.x = start, .width = x - start});
        }
        for (const auto& run : current) {
            const auto continued = std::ranges::any_of(
                previous, [&](const Run& prior) {
                    return prior.x == run.x && prior.width == run.width;
                });
            if (!continued) ++rectangles;
        }
        previous = std::move(current);
    }
    return rectangles;
}

struct DirtyPixelRect {
    std::uint32_t x{};
    std::uint32_t y{};
    std::uint32_t width{};
    std::uint32_t height{};
};

std::vector<DirtyPixelRect> merge_dirty_rectangles(
    const std::vector<std::uint8_t>& dirty,
    const std::uint32_t columns,
    const std::uint32_t rows,
    const std::uint32_t surface_width,
    const std::uint32_t surface_height) {
    struct ActiveRun {
        std::uint32_t x{};
        std::uint32_t width{};
        std::size_t rectangle_index{};
    };
    std::vector<DirtyPixelRect> rectangles;
    std::vector<ActiveRun> previous;
    for (std::uint32_t tile_y = 0; tile_y < rows; ++tile_y) {
        std::vector<ActiveRun> current;
        for (std::uint32_t tile_x = 0; tile_x < columns;) {
            if (dirty[static_cast<std::size_t>(tile_y) * columns + tile_x] == 0) {
                ++tile_x;
                continue;
            }
            const auto start = tile_x;
            while (tile_x < columns &&
                   dirty[static_cast<std::size_t>(tile_y) * columns + tile_x] != 0) {
                ++tile_x;
            }
            const auto run_width = tile_x - start;
            const auto continued = std::ranges::find_if(
                previous, [&](const ActiveRun& run) {
                    return run.x == start && run.width == run_width;
                });
            if (continued != previous.end()) {
                auto& rectangle = rectangles[continued->rectangle_index];
                rectangle.height = std::min(
                    surface_height - rectangle.y,
                    rectangle.height + 16U);
                current.push_back(*continued);
            } else {
                const auto x = start * 16U;
                const auto y = tile_y * 16U;
                rectangles.push_back({
                    .x = x,
                    .y = y,
                    .width = std::min(surface_width - x, run_width * 16U),
                    .height = std::min(surface_height - y, 16U),
                });
                current.push_back({
                    .x = start,
                    .width = run_width,
                    .rectangle_index = rectangles.size() - 1U,
                });
            }
        }
        previous = std::move(current);
    }
    return rectangles;
}

MacosDirtyTileStats aggregate_dirty_tiles(
    const std::vector<std::uint8_t>& base_dirty,
    const std::uint32_t base_columns,
    const std::uint32_t base_rows,
    const std::uint32_t tile_size) {
    constexpr std::uint32_t base_tile_size = 16;
    const auto scale = tile_size / base_tile_size;
    const auto columns = (base_columns + scale - 1U) / scale;
    const auto rows = (base_rows + scale - 1U) / scale;
    std::vector<std::uint8_t> dirty(
        static_cast<std::size_t>(columns) * rows, 0);
    std::uint32_t dirty_count{};
    for (std::uint32_t y = 0; y < rows; ++y) {
        for (std::uint32_t x = 0; x < columns; ++x) {
            bool changed{};
            for (std::uint32_t by = y * scale;
                 by < std::min(base_rows, (y + 1U) * scale) && !changed;
                 ++by) {
                for (std::uint32_t bx = x * scale;
                     bx < std::min(base_columns, (x + 1U) * scale);
                     ++bx) {
                    if (base_dirty[static_cast<std::size_t>(by) *
                                   base_columns + bx] != 0) {
                        changed = true;
                        break;
                    }
                }
            }
            if (changed) {
                dirty[static_cast<std::size_t>(y) * columns + x] = 1;
                ++dirty_count;
            }
        }
    }
    const auto total = columns * rows;
    return MacosDirtyTileStats{
        .tile_size = tile_size,
        .total_tiles = total,
        .dirty_tiles = dirty_count,
        .merged_rectangles = merged_rectangle_count(dirty, columns, rows),
        .dirty_ratio = total == 0
            ? 0.0
            : static_cast<double>(dirty_count) / total,
    };
}

}  // namespace

class MacosMetalDirtyTileAnalyzer::Impl {
public:
    Impl() {
        @autoreleasepool {
            device_ = [MTLCreateSystemDefaultDevice() retain];
            if (device_ == nil) {
                throw std::runtime_error("Metal device is unavailable");
            }
            queue_ = [device_ newCommandQueue];
            if (queue_ == nil) {
                throw std::runtime_error("Metal command queue creation failed");
            }
            NSString* source = [NSString stringWithUTF8String:R"metal(
#include <metal_stdlib>
using namespace metal;

kernel void rwn_dirty_tile_16(
    texture2d<half, access::read> current [[texture(0)]],
    texture2d<half, access::read> previous [[texture(1)]],
    device uint* dirty [[buffer(0)]],
    uint2 tile [[thread_position_in_grid]]) {
    const uint tiles_x = (current.get_width() + 15u) / 16u;
    const uint tiles_y = (current.get_height() + 15u) / 16u;
    if (tile.x >= tiles_x || tile.y >= tiles_y) return;
    const uint2 start = tile * 16u;
    bool changed = false;
    for (uint y = start.y; y < min(start.y + 16u, current.get_height()) && !changed; ++y) {
        for (uint x = start.x; x < min(start.x + 16u, current.get_width()); ++x) {
            if (any(current.read(uint2(x, y)) != previous.read(uint2(x, y)))) {
                changed = true;
                break;
            }
        }
    }
    dirty[tile.y * tiles_x + tile.x] = changed ? 1u : 0u;
}
)metal"];
            NSError* error = nil;
            id<MTLLibrary> library = [device_ newLibraryWithSource:source
                options:nil error:&error];
            if (library == nil) {
                const std::string reason = error == nil
                    ? "Metal shader compilation failed"
                    : error.localizedDescription.UTF8String;
                throw std::runtime_error(reason);
            }
            id<MTLFunction> function = [library
                newFunctionWithName:@"rwn_dirty_tile_16"];
            pipeline_ = [device_ newComputePipelineStateWithFunction:function
                error:&error];
            [function release];
            [library release];
            if (pipeline_ == nil) {
                const std::string reason = error == nil
                    ? "Metal pipeline creation failed"
                    : error.localizedDescription.UTF8String;
                throw std::runtime_error(reason);
            }
            const auto status = CVMetalTextureCacheCreate(
                kCFAllocatorDefault, nullptr, device_, nullptr, &texture_cache_);
            require_status(status, "create Metal texture cache");
        }
    }

    ~Impl() {
        @autoreleasepool {
            [result_buffer_ release];
            [analysis_previous_texture_ release];
            [latest_source_texture_ release];
            [canonical_exact_texture_ release];
            [pending_target_texture_ release];
            [snapshot_staging_ release];
            [pipeline_ release];
            [queue_ release];
            [device_ release];
            if (texture_cache_ != nullptr) {
                CFRelease(texture_cache_);
            }
        }
    }

    MacosDirtyAnalysisResult analyze(
        CVPixelBufferRef pixel_buffer,
        const std::uint64_t frame_id,
        const std::uint64_t captured_at_us) {
        std::lock_guard lock(mutex_);
        const auto started = std::chrono::steady_clock::now();
        if (CVPixelBufferGetPixelFormatType(pixel_buffer) !=
            kCVPixelFormatType_32BGRA) {
            throw std::runtime_error("dirty analyzer requires BGRA input");
        }
        const auto width = static_cast<std::uint32_t>(
            CVPixelBufferGetWidth(pixel_buffer));
        const auto height = static_cast<std::uint32_t>(
            CVPixelBufferGetHeight(pixel_buffer));
        ensure_resources(width, height);

        CVMetalTextureRef metal_reference{};
        require_status(CVMetalTextureCacheCreateTextureFromImage(
            kCFAllocatorDefault, texture_cache_, pixel_buffer, nullptr,
            MTLPixelFormatBGRA8Unorm, width, height, 0, &metal_reference),
            "create Metal texture from ScreenCaptureKit frame");
        id<MTLTexture> current = CVMetalTextureGetTexture(metal_reference);
        if (current == nil) {
            CFRelease(metal_reference);
            throw std::runtime_error("ScreenCaptureKit frame has no Metal texture");
        }

        id<MTLCommandBuffer> command = [queue_ commandBuffer];
        if (command == nil) {
            CFRelease(metal_reference);
            throw std::runtime_error("Metal command buffer creation failed");
        }
        if (has_previous_) {
            id<MTLComputeCommandEncoder> compute =
                [command computeCommandEncoder];
            [compute setComputePipelineState:pipeline_];
            [compute setTexture:current atIndex:0];
            [compute setTexture:analysis_previous_texture_ atIndex:1];
            [compute setBuffer:result_buffer_ offset:0 atIndex:0];
            const MTLSize grid = MTLSizeMake(tile_columns_, tile_rows_, 1);
            const auto width_threads = std::min<NSUInteger>(
                pipeline_.threadExecutionWidth, tile_columns_);
            const auto height_threads = std::max<NSUInteger>(
                1, std::min<NSUInteger>(
                    pipeline_.maxTotalThreadsPerThreadgroup / width_threads,
                    tile_rows_));
            [compute dispatchThreads:grid
                threadsPerThreadgroup:MTLSizeMake(
                    width_threads, height_threads, 1)];
            [compute endEncoding];
        }
        id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
        [blit copyFromTexture:current sourceSlice:0 sourceLevel:0
            sourceOrigin:MTLOriginMake(0, 0, 0)
            sourceSize:MTLSizeMake(width, height, 1)
            toTexture:analysis_previous_texture_ destinationSlice:0 destinationLevel:0
            destinationOrigin:MTLOriginMake(0, 0, 0)];
        [blit copyFromTexture:current sourceSlice:0 sourceLevel:0
            sourceOrigin:MTLOriginMake(0, 0, 0)
            sourceSize:MTLSizeMake(width, height, 1)
            toTexture:latest_source_texture_ destinationSlice:0 destinationLevel:0
            destinationOrigin:MTLOriginMake(0, 0, 0)];
        [blit endEncoding];
        [command commit];
        [command waitUntilCompleted];
        const auto command_error = command.error;
        CFRelease(metal_reference);
        if (command.status == MTLCommandBufferStatusError) {
            const std::string reason = command_error == nil
                ? "Metal dirty analysis failed"
                : command_error.localizedDescription.UTF8String;
            throw std::runtime_error(reason);
        }

        std::vector<std::uint8_t> base_dirty(tile_count_, 1);
        const auto baseline = !std::exchange(has_previous_, true);
        if (!baseline) {
            const auto* result = static_cast<const std::uint32_t*>(
                result_buffer_.contents);
            for (std::size_t i = 0; i < tile_count_; ++i) {
                base_dirty[i] = result[i] == 0 ? 0 : 1;
            }
        }
        const auto finished = std::chrono::steady_clock::now();
        const auto content_changed = baseline || std::ranges::any_of(
            base_dirty, [](const std::uint8_t value) { return value != 0; });
        latest_frame_id_ = frame_id;
        latest_captured_at_us_ = captured_at_us;
        if (content_changed) {
            latest_content_frame_id_ = frame_id;
            latest_updated_at_us_ = host_timestamp_us();
        }
        return MacosDirtyAnalysisResult{
            .frame_id = frame_id,
            .analyzer_us = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    finished - started).count()),
            .baseline_frame = baseline,
            .tile_16 = aggregate_dirty_tiles(
                base_dirty, tile_columns_, tile_rows_, 16),
            .tile_32 = aggregate_dirty_tiles(
                base_dirty, tile_columns_, tile_rows_, 32),
            .tile_64 = aggregate_dirty_tiles(
                base_dirty, tile_columns_, tile_rows_, 64),
        };
    }

    std::optional<MacosExactBaseState> latest_source_state() const {
        std::lock_guard lock(mutex_);
        if (!has_previous_ || latest_frame_id_ == 0) return std::nullopt;
        return MacosExactBaseState{
            .frame_id = latest_frame_id_,
            .content_frame_id = latest_content_frame_id_,
            .captured_at_us = latest_captured_at_us_,
            .updated_at_us = latest_updated_at_us_,
            .width = width_,
            .height = height_,
        };
    }

    std::optional<MacosExactBaseState> canonical_exact_state() const {
        std::lock_guard lock(mutex_);
        if (!has_canonical_exact_ || canonical_frame_id_ == 0) {
            return std::nullopt;
        }
        return MacosExactBaseState{
            .frame_id = canonical_frame_id_,
            .content_frame_id = canonical_content_frame_id_,
            .captured_at_us = canonical_captured_at_us_,
            .updated_at_us = canonical_updated_at_us_,
            .width = width_,
            .height = height_,
        };
    }

    MacosExactSnapshot snapshot_latest_source() {
        std::lock_guard lock(mutex_);
        if (!has_previous_ || latest_source_texture_ == nil ||
            pending_target_texture_ == nil || snapshot_staging_ == nil ||
            latest_frame_id_ == 0 || pending_target_frame_id_ != 0) {
            throw std::logic_error("persistent Metal latest source is unavailable");
        }
        const auto started = host_timestamp_us();
        id<MTLCommandBuffer> command = [queue_ commandBuffer];
        if (command == nil) {
            throw std::runtime_error("Metal snapshot command buffer creation failed");
        }
        id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
        [blit copyFromTexture:latest_source_texture_
            sourceSlice:0 sourceLevel:0
            sourceOrigin:MTLOriginMake(0, 0, 0)
            sourceSize:MTLSizeMake(width_, height_, 1)
            toBuffer:snapshot_staging_ destinationOffset:0
            destinationBytesPerRow:snapshot_staging_stride_
            destinationBytesPerImage:snapshot_staging_stride_ * height_];
        [blit copyFromTexture:latest_source_texture_
            sourceSlice:0 sourceLevel:0
            sourceOrigin:MTLOriginMake(0, 0, 0)
            sourceSize:MTLSizeMake(width_, height_, 1)
            toTexture:pending_target_texture_ destinationSlice:0 destinationLevel:0
            destinationOrigin:MTLOriginMake(0, 0, 0)];
        [blit endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            const std::string reason = command.error == nil
                ? "Metal exact snapshot readback failed"
                : command.error.localizedDescription.UTF8String;
            throw std::runtime_error(reason);
        }
        const auto packed_stride = static_cast<std::size_t>(width_) * 4U;
        MacosExactSnapshot result{
            .frame_id = latest_frame_id_,
            .content_frame_id = latest_content_frame_id_,
            .captured_at_us = latest_captured_at_us_,
            .source_updated_at_us = latest_updated_at_us_,
            .readback_us = host_timestamp_us() - started,
            .width = width_,
            .height = height_,
            .row_stride = static_cast<std::uint32_t>(packed_stride),
            .bgra = std::vector<std::byte>(packed_stride * height_),
        };
        const auto* source = static_cast<const std::byte*>(
            snapshot_staging_.contents);
        for (std::uint32_t row = 0; row < height_; ++row) {
            std::copy_n(
                source + static_cast<std::size_t>(row) * snapshot_staging_stride_,
                packed_stride,
                result.bgra.data() + static_cast<std::size_t>(row) * packed_stride);
        }
        pending_target_frame_id_ = latest_frame_id_;
        pending_target_content_frame_id_ = latest_content_frame_id_;
        pending_target_captured_at_us_ = latest_captured_at_us_;
        return result;
    }

    MacosExactRectCandidate evaluate_latest_rect(
        const std::uint64_t base_frame_id,
        const std::uint32_t maximum_dirty_ratio_ppm,
        const std::uint32_t maximum_rectangles,
        const std::size_t maximum_packed_bytes,
        const bool reserve_target) {
        std::lock_guard lock(mutex_);
        MacosExactRectCandidate result{
            .base_frame_id = base_frame_id,
            .target_frame_id = latest_frame_id_,
            .content_frame_id = latest_content_frame_id_,
            .captured_at_us = latest_captured_at_us_,
        };
        if (!has_canonical_exact_ || canonical_frame_id_ != base_frame_id ||
            latest_frame_id_ <= base_frame_id || latest_source_texture_ == nil ||
            canonical_exact_texture_ == nil ||
            (reserve_target && pending_target_frame_id_ != 0)) {
            return result;
        }
        const auto compare_started = host_timestamp_us();
        id<MTLCommandBuffer> command = [queue_ commandBuffer];
        if (command == nil) {
            throw std::runtime_error("Metal rect comparison command creation failed");
        }
        id<MTLComputeCommandEncoder> compute = [command computeCommandEncoder];
        [compute setComputePipelineState:pipeline_];
        [compute setTexture:latest_source_texture_ atIndex:0];
        [compute setTexture:canonical_exact_texture_ atIndex:1];
        [compute setBuffer:result_buffer_ offset:0 atIndex:0];
        const MTLSize grid = MTLSizeMake(tile_columns_, tile_rows_, 1);
        const auto width_threads = std::min<NSUInteger>(
            pipeline_.threadExecutionWidth, tile_columns_);
        const auto height_threads = std::max<NSUInteger>(
            1, std::min<NSUInteger>(
                pipeline_.maxTotalThreadsPerThreadgroup / width_threads,
                tile_rows_));
        [compute dispatchThreads:grid
            threadsPerThreadgroup:MTLSizeMake(width_threads, height_threads, 1)];
        [compute endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            const std::string reason = command.error == nil
                ? "Metal exact rectangle comparison failed"
                : command.error.localizedDescription.UTF8String;
            throw std::runtime_error(reason);
        }
        result.compare_us = host_timestamp_us() - compare_started;
        std::vector<std::uint8_t> dirty(tile_count_, 0);
        const auto* comparison = static_cast<const std::uint32_t*>(
            result_buffer_.contents);
        for (std::size_t index = 0; index < tile_count_; ++index) {
            if (comparison[index] != 0) {
                dirty[index] = 1;
                ++result.dirty_tiles;
            }
        }
        result.dirty_ratio_ppm = tile_count_ == 0
            ? 0U
            : static_cast<std::uint32_t>(
                static_cast<std::uint64_t>(result.dirty_tiles) * 1'000'000U /
                tile_count_);
        if (result.dirty_tiles == 0) {
            result.decision = MacosExactRectDecision::unchanged;
            return result;
        }
        if (result.dirty_ratio_ppm > maximum_dirty_ratio_ppm) {
            result.decision = MacosExactRectDecision::ratio_exceeded;
            return result;
        }
        const auto merged = merge_dirty_rectangles(
            dirty, tile_columns_, tile_rows_, width_, height_);
        result.merged_rectangles = static_cast<std::uint32_t>(merged.size());
        if (merged.empty() || merged.size() > maximum_rectangles) {
            result.decision = MacosExactRectDecision::rectangle_count_exceeded;
            return result;
        }
        for (const auto& rectangle : merged) {
            const auto bytes = static_cast<std::size_t>(rectangle.width) *
                rectangle.height * 4U;
            if (bytes > maximum_packed_bytes - result.packed_bytes) {
                result.decision = MacosExactRectDecision::byte_limit_exceeded;
                return result;
            }
            result.packed_bytes += bytes;
        }
        result.decision = MacosExactRectDecision::selected;
        if (!reserve_target) return result;

        const auto readback_started = host_timestamp_us();
        command = [queue_ commandBuffer];
        if (command == nil) {
            throw std::runtime_error("Metal rect readback command creation failed");
        }
        id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
        std::size_t staging_offset{};
        struct StagingRect {
            DirtyPixelRect rectangle;
            std::size_t offset{};
            std::size_t stride{};
        };
        std::vector<StagingRect> staging;
        staging.reserve(merged.size());
        for (const auto& rectangle : merged) {
            const auto packed_stride = static_cast<std::size_t>(rectangle.width) * 4U;
            const auto staging_stride = (packed_stride + 255U) & ~255U;
            staging_offset = (staging_offset + 255U) & ~255U;
            const auto staging_bytes = staging_stride * rectangle.height;
            if (staging_bytes > snapshot_staging_length_ - staging_offset) {
                result.decision = MacosExactRectDecision::byte_limit_exceeded;
                [blit endEncoding];
                return result;
            }
            [blit copyFromTexture:latest_source_texture_
                sourceSlice:0 sourceLevel:0
                sourceOrigin:MTLOriginMake(rectangle.x, rectangle.y, 0)
                sourceSize:MTLSizeMake(rectangle.width, rectangle.height, 1)
                toBuffer:snapshot_staging_ destinationOffset:staging_offset
                destinationBytesPerRow:staging_stride
                destinationBytesPerImage:staging_bytes];
            staging.push_back({
                .rectangle = rectangle,
                .offset = staging_offset,
                .stride = staging_stride,
            });
            staging_offset += staging_bytes;
        }
        [blit copyFromTexture:latest_source_texture_
            sourceSlice:0 sourceLevel:0
            sourceOrigin:MTLOriginMake(0, 0, 0)
            sourceSize:MTLSizeMake(width_, height_, 1)
            toTexture:pending_target_texture_ destinationSlice:0 destinationLevel:0
            destinationOrigin:MTLOriginMake(0, 0, 0)];
        [blit endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            const std::string reason = command.error == nil
                ? "Metal exact rectangle readback failed"
                : command.error.localizedDescription.UTF8String;
            throw std::runtime_error(reason);
        }
        result.readback_us = host_timestamp_us() - readback_started;
        const auto* source = static_cast<const std::byte*>(
            snapshot_staging_.contents);
        result.rectangles.reserve(staging.size());
        for (const auto& item : staging) {
            const auto packed_stride = item.rectangle.width * 4U;
            desktop::VisualRawRect rectangle{
                .base_frame_id = base_frame_id,
                .surface_width = width_,
                .surface_height = height_,
                .x = item.rectangle.x,
                .y = item.rectangle.y,
                .width = item.rectangle.width,
                .height = item.rectangle.height,
                .row_stride = packed_stride,
                .pixel_format = desktop::CanonicalPixelFormat::
                    bgra8_premultiplied_srgb,
                .bgra = std::vector<std::byte>(
                    static_cast<std::size_t>(packed_stride) *
                    item.rectangle.height),
            };
            for (std::uint32_t row = 0; row < item.rectangle.height; ++row) {
                std::copy_n(
                    source + item.offset + static_cast<std::size_t>(row) *
                        item.stride,
                    packed_stride,
                    rectangle.bgra.data() + static_cast<std::size_t>(row) *
                        packed_stride);
            }
            result.rectangles.push_back(std::move(rectangle));
        }
        pending_target_frame_id_ = latest_frame_id_;
        pending_target_content_frame_id_ = latest_content_frame_id_;
        pending_target_captured_at_us_ = latest_captured_at_us_;
        return result;
    }

    bool promote_pending_exact(const std::uint64_t frame_id) {
        std::lock_guard lock(mutex_);
        if (frame_id == 0 || pending_target_frame_id_ != frame_id) return false;
        std::swap(canonical_exact_texture_, pending_target_texture_);
        canonical_frame_id_ = pending_target_frame_id_;
        canonical_content_frame_id_ = pending_target_content_frame_id_;
        canonical_captured_at_us_ = pending_target_captured_at_us_;
        canonical_updated_at_us_ = host_timestamp_us();
        has_canonical_exact_ = true;
        pending_target_frame_id_ = 0;
        pending_target_content_frame_id_ = 0;
        pending_target_captured_at_us_ = 0;
        return true;
    }

    void cancel_pending_exact() noexcept {
        std::lock_guard lock(mutex_);
        pending_target_frame_id_ = 0;
        pending_target_content_frame_id_ = 0;
        pending_target_captured_at_us_ = 0;
    }

    void invalidate_exact_base() noexcept {
        std::lock_guard lock(mutex_);
        has_canonical_exact_ = false;
        canonical_frame_id_ = 0;
        canonical_content_frame_id_ = 0;
        canonical_captured_at_us_ = 0;
        canonical_updated_at_us_ = 0;
        pending_target_frame_id_ = 0;
        pending_target_content_frame_id_ = 0;
        pending_target_captured_at_us_ = 0;
    }

private:
    void ensure_resources(
        const std::uint32_t width,
        const std::uint32_t height) {
        if (width_ == width && height_ == height) return;
        [result_buffer_ release];
        result_buffer_ = nil;
        [analysis_previous_texture_ release];
        analysis_previous_texture_ = nil;
        [latest_source_texture_ release];
        latest_source_texture_ = nil;
        [canonical_exact_texture_ release];
        canonical_exact_texture_ = nil;
        [pending_target_texture_ release];
        pending_target_texture_ = nil;
        [snapshot_staging_ release];
        snapshot_staging_ = nil;
        width_ = width;
        height_ = height;
        tile_columns_ = (width + 15U) / 16U;
        tile_rows_ = (height + 15U) / 16U;
        tile_count_ = static_cast<std::size_t>(tile_columns_) * tile_rows_;
        result_buffer_ = [device_ newBufferWithLength:
            tile_count_ * sizeof(std::uint32_t)
            options:MTLResourceStorageModeShared];
        MTLTextureDescriptor* descriptor = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
            width:width height:height mipmapped:NO];
        descriptor.storageMode = MTLStorageModePrivate;
        descriptor.usage = MTLTextureUsageShaderRead;
        analysis_previous_texture_ =
            [device_ newTextureWithDescriptor:descriptor];
        latest_source_texture_ = [device_ newTextureWithDescriptor:descriptor];
        canonical_exact_texture_ = [device_ newTextureWithDescriptor:descriptor];
        pending_target_texture_ = [device_ newTextureWithDescriptor:descriptor];
        snapshot_staging_stride_ =
            (static_cast<std::size_t>(width) * 4U + 255U) & ~255U;
        snapshot_staging_length_ = snapshot_staging_stride_ * height;
        snapshot_staging_ = [device_ newBufferWithLength:snapshot_staging_length_
            options:MTLResourceStorageModeShared];
        if (result_buffer_ == nil || analysis_previous_texture_ == nil ||
            latest_source_texture_ == nil || canonical_exact_texture_ == nil ||
            pending_target_texture_ == nil || snapshot_staging_ == nil) {
            throw std::runtime_error("Metal dirty analyzer resource allocation failed");
        }
        has_previous_ = false;
        has_canonical_exact_ = false;
        latest_frame_id_ = 0;
        latest_content_frame_id_ = 0;
        latest_captured_at_us_ = 0;
        latest_updated_at_us_ = 0;
        canonical_frame_id_ = 0;
        canonical_content_frame_id_ = 0;
        canonical_captured_at_us_ = 0;
        canonical_updated_at_us_ = 0;
        pending_target_frame_id_ = 0;
        pending_target_content_frame_id_ = 0;
        pending_target_captured_at_us_ = 0;
    }

    id<MTLDevice> device_{};
    id<MTLCommandQueue> queue_{};
    id<MTLComputePipelineState> pipeline_{};
    id<MTLBuffer> result_buffer_{};
    id<MTLTexture> analysis_previous_texture_{};
    id<MTLTexture> latest_source_texture_{};
    id<MTLTexture> canonical_exact_texture_{};
    id<MTLTexture> pending_target_texture_{};
    id<MTLBuffer> snapshot_staging_{};
    CVMetalTextureCacheRef texture_cache_{};
    std::uint32_t width_{};
    std::uint32_t height_{};
    std::uint32_t tile_columns_{};
    std::uint32_t tile_rows_{};
    std::size_t tile_count_{};
    std::size_t snapshot_staging_stride_{};
    std::size_t snapshot_staging_length_{};
    bool has_previous_{};
    bool has_canonical_exact_{};
    std::uint64_t latest_frame_id_{};
    std::uint64_t latest_content_frame_id_{};
    std::uint64_t latest_captured_at_us_{};
    std::uint64_t latest_updated_at_us_{};
    std::uint64_t canonical_frame_id_{};
    std::uint64_t canonical_content_frame_id_{};
    std::uint64_t canonical_captured_at_us_{};
    std::uint64_t canonical_updated_at_us_{};
    std::uint64_t pending_target_frame_id_{};
    std::uint64_t pending_target_content_frame_id_{};
    std::uint64_t pending_target_captured_at_us_{};
    mutable std::mutex mutex_;
};

class MacosVideoToolboxEncoder::Impl {
public:
    explicit Impl(const MacosVideoToolboxMode mode) : mode_(mode) {}

    ~Impl() {
        {
            std::lock_guard lock(mutex_);
            shutting_down_ = true;
        }
        condition_.notify_all();
        if (session_ != nullptr) {
            static_cast<void>(
                VTCompressionSessionCompleteFrames(session_, kCMTimeInvalid));
            VTCompressionSessionInvalidate(session_);
            CFRelease(session_);
        }
    }

    desktop::VideoFrame encode(
        const desktop::RawFrame& frame,
        const desktop::VideoSettings& settings,
        const bool force_keyframe) {
        if (frame.width == 0 || frame.height == 0 || frame.row_stride < frame.width * 4U ||
            frame.bgra.size() < static_cast<std::size_t>(frame.row_stride) * frame.height) {
            throw std::invalid_argument("invalid BGRA frame for VideoToolbox");
        }
        ensure_session(frame.width, frame.height, settings);
        CVPixelBufferRef pixel_buffer{};
        require_status(
            CVPixelBufferCreate(
                kCFAllocatorDefault, frame.width, frame.height,
                kCVPixelFormatType_32BGRA, nullptr, &pixel_buffer),
            "create VideoToolbox pixel buffer");
        require_status(CVPixelBufferLockBaseAddress(pixel_buffer, 0),
                       "lock VideoToolbox pixel buffer");
        auto* destination = static_cast<std::byte*>(
            CVPixelBufferGetBaseAddress(pixel_buffer));
        const auto destination_stride = CVPixelBufferGetBytesPerRow(pixel_buffer);
        const auto row_size = static_cast<std::size_t>(frame.width) * 4U;
        for (std::uint32_t row = 0; row < frame.height; ++row) {
            std::copy_n(
                frame.bgra.data() + static_cast<std::size_t>(frame.row_stride) * row,
                row_size, destination + destination_stride * row);
        }
        CVPixelBufferUnlockBaseAddress(pixel_buffer, 0);
        submit_pixel_buffer(
            pixel_buffer, frame.frame_id, frame.captured_at_us,
            frame.width, frame.height, settings, force_keyframe,
            1U);
        CVPixelBufferRelease(pixel_buffer);
        auto encoded = next_encoded(std::chrono::seconds{5});
        if (!encoded) {
            throw std::runtime_error("VideoToolbox output callback timed out");
        }
        return std::move(*encoded);
    }

    void submit_pixel_buffer(
        CVPixelBufferRef pixel_buffer,
        const std::uint64_t frame_id,
        const std::uint64_t captured_at_us,
        const std::uint32_t width,
        const std::uint32_t height,
        const desktop::VideoSettings& settings,
        const bool force_keyframe,
        const std::uint64_t representation_epoch) {
        if (pixel_buffer == nullptr || width == 0 || height == 0 ||
            representation_epoch == 0) {
            throw std::invalid_argument("invalid ScreenCaptureKit pixel buffer");
        }
        if (CVPixelBufferGetPixelFormatType(pixel_buffer) !=
            kCVPixelFormatType_32BGRA) {
            throw std::runtime_error(
                "direct VideoToolbox submission requires ScreenCaptureKit BGRA");
        }
        CVBufferSetAttachment(
            pixel_buffer, kCVImageBufferColorPrimariesKey,
            kCVImageBufferColorPrimaries_ITU_R_709_2,
            kCVAttachmentMode_ShouldPropagate);
        CVBufferSetAttachment(
            pixel_buffer, kCVImageBufferTransferFunctionKey,
            kCVImageBufferTransferFunction_ITU_R_709_2,
            kCVAttachmentMode_ShouldPropagate);
        CVBufferSetAttachment(
            pixel_buffer, kCVImageBufferYCbCrMatrixKey,
            kCVImageBufferYCbCrMatrix_ITU_R_709_2,
            kCVAttachmentMode_ShouldPropagate);
        ensure_session(width, height, settings);
        const auto submitted_at_us = host_timestamp_us();
        auto* context = new SubmissionContext{
            .owner = this,
            .frame_id = frame_id,
            .representation_epoch = representation_epoch,
            .captured_at_us = captured_at_us,
            .submitted_at_us = submitted_at_us,
            .width = width,
            .height = height,
        };
        {
            std::unique_lock lock(mutex_);
            condition_.wait(lock, [&] {
                return shutting_down_ ||
                    in_flight_current_ + encoded_queue_.size() <
                        encoded_queue_capacity;
            });
            if (shutting_down_) {
                delete context;
                throw std::runtime_error("VideoToolbox encoder is shutting down");
            }
            if (representation_epoch < minimum_epoch_) {
                delete context;
                throw std::logic_error("obsolete VideoToolbox submission epoch");
            }
            ++submitted_frames_;
            ++in_flight_current_;
            in_flight_max_ = std::max(in_flight_max_, in_flight_current_);
        }
        CFDictionaryRef frame_properties = nullptr;
        if (force_keyframe) {
            const void* keys[] = {kVTEncodeFrameOptionKey_ForceKeyFrame};
            const void* values[] = {kCFBooleanTrue};
            frame_properties = CFDictionaryCreate(
                kCFAllocatorDefault, keys, values, 1,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks);
        }
        const auto presentation = CMTimeMake(
            static_cast<std::int64_t>(captured_at_us), 1000000);
        const auto duration = CMTimeMake(
            1, static_cast<std::int32_t>(settings.frames_per_second));
        const auto status = VTCompressionSessionEncodeFrame(
            session_, pixel_buffer, presentation, duration,
            frame_properties, context, nullptr);
        if (frame_properties != nullptr) CFRelease(frame_properties);
        if (status != noErr) {
            {
                std::lock_guard lock(mutex_);
                --in_flight_current_;
            }
            condition_.notify_all();
            delete context;
            require_status(status, "submit H.264 frame");
        }
    }

    std::optional<desktop::VideoFrame> next_encoded(
        const std::chrono::milliseconds timeout) {
        if (timeout < std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("encoded output timeout must be non-negative");
        }
        std::unique_lock lock(mutex_);
        if (!condition_.wait_for(lock, timeout, [&] {
                return !encoded_queue_.empty() || !async_error_.empty() ||
                    shutting_down_;
            })) {
            return std::nullopt;
        }
        if (!async_error_.empty()) {
            const auto error = std::exchange(async_error_, {});
            throw std::runtime_error(error);
        }
        if (encoded_queue_.empty()) return std::nullopt;
        auto frame = std::move(encoded_queue_.front());
        encoded_queue_.pop_front();
        if (!encoded_timings_.empty()) {
            last_timing_ = encoded_timings_.front();
            encoded_timings_.pop_front();
        }
        lock.unlock();
        condition_.notify_all();
        return frame;
    }

    void stop_submissions() {
        {
            std::lock_guard lock(mutex_);
            shutting_down_ = true;
        }
        condition_.notify_all();
    }

    MacosEncoderQueueStats queue_stats() const {
        std::lock_guard lock(mutex_);
        return {
            .submitted_frames = submitted_frames_,
            .completed_frames = completed_frames_,
            .in_flight_current = in_flight_current_,
            .in_flight_max = in_flight_max_,
            .encoded_queue_current = encoded_queue_.size(),
            .encoded_queue_max = encoded_queue_max_,
            .encoded_queue_overruns = encoded_queue_overruns_,
            .stale_epoch_drops = stale_epoch_drops_,
        };
    }

    bool has_submission_capacity() const {
        std::lock_guard lock(mutex_);
        return !shutting_down_ &&
            in_flight_current_ + encoded_queue_.size() <
                encoded_queue_capacity;
    }

    void discard_before_epoch(const std::uint64_t epoch) {
        if (epoch == 0) {
            throw std::invalid_argument("VideoToolbox epoch is zero");
        }
        std::lock_guard lock(mutex_);
        if (epoch < minimum_epoch_) {
            throw std::invalid_argument("VideoToolbox epoch moved backwards");
        }
        minimum_epoch_ = epoch;
        while (!encoded_queue_.empty() &&
               encoded_queue_.front().representation_epoch < epoch) {
            encoded_queue_.pop_front();
            if (!encoded_timings_.empty()) encoded_timings_.pop_front();
            ++stale_epoch_drops_;
        }
        condition_.notify_all();
    }

private:
    struct SubmissionContext {
        Impl* owner{};
        std::uint64_t frame_id{};
        std::uint64_t representation_epoch{};
        std::uint64_t captured_at_us{};
        std::uint64_t submitted_at_us{};
        std::uint32_t width{};
        std::uint32_t height{};
    };

    static void output_callback(
        void*, void* source_frame_ref_con, OSStatus status,
        VTEncodeInfoFlags, CMSampleBufferRef sample_buffer) {
        std::unique_ptr<SubmissionContext> context(
            static_cast<SubmissionContext*>(source_frame_ref_con));
        if (!context || context->owner == nullptr) return;
        auto& self = *context->owner;
        const auto callback_at_us = host_timestamp_us();
        std::vector<std::byte> encoded;
        bool keyframe{};
        OSStatus callback_status = status;
        if (status != noErr || sample_buffer == nullptr ||
            !CMSampleBufferDataIsReady(sample_buffer)) {
            if (callback_status == noErr) callback_status = paramErr;
        } else {
            const auto attachments = CMSampleBufferGetSampleAttachmentsArray(
                sample_buffer, false);
            keyframe = attachments == nullptr ||
                !CFDictionaryContainsKey(
                    static_cast<CFDictionaryRef>(
                        CFArrayGetValueAtIndex(attachments, 0)),
                    kCMSampleAttachmentKey_NotSync);
            callback_status = append_annex_b(sample_buffer, keyframe, encoded);
        }
        {
            std::lock_guard lock(self.mutex_);
            if (self.in_flight_current_ > 0) --self.in_flight_current_;
            ++self.completed_frames_;
            const MacosEncodeTiming timing{
                .frame_id = context->frame_id,
                .representation_epoch = context->representation_epoch,
                .submitted_at_us = context->submitted_at_us,
                .callback_at_us = callback_at_us,
                .submit_to_callback_us = callback_at_us >= context->submitted_at_us
                    ? callback_at_us - context->submitted_at_us
                    : 0U,
                .hardware_active = self.hardware_active_,
                .hardware_query_status = self.hardware_query_status_,
                .max_frame_delay_status = self.max_frame_delay_status_,
                .mode = self.mode_,
            };
            self.last_timing_ = timing;
            if (context->representation_epoch < self.minimum_epoch_) {
                ++self.stale_epoch_drops_;
            } else if (callback_status != noErr || encoded.empty()) {
                self.async_error_ =
                    "VideoToolbox output callback failed with OSStatus " +
                    std::to_string(callback_status);
            } else if (self.encoded_queue_.size() >= encoded_queue_capacity) {
                ++self.encoded_queue_overruns_;
                self.async_error_ = "bounded H.264 output queue overrun";
            } else {
                self.encoded_queue_.push_back({
                    .frame_id = context->frame_id,
                    .representation_epoch = context->representation_epoch,
                    .captured_at_us = context->captured_at_us,
                    .width = context->width,
                    .height = context->height,
                    .codec = desktop::VideoCodec::h264,
                    .keyframe = keyframe,
                    .encoded = std::move(encoded),
                });
                self.encoded_timings_.push_back(timing);
                self.encoded_queue_max_ = std::max(
                    self.encoded_queue_max_, self.encoded_queue_.size());
            }
        }
        self.condition_.notify_all();
    }

    static OSStatus append_annex_b(
        CMSampleBufferRef sample_buffer,
        const bool keyframe,
        std::vector<std::byte>& encoded) {
        int nal_header_length{4};
        if (keyframe) {
            auto description = static_cast<CMVideoFormatDescriptionRef>(
                CMSampleBufferGetFormatDescription(sample_buffer));
            std::size_t parameter_count{};
            const uint8_t* ignored_parameter{};
            std::size_t ignored_size{};
            auto status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                description, 0, &ignored_parameter, &ignored_size,
                &parameter_count, &nal_header_length);
            if (status != noErr) return status;
            for (std::size_t index = 0; index < parameter_count; ++index) {
                const uint8_t* parameter{};
                std::size_t parameter_size{};
                status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                    description, index, &parameter, &parameter_size,
                    nullptr, nullptr);
                if (status != noErr) return status;
                if (parameter == nullptr || parameter_size == 0) return paramErr;
                encoded.insert(
                    encoded.end(),
                    {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}});
                encoded.insert(
                    encoded.end(),
                    reinterpret_cast<const std::byte*>(parameter),
                    reinterpret_cast<const std::byte*>(parameter + parameter_size));
            }
        }
        if (nal_header_length <= 0 || nal_header_length > 4) {
            return paramErr;
        }
        const auto nal_header_size =
            static_cast<std::size_t>(nal_header_length);
        auto block = CMSampleBufferGetDataBuffer(sample_buffer);
        if (block == nullptr) return paramErr;
        const auto length = CMBlockBufferGetDataLength(block);
        std::vector<std::byte> avcc(length);
        const auto copy_status =
            CMBlockBufferCopyDataBytes(block, 0, length, avcc.data());
        if (copy_status != noErr) return copy_status;
        std::size_t offset{};
        while (offset < avcc.size()) {
            if (avcc.size() - offset < nal_header_size) {
                return paramErr;
            }
            std::size_t nal_size{};
            for (std::size_t index = 0; index < nal_header_size; ++index) {
                nal_size = (nal_size << 8U) |
                    std::to_integer<std::uint8_t>(avcc[offset + index]);
            }
            offset += nal_header_size;
            if (nal_size == 0 || nal_size > avcc.size() - offset) {
                return paramErr;
            }
            encoded.insert(
                encoded.end(),
                {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}});
            encoded.insert(
                encoded.end(),
                avcc.begin() + static_cast<std::ptrdiff_t>(offset),
                avcc.begin() +
                    static_cast<std::ptrdiff_t>(offset + nal_size));
            offset += nal_size;
        }
        return noErr;
    }

    void ensure_session(
        const std::uint32_t width, const std::uint32_t height,
        const desktop::VideoSettings& settings) {
        if (session_ != nullptr && width_ == width && height_ == height) {
            return;
        }
        if (session_ != nullptr) {
            require_status(
                VTCompressionSessionCompleteFrames(session_, kCMTimeInvalid),
                "drain H.264 encoder before reconfiguration");
            VTCompressionSessionInvalidate(session_);
            CFRelease(session_);
            session_ = nullptr;
        }
        auto specification = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 2,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(
            specification,
            kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder,
            kCFBooleanTrue);
        if (mode_ == MacosVideoToolboxMode::low_latency_rate_control) {
            CFDictionarySetValue(
                specification,
                kVTVideoEncoderSpecification_EnableLowLatencyRateControl,
                kCFBooleanTrue);
        }
        const auto create_status = VTCompressionSessionCreate(
            kCFAllocatorDefault, static_cast<std::int32_t>(width),
            static_cast<std::int32_t>(height), kCMVideoCodecType_H264,
            specification, nullptr, nullptr, output_callback, this, &session_);
        CFRelease(specification);
        require_status(create_status, "create hardware H.264 encoder");
        require_status(VTSessionSetProperty(
            session_, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue),
            "enable real-time H.264");
        require_status(VTSessionSetProperty(
            session_, kVTCompressionPropertyKey_AllowFrameReordering,
            kCFBooleanFalse), "disable H.264 B-frames");
        require_status(VTSessionSetProperty(
            session_, kVTCompressionPropertyKey_ProfileLevel,
            mode_ == MacosVideoToolboxMode::low_latency_rate_control
                ? kVTProfileLevel_H264_High_AutoLevel
                : kVTProfileLevel_H264_Main_AutoLevel),
            "set H.264 profile");
        max_frame_delay_status_ = 0;
        if (mode_ == MacosVideoToolboxMode::max_frame_delay_1 ||
            mode_ == MacosVideoToolboxMode::max_frame_delay_0) {
            const std::int32_t maximum_frame_delay =
                mode_ == MacosVideoToolboxMode::max_frame_delay_1 ? 1 : 0;
            auto maximum_frame_delay_number = CFNumberCreate(
                kCFAllocatorDefault, kCFNumberSInt32Type,
                &maximum_frame_delay);
            max_frame_delay_status_ = VTSessionSetProperty(
                session_, kVTCompressionPropertyKey_MaxFrameDelayCount,
                maximum_frame_delay_number);
            CFRelease(maximum_frame_delay_number);
        }
        const auto expected_frame_rate = static_cast<std::int32_t>(
            settings.frames_per_second);
        auto expected_frame_rate_number = CFNumberCreate(
            kCFAllocatorDefault, kCFNumberSInt32Type,
            &expected_frame_rate);
        require_status(VTSessionSetProperty(
            session_, kVTCompressionPropertyKey_ExpectedFrameRate,
            expected_frame_rate_number), "set expected H.264 frame rate");
        CFRelease(expected_frame_rate_number);
        const auto bitrate = static_cast<std::int32_t>(settings.bitrate_kbps * 1000U);
        auto bitrate_number = CFNumberCreate(
            kCFAllocatorDefault, kCFNumberSInt32Type, &bitrate);
        VTSessionSetProperty(
            session_, kVTCompressionPropertyKey_AverageBitRate, bitrate_number);
        CFRelease(bitrate_number);
        const auto interval = static_cast<std::int32_t>(settings.keyframe_interval);
        auto interval_number = CFNumberCreate(
            kCFAllocatorDefault, kCFNumberSInt32Type, &interval);
        VTSessionSetProperty(
            session_, kVTCompressionPropertyKey_MaxKeyFrameInterval,
            interval_number);
        CFRelease(interval_number);
        require_status(VTCompressionSessionPrepareToEncodeFrames(session_),
                       "prepare H.264 encoder");
        CFTypeRef hardware_property{};
        const auto hardware_status = VTSessionCopyProperty(
            session_, kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder,
            kCFAllocatorDefault, &hardware_property);
        hardware_query_status_ = hardware_status;
        hardware_active_ = false;
        if (hardware_status == noErr && hardware_property != nullptr) {
            if (CFGetTypeID(hardware_property) == CFBooleanGetTypeID()) {
                hardware_active_ = CFBooleanGetValue(
                    static_cast<CFBooleanRef>(hardware_property));
            } else if (CFGetTypeID(hardware_property) == CFNumberGetTypeID()) {
                std::int32_t value{};
                if (CFNumberGetValue(
                        static_cast<CFNumberRef>(hardware_property),
                        kCFNumberSInt32Type, &value)) {
                    hardware_active_ = value != 0;
                }
            }
        }
        if (hardware_property != nullptr) CFRelease(hardware_property);
        width_ = width;
        height_ = height;
    }

    VTCompressionSessionRef session_{};
    std::uint32_t width_{};
    std::uint32_t height_{};
    MacosVideoToolboxMode mode_{MacosVideoToolboxMode::baseline};
    static constexpr std::size_t encoded_queue_capacity{4};
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<desktop::VideoFrame> encoded_queue_;
    std::deque<MacosEncodeTiming> encoded_timings_;
    std::string async_error_;
    bool shutting_down_{};
    std::uint64_t submitted_frames_{};
    std::uint64_t completed_frames_{};
    std::size_t in_flight_current_{};
    std::size_t in_flight_max_{};
    std::size_t encoded_queue_max_{};
    std::uint64_t encoded_queue_overruns_{};
    std::uint64_t stale_epoch_drops_{};
    std::uint64_t minimum_epoch_{1};
    bool hardware_active_{};
    std::int32_t hardware_query_status_{};
    std::int32_t max_frame_delay_status_{};
    std::optional<MacosEncodeTiming> last_timing_;

public:
    std::optional<MacosEncodeTiming> last_timing() const {
        std::lock_guard lock(mutex_);
        return last_timing_;
    }
};

MacosScreenCaptureBackend::MacosScreenCaptureBackend()
    : impl_(std::make_unique<Impl>(0, 0, 60, nullptr)) {}
MacosScreenCaptureBackend::MacosScreenCaptureBackend(
    const std::uint32_t maximum_width,
    const std::uint32_t maximum_height,
    const std::uint32_t frames_per_second)
    : impl_(std::make_unique<Impl>(
          maximum_width, maximum_height, frames_per_second, nullptr)) {
    if (maximum_width < 320 || maximum_width > desktop::maximum_preview_width ||
        maximum_height < 180 || maximum_height > desktop::maximum_preview_height ||
        frames_per_second == 0 || frames_per_second > 60) {
        throw std::invalid_argument("invalid ScreenCaptureKit stream limits");
    }
}
MacosScreenCaptureBackend::MacosScreenCaptureBackend(
    const std::uint32_t maximum_width,
    const std::uint32_t maximum_height,
    const std::uint32_t frames_per_second,
    desktop::VisualLifecycleTracker* lifecycle_tracker,
    const bool shows_cursor,
    const bool analyze_from_start)
    : impl_(std::make_unique<Impl>(
          maximum_width, maximum_height, frames_per_second,
          lifecycle_tracker, shows_cursor, analyze_from_start)) {
    if (maximum_width < 320 || maximum_width > desktop::maximum_preview_width ||
        maximum_height < 180 || maximum_height > desktop::maximum_preview_height ||
        frames_per_second == 0 || frames_per_second > 60) {
        throw std::invalid_argument("invalid ScreenCaptureKit stream limits");
    }
}
MacosScreenCaptureBackend::~MacosScreenCaptureBackend() = default;
std::optional<desktop::RawFrame> MacosScreenCaptureBackend::capture(
    const std::chrono::milliseconds timeout) {
    return impl_->capture(timeout);
}

bool MacosScreenCaptureBackend::submit_latest(
    MacosVideoToolboxEncoder& encoder,
    const desktop::VideoSettings& settings,
    const bool force_keyframe,
    const std::uint64_t representation_epoch,
    const std::chrono::milliseconds timeout) {
    auto native = impl_->take_latest(timeout);
    if (!native) return false;
    auto buffer = native->pixel_buffer;
    const auto width = static_cast<std::uint32_t>(CVPixelBufferGetWidth(buffer));
    const auto height = static_cast<std::uint32_t>(CVPixelBufferGetHeight(buffer));
    try {
        encoder.impl_->submit_pixel_buffer(
            buffer, native->frame_id, native->captured_at_us,
            width, height, settings, force_keyframe, representation_epoch);
    } catch (...) {
        CVPixelBufferRelease(buffer);
        throw;
    }
    CVPixelBufferRelease(buffer);
    impl_->record_direct_timing(*native);
    return true;
}

bool MacosScreenCaptureBackend::submit_tail_repeat(
    MacosVideoToolboxEncoder& encoder,
    const desktop::VideoSettings& settings,
    const bool force_keyframe,
    const std::uint64_t representation_epoch) {
    auto native = impl_->repeat_last();
    if (!native) return false;
    auto buffer = native->pixel_buffer;
    const auto width = static_cast<std::uint32_t>(CVPixelBufferGetWidth(buffer));
    const auto height = static_cast<std::uint32_t>(CVPixelBufferGetHeight(buffer));
    try {
        encoder.impl_->submit_pixel_buffer(
            buffer, native->frame_id, native->captured_at_us,
            width, height, settings, force_keyframe, representation_epoch);
    } catch (...) {
        CVPixelBufferRelease(buffer);
        throw;
    }
    CVPixelBufferRelease(buffer);
    impl_->record_direct_timing(*native);
    return true;
}

std::optional<MacosCaptureTiming> MacosScreenCaptureBackend::last_timing() const {
    return impl_->last_timing();
}

std::uint64_t MacosScreenCaptureBackend::replaced_frame_count() const {
    return impl_->replaced_frame_count();
}

void MacosScreenCaptureBackend::enable_dirty_analysis(const bool enabled) {
    impl_->enable_dirty_analysis(enabled);
}

std::optional<MacosDirtyAnalysisResult>
MacosScreenCaptureBackend::analyze_latest(
    MacosMetalDirtyTileAnalyzer& analyzer,
    const std::chrono::milliseconds timeout) {
    auto native = impl_->take_analysis_latest(timeout);
    if (!native) return std::nullopt;
    try {
        auto result = analyzer.impl_->analyze(
            native->pixel_buffer, native->frame_id, native->captured_at_us);
        CVPixelBufferRelease(native->pixel_buffer);
        return result;
    } catch (...) {
        CVPixelBufferRelease(native->pixel_buffer);
        throw;
    }
}

std::uint64_t MacosScreenCaptureBackend::replaced_analysis_frame_count() const {
    return impl_->replaced_analysis_frame_count();
}

MacosMetalDirtyTileAnalyzer::MacosMetalDirtyTileAnalyzer()
    : impl_(std::make_unique<Impl>()) {}
MacosMetalDirtyTileAnalyzer::~MacosMetalDirtyTileAnalyzer() = default;
std::optional<MacosExactBaseState>
MacosMetalDirtyTileAnalyzer::latest_source_state() const {
    return impl_->latest_source_state();
}
std::optional<MacosExactBaseState>
MacosMetalDirtyTileAnalyzer::canonical_exact_state() const {
    return impl_->canonical_exact_state();
}
MacosExactSnapshot MacosMetalDirtyTileAnalyzer::snapshot_latest_source() {
    return impl_->snapshot_latest_source();
}
MacosExactRectCandidate MacosMetalDirtyTileAnalyzer::evaluate_latest_rect(
    const std::uint64_t base_frame_id,
    const std::uint32_t maximum_dirty_ratio_ppm,
    const std::uint32_t maximum_rectangles,
    const std::size_t maximum_packed_bytes,
    const bool reserve_target) {
    return impl_->evaluate_latest_rect(
        base_frame_id, maximum_dirty_ratio_ppm, maximum_rectangles,
        maximum_packed_bytes, reserve_target);
}
bool MacosMetalDirtyTileAnalyzer::promote_pending_exact(
    const std::uint64_t frame_id) {
    return impl_->promote_pending_exact(frame_id);
}
void MacosMetalDirtyTileAnalyzer::cancel_pending_exact() noexcept {
    impl_->cancel_pending_exact();
}
void MacosMetalDirtyTileAnalyzer::invalidate_exact_base() noexcept {
    impl_->invalidate_exact_base();
}

MacosVideoToolboxEncoder::MacosVideoToolboxEncoder()
    : impl_(std::make_unique<Impl>(MacosVideoToolboxMode::baseline)) {}
MacosVideoToolboxEncoder::MacosVideoToolboxEncoder(
    const MacosVideoToolboxMode mode)
    : impl_(std::make_unique<Impl>(mode)) {}
MacosVideoToolboxEncoder::~MacosVideoToolboxEncoder() = default;
desktop::VideoFrame MacosVideoToolboxEncoder::encode(
    const desktop::RawFrame& frame,
    const desktop::VideoSettings& settings,
    const bool force_keyframe) {
    return impl_->encode(frame, settings, force_keyframe);
}
std::optional<desktop::VideoFrame> MacosVideoToolboxEncoder::next_encoded(
    const std::chrono::milliseconds timeout) {
    return impl_->next_encoded(timeout);
}
bool MacosVideoToolboxEncoder::has_submission_capacity() const {
    return impl_->has_submission_capacity();
}
void MacosVideoToolboxEncoder::stop_submissions() {
    impl_->stop_submissions();
}
std::optional<MacosEncodeTiming> MacosVideoToolboxEncoder::last_timing() const {
    return impl_->last_timing();
}
MacosEncoderQueueStats MacosVideoToolboxEncoder::queue_stats() const {
    return impl_->queue_stats();
}
void MacosVideoToolboxEncoder::discard_before_epoch(
    const std::uint64_t epoch) {
    impl_->discard_before_epoch(epoch);
}

MacosCursorPositionSampler::MacosCursorPositionSampler(
    const std::uint32_t surface_width,
    const std::uint32_t surface_height)
    : surface_width_(surface_width), surface_height_(surface_height) {
    if (surface_width == 0 || surface_height == 0 ||
        surface_width > desktop::maximum_preview_width ||
        surface_height > desktop::maximum_preview_height) {
        throw std::invalid_argument("invalid cursor sampling surface");
    }
}

desktop::VisualCursorPosition MacosCursorPositionSampler::sample() const {
    auto event = CGEventCreate(nullptr);
    if (event == nullptr) {
        throw std::runtime_error("read macOS cursor position failed");
    }
    const auto location = CGEventGetLocation(event);
    CFRelease(event);
    const auto bounds = CGDisplayBounds(CGMainDisplayID());
    const auto local_x = std::clamp(
        location.x - bounds.origin.x, 0.0,
        std::max(0.0, bounds.size.width - 1.0));
    const auto local_y = std::clamp(
        location.y - bounds.origin.y, 0.0,
        std::max(0.0, bounds.size.height - 1.0));
    return {
        .x = static_cast<std::uint32_t>(
            local_x * surface_width_ / std::max(1.0, bounds.size.width)),
        .y = static_cast<std::uint32_t>(
            local_y * surface_height_ / std::max(1.0, bounds.size.height)),
        .visible = true,
        .shape_id = 1,
    };
}

std::optional<desktop::VisualCursorShape>
MacosCursorPositionSampler::sample_shape() const {
    @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        NSCursor* cursor = [NSCursor currentSystemCursor];
#pragma clang diagnostic pop
        if (cursor == nil || cursor.image == nil) return std::nullopt;
        NSImage* image = cursor.image;
        NSRect proposed{
            .origin = NSZeroPoint,
            .size = image.size,
        };
        CGImageRef cg_image = [image CGImageForProposedRect:&proposed
                                                    context:nil
                                                      hints:nil];
        if (cg_image == nullptr) return std::nullopt;
        const auto width = CGImageGetWidth(cg_image);
        const auto height = CGImageGetHeight(cg_image);
        if (width == 0 || height == 0 || width > 256U || height > 256U ||
            image.size.width <= 0 || image.size.height <= 0) {
            return std::nullopt;
        }
        const auto row_stride = width * 4U;
        std::vector<std::byte> bgra(row_stride * height);
        auto color_space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        if (color_space == nullptr) return std::nullopt;
        auto context = CGBitmapContextCreate(
            bgra.data(), width, height, 8, row_stride, color_space,
            static_cast<CGBitmapInfo>(kCGImageAlphaPremultipliedFirst) |
                static_cast<CGBitmapInfo>(kCGBitmapByteOrder32Little));
        CGColorSpaceRelease(color_space);
        if (context == nullptr) return std::nullopt;
        CGContextDrawImage(
            context,
            CGRectMake(0, 0, static_cast<CGFloat>(width),
                       static_cast<CGFloat>(height)),
            cg_image);
        CGContextRelease(context);
        const auto hotspot = cursor.hotSpot;
        const auto hotspot_x = static_cast<std::uint16_t>(std::clamp(
            hotspot.x * static_cast<double>(width) / image.size.width,
            0.0, static_cast<double>(width - 1U)));
        const auto hotspot_y = static_cast<std::uint16_t>(std::clamp(
            hotspot.y * static_cast<double>(height) / image.size.height,
            0.0, static_cast<double>(height - 1U)));
        std::uint64_t hash = 1469598103934665603ULL;
        auto mix = [&](const std::uint8_t value) {
            hash ^= value;
            hash *= 1099511628211ULL;
        };
        for (const auto value : bgra) {
            mix(std::to_integer<std::uint8_t>(value));
        }
        for (const auto value : {
                 static_cast<std::uint16_t>(width),
                 static_cast<std::uint16_t>(height),
                 hotspot_x, hotspot_y}) {
            mix(static_cast<std::uint8_t>(value >> 8U));
            mix(static_cast<std::uint8_t>(value & 0xffU));
        }
        if (hash == 0) hash = 1;
        return desktop::VisualCursorShape{
            .shape_id = hash,
            .width = static_cast<std::uint16_t>(width),
            .height = static_cast<std::uint16_t>(height),
            .hotspot_x = hotspot_x,
            .hotspot_y = hotspot_y,
            .bgra = std::move(bgra),
        };
    }
}

void MacosInputBackend::raw_key(
    const std::uint32_t hid_usage, const bool pressed) {
    if (hid_usage == 0x65U) {
        pointer_button(2, pressed);
        return;
    }
    auto event = CGEventCreateKeyboardEvent(
        nullptr, hid_usage_to_key_code(hid_usage), pressed);
    if (event == nullptr) throw std::runtime_error("create macOS key event failed");
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
}

void MacosInputBackend::text_commit(const std::string_view utf8) {
    if (!desktop::valid_utf8(utf8) ||
        utf8.size() > desktop::maximum_input_text_size) {
        throw std::invalid_argument("invalid UTF-8 text commit");
    }
    @autoreleasepool {
        NSString* text = [[NSString alloc]
            initWithBytes:utf8.data() length:utf8.size()
            encoding:NSUTF8StringEncoding];
        if (text == nil) throw std::invalid_argument("invalid UTF-8 text commit");
        std::vector<UniChar> characters(text.length);
        [text getCharacters:characters.data()
                      range:NSMakeRange(0, text.length)];
        auto event = CGEventCreateKeyboardEvent(nullptr, 0, true);
        CGEventKeyboardSetUnicodeString(
            event, characters.size(), characters.data());
        CGEventPost(kCGHIDEventTap, event);
        CFRelease(event);
        [text release];
    }
}

void MacosInputBackend::pointer_move(
    const std::uint16_t normalized_x, const std::uint16_t normalized_y) {
    const auto bounds = CGDisplayBounds(CGMainDisplayID());
    const CGPoint point{
        .x = bounds.origin.x + static_cast<double>(normalized_x) *
             (bounds.size.width - 1.0) / 65535.0,
        .y = bounds.origin.y + static_cast<double>(normalized_y) *
             (bounds.size.height - 1.0) / 65535.0,
    };
    CGEventType event_type = kCGEventMouseMoved;
    click_tracker_.move(point.x, point.y);
    CGMouseButton mouse_button = kCGMouseButtonLeft;
    if ((pressed_pointer_buttons_ & (1U << 0U)) != 0) {
        event_type = kCGEventLeftMouseDragged;
        mouse_button = kCGMouseButtonLeft;
    } else if ((pressed_pointer_buttons_ & (1U << 1U)) != 0) {
        event_type = kCGEventRightMouseDragged;
        mouse_button = kCGMouseButtonRight;
    } else if ((pressed_pointer_buttons_ & (1U << 2U)) != 0) {
        event_type = kCGEventOtherMouseDragged;
        mouse_button = kCGMouseButtonCenter;
    }
    auto event = CGEventCreateMouseEvent(nullptr, event_type, point, mouse_button);
    if (event == nullptr) throw std::runtime_error("create macOS pointer event failed");
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
}

void MacosInputBackend::pointer_button(
    const std::uint8_t button, const bool pressed) {
    CGMouseButton mouse_button{};
    CGEventType down{};
    CGEventType up{};
    switch (button) {
        case 1: mouse_button = kCGMouseButtonLeft;
                down = kCGEventLeftMouseDown; up = kCGEventLeftMouseUp; break;
        case 2: mouse_button = kCGMouseButtonRight;
                down = kCGEventRightMouseDown; up = kCGEventRightMouseUp; break;
        case 3: mouse_button = kCGMouseButtonCenter;
                down = kCGEventOtherMouseDown; up = kCGEventOtherMouseUp; break;
        default: throw std::invalid_argument("unsupported pointer button");
    }
    auto location_event = CGEventCreate(nullptr);
    if (location_event == nullptr) {
        throw std::runtime_error("read macOS pointer location failed");
    }
    const auto location = CGEventGetLocation(location_event);
    CFRelease(location_event);
    auto event = CGEventCreateMouseEvent(
        nullptr, pressed ? down : up, location, mouse_button);
    if (event == nullptr) throw std::runtime_error("create macOS button event failed");
    const auto click_count = click_tracker_.button(
        button, pressed, location.x, location.y,
        CGEventGetTimestamp(event) / 1000U,
        static_cast<std::uint64_t>([NSEvent doubleClickInterval] * 1'000'000.0));
    CGEventSetIntegerValueField(event, kCGMouseEventClickState, click_count);
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
    const auto button_mask = static_cast<std::uint8_t>(1U << (button - 1U));
    if (pressed) {
        pressed_pointer_buttons_ |= button_mask;
    } else {
        pressed_pointer_buttons_ &= static_cast<std::uint8_t>(~button_mask);
    }
}

void MacosInputBackend::pointer_wheel(
    const std::int32_t delta, const bool horizontal) {
    if (delta == 0) {
        throw std::invalid_argument("pointer wheel delta is zero");
    }
    auto event = CGEventCreateScrollWheelEvent(
        nullptr, kCGScrollEventUnitPixel, 2,
        horizontal ? 0 : delta,
        horizontal ? delta : 0);
    if (event == nullptr) {
        throw std::runtime_error("create macOS wheel event failed");
    }
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
}

std::string MacosClipboardBackend::read_utf8_text() {
    @autoreleasepool {
        NSString* value = [[NSPasteboard generalPasteboard]
            stringForType:NSPasteboardTypeString];
        return value == nil ? std::string{} : std::string(value.UTF8String);
    }
}

void MacosClipboardBackend::write_utf8_text(const std::string_view text) {
    if (!desktop::valid_utf8(text) ||
        text.size() > desktop::maximum_clipboard_text_size) {
        throw std::invalid_argument("invalid UTF-8 clipboard text");
    }
    @autoreleasepool {
        NSString* value = [[NSString alloc]
            initWithBytes:text.data() length:text.size()
            encoding:NSUTF8StringEncoding];
        auto pasteboard = [NSPasteboard generalPasteboard];
        [pasteboard clearContents];
        if (![pasteboard setString:value forType:NSPasteboardTypeString]) {
            [value release];
            throw std::runtime_error("write macOS clipboard failed");
        }
        [value release];
    }
}

desktop::DesktopPermissionStatus MacosDesktopPermissionBackend::status() const {
    return {
        .capture = CGPreflightScreenCaptureAccess()
            ? desktop::PermissionState::granted
            : desktop::PermissionState::denied,
        .input = AXIsProcessTrusted()
            ? desktop::PermissionState::granted
            : desktop::PermissionState::denied,
    };
}

void MacosDesktopPermissionBackend::request_capture() {
    static_cast<void>(CGRequestScreenCaptureAccess());
}

void MacosDesktopPermissionBackend::request_input() {
    const void* keys[] = {kAXTrustedCheckOptionPrompt};
    const void* values[] = {kCFBooleanTrue};
    auto options = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    static_cast<void>(AXIsProcessTrustedWithOptions(options));
    CFRelease(options);
}

}  // namespace rwn::platform::macos
